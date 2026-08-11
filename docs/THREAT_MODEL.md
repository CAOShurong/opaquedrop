# Threat model

OpaqueDrop is server-blind under a specific, limited trust model. It does not use “zero knowledge” as a blanket claim.

## Assets

- File contents, filenames, MIME metadata, and last-modified timestamps.
- Recipient P-256 private key and collect capability.
- Submit capability embedded in the shared URL fragment.
- Integrity of the exact encrypted manifest and ciphertext chunks accepted by the server.

## Trusted components

- The uploader's browser and operating system.
- The recipient device holding the private key.
- The OpaqueDrop binary and embedded JavaScript as built from the reviewed source/release.
- TLS termination and the path between it and OpaqueDrop when deployed publicly.

## Security goals

1. The storage server does not need the recipient private key and receives no plaintext filename or file content.
2. A submit capability can create bounded uploads but cannot list, download, collect, or acknowledge submissions.
3. A collect capability can read ciphertext and acknowledge collection but cannot decrypt without the separate private key.
4. Corruption, reordering, cross-upload substitution, and manifest-field tampering fail authentication in the collector.
5. A successful browser receipt identifies the exact manifest bytes and ordered ciphertext chunk hashes stored at completion.
6. Files are not exposed at their final recipient path until every authenticated chunk and the receipt have been verified.

## In-scope adversaries

- An honest-but-curious host or storage administrator inspecting files at rest.
- Later disclosure or theft of the server data directory without the recipient key file.
- A network attacker blocked by correctly configured HTTPS.
- A person who learns only the submit link and attempts listing, retrieval, over-quota writes, malformed chunks, path traversal, or cross-site browser abuse.
- Accidental or malicious ciphertext corruption in storage or transit.

## Explicitly out of scope

- **Malicious JavaScript delivery.** The same server that stores ciphertext serves the upload application. An administrator who changes `app.js` at upload time can exfiltrate plaintext or keys. A future independently packaged uploader could narrow this risk; the current release does not.
- A compromised uploader or recipient endpoint, browser extension, screen recorder, keylogger, or malware.
- Traffic-analysis privacy. IP addresses, timing, request labels, declared sizes, chunk counts, and total ciphertext sizes remain observable. Reverse proxies may log more.
- Availability against a submit-link holder. Quotas bound disk commitment, but the token holder can consume those quotas. `purge` recovers stale incomplete reservations.
- A submit-link holder can complete ciphertext that is structurally acceptable to the server but fails recipient-side authentication. Collection reports that upload ID, leaves it unacknowledged, and continues with later healthy submissions; it does not treat the poisoned item as plaintext or delete it automatically.
- Uploader anonymity. OpaqueDrop is not SecureDrop or OnionShare.
- Malware safety. The server cannot scan ciphertext. The collector never auto-opens a file, but the recipient must scan or sandbox it.
- Key recovery. Losing the recipient key makes ciphertext unrecoverable by design.
- Formal cryptographic verification or independent audit. The construction uses standard primitives but the composition is new and **has not been externally audited**.

## Capability boundaries

- Submit and collect tokens are independent 256-bit random values.
- The request bundle stores only SHA-256 token hashes. Verification uses constant-time comparison.
- The submit token begins in a URL fragment, which browsers do not send in HTTP requests. The application moves it to per-tab session storage and removes it from the address bar. API calls use the `Authorization` header.
- OpaqueDrop does not log request headers or tokens. Operators must also disable sensitive-header logging in reverse proxies.
- The API sends no CORS permission. It rejects `Sec-Fetch-Site: cross-site` and mismatched `Origin` hosts before capability processing. Non-browser clients normally omit both headers.
- The small invalid-capability limiter uses the immediate TCP peer by default. An operator can explicitly trust exact reverse-proxy IPs or CIDRs; only requests arriving from those peers may supply an `X-Forwarded-For` chain, which is parsed from right to left past other trusted hops. Untrusted peers cannot select their limiter identity by forging that header.
- A malformed forwarded hop encountered while walking the trusted suffix falls back to the immediate peer; attacker-controlled data farther left cannot override a client address already selected by an appending edge proxy. An overly broad trusted-proxy range can let a directly connected attacker evade the limiter by rotating forged addresses, so public client networks must never be trusted.
- The limiter keeps at most 4,096 active one-minute buckets and groups excess new identities into a bounded overflow bucket. It is an in-process brake on repeated invalid capabilities, not DDoS protection; it resets on restart and should be complemented by proxy-level limits.

## Cryptographic boundaries

Each file has a fresh ephemeral P-256 key pair, 256-bit HKDF salt, and 64-bit random nonce prefix. ECDH plus HKDF-SHA256 derives one AES-256-GCM key. Under that key:

- chunk counter values begin at `0x00000000` and increase monotonically;
- `0xffffffff` is reserved for encrypted metadata and cannot be used as a chunk index;
- the server limits chunk count below `0xffffffff`;
- a SHA-256 digest of every public manifest field is included in the associated data for metadata and every chunk;
- request ID, upload ID, header digest, content class, and chunk index are associated data, preventing valid ciphertext from being moved to another position or upload.

The 64-bit nonce prefix does not need to be globally collision-free because every file derives a new AES key. Its purpose is uniqueness within one key when combined with the non-repeating counter. Metadata has a reserved counter outside the permitted chunk range.

## Storage and finalization

- Manifests are capped at 64 KiB.
- Accepted chunk sizes are 64 KiB through 8 MiB; the browser uses 1 MiB.
- Chunk uploads go to a private temporary file and rename into place only after the exact declared length is received.
- Completion validates every expected chunk and length, computes the receipt, writes a temporary marker, syncs it, and atomically renames it to `complete.json`.
- Collection decrypts one bounded chunk at a time into a private temporary output file, verifies the receipt and total length, checks cancellation, syncs the file, and atomically publishes a no-replace hard link under a sanitized, component-bounded basename.
- A missing, corrupted, reordered, or header-mismatched upload leaves no completed recipient file.
- A failed completed upload cannot prevent later healthy submissions in the same request from being collected. Partial success still returns a nonzero CLI exit so automation cannot mistake the batch for wholly successful.

## Residual-risk decisions

Server-side antivirus and preview are intentionally incompatible with the server-blind goal. Retention defaults to keeping ciphertext after acknowledgement until the operator runs expiry cleanup; immediate deletion is opt-in. The first release intentionally avoids resumable-across-reload browser keys because persisting an ephemeral file key expands the browser secret-storage surface.

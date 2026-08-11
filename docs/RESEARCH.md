# Evidence and alternatives review

Research snapshot: 2026-08-11. This document explains why OpaqueDrop is a narrow project rather than another general file-sharing service.

## Documented workflow pain

The recurring need is not “put a file on a webpage.” Existing projects do that well. The friction appears when a nontechnical external person must send a large or sensitive file into a self-hosted system without receiving an account, seeing other submissions, or asking the recipient to download and re-stage the file.

- A homelab user receiving remote video footage described the double handling in Pingvin Share—upload to the server, then download again to the working machine—and explicitly prioritized restricted, secure upload access. [Practitioner thread](https://www.reddit.com/r/homelab/comments/1fb3zn1/selfhosted_file_transfer_service/)
- A family self-hosting discussion raised a different trust boundary: family members may want privacy from the person operating the home server, not only from cloud vendors. [Practitioner discussion](https://www.reddit.com/r/selfhosted/comments/1oebj1u/what_do_you_selfhost_for_your_family_that_they/)
- A 2026 self-hosted storage discussion with substantial participation described continued dissatisfaction with broad suites: resource use, cross-platform behavior, sharing, and operational complexity remain common failure points. [Practitioner discussion](https://www.reddit.com/r/selfhosted/comments/1rp2vup/why_does_a_simple_free_self_hosted_file_storage/)
- Administrators have long asked for a secure upload portal as the practical replacement for blocked encrypted archives and risky email attachments. [Practitioner discussion](https://www.reddit.com/r/sysadmin/comments/ll98bp/if_you_are_going_to_block_encrypted_zip_files_and/)

These are practitioner reports, not prevalence estimates. They establish real workflows and failure modes; they do not prove market size.

## Maintained alternatives

| Project | What it already solves | License and maintenance snapshot | Deployment weight and cost | Remaining mismatch for this lane |
|---|---|---|---|---|
| [Gokapi](https://github.com/Forceu/Gokapi) | Strong Go-based sharing, file requests, expiry, accounts, S3, optional E2EE for ordinary uploads | AGPL-3.0; active; v2.2.4 release and ~2.8k stars at research time | Single binaries or Docker; local/S3 operating cost | Its official usage documentation says **File Requests bypass Level 3 E2EE** and are stored with, at most, server-side encryption. Its troubleshooting guide also documents mobile E2EE download limits. [Exact source at audited commit](https://github.com/Forceu/Gokapi/blob/1af4241a529e51b5cc7b4f1bb1fadbe60b1c17dd/docs/usage.rst#L58-L65) |
| [Copyparty](https://github.com/9001/copyparty) | Excellent portable server, resumable uploads, and true write-only folders | MIT; very active; ~46k stars | One Python file or native package; low cost | The host receives ordinary file bytes. Its extensive permissions solve listing and authorization, not recipient-public-key encryption. [Write-only example](https://github.com/9001/copyparty#accounts-and-volumes) |
| [Nextcloud File Drop](https://docs.nextcloud.com/server/latest/user_manual/en/files/file_drop.html) | Mature anonymous upload into a hidden folder | AGPL-3.0; large active project | PHP application plus database and recommended cache/background services; highest maintenance and migration cost here | Broad suite; the destination server can process uploaded files. Adding OpaqueDrop solely for blind intake is cheaper than replacing an existing Nextcloud deployment, while deploying Nextcloud solely for this workflow is disproportionate. |
| [Pingvin Share](https://github.com/stonith404/pingvin-share) | Reverse shares, passwords, expiry, S3, ClamAV | BSD-2-Clause; repository archived in 2026; ~4.7k stars | Recommended Docker Compose deployment | Reverse shares solve inbound UX but not server-blind storage. ClamAV is useful precisely because the server can inspect plaintext; OpaqueDrop makes the opposite tradeoff. |
| [SFTPGo](https://github.com/drakkan/sftpgo) | Full managed file transfer across SFTP, HTTP, FTP, WebDAV, cloud backends, event actions | AGPL-3.0 with additional terms; active; ~12k stars | Single Go service, but broad protocol/configuration surface | Capable MFT platform with materially higher configuration and migration cost; recipient-only browser encryption is not its narrow purpose. |
| [sE2EEnd](https://github.com/sE2EEnd/sE2EEnd) | Browser E2EE for outbound file transfers, administration and SSO | GPL-3.0; active early-stage project | Docker Compose with frontend, Spring Boot, PostgreSQL, and Keycloak | Stronger team/admin scope and much heavier stack; its documented workflow is sender-created download links, not a public-key inbound request whose recipient key can stay off-host. |
| [Tresorit File Requests](https://support.tresorit.com/hc/en-us/articles/360012807300-About-file-requests) | Polished accountless end-to-end encrypted inbound requests | Proprietary commercial service | Subscription and provider lock-in; 5 GB browser-session limit documented | Valid proof that the workflow matters, but not self-hosted or locally operable. |

## Selection decision

A generic write-only upload server was rejected because Copyparty already solves it with exceptional deployment simplicity. A broad encrypted drive was rejected because it would duplicate mature suites and emerging projects while multiplying sync, account, and recovery risks. A Gokapi mobile-decryption companion was considered, but would leave the more fundamental inbound gap unchanged: File Requests bypass its end-to-end mode entirely.

OpaqueDrop therefore implements one defensible gap:

> A person with only a browser can submit files through an expiring, quota-limited capability; filenames and bytes are encrypted to a recipient key before upload; the server stores no raw capability or recipient private key; the recipient can collect on another device and verify the exact stored ciphertext.

## Operational follow-up: proxy-aware authorization limits

The first release deliberately ignored forwarded client addresses. That prevented header spoofing, but it also meant every public client behind the recommended loopback reverse proxy shared one invalid-capability bucket. Twelve bad attempts from one client could therefore make correct submit and collect capabilities from everyone behind that proxy receive HTTP 429 for one minute.

This is a documented operational failure pattern, not a hypothetical feature request:

- [Copyparty issue #1492](https://github.com/9001/copyparty/issues/1492) reports bot probes causing a reverse-proxy address to be banned so other users could not connect. Copyparty's maintained reverse-proxy guidance pairs the forwarded header with an explicit trusted source and proxy depth.
- [Gokapi issue #356](https://github.com/Forceu/Gokapi/issues/356) tracks a reverse-proxy client-IP regression and the subsequent Docker/CIDR trusted-proxy repair. Current Gokapi configuration exposes explicit trusted-proxy ranges.
- [ntfy's proxy documentation](https://github.com/binwiederhier/ntfy/blob/main/docs/config.md#behind-a-proxy-tls-etc) warns that without proxy-aware visitor identity all users are rate-limited as one, and supports trusted proxy hosts for multi-hop chains.
- [Nextcloud's reverse-proxy configuration](https://docs.nextcloud.com/server/latest/admin_manual/configuration_server/reverse_proxy_configuration.html) similarly limits forwarded client-IP trust to configured proxies and warns that incorrect headers enable IP spoofing.

OpaqueDrop v0.2.0 adopts that established boundary without adding a dependency: `--trusted-proxy` is opt-in and repeatable, the direct peer must match, and `X-Forwarded-For` is walked from the nearest hop toward the client. A malformed hop in the trusted suffix falls back to the peer; untrusted text farther toward the origin is ignored once the first valid non-trusted client address has been selected. A constant-size limiter table prevents newly distinguished source addresses from causing unbounded retained state. This improves fairness behind a proxy; it does not claim to prevent DDoS or abuse by someone who already holds a valid submit capability.

## Operational follow-up: isolate collection failures

The server can validate upload shape, lengths, and an exact ciphertext receipt, but it intentionally cannot prove that ciphertext authenticates under the off-host recipient key. A submit-capability holder can therefore complete a structurally valid poisoned upload. Before v0.3.0, the collector stopped at the first such item and the CLI suppressed any earlier successful results, so one old bad record could indefinitely block every later healthy submission.

The selected behavior follows established batch-transfer contracts rather than inventing a new protocol:

- [rclone's maintained documentation](https://rclone.org/docs/) says it accumulates per-file errors while running and exits nonzero only after retries if transfers still failed. [Issue #4670](https://github.com/rclone/rclone/issues/4670) requests an optional early-stop threshold, confirming that keep-going is deliberate default behavior.
- [rsync](https://man7.org/linux/man-pages/man1/rsync.1.html) reserves exit status 23 for partial transfer due to error instead of representing partial work as full success.
- [Gokapi File Requests](https://gokapi.readthedocs.io/en/latest/usage.html) provides both individual downloads and a batch archive, giving operators an item-level escape path.
- A [Nextcloud practitioner request](https://www.reddit.com/r/NextCloud/comments/1ei3lo7/how_to_make_nextcloud_macos_app_skip_a_file_if/) describes the same operational need to skip an errored item and continue later files. This is anecdotal evidence, not a prevalence estimate.

OpaqueDrop v0.3.0 keeps sequential processing and adds explicit selection and fail-fast controls. Per-submission cryptographic/protocol failures are isolated, successful files retain verify-sync-atomic-publish-ack ordering, shared output-filesystem failures stop immediately, and any partial failure still produces a nonzero process exit. A standard-library hard-link publish removes the old check-then-rename collision race without adding a dependency; unsupported destination filesystems fail closed. There is no state migration or wire-format change.

## Reuse and protocol choices

The project uses only platform primitives rather than introducing a cryptographic library or custom cipher:

- [W3C Web Cryptography Level 2](https://www.w3.org/TR/WebCryptoAPI/) provides browser-native ECDH, HKDF, and AES-GCM.
- [W3C cryptography usage guidance](https://www.w3.org/TR/security-guidelines-cryptography/) recommends authenticated encryption such as AES-GCM instead of confidentiality without integrity.
- Go's standard [`crypto/ecdh`](https://pkg.go.dev/crypto/ecdh) validates P-256 keys and implements key agreement; `crypto/hkdf` and `crypto/cipher` provide the remaining primitives.
- The framing format, associated data, nonce allocation, and fixed browser↔Go vector are documented in [PROTOCOL.md](PROTOCOL.md). This composition has **not** received an external cryptographic audit.

P-256 was selected over X25519 for the first format because ECDH P-256 has broader established Web Crypto interoperability across the browser versions this project targets. AES-GCM is hardware-accelerated and available in both Web Crypto and the Go standard library. A fresh ephemeral P-256 key, 256-bit HKDF salt, and 64-bit random nonce prefix are generated for every file.

## Cost, platform, and migration summary

- **Runtime dependency weight:** zero; static Go binary with embedded HTML/CSS/JavaScript.
- **Operating cost:** local disk plus an existing HTTPS reverse proxy; no database, queue, email, identity provider, object store, or hosted relay.
- **Platform fit:** release targets Windows, Linux, and macOS on amd64 and arm64. Public hosting is normally Linux, but key generation and collection are cross-platform.
- **Migration cost:** request files and upload directories are plain versioned JSON plus ciphertext chunks. Removing OpaqueDrop requires exporting/collecting desired files and deleting one data directory; no account or metadata database needs conversion.
- **Lock-in:** the format and cross-implementation vector are public, but no independent third-party decryptor exists at the initial release. That is a real remaining migration risk.

## Honest limits

OpaqueDrop cannot scan encrypted uploads for malware, preview them on the server, recover a lost recipient key, hide traffic metadata, provide uploader anonymity, prevent denial-of-service by someone holding the submit link, or protect an uploader from JavaScript maliciously modified by the server administrator at upload time. If the host is trusted with plaintext, Gokapi or Copyparty will usually offer more features with less key handling.

# OpaqueDrop protocol v1

Status: implemented by OpaqueDrop v0.1.0 and later. This format is versioned but has not been independently audited.

## Encoding

- JSON is UTF-8.
- Binary fields use unpadded base64url.
- Digests use lowercase hexadecimal SHA-256.
- Integers in JSON must fit exact JavaScript safe-integer handling; the server additionally caps request bytes at 1 PiB.

## Keys and derivation

The recipient request key and per-file ephemeral key use ECDH P-256 uncompressed public points. For each file:

```text
shared = ECDH(ephemeral_private, recipient_public)
file_key = HKDF-SHA256(
  secret = shared,
  salt = 32 random bytes,
  info = "OpaqueDrop/v1/request/" + request_id + "/upload/" + upload_id,
  length = 32
)
```

`file_key` is an AES-256-GCM key.

## Manifest header binding

The public header is serialized exactly as follows, ending with a newline:

```text
opaquedrop/v1/header
version={decimal}
request_id={base64url id}
upload_id={base64url id}
algorithm=ECDH-P256+HKDF-SHA256+AES-256-GCM-CHUNKED
ephemeral_public_key={base64url point}
salt={base64url bytes}
nonce_prefix={base64url bytes}
chunk_size={decimal}
chunk_count={decimal}
plain_size={decimal}
```

`header_sha256` is the lowercase SHA-256 of these UTF-8 bytes. The server recomputes it before reserving storage. The recipient recomputes it before deriving or opening anything.

## Nonces

Every nonce is 12 bytes:

```text
nonce = nonce_prefix[8 bytes] || uint32_be(index)
```

- file chunks use indices `0` through `chunk_count - 1`;
- `chunk_count` must be less than `0xffffffff`;
- encrypted metadata exclusively uses `0xffffffff`.

One file key is used with one random prefix and non-repeating indices. Every new file has a fresh ephemeral key and salt, so a prefix collision across files does not imply nonce reuse under one AES key.

## Associated data

Metadata:

```text
opaquedrop/v1|{request_id}|{upload_id}|header|{header_sha256}|metadata
```

Chunk `i`:

```text
opaquedrop/v1|{request_id}|{upload_id}|header|{header_sha256}|chunk|{i}
```

This binds the request, upload, complete public header, content class, and ordered position to each AES-GCM tag.

## Encrypted metadata

The metadata plaintext is UTF-8 JSON:

```json
{"name":"example.pdf","type":"application/pdf","last_modified":1700000000000}
```

`encrypted_metadata` is AES-256-GCM ciphertext with the tag appended, as returned by Web Crypto, encoded with base64url.

## Chunk framing

The browser implementation uses 1 MiB plaintext chunks. The server accepts configured manifest chunk sizes from 64 KiB through 8 MiB. Each stored chunk is:

```text
AES-256-GCM(file_key, nonce(index), plaintext_chunk, chunk_aad(index))
```

The GCM tag adds 16 bytes. An empty file has one zero-byte plaintext chunk and one 16-byte ciphertext chunk.

## Receipt

After all exact chunk lengths exist, the server computes:

```text
manifest_digest = SHA256(exact_manifest_request_body)
chunk_digest[i] = SHA256(exact_ciphertext_chunk[i])
receipt_sha256 = SHA256(
  UTF8("OpaqueDrop receipt v1\0") ||
  manifest_digest ||
  chunk_digest[0] || ... || chunk_digest[n-1]
)
```

The browser independently computes and compares this value. The collector recomputes it after downloading ciphertext and compares it with the completion receipt before finalizing output.

## Same-tab transfer replay

Transfer recovery does not change the cryptographic format. A repeated manifest setup must contain the exact same request body and upload ID; the server accepts it only when the existing manifest, server state, and chunks directory match that upload. Different bytes under the same upload ID are a conflict.

Each repeated chunk PUT contains the same ciphertext. If the server reports that the chunk already exists, an authenticated HEAD request returns its SHA-256 digest and the browser advances only when that digest matches its local ciphertext. Repeating completion returns the already persisted receipt. These rules support bounded retries while the page remains open; they do not persist the ephemeral file key or provide resume after reload.

## Cross-implementation vector

[`testdata/protocol-v1.json`](../testdata/protocol-v1.json) uses fixed recipient and ephemeral P-256 scalars. [`scripts/protocol-vector.mjs`](../scripts/protocol-vector.mjs) generates and verifies it through Node's Web Crypto implementation. Go tests open the same metadata and chunks, verify the receipt, assert nonce separation, and confirm corruption, reordering, and public-header mutations fail.

Regenerate and verify:

```console
node scripts/protocol-vector.mjs --write
go test ./internal/cryptobox -v
```

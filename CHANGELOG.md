# Changelog

All notable changes are documented here.

## [Unreleased]

## [0.2.0] - 2026-08-11

### Added

- Repeatable, opt-in `serve --trusted-proxy IP_OR_CIDR` handling for reverse-proxy deployments.
- Right-to-left `X-Forwarded-For` parsing behind explicitly trusted peers, with strict fallback on malformed chains.
- `Retry-After: 60` on invalid-capability rate-limit responses.

### Security

- Separate invalid-capability buckets for real clients behind a configured proxy, preventing one client from locking out every uploader and collector sharing that proxy.
- Bound in-memory failure state to 4,096 active buckets with expiry cleanup and an overflow bucket.
- Preserve the secure default: forwarded headers from untrusted peers are ignored.

## [0.1.0] - 2026-08-11

### Added

- Accountless, capability-scoped inbound file requests.
- Browser-native chunked P-256 ECDH, HKDF-SHA256, and AES-256-GCM encryption.
- Recipient-off-host request generation and public-bundle import.
- Exact ciphertext receipts and authenticated header binding.
- Cross-platform collector with atomic, filename-safe output.
- File/byte quotas, expiry, dry-run cleanup, security headers, and cross-origin rejection.
- Defense-in-depth request/upload identifier confinement before filesystem access.
- Deterministic browser WebCrypto ↔ Go test vector and adversarial corruption/reordering tests.
- Embedded responsive upload UI and dependency-free release binaries.

[Unreleased]: https://github.com/CAOShurong/opaquedrop/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/CAOShurong/opaquedrop/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/CAOShurong/opaquedrop/releases/tag/v0.1.0

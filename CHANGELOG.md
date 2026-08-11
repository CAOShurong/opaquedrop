# Changelog

All notable changes are documented here.

## [Unreleased]

## [0.3.0] - 2026-08-11

### Added

- Repeatable `collect --upload ID` for explicit selection and recovery, including intentional re-collection of retained acknowledged uploads.
- `collect --fail-fast` for automation that prefers first-error termination.

### Changed

- Collection now continues past isolated authentication, corruption, and protocol failures, reports every successful file, and exits nonzero when any submission failed.
- Shared output-filesystem failures and context cancellation still stop immediately.
- A file saved before an acknowledgement failure is now included in the successful-result output while the command reports the failed acknowledgement.
- Final output publication is now atomic and no-replace across concurrent collectors; filename collisions are bounded and suffixed instead of using a check-then-rename race.
- Decrypted filenames now fit conservative UTF-8/UTF-16 component limits and reject Windows reserved device basenames.
- The bounded receipt-list response limit now covers the protocol maximum of 10,000 completed uploads.

## [0.2.0] - 2026-08-11

### Added

- Repeatable, opt-in `serve --trusted-proxy IP_OR_CIDR` handling for reverse-proxy deployments.
- Right-to-left `X-Forwarded-For` parsing behind explicitly trusted peers, with safe fallback when the trusted suffix is malformed.
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

[Unreleased]: https://github.com/CAOShurong/opaquedrop/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/CAOShurong/opaquedrop/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/CAOShurong/opaquedrop/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/CAOShurong/opaquedrop/releases/tag/v0.1.0

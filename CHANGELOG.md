# Changelog

All notable changes are documented here.

## [Unreleased]

## [0.6.0] - 2026-08-11

### Added

- `collect --list` to inspect unacknowledged completed submissions before downloading, with authenticated local metadata decryption for sanitized filenames, sizes, completion times, states, and upload IDs.
- `collect --list --all` to include acknowledged submissions, plus repeatable `--upload ID` filtering for a named inspection subset.

### Changed

- Inspection fetches only the bounded receipt list and selected manifests; it creates no output directory, downloads no ciphertext chunks, and sends no acknowledgement.
- An unreadable manifest or encrypted filename is reported by upload ID as `<unreadable>` without blocking later healthy inspection results; any such partial failure still exits nonzero.
- Sender-provided names are displayed through the same cross-platform filename sanitizer used for collection and are quoted before terminal output.

## [0.5.0] - 2026-08-11

### Added

- Same-tab browser retries for interrupted manifest setup, individual chunk uploads, and receipt finalization.
- Bounded 250/500/1000 ms backoff for network failures and temporary 408/425/429/500/502/503/504 responses, with `Retry-After` support up to 30 seconds.
- Headless Node coverage that executes the shipped browser application through lost-response recovery for setup, chunk, and completion requests.

### Changed

- Repeating the exact same valid manifest for an existing, complete upload directory shape is now idempotent and does not consume quota twice; a different manifest with the same upload ID remains a conflict.
- Browser chunk retry continues to verify an already-stored ciphertext digest with the existing authenticated HEAD endpoint before advancing progress.
- Upload retry state remains in the current page only; file keys are not persisted and cross-reload resume is still intentionally unsupported.

## [0.4.0] - 2026-08-11

### Added

- `collect --read-retries N` (default 3, maximum 10) for bounded retries after temporary list, manifest, or chunk GET failures.
- Context-aware exponential read backoff, retry diagnostics on stderr, and `Retry-After` handling up to a 30-second automatic-wait limit.
- Portable interrupt handling so Ctrl+C cancels an in-flight collection or retry wait before final publication.

### Changed

- A truncated chunk response or temporary 408/425/429/500/502/503/504 now retries only that read; completed earlier chunks are not downloaded or written again.
- Invalid JSON, manifest/ciphertext authentication failures, response-limit violations, and permanent HTTP errors are not retried.
- Acknowledgement POST remains single-shot and refuses redirects because delete-after-collect requests do not yet have persistent idempotency tombstones.

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

[Unreleased]: https://github.com/CAOShurong/opaquedrop/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/CAOShurong/opaquedrop/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/CAOShurong/opaquedrop/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/CAOShurong/opaquedrop/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/CAOShurong/opaquedrop/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/CAOShurong/opaquedrop/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/CAOShurong/opaquedrop/releases/tag/v0.1.0

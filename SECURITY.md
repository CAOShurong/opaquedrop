# Security policy

## Supported versions

The latest tagged release receives security fixes. Pre-release builds and older minor lines are not supported once a replacement is available.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting for this repository: **Security → Report a vulnerability**. Do not open a public issue containing an exploit, private key, capability link, or sensitive upload.

Include:

- affected version and platform;
- the violated security property from `docs/THREAT_MODEL.md`;
- minimal reproduction steps using non-sensitive test data;
- whether confidentiality, integrity, authorization, availability, or key handling is affected;
- any suggested mitigation.

You should receive an acknowledgement within 72 hours. No bounty is promised. Coordinated disclosure is appreciated.

## Cryptographic review status

OpaqueDrop uses standard P-256 ECDH, HKDF-SHA256, and AES-256-GCM primitives from Web Crypto and the Go standard library. Its framing, associated-data composition, key lifecycle, and browser delivery model have **not been externally audited**. Passing test vectors and adversarial tests are not equivalent to a professional security assessment.

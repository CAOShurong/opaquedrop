# Contributing

OpaqueDrop intentionally stays narrow. Changes should preserve the accountless, server-blind inbound workflow and avoid adding a database, identity suite, tracking, or server-side plaintext processing.

## Development checks

Use Go 1.26 or newer and Node.js 22 or newer:

```console
node scripts/protocol-vector.mjs
go test ./... -race
go vet ./...
```

For changes to the browser cryptography or protocol, regenerate the deterministic vector, inspect the diff, run both the Node verifier and Go vector tests, and explain the security effect in the pull request. A protocol change requires a version change and migration story; silently changing v1 is not acceptable.

For UI changes, run the real server, exercise a complete encrypted upload and collection, inspect desktop and mobile-width screenshots, and report browser console errors.

## Pull requests

- Keep each change focused.
- Add observable regression tests before or with a fix.
- Update the threat model when a trust boundary changes.
- Do not commit real capability URLs, recipient keys, or uploaded files.
- Run formatting, tests, vet, the WebCrypto vector verifier, and the real CLI path.

## Code of conduct

Be precise, respectful, and focused on the work. Security disagreement is welcome when it includes evidence and a reproducible mechanism. Harassment, personal attacks, and disclosure of another person's secrets are not acceptable.

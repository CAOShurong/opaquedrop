# Deployment guide

OpaqueDrop binds to loopback by default. Keep it there and terminate public TLS in a maintained reverse proxy. Browser encryption is unavailable on ordinary public HTTP origins.

## Caddy

```caddyfile
drop.example.net {
    reverse_proxy 127.0.0.1:8080
    log {
        output file /var/log/caddy/opaquedrop-access.log
        format json
    }
}
```

Caddy does not log authorization headers in its standard access log. If you customize log fields, never add `Authorization` or the URL fragment (fragments do not reach the server in a conforming browser).

Run OpaqueDrop with the exact Caddy upstream address as a trusted proxy:

```console
opaquedrop serve --data /var/lib/opaquedrop --listen 127.0.0.1:8080 --trusted-proxy 127.0.0.1/32
```

## nginx

```nginx
server {
    listen 443 ssl http2;
    server_name drop.example.net;

    client_max_body_size 9m;
    proxy_request_buffering off;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $remote_addr;
    }
}
```

The nginx example is a single edge proxy, so it overwrites any client-supplied `X-Forwarded-For` instead of preserving it. Start OpaqueDrop with `--trusted-proxy 127.0.0.1/32` as in the Caddy example.

## Client IP and rate-limit boundary

OpaqueDrop uses client IPs only for its small invalid-capability limiter. They do not grant access and do not replace the submit or collect capability.

- By default, only the immediate TCP peer identifies the limiter bucket and every forwarded header is ignored.
- `--trusted-proxy IP_OR_CIDR` is repeatable. Only when the immediate peer matches one of these ranges does OpaqueDrop read `X-Forwarded-For`.
- For a proxy chain, OpaqueDrop walks the header from right to left, skips configured trusted proxies, and selects the first untrusted address. A malformed hop encountered before that selection fails closed to the immediate peer; data farther left cannot override an already selected client.
- Configure the smallest exact proxy ranges. Trusting a client-reachable or overly broad network lets clients choose limiter identities and evade this defense-in-depth throttle.
- Every trusted edge proxy must overwrite or safely append the address it observed. Do not pass a client-controlled identity header unchanged.

The limiter allows 12 failed capability checks per client per minute, returns `Retry-After: 60` while blocked, and retains at most 4,096 active buckets. Excess distinct clients share a bounded overflow bucket. State is intentionally in memory and resets on restart. This is not distributed-denial-of-service protection, and it does not stop a holder of a valid submit capability from consuming that request's quota. Keep proxy-level connection, request, and bandwidth controls for public deployments.

## systemd

Create a dedicated user and a real data directory. Do not place the recipient key in this directory if the server operator should not decrypt submissions.

```ini
[Unit]
Description=OpaqueDrop encrypted intake
After=network-online.target
Wants=network-online.target

[Service]
User=opaquedrop
Group=opaquedrop
ExecStart=/usr/local/bin/opaquedrop serve --data /var/lib/opaquedrop --listen 127.0.0.1:8080 --trusted-proxy 127.0.0.1/32
Restart=on-failure
RestartSec=3s
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/opaquedrop
UMask=0077

[Install]
WantedBy=multi-user.target
```

## State and backups

The server data directory contains:

```text
opaquedrop.json
requests/<request-id>.json
uploads/<request-id>/<upload-id>/
  manifest.json
  server.json
  chunks/00000000.bin ...
  complete.json
  acknowledged.json (after collection)
```

The recipient key file is a separate backup asset and is more sensitive than server data. Back it up through a recipient-controlled encrypted system. A server backup without that key preserves availability of ciphertext but not decryption capability.

## Collection failures and recovery

`opaquedrop collect` verifies submissions sequentially. A per-submission authentication, corruption, or protocol failure is reported with the public upload ID; that submission is not acknowledged and no final output file is exposed. Later healthy submissions are still processed. The overall command exits nonzero if any item failed, even when some files were successfully saved.

Use `--fail-fast` for automation that must stop at the first item failure. Use repeatable `--upload UPLOAD_ID` to collect only named completed submissions; this can intentionally re-collect an acknowledged upload while its ciphertext is retained. Output-directory creation, writes, sync, close, or atomic publication failures stop the batch immediately because they indicate a shared destination problem rather than an isolated upload.

The collector publishes a fully verified temporary file with a same-directory hard link. This gives no-replace atomicity even when multiple collectors choose the same decrypted name; existing names receive a bounded numeric suffix and are never overwritten. The destination filesystem must support hard links. Common local NTFS, ext4, APFS, and similar filesystems do; a filesystem or network share that rejects hard links fails closed with no final file and should be replaced by a supported staging directory.

OpaqueDrop does not automatically delete or acknowledge a failed submission. Retaining it preserves evidence and avoids turning a decryption error into destructive server action. Operators can let request expiry remove it or investigate the upload ID before cleanup.

## Cleanup

Preview expired requests and incomplete uploads older than 24 hours:

```console
opaquedrop purge --data /var/lib/opaquedrop
```

Apply exactly the displayed deletion set:

```console
opaquedrop purge --data /var/lib/opaquedrop --apply
```

The binary does not create a scheduler. If an operator adds a systemd timer, its purpose should be documented locally and it should invoke the noninteractive command without a console session.

## Upgrade and rollback

1. Keep the previous binary.
2. Download the new release archive and `SHA256SUMS` from GitHub Releases.
3. Verify the archive hash.
4. Run `opaquedrop version` and `opaquedrop doctor --data ...` with the new binary.
5. Stop the service, replace the binary, and start it.

Protocol and state schemas are versioned. v0.x does not perform an in-place database migration because there is no database. If a future release requires a state transformation, its release notes must provide an explicit backup and rollback path.

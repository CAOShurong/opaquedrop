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
    }
}
```

OpaqueDrop never trusts `X-Forwarded-For` for authorization or rate limiting. Its small invalid-capability limiter sees the proxy address; use the proxy's own rate controls if the service is exposed broadly.

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
ExecStart=/usr/local/bin/opaquedrop serve --data /var/lib/opaquedrop --listen 127.0.0.1:8080
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

Protocol and state schemas are versioned. v0.1.x does not perform an in-place database migration because there is no database. If a future release requires a state transformation, its release notes must provide an explicit backup and rollback path.

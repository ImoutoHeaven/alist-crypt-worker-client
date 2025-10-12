# alist-crypt-worker-local

Worker variant that keeps server-side logic to authentication, metadata retrieval, and encrypted proxying while delegating decryption to the browser/client.

## Environment variables

| Variable | Required | Description |
| --- | --- | --- |
| `ADDRESS` | ✅ | Base URL of the upstream API service (e.g. `https://crypt.ldc-fe.org`). |
| `TOKEN` | ✅ | Authorization token used when calling `ADDRESS`. |
| `SIGN_SECRET` | ⛔ optional | Secret used to validate `sign` parameters (defaults to `TOKEN` when omitted). |
| `VERIFY_HEADER` | ⛔ optional | Extra header key for upstream verification. |
| `VERIFY_SECRET` | ⛔ optional | Extra header value for upstream verification. |
| `IPV4_ONLY` | ⛔ optional | Set to `"true"` to block IPv6 clients. |
| `SESSION_TTL_SECONDS` | ⛔ optional | Lifetime of metadata sessions shared with `/fetch`; defaults to `300`. |

## Endpoints

- `GET /:path?sign=...` – primary entry point. When opened in a browser it renders a download dashboard (progress, speed, pause/resume, auto-retry). The page requests metadata via `/info` and decrypts the file locally before saving it to disk.
- `GET /info?path=<path>&sign=<signature>` – returns metadata and a short-lived session id. The response includes `dataKey`, nonce, block sizes, and a Worker-relative download URL for encrypted bytes.
- `GET /fetch?session=<sessionId>` – streams encrypted content by proxying the upstream file. Accepts `Range` headers and mirrors relevant response headers while keeping upstream authorization details opaque.

Example workflow:

1. Client requests `/info` with the original file path and signed query. Save `dataKey`, `nonce`, `block_*` sizes, `size`, and `downloadUrl` from the JSON payload.
2. Client issues one or more ranged requests to `downloadUrl` and decrypts blocks locally using the provided metadata.
3. If the session expires or a `410` is returned, request `/info` again to refresh the metadata.

> ℹ️ The in-browser decryptor loads `tweetnacl` from the public CDN `https://cdn.jsdelivr.net`. Ensure outbound access to that domain is permitted, or vendor the asset if offline operation is required.

## Browser downloader

The built-in front-end fetches metadata first, then performs a **four-threaded ranged download** of the encrypted payload, followed by client-side decryption and saving. Users can pause/resume while the download is in progress; each segment is retried up to three times (20 s backoff) and completed blocks are preserved between retries. If the Worker session expires, the page transparently refreshes the session and continues without losing progress. Because decryption happens after all segments are downloaded, browsers avoid CPU throttling issues previously observed inside Workers.

## Development

```sh
npm install
npm run build
wrangler dev
```

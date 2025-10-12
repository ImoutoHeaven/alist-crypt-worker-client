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

- `GET /:path?sign=...` – primary entry point. When opened in a browser it renders a download dashboard (progress, speed, pause/resume, auto-retry) and establishes a WebSocket session automatically.
- `GET /ws` – upgrades to a WebSocket connection. After sending an `init` message (`{ type: "init", path, sign }`) the Worker responds with metadata (`dataKey`, nonce, block sizes, etc.) and subsequently serves encrypted segments via binary frames. Supported commands include `segment` (start/continue a range), `cancel` (abort an in-flight range), and `ping`.
- `GET /info?path=<path>&sign=<signature>` – compatibility endpoint returning metadata plus a short-lived session id for HTTP-based downloads.
- `GET /fetch?session=<sessionId>` – compatibility endpoint that proxies encrypted content over HTTP. Accepts `Range` headers and mirrors relevant response headers while keeping upstream authorization details opaque.

Example workflow (WebSocket):

1. Client connects to `/ws`, sends an `init` message with the signed path, and receives metadata (`dataKey`, nonce, block sizes, file size/name).
2. Client sends `segment` commands (optionally in parallel) describing underlying offsets/lengths; the Worker replies with binary frames containing encrypted bytes for each segment id.
3. Client decrypts segments locally and optionally sends `cancel` to pause/stop workers; if the connection closes the client simply reconnects and resumes requesting remaining segments.

> ℹ️ The in-browser decryptor loads `tweetnacl` from the public CDN `https://cdn.jsdelivr.net`. Ensure outbound access to that domain is permitted, or vendor the asset if offline operation is required.

## Browser downloader

The built-in front-end now maintains a single WebSocket to drive a **four-threaded segmented download**. Metadata exchange happens during the WebSocket handshake; encrypted segments stream back as binary frames, and the page decrypts everything locally before saving. Pause/resume triggers `cancel` messages for in-flight segments, retries are still capped at three attempts with 20 s backoff, and reconnection is handled automatically when the Worker signals a session expiry or the socket closes. Because decryption happens after all segments arrive, browsers avoid CPU throttling issues previously observed inside Workers.

## Development

```sh
npm install
npm run build
wrangler dev
```

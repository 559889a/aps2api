# aps2api

[![CI](https://github.com/559889a/aps2api/actions/workflows/ci.yml/badge.svg)](https://github.com/559889a/aps2api/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/559889a/aps2api)](https://github.com/559889a/aps2api/releases)

**aps2api** is a single-binary proxy, written in Rust, that turns Vertex Gemini into a
self-hosted OpenAI-compatible (and Gemini-native) API: it accepts standard LLM chat
requests on an OpenAI-compatible endpoint (`/v1/chat/completions`, `/v1/models`) and a
Gemini-native endpoint (`/v1beta/...`), sanitizes and rebuilds the payload, and forwards
it to one of two upstream channels — a Vertex **Express API key** (native Gemini protocol)
or a **Google Cloud console cookie** (browser-emulating direct connection) — then streams
the response back in the client's protocol.

## Features

- **OpenAI-compatible endpoint** — `POST /v1/chat/completions` (streaming SSE and JSON)
  and `GET /v1/models`.
- **Gemini-native endpoint** — `POST /v1beta/models/{model}:generateContent`,
  `:streamGenerateContent` (SSE), `GET /v1beta/models`.
- **Dual upstream channels** — Express (official endpoint, API-key auth) and cookie
  (console batchGraphql direct with full Chrome TLS/HTTP2 fingerprint emulation via
  `wreq`, three-layer anti-detection: TLS fingerprint, browser header set, session
  context). Pick a channel per request with an `express/` or `cookie/` model-name prefix.
- **Payload rebuilding (never pass-through)** — penalty parameters, `top_k`, and
  `max_tokens` are stripped, thinking level is overridden per configuration, and a
  channel-specific safety-settings block is injected on every request.
- **Multimodal input** — text + images (base64 data URLs, or remote http(s) images fetched
  server-side with SSRF protection).
- **Prefill compatibility** — trailing assistant messages are kept and completed
  (unclosed thinking-tag guard included), so SillyTavern-style presets work on models
  that reject them.
- **Automatic retry** — on upstream 429/50x and transient stream errors, with
  fixed-interval or linear-backoff strategy, SSE keep-alive heartbeats while waiting,
  and a strict never-retry-after-emitting guarantee.
- **Local API key auth** and a global **authenticated SOCKS5 proxy** option
  (`socks5://user:pass@host:port`) that applies to every upstream connection.

## Quick Start

1. Download the archive for your platform from
   [Releases](https://github.com/559889a/aps2api/releases) (or a CI debug artifact from
   the Actions page) and unpack it — you get the `aps2api` binary, `config.example.yaml`,
   and `model.json` side by side.
2. `config.example.yaml` → `config.yaml`; fill in `api_key` (the key **your own clients**
   will present) and at least one upstream channel:
   - **Express**: `express.api_key` + `express.project_id` (Vertex Express API key).
   - **Cookie**: `cookie.cookie` (full `document.cookie` string from
     console.cloud.google.com) + `cookie.project_id` + `cookie.experiment_flags`.
3. Run the binary. Verify: `curl http://127.0.0.1:8080/health` → `{"status":"ok"}`.
4. Point your client at `http://127.0.0.1:8080/v1` with your `api_key`.

### PC (Windows / Linux)

Direct authenticated proxy, or a local chaining entry — both are plain SOCKS5 URLs:

```yaml
# static residential exit with embedded credentials
socks5: "socks5://user:pass@residential-host:port"
# ...or a local proxy client's mixed/socks port
# socks5: "socks5://127.0.0.1:7890"
```

Comment the line out for a direct connection (a first-class mode: works out of the box
behind your own VPN/clash).

### Termux (Android)

The Termux build is a native `aarch64-linux-android` binary (bionic libc — not a glibc
Linux build). Ports are >1024; the binary reads `config.yaml`/`model.json` from its own
directory; Android has no `/etc/resolv.conf`, so DNS goes through the system resolver.

```bash
chmod +x aps2api
./aps2api                      # config.yaml + model.json live next to the binary

# keep it alive in the background (Android is aggressive about killing background apps)
termux-wake-lock
# or run it as a termux-services service
```

On a phone you do not need any VPN app: put an authenticated SOCKS5 URL into the
`socks5:` field (e.g. `socks5://user:pass@your-home-exit:port`) and all upstream traffic
leaves from that static residential IP as long as the phone can reach the proxy entry.

## Configuration

All settings live in `config.yaml` next to the binary; see the heavily commented
[config.example.yaml](config.example.yaml). Highlights:

| Field | Meaning |
|-------|---------|
| `api_key` / `port` | local auth key and listen port (required) |
| `socks5` | global outbound SOCKS5 proxy (commented out = direct); supports `user:pass@` and `socks5h://` |
| `express.api_key` / `express.project_id` / `express.location` | Express channel credentials; keep `location: global` |
| `cookie.cookie` / `cookie.project_id` / `cookie.experiment_flags` | cookie channel credentials |
| `thinking_level` | forced thinking level: `minimal`/`low`/`medium`/`high`, empty = family defaults |
| `retry.max` / `retry.strategy` / `retry.interval` | retry count (`max+1` attempts total), `fixed`/`backoff`, fixed interval seconds |

Exposed models come from `model.json` (`models` list + optional `alias_map` for
request-name → real-model rewriting).

DNS resolution for proxied connections is performed by the proxy library at connect time
(local resolution, standard SOCKS5 behavior for reqwest/tokio-socks).

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | liveness probe, no auth |
| GET | `/v1/models` | OpenAI-style model list (from `model.json`) |
| POST | `/v1/chat/completions` | OpenAI chat completions, `stream: true/false` |
| GET | `/v1beta/models` | Gemini-style model list |
| GET | `/v1beta/models/{model}` | single model info |
| POST | `/v1beta/models/{model}:generateContent` | Gemini generate (JSON) |
| POST | `/v1beta/models/{model}:streamGenerateContent` | Gemini streaming (SSE; `?alt=sse` accepted and ignored) |

Auth for every endpoint except `/health`: `Authorization: Bearer <api_key>` or
`x-goog-api-key: <api_key>`.

## Project Structure

```
aps2api/
├── Cargo.toml               # pinned dependencies (spec appendix C.2 discipline)
├── config.example.yaml      # all-empty commented config template
├── model.json               # default three-model example list
├── .github/workflows/ci.yml # fmt/clippy/test + three-platform debug builds
└── src/
    ├── main.rs              # boot: load config + model list, axum serve, request log
    ├── config.rs            # config.yaml / model.json loading and validation
    └── auth.rs              # local API key middleware (Bearer / x-goog-api-key)
```

## License

MIT — see [LICENSE](LICENSE).

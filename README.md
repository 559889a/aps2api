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
- **Non-streaming over streaming-only upstreams** — the cookie channel has no
  non-streaming endpoint, so non-streaming requests are served by aggregating its SSE
  stream server-side; and an optional **bypass / fake-streaming mode** exposes
  `fake-streaming/express/<model>` aliases: the client gets a real SSE stream with
  keep-alive heartbeats during the silent wait, while the upstream runs as a single
  non-streaming call whose complete answer is replayed in one burst.
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
Linux build). It links against `libc++_shared.so`, which Termux provides through its
`libc++` package — install that once before the first run. Ports are >1024; the binary
reads `config.yaml`/`model.json` from its own directory; Android has no
`/etc/resolv.conf`, so DNS goes through the system resolver.

```bash
pkg install libc++              # provides libc++_shared.so required by the binary
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
| `bypass` | fake-streaming aliases: when `true`, `fake-streaming/express/<model>` ids are listed and served (SSE to the client, non-streaming to the express upstream, heartbeat-bridged); default `false` |
| `retry.max` / `retry.strategy` / `retry.interval` | retry count (`max+1` attempts total), `fixed`/`backoff`, fixed interval seconds |

Exposed models come from `model.json` (`models` list + optional `alias_map` for
request-name → real-model rewriting).

DNS resolution for proxied connections is always performed by the PROXY (socks5h
semantics — `socks5://` is normalized internally): the device's own resolver never
participates in upstream routing, which both keeps the fixed-exit disguise airtight and
avoids broken/polluted local DNS. Verified against a local chaining entry where local
resolution fails entirely and proxy-side resolution works.

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | liveness probe, no auth |
| GET | `/v1/models` | OpenAI-style model list (`model.json` plus `express/`- and `cookie/`-prefixed forms, and `fake-streaming/express/` aliases when `bypass: true`) |
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
├── Cargo.toml                       # pinned dependencies (appendix C.2 discipline)
├── config.example.yaml              # all-empty commented config template
├── model.json                       # default model list (models + alias_map)
├── .github/workflows/ci.yml         # fmt/clippy/test + three-platform debug builds
├── .github/workflows/release.yml    # tag-triggered three-platform release packaging
├── .github/workflows/debug-build.yml # manual three-platform debug artifacts (pre-release smoke)
├── examples/
│   └── tls_check.rs                 # TLS-fingerprint self-check vs a real Chrome (C.4)
└── src/
    ├── main.rs                      # boot: load config + model list, axum serve, route assembly
    ├── app.rs                       # AppState assembly: config + model list + outbound clients
    ├── auth.rs                      # local API key middleware (Bearer / x-goog-api-key)
    ├── config.rs                    # config.yaml / model.json loading and validation
    ├── errs.rs                      # upstream error taxonomy (§14) + user-facing hints
    ├── gemini_port/
    │   ├── mod.rs                   # /v1beta dispatch: prefix stripping, %2F decode, routes
    │   ├── parse.rs                 # Gemini request normalization -> ir (§10.2)
    │   └── emit.rs                  # events -> SSE chunks / aggregated response (§10.3)
    ├── httpx.rs                     # outbound clients: reqwest (express) + wreq (cookie), socks5h
    ├── images.rs                    # remote image fetch with SSRF protection (§9.3)
    ├── ir.rs                        # internal representation + unified event stream (§4)
    ├── modelcaps.rs                 # model capability profiles + level clamp (§3)
    ├── oai/
    │   ├── mod.rs                   # /v1 routes: model list + chat completions (§9)
    │   ├── parse.rs                 # OAI request -> ir (§9.2)
    │   └── emit.rs                  # events -> OAI SSE chunks / chat.completion JSON (§9.4)
    ├── pipeline.rs                  # shared retry loop: emitted guard, budget, disconnect (§12)
    ├── prefill.rs                   # prefill engine: nudge, CoT guard, deduper (§11)
    ├── rewrite.rs                   # outbound payload rewrite matrix + safety injection (§8)
    ├── retry.rs                     # backoff/fixed waits + SSE keep-alive heartbeats (§12.4)
    ├── sapisid.rs                   # cookie parsing, validation, SAPISIDHASH x3 (§7.1)
    ├── streamscan.rs                # bracket-balanced streaming JSON extractor (§13.1)
    └── channels/
        ├── mod.rs                   # client enum-dispatch + unified event extraction (§13.2)
        ├── express.rs               # express channel: native Gemini REST (§5)
        └── cookie.rs                # cookie channel: wreq Chrome149 masquerade (§6/§7)
```

## License

MIT — see [LICENSE](LICENSE).

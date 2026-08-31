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
  context). Pick a channel per request with an `express/` or `cookie/` model-name
  prefix — honored on **both** the OpenAI and the Gemini-native endpoint.
- **Payload rebuilding (never pass-through)** — penalty parameters, `top_k`, and
  `max_tokens` are stripped, thinking level is overridden per configuration, and a
  channel-specific safety-settings block is injected on every request.
- **Multimodal input** — text + images (base64 data URLs, or remote http(s) images fetched
  server-side with SSRF protection).
- **Prefill compatibility** — trailing assistant messages are kept and completed
  (unclosed thinking-tag guard included), so SillyTavern-style presets work on models
  that reject them; the response side stitches the prefill back so the client sees one
  continuous completion.
- **Thought/reasoning transparency** — model thinking survives intact: separate
  `reasoning_content` on the OpenAI endpoint, `thought: true` parts on the Gemini
  endpoint. A stream that ends without any visible content gets a clear diagnostic
  message instead of a silent empty reply.
- **Automatic retry** — on upstream 429/50x and transient stream errors, with
  fixed-interval or linear-backoff strategy, SSE keep-alive heartbeats while waiting,
  and a strict never-retry-after-emitting guarantee.
- **Observable by design** — every retry is a `WARN` log line with its reason and
  backoff, every successful response logs time-to-first-token plus the gateway's own
  prep cost, and each finished stream gets a one-line summary with total time and
  tokens/TPS (estimated on channels that don't report usage). See [Logging](#logging).
- **Non-streaming over streaming-only upstreams** — the cookie channel has no
  non-streaming endpoint, so non-streaming requests are served by aggregating its SSE
  stream server-side; and an optional **bypass / fake-streaming mode** exposes
  `fake-streaming/express/<model>` aliases: the client gets a real SSE stream with
  keep-alive heartbeats during the silent wait, while the upstream runs as a single
  non-streaming call whose complete answer is replayed in one burst.
- **Cookie auto-refresh** — the cookie channel harvests `Set-Cookie` rewrites from
  every upstream response into a runtime jar (persisted to `cookie.jar.yaml` next to
  the binary), so short-lived Google credentials keep rolling without ever
  re-copying cookies by hand; an auth failure that arrived while credentials were
  rolling is retried once on the refreshed jar automatically. Opt out with
  `cookie.auto_refresh: false`.
- **Local API key auth** and a global **authenticated SOCKS5 proxy** option
  (`socks5://user:pass@host:port`) that applies to every upstream connection —
  plus an optional **chained egress** (`socks5_transit`): an in-process loopback
  SOCKS5 bridge forwards transit → remote exit, so the fixed-IP egress keeps
  working even while the device's VPN/TUN is on.

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

# Chained egress (optional): first hop through the local proxy client while
# the remote exit stays the egress. Works even under TUN mode — see below.
# socks5_transit: "socks5://127.0.0.1:7890"
```

Comment the line out for a direct connection (a first-class mode: works out of the box
behind your own VPN/clash).

**TUN-mode clash users, read this before blaming the proxy.** If you point `socks5:`
at a remote proxy entry (e.g. your static residential exit) while a clash/mihomo TUN
mode is active, the TUN stack captures the TCP connection **to that entry** — the
connection never reaches the node, and every upstream request fails as a transport
error, even though the exact same config works the moment TUN is off. Loopback
entries are exempt (traffic to 127.0.0.1 does not enter the TUN), which is why the
local chaining form below keeps working under TUN. Fixes, in order of preference:

1. Set `socks5_transit: "socks5://127.0.0.1:7890"` (your proxy client's local
   mixed/socks port) alongside `socks5` (the remote exit). aps2api then dials the
   exit **through** the local proxy client via an in-process loopback SOCKS5
   bridge — the loopback hop is invisible to TUN, the remote exit still does the
   username/password auth, and DNS still resolves at the exit. This is the
   recommended form: it needs no proxy-client routing rules and works on the
   phone (FlClash/always-on VPN) exactly like on the desktop.
2. Keep `socks5: "socks5://127.0.0.1:7897"` (local chaining) and configure the
   proxy client itself to forward to the remote node.
3. Or add a DIRECT routing rule for the remote entry's IP in your proxy client, so
   connections to the entry bypass the TUN.
4. Or turn TUN off for this machine.

At boot the server probes the configured entry with a full SOCKS5 handshake
(method negotiation, username/password auth, one CONNECT through the exit to a
neutral address — a bare TCP open, no application data) and logs a
`WARN socks5 proxy entry failed the handshake probe` line when any stage fails.
The error text names the failing stage, which maps onto the checklist: "TCP
connects but the peer is not a SOCKS5 server" means the connection is being
intercepted or misrouted (TUN / wrong port); "username/password rejected" means
the credentials in the url; "CONNECT through the exit failed" means the entry is
up but the exit node is dead. Check the first seconds of the log before
debugging anything else. The probe is advisory only: it never blocks startup,
and an entry that whitelists your deployment machine's IP may still be flagged
on other machines.

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

If the phone runs an always-on VPN client (FlClash etc.) that the residential entry
cannot be reached through directly, add one line — the VPN client's local port as the
transit — and aps2api chains internally: loopback bridge → VPN client → your exit:

```yaml
socks5: "socks5://user:pass@your-home-exit:port"
socks5_transit: "socks5://127.0.0.1:7890"   # the VPN client's local mixed/socks port
```

## Configuration

All settings live in `config.yaml` next to the binary; see the heavily commented
[config.example.yaml](config.example.yaml). Highlights:

| Field | Meaning |
|-------|---------|
| `api_key` / `port` | local auth key and listen port (required) |
| `socks5` | global outbound SOCKS5 proxy (commented out = direct); supports `user:pass@` and `socks5h://` |
| `socks5_transit` | chained egress first hop (local proxy client port, e.g. `socks5://127.0.0.1:7890`); requires `socks5` — traffic then goes transit → remote exit through the in-process loopback bridge, immune to TUN/VPN takeover |
| `express.api_key` / `express.project_id` / `express.location` | Express channel credentials; keep `location: global` |
| `cookie.cookie` / `cookie.project_id` / `cookie.experiment_flags` | cookie channel credentials |
| `cookie.auto_refresh` | cookie auto-refresh (default `true`): harvest `Set-Cookie` rewrites into a jar persisted to `cookie.jar.yaml`; `false` freezes the startup string |
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

`{model}` may carry an `express/` or `cookie/` channel prefix on both the OpenAI and
the Gemini-native endpoint (and `fake-streaming/express/` bypass aliases when
`bypass: true`), e.g. `cookie/gemini-3.6-flash:streamGenerateContent`.

Auth for every endpoint except `/health`: `Authorization: Bearer <api_key>` or
`x-goog-api-key: <api_key>`.

## Logging

The server logs to stdout at `info` level by default (override with `RUST_LOG`, e.g.
`RUST_LOG=aps2api=debug,info`). A request is fully visible in five log lines:

| Log line | Level | Meaning |
|----------|-------|---------|
| `chat completion` / `gemini generate` | INFO | request accepted: `model`, `channel`, `stream`, `bypass` |
| `upstream attempt failed; retrying` | WARN | a retry was scheduled: `retry`/`max` within the budget, `delay_secs` backoff, failure reason |
| `upstream first response` | INFO | first token arrived: `ttfb_ms` (per attempt, reset on retry) and `prep_us` — the gateway's own pre-upstream cost (request received → dispatched), measured once on the first attempt |
| `stream complete` | INFO | the stream ended normally: `total_s` wall clock, `gen_s` first-token→end window, `retries` consumed, and output size/speed — `tokens`/`tps` when the upstream reports usage (express), `tokens_est`/`tps_est` when it does not (cookie) |
| `bypass complete` | INFO | a fake-streaming bypass request finished: `total_s` from request receipt to the completed upstream call, `prep_us`, `retries` (bypass has no first token to time, so there is no `upstream first response` line) |
| `upstream failed (...); returning the error to the client` | ERROR | terminal failure and its class: non-retryable, content-already-emitted (never-retry guarantee), or retry budget exhausted |

Notes:

- `tokens_est`/`tps_est` are ballpark estimates (~4 ASCII chars or ~1 non-ASCII char
  per token, thinking text included) for channels whose upstream never returns usage
  metadata — the `_est` suffix marks them as estimates, and real usage always wins
  when present. They are deliberately not comparable to a client-side tokenizer count.
- Fake-streaming bypass requests log no `upstream first response` and no
  `stream complete` (their upstream is a single non-streaming call with no first
  token); they log `bypass complete` instead.
- Non-streaming requests log `upstream first response` (the first aggregated event is
  the first token) but no summary line.
- The `prep_us` clock starts at handler entry and includes reading and JSON-parsing
  the request body on **both** ports (the OpenAI endpoint reads its body inside the
  handler for exactly this reason), so the readings are directly comparable across
  the two ports. Text chats read in the hundreds-of-microseconds range; single-digit
  milliseconds point at multi-MB base64 payloads.

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
    ├── cookiejar.rs                 # cookie auto-refresh jar: Set-Cookie merge + persistence (§7.4)
    ├── errs.rs                      # upstream error taxonomy (§14) + user-facing hints
    ├── gemini_port/
    │   ├── mod.rs                   # /v1beta dispatch: %2F decode, prefix pass-through, routes
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
    ├── proxybridge.rs               # chained-egress loopback SOCKS5 bridge: transit -> remote exit (§2.2)
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

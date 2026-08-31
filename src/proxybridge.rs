//! Chained-egress SOCKS5 bridge (spec §2.2 / §4) — `socks5_transit`.
//!
//! Why: a TUN-mode VPN client (clash / mihomo / FlClash) captures TCP to
//! PUBLIC addresses — including the connection this gateway opens to its
//! remote SOCKS5 exit — so a directly configured remote exit dies under TUN
//! even though the identical config works with TUN off (owner field reports
//! 2026-08-30/31). Loopback is exempt from TUN on every platform we ship
//! (Windows / Linux / Android VpnService). When `socks5_transit` is set,
//! upstream traffic is therefore chained in-process:
//!
//!   client (reqwest / wreq) → loopback bridge (this module, 127.0.0.1:ephemeral)
//!   → transit (first hop: the VPN client's local mixed/socks port)
//!   → socks5 exit (`socks5`, authenticated, the static residential IP)
//!   → target (domain passthrough: DNS still resolves at the exit)
//!
//! Invariants:
//! - The bridge binds 127.0.0.1 only; the exit keeps doing username/password
//!   auth; the last hop is byte-identical to the non-chained mode, so the
//!   fixed-exit disguise (spec §1.4) is preserved.
//! - Any chain stage failing replies SOCKS5 general failure to the local
//!   client, which both HTTP stacks surface as a connect error → retryable
//!   transport error (spec §12.1); the bridge logs a WARN naming the stage.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Per-stage timeout for TCP connects and every SOCKS5 handshake step. The
/// HTTP clients' own 30s connect timeout bounds the whole chain; this bounds
/// each hop so a stuck hop surfaces as a failure instead of silently eating
/// the entire budget.
const STEP: Duration = Duration::from_secs(10);

/// A parsed socks5:// / socks5h:// endpoint with optional embedded
/// credentials. The two schemes are identical here: WE dial the entry, so
/// the client-side socks5/socks5h DNS distinction never applies.
#[derive(Debug, Clone)]
pub struct SocksEndpoint {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
}

impl SocksEndpoint {
    pub fn parse(url: &str) -> Result<Self, String> {
        let parsed = reqwest::Url::parse(url).map_err(|e| format!("invalid proxy url: {e}"))?;
        match parsed.scheme() {
            "socks5" | "socks5h" => {}
            other => {
                return Err(format!(
                    "proxy url must be socks5:// or socks5h:// (got {other:?})"
                ))
            }
        }
        let host = parsed
            .host_str()
            .ok_or_else(|| "proxy url has no host".to_string())?
            .to_string();
        if host.is_empty() {
            return Err("proxy url has no host".to_string());
        }
        let port = parsed
            .port()
            .ok_or_else(|| "proxy url has no port".to_string())?;
        let username = decode_url_part(parsed.username());
        let password = decode_url_part(parsed.password().unwrap_or(""));
        Ok(SocksEndpoint {
            host,
            port,
            username,
            password,
        })
    }

    fn addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    fn has_creds(&self) -> bool {
        !self.username.is_empty() || !self.password.is_empty()
    }
}

/// Percent-decode a URL userinfo part (username/password); undecodable input
/// passes through raw rather than failing over an edge case.
fn decode_url_part(raw: &str) -> String {
    percent_encoding::percent_decode_str(raw)
        .decode_utf8()
        .map(|c| c.into_owned())
        .unwrap_or_else(|_| raw.to_string())
}

/// One SOCKS5 chain-stage failure, before any endpoint-specific phrasing.
#[derive(Debug)]
enum StageError {
    ConnectTimeout,
    Connect(String),
    NotSocks5(u8),
    AuthRequiredNoCreds,
    CredsTooLong,
    DomainTooLong,
    AuthRejected(u8),
    NoAcceptableMethod(u8),
    ConnectRefused(u8),
    MalformedReply(u8),
    WriteTimeout,
    WriteIo(String),
    ReadTimeout,
    ReadIo(String),
}

impl std::fmt::Display for StageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Exit-side phrasing; transit-specific overrides live in
        // transit_error. Keep these aligned with the probe checklist in the
        // README (each names one diagnosable failure mode).
        match self {
            StageError::ConnectTimeout => write!(f, "connect timed out after 10s"),
            StageError::Connect(e) => write!(f, "{e}"),
            StageError::NotSocks5(b) => write!(
                f,
                "TCP connects but the peer is not a SOCKS5 server (version byte {b:#04x}) — \
                 likely intercepted or misrouted (TUN?)"
            ),
            StageError::AuthRequiredNoCreds => write!(
                f,
                "SOCKS5 server requires username/password auth but the url has none"
            ),
            StageError::CredsTooLong => {
                write!(f, "proxy credentials exceed the SOCKS5 field limit")
            }
            StageError::DomainTooLong => {
                write!(
                    f,
                    "target domain exceeds the SOCKS5 field limit (255 bytes)"
                )
            }
            StageError::AuthRejected(s) => {
                write!(f, "SOCKS5 username/password rejected (status {s})")
            }
            StageError::NoAcceptableMethod(m) => {
                write!(f, "SOCKS5 server refused our auth methods (reply {m:#04x})")
            }
            StageError::ConnectRefused(r) => write!(
                f,
                "SOCKS5 CONNECT through the exit failed (reply {r:#04x}) — likely a dead or \
                 expired exit node"
            ),
            StageError::MalformedReply(a) => {
                write!(f, "malformed SOCKS5 CONNECT reply (ATYP {a:#04x})")
            }
            StageError::WriteTimeout => write!(f, "SOCKS5 handshake write timed out"),
            StageError::WriteIo(e) => write!(f, "SOCKS5 handshake write failed: {e}"),
            StageError::ReadTimeout => write!(f, "SOCKS5 handshake read timed out"),
            StageError::ReadIo(e) => write!(f, "SOCKS5 handshake read failed: {e}"),
        }
    }
}

/// Exit-stage phrasing: "{addr}: {stage}".
fn exit_error(addr: &str, e: StageError) -> String {
    format!("{addr}: {e}")
}

/// Transit-stage phrasing: same stages, transit-specific diagnosis on the
/// two failure shapes whose causes differ (not-a-SOCKS5 → wrong local port;
/// CONNECT refused → the VPN client routes the exit DIRECT, i.e. from a
/// network where the exit is unreachable, or its node is down).
fn transit_error(addr: &str, e: StageError) -> String {
    match e {
        StageError::NotSocks5(b) => format!(
            "transit {addr}: TCP connects but the peer is not a SOCKS5 server (version byte \
             {b:#04x}) — wrong port? an http-only proxy port answers differently"
        ),
        StageError::ConnectRefused(r) => format!(
            "transit {addr}: CONNECT to the exit failed (reply {r:#04x}) — the transit may be \
             routing the exit DIRECT (unreachable from its network) or its node is down"
        ),
        other => format!("transit {addr}: {other}"),
    }
}

async fn write_step(stream: &mut TcpStream, buf: &[u8]) -> Result<(), StageError> {
    tokio::time::timeout(STEP, stream.write_all(buf))
        .await
        .map_err(|_| StageError::WriteTimeout)?
        .map_err(|e| StageError::WriteIo(e.to_string()))
}

async fn read_step(stream: &mut TcpStream, buf: &mut [u8]) -> Result<(), StageError> {
    // read_exact yields Result<usize, _>; the tail must map to the () shape.
    tokio::time::timeout(STEP, stream.read_exact(buf))
        .await
        .map_err(|_| StageError::ReadTimeout)?
        .map_err(|e| StageError::ReadIo(e.to_string()))?;
    Ok(())
}

async fn tcp_connect(ep: &SocksEndpoint) -> Result<TcpStream, StageError> {
    match tokio::time::timeout(STEP, TcpStream::connect(ep.addr())).await {
        Err(_) => Err(StageError::ConnectTimeout),
        Ok(Err(e)) => Err(StageError::Connect(e.to_string())),
        Ok(Ok(s)) => Ok(s),
    }
}

/// Encode a SOCKS5 CONNECT request. IP literals go out as ATYP 1/4; domains
/// pass through as ATYP 3 so DNS resolves on the far side (spec §1.4).
fn encode_connect(host: &str, port: u16) -> Result<Vec<u8>, StageError> {
    let trimmed = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    let mut req = vec![0x05u8, 0x01, 0x00];
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => {
                req.push(0x01);
                req.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                req.push(0x04);
                req.extend_from_slice(&v6.octets());
            }
        }
    } else {
        let bytes = trimmed.as_bytes();
        if bytes.len() > 255 {
            return Err(StageError::DomainTooLong);
        }
        req.push(0x03);
        req.push(bytes.len() as u8);
        req.extend_from_slice(bytes);
    }
    req.extend_from_slice(&port.to_be_bytes());
    Ok(req)
}

/// Speak the CLIENT side of SOCKS5 to the stream's peer: method negotiation
/// (username/password auth when the endpoint has credentials), then CONNECT
/// to `target_host:target_port`. Drains the whole CONNECT reply so the
/// stream handed back to the caller starts clean at the application layer.
async fn socks_handshake(
    stream: &mut TcpStream,
    ep: &SocksEndpoint,
    target_host: &str,
    target_port: u16,
) -> Result<(), StageError> {
    let has_creds = ep.has_creds();
    let mut greeting = vec![0x05u8, 0x01, 0x00];
    if has_creds {
        greeting[1] = 0x02;
        greeting.push(0x02);
    }
    write_step(stream, &greeting).await?;

    let mut reply = [0u8; 2];
    read_step(stream, &mut reply).await?;
    if reply[0] != 0x05 {
        return Err(StageError::NotSocks5(reply[0]));
    }
    match reply[1] {
        0x00 => {}
        0x02 => {
            if !has_creds {
                return Err(StageError::AuthRequiredNoCreds);
            }
            if ep.username.len() > 255 || ep.password.len() > 255 {
                return Err(StageError::CredsTooLong);
            }
            let mut auth = vec![0x01u8, ep.username.len() as u8];
            auth.extend_from_slice(ep.username.as_bytes());
            auth.push(ep.password.len() as u8);
            auth.extend_from_slice(ep.password.as_bytes());
            write_step(stream, &auth).await?;
            let mut auth_reply = [0u8; 2];
            read_step(stream, &mut auth_reply).await?;
            if auth_reply[1] != 0x00 {
                return Err(StageError::AuthRejected(auth_reply[1]));
            }
        }
        other => return Err(StageError::NoAcceptableMethod(other)),
    }

    let request = encode_connect(target_host, target_port)?;
    write_step(stream, &request).await?;

    let mut head = [0u8; 4];
    read_step(stream, &mut head).await?;
    if head[1] != 0x00 {
        return Err(StageError::ConnectRefused(head[1]));
    }
    // Drain BND.ADDR + BND.PORT (ATYP-prefixed) so no reply bytes leak into
    // the application byte stream.
    let tail_len = match head[3] {
        0x01 => 4 + 2,
        0x04 => 16 + 2,
        0x03 => {
            let mut len = [0u8; 1];
            read_step(stream, &mut len).await?;
            len[0] as usize + 2
        }
        other => return Err(StageError::MalformedReply(other)),
    };
    let mut tail = vec![0u8; tail_len];
    read_step(stream, &mut tail).await?;
    Ok(())
}

/// Dial `target_host:target_port` through the egress chain and return the
/// connected stream. With `transit` the chain is transit → exit (the bridge
/// path); without it the exit is dialed directly (the pre-bridge behavior).
pub async fn dial_via_chain(
    transit: Option<&SocksEndpoint>,
    exit: &SocksEndpoint,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream, String> {
    let mut stream = match transit {
        Some(t) => {
            let mut s = tcp_connect(t)
                .await
                .map_err(|e| transit_error(&t.addr(), e))?;
            // Through the transit, CONNECT to the exit itself — the exit's
            // hostname (if any) resolves on the transit side.
            socks_handshake(&mut s, t, &exit.host, exit.port)
                .await
                .map_err(|e| transit_error(&t.addr(), e))?;
            s
        }
        None => tcp_connect(exit)
            .await
            .map_err(|e| exit_error(&exit.addr(), e))?,
    };
    socks_handshake(&mut stream, exit, target_host, target_port)
        .await
        .map_err(|e| exit_error(&exit.addr(), e))?;
    Ok(stream)
}

/// Bind the loopback bridge and spawn its accept loop; returns the bound
/// port. Must be called inside the tokio runtime. The accept task lives for
/// the whole process; per-connection chain failures reply SOCKS5 general
/// failure (the HTTP stacks turn that into a connect error → retryable
/// transport error, spec §12.1) and log a WARN naming the failing stage.
pub fn spawn_bridge(transit_url: &str, exit_url: &str) -> Result<u16, String> {
    let transit = SocksEndpoint::parse(transit_url).map_err(|e| format!("socks5_transit: {e}"))?;
    let exit = SocksEndpoint::parse(exit_url).map_err(|e| format!("socks5: {e}"))?;
    spawn_bridge_ep(&transit, &exit)
}

fn spawn_bridge_ep(transit: &SocksEndpoint, exit: &SocksEndpoint) -> Result<u16, String> {
    let std_listener = std::net::TcpListener::bind("127.0.0.1:0")
        .map_err(|e| format!("proxy bridge cannot bind loopback: {e}"))?;
    std_listener
        .set_nonblocking(true)
        .map_err(|e| format!("proxy bridge cannot switch to non-blocking: {e}"))?;
    let listener = TcpListener::from_std(std_listener)
        .map_err(|e| format!("proxy bridge cannot register its listener: {e}"))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("proxy bridge local_addr: {e}"))?
        .port();
    tracing::info!(
        listen = %format!("127.0.0.1:{port}"),
        transit = %transit.addr(),
        exit = %exit.addr(),
        "proxy bridge up: outbound clients → loopback bridge → transit → socks5 exit"
    );
    let transit = Arc::new(transit.clone());
    let exit = Arc::new(exit.clone());
    tokio::spawn(accept_loop(listener, transit, exit));
    Ok(port)
}

async fn accept_loop(listener: TcpListener, transit: Arc<SocksEndpoint>, exit: Arc<SocksEndpoint>) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let transit = transit.clone();
                let exit = exit.clone();
                tokio::spawn(async move {
                    if let Err(e) = serve_conn(stream, &transit, &exit).await {
                        tracing::debug!(error = %e, "proxy bridge connection ended with an error");
                    }
                });
            }
            Err(e) => {
                // Transient (EMFILE etc.): back off briefly and keep serving.
                tracing::warn!(error = %e, "proxy bridge accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

/// Serve one loopback SOCKS5 client: no-auth greeting → CONNECT → chain dial
/// → bidirectional splice. Only CONNECT is supported (the HTTP clients never
/// send BIND/UDP). Every read is bounded by the protocol itself (greeting
/// ≤ 2+255 bytes, request ≤ 4+1+255+2) and by STEP timeouts.
async fn serve_conn(
    mut client: TcpStream,
    transit: &SocksEndpoint,
    exit: &SocksEndpoint,
) -> Result<(), String> {
    // Greeting: pick no-auth when offered.
    let mut hdr = [0u8; 2];
    read_step(&mut client, &mut hdr)
        .await
        .map_err(|e| format!("client greeting: {e}"))?;
    if hdr[0] != 0x05 {
        return Err(format!("client speaks version {:#04x}, not SOCKS5", hdr[0]));
    }
    let mut methods = vec![0u8; hdr[1] as usize];
    read_step(&mut client, &mut methods)
        .await
        .map_err(|e| format!("client greeting: {e}"))?;
    if !methods.contains(&0x00) {
        let _ = client.write_all(&[0x05, 0xFF]).await;
        return Err("client offered no no-auth method".to_string());
    }
    write_step(&mut client, &[0x05, 0x00])
        .await
        .map_err(|e| format!("client greeting reply: {e}"))?;

    // CONNECT request: [VER, CMD, RSV, ATYP, ADDR, PORT].
    let mut rhead = [0u8; 4];
    read_step(&mut client, &mut rhead)
        .await
        .map_err(|e| format!("client request: {e}"))?;
    if rhead[0] != 0x05 {
        return Err(format!("client request version {:#04x}", rhead[0]));
    }
    if rhead[1] != 0x01 {
        let _ = reply(&mut client, 0x07).await; // command not supported
        return Err(format!(
            "client sent command {:#04x}; only CONNECT is supported",
            rhead[1]
        ));
    }
    let target_host = match rhead[3] {
        0x01 => {
            let mut b = [0u8; 4];
            read_step(&mut client, &mut b)
                .await
                .map_err(|e| format!("client request addr: {e}"))?;
            std::net::Ipv4Addr::from(b).to_string()
        }
        0x04 => {
            let mut b = [0u8; 16];
            read_step(&mut client, &mut b)
                .await
                .map_err(|e| format!("client request addr: {e}"))?;
            std::net::Ipv6Addr::from(b).to_string()
        }
        0x03 => {
            let mut len = [0u8; 1];
            read_step(&mut client, &mut len)
                .await
                .map_err(|e| format!("client request addr: {e}"))?;
            let mut d = vec![0u8; len[0] as usize];
            read_step(&mut client, &mut d)
                .await
                .map_err(|e| format!("client request addr: {e}"))?;
            String::from_utf8_lossy(&d).into_owned()
        }
        other => {
            let _ = reply(&mut client, 0x08).await; // address type not supported
            return Err(format!("client CONNECT ATYP {other:#04x} not supported"));
        }
    };
    let mut pbuf = [0u8; 2];
    read_step(&mut client, &mut pbuf)
        .await
        .map_err(|e| format!("client request port: {e}"))?;
    let target_port = u16::from_be_bytes(pbuf);
    let target = format!("{target_host}:{target_port}");

    match dial_via_chain(Some(transit), exit, &target_host, target_port).await {
        Ok(mut upstream) => {
            reply(&mut client, 0x00)
                .await
                .map_err(|e| format!("client reply: {e}"))?;
            if let Err(e) = tokio::io::copy_bidirectional(&mut client, &mut upstream).await {
                tracing::debug!(error = %e, "proxy bridge splice ended with an error");
            }
            Ok(())
        }
        Err(stage) => {
            tracing::warn!(target = %target, error = %stage, "proxy bridge: chain dial failed");
            let _ = reply(&mut client, 0x01).await; // general SOCKS server failure
            Ok(())
        }
    }
}

/// One SOCKS5 CONNECT reply with the given code; the bound address is
/// meaningless for a bridge and is filled with 0.0.0.0:0.
async fn reply(client: &mut TcpStream, code: u8) -> Result<(), StageError> {
    write_step(client, &[0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Records every CONNECT target a fake endpoint served.
    type Seen = Arc<Mutex<Vec<String>>>;

    // ---- test infrastructure -------------------------------------------

    /// Minimal SOCKS5 server: no-auth, or username/password auth (verified
    /// byte-for-byte). After CONNECT it replies success and splices to the
    /// real target — or, with `override_target`, to a fixed address (for
    /// targets that are unresolvable test domains) while still recording the
    /// requested one.
    async fn spawn_fake_socks(
        creds: Option<(String, String)>,
        override_target: Option<std::net::SocketAddr>,
    ) -> (std::net::SocketAddr, Seen) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen: Seen = Arc::new(Mutex::new(Vec::new()));
        let seen_task = seen.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    continue;
                };
                let creds = creds.clone();
                let override_target = override_target;
                let seen = seen_task.clone();
                tokio::spawn(async move {
                    let _ = fake_socks_serve(&mut stream, creds, override_target, &seen).await;
                });
            }
        });
        (addr, seen)
    }

    async fn fake_socks_serve(
        s: &mut TcpStream,
        creds: Option<(String, String)>,
        override_target: Option<std::net::SocketAddr>,
        seen: &Seen,
    ) -> std::io::Result<()> {
        // Greeting.
        let mut hdr = [0u8; 2];
        s.read_exact(&mut hdr).await?;
        let mut methods = vec![0u8; hdr[1] as usize];
        s.read_exact(&mut methods).await?;
        match creds {
            Some((user, pass)) => {
                s.write_all(&[0x05, 0x02]).await?;
                let mut v = [0u8; 2]; // [auth version, username length]
                s.read_exact(&mut v).await?;
                let mut ub = vec![0u8; v[1] as usize];
                s.read_exact(&mut ub).await?;
                let mut pl = [0u8; 1];
                s.read_exact(&mut pl).await?;
                let mut pb = vec![0u8; pl[0] as usize];
                s.read_exact(&mut pb).await?;
                let ok = ub == user.as_bytes() && pb == pass.as_bytes();
                s.write_all(&[0x01, u8::from(!ok)]).await?;
                if !ok {
                    return Ok(());
                }
            }
            None => {
                s.write_all(&[0x05, 0x00]).await?;
            }
        }
        // CONNECT.
        let mut rhead = [0u8; 4];
        s.read_exact(&mut rhead).await?;
        let host = match rhead[3] {
            0x01 => {
                let mut b = [0u8; 4];
                s.read_exact(&mut b).await?;
                std::net::Ipv4Addr::from(b).to_string()
            }
            0x04 => {
                let mut b = [0u8; 16];
                s.read_exact(&mut b).await?;
                std::net::Ipv6Addr::from(b).to_string()
            }
            0x03 => {
                let mut n = [0u8; 1];
                s.read_exact(&mut n).await?;
                let mut d = vec![0u8; n[0] as usize];
                s.read_exact(&mut d).await?;
                String::from_utf8(d).unwrap()
            }
            other => panic!("fake socks: unsupported ATYP {other:#04x}"),
        };
        let mut p = [0u8; 2];
        s.read_exact(&mut p).await?;
        let port = u16::from_be_bytes(p);
        seen.lock().unwrap().push(format!("{host}:{port}"));
        let target = override_target.unwrap_or_else(|| format!("{host}:{port}").parse().unwrap());
        match TcpStream::connect(target).await {
            Ok(mut upstream) => {
                s.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await?;
                let _ = tokio::io::copy_bidirectional(s, &mut upstream).await;
            }
            Err(_) => {
                let _ = s
                    .write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await;
            }
        }
        Ok(())
    }

    /// Canned HTTP/1.1 responder: answers "pong" once the request headers
    /// have been fully received.
    async fn spawn_http_pong() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = listener.accept().await else {
                    continue;
                };
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 512];
                    loop {
                        match s.read(&mut chunk).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                buf.extend_from_slice(&chunk[..n]);
                                if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 8192 {
                                    break;
                                }
                            }
                        }
                    }
                    let _ = s
                        .write_all(
                            b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: \
                             4\r\nconnection: close\r\n\r\npong",
                        )
                        .await;
                });
            }
        });
        addr
    }

    /// Minimal SOCKS5 client: no-auth greeting + domain CONNECT; returns the
    /// CONNECT reply code (0 = success).
    async fn socks5_connect(port: u16, host: &str, target_port: u16) -> u8 {
        let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut gr = [0u8; 2];
        s.read_exact(&mut gr).await.unwrap();
        assert_eq!(gr, [0x05, 0x00]);
        let mut req = vec![0x05u8, 0x01, 0x00, 0x03];
        req.push(host.len() as u8);
        req.extend_from_slice(host.as_bytes());
        req.extend_from_slice(&target_port.to_be_bytes());
        s.write_all(&req).await.unwrap();
        let mut head = [0u8; 4];
        s.read_exact(&mut head).await.unwrap();
        head[1]
    }

    fn endpoint(addr: std::net::SocketAddr, username: &str, password: &str) -> SocksEndpoint {
        SocksEndpoint {
            host: addr.ip().to_string(),
            port: addr.port(),
            username: username.to_string(),
            password: password.to_string(),
        }
    }

    // ---- endpoint parsing ----------------------------------------------

    #[test]
    fn parse_extracts_addr_and_percent_decoded_creds() {
        let ep = SocksEndpoint::parse("socks5://us%40r:p%40ss@10.0.0.1:1080").unwrap();
        assert_eq!(ep.host, "10.0.0.1");
        assert_eq!(ep.port, 1080);
        assert_eq!(ep.username, "us@r");
        assert_eq!(ep.password, "p@ss");
        assert!(ep.has_creds());

        let plain = SocksEndpoint::parse("socks5h://127.0.0.1:7890").unwrap();
        assert_eq!(plain.host, "127.0.0.1");
        assert_eq!(plain.port, 7890);
        assert!(!plain.has_creds());
    }

    #[test]
    fn parse_rejects_wrong_scheme_and_missing_port() {
        assert!(SocksEndpoint::parse("http://127.0.0.1:7890").is_err());
        assert!(SocksEndpoint::parse("socks5://host-without-port").is_err());
    }

    // ---- chain dialing -------------------------------------------------

    #[tokio::test]
    async fn direct_chain_passes_domains_to_the_exit() {
        tokio::time::timeout(Duration::from_secs(30), async {
            let echo = spawn_http_pong().await;
            let (exit_addr, exit_seen) =
                spawn_fake_socks(Some(("u".into(), "p".into())), Some(echo)).await;
            let exit = endpoint(exit_addr, "u", "p");

            let mut stream = dial_via_chain(None, &exit, "dom-passthrough.test", 81)
                .await
                .unwrap();
            stream
                .write_all(b"GET / HTTP/1.1\r\nhost: x\r\n\r\n")
                .await
                .unwrap();
            let mut buf = vec![0u8; 256];
            let n = stream.read(&mut buf).await.unwrap();
            let text = String::from_utf8_lossy(&buf[..n]).into_owned();
            assert!(text.ends_with("pong"), "unexpected echo: {text}");
            assert_eq!(exit_seen.lock().unwrap()[0], "dom-passthrough.test:81");
        })
        .await
        .expect("test timed out");
    }

    // ---- real-client interop through the bridge ------------------------
    // These two are the load-bearing tests for the zero-compile discipline:
    // they run the actual reqwest / wreq SOCKS5 client implementations
    // against the bridge, not a hand-rolled stand-in.

    #[tokio::test]
    async fn reqwest_through_the_bridge_chains_transit_and_exit() {
        tokio::time::timeout(Duration::from_secs(30), async {
            let echo = spawn_http_pong().await;
            let (exit_addr, exit_seen) =
                spawn_fake_socks(Some(("u-exit".into(), "p-exit".into())), Some(echo)).await;
            let (transit_addr, transit_seen) = spawn_fake_socks(None, None).await;
            let port = spawn_bridge_ep(
                &endpoint(transit_addr, "", ""),
                &endpoint(exit_addr, "u-exit", "p-exit"),
            )
            .unwrap();

            let client = reqwest::Client::builder()
                .no_proxy()
                .proxy(reqwest::Proxy::all(format!("socks5h://127.0.0.1:{port}")).unwrap())
                .build()
                .unwrap();
            let body = client
                .get("http://e2e-bridge.test/")
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap();
            assert_eq!(body, "pong");

            // The transit hop saw a CONNECT to the exit endpoint...
            assert_eq!(transit_seen.lock().unwrap().len(), 1);
            assert_eq!(transit_seen.lock().unwrap()[0], exit_addr.to_string());
            // ...and the exit hop received the DOMAIN: proxy-side DNS is
            // preserved through the whole chain.
            assert_eq!(exit_seen.lock().unwrap()[0], "e2e-bridge.test:80");
        })
        .await
        .expect("test timed out");
    }

    #[tokio::test]
    async fn wreq_through_the_bridge_round_trips() {
        tokio::time::timeout(Duration::from_secs(30), async {
            let echo = spawn_http_pong().await;
            let (exit_addr, _) =
                spawn_fake_socks(Some(("u-exit".into(), "p-exit".into())), Some(echo)).await;
            let (transit_addr, _) = spawn_fake_socks(None, None).await;
            let port = spawn_bridge_ep(
                &endpoint(transit_addr, "", ""),
                &endpoint(exit_addr, "u-exit", "p-exit"),
            )
            .unwrap();

            let client = wreq::Client::builder()
                .emulation(crate::channels::cookie::emulation())
                .proxy(wreq::Proxy::all(format!("socks5h://127.0.0.1:{port}")).unwrap())
                .build()
                .unwrap();
            let body = client
                .get("http://localhost/")
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap();
            assert_eq!(body, "pong");
        })
        .await
        .expect("test timed out");
    }

    // ---- failure paths --------------------------------------------------

    #[tokio::test]
    async fn dead_transit_fails_the_client_connect() {
        tokio::time::timeout(Duration::from_secs(30), async {
            let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let dead_port = dead.local_addr().unwrap().port();
            drop(dead);
            let (exit_addr, _) = spawn_fake_socks(None, None).await;
            let port = spawn_bridge_ep(
                &SocksEndpoint {
                    host: "127.0.0.1".into(),
                    port: dead_port,
                    username: String::new(),
                    password: String::new(),
                },
                &endpoint(exit_addr, "", ""),
            )
            .unwrap();
            let code = socks5_connect(port, "any.test", 80).await;
            assert_ne!(code, 0x00);
        })
        .await
        .expect("test timed out");
    }

    #[tokio::test]
    async fn rejected_exit_credentials_fail_the_client_connect() {
        tokio::time::timeout(Duration::from_secs(30), async {
            let echo = spawn_http_pong().await;
            // The exit demands (u, p); the bridge is configured with (u, WRONG).
            let (exit_addr, _) = spawn_fake_socks(Some(("u".into(), "p".into())), Some(echo)).await;
            let (transit_addr, _) = spawn_fake_socks(None, None).await;
            let port = spawn_bridge_ep(
                &endpoint(transit_addr, "", ""),
                &endpoint(exit_addr, "u", "WRONG"),
            )
            .unwrap();
            let code = socks5_connect(port, "any.test", 80).await;
            assert_ne!(code, 0x00);
        })
        .await
        .expect("test timed out");
    }
}

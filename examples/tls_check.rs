//! TLS-fingerprint self-check (spec appendix C.4, option 1): sends one GET
//! to a fingerprint echo service using a client built exactly like the cookie
//! channel's, then prints JA3/JA4/HTTP2 for comparison against a real Chrome.
//!
//! Usage: cargo run --example tls_check
//! Optional outbound proxy: TLS_CHECK_PROXY=socks5://127.0.0.1:7897

use wreq::Client;
use wreq_util::{Emulation, Platform, Profile};

#[tokio::main]
async fn main() -> wreq::Result<()> {
    // Keep in sync with src/channels/cookie.rs: pinned Chrome149 + Windows,
    // env-var proxy detection off, optional explicit socks5.
    let mut builder = Client::builder()
        .emulation(
            Emulation::builder()
                .profile(Profile::Chrome149)
                .platform(Platform::Windows)
                .build(),
        )
        .connect_timeout(std::time::Duration::from_secs(30))
        .no_proxy();
    if let Ok(url) = std::env::var("TLS_CHECK_PROXY") {
        builder = builder.proxy(wreq::Proxy::all(&url).expect("valid TLS_CHECK_PROXY url"));
    }
    let client = builder.build()?;

    let resp = client.get("https://tls.peet.ws/api/all").send().await?;
    let body: serde_json::Value = resp.json().await?;
    println!(
        "user_agent             = {}",
        body["user_agent"].as_str().unwrap_or("?")
    );
    println!(
        "ja3_hash               = {}",
        body["tls"]["ja3_hash"].as_str().unwrap_or("?")
    );
    println!(
        "ja4                    = {}",
        body["tls"]["ja4"].as_str().unwrap_or("?")
    );
    println!(
        "peetprint_hash         = {}",
        body["tls"]["peetprint_hash"].as_str().unwrap_or("?")
    );
    println!(
        "http2.akamai_fingerprint = {}",
        body["http2"]["akamai_fingerprint"].as_str().unwrap_or("?")
    );
    println!();
    println!("Reference: a real desktop Chrome shows ja4 = t13d151*h2_8daaf6152771_* and");
    println!("the same HTTP2 akamai fingerprint. A rustls/openssl fallback would differ far");
    println!("more (different cipher list hash entirely) — that is the downgrade red line.");
    Ok(())
}

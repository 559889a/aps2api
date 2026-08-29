//! Cookie parsing, startup validation, and the SAPISIDHASH authorization
//! header (spec §7.1).
//!
//! The three hash segments MUST share one timestamp (single `now()` call);
//! the header is recomputed for every request and every retry, never cached.

use sha1::{Digest, Sha1};

/// Extract cookie `name`'s value from a full cookie header string.
///
/// Plain string search (no regex): `SID=` also occurs inside
/// `__Secure-1PSID=`, so a hit only counts when the name is at position 0
/// or immediately follows `;` (whitespace allowed between them).
pub fn parse_cookie_value(cookie_str: &str, name: &str) -> String {
    let needle = format!("{name}=");
    let bytes = cookie_str.as_bytes();
    let mut search_from = 0usize;
    while let Some(rel) = cookie_str[search_from..].find(&needle) {
        let p = search_from + rel;
        let boundary_ok = p == 0
            || bytes[..p]
                .iter()
                .rev()
                .find(|b| !b.is_ascii_whitespace())
                .is_some_and(|b| *b == b';');
        if boundary_ok {
            let start = p + needle.len();
            let end = cookie_str[start..]
                .find(';')
                .map(|e| start + e)
                .unwrap_or(cookie_str.len());
            return cookie_str[start..end].trim().to_string();
        }
        search_from = p + 1;
    }
    String::new()
}

/// Startup validation (spec §7.1): the SAPISID family is mandatory (no auth
/// header without it); a missing SID family only warns.
pub fn validate_cookie(cookie_str: &str) -> Result<(), String> {
    let sapisid_family = !parse_cookie_value(cookie_str, "SAPISID").is_empty()
        || !parse_cookie_value(cookie_str, "__Secure-3PAPISID").is_empty();
    if !sapisid_family {
        return Err(
            "cookie string is missing SAPISID (or __Secure-3PAPISID): the SAPISIDHASH \
             authorization header cannot be computed; re-copy the full document.cookie"
                .to_string(),
        );
    }
    let sid_family = !parse_cookie_value(cookie_str, "SID").is_empty()
        || !parse_cookie_value(cookie_str, "__Secure-1PSID").is_empty();
    if !sid_family {
        tracing::warn!("cookie string has no SID/__Secure-1PSID; trying to use it anyway");
    }
    Ok(())
}

/// The three SAPISID hash segments for one instant in time.
struct HashSegs {
    sapisidhash: String,
    sapisid_1p: String,
    sapisid_3p: String,
}

fn seg(ts: u64, value: &str, origin: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(format!("{ts} {value} {origin}").as_bytes());
    let digest = hasher.finalize();
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    format!("{ts}_{hex}")
}

fn compute_segs(cookie_str: &str, ts: u64) -> HashSegs {
    const ORIGIN: &str = "https://console.cloud.google.com";
    let sapisid = parse_cookie_value(cookie_str, "SAPISID");
    let sapisid_1p = parse_cookie_value(cookie_str, "__Secure-1PAPISID");
    let sapisid_3p = parse_cookie_value(cookie_str, "__Secure-3PAPISID");
    let primary = if !sapisid.is_empty() {
        &sapisid
    } else if !sapisid_3p.is_empty() {
        &sapisid_3p
    } else {
        &sapisid_1p
    };
    HashSegs {
        sapisidhash: seg(
            ts,
            if sapisid.is_empty() {
                primary
            } else {
                &sapisid
            },
            ORIGIN,
        ),
        sapisid_1p: seg(
            ts,
            if sapisid_1p.is_empty() {
                primary
            } else {
                &sapisid_1p
            },
            ORIGIN,
        ),
        sapisid_3p: seg(
            ts,
            if sapisid_3p.is_empty() {
                primary
            } else {
                &sapisid_3p
            },
            ORIGIN,
        ),
    }
}

/// Build the full `authorization` header value at time `ts` (unix seconds).
/// Testable variant of [`authorization_header`]; all three segments share
/// the same `ts` (spec trap 1).
pub fn authorization_header_at(cookie_str: &str, ts: u64) -> String {
    let s = compute_segs(cookie_str, ts);
    format!(
        "SAPISIDHASH {} SAPISID1PHASH {} SAPISID3PHASH {}",
        s.sapisidhash, s.sapisid_1p, s.sapisid_3p
    )
}

/// Current-time authorization header; call fresh for every request/retry.
pub fn authorization_header(cookie_str: &str) -> String {
    authorization_header_at(cookie_str, chrono::Utc::now().timestamp().max(0) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    const COOKIE: &str = "AWSQC_1=x; __Secure-1PSID=abc.1psid; SAPISID=sapid123; \
                          __Secure-1PAPISID=onepap; __Secure-3PAPISID=threepap; SID=plain.sid; \
                          NID=zzz";

    #[test]
    fn sid_name_requires_own_boundary_not_prefix_of_secure_names() {
        // `SID=` appears inside `__Secure-1PSID=`; only the standalone
        // occurrence (right after "; ") counts.
        assert_eq!(parse_cookie_value(COOKIE, "SID"), "plain.sid");
        assert_eq!(parse_cookie_value(COOKIE, "__Secure-1PSID"), "abc.1psid");
    }

    #[test]
    fn first_position_and_tail_hits() {
        assert_eq!(parse_cookie_value("SID=head; X=1", "SID"), "head");
        assert_eq!(parse_cookie_value("X=1; SID=tail", "SID"), "tail");
        assert_eq!(parse_cookie_value("X=1;SID=nospace", "SID"), "nospace");
        assert_eq!(parse_cookie_value("XSID=nope; SID=yes", "SID"), "yes");
    }

    #[test]
    fn missing_name_returns_empty() {
        assert_eq!(parse_cookie_value(COOKIE, "NOT_THERE"), "");
        assert_eq!(parse_cookie_value("", "SID"), "");
    }

    #[test]
    fn validation_requires_sapisid_family() {
        assert!(validate_cookie(COOKIE).is_ok());
        assert!(validate_cookie("SID=only; NID=x").is_err());
        // 3PAPISID alone satisfies the family.
        assert!(validate_cookie("__Secure-3PAPISID=p3").is_ok());
    }

    #[test]
    fn three_segments_share_one_timestamp_and_use_own_values() {
        let ts = 1_700_000_000;
        let header = authorization_header_at(COOKIE, ts);
        let parts: Vec<&str> = header.split(' ').collect();
        assert_eq!(parts.len(), 6);
        assert_eq!(parts[0], "SAPISIDHASH");
        assert_eq!(parts[2], "SAPISID1PHASH");
        assert_eq!(parts[4], "SAPISID3PHASH");
        // Same instant in every segment.
        let ts_a = parts[1].split('_').next().unwrap();
        let ts_b = parts[3].split('_').next().unwrap();
        let ts_c = parts[5].split('_').next().unwrap();
        assert_eq!(
            (ts_a, ts_b, ts_c),
            ("1700000000", "1700000000", "1700000000")
        );
        // Hand-computed reference for segment 1: sha1("1700000000 sapid123 https://console.cloud.google.com")
        let expect = {
            use sha1::{Digest, Sha1};
            let mut h = Sha1::new();
            h.update(b"1700000000 sapid123 https://console.cloud.google.com");
            let hex: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
            format!("1700000000_{hex}")
        };
        assert_eq!(parts[1], expect);
    }

    #[test]
    fn missing_members_fall_back_to_primary() {
        let ts = 1_700_000_001;
        let only_sapisid = "SAPISID=onlyprimary";
        let header = authorization_header_at(only_sapisid, ts);
        let parts: Vec<&str> = header.split(' ').collect();
        // All three segments hash the same fallback value -> identical hashes.
        let h1 = parts[1].split('_').nth(1).unwrap();
        let h2 = parts[3].split('_').nth(1).unwrap();
        let h3 = parts[5].split('_').nth(1).unwrap();
        assert_eq!(h1, h2);
        assert_eq!(h2, h3);
    }
}

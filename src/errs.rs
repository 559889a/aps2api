//! Upstream error classification (spec §14) and user-facing hints.
//!
//! Priority order (§14.1): PROJECT first — "Permission denied on resource
//! projects/xxx" also matches the AUTH keywords, and misclassifying it as an
//! expired cookie sends users re-copying cookies forever (real-world trap).

use crate::ir::{ErrorKind, UpstreamError};

const PROJECT_KEYWORDS: [&str; 7] = [
    "requires billing",
    "billing to be enabled",
    "billing account",
    "has not been used in project",
    "is not found and cannot be used",
    "project not found",
    "invalid argument",
];

const RATELIMIT_KEYWORDS: [&str; 4] = [
    "resource_exhausted",
    "rate limit",
    "quota",
    "try again later",
];

const AUTH_KEYWORDS: [&str; 8] = [
    "permission",
    "denied",
    "aiplatform.endpoints.predict",
    "not authorized",
    "unauthenticated",
    "login required",
    "session expired",
    "invalid credentials",
];

const SERVER_KEYWORDS: [&str; 3] = ["overloaded", "temporarily unavailable", "internal error"];

fn contains_any(lower: &str, kws: &[&str]) -> bool {
    kws.iter().any(|k| lower.contains(k))
}

fn project_level(lower: &str) -> bool {
    if contains_any(lower, &PROJECT_KEYWORDS) {
        return true;
    }
    // A concrete project resource name + "denied" is a project-level error.
    (lower.contains("projects/") || lower.contains("project #")) && lower.contains("denied")
}

/// Classify an upstream failure from its HTTP status (when the request got
/// one) and its error message. `status == None` covers transport-level
/// failures only when the caller did not already map them to `Transport`.
pub fn classify(status: Option<u16>, message: &str) -> ErrorKind {
    let lower = message.to_lowercase();
    // 1. Project-level beats everything (spec §14.1).
    if project_level(&lower) {
        return ErrorKind::Project;
    }
    // 2. Rate limit (retryable).
    if status == Some(429) || contains_any(&lower, &RATELIMIT_KEYWORDS) {
        return ErrorKind::RateLimit;
    }
    // 3. Auth / cookie expired.
    if matches!(status, Some(401) | Some(403)) || contains_any(&lower, &AUTH_KEYWORDS) {
        return ErrorKind::Auth;
    }
    // 4. Invalid argument.
    if status == Some(400) || lower.contains("invalid") {
        return ErrorKind::Invalid;
    }
    // 5. Not found.
    if status == Some(404) || lower.contains("not found") {
        return ErrorKind::NotFound;
    }
    // 6. Server-side / transient.
    if status.is_some_and(|s| s >= 500) || contains_any(&lower, &SERVER_KEYWORDS) {
        return ErrorKind::Server;
    }
    ErrorKind::Invalid
}

pub fn classify_error(status: Option<u16>, message: impl Into<String>) -> UpstreamError {
    let message = message.into();
    let kind = classify(status, &message);
    UpstreamError {
        kind,
        status,
        message,
        jar_refreshed_since_send: false,
    }
}

/// User-facing hint appended to the error message (spec §14.2, verbatim).
pub fn user_hint(kind: ErrorKind) -> &'static str {
    match kind {
        ErrorKind::Auth => {
            "\n\n💡 Cookie 通常较为持久（只要不退出登录/改密码/被 Google 主动失效，可维持数周甚至更久）；\
自动续期已尝试刷新仍失败，说明登录态整体失效（非短期凭据滚动）。重新获取：电脑浏览器打开 \
console.cloud.google.com，F12 → Network，复制任意请求的 Cookie 头，更新 config.yaml 的 \
cookie 字段后重启。"
        }
        ErrorKind::Project => {
            "\n\n这看起来是**项目层面**的问题，不是 Cookie 失效，重取 Cookie 无用。请依次检查：\
1) 控制台里的 Project ID 是否填对（要用你能在 Vertex AI Studio 里正常出文的那个项目）；\
2) 该项目是否已开启计费（这条接口要求计费账号，未开启会报 requires billing）；\
3) 当前登录的 Google 账号对该项目是否有权限（换项目或换账号试试）。"
        }
        _ => "",
    }
}

/// Full message for the client: upstream message + hint where applicable.
pub fn client_message(err: &UpstreamError) -> String {
    let mut msg = err.message.clone();
    let hint = user_hint(err.kind);
    if !hint.is_empty() {
        msg.push_str(hint);
    }
    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_beats_auth_for_named_resource_denials() {
        // The §14.1 note: this message matches AUTH keywords too, but the
        // project resource form must win.
        let kind = classify(
            Some(403),
            "Permission 'aiplatform.endpoints.predict' denied on resource \
             '//aiplatform.googleapis.com/projects/my-proj' (or it may not exist).",
        );
        assert_eq!(kind, ErrorKind::Project);
    }

    #[test]
    fn bare_auth_without_project_resource_is_auth() {
        assert_eq!(
            classify(Some(401), "Request had invalid authentication credentials."),
            ErrorKind::Auth
        );
        assert_eq!(classify(None, "not authorized"), ErrorKind::Auth);
    }

    #[test]
    fn project_keywords() {
        assert_eq!(
            classify(
                Some(400),
                "Bucket is in project x: requires billing to be enabled"
            ),
            ErrorKind::Project
        );
        assert_eq!(
            classify(
                None,
                "API has not been used in project 123 before or it is disabled"
            ),
            ErrorKind::Project
        );
        assert_eq!(
            classify(None, "projects/my-proj: permission denied"),
            ErrorKind::Project
        );
    }

    #[test]
    fn ratelimit_and_retryables() {
        assert_eq!(classify(Some(429), "Quota exceeded"), ErrorKind::RateLimit);
        assert_eq!(
            classify(None, "Resource has been exhausted (e.g. check quota)."),
            ErrorKind::RateLimit
        );
        assert_eq!(
            classify(
                Some(503),
                "The model is overloaded. Please try again later."
            ),
            // "try again later" hits the RATELIMIT keyword list (§14.1);
            // both RateLimit and Server are retryable.
            ErrorKind::RateLimit
        );
        assert_eq!(
            classify(Some(500), "backend connection failed"),
            ErrorKind::Server
        );
        for k in [
            ErrorKind::RateLimit,
            ErrorKind::Server,
            ErrorKind::Transport,
        ] {
            assert!(UpstreamError {
                kind: k,
                status: None,
                message: String::new(),
                jar_refreshed_since_send: false,
            }
            .retryable());
        }
        for k in [
            ErrorKind::Auth,
            ErrorKind::Project,
            ErrorKind::Invalid,
            ErrorKind::NotFound,
        ] {
            assert!(!UpstreamError {
                kind: k,
                status: None,
                message: String::new(),
                jar_refreshed_since_send: false,
            }
            .retryable());
        }
    }

    #[test]
    fn invalid_and_notfound() {
        assert_eq!(classify(Some(400), "bad request"), ErrorKind::Invalid);
        assert_eq!(
            classify(Some(404), "Model gemini-x not found"),
            ErrorKind::NotFound
        );
    }

    #[test]
    fn hints_present_for_auth_and_project_only() {
        assert!(user_hint(ErrorKind::Auth).contains("console.cloud.google.com"));
        assert!(user_hint(ErrorKind::Project).contains("项目层面"));
        assert!(user_hint(ErrorKind::RateLimit).is_empty());
        let err = classify_error(Some(403), "unauthenticated");
        assert!(client_message(&err).contains("重新获取"));
    }
}

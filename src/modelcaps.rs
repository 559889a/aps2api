//! Model capability profiles (spec §3).
//!
//! Pure function `profile(model)` classifies a Gemini model name into a
//! capability profile: thinking kind/levels/defaults, whether sampling
//! params are deprecated, and whether the request must end with a user turn.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThinkingKind {
    /// 3.x+: `thinkingConfig.thinkingLevel` (LOW/HIGH/...).
    Level,
    /// 2.5: `thinkingConfig.thinkingBudget` (token budget).
    Budget,
    /// Older: no thinkingConfig at all.
    None,
}

#[derive(Debug, Clone)]
pub struct Profile {
    pub thinking: ThinkingKind,
    /// Legal levels ascending; only meaningful when thinking == Level.
    pub levels: Vec<&'static str>,
    /// Family default level (thinking == Level) or budget sentinel note.
    pub default_level: String,
    pub sampling_deprecated: bool,
    /// 3.x rejects requests ending with a model turn.
    pub requires_user_last_turn: bool,
    /// Budget family fields (thinking == Budget); -1 default = dynamic.
    /// min/max are informational for now — v1 always sends the family default
    /// budget (spec §8.3: forced levels do not apply to budget families).
    #[allow(dead_code)]
    pub budget_min: i32,
    #[allow(dead_code)]
    pub budget_max: i32,
    pub budget_default: i32,
}

/// Known display suffixes stripped before family parsing (spec §3.1).
const SUFFIXES: [&str; 5] = ["-search", "-1k", "-2k", "-4k", "-512"];

/// The full clamp ladder, low → high (spec §3.3).
pub const LADDER: [&str; 4] = ["minimal", "low", "medium", "high"];

fn strip_suffixes(name: &str) -> String {
    let mut cur = name.to_string();
    loop {
        let lower = cur.to_lowercase();
        let mut stripped = false;
        for s in SUFFIXES {
            if let Some(base) = lower.strip_suffix(s) {
                cur = base.to_string();
                stripped = true;
                break;
            }
        }
        if !stripped && lower.contains("-think-") {
            // -think-{tier} suffix: drop everything from "-think-" on.
            if let Some(pos) = lower.rfind("-think-") {
                cur = lower[..pos].to_string();
                stripped = true;
            }
        }
        if !stripped {
            return cur;
        }
    }
}

/// Extract (major, minor); unknown models are conservatively 3.0 (spec §3.1).
fn family(model: &str) -> (u32, u32) {
    let cleaned = strip_suffixes(&model.to_lowercase());
    let Some(rest) = cleaned.strip_prefix("gemini-") else {
        return (3, 0);
    };
    let bytes = rest.as_bytes();
    let mut i = 0;
    let mut major = 0u32;
    let mut has_major = false;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        major = major * 10 + (bytes[i] - b'0') as u32;
        has_major = true;
        i += 1;
    }
    if !has_major {
        return (3, 0);
    }
    let mut minor = 0u32;
    if i < bytes.len() && bytes[i] == b'.' {
        i += 1;
        let mut has_minor = false;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            minor = minor * 10 + (bytes[i] - b'0') as u32;
            has_minor = true;
            i += 1;
        }
        if !has_minor {
            return (3, 0);
        }
    }
    (major, minor)
}

pub fn profile(model: &str) -> Profile {
    let lower = model.to_lowercase();
    let (major, minor) = family(model);
    let is_pro = lower.contains("pro");
    let is_flash_lite = lower.contains("flash-lite");

    if major >= 3 {
        let supports_minimal = !is_pro && (major < 3 || (major == 3 && minor <= 6));
        let mut levels: Vec<&'static str> = vec!["low", "medium", "high"];
        if supports_minimal {
            levels.insert(0, "minimal");
        }
        let default_level = if is_pro {
            "high".to_string()
        } else if is_flash_lite && supports_minimal {
            "minimal".to_string()
        } else {
            "medium".to_string()
        };
        let sampling_deprecated =
            major >= 4 || (major == 3 && minor >= 6) || (major == 3 && minor == 5 && is_flash_lite);
        Profile {
            thinking: ThinkingKind::Level,
            levels,
            default_level,
            sampling_deprecated,
            requires_user_last_turn: true,
            budget_min: 0,
            budget_max: 0,
            budget_default: 0,
        }
    } else if major == 2 && minor >= 5 {
        // Budget family (spec §3.2): pro 128..32768 (0 not allowed);
        // flash-lite 512..24576 (0 allowed); flash 0..24576 (0 allowed).
        let (budget_min, budget_max, budget_default) = if is_pro {
            (128, 32768, -1)
        } else if is_flash_lite {
            (512, 24576, 0)
        } else {
            (0, 24576, 0)
        };
        Profile {
            thinking: ThinkingKind::Budget,
            levels: vec![],
            default_level: budget_default.to_string(),
            sampling_deprecated: false,
            requires_user_last_turn: false,
            budget_min,
            budget_max,
            budget_default,
        }
    } else {
        Profile {
            thinking: ThinkingKind::None,
            levels: vec![],
            default_level: String::new(),
            sampling_deprecated: false,
            requires_user_last_turn: false,
            budget_min: 0,
            budget_max: 0,
            budget_default: 0,
        }
    }
}

/// Clamp a requested thinking level onto the model's legal set (spec §3.3):
/// prefer stepping DOWN the ladder (users lower levels to think less);
/// unknown words are treated as the highest level, then clamped down.
pub fn clamp_level(level: &str, levels: &[&'static str]) -> String {
    let want = level.to_lowercase();
    if levels.contains(&want.as_str()) {
        return want;
    }
    // Position on the ladder; unknown words sit above the whole ladder.
    let pos = LADDER
        .iter()
        .position(|&l| l == want)
        .unwrap_or(LADDER.len());
    let legal_pos: Vec<usize> = levels
        .iter()
        .filter_map(|l| LADDER.iter().position(|&x| x == *l))
        .collect();
    if legal_pos.is_empty() {
        return want;
    }
    // Nearest legal position strictly below `pos` (lower index = lower level);
    // if none, take the lowest legal level (nearest going up).
    match legal_pos.iter().rev().find(|&&p| p < pos) {
        Some(&p) => LADDER[p].to_string(),
        None => LADDER[legal_pos[0]].to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn level_levels(p: &Profile) -> Vec<String> {
        p.levels.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn gemini_3_1_pro() {
        let p = profile("gemini-3.1-pro");
        assert_eq!(p.thinking, ThinkingKind::Level);
        assert_eq!(level_levels(&p), ["low", "medium", "high"]);
        assert_eq!(p.default_level, "high");
        assert!(!p.sampling_deprecated);
        assert!(p.requires_user_last_turn);
    }

    #[test]
    fn gemini_3_1_pro_preview() {
        // Live model name (user-verified 2026-08-30): preview suffix must not
        // affect family parsing; pro defaults stay.
        let p = profile("gemini-3.1-pro-preview");
        assert_eq!(p.thinking, ThinkingKind::Level);
        assert_eq!(level_levels(&p), ["low", "medium", "high"]);
        assert_eq!(p.default_level, "high");
        assert!(!p.sampling_deprecated);
        assert!(p.requires_user_last_turn);
    }

    #[test]
    fn gemini_3_6_flash() {
        let p = profile("gemini-3.6-flash");
        assert_eq!(level_levels(&p), ["minimal", "low", "medium", "high"]);
        assert_eq!(p.default_level, "medium");
        assert!(p.sampling_deprecated);
        assert!(p.requires_user_last_turn);
    }

    #[test]
    fn gemini_3_7_flash() {
        let p = profile("gemini-3.7-flash");
        assert_eq!(level_levels(&p), ["low", "medium", "high"]);
        assert_eq!(p.default_level, "medium");
        assert!(p.sampling_deprecated);
        assert!(p.requires_user_last_turn);
    }

    #[test]
    fn gemini_2_5_pro_budget() {
        let p = profile("gemini-2.5-pro");
        assert_eq!(p.thinking, ThinkingKind::Budget);
        assert_eq!(p.budget_min, 128);
        assert_eq!(p.budget_max, 32768);
        assert_eq!(p.budget_default, -1);
        assert!(!p.requires_user_last_turn);
        assert!(!p.sampling_deprecated);
    }

    #[test]
    fn gemini_2_5_flash_budget() {
        let p = profile("gemini-2.5-flash");
        assert_eq!(p.thinking, ThinkingKind::Budget);
        assert_eq!(p.budget_min, 0);
        assert_eq!(p.budget_max, 24576);
        assert_eq!(p.budget_default, 0);
    }

    #[test]
    fn unknown_model_conservative_3_0() {
        let p = profile("gemini-future-ultra");
        assert_eq!(p.thinking, ThinkingKind::Level);
        assert!(p.requires_user_last_turn);
        // Unknown = treated as 3.0 (major 3, minor 0).
        assert_eq!(level_levels(&p), ["minimal", "low", "medium", "high"]);
    }

    #[test]
    fn non_gemini_conservative_3_0() {
        let p = profile("totally-unknown");
        assert_eq!(p.thinking, ThinkingKind::Level);
        assert!(p.requires_user_last_turn);
    }

    #[test]
    fn suffixes_stripped_before_family_parse() {
        assert_eq!(family("gemini-3.1-pro-search"), (3, 1));
        assert_eq!(family("gemini-2.5-flash-1k"), (2, 5));
        assert_eq!(family("gemini-3.7-flash-think-high"), (3, 7));
        assert_eq!(family("GEMINI-3.6-Flash"), (3, 6));
    }

    #[test]
    fn clamp_prefers_down() {
        let levels = ["low", "medium", "high"];
        assert_eq!(clamp_level("minimal", &levels), "low"); // nothing below -> up
        assert_eq!(clamp_level("low", &levels), "low");
        assert_eq!(clamp_level("medium", &levels), "medium");
        assert_eq!(clamp_level("ultra", &levels), "high"); // unknown -> highest -> stays
    }

    #[test]
    fn clamp_with_minimal_set() {
        let levels = ["minimal", "low", "medium", "high"];
        assert_eq!(clamp_level("minimal", &levels), "minimal");
        assert_eq!(clamp_level("high", &levels), "high");
    }

    #[test]
    fn clamp_unknown_word_treated_as_highest_then_down() {
        let levels = ["minimal", "low", "medium", "high"];
        assert_eq!(clamp_level("med", &levels), "high");
        assert_eq!(clamp_level("ultra", &levels), "high");
        // 3.7-style set (no minimal): unknown words clamp down to high as well.
        let levels37 = ["low", "medium", "high"];
        assert_eq!(clamp_level("minimal", &levels37), "low");
    }
}

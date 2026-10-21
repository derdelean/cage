//! The frozen issuance policy, read from the environment at start-up.
//!
//!   CAGE_ISSUANCE_SCOPES=llm.,sign.   (comma-separated; unset disables the policy)
//!   CAGE_ISSUANCE_MAX_TTL=300  CAGE_ISSUANCE_MAX_USES=10
//!   CAGE_ISSUANCE_MAX_TOKENS_PER_SCOPE=1000   (optional lifetime cap per entry)
//!
//! An unset number takes its default. A set but malformed value is an error, never
//! the default: a typo must not loosen the ceiling it was meant to tighten. So is a
//! number set without `CAGE_ISSUANCE_SCOPES`, which would otherwise leave the
//! process with no policy at all.

use std::env::VarError;

use cage_core::IssuancePolicy;

const NUMBER_KEYS: [&str; 3] = [
    "CAGE_ISSUANCE_MAX_TTL",
    "CAGE_ISSUANCE_MAX_USES",
    "CAGE_ISSUANCE_MAX_TOKENS_PER_SCOPE",
];

/// The issuance policy the environment provisions, `Ok(None)` when
/// `CAGE_ISSUANCE_SCOPES` is unset, or an error naming the malformed variable.
pub fn issuance_policy_from_env() -> Result<Option<IssuancePolicy>, String> {
    parse_issuance_policy(|key| std::env::var(key))
}

fn parse_issuance_policy(
    var: impl Fn(&str) -> Result<String, VarError>,
) -> Result<Option<IssuancePolicy>, String> {
    let Some(raw) = read(&var, "CAGE_ISSUANCE_SCOPES")? else {
        for key in NUMBER_KEYS {
            if read(&var, key)?.is_some() {
                return Err(format!(
                    "{key} is set but CAGE_ISSUANCE_SCOPES is not, so no policy would apply"
                ));
            }
        }
        return Ok(None);
    };
    let allowed_scopes: Vec<String> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    let max_ttl_seconds = number(&var, "CAGE_ISSUANCE_MAX_TTL")?.unwrap_or(300);
    let max_uses = number(&var, "CAGE_ISSUANCE_MAX_USES")?.unwrap_or(50);
    let max_tokens_per_scope = number(&var, "CAGE_ISSUANCE_MAX_TOKENS_PER_SCOPE")?;
    Ok(Some(IssuancePolicy {
        allowed_scopes,
        max_ttl_seconds,
        max_uses,
        max_tokens_per_scope,
    }))
}

/// `Ok(None)` only when `key` is unset. A value that is not UTF-8 is an error.
fn read(
    var: &impl Fn(&str) -> Result<String, VarError>,
    key: &str,
) -> Result<Option<String>, String> {
    match var(key) {
        Ok(value) => Ok(Some(value)),
        Err(VarError::NotPresent) => Ok(None),
        Err(VarError::NotUnicode(_)) => Err(format!("{key} is not valid UTF-8")),
    }
}

fn number<T: std::str::FromStr>(
    var: &impl Fn(&str) -> Result<String, VarError>,
    key: &str,
) -> Result<Option<T>, String> {
    let Some(raw) = read(var, key)? else {
        return Ok(None);
    };
    raw.trim()
        .parse()
        .map(Some)
        .map_err(|_| format!("{key}={raw:?} is not a valid number"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::ffi::OsString;

    fn parse(vars: &[(&str, &str)]) -> Result<Option<IssuancePolicy>, String> {
        let map: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        parse_issuance_policy(|key| map.get(key).cloned().ok_or(VarError::NotPresent))
    }

    #[test]
    fn unset_scopes_means_no_policy() {
        assert!(parse(&[]).unwrap().is_none());
    }

    #[test]
    fn a_number_without_scopes_is_refused() {
        for key in NUMBER_KEYS {
            let err = parse(&[(key, "3")]).unwrap_err();
            assert!(
                err.contains(key) && err.contains("CAGE_ISSUANCE_SCOPES"),
                "{err}"
            );
        }
    }

    #[test]
    fn unset_numbers_take_the_defaults() {
        let policy = parse(&[("CAGE_ISSUANCE_SCOPES", "llm., sign.")])
            .unwrap()
            .unwrap();
        assert_eq!(policy.allowed_scopes, ["llm.", "sign."]);
        assert_eq!(policy.max_ttl_seconds, 300);
        assert_eq!(policy.max_uses, 50);
        assert_eq!(policy.max_tokens_per_scope, None);
    }

    #[test]
    fn set_numbers_are_trimmed_and_used() {
        let policy = parse(&[
            ("CAGE_ISSUANCE_SCOPES", "sign."),
            ("CAGE_ISSUANCE_MAX_TTL", " 60 "),
            ("CAGE_ISSUANCE_MAX_USES", "2"),
            ("CAGE_ISSUANCE_MAX_TOKENS_PER_SCOPE", "10"),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(policy.max_ttl_seconds, 60);
        assert_eq!(policy.max_uses, 2);
        assert_eq!(policy.max_tokens_per_scope, Some(10));
    }

    #[test]
    fn malformed_numbers_are_refused_not_defaulted() {
        for (key, value) in [
            ("CAGE_ISSUANCE_MAX_TTL", "5m"),
            ("CAGE_ISSUANCE_MAX_USES", "ten"),
            ("CAGE_ISSUANCE_MAX_USES", ""),
            ("CAGE_ISSUANCE_MAX_TOKENS_PER_SCOPE", "1,000"),
            ("CAGE_ISSUANCE_MAX_TOKENS_PER_SCOPE", "-1"),
        ] {
            let err = parse(&[("CAGE_ISSUANCE_SCOPES", "sign."), (key, value)]).unwrap_err();
            assert!(err.contains(key), "{err}");
        }
    }

    #[test]
    fn max_uses_above_u32_is_refused_not_truncated() {
        // 2^32 + 1 would truncate to 1 under an `as u32` cast.
        let err = parse(&[
            ("CAGE_ISSUANCE_SCOPES", "sign."),
            ("CAGE_ISSUANCE_MAX_USES", "4294967297"),
        ])
        .unwrap_err();
        assert!(err.contains("CAGE_ISSUANCE_MAX_USES"), "{err}");
    }

    #[test]
    fn non_utf8_scopes_are_refused_not_treated_as_unset() {
        let result = parse_issuance_policy(|key| match key {
            "CAGE_ISSUANCE_SCOPES" => Err(VarError::NotUnicode(OsString::from("x"))),
            _ => Err(VarError::NotPresent),
        });
        assert!(result.unwrap_err().contains("CAGE_ISSUANCE_SCOPES"));
    }
}

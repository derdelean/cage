//! The frozen issuance policy, read from the environment at start-up.
//!
//!   CAGE_ISSUANCE_SCOPES=llm.,sign.   (comma-separated, at least one scope)
//!   CAGE_ISSUANCE_MAX_TTL=300  CAGE_ISSUANCE_MAX_USES=10
//!   CAGE_ISSUANCE_MAX_TOKENS_PER_SCOPE=1000   (optional lifetime cap per entry)
//!
//! An unset number takes its default. A set but malformed value is an error, never
//! the default: a typo must not loosen the ceiling it was meant to tighten. So is a
//! number set without `CAGE_ISSUANCE_SCOPES`, which would otherwise leave the
//! process with no policy at all, and a scope list that names no scope. Unset
//! `CAGE_ISSUANCE_SCOPES` means no policy, which the broker refuses unless the
//! operator waives it.
//!
//! Any other variable whose name starts with `CAGE_ISSUANCE_`, in any case, is an
//! error as well. Read alone, a misspelled name would be ignored: no policy for the
//! scope list, the default for a limit, no cap for the cap. A misspelling outside
//! that prefix is not caught here. For the scope list the broker catches it anyway,
//! because it refuses to start without a policy unless the operator sets
//! `CAGE_BROKER_ALLOW_NO_POLICY=1`. A limit misspelled outside the prefix still takes
//! its default.

use std::env::VarError;

use cage_core::IssuancePolicy;

const PREFIX: &str = "CAGE_ISSUANCE_";
const SCOPES_KEY: &str = "CAGE_ISSUANCE_SCOPES";
const MAX_TTL_KEY: &str = "CAGE_ISSUANCE_MAX_TTL";
const MAX_USES_KEY: &str = "CAGE_ISSUANCE_MAX_USES";
const MAX_TOKENS_KEY: &str = "CAGE_ISSUANCE_MAX_TOKENS_PER_SCOPE";
const NUMBER_KEYS: [&str; 3] = [MAX_TTL_KEY, MAX_USES_KEY, MAX_TOKENS_KEY];
const KNOWN_KEYS: [&str; 4] = [SCOPES_KEY, MAX_TTL_KEY, MAX_USES_KEY, MAX_TOKENS_KEY];

/// The issuance policy the environment provisions, `Ok(None)` when
/// `CAGE_ISSUANCE_SCOPES` is unset, or an error naming the malformed or unknown
/// variable.
pub fn issuance_policy_from_env() -> Result<Option<IssuancePolicy>, String> {
    let names: Vec<String> = std::env::vars_os()
        .map(|(name, _)| name.to_string_lossy().into_owned())
        .collect();
    parse_issuance_policy(&names, |key| std::env::var(key))
}

fn parse_issuance_policy(
    names: &[String],
    var: impl Fn(&str) -> Result<String, VarError>,
) -> Result<Option<IssuancePolicy>, String> {
    reject_unknown_names(names)?;
    let Some(raw) = read(&var, SCOPES_KEY)? else {
        for key in NUMBER_KEYS {
            if read(&var, key)?.is_some() {
                return Err(format!(
                    "{key} is set but {SCOPES_KEY} is not, so no policy would apply"
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
    if allowed_scopes.is_empty() {
        // An empty variable, for example from an unset shell variable, would freeze a
        // policy that admits nothing and let the process start anyway.
        return Err(format!("{SCOPES_KEY}={raw:?} names no scope"));
    }
    let max_ttl_seconds = number(&var, MAX_TTL_KEY)?.unwrap_or(300);
    let max_uses = number(&var, MAX_USES_KEY)?.unwrap_or(50);
    let max_tokens_per_scope = number(&var, MAX_TOKENS_KEY)?;
    Ok(Some(IssuancePolicy {
        allowed_scopes,
        max_ttl_seconds,
        max_uses,
        max_tokens_per_scope,
    }))
}

/// An error naming the first variable that carries the policy prefix, in any case,
/// but is not a policy variable. The name is printed escaped, so a control
/// character in it cannot forge a log line.
fn reject_unknown_names(names: &[String]) -> Result<(), String> {
    for name in names {
        let has_prefix = name
            .get(..PREFIX.len())
            .is_some_and(|start| start.eq_ignore_ascii_case(PREFIX));
        if !has_prefix || KNOWN_KEYS.contains(&name.as_str()) {
            continue;
        }
        if let Some(meant) = KNOWN_KEYS.iter().find(|key| key.eq_ignore_ascii_case(name)) {
            return Err(format!(
                "{name:?} is not an issuance policy variable. Names are case-sensitive, \
                 did you mean {meant}?"
            ));
        }
        return Err(format!(
            "{name:?} is not an issuance policy variable (known: {})",
            KNOWN_KEYS.join(", ")
        ));
    }
    Ok(())
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
        let names: Vec<String> = map.keys().cloned().collect();
        parse_issuance_policy(&names, |key| {
            map.get(key).cloned().ok_or(VarError::NotPresent)
        })
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
    fn an_unknown_policy_variable_is_refused() {
        // Each would otherwise be ignored: no policy, the default use limit, no cap,
        // no policy.
        for (vars, unknown) in [
            (
                &[("CAGE_ISSUANCE_SCOPE", "sign.")][..],
                "CAGE_ISSUANCE_SCOPE",
            ),
            (
                &[
                    ("CAGE_ISSUANCE_SCOPES", "sign."),
                    ("CAGE_ISSUANCE_MAX_USE", "2"),
                ][..],
                "CAGE_ISSUANCE_MAX_USE",
            ),
            (
                &[
                    ("CAGE_ISSUANCE_SCOPES", "sign."),
                    ("CAGE_ISSUANCE_MAX_TOKENS", "10"),
                ][..],
                "CAGE_ISSUANCE_MAX_TOKENS",
            ),
            (
                &[("cage_issuance_scopes", "sign.")][..],
                "cage_issuance_scopes",
            ),
        ] {
            let err = parse(vars).unwrap_err();
            assert!(err.contains(&format!("{unknown:?}")), "{vars:?}: {err}");
        }
    }

    #[test]
    fn a_scope_list_without_a_scope_is_refused() {
        for raw in ["", " ", ",", " , ,"] {
            let err = parse(&[("CAGE_ISSUANCE_SCOPES", raw)]).unwrap_err();
            assert!(err.contains("names no scope"), "{raw:?}: {err}");
        }
    }

    #[test]
    fn the_prefix_ends_at_its_underscore() {
        let policy = parse(&[
            ("CAGE_ISSUANCE_SCOPES", "sign."),
            ("CAGE_ISSUANCE", "x"),
            ("CAGE_ISSUANCEX", "x"),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(policy.allowed_scopes, ["sign."]);
        let err = parse(&[("CAGE_ISSUANCE_SCOPES", "sign."), ("CAGE_ISSUANCE_", "x")]).unwrap_err();
        assert!(err.contains("\"CAGE_ISSUANCE_\""), "{err}");
    }

    #[test]
    fn a_case_variant_points_to_the_known_name() {
        let err = parse(&[("Cage_Issuance_Max_Uses", "2")]).unwrap_err();
        assert!(
            err.contains("case-sensitive") && err.contains("CAGE_ISSUANCE_MAX_USES"),
            "{err}"
        );
    }

    #[test]
    fn an_unknown_name_is_escaped_in_the_error() {
        // A newline in the name would otherwise start a forged log line.
        let err = parse(&[("CAGE_ISSUANCE_X\n[cage-broker] policy frozen", "1")]).unwrap_err();
        assert!(!err.contains('\n'), "{err}");
    }

    #[test]
    fn other_cage_variables_are_not_policy_variables() {
        let policy = parse(&[
            ("CAGE_ISSUANCE_SCOPES", "sign."),
            ("CAGE_LLM_PROVIDER", "anthropic"),
            ("CAGE_BROKER_SECRET_FILE", "/tmp/x"),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(policy.allowed_scopes, ["sign."]);
    }

    #[test]
    fn non_utf8_scopes_are_refused_not_treated_as_unset() {
        let names = [SCOPES_KEY.to_string()];
        let result = parse_issuance_policy(&names, |key| match key {
            "CAGE_ISSUANCE_SCOPES" => Err(VarError::NotUnicode(OsString::from("x"))),
            _ => Err(VarError::NotPresent),
        });
        assert!(result.unwrap_err().contains("CAGE_ISSUANCE_SCOPES"));
    }
}

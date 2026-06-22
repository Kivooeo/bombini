use std::collections::HashMap;

use anyhow::{Result, bail};
use serde_yml::Value;

pub fn expand_config(value: &mut Value) -> Result<()> {
    let Value::Mapping(map) = value else {
        return Ok(());
    };
    let Some(macros_val) = map.remove("macros") else {
        return Ok(());
    };

    let defs = parse_defs(&macros_val)?;
    if defs.is_empty() {
        return Ok(());
    }

    let mut resolved: HashMap<String, String> = HashMap::new();
    for name in defs.keys() {
        resolve(name, &defs, &mut resolved, &mut Vec::new())?;
    }

    expand_value(value, &resolved);
    Ok(())
}

fn parse_defs(macros_val: &Value) -> Result<HashMap<String, String>> {
    let Some(items) = macros_val.as_sequence() else {
        bail!("`macros` must be a list of `- macro: <name>` / `condition: <expr>` entries");
    };

    let mut defs = HashMap::new();
    for item in items {
        let Value::Mapping(entry) = item else {
            bail!("each `macros` entry must be a mapping with `macro` and `condition` keys");
        };
        let Some(name) = entry.get("macro").and_then(Value::as_str) else {
            bail!("`macros` entry is missing a string `macro` name");
        };
        let Some(condition) = entry.get("condition").and_then(Value::as_str) else {
            bail!("macro `{name}` is missing a string `condition`");
        };
        if !is_valid_name(name) {
            bail!("invalid macro name `{name}`: expected an identifier like `shell_proc`");
        }
        if condition.trim().is_empty() {
            bail!("macro `{name}` has an empty `condition`");
        }
        if defs
            .insert(name.to_string(), condition.to_string())
            .is_some()
        {
            bail!("macro `{name}` is defined more than once");
        }
    }
    Ok(defs)
}

fn resolve(
    name: &str,
    defs: &HashMap<String, String>,
    resolved: &mut HashMap<String, String>,
    stack: &mut Vec<String>,
) -> Result<String> {
    if let Some(cached) = resolved.get(name) {
        return Ok(cached.clone());
    }
    if stack.iter().any(|n| n == name) {
        stack.push(name.to_string());
        bail!("cyclic macro reference: {}", stack.join(" -> "));
    }

    stack.push(name.to_string());
    let body = defs.get(name).expect("resolve called with unknown macro");
    let expanded = expand_str(body, defs, resolved, stack)?;
    stack.pop();

    resolved.insert(name.to_string(), expanded.clone());
    Ok(expanded)
}

fn expand_str(
    input: &str,
    defs: &HashMap<String, String>,
    resolved: &mut HashMap<String, String>,
    stack: &mut Vec<String>,
) -> Result<String> {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];
        if c == '"' {
            out.push(c);
            i += 1;
            while i < chars.len() {
                out.push(chars[i]);
                let closed = chars[i] == '"';
                i += 1;
                if closed {
                    break;
                }
            }
        } else if c.is_ascii_alphabetic() {
            let start = i;
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            let ident: String = chars[start..i].iter().collect();
            if defs.contains_key(&ident) {
                let expansion = resolve(&ident, defs, resolved, stack)?;
                out.push('(');
                out.push_str(&expansion);
                out.push(')');
            } else {
                out.push_str(&ident);
            }
        } else {
            out.push(c);
            i += 1;
        }
    }

    Ok(out)
}

fn expand_value(value: &mut Value, resolved: &HashMap<String, String>) {
    match value {
        Value::Mapping(map) => {
            for (key, val) in map.iter_mut() {
                if matches!(key.as_str(), "scope" | "event")
                    && let Some(pred) = val.as_str()
                {
                    let expanded =
                        expand_str(pred, resolved, &mut resolved.clone(), &mut Vec::new())
                            .expect("expansion over a resolved macro set is infallible");
                    *val = Value::String(expanded);
                    continue;
                }
                expand_value(val, resolved);
            }
        }
        Value::Sequence(seq) => {
            for item in seq.iter_mut() {
                expand_value(item, resolved);
            }
        }
        _ => {}
    }
}

fn is_valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

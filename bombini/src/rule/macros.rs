use std::collections::HashMap;

use anyhow::{Result, bail};
use serde_yml::Value;

pub fn expand_config(value: &mut Value) -> Result<()> {
    let Value::Mapping(map) = value else {
        return Ok(());
    };

    let lists = match map.remove("lists") {
        Some(lists_val) => parse_list_defs(&lists_val)?,
        None => HashMap::new(),
    };
    let mut defs = match map.remove("macros") {
        Some(macros_val) => parse_defs(&macros_val)?,
        None => HashMap::new(),
    };

    if lists.is_empty() && defs.is_empty() {
        return Ok(());
    }

    // Pass 1: inline list references into macro conditions so the macro
    // resolution below operates on list-free text.
    for condition in defs.values_mut() {
        *condition = substitute_lists(condition, &lists);
    }

    let mut resolved: HashMap<String, String> = HashMap::new();
    for name in defs.keys() {
        resolve(name, &defs, &mut resolved, &mut Vec::new())?;
    }

    expand_value(value, &lists, &resolved);
    Ok(())
}

fn parse_list_defs(lists_val: &Value) -> Result<HashMap<String, String>> {
    let Some(items) = lists_val.as_sequence() else {
        bail!("`lists` must be a list of `- list: <name>` / `items: [...]` entries");
    };

    let mut defs = HashMap::new();
    for item in items {
        let Value::Mapping(entry) = item else {
            bail!("each `lists` entry must be a mapping with `list` and `items` keys");
        };
        let Some(name) = entry.get("list").and_then(Value::as_str) else {
            bail!("`lists` entry is missing a string `list` name");
        };
        if !is_valid_name(name) {
            bail!("invalid list name `{name}`: expected an identifier like `shell_binaries`");
        }
        let Some(values) = entry.get("items").and_then(Value::as_sequence) else {
            bail!("list `{name}` is missing an `items` array");
        };
        if values.is_empty() {
            bail!("list `{name}` has no items");
        }
        let mut parts = Vec::with_capacity(values.len());
        for value in values {
            if let Some(s) = value.as_str() {
                parts.push(format!("\"{s}\""));
            } else if let Some(n) = value.as_u64() {
                parts.push(n.to_string());
            } else if let Some(n) = value.as_i64() {
                parts.push(n.to_string());
            } else {
                bail!("list `{name}` items must be strings or integers");
            }
        }
        if defs.insert(name.to_string(), parts.join(", ")).is_some() {
            bail!("list `{name}` is defined more than once");
        }
    }
    Ok(defs)
}

/// Replace whole-word list references with their comma-separated items. Lists are
/// flat (no nesting), so a single non-recursive pass is enough. Identifiers inside
/// quoted string literals are left untouched.
fn substitute_lists(input: &str, lists: &HashMap<String, String>) -> String {
    if lists.is_empty() {
        return input.to_string();
    }
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
            if let Some(items) = lists.get(&ident) {
                out.push_str(items);
            } else {
                out.push_str(&ident);
            }
        } else {
            out.push(c);
            i += 1;
        }
    }

    out
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

fn expand_value(
    value: &mut Value,
    lists: &HashMap<String, String>,
    resolved: &HashMap<String, String>,
) {
    match value {
        Value::Mapping(map) => {
            for (key, val) in map.iter_mut() {
                if matches!(key.as_str(), "scope" | "event")
                    && let Some(pred) = val.as_str()
                {
                    // Pass 1: lists, then pass 2: macros.
                    let pred = substitute_lists(pred, lists);
                    let expanded =
                        expand_str(&pred, resolved, &mut resolved.clone(), &mut Vec::new())
                            .expect("expansion over a resolved macro set is infallible");
                    *val = Value::String(expanded);
                    continue;
                }
                expand_value(val, lists, resolved);
            }
        }
        Value::Sequence(seq) => {
            for item in seq.iter_mut() {
                expand_value(item, lists, resolved);
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

//! Built-in functions available to TraceScript scripts.
//!
//! Built-ins are pure: they don't touch the table store, the event registry, or any
//! other runtime state. Anything that needs that access (`count`, `filter`, `sort`,
//! alert/show/insert/export side effects) lives on the [`crate::interp::Interpreter`]
//! and [`crate::bytecode::vm::VM`] directly.

use crate::error::{Result, TraceError};
use crate::interp::value::Value;

/// Return the number of arguments expected by a built-in, or `None` if `name` is not
/// a built-in. Used by the bytecode VM to pop the right number of values before
/// dispatching.
pub fn arity(name: &str) -> Option<usize> {
    match name {
        "len" | "to_string" | "now" | "lower" | "upper" | "trim" | "hash_sha256" => Some(1),
        "contains" | "starts_with" | "ends_with" => Some(2),
        "substring" => Some(3),
        _ => None,
    }
}

/// Result of evaluating a built-in: a single `Value` (for `len`) or `None` if the call
/// name isn't a built-in.
pub fn try_call(name: &str, args: &[Value]) -> Option<Result<Value>> {
    let res = match name {
        "len" => call_len(args),
        "contains" => call_contains(args),
        "starts_with" => call_starts_with(args),
        "ends_with" => call_ends_with(args),
        "to_string" => call_to_string(args),
        "now" => call_now(args),
        "substring" => call_substring(args),
        "lower" => call_lower(args),
        "upper" => call_upper(args),
        "trim" => call_trim(args),
        "hash_sha256" => call_hash_sha256(args),
        _ => return None,
    };
    Some(res)
}

fn arg_str<'a>(args: &'a [Value], i: usize, fn_name: &str) -> Result<&'a str> {
    args.get(i)
        .ok_or_else(|| TraceError::Runtime {
            msg: format!("{}: missing argument {}", fn_name, i),
            pos: None,
        })?
        .as_str()
        .ok_or_else(|| TraceError::Runtime {
            msg: format!("{}: argument {} must be a string", fn_name, i),
            pos: None,
        })
}

fn call_len(args: &[Value]) -> Result<Value> {
    if args.len() != 1 {
        return Err(TraceError::Runtime {
            msg: format!("len: expected 1 argument, got {}", args.len()),
            pos: None,
        });
    }
    match &args[0] {
        Value::Str(s) => Ok(Value::Int(s.chars().count() as i64)),
        Value::Event(m) => Ok(Value::Int(m.len() as i64)),
        other => Err(TraceError::Runtime {
            msg: format!("len: unsupported type {}", type_name(other)),
            pos: None,
        }),
    }
}

fn call_contains(args: &[Value]) -> Result<Value> {
    if args.len() != 2 {
        return Err(TraceError::Runtime {
            msg: format!("contains: expected 2 arguments, got {}", args.len()),
            pos: None,
        });
    }
    let hay = arg_str(args, 0, "contains")?;
    let needle = arg_str(args, 1, "contains")?;
    Ok(Value::Bool(hay.contains(needle)))
}

fn call_starts_with(args: &[Value]) -> Result<Value> {
    if args.len() != 2 {
        return Err(TraceError::Runtime {
            msg: format!("starts_with: expected 2 arguments, got {}", args.len()),
            pos: None,
        });
    }
    let hay = arg_str(args, 0, "starts_with")?;
    let prefix = arg_str(args, 1, "starts_with")?;
    Ok(Value::Bool(hay.starts_with(prefix)))
}

fn call_ends_with(args: &[Value]) -> Result<Value> {
    if args.len() != 2 {
        return Err(TraceError::Runtime {
            msg: format!("ends_with: expected 2 arguments, got {}", args.len()),
            pos: None,
        });
    }
    let hay = arg_str(args, 0, "ends_with")?;
    let suffix = arg_str(args, 1, "ends_with")?;
    Ok(Value::Bool(hay.ends_with(suffix)))
}

fn call_to_string(args: &[Value]) -> Result<Value> {
    if args.len() != 1 {
        return Err(TraceError::Runtime {
            msg: format!("to_string: expected 1 argument, got {}", args.len()),
            pos: None,
        });
    }
    Ok(Value::Str(args[0].to_string()))
}

fn call_now(_args: &[Value]) -> Result<Value> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    Ok(Value::Int(secs))
}

fn call_substring(args: &[Value]) -> Result<Value> {
    if args.len() != 3 {
        return Err(TraceError::Runtime {
            msg: format!("substring: expected 3 arguments, got {}", args.len()),
            pos: None,
        });
    }
    let s = arg_str(args, 0, "substring")?;
    let start = args[1].as_int().ok_or_else(|| TraceError::Runtime {
        msg: "substring: start must be an integer".into(),
        pos: None,
    })?;
    let len = args[2].as_int().ok_or_else(|| TraceError::Runtime {
        msg: "substring: length must be an integer".into(),
        pos: None,
    })?;
    let start = start.max(0) as usize;
    let len = len.max(0) as usize;
    let chars: Vec<char> = s.chars().collect();
    if start >= chars.len() {
        return Ok(Value::Str(String::new()));
    }
    let end = (start + len).min(chars.len());
    Ok(Value::Str(chars[start..end].iter().collect()))
}

fn call_lower(args: &[Value]) -> Result<Value> {
    if args.len() != 1 {
        return Err(TraceError::Runtime {
            msg: format!("lower: expected 1 argument, got {}", args.len()),
            pos: None,
        });
    }
    Ok(Value::Str(arg_str(args, 0, "lower")?.to_lowercase()))
}

fn call_upper(args: &[Value]) -> Result<Value> {
    if args.len() != 1 {
        return Err(TraceError::Runtime {
            msg: format!("upper: expected 1 argument, got {}", args.len()),
            pos: None,
        });
    }
    Ok(Value::Str(arg_str(args, 0, "upper")?.to_uppercase()))
}

fn call_trim(args: &[Value]) -> Result<Value> {
    if args.len() != 1 {
        return Err(TraceError::Runtime {
            msg: format!("trim: expected 1 argument, got {}", args.len()),
            pos: None,
        });
    }
    Ok(Value::Str(arg_str(args, 0, "trim")?.trim().to_string()))
}

fn call_hash_sha256(args: &[Value]) -> Result<Value> {
    if args.len() != 1 {
        return Err(TraceError::Runtime {
            msg: format!("hash_sha256: expected 1 argument, got {}", args.len()),
            pos: None,
        });
    }
    let s = arg_str(args, 0, "hash_sha256")?;
    let digest = crate::sha256::hash(s.as_bytes());
    Ok(Value::Str(crate::sha256::hex_digest(&digest)))
}

fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Int(_) => "int",
        Value::Float(_) => "float",
        Value::Str(_) => "string",
        Value::Bool(_) => "bool",
        Value::Event(_) => "event",
        Value::Unit => "unit",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn len_and_contains() {
        assert_eq!(try_call("len", &[Value::Str("abc".into())]).unwrap().unwrap(), Value::Int(3));
        assert_eq!(
            try_call("contains", &[Value::Str("hello world".into()), Value::Str("world".into())])
                .unwrap()
                .unwrap(),
            Value::Bool(true)
        );
    }

    #[test]
    fn starts_ends() {
        assert_eq!(
            try_call("starts_with", &[Value::Str("foo".into()), Value::Str("f".into())])
                .unwrap()
                .unwrap(),
            Value::Bool(true)
        );
        assert_eq!(
            try_call("ends_with", &[Value::Str("foo".into()), Value::Str("o".into())])
                .unwrap()
                .unwrap(),
            Value::Bool(true)
        );
    }

    #[test]
    fn substring_works() {
        let r = try_call("substring", &[Value::Str("abcdef".into()), Value::Int(1), Value::Int(3)])
            .unwrap()
            .unwrap();
        assert_eq!(r, Value::Str("bcd".into()));
    }

    #[test]
    fn sha256_real_known_vector() {
        let r = try_call("hash_sha256", &[Value::Str("abc".into())]).unwrap().unwrap();
        assert_eq!(
            r,
            Value::Str("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".into())
        );
    }
}
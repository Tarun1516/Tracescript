//! Host functions — operations that need access to runtime state (tables, alerts)
//! and live as a thin layer on top of the `Value` system.
//!
//! Both the tree-walking interpreter and the bytecode VM route their call handling
//! through this module. Keeping it in one place means the host-side semantics stay
//! consistent across execution modes.

use crate::error::{Result, TraceError};
use crate::interp::value::Value;
use crate::tables::TableStore;

/// Return the number of rows currently in the named table, or a runtime error.
pub fn count(store: &TableStore, name: &str) -> Result<Value> {
    store.count(name).map(|n| Value::Int(n as i64)).map_err(|e| match e {
        TraceError::Runtime { msg, .. } => TraceError::Runtime { msg, pos: None },
        other => other,
    })
}

/// Keep only the rows whose `field` is equal to `needle`. Returns the number of
/// rows kept (also reflected in the table).
pub fn filter(store: &mut TableStore, name: &str, field: &str, needle: &str) -> Result<Value> {
    let field_idx = store
        .get(name)
        .and_then(|t| t.fields.iter().position(|f| f.name == field))
        .ok_or_else(|| TraceError::Runtime {
            msg: format!("filter: unknown table or field '{}'", field),
            pos: None,
        })?;
    let n_before = store.count(name).unwrap_or(0);
    store.get_mut(name).unwrap().rows.retain(|row| {
        matches!(&row[field_idx], Value::Str(s) if s == needle)
    });
    let n_after = store.count(name).unwrap_or(0);
    let _ = n_before;
    Ok(Value::Int(n_after as i64))
}

/// Sort the table in place by a string field in ascending order. Returns Unit.
pub fn sort(store: &mut TableStore, name: &str, field: &str) -> Result<Value> {
    let idx = store
        .get(name)
        .and_then(|t| t.fields.iter().position(|f| f.name == field))
        .ok_or_else(|| TraceError::Runtime {
            msg: format!("sort: unknown field '{}'", field),
            pos: None,
        })?;
    let t = store.get_mut(name).unwrap();
    t.rows.sort_by(|a, b| {
        let av = a.get(idx).map(|v| v.to_string()).unwrap_or_default();
        let bv = b.get(idx).map(|v| v.to_string()).unwrap_or_default();
        av.cmp(&bv)
    });
    Ok(Value::Unit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{TableField, TypeName};

    fn make_store() -> TableStore {
        let mut s = TableStore::new();
        s.create(
            "t".into(),
            vec![
                TableField {
                    name: "host".into(),
                    field_type: TypeName::Str,
                },
                TableField {
                    name: "n".into(),
                    field_type: TypeName::Int,
                },
            ],
        )
        .unwrap();
        s.insert("t", vec![Value::Str("a".into()), Value::Int(1)])
            .unwrap();
        s.insert("t", vec![Value::Str("b".into()), Value::Int(2)])
            .unwrap();
        s.insert("t", vec![Value::Str("a".into()), Value::Int(3)])
            .unwrap();
        s
    }

    #[test]
    fn count_returns_rows() {
        let s = make_store();
        let r = count(&s, "t").unwrap();
        assert_eq!(r, Value::Int(3));
    }

    #[test]
    fn filter_keeps_matching_rows() {
        let mut s = make_store();
        filter(&mut s, "t", "host", "a").unwrap();
        assert_eq!(s.count("t").unwrap(), 2);
    }

    #[test]
    fn sort_orders_rows() {
        let mut s = make_store();
        sort(&mut s, "t", "host").unwrap();
        let t = s.get("t").unwrap();
        assert_eq!(t.rows[0][0], Value::Str("a".into()));
        assert_eq!(t.rows[1][0], Value::Str("a".into()));
        assert_eq!(t.rows[2][0], Value::Str("b".into()));
    }
}
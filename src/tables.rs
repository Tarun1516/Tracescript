//! Table engine for TraceScript.
//!
//! Tables are declared with column names and types, then rows are appended via
//! `insert`. They can be displayed (`show`) and exported to CSV/JSON.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use serde::Serialize;

use crate::error::{Result, TraceError};
use crate::interp::value::Value;
use crate::parser::TableField;

#[derive(Debug, Clone)]
pub struct Table {
    pub name: String,
    pub fields: Vec<TableField>,
    pub rows: Vec<Vec<Value>>,
}

impl Table {
    pub fn new(name: String, fields: Vec<TableField>) -> Self {
        Self {
            name,
            fields,
            rows: Vec::new(),
        }
    }

    pub fn insert(&mut self, row: Vec<Value>) -> Result<()> {
        if row.len() != self.fields.len() {
            return Err(TraceError::Runtime {
                msg: format!(
                    "table '{}' expects {} values, got {}",
                    self.name,
                    self.fields.len(),
                    row.len()
                ),
                pos: None,
            });
        }
        self.rows.push(row);
        Ok(())
    }

    pub fn show(&self) {
        if self.rows.is_empty() {
            println!("TABLE {}", self.name);
            println!("(no rows)");
            return;
        }

        // Compute column widths
        let mut widths: Vec<usize> = self
            .fields
            .iter()
            .map(|f| f.name.len())
            .collect();
        for row in &self.rows {
            for (i, v) in row.iter().enumerate() {
                let s = v.to_string();
                if i < widths.len() && s.len() > widths[i] {
                    widths[i] = s.len();
                }
            }
        }

        println!("TABLE {}", self.name);
        // header
        let header: Vec<String> = self
            .fields
            .iter()
            .enumerate()
            .map(|(i, f)| pad(&f.name, widths[i]))
            .collect();
        println!("{}", header.join(" "));
        let sep: Vec<String> = widths.iter().map(|w| "-".repeat(*w)).collect();
        println!("{}", sep.join(" "));
        for row in &self.rows {
            let cells: Vec<String> = row
                .iter()
                .enumerate()
                .map(|(i, v)| {
                    if i < widths.len() {
                        pad(&v.to_string(), widths[i])
                    } else {
                        v.to_string()
                    }
                })
                .collect();
            println!("{}", cells.join(" "));
        }
    }

    pub fn export_csv(&self, path: &Path) -> Result<()> {
        let f = File::create(path)?;
        let mut wtr = csv::Writer::from_writer(BufWriter::new(f));
        wtr.write_record(self.fields.iter().map(|f| f.name.clone()))
            .map_err(|e| TraceError::Io { msg: e.to_string() })?;
        for row in &self.rows {
            let rec: Vec<String> = row.iter().map(|v| v.to_string()).collect();
            wtr.write_record(&rec).map_err(|e| TraceError::Io { msg: e.to_string() })?;
        }
        wtr.flush().map_err(|e| TraceError::Io { msg: e.to_string() })?;
        Ok(())
    }

    pub fn export_json(&self, path: &Path) -> Result<()> {
        #[derive(Serialize)]
        struct Out<'a> {
            table: &'a str,
            columns: Vec<&'a str>,
            rows: Vec<BTreeMap<String, String>>,
        }
        let cols: Vec<&str> = self.fields.iter().map(|f| f.name.as_str()).collect();
        let mut rows: Vec<BTreeMap<String, String>> = Vec::new();
        for row in &self.rows {
            let mut m = BTreeMap::new();
            for (i, f) in self.fields.iter().enumerate() {
                m.insert(f.name.clone(), row[i].to_string());
            }
            rows.push(m);
        }
        let out = Out {
            table: &self.name,
            columns: cols,
            rows,
        };
        let s = serde_json::to_string_pretty(&out)
            .map_err(|e| TraceError::Runtime { msg: e.to_string(), pos: None })?;
        let mut f = File::create(path)?;
        f.write_all(s.as_bytes())?;
        Ok(())
    }
}

fn pad(s: &str, w: usize) -> String {
    if s.len() >= w {
        s.to_string()
    } else {
        let mut out = String::with_capacity(w);
        out.push_str(s);
        for _ in 0..(w - s.len()) {
            out.push(' ');
        }
        out
    }
}

#[derive(Debug, Clone, Default)]
pub struct TableStore {
    tables: BTreeMap<String, Table>,
}

impl TableStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn create(&mut self, name: String, fields: Vec<TableField>) -> Result<()> {
        if self.tables.contains_key(&name) {
            return Err(TraceError::Runtime {
                msg: format!("table '{}' already exists", name),
                pos: None,
            });
        }
        self.tables.insert(name.clone(), Table::new(name, fields));
        Ok(())
    }

    pub fn get(&self, name: &str) -> Option<&Table> {
        self.tables.get(name)
    }

    pub fn get_mut(&mut self, name: &str) -> Option<&mut Table> {
        self.tables.get_mut(name)
    }

    pub fn insert(&mut self, name: &str, row: Vec<Value>) -> Result<()> {
        let t = self.tables.get_mut(name).ok_or_else(|| TraceError::Runtime {
            msg: format!("unknown table '{}'", name),
            pos: None,
        })?;
        t.insert(row)
    }

    pub fn show(&self, name: &str) -> Result<()> {
        let t = self.tables.get(name).ok_or_else(|| TraceError::Runtime {
            msg: format!("unknown table '{}'", name),
            pos: None,
        })?;
        t.show();
        Ok(())
    }

    pub fn export(&self, name: &str, path: &str) -> Result<()> {
        let t = self.tables.get(name).ok_or_else(|| TraceError::Runtime {
            msg: format!("unknown table '{}'", name),
            pos: None,
        })?;
        let p = Path::new(path);
        let lower = path.to_lowercase();
        if lower.ends_with(".json") {
            t.export_json(p)
        } else {
            // default to CSV
            t.export_csv(p)
        }
    }

    pub fn count(&self, name: &str) -> Result<usize> {
        let t = self.tables.get(name).ok_or_else(|| TraceError::Runtime {
            msg: format!("unknown table '{}'", name),
            pos: None,
        })?;
        Ok(t.rows.len())
    }

    pub fn names(&self) -> Vec<String> {
        self.tables.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::TypeName;

    #[test]
    fn insert_and_show() {
        let mut store = TableStore::new();
        store
            .create(
                "t".into(),
                vec![
                    TableField {
                        name: "a".into(),
                        field_type: TypeName::Str,
                    },
                    TableField {
                        name: "b".into(),
                        field_type: TypeName::Int,
                    },
                ],
            )
            .unwrap();
        store
            .insert("t", vec![Value::Str("x".into()), Value::Int(1)])
            .unwrap();
        assert_eq!(store.count("t").unwrap(), 1);
    }

    #[test]
    fn arity_mismatch() {
        let mut store = TableStore::new();
        store
            .create(
                "t".into(),
                vec![
                    TableField {
                        name: "a".into(),
                        field_type: TypeName::Str,
                    },
                    TableField {
                        name: "b".into(),
                        field_type: TypeName::Int,
                    },
                ],
            )
            .unwrap();
        let err = store.insert("t", vec![Value::Int(1)]).unwrap_err();
        assert!(matches!(err, TraceError::Runtime { .. }));
    }
}
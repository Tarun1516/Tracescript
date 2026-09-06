//! Output formatting helpers.
//!
//! `show` and `export` are primarily handled by the table engine itself (`tables`).
//! This module currently exists to document the output API and to host any future
//! formats (e.g. JSONL streaming for very large tables).

use crate::error::Result;
use crate::tables::TableStore;

/// Pretty-print every table. Used by the CLI's `run --print-tables` debug flag.
pub fn show_all(store: &TableStore) -> Result<()> {
    let names = store.names();
    for (i, n) in names.iter().enumerate() {
        if i > 0 {
            println!();
        }
        store.show(n)?;
    }
    Ok(())
}
//! Integration tests for the full pipeline: lex + parse + semantic + interpreter +
//! runtime + table engine + exports.
//!
//! These tests run end-to-end without spawning the CLI; they exercise the public API
//! directly so they're cheap to add and easy to debug.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use tracescript::interp::value::Value;
use tracescript::interp::Interpreter;
use tracescript::parser::Parser;
use tracescript::runtime;
use tracescript::sema::Analyzer;

fn workspace_path() -> PathBuf {
    // The pcap generator and example scripts live in the workspace, not in `target/`.
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("test_data");
    p.push("lab_capture.pcap");
    p
}

fn run_program(src: &str) -> Interpreter {
    let prog = Parser::from_source(src).unwrap().parse_program().unwrap();
    let mut a = Analyzer::new();
    a.analyze(&prog).unwrap();
    let symbols = a.into_symbols();
    Interpreter::new(&prog, &symbols).unwrap()
}

#[test]
fn end_to_end_dns_pcap() {
    let src = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/dns_forensic.trace"),
    )
    .unwrap();
    let mut interp = run_program(&src);
    let n = runtime::run_pcap(&workspace_path(), &mut interp).unwrap();
    assert!(n >= 5, "expected several DNS queries, got {}", n);
    // Two suspicious queries should have produced alerts.
    assert_eq!(interp.alerts.len(), 2, "alerts: {:?}", interp.alerts);
    // Table should be populated.
    let t = interp.tables.get("dns_events").expect("table");
    assert!(t.rows.len() >= 5);
    let first_query = match &t.rows[0][3] {
        Value::Str(s) => s.clone(),
        _ => panic!("expected string query"),
    };
    assert_eq!(first_query, "example.com");
}

#[test]
fn synthetic_event_dispatch() {
    let src = r#"
        table counters { label: string, value: int }
        function bump(n) { return n + 1 }
        on tick(event) {
            insert counters(event.label, bump(event.value))
        }
        after finish {
            show counters
        }
    "#;
    let mut interp = run_program(src);
    let mut fields = HashMap::new();
    fields.insert("label".into(), Value::Str("a".into()));
    fields.insert("value".into(), Value::Int(1));
    interp.dispatch_event("tick", fields.clone()).unwrap();
    fields.insert("label".into(), Value::Str("b".into()));
    fields.insert("value".into(), Value::Int(7));
    interp.dispatch_event("tick", fields).unwrap();
    interp.run_finish().unwrap();
    let t = interp.tables.get("counters").unwrap();
    assert_eq!(t.rows.len(), 2);
}
#[test]
fn runs_complex_capture_through_interpreter() {
    use std::path::PathBuf;
    let src_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("examples")
        .join("complex_protocols.trace");
    let pcap = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("test_data")
        .join("complex.pcap");
    let src_text = std::fs::read_to_string(&src_path).unwrap();
    let prog = tracescript::parser::Parser::from_source(&src_text)
        .unwrap()
        .parse_program()
        .unwrap();
    let mut a = tracescript::sema::Analyzer::new();
    a.analyze(&prog).unwrap();
    let symbols = a.into_symbols();
    let mut interp = tracescript::interp::Interpreter::new(&prog, &symbols).unwrap();
    let src_path = interp.source_path().map(|s| s.to_string());
    tracescript::runtime::run_script(&mut interp, src_path.as_deref(), Some(pcap.to_str().unwrap())).unwrap();
    interp.run_finish().unwrap();
    // We expect at least 4 alerts (2 suspicious DNS, 1 TLS SYN, 1 sensitive HTTP).
    assert!(interp.alerts.len() >= 4, "alerts = {:?}", interp.alerts);
    // Events table should have rows.
    assert!(!interp.tables.get("events").unwrap().rows.is_empty());
}

#[test]
fn filter_extracts_matching_frames() {
    use std::path::PathBuf;
    let input = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("test_data")
        .join("complex.pcap");
    let output = std::env::temp_dir().join("ts_extract_test.pcap");
    let n = tracescript::runtime::extract_matching_frames(
        &input,
        &output,
        &tracescript::filter::Filter::parse("udp port 53").ok(),
        &None,
    )
    .unwrap();
    // The complex pcap has 5 DNS-over-UDP queries.
    assert_eq!(n, 5);
    assert!(output.exists());
    std::fs::remove_file(&output).ok();
}

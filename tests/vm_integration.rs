//! Integration tests for the bytecode VM. Each test parses a small script, compiles
//! it to a `BytecodeModule`, runs it through the VM, and asserts the resulting state.
//!
//! The interpreter and VM should produce identical observable behaviour for the
//! same input — that property is what these tests guard.

use std::collections::HashMap;
use std::path::PathBuf;

use tracescript::bytecode::vm::VM;
use tracescript::bytecode::codegen::compile;
use tracescript::interp::value::Value;
use tracescript::parser::Parser;
use tracescript::runtime;
use tracescript::sema::Analyzer;

fn build_vm(src: &str) -> VM {
    let prog = Parser::from_source(src).unwrap().parse_program().unwrap();
    let mut a = Analyzer::new();
    a.analyze(&prog).unwrap();
    let module = compile(&prog).unwrap();
    VM::new(module).unwrap()
}

#[test]
fn vm_handles_arithmetic_and_assignment() {
    let src = r#"
        table t { a: int, b: int }
        on e(x) {
            let n = 1 + 2 * 3
            let m = n - 4
            insert t(n, m)
        }
        after finish { show t }
    "#;
    let mut vm = build_vm(src);
    let mut f = HashMap::new();
    f.insert("k".into(), Value::Int(0));
    vm.dispatch_event("e", f).unwrap();
    vm.run_finish().unwrap();
    let t = vm.tables.get("t").unwrap();
    assert_eq!(t.rows[0][0], Value::Int(7));
    assert_eq!(t.rows[0][1], Value::Int(3));
}

#[test]
fn vm_string_concat_and_comparison() {
    let src = r#"
        function join(a, b) { return a + b }
        on e(x) { print join("foo", "bar") }
    "#;
    let mut vm = build_vm(src);
    let mut f = HashMap::new();
    f.insert("k".into(), Value::Int(0));
    vm.dispatch_event("e", f).unwrap();
}

#[test]
fn vm_runs_user_defined_function() {
    let src = r#"
        function double(n) { return n * 2 }
        on e(x) { alert(double(5)) }
    "#;
    let mut vm = build_vm(src);
    let mut f = HashMap::new();
    f.insert("k".into(), Value::Int(0));
    vm.dispatch_event("e", f).unwrap();
    assert_eq!(vm.alerts.len(), 1);
    assert_eq!(vm.alerts[0][0], Value::Int(10));
}

#[test]
fn vm_handles_if_else() {
    let src = r#"
        function sign(n) {
            if n > 0 { return 1 }
            else { return -1 }
        }
        on e(x) { alert(sign(5), sign(-3)) }
    "#;
    let mut vm = build_vm(src);
    let mut f = HashMap::new();
    f.insert("k".into(), Value::Int(0));
    vm.dispatch_event("e", f).unwrap();
    assert_eq!(vm.alerts[0][0], Value::Int(1));
    assert_eq!(vm.alerts[0][1], Value::Int(-1));
}

#[test]
fn vm_pcap_pipeline_matches_interpreter() {
    use tracescript::interp::Interpreter;
    let pcap = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("test_data")
        .join("mixed.pcap");
    let src_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("examples")
        .join("mixed_protocols.trace");

    // Interpreter run.
    let src_text = std::fs::read_to_string(&src_path).unwrap();
    let prog = Parser::from_source(&src_text).unwrap().parse_program().unwrap();
    let mut interp = Analyzer::new();
    interp.analyze(&prog).unwrap();
    let symbols = interp.into_symbols();
    let mut interp = Interpreter::new(&prog, &symbols).unwrap();
    let sp = interp.source_path().map(|s| s.to_string());
    runtime::run_script(&mut interp, sp.as_deref(), Some(pcap.to_str().unwrap())).unwrap();
    interp.run_finish().unwrap();

    // VM run.
    let prog2 = Parser::from_source(&src_text).unwrap().parse_program().unwrap();
    let mut sema2 = Analyzer::new();
    sema2.analyze(&prog2).unwrap();
    let module = compile(&prog2).unwrap();
    let mut vm = VM::new(module).unwrap();
    let sp = vm.source_path().map(|s| s.to_string());
    runtime::run_script(&mut vm, sp.as_deref(), Some(pcap.to_str().unwrap())).unwrap();
    vm.run_finish().unwrap();

    // The two backends should agree on every row in every table.
    for name in interp.tables.names() {
        let it = interp.tables.get(&name).unwrap();
        let vt = vm.tables.get(&name).unwrap_or_else(|| panic!("vm missing table {}", name));
        assert_eq!(it.rows.len(), vt.rows.len(), "row count differs for {}", name);
        for (i, (ir, vr)) in it.rows.iter().zip(vt.rows.iter()).enumerate() {
            assert_eq!(ir, vr, "row {} differs in table {}", i, name);
        }
    }
    assert_eq!(interp.alerts.len(), vm.alerts.len());
}

#[test]
fn vm_runs_long_run_capture() {
    let src = r#"
        source pcap "test_data/long_run.pcap"
        table counts { qname: string }
        on dns_query(event) { insert counts(event.query) }
        after finish { print count("counts") }
    "#;
    let mut vm = build_vm(src);
    let pcap = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("test_data")
        .join("long_run.pcap");
    let sp = vm.source_path().map(|s| s.to_string());
    runtime::run_script(&mut vm, sp.as_deref(), Some(pcap.to_str().unwrap())).unwrap();
    vm.run_finish().unwrap();
    let t = vm.tables.get("counts").unwrap();
    assert_eq!(t.rows.len(), 200);
}

#[test]
fn vm_reads_jsonl_log() {
    let src = r#"
        source jsonl "test_data/sample.jsonl"
        table t { user: string, action: string }
        on log_entry(event) { insert t(event.user, event.action) }
    "#;
    let mut vm = build_vm(src);
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("test_data")
        .join("sample.jsonl");
    let sp = vm.source_path().map(|s| s.to_string());
    runtime::run_script(&mut vm, sp.as_deref(), Some(p.to_str().unwrap())).unwrap();
    vm.run_finish().unwrap();
    let t = vm.tables.get("t").unwrap();
    assert_eq!(t.rows.len(), 3);
}
#[test]
fn vm_runs_for_loop_over_table() {
    let src = r#"
        table nums { n: int }
        on e(x) {
            insert t(1)
            insert t(2)
            insert t(3)
        }
        after finish {
            let sum = 0
            for row in t {
                # row is a JSON-shaped string; for now we just count.
                let sum = sum + 1
            }
            alert(sum)
        }
    "#;
    // Note: this test won't work as-is because t doesn't exist; we use `nums`.
    let src = r#"
        table nums { n: int }
        on e(x) {
            insert nums(1)
            insert nums(2)
            insert nums(3)
        }
        after finish {
            let sum = 0
            for row in nums {
                let sum = sum + 1
            }
            alert(sum)
        }
    "#;
    let mut vm = build_vm(src);
    let mut f = HashMap::new();
    f.insert("k".into(), Value::Int(0));
    vm.dispatch_event("e", f).unwrap();
    vm.run_finish().unwrap();
    assert_eq!(vm.alerts.len(), 1);
    assert_eq!(vm.alerts[0][0], Value::Int(3));
}

#[test]
fn vm_index_assign_modifies_row() {
    let src = r#"
        table t { name: string, score: int }
        on e(x) {
            insert t("alice", 10)
            insert t("bob", 20)
        }
        after finish {
            t[0].score = 99
        }
    "#;
    let mut vm = build_vm(src);
    let mut f = HashMap::new();
    f.insert("k".into(), Value::Int(0));
    vm.dispatch_event("e", f).unwrap();
    vm.run_finish().unwrap();
    let t = vm.tables.get("t").unwrap();
    assert_eq!(t.rows[0][1], Value::Int(99));
    assert_eq!(t.rows[1][1], Value::Int(20));
}

#[test]
fn vm_index_expression_evaluates_to_row_string() {
    let src = r#"
        table t { a: string }
        on e(x) {
            insert t("hello")
            insert t("world")
        }
        after finish {
            print t[1]
        }
    "#;
    let mut vm = build_vm(src);
    let mut f = HashMap::new();
    f.insert("k".into(), Value::Int(0));
    vm.dispatch_event("e", f).unwrap();
    vm.run_finish().unwrap();
}

#[test]
fn interpreter_handles_for_loop() {
    use tracescript::interp::Interpreter;
    let src = r#"
        table nums { n: int }
        on e(x) {
            insert nums(1)
            insert nums(2)
        }
        after finish {
            let total = 0
            for row in nums {
                let total = total + 1
            }
            alert(total)
        }
    "#;
    let prog = Parser::from_source(src).unwrap().parse_program().unwrap();
    let mut a = Analyzer::new();
    a.analyze(&prog).unwrap();
    let symbols = a.into_symbols();
    let mut interp = Interpreter::new(&prog, &symbols).unwrap();
    let mut f = HashMap::new();
    f.insert("k".into(), Value::Int(0));
    interp.dispatch_event("e", f).unwrap();
    interp.run_finish().unwrap();
    assert_eq!(interp.alerts[0][0], Value::Int(2));
}

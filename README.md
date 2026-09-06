# TraceScript

An event-driven **forensic scripting language** for analysing packet-capture
files and structured logs. Write `.trace` scripts that read offline `.pcap`
captures, JSONL or CSV logs, decode network events (DNS queries, TCP
connections, HTTP requests), store them in structured tables, run detection
rules, and export results as console tables, CSV, or JSON.

The language is implemented from scratch in Rust. Two execution modes are
provided:

- a tree-walking **interpreter** for fast iteration and debugging, and
- a **bytecode compiler + stack VM** for production runs. Compile to a
  `.traceb` file once and replay it against many captures.

Both modes are kept in sync by an integration test that asserts they produce
identical tables for the same input.

> **Ethical scope.** TraceScript is designed for *passive, authorised* forensic
> analysis of captures produced by the analyst in an isolated lab. The
> language does **not** expose any facility for live capture, log deletion,
> AV/EDR bypass, or process manipulation. See `docs/security-notes.md` for
> the explicit allow-list and deny-list.

## Quick start

```bash
# 1. Build
cargo build --release

# 2. Generate synthetic lab captures (lab traffic only, never production networks)
cd test_data && python3 make_lab_pcap.py && cd ..

# 3. Run the bundled forensic example with the interpreter
./target/release/tracescript run examples/dns_forensic.trace \
    --pcap test_data/dns_only.pcap

# 4. Same script, this time through the bytecode VM
./target/release/tracescript run examples/dns_forensic.trace --vm \
    --pcap test_data/dns_only.pcap

# 5. Or compile once and run repeatedly
./target/release/tracescript compile examples/dns_forensic.trace -o dns.traceb
./target/release/tracescript vm dns.traceb --pcap test_data/dns_only.pcap

# 6. Extract matching frames to a new pcap (evidence preservation)
./target/release/tracescript extract test_data/complex.pcap -o sus.pcap \
    --filter 'host 10.0.0.5 and tcp port 80'

# 7. Interactive REPL
./target/release/tracescript repl
```

The script extracts DNS queries from the capture, populates a `dns_events`
table, fires alerts on suspicious domains (`.xyz`, `.invalid`, length > 40),
and exports the table to `out_dns_events.csv` and `out_dns_events.json`.

## Language at a glance

```text
source pcap "lab_capture.pcap"

table dns_events {
    time:   string,
    src_ip: string,
    query:  string,
    qtype:  string
}

function is_suspicious(d) {
    if ends_with(d, ".xyz") or len(d) > 40 {
        return true
    }
    return false
}

on dns_query(event) {
    if is_suspicious(event.query) {
        alert("Suspicious DNS query", event.query)
    }
    insert dns_events(event.time, event.src_ip, event.query, event.qtype)
}

after finish {
    show dns_events
    export dns_events to "dns_events.csv"
    export dns_events to "dns_events.json"
}
```

### Data types

`int`, `float`, `string`, `bool`, `time` (stored as ISO-8601 string), `ip`
(stored as dotted-quad string), `event` (a record of named fields), `table`.

### Statements

`let`, `=`, `if/else`, `insert`, `show`, `export`, `alert`, `print`,
`return`, function call as statement.

### Expressions

Standard precedence: `or` < `and` < equality (`==`, `!=`) < comparison (`<`,
`>`, `<=`, `>=`, `contains`) < additive (`+`, `-`) < multiplicative (`*`,
`/`, `%`) < unary (`!`, `-`) < primary.

Field access on events: `event.query`. Function calls: `len(s)`,
`contains(s, sub)`, `starts_with`, `ends_with`, `to_string`, `now`,
`substring`, `lower`, `upper`, `trim`, `hash_sha256` (real SHA-256,
FIPS 180-4).

### Host functions

These require table access and are dispatched by the runtime, not the pure
builtin registry: `count(table)`, `filter(table, field, value)`,
`sort(table, field)`.

### Declarations

- `source pcap "PATH"` / `source jsonl "PATH"` / `source csv "PATH"` —
  declare the input source.
- `table NAME { field: type, ... }` — declare a structured result table.
- `on EVENT_NAME(param) { ... }` — register an event handler.
- `after finish { ... }` — register a finalisation handler.
- `function NAME(params) { ... }` — declare a helper function.

## CLI

```text
tracescript <command> [args]

  lex      <script>            Tokenize and print tokens
  parse    <script>            Tokenize, parse, and print the AST
  check    <script>            Lex + parse + semantic check
  run      <script> [--pcap PATH] [--vm] [--filter EXPR] [--grep NEEDLE]
                                [--print-tables] [--log-file PATH]
                                Execute the script. --vm routes through bytecode VM.
  compile  <script> [-o PATH]   Compile to bytecode (.traceb)
  vm       <module> [--pcap PATH] [--filter EXPR] [--grep NEEDLE]
                                [--log-file PATH]
                                Run a compiled bytecode module
  repl                          Interactive REPL
  extract  <input.pcap> -o <out.pcap>
            [--filter EXPR] [--grep NEEDLE]
                                Extract frames matching filter to a new pcap
```

`run` and `vm` return exit code `0` on success, `2` on a TraceError (lex /
parse / semantic / runtime), so the tool is shell-pipeline friendly.

## Events

| Event              | Trigger                                                  | Fields                                                                                |
|--------------------|----------------------------------------------------------|---------------------------------------------------------------------------------------|
| `packet`           | every IPv4 frame                                         | `time`, `src_ip`, `dst_ip`, `length`, `protocol`, `packet_id`                          |
| `tcp_connection`   | every TCP segment                                        | `time`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `seq`, `ack`, `flags`              |
| `dns_query`        | DNS query on UDP/53 or TCP/53                            | `time`, `src_ip`, `dst_ip`, `query`, `qtype`, `packet_id`, `is_response`               |
| `dns_response`     | DNS response on UDP/53 or TCP/53                         | same as `dns_query`                                                                   |
| `http_request`     | ASCII HTTP/1.x request to TCP/80 or 8080                | `time`, `src_ip`, `dst_ip`, `method`, `uri`, `version`, `host`, `user_agent`, `packet_id` |
| `log_entry`        | one per JSONL or CSV record                              | derived from the record's keys/columns                                                |

## Project layout

```text
tracescript/
    Cargo.toml
    README.md
    docs/
        language_spec.md
        security-notes.md
    examples/
        dns_forensic.trace         # Main demo: DNS detection + export
        mixed_protocols.trace      # TCP / HTTP / DNS over UDP+TCP
        jsonl_audit.trace          # Log-file (JSONL) audit trail
        demo_no_io.trace           # Interpreter-only demo (no pcap)
        duplicate_table.trace      # Expected to fail semantic check
        mixed_protocols.trace      # TCP / HTTP / DNS over UDP+TCP
        complex_protocols.trace    # All-event tour (DNS, TCP, HTTP, ICMP, ARP)
        jsonl_audit.trace          # Log-file (JSONL) audit trail
        csv_employees.trace        # CSV source demo
    test_data/
        make_lab_pcap.py           # Synthetic-pcap generator (lab only)
        dns_only.pcap              # DNS over UDP only
        mixed.pcap                 # DNS over UDP+TCP plus HTTP GET and TCP SYN
        complex.pcap               # Multi-protocol realistic capture
        long_run.pcap              # 200 DNS queries (stress test)
        sample.jsonl               # Example JSONL log
        employees.csv              # Example CSV
    src/
        lib.rs                     # Library entry for integration tests
        main.rs                    # CLI entry
        build.rs                   # build.rs: git SHA + build date for --version
        cli.rs                     # Clap-based subcommand dispatch
        error.rs                   # TraceError + SourcePos
        filter.rs                  # BPF-style packet filter
        lexer.rs                   # Tokeniser (recursive scan)
        parser.rs                  # Recursive-descent parser + AST
        sema.rs                    # Symbol tables + semantic checks
        interp/
            mod.rs                 # Tree-walking interpreter
            value.rs               # Runtime Value enum
            builtins.rs            # Standard library
        tables.rs                  # Table engine + CSV/JSON export
        runtime.rs                 # Pcap + JSONL + CSV readers + decoders + dispatcher
        host.rs                    # count / filter / sort (table-aware builtins)
        sha256.rs                  # Self-contained SHA-256 (FIPS 180-4)
        output.rs                  # Output helpers
        bytecode/
            mod.rs
            opcode.rs              # Instruction set + serialised module
            codegen.rs             # AST → bytecode
            vm.rs                  # Stack-based VM
    tests/
        integration.rs             # End-to-end interpreter + pcap pipeline
        vm_integration.rs          # VM + interpreter parity tests
        fuzz_lexer.rs              # Random-byte fuzz harness
```

## Development

```bash
cargo build --release
cargo test                # 120 tests across 6 binaries
cargo run -- lex examples/dns_forensic.trace
cargo run -- parse examples/dns_forensic.trace
cargo run -- check examples/dns_forensic.trace
cargo run -- run examples/dns_forensic.trace --pcap test_data/dns_only.pcap
cargo run -- run examples/dns_forensic.trace --vm --pcap test_data/dns_only.pcap
cargo run -- compile examples/dns_forensic.trace -o dns.traceb
cargo run -- vm dns.traceb --pcap test_data/dns_only.pcap
cargo run -- run examples/complex_protocols.trace \
    --pcap test_data/complex.pcap \
    --filter 'host 10.0.0.5' --grep 'evil' --log-file alerts.jsonl
cargo run -- extract test_data/complex.pcap -o sus.pcap \
    --filter 'tcp port 443'
cargo run -- repl
```

## Security and ethical scope

The language is scoped to **defensive forensic analysis**:

- ✅ Read offline `.pcap` / `.jsonl` / `.csv` files you own.
- ✅ Decode packet headers (Ethernet, IPv4, TCP, UDP) and DNS / HTTP requests.
- ✅ Store events in tables, show them, export to CSV/JSON.
- ✅ Generate alerts based on script-defined rules.
- ✅ Compile scripts to a portable `.traceb` bytecode module.
- ❌ No live capture interface.
- ❌ No file deletion, no log tampering.
- ❌ No process / EDR / AV interaction.
- ❌ No network injection, MITM, or scanning.

Use TraceScript only against captures produced in an isolated lab VM that you
control. Do not point it at traffic from networks you don't own.
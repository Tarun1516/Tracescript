# TraceScript language specification (v0.1)

This document pins down the syntax and semantics of TraceScript as implemented in
the current version of the toolchain. Anything not in this document is not part of
the language.

## 1. Program structure

A TraceScript program is a sequence of **declarations**:

```ebnf
program        := declaration*
declaration    := source_decl | table_decl | event_handler_decl
                | finish_handler_decl | function_decl
```

Every declaration is global. There are no nested scopes in the source other than
function and event-handler bodies.

## 2. Source declaration

```text
source pcap "path/to/file.pcap"
```

Declares the offline packet capture to analyse. Exactly one `source` declaration is
allowed per program; duplicates are a semantic error. The runtime reads the file
when the program starts executing.

## 3. Tables

```text
table NAME {
    field1: type,
    field2: type,
    ...
}
```

Field types are `int`, `float`, `string`, `bool`, `time`, `ip`. Tables are
append-only: rows are inserted in declaration order via `insert` and rendered by
`show` / `export` in the same order.

`time` and `ip` are stored as strings internally — the type system distinguishes
them by name but the value carries the canonical textual form.

## 4. Events and handlers

```text
on EVENT_NAME(param) {
    statement*
}
```

`EVENT_NAME` is a script-defined identifier. The runtime fires one event per
matched packet / log record; the handler body executes with the parameter bound
to the event object.

Events emitted in v0.1 by the runtime:

- `packet` — every IPv4 frame seen in the source. Fields: `time`, `src_ip`,
  `dst_ip`, `length`, `protocol`, `packet_id`.
- `tcp_connection` — every TCP segment. Fields: `time`, `src_ip`, `dst_ip`,
  `src_port`, `dst_port`, `seq`, `ack`, `flags` (a printable string like
  `"S"`, `"PA"`, `"R"`).
- `dns_query` / `dns_response` — DNS messages observed over UDP/53 or TCP/53.
  Fields: `time`, `src_ip`, `dst_ip`, `query`, `qtype`, `packet_id`,
  `is_response`.
- `http_request` — ASCII HTTP requests to TCP/80 or TCP/8080. Fields:
  `time`, `src_ip`, `dst_ip`, `method`, `uri`, `version`, `host`,
  `user_agent`, `packet_id`.
- `log_entry` — one per record when the source is JSONL or CSV. Fields are
  derived from the record's keys/columns.

A handler for an unknown event is silently ignored — this matches the Zeek
philosophy of "scripts that don't reference an event type have no effect".

## 5. Finish handler

```text
after finish {
    statement*
}
```

Executed exactly once after the source has been fully consumed. Typically used
for `show` and `export` statements.

## 6. Functions

```text
function NAME(param1, param2, ...) {
    statement*
    return EXPR
}
```

Return is implicit `()` if the last statement is not a `return`. Returning from
a non-function body is a runtime error.

## 7. Statements

| Statement     | Meaning                                          |
|---------------|--------------------------------------------------|
| `let x = E`   | Declare a local variable, visible for the rest of the enclosing block. |
| `x = E`       | Reassign an existing local variable.             |
| `if E { ... } else { ... }` | Branch on truthiness of `E`.           |
| `insert T(args)` | Append a row to table `T` with one value per column. |
| `alert(args)` | Print an alert and record it.                    |
| `show T`      | Render table `T` as a console table.             |
| `export T to "PATH"` | Write table `T` to disk; format inferred from the extension (`.csv` or `.json`). |
| `print E`     | Evaluate and print.                               |
| `NAME(args)`  | Function call as a statement.                    |
| `return E?`   | Early return from a function.                    |

## 8. Expressions

### Operators (in increasing precedence)

- `or`
- `and`
- `==`, `!=`
- `<`, `>`, `<=`, `>=`, `contains`
- `+`, `-` (string concatenation when both operands are strings)
- `*`, `/`, `%`
- `!`, unary `-`
- `.` field access, `()` call

`contains` is syntactic sugar for `BUILTIN_contains(a, b)` and is treated as a
binary operator at parse time.

### Literals

Integer (`42`), float (`3.14`), string (`"hello\n"`), bool (`true`/`false`).

### Field access

`EXPR.IDENTIFIER` — only defined on event values.

### Built-in functions

| Function         | Signature                              | Purpose                              |
|------------------|----------------------------------------|--------------------------------------|
| `len`            | `len(value) -> int`                    | String length (chars) or event size  |
| `contains`       | `contains(s, sub) -> bool`             | Substring search                     |
| `starts_with`    | `starts_with(s, p) -> bool`            | Prefix check                         |
| `ends_with`      | `ends_with(s, sfx) -> bool`            | Suffix check                         |
| `to_string`      | `to_string(v) -> string`               | Stringify any value                  |
| `now`            | `now() -> int`                         | UNIX seconds                         |
| `substring`      | `substring(s, start, len) -> string`   | Slice by chars                       |
| `lower` / `upper`| `lower(s) -> string`                   | ASCII case conversion                |
| `trim`           | `trim(s) -> string`                    | Strip whitespace                     |
| `hash_sha256`    | `hash_sha256(s) -> string`             | Hex digest (FNV-1a 64-bit for v0.1)  |

## 9. Truthiness

`false`, integer `0`, and empty string are falsy. Everything else, including
events and floats, is truthy.

## 10. Output formats

`show NAME` prints an ASCII table whose column widths are computed from the
largest cell. `export` writes to disk; the extension chooses the format (`.csv`
or `.json`). CSV uses the `csv` crate; JSON uses `serde_json` and emits a
document with `table`, `columns`, and `rows` keys.

## 11. Error reporting

Errors carry source positions (`line`, `column`) and a category (`lex`, `parse`,
`sema`, `runtime`, `io`). The CLI exits with status `2` on any error and prints
`error: [category] message at line X, column Y` to stderr.

## 12. Execution modes

The toolchain ships **two execution modes**:

- **Tree-walking interpreter** — `Interpreter::new(program, symbols).unwrap()`
  executes AST nodes directly. Use it for fast iteration and debugging.
- **Bytecode VM** — `bytecode::codegen::compile(program)` produces a
  `BytecodeModule`; `bytecode::vm::VM::new(module)` runs it. Use it for
  hot-path or production deployment. The two are kept in sync by
  `tests/vm_integration.rs` which asserts they produce identical tables for the
  same input.

## 13. Sources

The `source` declaration names an input source for the runtime. Three source
types are accepted:

- `source pcap "PATH"` — a libpcap-format `.pcap` file. The runtime emits
  `packet`, `tcp_connection`, `dns_query`, `dns_response`, and `http_request`
  events as it walks the file.
- `source jsonl "PATH"` — a newline-delimited JSON log. Each non-empty line is
  decoded into a `log_entry` event whose fields are the JSON object's keys.
- `source csv "PATH"` — a CSV file with a header row. Each subsequent row
  produces a `log_entry` event whose fields are named by the header.

## 14. What v0.1 deliberately omits

The following are out of scope for the first version and reserved for later
releases:

- Live network capture.
- TLS / SSH application-layer events.
- For loops (`for ... in ...` is a reserved keyword but not implemented).
- Modules / imports.
- Type coercions at runtime.

Anything outside this specification is implementation detail and may change
without notice.
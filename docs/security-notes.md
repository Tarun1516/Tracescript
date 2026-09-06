# Security and ethical notes

## What TraceScript is for

TraceScript is a domain-specific language for **passive forensic analysis of
network packet captures**. It is intended for use by:

- Security analysts reviewing evidence in an isolated lab.
- Researchers studying traffic patterns from captures they generated themselves.
- Incident-response teams standardising triage rules over `.pcap` files.

The original problem statement frames this as "analysis without triggering security
solutions". That interpretation is defensible only if the scope is restricted to
**read-only observation of captures you already have**.

## Allowed operations

The language exposes exactly the following defensive capabilities:

| Capability              | How it appears in the language             |
|-------------------------|--------------------------------------------|
| Read a `.pcap` file     | `source pcap "path.pcap"`                  |
| Decode DNS queries      | Implicit when an `on dns_query` handler exists |
| Store events in tables  | `table` + `insert`                         |
| Display results         | `show`, `print`                            |
| Export evidence         | `export NAME to "out.csv"`                 |
| Generate alerts         | `alert(...)`                               |
| Define detection rules  | `function`, `if`, comparison operators     |

## Explicit non-features

The following capabilities are **deliberately absent**. There is no built-in to
enable them and the interpreter does not provide any FFI to the host operating
system:

- Live network capture (no `pcap` crate `Capture` is used; only `pcap_file` for
  offline reads).
- Process / file / registry inspection or modification.
- Anti-virus / EDR disable.
- Log deletion or tampering.
- Code injection, DLL hijacking, credential dumping.
- Lateral movement or remote execution primitives.

The `runtime` module only opens files via `std::fs::File::open` and reads packets
through `pcap_file::PcapReader`. It never opens sockets, never spawns processes,
never invokes `unsafe` blocks.

## Lab-only directive

Do not point TraceScript at:

- College or office networks (even your own traffic there may be subject to institutional monitoring).
- Public Wi-Fi.
- Production systems or shared infrastructure.
- Third-party services.

The synthetic `.pcap` shipped in `test_data/lab_capture.pcap` is generated entirely
client-side by `test_data/make_lab_pcap.py` from fictitious IP/MAC addresses. It is
safe to inspect but contains no real network data.

## Reporting

If you find a way to use TraceScript in a non-defensive manner, that is a usage
bug, not a tool bug — please do not pursue it. If you discover an actual capability
of the language that the table above does not authorise, please open an issue.
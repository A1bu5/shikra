# Shikra

[![CI](https://github.com/A1bu5/shikra/actions/workflows/ci.yml/badge.svg)](https://github.com/A1bu5/shikra/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A cross-platform command-and-control framework written in native Rust, with a
Tauri operator console and a model-driven AI copilot. Shikra is a clean-room
implementation inspired by Sliver's architecture; no third-party C2 code is
vendored.

> [!WARNING]
> **Authorized use only.** Shikra is an adversary-emulation framework for
> red-team engagements, scoped penetration tests, lab research, and detection
> engineering. Using it against systems you do not own or have explicit
> written permission to test is illegal in most jurisdictions. You are
> responsible for compliance with your local laws and your rules of
> engagement. See [`SECURITY.md`](SECURITY.md) for reporting vulnerabilities.


## Architecture

```
┌──────────────┐   gRPC + mTLS      ┌──────────────┐   E2E encrypted  ┌──────────────┐
│ shikra-client│ ─────────────────▶ │ shikra-server│ ───────────────▶ │ shikra-implant│
│ (CLI / GUI)  │ ◀───────────────── │  (teamserver)│ ◀─────────────── │   (agent)     │
└──────────────┘                    └──────────────┘                  └──────────────┘
```

- **Implant** — a single binary supporting session, beacon, QUIC, DNS and
  WireGuard transports, with automatic fallback across them.
- **Teamserver** — a Tokio/tonic server exposing gRPC (mTLS), an HTTPS beacon
  listener with profile rotation, plus QUIC, DNS and WireGuard listeners.
- **Operator client** — a `shikra-client` CLI and a Tauri 2 console with
  terminal, file browser, payload builder, C2 profile editor, tunnels,
  extensions, team management and an AI copilot behind an approval gate.
  File paths use native pickers and drag-and-drop.

## Cryptography

- **Operator channel** — TLS with a generated CA/client certificate pair;
  operators authenticate with bearer tokens.
- **Agent channel** — application-layer end-to-end encryption: X25519 key
  exchange → HKDF-SHA256 → ChaCha20-Poly1305, with monotonically increasing
  sequence numbers to reject replays. Framing is transport-independent.
- **Enrollment** — Ed25519 identity signatures bound to the session key, with
  single-use enrollment tokens.
- **Extensions** — Ed25519-signed packages verified before execution.

## Building

Requires Rust 1.88 (pinned by `rust-toolchain.toml`) and a PostgreSQL 15+
database for the teamserver.

```sh
cargo build --release
cargo build --release -p shikra-implant     # agent binary
```

The operator console lives in `gui/` and builds with the Tauri 2 toolchain:

```sh
cd gui && cargo tauri dev      # development
cd gui && cargo tauri build    # signed bundle
```

### Environment

| Variable | Purpose |
| --- | --- |
| `SHIKRA_DATABASE_URL` | PostgreSQL connection string (required) |
| `SHIKRA_GRPC_ADDR` | Operator (gRPC) listener override |
| `SHIKRA_DNS_ADDR` / `SHIKRA_WG_ADDR` / `SHIKRA_DNS_ZONE` | DNS + WireGuard transport |
| `SHIKRA_STATE_DIR` | State directory (CA, keys, tokens, profiles) |
| `SHIKRA_LOG_FORMAT` | `text` or `json` |
| `SHIKRA_DNS_RESOLVER`, `SHIKRA_PUBLIC_IP` | Registration helpers |
| `SHIKRA_LLM_BASE_URL`, `SHIKRA_LLM_MODEL` | AI copilot backend |

## Quickstart

The GUI can host the teamserver for you (login page → "Host teamserver"):
initialize the material, start/stop the server and connect with the generated
operator token. **No PostgreSQL installation is required** — the console
provisions a private embedded PostgreSQL inside the state directory
(`pgdata/`) on first use, or you can point it at an external database URL.
Listener/transport endpoints are configured where payloads are built, not on
the login page. The CLI equivalent:

```sh
# 1. Bootstrap: generates CA, server certificate, tokens and keys. The CA is
#    created with rcgen on first run; private keys are written 0600.
shikra-server --bootstrap --state-dir ./state

# 2. Run: only the operator channel binds at boot; beacon listeners are
#    started at runtime from the console Listeners tab (or `shikra-client
#    listener-start --kind http --addr 0.0.0.0:8080`).
shikra-server --state-dir ./state --database-url postgres://localhost/shikra

# The bootstrap output prints the enrollment and operator tokens once.

# 2. Build an agent pointing at the teamserver.
shikra-builder --server https://127.0.0.1:8443 --token <enroll-token> \
  --mode beacon --output ./agent

# 3. Connect the operator client.
export SHIKRA_SERVER=https://127.0.0.1:8443
export SHIKRA_CA_CERT=./state/ca.pem
export SHIKRA_OPERATOR_TOKEN=<operator-token>
shikra-client sessions
```

## Capabilities

| Area | Commands |
| --- | --- |
| Execution | `shell`, `spawn`, `kill`, `execute-assembly` |
| File transfer | `ls`, `download`, `upload`, `rm`, `mkdir` |
| Injection | `inject`, `migrate`, `steal-token`, `make-token`, `rev2self` |
| Recon | `screenshot`, `portscan`, `ps`, `env`, `ifconfig` |
| Pivoting | `socks5`, `portfwd`, `rportfwd`, `rportfwd-stop`, `pivots` |
| Extensions | `bof`, `wasm-load`/`run`, `native-load`/`run`/`list`/`remove` |
| Registry | `extension-pack`, `extension-push`, `extension-install` |
| Profiles | `profiles`, `profiles-set` (live malleable C2 profile edits) |
| Collaboration | Team chat, event feed, session color tags/mark-dead/export, Discord webhook alerts |
| Listeners | `listeners`, `listener-start`, `listener-stop` (runtime beacon listeners) |
| ExternalC2 | HTTPS bridge for bring-your-own agents (`examples/external-agent/`) |
| Team | `team-operators`, `team-listeners`, `team-loot`, `team-canaries` |
| Build | `shikra-builder` (CLI) or the GUI Payload tab with server-profile baking |
| AI | `ai` (tool-calling operator behind an approval gate) |

Transports support automatic fallback: `--mode fallback
--fallback quic,http,dns,wireguard` with a per-transport connect timeout.

C2 profiles can be edited at runtime (GUI Profiles tab or
`shikra-client profiles-set profiles.json`); the HTTP listener picks up new
enroll/poll routes immediately, and beacons built afterwards bake the live
profile set in (`shikra-builder --profiles-file profiles.json`).

## Hardening

- Agent strings are obfuscated at compile time (`shikra-obf`) with a random
  per-build seed; `--no-obfuscation` opts out for debugging.
- Windows agents resolve NT syscalls dynamically and call them indirectly;
  AMSI/ETW providers are patched before injection tasks.
- Beacon traffic sleeps under memory encryption and jitters its timing.
- Teamserver enrollment is rate limited per peer (30 attempts/minute) and
  authentication failures are recorded as throttled audit events.

See `docs/OPSEC.md` for the operational security guide and
`docs/COMPARISON.md` for a feature-by-feature comparison with Sliver and
Havoc.

## Testing

```sh
export SHIKRA_TEST_DATABASE_URL=postgres://localhost/shikra_test
cargo test --workspace
cargo clippy --workspace --all-targets
cargo fmt --all -- --check
```

End-to-end coverage lives in `crates/server/tests/e2e.rs` (enrollment, beacons,
file transfer, tunnels, pivots, port scan, profiles, staged delivery, registry,
rate limiting).

## Repository layout

| Path | Contents |
| --- | --- |
| `crates/server` | Teamserver: gRPC, HTTP/QUIC/DNS/WireGuard listeners, audit log |
| `crates/implant` | Agent: transports, task handlers, post-exploitation |
| `crates/client` | Operator CLI and gRPC client library |
| `crates/proto` | Protobuf definitions |
| `crates/crypto` | E2E handshake, framing, token and certificate helpers |
| `crates/transport` | DNS/WireGuard transports, profiles, extension packages |
| `crates/store` | PostgreSQL persistence (sqlx) |
| `crates/builder` | Payload builder and stager generation |
| `crates/evasion` | Encoders, PE parsing, masking, sleep obfuscation |
| `crates/obf` | Compile-time string obfuscation macros |
| `crates/ai`, `crates/mcp` | AI copilot and MCP bridge |
| `gui` | Tauri 2 operator console |
| `migrations` | Database schema |
| `scripts` | Acceptance helpers |

## License

Licensed under the [Apache License, Version 2.0](LICENSE). Third-party
components are used under their own licenses (see `Cargo.lock` and
`deny.toml`).

Shikra is a clean-room implementation and contains no code from Sliver,
Havoc, Metasploit, Cobalt Strike, or any other C2 framework (see `NOTICE`).

Use it only on systems you own or are explicitly authorized to test.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). All contributions must be
clean-room and are accepted under the Developer Certificate of Origin.
Security reports go through [`SECURITY.md`](SECURITY.md), not public issues.

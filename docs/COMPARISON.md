# Shikra vs. Sliver vs. Havoc

A feature and architecture comparison between Shikra and the two widely known
open-source C2 frameworks it draws inspiration from. Facts about Sliver come
from its source tree and public documentation; facts about Havoc come from its
public repository (archived read-only in February 2026).

## Positioning

| | Shikra | Sliver | Havoc |
| --- | --- | --- | --- |
| First release | 2026 | 2019 | 2022 |
| Primary language | Rust (whole stack) | Go (whole stack) | Go teamserver, C++/Qt client, C/ASM agent |
| License | GPL-3.0 | GPLv3 | GPL-3.0 |
| Design stance | Clean-room, Rust-native, database-backed, AI-native | Mature general-purpose adversary emulation | Windows-focused evasion-forward post-exploitation |
| Status | Active development | Actively maintained | **Archived** (read-only since Feb 2026) |
| Codebase size | ~29k lines Rust + ~8k Tauri UI | ~247k lines Go (server/client/implant, no vendor) | Smaller; agent plus teamserver |

## Architecture

| | Shikra | Sliver | Havoc |
| --- | --- | --- | --- |
| Teamserver | Tokio + tonic/axum, PostgreSQL | Go, gRPC, SQLite (Postgres/SQLite via gorm) | Go, SQLite |
| Operator channel | gRPC over TLS 1.3 (mTLS-capable), bearer token auth | gRPC over mTLS | Custom TCP protocol (C++ client) |
| Operator UI | Tauri 2 desktop GUI **and** CLI | Terminal UI (Bubble Tea v2) | C++/Qt desktop GUI |
| Multiplayer | Yes, with RBAC roles + hash-chained audit log | Yes | Yes |
| Embedded database option | GUI provisions embedded PostgreSQL | SQLite embedded by default | SQLite |
| AI copilot | Built-in agentic loop + MCP server with approval gate | Built-in agentic loop + MCP server | None built-in (Python API) |

## Transports

| | Shikra | Sliver | Havoc |
| --- | --- | --- | --- |
| mTLS session | Yes (gRPC) | Yes | No |
| HTTP(S) beacon | Yes, malleable profiles with rotation | Yes | Yes |
| QUIC | Yes | No | No |
| DNS | Yes (TXT beacons) | Yes | No |
| WireGuard | Yes (userspace, boringtun) | Yes | No |
| SMB named pipe | Yes (session riding + pivots) | Yes (pivots) | Yes |
| Automatic fallback chain | Yes (`--fallback quic,http,dns,wireguard`) | Manual/session-based | No |
| External C2 | Yes (HTTPS relay bridge) | Yes (external builder pipeline) | Yes |

## Cryptography

| | Shikra | Sliver | Havoc |
| --- | --- | --- | --- |
| Agent E2E encryption | X25519 → HKDF-SHA256 → ChaCha20-Poly1305, monotonic sequence anti-replay | age (X25519 + ChaCha20-Poly1305) with per-binary keypairs | AES-256 session keys negotiated over the wire protocol |
| Enrollment | Ed25519 signature binds identity to session key; single-use tokens, constant-time compare, rate limited | Implant asymmetric key exchange at build time | Protocol-level key exchange |
| Transport security | TLS 1.3 with generated CA; server identity pinned in the binary | mTLS with generated CA | No TLS on the C2 protocol itself (HTTP transport aside) |
| Extension trust | Ed25519-signed packages verified before load | Armory + extension signing | Modules loaded from disk |
| Audit integrity | Hash-chained audit rows in PostgreSQL | Event log in DB | In-memory |
| Replay protection | Strict per-direction sequence numbers at the crypto layer | Session nonces | Session-scoped |

## Evasion and tradecraft

| | Shikra | Sliver | Havoc |
| --- | --- | --- | --- |
| Compile-time string obfuscation | Yes (`shikra-obf`, random per-build seed) | No (encoder-based) | No |
| Indirect syscalls (Windows) | Yes (dynamic NT resolution) | Partial (community extensions) | Yes |
| AMSI/ETW patching | Yes (before injection tasks) | Partial | Yes (hardware breakpoints) |
| Sleep obfuscation | Memory-encrypted task results; indirect `NtDelayExecution` | None built-in | Yes (Ekko/Zilean/FOLIAGE) |
| Return address spoofing | No | No | Yes |
| Shellcode encoders / stagers | Multiple encoders + staged delivery with XOR key | Donut, encoders, stagers | Shellcode payloads, External C2 |
| Malleability | String obfuscation, PE timestamp/checksum edits, profile rotation | Traffic profiles | C2 profiles |

Havoc is currently ahead on Windows-specific evasion depth (return address
spoofing, full sleep obfuscation, hardware breakpoint AMSI/ETW patching).
Shikra covers the common baseline (indirect syscalls, AMSI/ETW patching,
compile-time string obfuscation, in-memory result encryption at rest).

## Extensibility

| | Shikra | Sliver | Havoc |
| --- | --- | --- | --- |
| BOF/COFF | Yes (amd64 + arm64) | Yes (amd64 + arm64) | Yes (BOF modules) |
| .NET assemblies | Yes (in-process CLR hosting) | Yes (go-clr) | Via modules |
| WASM | Yes (wasmi) | Yes (wazero) | No |
| Native libraries | Yes (load/run/remove with registry) | Yes (shared library extensions) | Yes (modules) |
| Extension packages | Signed JSON packages, registry, armory key per team | Armory (community ecosystem) | Community modules |
| Scripting | None yet | Go | Python API |

Sliver's Armory ecosystem is the most mature third-party extension channel.
Shikra's package registry is newer but cryptographically signed end-to-end.

## Post-exploitation surface

| | Shikra | Sliver | Havoc |
| --- | --- | --- | --- |
| Shell / process spawn | Yes | Yes | Yes |
| File transfer | Yes (resumable downloads) | Yes | Yes |
| Injection | Yes (remote, reflective DLL, self/spawn exec) | Yes | Yes |
| Token operations | Yes (steal/make/rev2self) | Yes | Yes (token vault) |
| Kerberos | Yes (klist/purge/ptt on Windows) | Extensions | Yes |
| Registry / services | Yes (Windows) | Yes | Yes |
| Screenshot / portscan / netenum | Yes | Yes | Yes (portscan) |
| Pivoting | TCP pivots, multi-hop chains, SMB pipes, SOCKS5, portfwd, rportfwd | TCP/WireGuard pivots, SOCKS5, portfwd | SMB pivots |
| Job control | list/suspend/resume/kill | Jobs | In-client |
| Canaries / blue-team traps | Yes | Yes (DNS canaries) | No |

## AI and automation

| | Shikra | Sliver | Havoc |
| --- | --- | --- | --- |
| Built-in agentic loop | Yes (turn/item lifecycle, context filtering) | Yes (Responses API port) | No |
| MCP server | Yes, with risk tiers (read-only / mutating / destructive) | Yes (read tools first, expanded later) | No |
| Approval gate | Yes (policy engine + operator confirmation in GUI) | Not by default | N/A |
| Local model support | Any OpenAI-compatible endpoint (`SHIKRA_LLM_BASE_URL`) | OpenAI/OpenRouter/compatible | N/A |

Both Shikra and current Sliver ship AI copilots and MCP bridges; Shikra adds a
per-tool risk policy and approval gate, and records AI-initiated tasks in the
task table (`ai_initiated`, `approved_by`).

## Where Shikra stands out

- **Memory-safe native stack**: server, agent, and CLI are all Rust.
- **Relational core**: PostgreSQL with schema migrations, RBAC, and a
  tamper-evident audit chain — friendlier to multi-operator and compliance
  workflows than embedded SQLite.
- **GUI-first operator experience**: a cross-platform Tauri console with
  terminal, file browser, payload builder, profile editor, tunnels, extensions,
  team management and the AI copilot in one place, plus an equivalent CLI.
- **Transport breadth**: QUIC and WireGuard beacons in addition to the
  mTLS/HTTP/DNS baseline, with an automatic fallback chain.
- **Cryptographic hygiene**: application-layer E2E encryption independent of
  the transport, strict sequence anti-replay, signed extensions, single-use
  enroll tokens, constant-time secret comparison, per-build obfuscation seeds.

## Where Sliver and Havoc are ahead

- **Sliver**: ecosystem and maturity (Armory, TUI ergonomics, years of field
  use, community extensions), in-process WASM (wazero) and BOF ecosystem, DNS
  canaries, watchtower sample monitoring, site hosting.
- **Havoc**: Windows evasion depth (return address spoofing, Ekko/Zilean/
  FOLIAGE sleep obfuscation, hardware breakpoint AMSI/ETW patching, stack
  duplication), and a polished Qt client. Note that development stopped when
  the repository was archived; it no longer receives updates.
- **Both**: larger post-exploitation command sets accumulated over years, and
  battle-tested edge-case handling.

## Suggested roadmap to close gaps

1. **Full sleep obfuscation** (encrypt the agent's own image during sleep,
   ROP-based timers) modeled on the Ekko/FOLIAGE public literature.
2. **Return address spoofing** for Windows task execution.
3. **BOF arm64 parity testing** in CI on real runners.
4. **Community extension ecosystem**: publish the package format and host a
   registry analogous to Armory.
5. **Watchtower-style sample monitoring** (hash/AV telemetry for built
   artifacts).

## Verification status

The comparison concentrates on architecture. Shikra's acceptance suite
(`crates/server/tests/e2e.rs`) covers enrollment, encrypted communication over
gRPC, HTTP, QUIC, DNS and WireGuard, file transfer, tunnels, pivots, port
scanning, profile rotation, staged delivery, the extension registry, and
enrollment rate limiting. Havoc and Sliver features are compared from their
public sources; no third-party code is used in Shikra.

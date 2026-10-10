# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **AI copilot console panel** — a visual agentic operator with streaming tool
  cards, an interactive approve/deny gate and risk-tier badges. It shares the
  25-tool surface and risk policy with `shikra-client ai` and is configurable
  per console (provider URL, model, API key) or with `SHIKRA_LLM_*`.
- **Expanded AI tool surface** — session introspection (`session_info`,
  `list_tasks`), fleet overview (`list_listeners`, `list_pivots`,
  `list_extensions`, `list_credentials`, `list_loot`), target recon (`ps`,
  `netstat`, `ifconfig`, `env_dump`), `portscan`, `screenshot` (saved on the
  operator host) and listener control (`listener_start`, `listener_stop`).
- **AI provenance** — tasks submitted by the copilot carry an `ai_initiated`
  flag and show up as `[ai]` in `shikra-client tasks`.
- **Runtime approval hook for the agent loop** — `AgenticLoop` accepts an
  async `Approver`, letting interfaces gate individual calls the policy does
  not auto-approve (used by the console panel).

### Fixed

- **Sessions self-heal after lost requests** — the receive sequence demanded
  exact ordering, so a single dropped or rejected poll (for example an
  oversized task result answered with HTTP 413) permanently bricked the
  session with 401s. Receivers now tolerate bounded sequence gaps (4096) and
  still reject replays.
- **Large task results over the beacon transport** — the HTTP beacon body
  limit was axum's 2 MiB default; it is now 32 MiB, and the gRPC and QUIC
  frame limits were raised to match, so multi-megabyte screenshots transfer.

## [0.1.0] - 2026-10-10

Initial public release.

### Added

- **Teamserver** (`shikra-server`): gRPC control plane with TLS, HTTPS beacon
  listener with malleable profile rotation, and QUIC, DNS and WireGuard
  beacon listeners started at runtime from the console.
- **Agent** (`shikra-implant`): single binary with session, beacon, QUIC, DNS
  and WireGuard modes plus an ordered fallback chain; session mode can ride a
  named pipe or Unix socket.
- **End-to-end cryptography**: X25519 key exchange → HKDF-SHA256 →
  ChaCha20-Poly1305 with strict per-direction sequence numbers; Ed25519
  identity binding at enrollment; single-use enrollment tokens; signed
  extension packages.
- **Operator surfaces**: `shikra-client` CLI and the Tauri 2 console
  (terminal, file browser, payload builder, profile editor, tunnels,
  extensions, team management, AI copilot with approval gate).
- **Payload builder** (`shikra-builder`): per-build embedded configuration,
  compile-time string obfuscation with a random seed, PE malleability options,
  and staged delivery (`--stager`) with encoded stage payloads.
- **Post-exploitation**: shell/spawn, file transfer with resumable downloads,
  injection (remote, reflective DLL, self/spawn exec), token operations,
  Kerberos ticket management, registry and service enumeration, screenshots,
  port scanning, network enumeration.
- **Pivoting**: TCP pivots with multi-hop chains, SMB named-pipe pivots,
  SOCKS5, local/remote port forwarding.
- **Extensions**: BOF/COFF, WASM (wasmi), native libraries, .NET assemblies
  (Windows CLR hosting), with a signed extension registry.
- **Team features**: RBAC (admin/operator/watcher), hash-chained audit log,
  team chat and event feed, loot and credential storage, canaries, Discord
  webhook alerts.
- **AI integration**: built-in agentic loop with a tool-approval policy and an
  MCP server exposing read-only, mutating and destructive tool tiers.
- **ExternalC2**: HTTPS bridge for bring-your-own agents, with an example
  Python agent.
- **Testing**: encrypted end-to-end suite covering all transports, tunnels,
  pivots, port scan, profile rotation, staged delivery, extension registry and
  enrollment rate limiting.

### Security

- Windows agents resolve NT syscalls dynamically and call them indirectly;
  AMSI/ETW providers are patched before injection tasks.
- Beacon task results are kept encrypted in memory between polls.
- Enrollment is rate limited per peer and authentication failures are audited.

[Unreleased]: https://github.com/A1bu5/shikra/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/A1bu5/shikra/releases/tag/v0.1.0

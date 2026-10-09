# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/OWNER/shikra/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/OWNER/shikra/releases/tag/v0.1.0

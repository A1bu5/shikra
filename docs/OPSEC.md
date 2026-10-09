# Shikra OPSEC Guide

Operational security guidance for deploying and operating Shikra. This is a
defensive-minded reference: every feature below exists so that an authorized
engagement can be conducted with controlled, auditable risk.

## Threat model

Shikra assumes:

- **Network observers** can capture and replay agent/server traffic.
- **Endpoints** run EDR/AV with userland hooks and network inspection.
- **The teamserver** may be probed by unauthenticated peers (scanning,
  enrollment abuse, token guessing).
- **The database** may be read by a passive attacker, so audit integrity must
  not depend on secrecy alone.

It does *not* assume the teamserver host is compromised; if it is, the
enrollment token and operator token must be rotated (see Incident response).

## Cryptography invariants

| Layer | Mechanism |
| --- | --- |
| Operator ↔ teamserver | TLS 1.3 (mTLS-capable), bearer token |
| Agent ↔ teamserver | X25519 → HKDF-SHA256 → ChaCha20-Poly1305, sequence numbers |
| Identity | Ed25519 signatures over the session key binding |
| Enrollment | Single-use tokens, constant-time comparison |
| Extensions | Ed25519 package signatures, verified before load |
| Audit | Hash-chained rows serialized by a PostgreSQL advisory lock |

Rules:

1. Never disable TLS verification (`SHIKRA_*_INSECURE` style flags do not
   exist by design).
2. Never reuse enrollment tokens across hosts; tokens are deleted on use.
3. Rotate the CA and operator tokens after any suspected teamserver exposure.
4. Treat the state directory as secret: it holds the CA private key, armory
   signing key and WireGuard keys. Use `chmod 700` and encrypted disks.
5. Extension signing keys are separate from the armory key; keep the private
   seed offline and only on the packaging machine.

## Agent-side OPSEC

### Build hygiene

- Every release build derives a random obfuscation seed. Record the seed in the
  engagement log so crashes can be symbolized; pass `--obf-seed <hex>` for
  reproducible builds and `--no-obfuscation` only for debugging.
- Verify no plaintext strings leak: `scripts/verify-obfuscation.sh <binary>`
  must report zero findings before deployment.
- Prefer `--mode beacon` with jitter for long-haul operations; reserve
  `session` mode for interactive, short-lived actions.
- Staged delivery (`--stager`) keeps the final payload off disk: the stager
  downloads, decodes, executes in place and deletes itself after ~15 seconds.
  Host the stage at a benign path via the `/cdn/{file}` endpoint.

### Transport selection

- Use the fallback chain (`--mode fallback --fallback quic,http,dns,wireguard`)
  when egress filters vary by site. The agent tries each transport in order
  with a bounded per-transport connect timeout, so a blocked protocol does not
  stall the beacon and only one transport ever enrolls.
- DNS transport is the loudest in terms of volume; reduce beacon frequency and
  keep responses small. Domain fronting is out of scope for this codebase.
- Profile rotation spreads HTTP beaconing across multiple profile paths and
  headers; keep the profile set small (2–4) to avoid distinguishable patterns.
- Beacons that miss three consecutive check-in windows (estimated from their
  observed cadence, 90s minimum) are marked `stale`; task submission then
  fails fast until the beacon polls again. Sessions silent for over 10 minutes
  are retired and must re-enroll.

### Injection and evasion

- Indirect syscalls resolve NT function numbers at runtime; keep the target
  Windows build in the supported matrix so the resolver table matches.
- AMSI/ETW patches happen only for tasks that need them (execute-assembly,
  PowerShell). Avoid enabling them for unrelated tasks to reduce sensor noise.
- Sleep obfuscation encrypts the beacon heap while idle; do not combine with
  tools that scan memory of long-running processes unless expected.
- Prefer `migrate` into a process whose network usage matches the beacon
  transport, and avoid injecting into protected processes.

## Teamserver hardening

- Bind gRPC/HTTP behind a reverse proxy that terminates only the expected
  hostnames; do not expose the enrollment endpoint to the public internet
  without a rate limit. Shikra enforces 30 enrollment attempts/minute per
  peer and returns HTTP 429; failures emit `enrollment_rejected` /
  `enrollment_rate_limited` events.
- Operator authentication failures are audited at most once every 5 seconds
  per peer (`operator_auth_failed`) to prevent log floods.
- The audit hash chain is serialized with `pg_advisory_xact_lock`; do not
  disable it. Verify chain continuity with a scheduled job comparing each
  row's `prev_hash` to the previous `hash`.
- Restrict database access to the teamserver role; the audit trail is only as
  trustworthy as the host enforcing it. When using the console's embedded
  PostgreSQL, the cluster lives under `<state_dir>/pgdata` and its password is
  stored in `~/.shikra/console.json` (0600): treat both like key material.
- Rotate WireGuard keys per engagement and never reuse the teamserver address
  across concurrent operations for different customers.

## Operator tradecraft

- One operator token per person; revoke tokens on personnel change. The team
  panel lists operators and credentials with the installing operator recorded.
- Use the AI copilot's approval gate for mutating tools. Auto-approve
  (`--auto-approve`) is for lab ranges only.
- Loot and credentials are stored server-side; mark canaries for detection
  exercises and avoid exfiltrating real user data beyond agreed scope.
- Keep an engagement log of: build seeds, tokens issued, hosts enrolled,
  listeners started, and every extension installed from the registry.

## Logging and detection

Audit events are queryable from the operator client:

- `enrollment_rejected`, `enrollment_rate_limited` — perimeter abuse.
- `operator_auth_failed` — token guessing or misconfigured clients.
- `session_registered`, `task_dispatched`, `extension_installed` — normal
  lifecycle, useful for reconstructing timelines.
- `chain_break` alerts if the audit chain fails verification at read time.

Forward teamserver logs (`SHIKRA_LOG_FORMAT=json`) to the engagement SIEM.
Beacon user-agent and profile paths should be reviewed during the deconfliction
brief with the blue team.

## Incident response

1. **Suspected agent compromise** — kill the session, revoke its enrollment
   token, and rotate the CA if the session key may have leaked.
2. **Suspected teamserver compromise** — stop listeners, rotate CA, operator
   tokens, WireGuard keys and the armory key; rebuild from a clean host and
   verify the audit chain before restoring.
3. **Leaked extension private key** — re-sign all packages from a clean build,
   bump versions, and remove untrusted registry entries.
4. **Rate-limit bypass observed** — disable the enrollment endpoint entirely
   and enroll agents out-of-band (pre-issued tokens via the builder).

## Do not

- Do not run Shikra against systems outside a written engagement scope.
- Do not enable obfuscation-less builds in the field, even for "just a quick
  test".
- Do not commit state directories, seeds, tokens or CA material to source
  control. The repository ignores `state/` and `*.pem` by convention; verify
  before pushing.

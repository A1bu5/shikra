# Contributing to Shikra

Thanks for your interest. Shikra is an adversary-emulation framework for
authorized security testing; contributions should keep it usable for
legitimate red-team work and clearly scoped in documentation.

## Ground rules

1. **Clean-room only.** Do not copy code from Sliver, Havoc, Metasploit,
   Cobalt Strike, or any other C2 or security project, even partially.
   Implement from public specifications, RFCs, and documentation, or from
   scratch. If you believe existing code violates this, report it privately.
2. **Authorized use.** Features that make the tool harder to scope (e.g.
   unattributed targeting, self-propagating behavior) are out of scope.
3. **No secrets.** Never commit state directories, keys, tokens, or CA
   material. See `.gitignore`; CI runs secret scanning.
4. **No prebuilt implants in releases.** Releases ship source and
   server/client binaries only. Agents are built by the operator.

## Development setup

Requirements: Rust 1.88 (pinned), PostgreSQL 15+ for the teamserver.

```sh
# Unit tests + encrypted end-to-end suite (the e2e suite skips itself when
# the database variable is unset).
export SHIKRA_TEST_DATABASE_URL=postgres://localhost/shikra_test
cargo test --workspace

# Lint and format gates (same as CI)
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings

# License/advisory/source policy
cargo deny check

# GUI
cd gui && cargo check
```

End-to-end coverage lives in `crates/server/tests/e2e.rs`. When you change a
transport, task surface, or listener, extend the e2e suite rather than relying
on manual testing. The acceptance helpers in `scripts/` show how to drive a
real server + agent pair.

## Pull requests

- Use the PR template and fill in the checklist.
- Keep changes focused; unrelated refactors belong in separate PRs.
- Add or update tests for behavioral changes.
- Update `CHANGELOG.md` under `## [Unreleased]`.
- Sign off your commits (`git commit -s`) to certify the Developer
  Certificate of Origin (DCO) — see below.

### Developer Certificate of Origin

By signing off a commit you certify that you wrote the contribution, or have
the right to submit it under the project license (Apache-2.0). The full text
is at https://developercertificate.org/.

```
git commit -s -m "feat(transport): add DNS retry backoff"
```

## Commit conventions

Conventional Commits are preferred (`feat:`, `fix:`, `docs:`, `chore:`,
`refactor:`, `test:`). Scope by component (`agent`, `server`, `client`,
`gui`, `crypto`, `transport`, `docs`). Keep the subject under 72 characters.

## Code style

- Rust: `cargo fmt` formatting, no clippy warnings (`-D warnings`), explicit
  error types via `thiserror`/`anyhow` as established per crate.
- Prefer small modules with doc comments on public items.
- Unsafe code is denied at the workspace level; the few explicitly annotated
  Windows syscall modules are the only exceptions and must be justified in
  review.
- GUI: keep DOM/JS logic in `gui/ui/`, Rust commands thin and typed.

## Reporting bugs and requesting features

Use the issue templates. For vulnerabilities, follow `SECURITY.md` — do not
open a public issue.

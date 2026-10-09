# Pull Request

## Summary

<!-- What does this change and why? Link issues with "Closes #123". -->

## Type

- [ ] Bug fix
- [ ] New feature
- [ ] Refactor (no behavior change)
- [ ] Documentation
- [ ] Build / CI / tooling

## Component(s)

- [ ] `shikra-server`
- [ ] `shikra-implant`
- [ ] `shikra-client`
- [ ] `shikra-builder`
- [ ] GUI console
- [ ] MCP / AI copilot
- [ ] transports / crypto
- [ ] docs / CI

## Checklist

- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo test --workspace` passes (e2e runs when `SHIKRA_TEST_DATABASE_URL` is set)
- [ ] `cargo deny check` passes
- [ ] Tests added/updated for behavioral changes
- [ ] `CHANGELOG.md` updated under `[Unreleased]`
- [ ] Commits are signed off (DCO, `git commit -s`)

## Clean-room and safety attestation

- [ ] This contribution contains **no code copied** from Sliver, Havoc,
      Metasploit, Cobalt Strike, or any other project.
- [ ] This change does not weaken scoping controls (audit log, RBAC,
      enrollment rate limits, approval gates).
- [ ] No secrets, state directories, keys, or tokens are included.

## Testing notes

<!-- How was this validated? Include commands, lab layout, and observed results. -->

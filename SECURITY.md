# Security Policy

## Authorized use

Shikra is an adversary-emulation framework intended **exclusively** for
authorized security testing: red-team engagements, penetration tests with a
signed scope, lab research, and detection engineering. Running it against
systems you do not own or have explicit written permission to test is illegal
in most jurisdictions and is not a supported use.

## Supported versions

Security fixes are provided for the latest release only. As the project is
pre-1.0, expect breaking changes between minor versions.

| Version | Supported |
| ------- | --------- |
| latest  | ✅        |
| older   | ❌        |

## Reporting a vulnerability

Please **do not** open a public issue for security-sensitive reports. Use
GitHub's private vulnerability reporting:

1. Open the repository's **Security** tab.
2. Click **Report a vulnerability**.
3. Include: affected version/commit, a minimal reproduction, impact, and any
   suggested fix.

If GitHub private reporting is unavailable, contact the maintainers by email
at the address listed in the repository profile.

### What to expect

- Acknowledgement within **72 hours**.
- Triage and severity assessment within **7 days**.
- A coordinated disclosure window of **90 days** (or earlier by mutual
  agreement) before public details are published.

Credits are given in the release notes unless you prefer to remain anonymous.

## Scope notes

Because Shikra produces offensive tooling, the following are **in scope**:

- Cryptographic flaws in the agent/teamserver handshake, framing, or session
  key derivation.
- Authentication/authorization bypasses in the operator gRPC surface or the
  beacon listeners.
- Remote code execution or sandbox escape reachable from beacon enrollment
  without valid credentials.
- Injection or deserialization issues in task handling.

The following are generally **out of scope**:

- Detection by a specific AV/EDR product (bypass is engagement-specific and
  not a security property of the framework).
- Social-engineering or physical vectors.
- Issues that require an already-compromised teamserver host.

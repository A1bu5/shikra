#!/usr/bin/env bash
# M9 acceptance helper: verifies that string obfuscation actually removed
# sensitive literals from a built implant binary.
#
# Usage: scripts/verify-obfuscation.sh <path-to-implant-binary>

set -euo pipefail

BINARY="${1:?usage: verify-obfuscation.sh <path-to-implant-binary>}"

if [[ ! -f "$BINARY" ]]; then
    echo "error: binary not found: $BINARY" >&2
    exit 1
fi

# Literals that must not appear in a hardened build. The first group is
# obfuscated by the Windows evasion module, the second by the implant win.rs.
PATTERNS=(
    "amsi.dll"
    "AmsiScanBuffer"
    "EtwEventWrite"
    "EtwEventWriteFull"
    "NtProtectVirtualMemory"
    "NtAllocateVirtualMemory"
    "NtWriteVirtualMemory"
    "NtReadVirtualMemory"
    "NtOpenProcess"
    "NtCreateThreadEx"
    "NtTerminateProcess"
    "NtSuspendThread"
    "NtClose"
    "NtDelayExecution"
    "LdrLoadDll"
    "mscoree.dll"
    "CLRCreateInstance"
    "OpenProcessToken"
    "DuplicateTokenEx"
    "ImpersonateLoggedOnUser"
    "LogonUserW"
    "RevertToSelf"
    "CurrentControlSet"
)

failures=0
for pattern in "${PATTERNS[@]}"; do
    if grep -a -q -F "$pattern" "$BINARY"; then
        echo "FAIL: plaintext literal present: $pattern"
        failures=$((failures + 1))
    else
        echo "ok:   literal absent: $pattern"
    fi
done

if [[ "$failures" -gt 0 ]]; then
    echo
    echo "$failures literal(s) leaked into $BINARY" >&2
    exit 1
fi

echo
echo "all checked literals are obfuscated in $BINARY"

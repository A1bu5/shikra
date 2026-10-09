# External agent example

A minimal bring-your-own agent that talks to the teamserver's ExternalC2
bridge over HTTPS. It registers, long-polls for tasks and posts results.

```sh
export SHIKRA_URL=https://127.0.0.1:8080
export SHIKRA_RELAY_TOKEN=$(cat <state_dir>/relay.token)
export SHIKRA_CA_CERT=<state_dir>/ca.pem
python3 agent.py
```

The session appears in the console like any beacon and accepts `echo` and
`shell` tasks. Extend `execute()` (or replace the loop) to build a custom
agent; task payloads arrive hex-encoded in `payload_hex`.

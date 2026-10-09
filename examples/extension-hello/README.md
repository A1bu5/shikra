# Shikra extension SDK

Shikra supports two extension kinds, both visible to the operator through the
signed registry:

| Kind   | Format                                | Loaded by task  |
| ------ | ------------------------------------- | --------------- |
| wasm   | WebAssembly module (`*.wasm`)         | `wasm_load`     |
| native | Shared library (`*.dylib/*.so/*.dll`) | `native_load`   |

Extensions run in-process on the agent. Both ABIs receive the task argument
string and write output through a host callback.

## Native ABI (C)

```c
#include <stddef.h>
#include <stdint.h>

typedef void (*shikra_ext_output_fn)(void *ctx, const uint8_t *data, size_t len);

uint32_t shikra_ext_abi(void);                       /* must return 1 */
int32_t  shikra_ext_run(const uint8_t *args, size_t args_len,
                        shikra_ext_output_fn output, void *ctx);
```

- Build a shared library and keep the symbol names unmangled (C, no `extern "C++"`).
- `args` is the raw `--args` string; `output(ctx, data, len)` appends to the
  task result.
- The return value becomes the task exit code.
- A complete example lives in `examples/extension-hello/hello.c`.

## WASM ABI

The module must export `memory` and:

- `alloc(size: i32) -> i32` — allocate a buffer for arguments (optional when
  no arguments are passed).
- `run(ptr: i32, len: i32) -> i32` — entry point; the argument string is
  written to `ptr..ptr+len` before the call.

The module imports `env.host_output(ptr: i32, len: i32)` and calls it to emit
results. `examples/extension-hello/hello.wat` is a minimal example.

## Packaging and signing

Packages are JSON documents signed with the team's armory key
(`<state_dir>/armory.key`):

```bash
# native
cc -shared -fPIC -o hello.dylib hello.c
shikra-client extension-pack hello.dylib --name hello --kind native \
  --platform macos --key run/armory.key --output hello.pkg

# wasm
shikra-client extension-pack hello.wasm --name hello-wasm --kind wasm \
  --key run/armory.key --output hello-wasm.pkg
```

Package layout:

```json
{
  "manifest": {
    "name": "hello",
    "version": "1.0.0",
    "kind": "native",
    "platform": "any",
    "architecture": "any",
    "description": "example extension",
    "sha256": "<payload hash>",
    "size": 1234
  },
  "payload_b64": "<base64 payload>",
  "signer": "<hex ed25519 public key>",
  "signature": "<hex ed25519 signature>"
}
```

The signature covers `name/version/kind/platform/architecture/description/
sha256/size`; the payload hash covers the payload. Tampering with either is
rejected at install time.

## Registry workflow

```bash
shikra-client extension-install hello.pkg        # verify + store on the teamserver
shikra-client extensions                         # list everything installed
shikra-client extension-push --session <id> --name hello   # fetch + load on target
```

`extension-push` picks `wasm_load` or `native_load` from the manifest kind and
can filter by platform when several builds share a name.

## Platform notes

- `--platform any` packages are accepted everywhere; use `macos`, `linux` or
  `windows` for architecture-specific builds.
- Native extensions are loaded with `dlopen`/`LoadLibraryW` and stay resident
  until `native-remove` (which unloads and deletes the staged file).
- ABI version mismatches, missing symbols and invalid libraries are rejected
  before any code runs.

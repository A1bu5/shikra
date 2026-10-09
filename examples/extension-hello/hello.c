/*
 * Shikra native extension SDK example.
 *
 * A native extension is a shared library exporting the ABI below. Build it
 * with the platform C compiler, then pack and install it:
 *
 *   cc -shared -fPIC -o libhello.dylib hello.c          # macOS
 *   cc -shared -fPIC -o libhello.so hello.c             # Linux
 *   x86_64-w64-mingw32-gcc -shared -o hello.dll hello.c # Windows
 *
 *   shikra-client extension-pack hello.c --name hello --kind native \
 *     --platform any --key run/armory.key --output hello.pkg
 *   shikra-client extension-install hello.pkg
 *   shikra-client extension-push --session <id> --name hello
 *
 * The host provides an output callback; write results through it so the
 * extension does not need to manage host memory.
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define SHIKRA_EXT_ABI 1

typedef void (*shikra_ext_output_fn)(void *ctx, const uint8_t *data, size_t len);

/* Required: report the ABI version the extension was built against. */
uint32_t shikra_ext_abi(void) { return SHIKRA_EXT_ABI; }

/* Required: entry point. Return a process-style exit code. */
int32_t shikra_ext_run(const uint8_t *args, size_t args_len,
                       shikra_ext_output_fn output, void *ctx) {
    static const char banner[] = "hello from a shikra native extension\n";
    output(ctx, (const uint8_t *)banner, sizeof(banner) - 1);

    if (args_len > 0) {
        output(ctx, (const uint8_t *)"args: ", 6);
        output(ctx, args, args_len);
        output(ctx, (const uint8_t *)"\n", 1);
    }
    return 0;
}

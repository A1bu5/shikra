;; Shikra WASM extension SDK example.
;;
;; Build:  wat2wasm hello.wat -o hello.wasm
;; Pack:   shikra-client extension-pack hello.wasm --name hello-wasm \
;;           --kind wasm --key run/armory.key --output hello-wasm.pkg
;;
;; The host provides arguments through the `alloc` buffer and collects output
;; through the imported `env.host_output` callback.
(module
  (import "env" "host_output" (func $host_output (param i32 i32)))
  (memory (export "memory") 1)
  (data (i32.const 1024) "hello from a shikra wasm extension")

  ;; Scratch buffer for task arguments.
  (func (export "alloc") (param i32) (result i32)
    (i32.const 2048))

  (func (export "run") (param i32 i32) (result i32)
    ;; banner
    (call $host_output (i32.const 1024) (i32.const 34))
    ;; echo arguments when provided
    (if (i32.gt_u (local.get 1) (i32.const 0))
      (then
        (call $host_output (local.get 0) (local.get 1))))
    (i32.const 0))
)

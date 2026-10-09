//! Renders a tiny demonstration WASM extension for CLI verification:
//! `cargo run -p shikra-implant --example make_test_wasm -- /tmp/ext.wasm`

fn main() -> anyhow::Result<()> {
    let wat = r#"
    (module
      (import "env" "host_output" (func $host_output (param i32 i32)))
      (memory (export "memory") 1)
      (data (i32.const 512) "wasm-cli-ok")
      (func (export "alloc") (param i32) (result i32) (i32.const 1024))
      (func (export "run") (param i32 i32) (result i32)
        (call $host_output (i32.const 512) (i32.const 11))
        (call $host_output (local.get 0) (local.get 1))
        (i32.const 0)))
    "#;
    let bytes = wat::parse_str(wat)?;
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/tmp/shikra-test-ext.wasm".into());
    std::fs::write(&path, &bytes)?;
    println!("wrote {} bytes to {path}", bytes.len());
    Ok(())
}

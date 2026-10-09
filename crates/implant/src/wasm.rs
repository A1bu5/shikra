use anyhow::{anyhow, Context, Result};
use std::collections::HashMap;
use wasmi::{Caller, Engine, Linker, Memory, Module, Store};

/// A registered WASM extension plus its declared metadata.
#[derive(Debug, Clone)]
pub struct WasmExtension {
    pub name: String,
    pub bytes: Vec<u8>,
}

#[derive(Default)]
pub struct WasmRegistry {
    extensions: HashMap<String, WasmExtension>,
}

impl std::fmt::Debug for WasmRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmRegistry")
            .field("extensions", &self.list())
            .finish()
    }
}

impl WasmRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, name: impl Into<String>, bytes: Vec<u8>) -> Result<()> {
        let name = name.into();
        if name.is_empty() {
            return Err(anyhow!("extension name must not be empty"));
        }
        // Validate the module at registration time so failures surface early.
        let engine = Engine::default();
        Module::new(&engine, &bytes[..]).map_err(|err| anyhow!("invalid wasm module: {err}"))?;
        self.extensions
            .insert(name.clone(), WasmExtension { name, bytes });
        Ok(())
    }

    pub fn remove(&mut self, name: &str) -> bool {
        self.extensions.remove(name).is_some()
    }

    pub fn list(&self) -> Vec<String> {
        let mut names: Vec<String> = self.extensions.keys().cloned().collect();
        names.sort();
        names
    }

    pub fn get(&self, name: &str) -> Option<&WasmExtension> {
        self.extensions.get(name)
    }
}

struct HostState {
    output: Vec<u8>,
}

/// Runs a registered extension. Convention:
/// - module exports `memory` and `run(ptr, len) -> i32`
/// - module may export `alloc(size) -> ptr` to receive arguments
/// - module imports `env.host_output(ptr, len)` for output
pub fn run_extension(extension: &WasmExtension, args: &[u8]) -> Result<TaskWasmOutcome> {
    let engine = Engine::default();
    let module = Module::new(&engine, &extension.bytes[..])
        .map_err(|err| anyhow!("invalid wasm module: {err}"))?;

    let mut store = Store::new(&engine, HostState { output: Vec::new() });
    let mut linker = Linker::new(&engine);

    linker
        .func_wrap(
            "env",
            "host_output",
            |mut caller: Caller<'_, HostState>, ptr: i32, len: i32| {
                let Some(export) = caller.get_export("memory") else {
                    return;
                };
                let Some(memory) = export.into_memory() else {
                    return;
                };
                let (ptr, len) = (ptr as usize, len as usize);
                let mut buffer = vec![0u8; len];
                if memory.read(&caller, ptr, &mut buffer).is_err() {
                    return;
                }
                caller.data_mut().output.extend_from_slice(&buffer);
            },
        )
        .map_err(|err| anyhow!("failed to register host_output: {err}"))?;

    let instance = linker
        .instantiate_and_start(&mut store, &module)
        .context("failed to instantiate extension")?;

    let memory: Memory = instance
        .get_memory(&store, "memory")
        .ok_or_else(|| anyhow!("extension must export `memory`"))?;

    let (arg_ptr, arg_len) = if args.is_empty() {
        (0i32, 0i32)
    } else {
        let alloc = instance
            .get_typed_func::<i32, i32>(&store, "alloc")
            .map_err(|_| anyhow!("extension must export `alloc(size)` to receive arguments"))?;
        let ptr = alloc
            .call(&mut store, args.len() as i32)
            .context("alloc trap")?;
        memory
            .write(&mut store, ptr as usize, args)
            .context("failed to write arguments into extension memory")?;
        (ptr, args.len() as i32)
    };

    let run = instance
        .get_typed_func::<(i32, i32), i32>(&store, "run")
        .map_err(|_| anyhow!("extension must export `run(ptr, len) -> i32`"))?;

    let exit_code = run
        .call(&mut store, (arg_ptr, arg_len))
        .context("extension run trap")?;

    let output = store.data().output.clone();
    Ok(TaskWasmOutcome { exit_code, output })
}

#[derive(Debug)]
pub struct TaskWasmOutcome {
    pub exit_code: i32,
    pub output: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn echo_extension_wat() -> Vec<u8> {
        let wat = r#"
        (module
          (import "env" "host_output" (func $host_output (param i32 i32)))
          (memory (export "memory") 1)
          (data (i32.const 1024) "wasm-ext-ok")
          (func (export "alloc") (param i32) (result i32)
            (i32.const 2048))
          (func (export "run") (param i32 i32) (result i32)
            ;; emit the static string
            (call $host_output (i32.const 1024) (i32.const 11))
            ;; emit the input arguments from the alloc buffer
            (call $host_output (local.get 0) (local.get 1))
            (i32.const 7))
        )
        "#;
        wat::parse_str(wat).expect("wat")
    }

    #[test]
    fn register_validate_and_run() {
        let mut registry = WasmRegistry::new();
        registry
            .register("echo", echo_extension_wat())
            .expect("register");
        assert_eq!(registry.list(), vec!["echo".to_string()]);

        let extension = registry.get("echo").expect("extension");
        let outcome = run_extension(extension, b"args-through").expect("run");
        assert_eq!(outcome.exit_code, 7);
        let output = String::from_utf8_lossy(&outcome.output);
        assert!(output.contains("wasm-ext-ok"), "output: {output:?}");
        assert!(output.contains("args-through"), "output: {output:?}");
    }

    #[test]
    fn register_rejects_garbage() {
        let mut registry = WasmRegistry::new();
        assert!(registry.register("bad", b"not wasm".to_vec()).is_err());
    }

    #[test]
    fn remove_unregisters() {
        let mut registry = WasmRegistry::new();
        registry
            .register("echo", echo_extension_wat())
            .expect("register");
        assert!(registry.remove("echo"));
        assert!(registry.list().is_empty());
        assert!(!registry.remove("echo"));
    }
}

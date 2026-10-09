//! Windows-only post-exploitation helpers (registry, services).
//!
//! All functions are pure host-side enumeration: they read local state and
//! return JSON. Compiled only on Windows; other platforms expose stubs that
//! return a clear "unsupported on this platform" task failure.

use crate::TaskOutcome;
#[cfg(windows)]
use serde_json::json;
#[cfg(windows)]
use shikra_obf::obf;

#[cfg(windows)]
mod imp {
    use super::*;
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ};
    use winreg::RegKey;

    fn open_hive(hive: &str) -> Option<RegKey> {
        match hive.to_ascii_uppercase().as_str() {
            "HKLM" | "HKEY_LOCAL_MACHINE" => Some(RegKey::predef(HKEY_LOCAL_MACHINE)),
            "HKCU" | "HKEY_CURRENT_USER" => Some(RegKey::predef(HKEY_CURRENT_USER)),
            _ => None,
        }
    }

    fn normalize_path(path: &str) -> String {
        path.trim_start_matches('\\')
            .trim_start_matches('/')
            .to_string()
    }

    pub fn registry_read(hive: &str, path: &str, value_name: &str) -> TaskOutcome {
        let Some(hive) = open_hive(hive) else {
            return TaskOutcome::fail("unsupported hive (use HKLM or HKCU)");
        };
        let path = normalize_path(path);
        let key = match hive.open_subkey_with_flags(&path, KEY_READ) {
            Ok(key) => key,
            Err(err) => return TaskOutcome::fail(format!("open key failed: {err}")),
        };
        match key.get_raw_value(value_name) {
            Ok(raw) => {
                let rendered = match raw.vtype {
                    winreg::enums::REG_DWORD => {
                        u32::from_le_bytes(raw.bytes[..4].try_into().unwrap_or([0; 4])).to_string()
                    }
                    winreg::enums::REG_SZ | winreg::enums::REG_EXPAND_SZ => {
                        String::from_utf16_lossy(
                            &raw.bytes
                                .chunks_exact(2)
                                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                                .take_while(|value| *value != 0)
                                .collect::<Vec<u16>>(),
                        )
                    }
                    _ => String::from_utf8_lossy(&raw.bytes).to_string(),
                };
                TaskOutcome::ok(json!({ "value": rendered }).to_string())
            }
            Err(err) => TaskOutcome::fail(format!("read value failed: {err}")),
        }
    }

    pub fn registry_list(hive: &str, path: &str) -> TaskOutcome {
        let Some(hive) = open_hive(hive) else {
            return TaskOutcome::fail("unsupported hive (use HKLM or HKCU)");
        };
        let path = normalize_path(path);
        let key = match hive.open_subkey_with_flags(&path, KEY_READ) {
            Ok(key) => key,
            Err(err) => return TaskOutcome::fail(format!("open key failed: {err}")),
        };

        let mut subkeys: Vec<String> = key.enum_keys().filter_map(|item| item.ok()).collect();
        subkeys.sort();

        let mut values: Vec<serde_json::Value> = Vec::new();
        for value in key.enum_values().flatten() {
            let (name, raw) = value;
            let rendered = match raw.vtype {
                winreg::enums::REG_DWORD if raw.bytes.len() >= 4 => {
                    u32::from_le_bytes(raw.bytes[..4].try_into().unwrap_or([0; 4])).to_string()
                }
                winreg::enums::REG_SZ | winreg::enums::REG_EXPAND_SZ => String::from_utf16_lossy(
                    &raw.bytes
                        .chunks_exact(2)
                        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                        .take_while(|value| *value != 0)
                        .collect::<Vec<u16>>(),
                ),
                _ => format!("<{} bytes>", raw.bytes.len()),
            };
            values.push(json!({ "name": name, "value": rendered }));
        }

        TaskOutcome::ok(json!({ "subkeys": subkeys, "values": values }).to_string())
    }

    pub fn services_list() -> TaskOutcome {
        // Enumerate service configuration from the registry (read-only).
        let services =
            match registry_json(&obf!("HKLM"), &obf!(r"SYSTEM\CurrentControlSet\Services")) {
                Some(value) => value,
                None => return TaskOutcome::fail("failed to enumerate services"),
            };
        TaskOutcome::ok(services)
    }

    fn registry_json(hive: &str, path: &str) -> Option<String> {
        use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
        use winreg::RegKey;
        let _ = hive;
        let root = RegKey::predef(HKEY_LOCAL_MACHINE);
        let key = root.open_subkey_with_flags(path, KEY_READ).ok()?;
        let mut rows: Vec<serde_json::Value> = Vec::new();
        for name in key.enum_keys().flatten() {
            let Ok(subkey) = key.open_subkey_with_flags(&name, KEY_READ) else {
                continue;
            };
            let display: String = subkey.get_value("DisplayName").unwrap_or_default();
            let image: String = subkey.get_value("ImagePath").unwrap_or_default();
            let start: u32 = subkey.get_value("Start").unwrap_or(u32::MAX);
            let service_type: u32 = subkey.get_value("Type").unwrap_or(u32::MAX);
            if image.is_empty() && display.is_empty() {
                continue;
            }
            rows.push(json!({
                "name": name,
                "display_name": display,
                "image_path": image,
                "start": start,
                "type": service_type,
            }));
        }
        rows.sort_by(|a, b| {
            a["name"]
                .as_str()
                .unwrap_or_default()
                .cmp(b["name"].as_str().unwrap_or_default())
        });
        Some(serde_json::to_string(&rows).unwrap_or_default())
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;

    pub fn registry_read(_hive: &str, _path: &str, _value_name: &str) -> TaskOutcome {
        TaskOutcome::fail("registry access is only supported on Windows")
    }

    pub fn registry_list(_hive: &str, _path: &str) -> TaskOutcome {
        TaskOutcome::fail("registry access is only supported on Windows")
    }

    pub fn services_list() -> TaskOutcome {
        TaskOutcome::fail("service enumeration is only supported on Windows")
    }
}

pub fn registry_read(hive: &str, path: &str, value_name: &str) -> TaskOutcome {
    imp::registry_read(hive, path, value_name)
}

pub fn registry_list(hive: &str, path: &str) -> TaskOutcome {
    imp::registry_list(hive, path)
}

pub fn services_list() -> TaskOutcome {
    imp::services_list()
}

#[cfg(test)]
mod tests {
    #[cfg(not(windows))]
    #[test]
    fn non_windows_returns_clear_error() {
        let outcome = super::registry_read("HKLM", r"SOFTWARE", "test");
        assert_ne!(outcome.exit_code, 0);
        assert!(outcome.stderr.contains("Windows"));
    }

    #[cfg(not(windows))]
    #[test]
    fn services_unsupported_on_non_windows() {
        let outcome = super::services_list();
        assert_ne!(outcome.exit_code, 0);
    }
}

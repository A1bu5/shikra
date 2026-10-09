//! Screen capture task.
//!
//! Uses platform-native tooling where available and returns raw PNG/JPEG bytes
//! through the normal task result channel.

use crate::TaskOutcome;

const MAX_SCREENSHOT: usize = 6 * 1024 * 1024;

#[cfg(unix)]
pub fn capture_unix() -> TaskOutcome {
    let candidates: &[(&str, &[&str])] = if cfg!(target_os = "macos") {
        &[("screencapture", &["-x", "-t", "png"])]
    } else {
        &[
            ("gnome-screenshot", &["-f"]),
            ("grim", &[]),
            ("import", &["-window", "root"]),
        ]
    };

    for (program, base_args) in candidates {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("shikra-shot-{}.png", std::process::id()));
        let path_string = path.display().to_string();
        let mut args: Vec<&str> = base_args.to_vec();
        let needs_output_arg = *program != "grim" && !base_args.is_empty();
        if needs_output_arg {
            args.push(&path_string);
        } else if *program == "grim" {
            args = vec![&path_string];
        }

        let output = match std::process::Command::new(program).args(&args).output() {
            Ok(output) => output,
            Err(_) => continue,
        };
        if !output.status.success() {
            continue;
        }
        match std::fs::read(&path) {
            Ok(bytes) => {
                let _ = std::fs::remove_file(&path);
                if bytes.len() > MAX_SCREENSHOT {
                    return TaskOutcome::fail(format!(
                        "screenshot too large: {} bytes",
                        bytes.len()
                    ));
                }
                return TaskOutcome {
                    exit_code: 0,
                    stdout: bytes,
                    stderr: String::new(),
                };
            }
            Err(_) => continue,
        }
    }
    TaskOutcome::fail("no screenshot tool available (tried screencapture/grim/import)")
}

#[cfg(not(unix))]
pub fn capture_unix() -> TaskOutcome {
    TaskOutcome::fail("screenshot is unsupported on this platform")
}

#[cfg(windows)]
mod windows_impl {
    #![allow(unsafe_code)]

    use windows_sys::Win32::Foundation::HWND;
    use windows_sys::Win32::Graphics::Gdi::{
        BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, DeleteDC, DeleteObject, GetDC,
        GetDIBits, ReleaseDC, SelectObject, BITMAPINFO, BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS,
        SRCCOPY,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_CXSCREEN, SM_CYSCREEN};

    pub fn capture() -> Result<Vec<u8>, String> {
        unsafe {
            let width = GetSystemMetrics(SM_CXSCREEN);
            let height = GetSystemMetrics(SM_CYSCREEN);
            if width <= 0 || height <= 0 {
                return Err("invalid screen dimensions".into());
            }
            let screen = GetDC(std::ptr::null_mut() as HWND);
            if screen.is_null() {
                return Err("GetDC failed".into());
            }
            let memory = CreateCompatibleDC(screen);
            if memory.is_null() {
                ReleaseDC(std::ptr::null_mut() as HWND, screen);
                return Err("CreateCompatibleDC failed".into());
            }
            let bitmap = CreateCompatibleBitmap(screen, width, height);
            if bitmap.is_null() {
                DeleteDC(memory);
                ReleaseDC(std::ptr::null_mut() as HWND, screen);
                return Err("CreateCompatibleBitmap failed".into());
            }
            let previous = SelectObject(memory, bitmap);
            let copied = BitBlt(memory, 0, 0, width, height, screen, 0, 0, SRCCOPY);
            if copied == 0 {
                SelectObject(memory, previous);
                DeleteObject(bitmap);
                DeleteDC(memory);
                ReleaseDC(std::ptr::null_mut() as HWND, screen);
                return Err("BitBlt failed".into());
            }

            let stride = (width as usize) * 4;
            let mut buffer = vec![0u8; stride * height as usize];
            let mut info = BITMAPINFO {
                bmiHeader: BITMAPINFOHEADER {
                    biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                    biWidth: width,
                    biHeight: -height, // top-down
                    biPlanes: 1,
                    biBitCount: 32,
                    biCompression: BI_RGB as u32,
                    ..Default::default()
                },
                ..Default::default()
            };
            let lines = GetDIBits(
                memory,
                bitmap,
                0,
                height as u32,
                buffer.as_mut_ptr() as *mut _,
                &mut info,
                DIB_RGB_COLORS,
            );

            SelectObject(memory, previous);
            DeleteObject(bitmap);
            DeleteDC(memory);
            ReleaseDC(std::ptr::null_mut() as HWND, screen);

            if lines == 0 {
                return Err("GetDIBits failed".into());
            }
            encode_bmp(width as u32, height as u32, &buffer)
        }
    }

    /// Encodes a top-down BGRA buffer as a 32-bit BMP file.
    fn encode_bmp(width: u32, height: u32, bgra: &[u8]) -> Result<Vec<u8>, String> {
        let stride = width as usize * 4;
        let image_size = stride
            .checked_mul(height as usize)
            .ok_or_else(|| "image too large".to_string())?;
        if bgra.len() < image_size {
            return Err("short pixel buffer".into());
        }
        let file_size = 14 + 40 + image_size;
        let mut out = Vec::with_capacity(file_size);
        out.extend_from_slice(b"BM");
        out.extend_from_slice(&(file_size as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // reserved
        out.extend_from_slice(&54u32.to_le_bytes()); // pixel data offset
        out.extend_from_slice(&40u32.to_le_bytes()); // DIB header size
        out.extend_from_slice(&width.to_le_bytes());
        out.extend_from_slice(&height.to_le_bytes()); // positive: bottom-up rows
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&32u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // BI_RGB
        out.extend_from_slice(&(image_size as u32).to_le_bytes());
        out.extend_from_slice(&2835u32.to_le_bytes());
        out.extend_from_slice(&2835u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        // BMP stores rows bottom-up; the captured buffer is top-down.
        for row in (0..height as usize).rev() {
            out.extend_from_slice(&bgra[row * stride..row * stride + stride]);
        }
        Ok(out)
    }

    #[cfg(test)]
    mod tests {
        #[test]
        fn bmp_header_layout() {
            let pixels = vec![0xAAu8; 2 * 2 * 4];
            let bmp = super::encode_bmp(2, 2, &pixels).expect("bmp");
            assert_eq!(&bmp[..2], b"BM");
            assert_eq!(bmp.len(), 14 + 40 + 16);
            let file_size = u32::from_le_bytes(bmp[2..6].try_into().unwrap());
            assert_eq!(file_size as usize, bmp.len());
            assert_eq!(u32::from_le_bytes(bmp[18..22].try_into().unwrap()), 2);
            assert_eq!(i32::from_le_bytes(bmp[22..26].try_into().unwrap()), 2);
        }
    }
}

#[cfg(windows)]
pub fn capture_windows() -> TaskOutcome {
    match windows_impl::capture() {
        Ok(bytes) => {
            if bytes.len() > MAX_SCREENSHOT {
                return TaskOutcome::fail(format!("screenshot too large: {} bytes", bytes.len()));
            }
            TaskOutcome {
                exit_code: 0,
                stdout: bytes,
                stderr: String::new(),
            }
        }
        Err(err) => TaskOutcome::fail(err),
    }
}

#[cfg(not(windows))]
pub fn capture_windows() -> TaskOutcome {
    TaskOutcome::fail("Windows screenshot capture is unsupported on this platform")
}

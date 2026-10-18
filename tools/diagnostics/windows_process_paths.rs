// Standalone Windows runner probe; no dependencies, media access or installed changes.
use std::{
    fs::File,
    os::windows::io::AsRawHandle,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetFinalPathNameByHandleW(
        file: *mut std::ffi::c_void,
        output: *mut u16,
        size: u32,
        flags: u32,
    ) -> u32;
}
fn final_name(path: &Path, flag: u32) -> PathBuf {
    let file = File::open(path).unwrap();
    let mut output = vec![0u16; 32768];
    let size = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            output.as_mut_ptr(),
            output.len() as u32,
            flag,
        )
    } as usize;
    assert!(size > 0 && size < output.len());
    let name = String::from_utf16(&output[..size]).unwrap();
    PathBuf::from(if flag == 2 {
        format!(r"\\?\GLOBALROOT{name}")
    } else {
        name
    })
}
fn main() {
    let system_root = std::env::var_os("SystemRoot").unwrap();
    for (role, args) in [
        ("cmd.exe", vec!["/d", "/c", "exit", "0"]),
        ("where.exe", vec!["/?"]),
    ] {
        let original = Path::new(&system_root).join("System32").join(role);
        for (kind, path) in [
            ("dos", original.clone()),
            ("kernel", final_name(&original, 2)),
            ("guid", final_name(&original, 1)),
        ] {
            assert_eq!(
                std::fs::read(&original).unwrap(),
                std::fs::read(&path).unwrap()
            );
            for piped in [false, true] {
                let mut command = Command::new(&path);
                command
                    .args(&args)
                    .env_clear()
                    .env("SystemRoot", &system_root)
                    .stdin(Stdio::null());
                if piped {
                    match command.output() {
                        Ok(result) => println!(
                            "role={role} path={kind} piped=true exit={:?}",
                            result.status.code()
                        ),
                        Err(error) => println!(
                            "role={role} path={kind} piped=true error={:?}",
                            error.raw_os_error()
                        ),
                    }
                } else {
                    match command.stdout(Stdio::null()).stderr(Stdio::null()).status() {
                        Ok(status) => println!(
                            "role={role} path={kind} piped=false exit={:?}",
                            status.code()
                        ),
                        Err(error) => println!(
                            "role={role} path={kind} piped=false error={:?}",
                            error.raw_os_error()
                        ),
                    }
                }
            }
        }
    }
}

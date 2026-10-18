// Standalone Windows runner probe; no dependencies, media access or installed changes.
use std::{
    fs::File,
    os::windows::{ffi::OsStrExt, io::AsRawHandle},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
#[repr(C)]
struct StartupInfo {
    size: u32,
    reserved: *mut u16,
    desktop: *mut u16,
    title: *mut u16,
    geometry: [u32; 7],
    flags: u32,
    show: u16,
    reserved_length: u16,
    reserved_data: *mut u8,
    input: *mut std::ffi::c_void,
    output: *mut std::ffi::c_void,
    error: *mut std::ffi::c_void,
}
#[repr(C)]
struct ProcessInfo {
    process: *mut std::ffi::c_void,
    thread: *mut std::ffi::c_void,
    process_id: u32,
    thread_id: u32,
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateProcessW(
        application: *const u16,
        command: *mut u16,
        process_security: *const std::ffi::c_void,
        thread_security: *const std::ffi::c_void,
        inherit: i32,
        flags: u32,
        environment: *const std::ffi::c_void,
        directory: *const u16,
        startup: *const StartupInfo,
        process: *mut ProcessInfo,
    ) -> i32;
    fn WaitForSingleObject(handle: *mut std::ffi::c_void, milliseconds: u32) -> u32;
    fn GetExitCodeProcess(handle: *mut std::ffi::c_void, code: *mut u32) -> i32;
    fn TerminateProcess(handle: *mut std::ffi::c_void, code: u32) -> i32;
    fn CloseHandle(handle: *mut std::ffi::c_void) -> i32;

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
fn direct_process(path: &Path, args: &[&str], explicit_application: bool) -> String {
    let application: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut command: Vec<u16> = format!("\"{}\" {}\0", path.display(), args.join(" "))
        .encode_utf16()
        .collect();
    let environment: Vec<u16> = format!("SystemRoot={}\0\0", std::env::var("SystemRoot").unwrap())
        .encode_utf16()
        .collect();
    let mut startup: StartupInfo = unsafe { std::mem::zeroed() };
    startup.size = std::mem::size_of::<StartupInfo>() as u32;
    let mut process: ProcessInfo = unsafe { std::mem::zeroed() };
    assert_eq!(std::mem::size_of::<StartupInfo>(), 104);
    assert_eq!(std::mem::size_of::<ProcessInfo>(), 24);
    let created = unsafe {
        CreateProcessW(
            if explicit_application {
                application.as_ptr()
            } else {
                std::ptr::null()
            },
            command.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            0x400,
            environment.as_ptr().cast(),
            std::ptr::null(),
            &startup,
            &mut process,
        )
    };
    if created == 0 {
        return format!("error={:?}", std::io::Error::last_os_error().raw_os_error());
    }
    let waited = unsafe { WaitForSingleObject(process.process, 5000) };
    if waited != 0 {
        let terminated = unsafe { TerminateProcess(process.process, 1) };
        let drained = unsafe { WaitForSingleObject(process.process, 5000) };
        unsafe {
            CloseHandle(process.thread);
            CloseHandle(process.process);
        }
        assert_ne!(terminated, 0);
        assert_eq!(drained, 0);
        return format!("wait={waited}");
    }
    let mut code = 0;
    let read = unsafe { GetExitCodeProcess(process.process, &mut code) };
    unsafe {
        CloseHandle(process.thread);
        CloseHandle(process.process);
    }
    assert_ne!(read, 0);
    format!("exit={code}")
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
            for explicit in [false, true] {
                let result = direct_process(&path, &args, explicit);
                if kind == "dos" {
                    assert_eq!(result, "exit=0", "direct Win32 baseline must succeed");
                }
                println!("role={role} path={kind} direct=true explicit={explicit} {result}");
            }
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

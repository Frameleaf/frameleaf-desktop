// Disposable Windows runner probe: compare module loaders without changing production authority.
use std::{
    fs,
    fs::OpenOptions,
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    path::{Path, PathBuf},
    process::Command,
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
fn kernel_path(path: &Path, device: bool) -> PathBuf {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(0x02000000 | 0x00200000) // Directory handles; do not follow a final reparse point.
        .open(path)
        .unwrap();
    let mut buffer = vec![0u16; 32768];
    let size = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            2,
        )
    } as usize;
    assert!(size > 0 && size < buffer.len());
    let name = String::from_utf16(&buffer[..size]).unwrap();
    PathBuf::from(format!(
        "{}GLOBALROOT{name}",
        if device { r"\\.\" } else { r"\\?\" }
    ))
}
fn main() {
    let node = PathBuf::from(std::env::var_os("FRAMELEAF_DIAGNOSTIC_NODE").unwrap());
    let version = Command::new(&node).arg("--version").output().unwrap();
    assert!(version.status.success());
    assert_eq!(String::from_utf8_lossy(&version.stdout).trim(), "v26.11.1");
    let scratch = std::env::temp_dir().join(format!(
        "frameleaf-node-paths-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&scratch).unwrap();
    fs::write(scratch.join("fixture.cjs"), "module.exports = 42;\n").unwrap();
    fs::write(scratch.join("fixture.mjs"), "export default 43;\n").unwrap();
    let common = r#"
const root = process.env.FRAMELEAF_PROBE_ROOT;
assert.equal(fs.readFileSync(path.join(root, 'fixture.cjs'), 'utf8'), 'module.exports = 42;\n');
console.log('raw-io-ok', process.execPath);
"#;
    let nested = r#"
const child = spawnSync(process.env.FRAMELEAF_PROBE_NODE,
  [...process.execArgv.filter(arg => arg.startsWith('--preserve-symlinks')), '--process-timeout=5s', '-e', "console.log(require(require('node:path').join(process.env.FRAMELEAF_PROBE_ROOT, 'fixture.cjs')))"],
  { encoding: 'utf8', timeout: 8000, windowsHide: true });
assert.ifError(child.error);
assert.equal(child.status, 0, child.stderr);
assert.equal(child.stdout.trim(), '42');
console.log('nested-ok');
"#;
    let cjs = format!("const assert=require('node:assert/strict'), fs=require('node:fs'), path=require('node:path'), {{spawnSync}}=require('node:child_process');\n{common}\nassert.equal(require(path.join(root,'fixture.cjs')),42); console.log('cjs-ok');\n{nested}");
    let esm = format!("import assert from 'node:assert/strict'; import fs from 'node:fs'; import path from 'node:path'; import {{spawnSync}} from 'node:child_process'; import {{pathToFileURL}} from 'node:url';\n{common}\nassert.equal((await import(pathToFileURL(path.join(root,'fixture.mjs')).href)).default,43); console.log('esm-ok');\n{nested}");
    fs::write(scratch.join("main.cjs"), &cjs).unwrap();
    fs::write(scratch.join("main.mjs"), &esm).unwrap();
    for (kind, executable, root) in [
        ("dos", node.clone(), scratch.clone()),
        (
            "device-kernel",
            kernel_path(&node, true),
            kernel_path(&scratch, true),
        ),
        (
            "verbatim-kernel",
            kernel_path(&node, true),
            kernel_path(&scratch, false),
        ),
    ] {
        assert_eq!(fs::read(&node).unwrap(), fs::read(&executable).unwrap());
        assert_eq!(
            fs::read(scratch.join("main.cjs")).unwrap(),
            fs::read(root.join("main.cjs")).unwrap()
        );
        for preserve in [false, true] {
            for mode in ["cjs", "esm", "eval"] {
                let mut command = Command::new(&executable);
                command
                    .env_clear()
                    .env("SystemRoot", std::env::var_os("SystemRoot").unwrap())
                    .env("TEMP", &scratch)
                    .env("TMP", &scratch)
                    .env("FRAMELEAF_PROBE_ROOT", &root)
                    .env("FRAMELEAF_PROBE_NODE", &executable)
                    .arg("--process-timeout=10s");
                if preserve {
                    command.args(["--preserve-symlinks", "--preserve-symlinks-main"]);
                }
                match mode {
                    "eval" => {
                        command.arg("-e").arg(&cjs);
                    }
                    "cjs" => {
                        command.arg(root.join("main.cjs"));
                    }
                    _ => {
                        command.arg(root.join("main.mjs"));
                    }
                }
                let output = command.output().unwrap();
                println!(
                    "path={kind} preserve={preserve} mode={mode} exit={:?}\nstdout={}\nstderr={}",
                    output.status.code(),
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
                if kind == "dos" {
                    assert!(output.status.success(), "DOS calibration must succeed");
                }
            }
        }
    }
    fs::remove_dir_all(&scratch).unwrap();
}

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from windows_probe_process import create_probe_directory, run_probe


@unittest.skipUnless(os.name == 'nt', 'requires Windows Job Objects')
class OwnedProbeTests(unittest.TestCase):
    def test_private_state_creation_refuses_existing_directory(self):
        with tempfile.TemporaryDirectory() as state:
            directory = Path(state) / 'owned-state'
            create_probe_directory(directory)
            marker = directory / 'marker'
            marker.write_text('preserved')
            with self.assertRaises(FileExistsError):
                create_probe_directory(directory)
            self.assertEqual(marker.read_text(), 'preserved')

    def test_normal_exit_removes_lingering_descendant(self):
        code = """import subprocess,sys
assert sys.stdin.buffer.read(1) == b'1'
p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(120)'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
print(p.pid, flush=True)
"""
        result = run_probe([sys.executable, '-c', code], timeout=10)
        self.assertEqual(result.returncode, 0)
        self.assert_process_exited(int(result.stdout))

    def test_timeout_removes_parent_and_descendant(self):
        code = """import pathlib,subprocess,sys,time
assert sys.stdin.buffer.read(1) == b'1'
p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(120)'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
pathlib.Path(sys.argv[1]).write_text(str(p.pid))
time.sleep(120)
"""
        with tempfile.TemporaryDirectory() as state:
            pid_file = Path(state) / 'owned-child.pid'
            with self.assertRaises(subprocess.TimeoutExpired):
                run_probe([sys.executable, '-c', code, str(pid_file)], timeout=3)
            self.assert_process_exited(int(pid_file.read_text()))

    def test_nonzero_exit_is_preserved(self):
        result = run_probe([sys.executable, '-c', "import sys; assert sys.stdin.buffer.read(1)==b'1'; sys.exit(7)"], timeout=10)
        self.assertEqual(result.returncode, 7)

    def assert_process_exited(self, pid):
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel.WaitForSingleObject.restype = wintypes.DWORD
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        handle = kernel.OpenProcess(0x100000, False, pid)
        if not handle:
            self.assertEqual(ctypes.get_last_error(), 87)
            return
        try:
            # Job termination is asynchronous; require the process object to signal.
            self.assertEqual(kernel.WaitForSingleObject(handle, 5000), 0)
        finally:
            self.assertTrue(kernel.CloseHandle(handle))


if __name__ == '__main__':
    unittest.main()

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from qualify_windows_user_host import select_executable
from windows_probe_process import run_probe


class CargoReceiptTests(unittest.TestCase):
    def test_only_the_exact_compiled_host_test_is_selected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / 'src-tauri/target/debug/deps/host_runtime-0123456789abcdef.exe'
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b'fixture')
            record = {'reason':'compiler-artifact', 'target':{'name':'host_runtime','kind':['test']},
                      'profile':{'test':True}, 'executable':str(binary)}
            receipt = root / 'build.jsonl'
            receipt.write_text(json.dumps(record)+'\n')
            self.assertEqual(select_executable(receipt, root), binary.resolve())
            for mutation in [{'executable':str(root/'outside.exe')},
                             {'target':{'name':'other','kind':['test']}},
                             {'profile':{'test':False}}]:
                receipt.write_text(json.dumps(record | mutation)+'\n')
                with self.assertRaises(ValueError):
                    select_executable(receipt, root)
            receipt.write_text((json.dumps(record)+'\n')*2)
            with self.assertRaises(ValueError):
                select_executable(receipt, root)

    @unittest.skipUnless(os.name == 'nt', 'requires Windows token and Job APIs')
    def test_restricted_child_keeps_identity_and_preserves_nonzero_exit(self):
        code = """import sys
assert sys.stdin.buffer.read(1)==b'1'
from qualify_windows_user_host import run_restricted
sys.exit(run_restricted([sys.executable,'-c','import sys; print("owned restricted child"); sys.exit(7)'], {'SystemRoot':__import__('os').environ['SystemRoot']}, __import__('os').getcwd()))
"""
        result = run_probe([sys.executable,'-c',code], cwd=Path(__file__).parent, timeout=15)
        self.assertEqual(result.returncode, 7, result.stdout + result.stderr)
        facts = json.loads(result.stdout.splitlines()[0])
        self.assertTrue(facts['sameUser'])
        self.assertFalse(facts['administratorsEnabled'])
        self.assertFalse(facts['powerUsersEnabled'])
        self.assertTrue(facts['defaultDaclUserAccessAdded'])
        self.assertIn('integrityRid',facts)
        self.assertIn('elevated',facts)
        self.assertIn('owned restricted child',result.stdout)

    @unittest.skipUnless(os.name == 'nt', 'requires Windows token and Job APIs')
    def test_restricted_system_child_preserves_output_and_exit(self):
        code = """import os,sys
assert sys.stdin.buffer.read(1)==b'1'
from qualify_windows_user_host import run_restricted
from pathlib import Path
sys.exit(run_restricted([str(Path(os.environ['SystemRoot'])/'System32/cmd.exe'),'/d','/c','echo owned restricted child&exit /b 7'], {'SystemRoot':os.environ['SystemRoot']}, os.getcwd()))
"""
        result = run_probe([sys.executable,'-c',code], cwd=Path(__file__).parent, timeout=15)
        self.assertEqual(result.returncode, 7, result.stdout + result.stderr)
        self.assertIn('owned restricted child',result.stdout)


if __name__ == '__main__':
    unittest.main()

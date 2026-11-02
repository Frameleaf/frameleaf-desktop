import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


@unittest.skipIf(os.name == 'nt', 'Linux shell verifier runs on Unix')
class LinuxInstallerVerifierTests(unittest.TestCase):
    def test_stored_modes_and_fail_closed_extraction(self):
        producer = '''from pathlib import Path
import os, sys
case = os.environ['CHECK_CASE']
if ROLE == 'deb':
    assert sys.argv[1] == '--extract'
    destination = Path(sys.argv[-1])
else:
    assert sys.argv[1:6] == ['-strict-errors', '-no-progress', '-processors', '1', '-offset']
    assert sys.argv[6] == '4096'
    assert sys.argv[7] == '-dest'
    assert sys.argv[-1] == 'usr/share/Frameleaf/native-runtime'
    destination = Path(sys.argv[8])
if case == ROLE + '-extract-fail': sys.exit(19)
root = destination / 'usr/share/Frameleaf/native-runtime'
(root / 'payload').mkdir(parents=True)
for name in ['manifest.json', 'manifest.sig', 'payload/python']:
    path = root / name
    path.write_text('{"python":"python"}' if name == 'manifest.json' else 'fixture')
    path.chmod(0o755 if name == 'payload/python' else 0o644)
for path in [root, root / 'payload']: path.chmod(0o755)
if case == ROLE + '-private-directory': root.chmod(0o700)
if case == ROLE + '-private-signature': (root / 'manifest.sig').chmod(0o600)
if case == ROLE + '-nonexecutable': (root / 'payload/python').chmod(0o644)
if case == ROLE + '-writable': (root / 'manifest.sig').chmod(0o666)
'''
        cases = ['valid', 'missing', 'duplicate', 'invalid-offset', 'deb-extract-fail',
                 'image-extract-fail', 'crypto-fail']
        cases += [role + '-' + failure for role in ['deb', 'image']
                  for failure in ['private-directory', 'private-signature', 'nonexecutable', 'writable']]
        if sys.platform == 'linux':
            for tool in ['mksquashfs', 'unsquashfs']:
                self.assertIsNotNone(shutil.which(tool), tool + ' is required on Linux')
            cases += ['real-valid', 'real-private-directory']
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory(prefix='installer modes ') as temp:
                root = Path(temp)
                (root / 'tools').mkdir()
                shutil.copyfile(Path(__file__).with_name('verify_linux_installers.sh'), root / 'tools/verify_linux_installers.sh')
                binaries = root / 'bin'
                binaries.mkdir()

                def executable(path, body):
                    path.write_text(body)
                    path.chmod(0o755)

                executable(binaries / 'uname', '#!/bin/sh\necho Linux\n')
                executable(binaries / 'mktemp', '#!/bin/sh\nmkdir \"$CHECK_ROOT/scratch\"\nprintf \"%s\" \"$CHECK_ROOT/scratch\"\n')
                executable(binaries / 'dpkg-deb', '#!/usr/bin/env python3\nROLE="deb"\n' + producer)
                if not case.startswith('real-'):
                    executable(binaries / 'unsquashfs', '#!/usr/bin/env python3\nROLE="image"\n' + producer)
                executable(binaries / 'node', '''#!/usr/bin/env python3
import os, sys
from pathlib import Path
assert 'await packageConfiguration(process.argv[1])' in sys.argv[-2]
assert (Path(sys.argv[-1]) / 'manifest.sig').is_file()
if os.environ['CHECK_CASE'] == 'crypto-fail': sys.exit(31)
with open(os.environ['CHECK_ROOT'] + '/verified.txt', 'a') as output: output.write(sys.argv[-1] + '\\n')
''')
                bundle = root / 'src-tauri/target/release/bundle'
                (bundle / 'deb').mkdir(parents=True)
                (bundle / 'appimage').mkdir()
                (bundle / 'deb/Frameleaf.deb').touch()
                if case != 'missing':
                    executable(bundle / 'appimage/Frameleaf Candidate.AppImage', '''#!/bin/sh
[ "$1" = --appimage-offset ] || exit 29
if [ "$CHECK_CASE" = invalid-offset ]; then echo invalid; else echo 4096; fi
''')
                if case.startswith('real-'):
                    stored = root / 'stored'
                    subprocess.run([str(binaries / 'dpkg-deb'), '--extract', 'fixture', str(stored)],
                                   env={**os.environ, 'CHECK_CASE': 'deb-private-directory' if case.endswith('private-directory') else 'valid'},
                                   check=True, capture_output=True, timeout=30)
                    image = root / 'fixture.squashfs'
                    subprocess.run(['mksquashfs', str(stored), str(image), '-noappend', '-no-progress', '-processors', '1'],
                                   check=True, capture_output=True, timeout=30)
                    prefix = b'#!/bin/sh\n[ "$1" = --appimage-offset ] || exit 29\necho 4096\nexit 0\n'
                    (bundle / 'appimage/Frameleaf Candidate.AppImage').write_bytes(prefix.ljust(4096, b'\0') + image.read_bytes())
                if case == 'duplicate':
                    (bundle / 'deb/duplicate.deb').touch()
                result = subprocess.run(['bash', str(root / 'tools/verify_linux_installers.sh')], cwd=root,
                                        env={**os.environ, 'PATH': str(binaries) + os.pathsep + os.environ['PATH'],
                                             'CHECK_CASE': case, 'CHECK_ROOT': str(root)}, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode == 0, case in {'valid', 'real-valid'}, result.stdout + result.stderr)
                self.assertFalse((root / 'scratch').exists())
                if case in {'valid', 'real-valid'}:
                    self.assertEqual(len((root / 'verified.txt').read_text().splitlines()), 2)
                elif case.endswith('private-directory'):
                    self.assertIn('. has 0700', result.stderr)
                elif case.endswith('private-signature'):
                    self.assertIn('manifest.sig has 0600', result.stderr)
                elif case.endswith('nonexecutable'):
                    self.assertIn('payload/python has 0644', result.stderr)
                elif case.endswith('writable'):
                    self.assertIn('manifest.sig has 0666', result.stderr)


if __name__ == '__main__':
    unittest.main()

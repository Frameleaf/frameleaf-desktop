import hashlib
import json
import os
import shlex
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from build_host_linux_deb import installer_scripts, package_names, stage_packages, archive, dependencies, build
from build_runtime import BuildError


class LinuxHostDebTests(unittest.TestCase):
    def test_build_verifies_with_trusted_node_before_staging_or_executing_payload(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            candidate, controller, _ = self.fixture(root)
            controller.write_bytes(b'\x7fELF\x02\x01' + b'\0' * 12 + (62).to_bytes(2, 'little'))
            with patch('build_host_linux_deb.platform.system', return_value='Linux'), patch('build_host_linux_deb.platform.machine', return_value='x86_64'), patch('build_host_linux_deb.shutil.which', return_value='/trusted/build-node'), patch('build_host_linux_deb.run', side_effect=BuildError('host_signature_invalid')) as command:
                with self.assertRaisesRegex(BuildError, 'host_signature_invalid'):
                    build(candidate, controller, root / 'out')
                self.assertEqual(command.call_count, 1)
                self.assertEqual(command.call_args.args[0][0], '/trusted/build-node')
                self.assertNotIn(str(controller), [str(arg) for arg in command.call_args.args[0]])
                self.assertFalse((root / 'out').exists())

    def test_private_sonames_map_only_bundled_versions_without_ignoring_missing_info(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            tree = root / 'tree'
            tree.mkdir()
            (tree / 'library').write_bytes(b'\x7fELFfixture')
            def command(args, **kwargs):
                return '(SONAME) Library soname: [libfixture-2.so]\n(SONAME) Library soname: [libprivate.so]' if args[0] == 'readelf' else 'shlibs:Depends=libc6 (>= 2.39)'
            with patch('build_host_linux_deb.run', side_effect=command) as call:
                self.assertIn('libc6', dependencies(tree, 'frameleaf-fixture', root / 'work'))
                self.assertEqual((root / 'work/debian/shlibs.local').read_text(), 'libfixture 2 frameleaf-fixture\n')
                args = call.call_args.args[0]
                self.assertIn('-xframeleaf-fixture', args)
                self.assertNotIn('--ignore-missing-info', args)

    @unittest.skipUnless(os.name == 'posix' and os.getuid() != 0, 'requires ordinary POSIX account')
    def test_unmodified_hooks_refuse_nonroot_before_touching_installed_paths(self):
        with tempfile.TemporaryDirectory() as temp:
            for hooks in installer_scripts('a' * 64, 'b' * 64).values():
                for name, text in hooks.items():
                    script = Path(temp) / name
                    script.write_text(text)
                    result = subprocess.run(['/bin/sh', script, 'install'], capture_output=True)
                    self.assertEqual(result.returncode, 77)

    def test_identity_and_architecture_cannot_inject_control_or_paths(self):
        self.assertEqual(len(package_names('a' * 64, 'b' * 64)), 2)
        for value in ['', '../escape', 'A' * 64, 'a' * 64 + '\nDepends: bad']:
            with self.assertRaises(BuildError):
                package_names(value, 'b' * 64)

    def fixture(self, root):
        candidate = root / 'candidate'
        (candidate / 'payload').mkdir(parents=True)
        (candidate / 'payload/node').write_bytes(b'fixture node, do not execute')
        (candidate / 'payload/node').chmod(0o700)
        for name in ['manifest.json', 'manifest.sig']:
            (candidate / name).write_bytes(b'fixture')
        controller = root / 'controller'
        controller.write_bytes(b'fixture helper, do not execute')
        controller.chmod(0o700)
        return candidate, controller, hashlib.sha256(controller.read_bytes()).hexdigest()

    @unittest.skipUnless(os.name == 'posix', 'requires POSIX permissions')
    def test_staging_separates_bootstrap_runtime_and_preserves_sources(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            candidate, controller, digest = self.fixture(root)
            out = root / 'out'
            bootstrap, runtime = stage_packages(candidate, controller, out, 'a' * 64, digest, 'amd64')
            names = package_names('a' * 64, digest)
            self.assertIn('Package: ' + names[0], (bootstrap / 'DEBIAN/control').read_text())
            self.assertIn('Pre-Depends: ' + names[0] + ' (= 1)', (runtime / 'DEBIAN/control').read_text())
            base = runtime / 'opt/frameleaf'
            self.assertEqual((base / 'Runtimes' / ('a' * 64) / 'payload/node').read_bytes(), (candidate / 'payload/node').read_bytes())
            self.assertEqual((bootstrap / 'opt/frameleaf/Bootstrap' / digest / 'frameleaf-native-host').read_bytes(), controller.read_bytes())
            self.assertEqual((base / 'Controllers' / ('a' * 64) / digest / 'frameleaf-native-host').stat().st_mode & 0o777, 0o755)
            self.assertFalse((base / 'Profiles').exists())
            self.assertFalse(any(p.name in ['installation.json', '.runtime-lease', '.package-maintenance'] for p in out.rglob('*')))
            self.assertEqual((candidate / 'payload/node').stat().st_mode & 0o777, 0o700)
            self.assertEqual(controller.stat().st_mode & 0o777, 0o700)
            with self.assertRaises(BuildError):
                stage_packages(candidate, controller, out, 'a' * 64, digest, 'amd64')
            with self.assertRaises(BuildError):
                stage_packages(candidate, controller, root / 'invalid', 'a' * 64, digest, 'amd64\nDepends: bad')

    @unittest.skipUnless(os.name == 'posix', 'requires POSIX shell')
    def test_hooks_fence_before_replacement_and_preserve_refusals_and_data(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            marker, fail = root / 'called', root / 'fail'
            runtime = root / 'opt/frameleaf/Runtimes' / ('a' * 64)
            helper = root / 'helper'
            helper.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> ' + shlex.quote(str(marker)) + '\n[ ! -e ' + shlex.quote(str(fail)) + ' ] || exit 73\nif [ "$1" = --prepare-linux-package ] && [ -d ' + shlex.quote(str(runtime)) + ' ]; then : > ' + shlex.quote(str(runtime / '.package-maintenance')) + '; fi\n')
            helper.chmod(0o755)
            digest = hashlib.sha256(helper.read_bytes()).hexdigest()
            # Simulate root metadata only within temporary fixtures; never elevate or install.
            stat = root / 'stat'
            stat.write_text('#!' + shutil.which('python3') + '\nimport os,sys\ns=os.lstat(sys.argv[-1]);print({"%u":"0","%a":format(s.st_mode&0o7777,"o"),"%h":str(s.st_nlink),"%s":str(s.st_size)}[sys.argv[2]])\n')
            stat.chmod(0o755)
            identity = root / 'id'
            identity.write_text('#!/bin/sh\nprintf "0\\n"\n')
            identity.chmod(0o755)
            sha = root / 'sha'
            sha.write_text('#!' + shutil.which('python3') + '\nimport hashlib,sys\nprint(hashlib.sha256(open(sys.argv[-1],"rb").read()).hexdigest()+"  "+sys.argv[-1])\n')
            sha.chmod(0o755)
            scripts = {}
            for role, hooks in installer_scripts('a' * 64, digest).items():
                for name, text in hooks.items():
                    path = root / (role + '-' + name)
                    path.write_text(text.replace('/opt', str(root / 'opt')).replace('/usr/bin/stat', str(stat)).replace('/usr/bin/id', str(identity)).replace('/usr/bin/sha256sum', str(sha)))
                    subprocess.run(['/bin/sh', '-n', path], check=True)
                    scripts[role, name] = path
            def run(role, hook, mode):
                return subprocess.run(['/bin/sh', scripts[role, hook], mode], capture_output=True).returncode
            self.assertEqual(run('bootstrap', 'preinst', 'install'), 0)
            installed = root / 'opt/frameleaf/Bootstrap' / digest / 'frameleaf-native-host'
            shutil.copy2(helper, installed)
            self.assertEqual(run('bootstrap', 'postinst', 'configure'), 0)
            self.assertEqual(run('runtime', 'preinst', 'install'), 0)
            self.assertTrue(marker.read_text().startswith('--prepare-linux-package '))
            runtime.mkdir(parents=True)
            self.assertEqual(run('runtime', 'preinst', 'upgrade'), 0)
            self.assertTrue(marker.read_text().splitlines()[-1].startswith('--prepare-linux-package '))
            fail.touch()
            self.assertEqual(run('runtime', 'prerm', 'upgrade'), 73)
            before = marker.read_bytes()
            self.assertNotEqual(run('runtime', 'prerm', 'failed-upgrade'), 0)
            self.assertEqual(marker.read_bytes(), before)
            fail.unlink()
            receipt = runtime / 'installation.json'
            receipt.write_text('fixture receipt')
            retained = runtime / 'retained'
            retained.write_bytes(b'keep')
            self.assertEqual(run('runtime', 'postrm', 'abort-upgrade'), 0)
            self.assertTrue(receipt.exists())
            self.assertEqual(run('runtime', 'postrm', 'remove'), 0)
            self.assertFalse(receipt.exists())
            self.assertTrue((runtime / '.package-maintenance').exists())
            self.assertEqual(retained.read_bytes(), b'keep')
            installed.write_bytes(b'changed helper')
            self.assertNotEqual(run('runtime', 'postinst', 'configure'), 0)
            self.assertEqual(marker.read_bytes(), before)
            installed.unlink()
            installed.symlink_to(helper)
            self.assertNotEqual(run('bootstrap', 'preinst', 'install'), 0)
            installed.unlink()
            shutil.copy2(helper, installed)
            installed.parent.chmod(0o777)
            self.assertNotEqual(run('runtime', 'preinst', 'install'), 0)
            installed.parent.chmod(0o755)
            self.assertNotEqual(run('runtime', 'preinst', 'unknown'), 0)

    @unittest.skipUnless(shutil.which('dpkg-deb') and os.name == 'posix', 'requires Debian archive tool')
    def test_real_archives_have_root_owners_and_required_bootstrap(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            candidate, controller, digest = self.fixture(root)
            roots = stage_packages(candidate, controller, root / 'out', 'a' * 64, digest, 'amd64')
            for index, tree in enumerate(roots):
                package = root / (str(index) + '.deb')
                archive(tree, package)
                listing = subprocess.check_output(['dpkg-deb', '--contents', package], text=True)
                self.assertIn('root/root', listing)
                control = subprocess.check_output(['dpkg-deb', '--field', package], text=True)
                self.assertIn('Architecture: amd64', control)
                self.assertNotIn('Profiles', listing)
                if index == 1:
                    self.assertIn('Pre-Depends: ' + package_names('a' * 64, digest)[0] + ' (= 1)', control)

    @unittest.skipUnless(os.sys.platform.startswith('linux') and shutil.which('dpkg-shlibdeps'), 'requires Linux ELF dependency tooling')
    def test_real_system_elf_generates_dependencies_without_executing_it(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            tree = root / 'package'
            (tree / 'bin').mkdir(parents=True)
            shutil.copy2('/bin/true', tree / 'bin/never-run')
            result = dependencies(tree, 'frameleaf-fixture', root / 'work')
            self.assertIn('libc6', result)
            self.assertNotIn('frameleaf-fixture', result)

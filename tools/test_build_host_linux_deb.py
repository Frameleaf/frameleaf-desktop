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
from build_runtime import BuildError, run


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

    def test_native_addon_sonames_keep_dependency_analysis_without_library_version_mapping(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            tree = root / 'tree'
            tree.mkdir()
            names = ['sharp-linux-x64-0.35.5.node', 'bare-fs@4.bare', 'bare-path@3.bare', 'bare-url@2.bare', 'bcrypt_lib.node']
            for name in names:
                (tree / name).write_bytes(b'\x7fELFfixture')
            def command(args, **kwargs):
                return '(SONAME) Library soname: [' + args[-1].name + ']' if args[0] == 'readelf' else 'shlibs:Depends=libc6 (>= 2.39)'
            with patch('build_host_linux_deb.run', side_effect=command) as call:
                self.assertIn('libc6', dependencies(tree, 'frameleaf-fixture', root / 'work'))
                self.assertEqual((root / 'work/debian/shlibs.local').read_text(), '')
                args = call.call_args.args[0]
                self.assertEqual(sum(str(arg).startswith('-e') for arg in args), len(names))
                self.assertNotIn('--ignore-missing-info', args)

    def test_origin_needed_is_normalized_only_in_a_private_analysis_copy(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            tree = root / 'tree'
            library = tree / 'lib'
            library.mkdir(parents=True)
            shim = library / 'libpython3.so'
            target = library / 'libpython3.12.so.1.0'
            for path in [shim, target]:
                path.write_bytes(b'\x7fELFfixture')
            original = shim.read_bytes()
            def command(args, **kwargs):
                if args[0] == 'readelf':
                    if args[-1] == shim:
                        return '(SONAME) Library soname: [libpython3.so]\n(NEEDED) Shared library: [$ORIGIN/../lib/libpython3.12.so.1.0]\n(RUNPATH) Library runpath: [$ORIGIN]'
                    return '(SONAME) Library soname: [libpython3.12.so.1.0]'
                return 'shlibs:Depends=libc6 (>= 2.39)' if args[0] == 'dpkg-shlibdeps' else ''
            with patch('build_host_linux_deb.run', side_effect=command) as call, patch('build_host_linux_deb.shutil.which', return_value='/trusted/patchelf'):
                self.assertIn('libc6', dependencies(tree, 'frameleaf-fixture', root / 'work'))
                changes = [item.args[0] for item in call.call_args_list if item.args[0][0] == '/trusted/patchelf']
                self.assertTrue(changes)
                alias = 'libframeleaf-analysis-' + hashlib.sha256(target.read_bytes()).hexdigest() + '.so.1'
                replacement = next(change for change in changes if change[1] == '--replace-needed')
                self.assertEqual(replacement[1:4], ['--replace-needed', '$ORIGIN/../lib/libpython3.12.so.1.0', alias])
                copy = replacement[-1]
                selected = root / 'work/origin-analysis/libraries' / alias
                self.assertEqual(selected.read_bytes(), target.read_bytes())
                self.assertIn(['/trusted/patchelf', '--set-soname', alias, selected], changes)
                self.assertTrue(copy.is_relative_to(root / 'work'))
                self.assertFalse(copy.is_relative_to(tree))
                self.assertIn(['/trusted/patchelf', '--set-rpath', str(selected.parent) + ':' + str(library), copy], changes)
                self.assertIn('libframeleaf-analysis-' + hashlib.sha256(target.read_bytes()).hexdigest() + ' 1 frameleaf-fixture', (root / 'work/debian/shlibs.local').read_text())
                self.assertNotIn('-e' + str(shim), call.call_args.args[0])
                self.assertIn('-e' + str(copy), call.call_args.args[0])
                self.assertEqual(shim.read_bytes(), original)
            with patch('build_host_linux_deb.run', side_effect=command), patch('build_host_linux_deb.shutil.which', return_value=None):
                with self.assertRaisesRegex(BuildError, 'host_install_elf_tools_missing'):
                    dependencies(tree, 'frameleaf-fixture', root / 'without-tool')
                self.assertFalse((root / 'without-tool/origin-analysis').exists())

    def test_origin_needed_refuses_a_library_outside_the_staged_package(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            tree = root / 'tree'
            tree.mkdir()
            (tree / 'shim').write_bytes(b'\x7fELFfixture')
            (root / 'outside.so.1').write_bytes(b'\x7fELFoutside')
            with patch('build_host_linux_deb.run', return_value='(NEEDED) Shared library: [$ORIGIN/../outside.so.1]'):
                with self.assertRaisesRegex(BuildError, 'host_install_origin_dependency_invalid'):
                    dependencies(tree, 'frameleaf-fixture', root / 'work')

    def test_addon_sonames_refuse_paths_unknown_extensions_and_invalid_versions(self):
        for name in ['/tmp/addon.node', 'addon.node/escape', 'bare-fs@bad.bare', 'unknown.plugin']:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                root = Path(temp).resolve()
                tree = root / 'tree'
                tree.mkdir()
                (tree / 'addon').write_bytes(b'\x7fELFfixture')
                with patch('build_host_linux_deb.run', return_value='(SONAME) Library soname: [' + name + ']') as call:
                    with self.assertRaisesRegex(BuildError, 'host_install_private_soname_unsupported'):
                        dependencies(tree, 'frameleaf-fixture', root / 'work')
                    self.assertEqual(call.call_count, 1)

    def test_origin_search_paths_cannot_escape_before_analysis(self):
        for tag in ['RPATH', 'RUNPATH']:
            for reference in ['$ORIGIN/../../outside', '${ORIGIN}/../../outside', '$ORIGIN/zalias']:
                for needed in ['$ORIGIN/private.so.1', 'libc.so.6']:
                    with self.subTest(tag=tag, reference=reference, needed=needed), tempfile.TemporaryDirectory() as temp:
                        root = Path(temp).resolve()
                        tree = root / 'tree'
                        library = tree / 'lib'
                        library.mkdir(parents=True)
                        (library / 'shim.so').write_bytes(b'\x7fELFfixture')
                        (library / 'private.so.1').write_bytes(b'\x7fELFfixture')
                        (root / 'outside').mkdir()
                        if reference.endswith('/zalias'):
                            try:
                                (library / 'zalias').symlink_to(root / 'outside', target_is_directory=True)
                            except (OSError, NotImplementedError):
                                self.skipTest('directory symlink creation unavailable')
                        metadata = f'(NEEDED) Shared library: [{needed}]\n({tag}) Library search path: [{reference}]'
                        with patch('build_host_linux_deb.run', return_value=metadata) as command, patch('build_host_linux_deb.shutil.which', return_value='/trusted/patchelf'):
                            with self.assertRaisesRegex(BuildError, 'host_install_origin_dependency_invalid'):
                                dependencies(tree, 'frameleaf-fixture', root / 'work')
                            self.assertTrue(all(call.args[0][0] == 'readelf' for call in command.call_args_list))
                            self.assertFalse((root / 'work/origin-analysis').exists())

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

    @unittest.skipUnless(
        os.sys.platform.startswith('linux')
        and all(shutil.which(tool) for tool in ['gcc', 'readelf', 'patchelf', 'dpkg-shlibdeps']),
        'requires Linux native dependency build tools',
    )
    def test_real_native_addon_with_origin_dependency_preserves_staged_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            tree = root / 'package with spaces'
            library = tree / 'lib'
            library.mkdir(parents=True)
            wrong = tree / 'earlier-same-name'
            wrong.mkdir()
            (root / 'wrong.c').write_text('int answer(void) { return 17; }')
            (root / 'answer.c').write_text('int answer(void) { return 42; }')
            (root / 'addon.c').write_text('#include <stdio.h>\nextern int answer(void); int addon(void) { puts("fixture"); return answer(); }')
            target, addon = library / 'libanswer.so.1', library / 'answer.node'
            for command in [
                ['gcc', '-shared', '-fPIC', root / 'wrong.c', '-Wl,-soname,libanswer.so.1', '-o', wrong / 'libanswer.so.1'],
                ['gcc', '-shared', '-fPIC', root / 'answer.c', '-Wl,-soname,libanswer.so.1', '-o', target],
                ['gcc', '-shared', '-fPIC', root / 'addon.c', '-L' + str(library), '-l:libanswer.so.1', '-Wl,-soname,answer.node', '-Wl,-rpath,$ORIGIN/../earlier-same-name', '-o', addon],
                ['patchelf', '--replace-needed', 'libanswer.so.1', '$ORIGIN/libanswer.so.1', addon],
            ]:
                subprocess.run(command, check=True, capture_output=True)
            originals = {path: path.read_bytes() for path in [target, addon, wrong / 'libanswer.so.1']}
            with patch('build_host_linux_deb.run', wraps=run) as observed:
                result = dependencies(tree, 'frameleaf-fixture', root / 'work')
            self.assertIn('libc6', result)
            self.assertNotIn('frameleaf-fixture', result)
            for path, contents in originals.items():
                self.assertEqual(path.read_bytes(), contents)
            analysis = root / 'work/origin-analysis'
            copies = [path for path in analysis.iterdir() if path.is_file()]
            self.assertEqual(len(copies), 1)
            alias = 'libframeleaf-analysis-' + hashlib.sha256(originals[target]).hexdigest() + '.so.1'
            metadata = subprocess.check_output(['readelf', '-d', copies[0]], text=True)
            self.assertIn('Shared library: [' + alias + ']', metadata)
            self.assertNotIn('Shared library: [$ORIGIN/', metadata)
            self.assertIn(str(analysis / 'libraries') + ':', metadata)
            import ctypes
            selected = ctypes.CDLL(str(analysis / 'libraries' / alias))
            self.assertEqual(selected.answer(), 42)
            self.assertEqual(ctypes.CDLL(str(wrong / 'libanswer.so.1')).answer(), 17)
            analyzer = [call for call in observed.call_args_list if call.args[0][0] == 'dpkg-shlibdeps']
            self.assertEqual(len(analyzer), 1)
            arguments, options = analyzer[0].args[0], analyzer[0].kwargs
            # Keep the production receipt strict; collect verbose selection evidence separately.
            verbose = subprocess.run([*arguments, '-v'], **options, text=True,
                                     capture_output=True, check=True, timeout=60)
            diagnostics = verbose.stdout + verbose.stderr
            selected_path = analysis / 'libraries' / alias
            chosen = f'Using shlibs+objdump for {alias} (file {selected_path})'
            self.assertIn(chosen, diagnostics)
            # Force the old basename/search-order bug in disposable analysis inputs.
            subprocess.run(['patchelf', '--replace-needed', alias, 'libanswer.so.1', copies[0]], check=True, capture_output=True)
            subprocess.run(['patchelf', '--set-rpath', str(wrong), copies[0]], check=True, capture_output=True)
            decoy = subprocess.run([*arguments, '-v'], **options, text=True,
                                   capture_output=True, check=True, timeout=60)
            self.assertEqual([line for line in decoy.stdout.splitlines() if line.startswith('shlibs:Depends=')], ['shlibs:Depends=' + result])
            self.assertIn(f"Using shlibs+objdump for libanswer.so.1 (file {wrong / 'libanswer.so.1'})", decoy.stdout + decoy.stderr)
            self.assertNotIn(chosen, decoy.stdout + decoy.stderr)
            for path, contents in originals.items():
                self.assertEqual(path.read_bytes(), contents)

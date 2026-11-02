import shutil
import subprocess
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from build_runtime import BuildError
from relocate_windows import closure, pe_imports, inspect_pe


def pe(imports=True, machine=0x8664):
    data = bytearray(512)
    data[:2] = b'MZ'
    data[60:64] = (64).to_bytes(4, 'little')
    data[64:68] = b'PE\0\0'
    data[68:70] = machine.to_bytes(2, 'little')
    data[84:86] = (240).to_bytes(2, 'little')
    data[86:88] = (0x2022).to_bytes(2, 'little')
    data[88:90] = (0x20b).to_bytes(2, 'little')
    data[196:200] = (16).to_bytes(4, 'little')
    data[208:212] = (4096 if imports else 0).to_bytes(4, 'little')
    data[212:216] = (100 if imports else 0).to_bytes(4, 'little')
    return bytes(data)


def pe_image(names):
    data = bytearray(pe(bool(names))) + bytearray(512)
    data[70:72] = (1).to_bytes(2, 'little')
    for offset, value in [(336, 512), (340, 4096), (344, 512), (348, 512)]:
        data[offset:offset + 4] = value.to_bytes(4, 'little')
    data[212:216] = ((len(names) + 1) * 20 if names else 0).to_bytes(4, 'little')
    cursor = 616
    for index, name in enumerate(names):
        data[524 + index * 20:528 + index * 20] = (4096 + cursor - 512).to_bytes(4, 'little')
        encoded = name.encode('ascii') + b'\0'
        data[cursor:cursor + len(encoded)] = encoded
        cursor += len(encoded)
    return bytes(data)


class InspectorTests(unittest.TestCase):
    def test_clean_partial_listing_cannot_hide_an_import_descriptor(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'probe.exe'
            source.write_bytes(pe_image(['KERNEL32.dll', 'vendor.dll']))
            args = [root / 'objdump.exe', '-p', source]
            for output in ['DLL Name: KERNEL32.dll', 'DLL Name: KERNEL32.dll\nDLL Name: KERNEL32.dll']:
                with self.subTest(output=output), patch('relocate_windows.subprocess.run', return_value=subprocess.CompletedProcess(args, 0, output, '')):
                    with self.assertRaisesRegex(BuildError, 'host_pe_imports_missing'):
                        inspect_pe(args[0], source, cwd=root, env={})

    def test_imports_must_be_terminated_and_bound_to_unique_file_backed_sections(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'probe.exe'
            args = [root / 'objdump.exe', '-p', source]
            original = pe_image(['KERNEL32.dll', 'vendor.dll'])
            cases = [original[:-1]]
            for offset, value in [(208, 0xffff0000), (544, 0xffff0000), (344, 0xffff0000)]:
                data = bytearray(original)
                data[offset:offset + 4] = value.to_bytes(4, 'little')
                cases.append(bytes(data))
            data = bytearray(original)
            data[70:72] = (2).to_bytes(2, 'little')
            data[368:408] = data[328:368]
            cases.append(bytes(data))
            data = bytearray(original)
            data[552:572] = data[512:532]
            cases.append(bytes(data))
            data = bytearray(original)
            data[616:] = b'A' * (len(data) - 616)
            cases.append(bytes(data))
            output = 'DLL Name: KERNEL32.dll\nDLL Name: vendor.dll'
            for data in cases:
                source.write_bytes(data)
                with self.subTest(data=data[70:72]), patch('relocate_windows.subprocess.run', return_value=subprocess.CompletedProcess(args, 0, output, '')):
                    with self.assertRaises(BuildError):
                        inspect_pe(args[0], source, cwd=root, env={})
            source.write_bytes(original)
            with patch('relocate_windows.subprocess.run', return_value=subprocess.CompletedProcess(args, 0, output, '')):
                self.assertEqual(inspect_pe(args[0], source, cwd=root, env={}), output)
            source.write_bytes(pe_image([]))
            with patch('relocate_windows.subprocess.run', return_value=subprocess.CompletedProcess(args, 0, '', '')):
                self.assertEqual(inspect_pe(args[0], source, cwd=root, env={}), '')

    def test_inspector_requires_clean_success_and_records_bounded_diagnostics(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            env = {"HOME": str(root / "home"), "FRAMELEAF_BUILD_ERROR_LOG": str(root / "error.log")}
            args = [root / "objdump.exe", "-p", root / "probe.exe"]
            args[-1].write_bytes(pe_image(['KERNEL32.dll']))
            with patch('relocate_windows.subprocess.run', return_value=subprocess.CompletedProcess(args, 0, 'DLL Name: KERNEL32.dll\n', '')) as call:
                self.assertEqual(inspect_pe(args[0], args[-1], cwd=root, env=env), 'DLL Name: KERNEL32.dll')
                self.assertEqual(call.call_args.args[0], args)
                self.assertEqual(call.call_args.kwargs['env'], env)
                self.assertEqual(call.call_args.kwargs['cwd'], root)
                self.assertEqual(call.call_args.kwargs['timeout'], 60)
            for result in [subprocess.CompletedProcess(args, 1, '', 'invalid PE'),
                           subprocess.CompletedProcess(args, 0, 'DLL Name: KERNEL32.dll', 'partial decode ' + 'x' * 40000)]:
                with self.subTest(code=result.returncode), patch('relocate_windows.subprocess.run', return_value=result):
                    with self.assertRaisesRegex(BuildError, 'host_pe_inspection_failed'):
                        inspect_pe(args[0], args[-1], cwd=root, env=env)
                    self.assertLessEqual(len((root / 'error.log').read_text()), 32768)
            for error in [OSError('missing tool'), subprocess.TimeoutExpired(args, 60)]:
                with self.subTest(error=type(error).__name__), patch('relocate_windows.subprocess.run', side_effect=error):
                    with self.assertRaisesRegex(BuildError, 'host_pe_inspection_failed'):
                        inspect_pe(args[0], args[-1], cwd=root, env=env)


class WindowsClosureTests(unittest.TestCase):
    def test_x64_headers_and_import_table_are_bounded(self):
        self.assertTrue(pe_imports(pe()))
        self.assertFalse(pe_imports(pe(False)))
        for data in [b'not-pe', pe()[:100], pe(machine=0xaa64), pe()[:60] + b'\xff' * 4 + pe()[64:]]:
            with self.subTest(data=data[:6]), self.assertRaises(BuildError):
                pe_imports(data)
        for offset in [84, 196, 304]:
            data = bytearray(pe())
            data[offset:offset + 4] = (128 if offset == 84 else 17 if offset == 196 else 1).to_bytes(4, 'little')
            with self.subTest(offset=offset), self.assertRaises(BuildError):
                pe_imports(data)

    def test_transitive_private_dlls_are_copied_and_system_dlls_stay_external(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source = root / 'source'
            source.mkdir()
            for name in ['engine.exe', 'Vendor.dll', 'nested.dll']:
                (source / name).write_bytes(pe())
            imports = {'engine.exe': ['VENDOR.DLL', 'KERNEL32.dll', 'gdiplus.dll', 'COMCTL32.dll'],
                       'Vendor.dll': ['nested.dll', 'api-ms-win-core-file-l1-1-0.dll'],
                       'nested.dll': ['ucrtbase.dll']}
            calls = []

            def inspect(path):
                calls.append(path.name)
                return '\n'.join('DLL Name: ' + name for name in imports[path.name])

            report = closure({'bin/engine.exe': source / 'engine.exe'}, [source], root / 'output', inspect)
            shutil.rmtree(source)
            self.assertEqual(set(calls), set(imports))
            self.assertEqual((root / 'output/bin/Vendor.dll').read_bytes(), pe())
            self.assertTrue((root / 'output/bin/nested.dll').is_file())
            self.assertFalse((root / 'output/bin/KERNEL32.dll').exists())
            self.assertIn('kernel32.dll', report['systemLibraries'])
            self.assertIn('gdiplus.dll', report['systemLibraries'])
            self.assertIn('comctl32.dll', report['systemLibraries'])
            self.assertFalse((root / 'output/bin/comctl32.dll').exists())
            self.assertFalse((root / 'output/bin/gdiplus.dll').exists())
            self.assertEqual(len(report['objects']), 3)

    def test_missing_ambiguous_posix_and_incomplete_imports_are_refused(self):
        for problem in ['missing', 'ambiguous', 'msys-2.0.dll', 'cygwin1.dll', '../escape.dll', 'empty']:
            with self.subTest(problem=problem), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                source, other = root / 'source', root / 'other'
                source.mkdir(); other.mkdir()
                (source / 'engine.exe').write_bytes(pe())
                if problem == 'ambiguous':
                    (source / 'vendor.dll').write_bytes(pe())
                    (other / 'vendor.dll').write_bytes(pe() + b'different')
                name = 'vendor.dll' if problem in {'missing', 'ambiguous'} else problem
                with self.assertRaises(BuildError):
                    closure({'bin/engine.exe': source / 'engine.exe'}, [source, other], root / 'output',
                            lambda _: '' if problem == 'empty' else 'DLL Name: ' + name)

    def test_import_free_data_dll_and_dependency_cycles_are_supported(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / 'a.dll').write_bytes(pe())
            (root / 'b.dll').write_bytes(pe())
            (root / 'data.dll').write_bytes(pe(False))
            report = closure({'bin/a.dll': root / 'a.dll', 'bin/data.dll': root / 'data.dll'},
                             [root], root / 'output',
                             lambda p: '' if p.name == 'data.dll' else 'DLL Name: ' + ('b.dll' if p.name == 'a.dll' else 'a.dll'))
            self.assertEqual(len(report['objects']), 3)

    def test_links_and_case_colliding_outputs_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source = root / 'source.dll'
            source.write_bytes(pe())
            with self.assertRaisesRegex(BuildError, 'posix_runtime_forbidden'):
                closure({'bin/msys-2.0.dll': source}, [root], root / 'posix-output', lambda _: '')
            with self.assertRaises(BuildError):
                closure({'bin/a.dll': source, 'bin/A.dll': source}, [root], root / 'output', lambda _: 'DLL Name: kernel32.dll')
            if hasattr(Path, 'symlink_to'):
                try:
                    (root / 'link.dll').symlink_to(source)
                except OSError:
                    return
                with self.assertRaises(BuildError):
                    closure({'bin/a.dll': root / 'link.dll'}, [root], root / 'output-link', lambda _: '')


class WindowsSystemGraphicsTests(unittest.TestCase):
    @unittest.skipUnless(os.name == 'nt', 'actual Windows system-loader probe')
    def test_gdiplus_resolves_from_the_operating_system(self):
        import ctypes
        library = ctypes.WinDLL('gdiplus.dll', winmode=0x00000800)
        kernel = ctypes.WinDLL('kernel32.dll', use_last_error=True)
        kernel.GetModuleFileNameW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32]
        kernel.GetModuleFileNameW.restype = ctypes.c_uint32
        buffer = ctypes.create_unicode_buffer(32768)
        length = kernel.GetModuleFileNameW(library._handle, buffer, len(buffer))
        self.assertGreater(length, 0)
        self.assertLess(length, len(buffer))
        resolved = Path(buffer.value).resolve(strict=True)
        self.assertEqual(resolved.name.casefold(), 'gdiplus.dll')
        self.assertTrue(resolved.is_relative_to(Path(os.environ['SystemRoot']).resolve(strict=True)))

    @unittest.skipUnless(os.name == 'nt', 'actual Windows common-controls system-loader probe')
    def test_comctl32_resolves_from_the_operating_system(self):
        import ctypes
        library = ctypes.WinDLL('comctl32.dll', winmode=0x00000800)
        self.assertIsNotNone(library.InitCommonControlsEx)
        kernel = ctypes.WinDLL('kernel32.dll', use_last_error=True)
        kernel.GetModuleFileNameW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32]
        kernel.GetModuleFileNameW.restype = ctypes.c_uint32
        buffer = ctypes.create_unicode_buffer(32768)
        length = kernel.GetModuleFileNameW(library._handle, buffer, len(buffer))
        self.assertGreater(length, 0)
        self.assertLess(length, len(buffer))
        resolved = Path(buffer.value).resolve(strict=True)
        self.assertEqual(resolved.name.casefold(), 'comctl32.dll')
        self.assertTrue(resolved.is_relative_to(Path(os.environ['SystemRoot']).resolve(strict=True)))

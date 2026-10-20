import shutil
import os
import tempfile
import unittest
from pathlib import Path

from build_runtime import BuildError
from relocate_windows import closure, pe_imports

BROWSER_SYSTEM_MODULES = {
    'bthprops.cpl': 'BluetoothFindFirstRadio',
    'd3d11.dll': 'D3D11CreateDevice',
    'd3d12.dll': 'D3D12CreateDevice',
    'dcomp.dll': 'DCompositionCreateDevice',
    'dhcpcsvc.dll': 'DhcpRequestParams',
    'dxgi.dll': 'CreateDXGIFactory2',
    'mf.dll': 'MFCreateMediaSession',
    'mfplat.dll': 'MFStartup',
    'mfreadwrite.dll': 'MFCreateSourceReaderFromURL',
    'mmdevapi.dll': 'ActivateAudioInterfaceAsync',
    'oleacc.dll': 'AccessibleObjectFromWindow',
    'pdh.dll': 'PdhOpenQueryW',
    'tbs.dll': 'Tbsi_Context_Create',
    'uiautomationcore.dll': 'UiaClientsAreListening',
    'winusb.dll': 'WinUsb_Initialize',
}


def pe(imports=True, machine=0x8664, delay=False):
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
    data[304:308] = (8192 if delay else 0).to_bytes(4, 'little')
    data[308:312] = (64 if delay else 0).to_bytes(4, 'little')
    return bytes(data)


class WindowsClosureTests(unittest.TestCase):
    def test_normal_and_delayed_imports_must_both_be_inspected(self):
        for normal in [False, True]:
            for mode in ['complete', 'missing-delay', 'missing-normal', 'unexpected-normal']:
                with self.subTest(normal=normal, mode=mode), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary).resolve()
                    node, addon = root / 'node.exe', root / 'addon.node'
                    node.write_bytes(pe()); addon.write_bytes(pe(normal, delay=True))

                    def inspect(path):
                        if path == node:
                            return 'DLL Name: KERNEL32.dll'
                        text = ''
                        if (normal and mode != 'missing-normal') or mode == 'unexpected-normal':
                            text += 'Import {\n  Name: KERNEL32.dll\n}\n'
                        if mode != 'missing-delay':
                            text += 'DelayImport {\n  Name: node.exe\n  Import {\n    Symbol: napi_create_function\n  }\n}\n'
                        return text

                    entries = {'node.exe': node, 'media/addon.node': addon}
                    invalid = mode == 'missing-delay' or (normal and mode == 'missing-normal') or (not normal and mode == 'unexpected-normal')
                    if invalid:
                        with self.assertRaisesRegex(BuildError, 'host_pe_imports_missing'):
                            closure(entries, [], root / 'output', inspect)
                    else:
                        report = closure(entries, [], root / 'output', inspect)
                        self.assertIn('node.exe', report['objects']['media/addon.node']['imports'])
                        self.assertEqual(report['objects']['media/addon.node']['delayImports'], ['node.exe'])

    def test_delayed_private_dependency_is_not_treated_as_system_supplied(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            addon, vendor = root / 'addon.node', root / 'vendor.dll'
            addon.write_bytes(pe(delay=True)); vendor.write_bytes(pe())

            def inspect(path):
                return ('Import {\n  Name: KERNEL32.dll\n}\nDelayImport {\n  Name: vendor.dll\n}\n'
                        if path == addon else 'DLL Name: KERNEL32.dll')

            report = closure({'addon.node': addon}, [root], root / 'output', inspect)
            self.assertEqual((root / 'output/bin/vendor.dll').read_bytes(), pe())
            vendor.unlink()
            with self.assertRaisesRegex(BuildError, 'host_pe_dependency_missing:vendor.dll'):
                closure({'addon.node': addon}, [root], root / 'missing-output', inspect)

    def test_addon_executable_import_requires_one_explicit_entry(self):
        for mode in ['approved', 'undeclared', 'ambiguous']:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                node, addon = root / 'Node.EXE', root / 'addon.node'
                node.write_bytes(pe()); addon.write_bytes(pe())
                entries = {'media/addon.node': addon}
                if mode != 'undeclared':
                    entries['runtime/Node.EXE'] = node
                if mode == 'ambiguous':
                    entries['other/node.exe'] = node

                def inspect(path):
                    return 'DLL Name: ' + ('node.exe' if path == addon else 'KERNEL32.dll')

                if mode != 'approved':
                    with self.assertRaisesRegex(BuildError, 'host_pe_executable_import_unapproved'):
                        closure(entries, [root], root / 'output', inspect)
                    continue
                report = closure(entries, [root], root / 'output', inspect)
                self.assertEqual(set(report['objects']), set(entries))
                self.assertEqual(report['objects']['media/addon.node']['imports'], ['node.exe'])
                self.assertEqual((root / 'output/runtime/Node.EXE').read_bytes(), pe())
                self.assertFalse((root / 'output/bin/node.exe').exists())

    def test_explicit_executable_import_still_requires_x64_pe(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            node, addon = root / 'node.exe', root / 'addon.node'
            node.write_bytes(pe(machine=0xaa64)); addon.write_bytes(pe())
            with self.assertRaisesRegex(BuildError, 'host_pe_header_unsupported'):
                closure({'node.exe': node, 'media/addon.node': addon}, [], root / 'output',
                        lambda path: 'DLL Name: node.exe' if path == addon else 'DLL Name: KERNEL32.dll')

    def test_browser_system_modules_stay_external(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            executable = root / 'browser.exe'
            executable.write_bytes(pe())
            for index, name in enumerate(BROWSER_SYSTEM_MODULES):
                with self.subTest(name=name):
                    report = closure({'browser.exe': executable}, [root], root / str(index),
                                     lambda _, name=name: 'DLL Name: ' + name.upper())
                    self.assertEqual(set(report['objects']), {'browser.exe'})
                    self.assertEqual(report['systemLibraries'], [name])
                    self.assertFalse((root / str(index) / 'bin').exists())

    def test_only_the_known_system_cpl_import_is_allowed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            executable = root / 'browser.exe'
            executable.write_bytes(pe(delay=True))
            (root / 'private.cpl').write_bytes(pe())
            normal = 'Import {\n  Name: KERNEL32.dll\n}\n'
            report = closure({'browser.exe': executable}, [root], root / 'system',
                             lambda _: normal + 'DelayImport {\n  Name: BTHPROPS.CPL\n}')
            self.assertEqual(report['objects']['browser.exe']['delayImports'], ['bthprops.cpl'])
            with self.assertRaisesRegex(BuildError, 'host_pe_dependency_invalid'):
                closure({'browser.exe': executable}, [root], root / 'private',
                        lambda _: normal + 'DelayImport {\n  Name: private.cpl\n}')

    def test_x64_headers_and_import_table_are_bounded(self):
        self.assertTrue(pe_imports(pe()))
        self.assertFalse(pe_imports(pe(False)))
        with self.assertRaisesRegex(BuildError, 'host_pe_delay_imports_unsupported'):
            pe_imports(pe(delay=True))
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
            imports = {'engine.exe': ['VENDOR.DLL', 'KERNEL32.dll', 'gdiplus.dll', 'COMCTL32.dll', 'CldApi.dll', 'ComBase.dll', 'AVICAP32.dll', 'CFGMGR32.dll'],
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
            self.assertIn('cldapi.dll', report['systemLibraries'])
            self.assertFalse((root / 'output/bin/cldapi.dll').exists())
            self.assertIn('combase.dll', report['systemLibraries'])
            self.assertFalse((root / 'output/bin/combase.dll').exists())
            for name in ['avicap32.dll', 'cfgmgr32.dll']:
                self.assertIn(name, report['systemLibraries'])
                self.assertFalse((root / 'output/bin'/name).exists())
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
    @unittest.skipUnless(os.name == 'nt', 'actual Windows desktop system-loader probe')
    def test_desktop_modules_resolve_from_the_operating_system(self):
        import ctypes
        kernel = ctypes.WinDLL('kernel32.dll', use_last_error=True)
        kernel.GetModuleFileNameW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32]
        kernel.GetModuleFileNameW.restype = ctypes.c_uint32
        for name, symbol in [('cldapi.dll', 'CfGetPlaceholderInfo'), ('combase.dll', 'RoGetAgileReference'),
                             ('avicap32.dll', 'capCreateCaptureWindowW'), ('cfgmgr32.dll', 'CM_Get_DevNode_Status'),
                             *BROWSER_SYSTEM_MODULES.items()]:
            with self.subTest(name=name):
                library = ctypes.WinDLL(name, winmode=0x00000800)
                self.assertIsNotNone(getattr(library, symbol))
                buffer = ctypes.create_unicode_buffer(32768)
                length = kernel.GetModuleFileNameW(library._handle, buffer, len(buffer))
                self.assertGreater(length, 0)
                self.assertLess(length, len(buffer))
                resolved = Path(buffer.value).resolve(strict=True)
                self.assertEqual(resolved.name.casefold(), name)
                self.assertTrue(resolved.is_relative_to(Path(os.environ['SystemRoot']).resolve(strict=True)))

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

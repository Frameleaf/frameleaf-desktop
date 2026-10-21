"""Qualify the real compiled per-user host without the CI runner's administrator groups."""
import argparse
from contextlib import ExitStack
import ctypes
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from windows_probe_process import run_probe

TEST = 'factory_signed_host_starts_and_restarts_through_compiled_authority'


def select_executable(receipt, root):
    if receipt.stat().st_size > 32 * 1024**2:
        raise ValueError('host_test_receipt_oversized')
    records = [json.loads(line) for line in receipt.read_text(encoding='utf-8-sig').splitlines() if line.strip()]
    artifacts = [r for r in records if r.get('reason') == 'compiler-artifact'
                 and r.get('target', {}).get('name') == 'host_runtime'
                 and r.get('target', {}).get('kind') == ['test']
                 and r.get('profile', {}).get('test') is True and r.get('executable')]
    if len(artifacts) != 1:
        raise ValueError('host_test_artifact_ambiguous')
    binary = Path(artifacts[0]['executable'])
    expected = (root / 'src-tauri/target/debug/deps').resolve()
    if (not binary.is_absolute() or binary.is_symlink() or not binary.is_file()
        or binary.resolve().parent != expected
        or not re.fullmatch(r'host_runtime-[a-f0-9]{16}\.exe', binary.name)):
        raise ValueError('host_test_executable_invalid')
    return binary.resolve()


def run_restricted(command, environment, cwd):
    if os.name != 'nt':
        raise OSError('restricted host qualification requires Windows')
    from ctypes import wintypes as w

    class SidAttributes(ctypes.Structure):
        _fields_ = [('sid', ctypes.c_void_p), ('attributes', w.DWORD)]

    class Startup(ctypes.Structure):
        _fields_ = [('cb', w.DWORD), ('reserved', w.LPWSTR), ('desktop', w.LPWSTR),
                    ('title', w.LPWSTR), ('x', w.DWORD), ('y', w.DWORD),
                    ('width', w.DWORD), ('height', w.DWORD), ('charsX', w.DWORD),
                    ('charsY', w.DWORD), ('fill', w.DWORD), ('flags', w.DWORD),
                    ('show', w.WORD), ('reservedSize', w.WORD), ('reservedBytes', ctypes.c_void_p),
                    ('stdin', w.HANDLE), ('stdout', w.HANDLE), ('stderr', w.HANDLE)]

    class Process(ctypes.Structure):
        _fields_ = [('process', w.HANDLE), ('thread', w.HANDLE), ('pid', w.DWORD), ('tid', w.DWORD)]

    class Trustee(ctypes.Structure):
        _fields_ = [('multiple', ctypes.c_void_p), ('operation', ctypes.c_int),
                    ('form', ctypes.c_int), ('kind', ctypes.c_int), ('sid', ctypes.c_void_p)]

    class Access(ctypes.Structure):
        _fields_ = [('mask', w.DWORD), ('mode', ctypes.c_int), ('inherit', w.DWORD), ('trustee', Trustee)]

    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    security = ctypes.WinDLL('advapi32', use_last_error=True)
    definitions = [
        (kernel, 'GetCurrentProcess', [], w.HANDLE),
        (kernel, 'GetStdHandle', [w.DWORD], w.HANDLE),
        (kernel, 'GetHandleInformation', [w.HANDLE, ctypes.POINTER(w.DWORD)], w.BOOL),
        (kernel, 'GetFileType', [w.HANDLE], w.DWORD),
        (kernel, 'CloseHandle', [w.HANDLE], w.BOOL),
        (kernel, 'LocalFree', [ctypes.c_void_p], ctypes.c_void_p),
        (kernel, 'ResumeThread', [w.HANDLE], w.DWORD),
        (kernel, 'WaitForSingleObject', [w.HANDLE, w.DWORD], w.DWORD),
        (kernel, 'GetExitCodeProcess', [w.HANDLE, ctypes.POINTER(w.DWORD)], w.BOOL),
        (kernel, 'TerminateProcess', [w.HANDLE, w.UINT], w.BOOL),
        (kernel, 'IsProcessInJob', [w.HANDLE, w.HANDLE, ctypes.POINTER(w.BOOL)], w.BOOL),
        (security, 'OpenProcessToken', [w.HANDLE, w.DWORD, ctypes.POINTER(w.HANDLE)], w.BOOL),
        (security, 'CreateRestrictedToken', [w.HANDLE, w.DWORD, w.DWORD, ctypes.POINTER(SidAttributes), w.DWORD, ctypes.c_void_p, w.DWORD, ctypes.c_void_p, ctypes.POINTER(w.HANDLE)], w.BOOL),
        (security, 'DuplicateToken', [w.HANDLE, ctypes.c_int, ctypes.POINTER(w.HANDLE)], w.BOOL),
        (security, 'CheckTokenMembership', [w.HANDLE, ctypes.c_void_p, ctypes.POINTER(w.BOOL)], w.BOOL),
        (security, 'GetTokenInformation', [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD, ctypes.POINTER(w.DWORD)], w.BOOL),
        (security, 'SetTokenInformation', [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD], w.BOOL),
        (security, 'SetEntriesInAclW', [w.ULONG, ctypes.POINTER(Access), ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)], w.DWORD),
        (security, 'GetLengthSid', [ctypes.c_void_p], w.DWORD),
        (security, 'IsValidSid', [ctypes.c_void_p], w.BOOL),
        (security, 'ConvertStringSidToSidW', [w.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)], w.BOOL),
        (security, 'CreateProcessAsUserW', [w.HANDLE, w.LPCWSTR, w.LPWSTR, ctypes.c_void_p, ctypes.c_void_p, w.BOOL, w.DWORD, ctypes.c_void_p, w.LPCWSTR, ctypes.POINTER(Startup), ctypes.POINTER(Process)], w.BOOL),
    ]
    for library, name, arguments, result in definitions:
        api = getattr(library, name)
        api.argtypes, api.restype = arguments, result

    def check(success):
        if not success:
            raise ctypes.WinError(ctypes.get_last_error())

    def token_info(token, kind):
        size = w.DWORD()
        security.GetTokenInformation(token, kind, None, 0, ctypes.byref(size))
        if not 0 < size.value <= 65536:
            raise RuntimeError('host_test_token_information_invalid')
        value = ctypes.create_string_buffer(size.value)
        check(security.GetTokenInformation(token, kind, value, len(value), ctypes.byref(size)))
        return value

    def sid_bytes(value):
        sid = SidAttributes.from_buffer(value).sid
        check(security.IsValidSid(sid))
        return ctypes.string_at(sid, security.GetLengthSid(sid))

    with ExitStack() as owner:
        def own(handle):
            owner.callback(lambda: check(kernel.CloseHandle(handle)))
            return handle

        member = w.BOOL()
        check(kernel.IsProcessInJob(kernel.GetCurrentProcess(), None, ctypes.byref(member)))
        if not member.value:
            raise RuntimeError('host_test_job_owner_required')
        original = w.HANDLE()
        check(security.OpenProcessToken(kernel.GetCurrentProcess(), 0x2008b, ctypes.byref(original)))
        own(original)
        sids = []
        for text in ['S-1-5-32-544', 'S-1-5-32-547']:
            sid = ctypes.c_void_p()
            check(security.ConvertStringSidToSidW(text, ctypes.byref(sid)))
            owner.callback(lambda pointer=sid: check(not kernel.LocalFree(pointer)))
            sids.append(sid)
        disabled = (SidAttributes * 2)(*(SidAttributes(sid, 0) for sid in sids))
        token = w.HANDLE()
        check(security.CreateRestrictedToken(original, 1, 2, disabled, 0, None, 0, None, ctypes.byref(token)))
        own(token)
        # Keep new kernel objects accessible to the user after disabling administrator groups.
        user_info = token_info(token, 1)
        default_info = token_info(token, 6)
        old_acl = ctypes.c_void_p.from_buffer(default_info).value
        if not old_acl:
            raise RuntimeError('host_test_default_acl_missing')
        access = Access(0x10000000, 1, 1, Trustee(None, 0, 0, 1, SidAttributes.from_buffer(user_info).sid))
        new_acl = ctypes.c_void_p()
        status = security.SetEntriesInAclW(1, ctypes.byref(access), old_acl, ctypes.byref(new_acl))
        if status:
            raise ctypes.WinError(status)
        owner.callback(lambda: check(not kernel.LocalFree(new_acl)))

        def acl_bytes(pointer):
            if not pointer:
                raise RuntimeError('host_test_default_acl_missing')
            header = ctypes.string_at(pointer, 8)
            size = int.from_bytes(header[2:4], 'little')
            if not 8 <= size <= 65535:
                raise RuntimeError('host_test_default_acl_invalid')
            return ctypes.string_at(pointer, size)

        expected_acl = acl_bytes(new_acl)
        check(security.SetTokenInformation(token, 6, ctypes.byref(new_acl), ctypes.sizeof(new_acl)))
        checked_default = token_info(token, 6)
        if acl_bytes(ctypes.c_void_p.from_buffer(checked_default).value) != expected_acl:
            raise RuntimeError('host_test_default_acl_changed')

        def facts(candidate):
            impersonation = w.HANDLE()
            check(security.DuplicateToken(candidate, 2, ctypes.byref(impersonation)))
            own(impersonation)
            enabled = []
            for sid in sids:
                check(security.CheckTokenMembership(impersonation, sid, ctypes.byref(member)))
                enabled.append(bool(member.value))
            same = sid_bytes(token_info(original, 1)) == sid_bytes(token_info(candidate, 1))
            if not same or any(enabled):
                raise RuntimeError('host_test_token_not_restricted')
            candidate_default = token_info(candidate, 6)
            if acl_bytes(ctypes.c_void_p.from_buffer(candidate_default).value) != expected_acl:
                raise RuntimeError('host_test_child_default_acl_changed')
            integrity = sid_bytes(token_info(candidate, 25))
            return {'sameUser': same, 'administratorsEnabled': enabled[0],
                    'powerUsersEnabled': enabled[1], 'integrityRid': int.from_bytes(integrity[-4:], 'little'),
                    'defaultDaclUserAccessAdded': True,
                    'elevated': bool(int.from_bytes(token_info(candidate, 20).raw[:4], 'little')),
                    'installedUserAcceptance': False}

        facts(token)
        startup = Startup()
        startup.cb, startup.flags = ctypes.sizeof(Startup), 0x100
        startup.stdin, startup.stdout, startup.stderr = [kernel.GetStdHandle(n & 0xffffffff) for n in [-10, -11, -12]]
        environment_block = ctypes.create_unicode_buffer('\0'.join(f'{k}={v}' for k, v in sorted(environment.items())) + '\0\0')
        process = Process()
        command_line = ctypes.create_unicode_buffer(subprocess.list2cmdline(command))
        check(security.CreateProcessAsUserW(token, command[0], command_line, None, None, True,
                                           0x08000404, environment_block, str(cwd), ctypes.byref(startup), ctypes.byref(process)))
        own(process.process)
        own(process.thread)
        completed = False

        def stop_unfinished():
            if not completed:
                check(kernel.TerminateProcess(process.process, 1))
                if kernel.WaitForSingleObject(process.process, 5000) != 0:
                    raise RuntimeError('host_test_shutdown_unconfirmed')

        owner.callback(stop_unfinished)
        check(kernel.IsProcessInJob(process.process, None, ctypes.byref(member)))
        if not member.value:
            raise RuntimeError('host_test_child_job_missing')
        child_token = w.HANDLE()
        check(security.OpenProcessToken(process.process, 0x000a, ctypes.byref(child_token)))
        own(child_token)
        observed = facts(child_token)
        inherited = []
        for handle in [startup.stdin, startup.stdout, startup.stderr]:
            flags = w.DWORD()
            check(kernel.GetHandleInformation(handle, ctypes.byref(flags)))
            inherited.append(bool(flags.value & 1))
        observed['standardHandlesInheritable'] = inherited
        observed['standardHandleTypes'] = [kernel.GetFileType(handle) for handle in [startup.stdin, startup.stdout, startup.stderr]]
        print(json.dumps(observed), flush=True)
        resumed = kernel.ResumeThread(process.thread)
        if resumed == 0xffffffff:
            raise ctypes.WinError(ctypes.get_last_error())
        waited = kernel.WaitForSingleObject(process.process, 900000)
        if waited != 0:
            raise RuntimeError('host_test_wait_failed')
        completed = True
        code = w.DWORD()
        check(kernel.GetExitCodeProcess(process.process, ctypes.byref(code)))
        print(json.dumps({'state':'restricted-child-exited', 'resumeCount':resumed,
                          'waitResult':waited, 'rawExitCode':code.value}), flush=True)
        return code.value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-receipts', type=Path, required=True)
    parser.add_argument('--log', type=Path, required=True)
    args = parser.parse_args()
    binary = select_executable(args.build_receipts, Path.cwd())
    environment = {key: os.environ[key] for key in ['SystemRoot', 'FRAMELEAF_TEST_HOST_CANDIDATE', 'FRAMELEAF_TEST_HOST_STATE']}
    code = """import json,sys
assert sys.stdin.buffer.read(1)==b'1'
from qualify_windows_user_host import run_restricted
sys.exit(run_restricted(json.loads(sys.argv[1]),json.loads(sys.argv[2]),sys.argv[3]))
"""
    result = run_probe([sys.executable, '-c', code,
                        json.dumps([str(binary), '--exact', TEST, '--ignored', '--nocapture']),
                        json.dumps(environment), str(Path.cwd())],
                       cwd=Path(__file__).resolve().parent, timeout=920)
    if len(result.stdout) + len(result.stderr) > 1024**2:
        raise RuntimeError('host_test_output_oversized')
    args.log.write_text(result.stdout + result.stderr, encoding='utf-8')
    print(result.stdout, end='')
    print(result.stderr, end='', file=sys.stderr)
    return result.returncode


if __name__ == '__main__':
    sys.exit(main())

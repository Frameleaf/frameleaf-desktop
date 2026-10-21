"""Run a stdin-gated diagnostic inside an owned Windows process tree."""
import ctypes
import os
import subprocess
import time


def run_probe(command, *, timeout, cwd=None):
    """The trusted child must read byte '1' from stdin before spawning children."""
    if os.name != 'nt':
        raise OSError('Windows probe ownership requires Windows')
    from ctypes import wintypes

    class BasicLimits(ctypes.Structure):
        _fields_ = [('times', ctypes.c_int64 * 2), ('flags', wintypes.DWORD),
                    ('minimum', ctypes.c_size_t), ('maximum', ctypes.c_size_t),
                    ('active', wintypes.DWORD), ('affinity', ctypes.c_size_t),
                    ('priority', wintypes.DWORD), ('scheduling', wintypes.DWORD)]

    class ExtendedLimits(ctypes.Structure):
        _fields_ = [('basic', BasicLimits), ('io', ctypes.c_uint64 * 6),
                    ('memory', ctypes.c_size_t * 4)]

    class Accounting(ctypes.Structure):
        _fields_ = [('times', ctypes.c_int64 * 4), ('faults', wintypes.DWORD),
                    ('total', wintypes.DWORD), ('active', wintypes.DWORD),
                    ('terminated', wintypes.DWORD)]

    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    signatures = {
        'CreateJobObjectW': ([ctypes.c_void_p, wintypes.LPCWSTR], wintypes.HANDLE),
        'SetInformationJobObject': ([wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD], wintypes.BOOL),
        'AssignProcessToJobObject': ([wintypes.HANDLE, wintypes.HANDLE], wintypes.BOOL),
        'QueryInformationJobObject': ([wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p], wintypes.BOOL),
        'TerminateJobObject': ([wintypes.HANDLE, wintypes.UINT], wintypes.BOOL),
        'CloseHandle': ([wintypes.HANDLE], wintypes.BOOL),
    }
    for name, (arguments, result) in signatures.items():
        function = getattr(kernel, name)
        function.argtypes, function.restype = arguments, result
    job = kernel.CreateJobObjectW(None, None)
    if not job:
        raise ctypes.WinError(ctypes.get_last_error())
    process = None
    assigned = False
    try:
        limits = ExtendedLimits()
        limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not kernel.SetInformationJobObject(job, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            raise ctypes.WinError(ctypes.get_last_error())
        process = subprocess.Popen(command, cwd=cwd, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   creationflags=subprocess.CREATE_NO_WINDOW)
        # CPython owns this process handle; do not reopen a possibly recycled PID.
        if not kernel.AssignProcessToJobObject(job, int(process._handle)):
            raise ctypes.WinError(ctypes.get_last_error())
        assigned = True
        stdout, stderr = process.communicate(b'1', timeout=timeout)
        return subprocess.CompletedProcess(command, process.returncode,
                                           stdout.decode('utf-8'), stderr.decode('utf-8'))
    finally:
        try:
            if assigned:
                if not kernel.TerminateJobObject(job, 1):
                    raise ctypes.WinError(ctypes.get_last_error())
                deadline = time.monotonic() + 5
                while True:
                    accounting = Accounting()
                    if not kernel.QueryInformationJobObject(job, 1, ctypes.byref(accounting), ctypes.sizeof(accounting), None):
                        raise ctypes.WinError(ctypes.get_last_error())
                    if accounting.active == 0:
                        break
                    if time.monotonic() >= deadline:
                        raise RuntimeError('probe_process_shutdown_unconfirmed')
                    time.sleep(0.02)
            elif process is not None:
                process.kill()
            if process is not None:
                process.communicate(timeout=5)
        finally:
            if not kernel.CloseHandle(job):
                raise ctypes.WinError(ctypes.get_last_error())

"""Create private build directories readable by PostgreSQL's restricted user token."""
import ctypes
import csv
import os
from pathlib import Path
import re
import subprocess


def create_private_directory(path):
    path = Path(path)
    if os.name == 'nt':
        _windows_private_directory(path)
    else:
        path.mkdir(mode=0o700)


def _windows_private_directory(path):
    """Create-only state with an inheritable user ACE, independent of token owner rights."""
    from ctypes import wintypes
    path = Path(path)
    if not path.is_absolute():
        raise ValueError('private_directory_not_absolute')
    identity = subprocess.check_output(
        [str(Path(os.environ['SystemRoot']) / 'System32/whoami.exe'), '/user', '/fo', 'csv', '/nh'],
        text=True, timeout=10)
    rows = list(csv.reader(identity.splitlines()))
    if len(rows) != 1 or len(rows[0]) != 2 or not re.fullmatch(r'S-1-(?:5-21|12-1)-(?:[0-9]+-){3}[0-9]+', rows[0][1]):
        raise ValueError('private_user_identity_invalid')
    sid = rows[0][1]

    class Attributes(ctypes.Structure):
        _fields_ = [('length', wintypes.DWORD), ('descriptor', ctypes.c_void_p),
                    ('inherit', wintypes.BOOL)]

    security = ctypes.WinDLL('advapi32', use_last_error=True)
    security.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    security.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateDirectoryW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(Attributes)]
    kernel.CreateDirectoryW.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    descriptor = ctypes.c_void_p()
    sddl = f'O:{sid}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{sid})'
    if not security.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(descriptor), None):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        attributes = Attributes(ctypes.sizeof(Attributes), descriptor, False)
        if not kernel.CreateDirectoryW(str(path), ctypes.byref(attributes)):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        if kernel.LocalFree(descriptor):
            raise ctypes.WinError(ctypes.get_last_error())


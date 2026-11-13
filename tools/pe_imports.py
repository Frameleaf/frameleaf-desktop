"""Check, without loading anything, that a Windows library's imports can be satisfied.

Used by `smoke_accelerated_runtime.py` on Windows. Loading a provider library there fails with
one of two codes that name nothing: 126 (a library it needs is absent) or 127 (a library it needs
is present but lacks a function it imports). This reads the import table of the library and the
export tables of what it imports, so the missing library or function is named.
"""

import struct
from pathlib import Path


class PortableExecutable:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.data = data = path.read_bytes()
        if data[:2] != b"MZ":
            raise ValueError(f"not a Windows library: {path}")
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe : pe + 4] != b"PE\0\0":
            raise ValueError(f"not a Windows library: {path}")
        sections, optional_size = struct.unpack_from("<H", data, pe + 6)[0], struct.unpack_from("<H", data, pe + 20)[0]
        optional = pe + 24
        magic = struct.unpack_from("<H", data, optional)[0]
        if magic not in (0x10B, 0x20B):
            raise ValueError(f"unknown optional header in {path}")
        self.wide = magic == 0x20B
        directories = optional + (112 if self.wide else 96)
        count = struct.unpack_from("<I", data, directories - 4)[0]
        self.directories = [struct.unpack_from("<II", data, directories + 8 * index) for index in range(min(count, 16))]
        table = optional + optional_size
        self.sections = []
        for index in range(sections):
            virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from("<IIII", data, table + 40 * index + 8)
            self.sections.append((virtual_address, max(virtual_size, raw_size), raw_offset))

    def offset(self, rva: int) -> int:
        for address, size, raw in self.sections:
            if address <= rva < address + size:
                return rva - address + raw
        raise ValueError(f"address {rva:#x} is outside every section of {self.path}")

    def text(self, rva: int) -> str:
        start = self.offset(rva)
        return self.data[start : self.data.index(b"\0", start)].decode("ascii", "replace")

    def exports(self) -> set[str]:
        rva, size = self.directories[0]
        if not rva or not size:
            return set()
        base = self.offset(rva)
        names, name_table = struct.unpack_from("<I", self.data, base + 24)[0], struct.unpack_from("<I", self.data, base + 32)[0]
        table = self.offset(name_table) if names else 0
        return {self.text(struct.unpack_from("<I", self.data, table + 4 * index)[0]) for index in range(names)}

    def imports(self) -> dict[str, list[str]]:
        """Library name -> the functions imported from it by name (ordinal imports are left out)."""
        rva, size = self.directories[1]
        result: dict[str, list[str]] = {}
        if not rva or not size:
            return result
        entry = self.offset(rva)
        width, flag = (8, 1 << 63) if self.wide else (4, 1 << 31)
        while True:
            lookup, _, _, name, thunk = struct.unpack_from("<IIIII", self.data, entry)
            if not name:
                break
            functions = result.setdefault(self.text(name), [])
            cursor = self.offset(lookup or thunk)
            while True:
                value = struct.unpack_from("<Q" if self.wide else "<I", self.data, cursor)[0]
                if not value:
                    break
                if not value & flag:
                    functions.append(self.text(value + 2))
                cursor += width
            entry += 20
        return result

    def delayed(self) -> list[str]:
        """Libraries loaded only when first used (their absence does not stop this one loading)."""
        rva, size = self.directories[13] if len(self.directories) > 13 else (0, 0)
        result = []
        if not rva or not size:
            return result
        entry = self.offset(rva)
        while True:
            _, name = struct.unpack_from("<II", self.data, entry)
            if not name:
                break
            result.append(self.text(name))
            entry += 32
        return result


def unsatisfied(library: Path, folders: list[Path]) -> dict[str, list[str] | None]:
    """What `library` imports that the folders cannot give it: a library name mapped to None when
    no folder has it, or to the functions it lacks. Windows' own API-set names are not files."""
    problems: dict[str, list[str] | None] = {}
    for name, functions in PortableExecutable(library).imports().items():
        if name.lower().startswith(("api-ms-win-", "ext-ms-")):
            continue
        found = next((folder / name for folder in folders if (folder / name).is_file()), None)
        if found is None:
            # Windows file names are not case sensitive.
            lowered = name.lower()
            found = next(
                (item for folder in folders if folder.is_dir() for item in folder.iterdir() if item.name.lower() == lowered),
                None,
            )
        if found is None:
            problems[name] = None
            continue
        missing = sorted(set(functions) - PortableExecutable(found).exports())
        if missing:
            problems[name] = missing
    return problems

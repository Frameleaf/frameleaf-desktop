"""Judge what the dynamic linker says about the CUDA provider library of a built pack.

Used by `smoke_accelerated_runtime.py`; kept apart so the rule is tested without a pack.
"""

from pathlib import Path

DRIVER = "libcuda.so.1"


def check_linked(listing: str, pack: Path, driver_present: bool) -> list[str]:
    """Check `ldd` output for the provider library; return the sorted names it resolved.

    Every NVIDIA library it links against must resolve inside the pack, except the driver's own
    library, which belongs to the NVIDIA driver installed on the computer: with a driver it must
    resolve (from wherever the system has it); without one it is the only library that may be
    missing. Anything else missing, or an NVIDIA library taken from outside the pack, is an error.
    """
    resolved: dict[str, str] = {}
    missing: list[str] = []
    for line in listing.splitlines():
        parts = line.split()
        if "=>" not in parts:
            continue
        if "not found" in line:
            missing.append(parts[0])
        elif len(parts) >= 3:
            resolved[parts[0]] = parts[2]
    expected = [] if driver_present else [DRIVER]
    if sorted(missing) != expected:
        raise ValueError(f"unresolved libraries {sorted(missing)}, expected {expected}")
    if driver_present and DRIVER not in resolved:
        raise ValueError(f"{DRIVER} is not linked although a driver is present")
    nvidia = {
        name: where
        for name, where in resolved.items()
        if name.startswith(("libcu", "libnv")) and name != DRIVER
    }
    if not any(name.startswith("libcublas") for name in nvidia):
        raise ValueError("the provider library does not link cuBLAS from the pack")
    root = pack.resolve()
    for name, where in nvidia.items():
        if not Path(where).resolve().is_relative_to(root):
            raise ValueError(f"{name} resolves outside the pack: {where}")
    return sorted(resolved)

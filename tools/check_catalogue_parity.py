"""Fail when Desktop's compiled model catalogue differs from a server catalogue.

    git -C ../immich show origin/main:server/resources/desktop/model-catalogue.json \\
      | python3 tools/check_catalogue_parity.py -

Profiles are matched by (workload, modelName, runtimeSourceRevision, spec.provider) and
compared canonically: key order and the spelling of whole numbers (181 or 181.0) do not
matter, every value and the order of the profiles do.
"""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUNTIME_FIELDS = ("python", "uv", "extra", "provider")


def canonical(value):
    if isinstance(value, dict):
        return {key: canonical(item) for key, item in sorted(value.items())}
    if isinstance(value, list):
        return [canonical(item) for item in value]
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


def profile_key(profile):
    return (
        profile["workload"],
        profile["modelName"],
        profile["runtimeSourceRevision"],
        profile["spec"]["provider"],
    )


def grouped(catalogue):
    groups = {}
    for profile in catalogue["profiles"]:
        groups.setdefault(profile_key(profile), []).append(
            json.dumps(canonical(profile), sort_keys=True)
        )
    return {key: sorted(items) for key, items in groups.items()}


def catalogue_differences(desktop, server):
    problems = []
    for field in ("schemaVersion", "epoch"):
        if desktop.get(field) != server.get(field):
            problems.append(
                f"{field}: desktop {desktop.get(field)!r}, server {server.get(field)!r}"
            )
    ours, theirs = grouped(desktop), grouped(server)
    label = lambda key: f"{key[0]} {key[1]} @{key[2][:8]} {key[3]}"
    for key in sorted(set(theirs) - set(ours)):
        problems.append(f"server only: {label(key)} ({len(theirs[key])})")
    for key in sorted(set(ours) - set(theirs)):
        problems.append(f"desktop only: {label(key)} ({len(ours[key])})")
    for key in sorted(set(ours) & set(theirs)):
        if ours[key] != theirs[key]:
            problems.append(f"differs: {label(key)}")
    if not problems and canonical(desktop["profiles"]) != canonical(server["profiles"]):
        problems.append("profile order differs")
    return problems


def runtime_differences(desktop, server):
    """Every runtime Desktop builds must be one the server approves, on the same targets."""
    problems = []
    for name, profile in sorted(desktop["profiles"].items()):
        approved = server["profiles"].get(name)
        if approved is None:
            problems.append(f"runtime profile {name}: not approved by the server")
            continue
        for field in RUNTIME_FIELDS:
            if profile.get(field) != approved.get(field):
                problems.append(
                    f"runtime profile {name}: {field} desktop {profile.get(field)!r}, "
                    f"server {approved.get(field)!r}"
                )
        extra = sorted(set(profile["targets"]) - set(approved["targets"]))
        if extra:
            problems.append(f"runtime profile {name}: targets not approved: {extra}")
    return problems


def load(path):
    return json.load(sys.stdin) if path == "-" else json.loads(Path(path).read_text())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("server_catalogue", help="server model-catalogue.json, or - for stdin")
    parser.add_argument("--desktop", default=ROOT / "runtime/model-catalogue.json")
    parser.add_argument(
        "--runtime-profiles", help="also check against the server's runtime-profiles.json"
    )
    args = parser.parse_args(argv)
    desktop, server = load(args.desktop), load(args.server_catalogue)
    problems = catalogue_differences(desktop, server)
    if args.runtime_profiles:
        ours = load(ROOT / "runtime/profiles.json")
        theirs = load(args.runtime_profiles)
        problems += runtime_differences(ours, theirs)
        for name in sorted(set(theirs["profiles"]) - set(ours["profiles"])):
            print(f"catalogue only (Desktop builds no {name} runtime)")
    for problem in problems:
        print(problem, file=sys.stderr)
    if problems:
        print(f"catalogue parity FAILED ({len(problems)})", file=sys.stderr)
        return 1
    print(f"catalogue parity ok: epoch {desktop['epoch']}, {len(desktop['profiles'])} profiles")
    return 0


if __name__ == "__main__":
    sys.exit(main())

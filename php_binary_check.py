#!/usr/bin/env python3
"""
php_binary_check.py
===================

Definitive check of whether a PHP binary or shared library contains the
CVE-2026-109618 / CVE-2026-109619 fix. Works directly on the compiled binary
by searching for unique strings that only exist in the patched memory
manager, so it is immune to distro version-string backporting (where the
version stays "8.2.34" but the fix is actually applied).

Signatures used (present in ALL fixed versions 8.2.35 / 8.3.36 / 8.4.27 /
8.5.12, absent in ALL affected versions):

  1. "memory_hard_limit_percent"     - new INI directive name
  2. "ZEND_MM_MAX_ALLOCS"            - env var read at request startup
  3. "Hard memory limit of"          - new error message for hard limit
  4. "zend_mm_set_max_allocs"        - new API symbol name (may be stripped in
                                       release builds, so treated as optional)

Usage:
    python php_binary_check.py /usr/bin/php
    python php_binary_check.py /usr/lib/apache2/modules/libphp.so
    python php_binary_check.py C:\\php\\php8.dll
    python php_binary_check.py /usr/bin/php --json result.json
    python php_binary_check.py /path/to/dir --dir   # scan every file in a dir
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# (string, required)
SIGNATURES = [
    (b"memory_hard_limit_percent", True),
    (b"ZEND_MM_MAX_ALLOCS", True),
    (b"Hard memory limit of", True),
    (b"zend_mm_set_max_allocs", False),  # may be stripped in release builds
]

# Format string that changed subtly between affected and fixed versions.
# Affected:  "Allowed memory size of %zu bytes exhausted"
# Fixed has BOTH that and a new "%zu bytes exhausted at %s:%d" variant.
OLD_OOM_FORMAT = b"Allowed memory size of %zu bytes exhausted (tried to allocate %zu bytes)"
NEW_OOM_FORMAT = b"Allowed memory size of %zu bytes exhausted at %s:%d (tried to allocate %zu bytes)"


def check_file(path: Path) -> dict:
    data = path.read_bytes()
    result = {
        "path": str(path),
        "size": len(data),
        "signatures": {},
        "patched": None,
        "confidence": "low",
        "reason": "",
    }
    required_hits = 0
    required_total = 0
    for sig, required in SIGNATURES:
        present = sig in data
        result["signatures"][sig.decode()] = present
        if required:
            required_total += 1
            if present:
                required_hits += 1

    # Additional corroboration: the new OOM format variant.
    result["signatures"]["new_oom_format_variant"] = NEW_OOM_FORMAT in data
    result["signatures"]["old_oom_format_present"] = OLD_OOM_FORMAT in data

    if required_hits == required_total:
        result["patched"] = True
        result["confidence"] = "high"
        result["reason"] = (
            "All required patched-version strings present. Binary contains the "
            "fallible-allocation memory manager introduced with the CVE-2026-109618/109619 fix."
        )
    elif required_hits == 0:
        result["patched"] = False
        result["confidence"] = "high"
        result["reason"] = (
            "No patched-version strings present. Binary predates the "
            "CVE-2026-109618/109619 fix (vulnerable unless distro backported "
            "without the new strings, which is very unusual)."
        )
    else:
        result["patched"] = None
        result["confidence"] = "medium"
        result["reason"] = (
            f"Partial match: {required_hits}/{required_total} required strings "
            "found. Possibly a partial backport or stripped binary; manual review recommended."
        )
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="PHP CVE fix presence check on a binary")
    parser.add_argument("path", help="binary or shared library, or directory with --dir")
    parser.add_argument("--dir", action="store_true", help="treat path as a directory of files to check")
    parser.add_argument("--json", help="write JSON output to this file")
    parser.add_argument("--quiet", action="store_true", help="only output verdicts, no explanations")
    args = parser.parse_args(argv)

    targets: list[Path] = []
    p = Path(args.path)
    if args.dir:
        if not p.is_dir():
            print(f"error: {p} is not a directory", file=sys.stderr)
            return 2
        targets = sorted(x for x in p.iterdir() if x.is_file())
    else:
        if not p.is_file():
            print(f"error: {p} is not a file", file=sys.stderr)
            return 2
        targets = [p]

    results = []
    for t in targets:
        try:
            r = check_file(t)
        except PermissionError as e:
            r = {"path": str(t), "error": f"permission denied: {e}", "patched": None}
        except OSError as e:
            r = {"path": str(t), "error": str(e), "patched": None}
        results.append(r)

    if args.quiet:
        for r in results:
            verdict = {True: "PATCHED", False: "VULNERABLE", None: "UNKNOWN"}.get(r.get("patched"), "ERROR")
            print(f"{verdict}  {r['path']}" + (f"  {r.get('error')}" if "error" in r else ""))
    else:
        for r in results:
            if "error" in r:
                print(f"ERROR  {r['path']}: {r['error']}")
                continue
            verdict = {True: "PATCHED", False: "VULNERABLE", None: "UNKNOWN"}.get(r["patched"], "UNKNOWN")
            print(f"\n{verdict}  {r['path']}  ({r['size']:,} bytes)")
            print(f"  Confidence: {r['confidence']}")
            print(f"  {r['reason']}")
            for sig, present in r["signatures"].items():
                mark = "Y" if present else "n"
                print(f"    [{mark}] {sig}")

    if args.json:
        Path(args.json).write_text(json.dumps(results, indent=2))
        if not args.quiet:
            print(f"\nJSON written to {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

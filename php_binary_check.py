#!/usr/bin/env python3
"""
php_binary_check.py
===================

Checks a PHP binary or shared library for strings introduced by the new OOM
memory manager. These strings are strong corroborating evidence for the
CVE-2026-109618 fix family, but do not independently prove that every
CVE-2026-109619 state-reset change was backported.

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
import re
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

PHP_FILENAME_RE = re.compile(
    r"(?i)(?:^|[-_.])(?:php(?:\d+(?:\.\d+)?)?(?:-?fpm|-?cgi)?|"
    r"libphp\d*(?:\.\d+)?|lsphp\d*|frankenphp|php\d*\.dll)(?:[-_.]|$)"
)
EXECUTABLE_MAGICS = (
    b"\x7fELF",  # ELF
    b"MZ",       # PE/COFF
    b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",  # Mach-O 32-bit
    b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",  # Mach-O 64-bit
)


def _is_executable_format(data: bytes) -> bool:
    return any(data.startswith(magic) for magic in EXECUTABLE_MAGICS)


def _is_php_runtime(path: Path, data: bytes) -> bool:
    """Reject arbitrary files before interpreting fix strings.

    Names are only a hint: a supported executable format and either a
    PHP-runtime filename or characteristic runtime data are required.
    """
    if not _is_executable_format(data):
        return False
    name_hint = bool(PHP_FILENAME_RE.search(path.name))
    runtime_markers = (
        b"Zend Engine",
        b"PHP Version",
        b"php.ini",
        b"PHPAPI",
        b"PHP Extension",
    )
    return name_hint or any(marker in data for marker in runtime_markers)


def check_file(path: Path) -> dict:
    data = path.read_bytes()
    result = {
        "path": str(path),
        "size": len(data),
        "applicable": False,
        "signatures": {},
        "oom_fix_signatures": None,
        "patched": None,
        "confidence": "low",
        "reason": "",
    }
    if not _is_php_runtime(path, data):
        result["verdict"] = "NOT_PHP_RUNTIME"
        result["reason"] = "File is not an identifiable PHP executable or runtime library"
        return result

    result["applicable"] = True
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
        result["oom_fix_signatures"] = True
        result["verdict"] = "OOM_FIX_SIGNATURES_PRESENT"
        result["confidence"] = "high"
        result["reason"] = (
            "All required OOM-patch strings are present. This strongly supports "
            "the CVE-2026-109618 fix family, but complete dual-CVE status still "
            "requires upstream or vendor build provenance."
        )
    elif required_hits == 0:
        result["oom_fix_signatures"] = False
        result["verdict"] = "OOM_FIX_SIGNATURES_ABSENT"
        result["confidence"] = "medium"
        result["reason"] = (
            "No OOM-patch strings are present. This supports an affected build, "
            "but unusual compile options or a differently structured vendor "
            "backport require package/source provenance before a final verdict."
        )
    else:
        result["verdict"] = "PARTIAL_OOM_FIX_SIGNATURES"
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
            r = {"path": str(t), "error": f"permission denied: {e}", "patched": None, "verdict": "ERROR"}
        except OSError as e:
            r = {"path": str(t), "error": str(e), "patched": None, "verdict": "ERROR"}
        results.append(r)

    if args.quiet:
        for r in results:
            verdict = r.get("verdict", "ERROR")
            print(f"{verdict}  {r['path']}" + (f"  {r.get('error')}" if "error" in r else ""))
    else:
        for r in results:
            if "error" in r:
                print(f"ERROR  {r['path']}: {r['error']}")
                continue
            verdict = r.get("verdict", "UNKNOWN")
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
    if any(r.get("verdict") == "OOM_FIX_SIGNATURES_ABSENT" for r in results):
        return 2
    if any(r.get("verdict") in {"PARTIAL_OOM_FIX_SIGNATURES", "ERROR"} for r in results):
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())

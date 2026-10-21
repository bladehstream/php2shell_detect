#!/usr/bin/env python3
"""
php_cve_audit_local.py
======================

Local audit for CVE-2026-109618 / CVE-2026-109619 ("PHP2Shell").

Inspects the current host for PHP installations and running processes that are
below the fixed versions for these CVEs. Read-only: does not modify anything.

Usage:
    python php_cve_audit_local.py
    python php_cve_audit_local.py --json out.json --csv out.csv
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

CVE_IDS = ("CVE-2026-109618", "CVE-2026-109619")

FIXED_VERSIONS = {
    (8, 2): "8.2.35",
    (8, 3): "8.3.36",
    (8, 4): "8.4.27",
    (8, 5): "8.5.12",
}

VERSION_RE = re.compile(r"(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)(?:[-.]?(?P<suffix>[A-Za-z0-9]+))?")

# Strings present in every fixed build (8.2.35/8.3.36/8.4.27/8.5.12) and absent
# in every affected build. Derived by diffing the official php-src tarballs;
# see php2shell-scanner/README.md section "Ground-truth binary signatures".
BINARY_PATCH_SIGNATURES = [
    b"memory_hard_limit_percent",
    b"ZEND_MM_MAX_ALLOCS",
    b"Hard memory limit of",
]


@dataclass
class AuditResult:
    source: str
    php_version: Optional[str]
    path: str
    vulnerable: Optional[bool]
    reason: str
    cves: list = field(default_factory=list)
    branch_no_fix: bool = False

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "php_version": self.php_version,
            "path": self.path,
            "vulnerable": self.vulnerable,
            "reason": self.reason,
            "cves": self.cves,
            "branch_no_fix": self.branch_no_fix,
        }


def _classify(version_str: str, source: str, path: str) -> AuditResult:
    m = VERSION_RE.search(version_str)
    if not m:
        return AuditResult(source, version_str, path, None,
                           "Could not parse version from '" + version_str + "'", list(CVE_IDS))
    major, minor, patch = int(m.group("major")), int(m.group("minor")), int(m.group("patch"))
    v = f"{major}.{minor}.{patch}"
    branch = (major, minor)
    if branch not in FIXED_VERSIONS:
        return AuditResult(source, v, path, True,
                           f"PHP branch {major}.{minor}.x has no fix released", list(CVE_IDS), branch_no_fix=True)
    fixed = tuple(int(x) for x in FIXED_VERSIONS[branch].split("."))
    if (major, minor, patch) < fixed:
        return AuditResult(source, v, path, True,
                           f"PHP {v} < fixed {FIXED_VERSIONS[branch]}", list(CVE_IDS))
    return AuditResult(source, v, path, False,
                       f"PHP {v} >= fixed {FIXED_VERSIONS[branch]}", [])


def _query_binary(exe: str, source: str) -> AuditResult:
    try:
        out = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=10)
        text = out.stdout or out.stderr or ""
        first_line = text.splitlines()[0] if text.splitlines() else ""
        if "PHP" in first_line:
            return _classify(first_line, source, exe)
        return AuditResult(source, None, exe, None, "No PHP version banner", list(CVE_IDS))
    except (OSError, subprocess.TimeoutExpired) as e:
        return AuditResult(source, None, exe, None, f"Could not query version: {e}", list(CVE_IDS))


def binary_is_patched(exe: str) -> Optional[bool]:
    """Read the binary and look for the fix's unique strings. True if all
    required signatures are present, False if none are, None otherwise."""
    try:
        data = Path(exe).read_bytes()
    except OSError:
        return None
    hits = sum(1 for sig in BINARY_PATCH_SIGNATURES if sig in data)
    if hits == len(BINARY_PATCH_SIGNATURES):
        return True
    if hits == 0:
        return False
    return None


def _query_binary_with_signature(exe: str, source: str) -> AuditResult:
    """Version check combined with ground-truth binary signature check."""
    version_result = _query_binary(exe, source)
    sig = binary_is_patched(exe)
    if version_result.php_version is None or sig is None:
        if sig is False and version_result.vulnerable is True:
            return AuditResult(source, version_result.php_version, exe, True,
                version_result.reason + "; binary check confirms fix strings absent",
                list(CVE_IDS), version_result.branch_no_fix)
        if sig is True:
            return AuditResult(source, version_result.php_version, exe, False,
                "Binary contains the patched memory-manager strings; treat as patched "
                "(fix backported; version string unreliable)", [])
        return version_result
    if sig is True and version_result.vulnerable:
        return AuditResult(source, version_result.php_version, exe, False,
            f"Version string suggests '{version_result.reason}', but binary contains "
            "the patched memory-manager strings; treat as patched (backported fix)",
            [])
    if sig is False and version_result.vulnerable:
        return AuditResult(source, version_result.php_version, exe, True,
            version_result.reason + "; binary check confirms fix strings absent",
            list(CVE_IDS), version_result.branch_no_fix)
    if sig is False and not version_result.vulnerable:
        return AuditResult(source, version_result.php_version, exe, None,
            f"Version {version_result.php_version} appears patched, but binary lacks fix "
            "strings; possible custom/foreign build, manual review required",
            list(CVE_IDS))
    return version_result


def audit_php_binaries() -> list:
    """Find php binaries on PATH and query their version."""
    results = []
    seen = set()
    names = ["php", "php8.2", "php8.3", "php8.4", "php8.5",
             "php7.4", "php7.3", "php7.2", "php7.1", "php7.0", "php5", "php5.6"]
    for name in names:
        exe = shutil.which(name)
        if exe and exe not in seen:
            seen.add(exe)
            results.append(_query_binary_with_signature(exe, "binary:" + name))
    return results


def audit_packages() -> list:
    """Query OS package manager for installed PHP package versions."""
    results = []
    if sys.platform.startswith("linux"):
        if shutil.which("dpkg"):
            try:
                out = subprocess.run(["dpkg", "-l"], capture_output=True, text=True, timeout=30)
                for line in (out.stdout or "").splitlines():
                    if not line.startswith("ii"):
                        continue
                    cols = line.split()
                    if len(cols) < 3:
                        continue
                    pkg, ver = cols[1], cols[2]
                    if not pkg.startswith("php") and "php" not in pkg:
                        continue
                    m = re.match(r"^(\d+:)?(\d+)\.(\d+)\.(\d+)", ver)
                    if m:
                        v = f"{m.group(2)}.{m.group(3)}.{m.group(4)}"
                        results.append(_classify(v, "dpkg:" + pkg, ver))
            except (OSError, subprocess.TimeoutExpired):
                pass
        if shutil.which("rpm"):
            try:
                out = subprocess.run(["rpm", "-qa"], capture_output=True, text=True, timeout=30)
                for line in (out.stdout or "").splitlines():
                    low = line.lower()
                    if "php" not in low:
                        continue
                    # rpm -qa format: name-version-release.arch
                    m = re.match(r"^([A-Za-z0-9_.+-]*php[A-Za-z0-9_.+-]*)-(\d+)\.(\d+)\.(\d+)", line)
                    if m:
                        v = f"{m.group(2)}.{m.group(3)}.{m.group(4)}"
                        results.append(_classify(v, "rpm:" + m.group(1), line))
            except (OSError, subprocess.TimeoutExpired):
                pass
    elif sys.platform == "win32":
        candidates = [
            Path(r"C:\php\php.exe"),
            Path(r"C:\php8\php.exe"),
            Path(r"C:\Program Files\PHP\php.exe"),
            Path(r"C:\xampp\php\php.exe"),
        ]
        for c in candidates:
            if c.exists():
                results.append(_query_binary(str(c), "win-path"))
    return results


def audit_running_processes() -> list:
    """Look for running PHP processes and record their command line."""
    results = []
    try:
        if sys.platform.startswith("linux") or sys.platform == "darwin":
            out = subprocess.run(["ps", "-eo", "pid,comm,args"], capture_output=True, text=True, timeout=15)
            for line in (out.stdout or "").splitlines()[1:]:
                low = line.lower()
                if "php-fpm" in low or "php-cgi" in low or "php " in low:
                    results.append(AuditResult("process", None, line.strip(), None,
                        "PHP process running; cross-reference with binary/package audit for version", list(CVE_IDS)))
        elif sys.platform == "win32":
            out = subprocess.run(["tasklist", "/FO", "CSV", "/NH"], capture_output=True, text=True, timeout=15)
            for row in csv.reader((out.stdout or "").splitlines()):
                if row and row[0].lower().startswith("php"):
                    results.append(AuditResult("process", None, ",".join(row), None,
                        "PHP process running; cross-reference with binary/package audit for version", list(CVE_IDS)))
    except (OSError, subprocess.TimeoutExpired):
        pass
    return results


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Local audit for CVE-2026-109618 / CVE-2026-109619")
    parser.add_argument("--json", help="write JSON results to this file")
    parser.add_argument("--csv", help="write CSV results to this file")
    args = parser.parse_args(argv)

    results = []
    results.extend(audit_php_binaries())
    results.extend(audit_packages())
    results.extend(audit_running_processes())

    vuln = [r for r in results if r.vulnerable]
    safe = [r for r in results if r.vulnerable is False]
    unknown = [r for r in results if r.vulnerable is None]

    print(f"Local audit complete. {len(results)} result(s).")
    if vuln:
        print()
        print(f"== POTENTIALLY VULNERABLE ({len(vuln)}) ==")
        for r in vuln:
            tag = "NO-FIX" if r.branch_no_fix else "PATCH"
            print(f"  [{tag}] {r.source}  PHP {r.php_version or 'unknown'}  {r.path}  {r.reason}")
    if unknown:
        print()
        print(f"== NEEDS FOLLOW-UP ({len(unknown)}) ==")
        for r in unknown:
            print(f"  [UNKNOWN] {r.source}  {r.path}  {r.reason}")
    if safe:
        print()
        print(f"== PATCHED / SAFE ({len(safe)}) ==")
        for r in safe:
            print(f"  [OK] {r.source}  PHP {r.php_version}  {r.path}")
    if not results:
        print("No PHP installations found on this host.")

    if args.json:
        Path(args.json).write_text(json.dumps([r.to_dict() for r in results], indent=2))
        print()
        print(f"JSON written to {args.json}")
    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["source", "php_version", "path", "vulnerable", "reason"])
            for r in results:
                w.writerow([r.source, r.php_version, r.path, r.vulnerable, r.reason])
        print(f"CSV written to {args.csv}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

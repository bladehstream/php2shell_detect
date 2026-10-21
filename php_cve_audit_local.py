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
import glob
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from php_binary_check import check_file

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
UBUNTU_FIXED_FLOORS = {
    ("14.04", "5.5"): "5.5.9+dfsg-1ubuntu4.29+esm18",
    ("16.04", "7.0"): "7.0.33-0ubuntu0.16.04.16+esm22",
    ("18.04", "7.2"): "7.2.24-0ubuntu0.18.04.17+esm14",
    ("20.04", "7.4"): "7.4.3-4ubuntu2.29+esm5",
    ("22.04", "8.1"): "8.1.2-1ubuntu2.28",
    ("24.04", "8.3"): "8.3.6-0ubuntu0.24.04.13",
    ("trusty", "5.5"): "5.5.9+dfsg-1ubuntu4.29+esm18",
    ("xenial", "7.0"): "7.0.33-0ubuntu0.16.04.16+esm22",
    ("bionic", "7.2"): "7.2.24-0ubuntu0.18.04.17+esm14",
    ("focal", "7.4"): "7.4.3-4ubuntu2.29+esm5",
    ("jammy", "8.1"): "8.1.2-1ubuntu2.28",
    ("noble", "8.3"): "8.3.6-0ubuntu0.24.04.13",
    ("resolute", "8.5"): "8.5.4-0ubuntu1.5",
    ("stonking", "8.5"): "8.5.9-0ubuntu2.1",
}

DEB_RUNTIME_PACKAGE_RE = re.compile(
    r"^(?:php(?:\d+\.\d+)?(?:-(?:cli|fpm|cgi|common))?|"
    r"libapache2-mod-php(?:\d+\.\d+)?)$",
    re.I,
)
RPM_RUNTIME_PACKAGE_RE = re.compile(
    r"^(?:php(?:-cli|-fpm|-common)?|php\d+-php(?:-cli|-fpm|-common)?|"
    r"ea-php\d+-php(?:-cli|-fpm|-common)?|alt-php\d+-php(?:-cli|-fpm|-common)?)$",
    re.I,
)


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
    if m.group("suffix"):
        return AuditResult(source, v + m.group("suffix"), path, None,
                           "Pre-release or suffixed PHP version requires build verification",
                           list(CVE_IDS))
    branch = (major, minor)
    if branch not in FIXED_VERSIONS:
        if branch > max(FIXED_VERSIONS):
            return AuditResult(source, v, path, None,
                               f"PHP branch {major}.{minor}.x is newer than the advisory table; verify provenance",
                               list(CVE_IDS))
        return AuditResult(source, v, path, True,
                           f"PHP branch {major}.{minor}.x has no fixed upstream release; vendor/source backport may exist",
                           list(CVE_IDS), branch_no_fix=True)
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


def binary_oom_fix_evidence(exe: str) -> Optional[bool]:
    """Return corroborating OOM-patch evidence for an identifiable PHP binary."""
    try:
        result = check_file(Path(exe))
    except OSError:
        return None
    return result.get("oom_fix_signatures") if result.get("applicable") else None


def _query_binary_with_signature(exe: str, source: str) -> AuditResult:
    """Version check combined with corroborating OOM-patch signatures."""
    version_result = _query_binary(exe, source)
    sig = binary_oom_fix_evidence(exe)
    if version_result.php_version is None or sig is None:
        if sig is False and version_result.vulnerable is True:
            return AuditResult(source, version_result.php_version, exe, True,
                version_result.reason + "; binary check confirms fix strings absent",
                list(CVE_IDS), version_result.branch_no_fix)
        if sig is True:
            return AuditResult(source, version_result.php_version, exe, None,
                "OOM-fix signatures present, but complete dual-CVE build provenance is unknown",
                list(CVE_IDS))
        return version_result
    if sig is True and version_result.vulnerable:
        return AuditResult(source, version_result.php_version, exe, None,
            f"Version suggests '{version_result.reason}', while OOM-fix signatures are present; "
            "verify the exact vendor/source build covers both CVEs",
            list(CVE_IDS))
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
    """Find common CLI/FPM/CGI/SAPI binaries and modules."""
    results = []
    seen = set()
    names = ["php", "php8.2", "php8.3", "php8.4", "php8.5",
             "php7.4", "php7.3", "php7.2", "php7.1", "php7.0", "php5", "php5.6"]
    for name in names:
        exe = shutil.which(name)
        if exe and exe not in seen:
            seen.add(exe)
            results.append(_query_binary_with_signature(exe, "binary:" + name))
    patterns = []
    if sys.platform.startswith("linux"):
        patterns = [
            "/usr/bin/php*", "/usr/sbin/php-fpm*", "/usr/bin/php-cgi*",
            "/usr/local/bin/php*", "/usr/local/sbin/php*",
            "/usr/lib/apache2/modules/libphp*.so", "/usr/lib64/httpd/modules/libphp*.so",
            "/opt/cpanel/ea-php*/root/usr/bin/php", "/opt/cpanel/ea-php*/root/usr/sbin/php-fpm",
            "/opt/plesk/php/*/bin/php", "/opt/plesk/php/*/sbin/php-fpm",
            "/opt/alt/php*/usr/bin/php", "/opt/remi/php*/root/usr/bin/php",
            "/usr/local/lsws/lsphp*/bin/lsphp",
        ]
    for pattern in patterns:
        for candidate in glob.glob(pattern):
            try:
                resolved = str(Path(candidate).resolve())
            except OSError:
                resolved = candidate
            if resolved in seen or not Path(candidate).is_file():
                continue
            seen.add(resolved)
            if candidate.endswith(".so"):
                sig = binary_oom_fix_evidence(candidate)
                reason = {
                    True: "Apache PHP module contains OOM-fix signatures; verify package covers both CVEs",
                    False: "Apache PHP module lacks OOM-fix signatures; affected build likely",
                    None: "Apache PHP module signature result inconclusive",
                }[sig]
                results.append(AuditResult("apache-module", None, candidate,
                                           True if sig is False else None, reason, list(CVE_IDS)))
            elif os.access(candidate, os.X_OK):
                results.append(_query_binary_with_signature(candidate, "discovered-binary"))
    return results


def _os_release() -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        for line in Path("/etc/os-release").read_text(errors="replace").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key] = value.strip().strip('"')
    except OSError:
        pass
    return values


def _dpkg_at_least(installed: str, floor: str) -> bool:
    try:
        return subprocess.run(
            ["dpkg", "--compare-versions", installed, "ge", floor],
            timeout=10, check=False,
        ).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def audit_packages() -> list:
    """Query OS package manager for installed PHP package versions."""
    results = []
    if sys.platform.startswith("linux"):
        if shutil.which("dpkg"):
            try:
                out = subprocess.run(
                    ["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\n"],
                    capture_output=True, text=True, timeout=30,
                )
                os_release = _os_release()
                for line in (out.stdout or "").splitlines():
                    cols = line.split("\t", 1)
                    if len(cols) != 2:
                        continue
                    pkg, ver = cols[0].split(":", 1)[0], cols[1]
                    if not DEB_RUNTIME_PACKAGE_RE.match(pkg):
                        continue
                    m = re.match(r"^(\d+:)?(\d+)\.(\d+)\.(\d+)", ver)
                    if m:
                        v = f"{m.group(2)}.{m.group(3)}.{m.group(4)}"
                        branch_text = f"{m.group(2)}.{m.group(3)}"
                        floor = (
                            UBUNTU_FIXED_FLOORS.get((os_release.get("VERSION_CODENAME", ""), branch_text))
                            or UBUNTU_FIXED_FLOORS.get((os_release.get("VERSION_ID", ""), branch_text))
                        )
                        if os_release.get("ID") == "ubuntu" and floor and _dpkg_at_least(ver, floor):
                            results.append(AuditResult(
                                "dpkg:" + pkg, v, ver, False,
                                f"Installed Ubuntu package meets vendor floor {floor} for both CVEs",
                                [],
                            ))
                        else:
                            results.append(_classify(v, "dpkg:" + pkg, ver))
            except (OSError, subprocess.TimeoutExpired):
                pass
        if shutil.which("rpm"):
            try:
                out = subprocess.run(["rpm", "-qa"], capture_output=True, text=True, timeout=30)
                for line in (out.stdout or "").splitlines():
                    # rpm -qa format: name-version-release.arch
                    m = re.match(r"^([A-Za-z0-9_.+-]*php[A-Za-z0-9_.+-]*)-(\d+)\.(\d+)\.(\d+)", line)
                    if m and RPM_RUNTIME_PACKAGE_RE.match(m.group(1)):
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
                results.append(_query_binary_with_signature(str(c), "win-path"))
    return results


def audit_running_processes() -> list:
    """Look for running PHP processes and record their command line."""
    results = []
    try:
        if sys.platform.startswith("linux") or sys.platform == "darwin":
            out = subprocess.run(["ps", "-eo", "pid=,comm=,args="], capture_output=True, text=True, timeout=15)
            seen_paths = set()
            for line in (out.stdout or "").splitlines():
                low = line.lower()
                parts = line.strip().split(None, 2)
                if len(parts) < 2:
                    continue
                pid, comm = parts[0], parts[1].lower()
                if not any(name in comm for name in ("php", "lsphp", "frankenphp", "apache", "httpd")):
                    continue
                exe_link = Path("/proc") / pid / "exe"
                try:
                    exe = str(exe_link.resolve(strict=True))
                except OSError:
                    exe = ""
                if exe and exe not in seen_paths and any(name in comm for name in ("php", "lsphp", "frankenphp")):
                    seen_paths.add(exe)
                    result = _query_binary_with_signature(exe, f"process:{pid}:{comm}")
                    result.path = exe
                    results.append(result)
                maps_path = Path("/proc") / pid / "maps"
                try:
                    mapped = {
                        entry.split()[-1]
                        for entry in maps_path.read_text(errors="replace").splitlines()
                        if "/" in entry and re.search(r"/libphp[^/]*\.so", entry.split()[-1], re.I)
                    }
                except OSError:
                    mapped = set()
                for module in mapped:
                    if module in seen_paths:
                        continue
                    seen_paths.add(module)
                    sig = binary_oom_fix_evidence(module)
                    results.append(AuditResult(
                        f"process-map:{pid}:{comm}", None, module,
                        True if sig is False else None,
                        "Loaded Apache PHP module " + (
                            "lacks OOM-fix signatures" if sig is False else
                            "contains OOM-fix signatures; verify package covers both CVEs" if sig is True else
                            "could not be conclusively checked"
                        ), list(CVE_IDS),
                    ))
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
        print(f"== VENDOR OR UPSTREAM FIX CONFIRMED ON DISK ({len(safe)}) ==")
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
    if vuln:
        return 2
    if unknown:
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())

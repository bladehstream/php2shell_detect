#!/usr/bin/env python3
"""
php_cve_scanner.py
==================

Network scanner for CVE-2026-109618 ("PHP2Shell" OOM-bailout memory corruption)
and CVE-2026-109619 (stale-global-state use-after-free), both remotely
exploitable via any HTTP request on unpatched PHP.

Fixed in:
    PHP 8.2 -> 8.2.35
    PHP 8.3 -> 8.3.36
    PHP 8.4 -> 8.4.27
    PHP 8.5 -> 8.5.12

PHP 8.1 and earlier have no fix available at the time of writing and should be
assumed vulnerable regardless of patch level.

Detection strategy (all safe methods only):
  1. Look for the "X-Powered-By" response header (most common leak).
  2. If not present, send a request with a PHP session cookie parameter
     (?PHPSESSID=... / ?PHP_SESSION_ID=...) and look for a Set-Cookie response,
     which confirms PHP is handling the request but does not reveal the exact
     version (marks it as "version-unknown but PHP present").
  3. Probe common PHP entry points and CGI paths (index.php, info.php,
     cgi-bin/php*, etc.) to widen coverage.

Usage examples:
    python php_cve_scanner.py --subnet 10.0.0.0/24
    python php_cve_scanner.py --target 10.0.0.15
    python php_cve_scanner.py --target 10.0.0.15 --port 8080 --https
    python php_cve_scanner.py --subnet 10.0.0.0/24 --threads 200 --output out.json
    python php_cve_scanner.py --target 10.0.0.15 --wordlist paths.txt
    python php_cve_scanner.py --target 10.0.0.15 --path-traversal
    python php_cve_scanner.py --subnet 10.0.0.0/24 --deep-presence
    python php_cve_scanner.py --target 10.0.0.15 --fpm-port 9000

This tool only sends benign GET requests. It does NOT exploit the
vulnerabilities; it fingerprints the PHP version and determines whether that
version falls below the fixed threshold for each advisory.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import ipaddress
import json
import logging
import re
import sys
import urllib.error
import urllib.request
import ssl
import socket
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

log = logging.getLogger("php_cve_scanner")

# ---------------------------------------------------------------------------
# CVE metadata
# ---------------------------------------------------------------------------

CVE_IDS = ("CVE-2026-109618", "CVE-2026-109619")

# Mapping of PHP major.minor branch -> fixed patch version.
# Branches not listed here have no fix released at the time of writing.
FIXED_VERSIONS = {
    (8, 2): "8.2.35",
    (8, 3): "8.3.36",
    (8, 4): "8.4.27",
    (8, 5): "8.5.12",
}

DEFAULT_PORTS_HTTP = [80, 8080, 8000]
DEFAULT_PORTS_HTTPS = [443, 8443]

DEFAULT_PATHS = [
    "/index.php",
    "/index.php/",
    "/info.php",
    "/test.php",
    "/phpinfo.php",
    "/cgi-bin/php",
    "/cgi-bin/php5",
    "/cgi-bin/php7",
    "/cgi-bin/php8",
    "/cgi-bin/php-cgi",
    "/cgi-bin/php.fcgi",
]

DEFAULT_TIMEOUT = 5.0

USER_AGENT = "php2shell-cve-scanner/1.0 (CVE-2026-109618 CVE-2026-109619 detection)"

# Regex to pull major.minor.patch (with optional pre-release suffix) from a
# version string. Handles things like "8.2.34", "8.5.11RC1", "8.1.0-dev".
VERSION_RE = re.compile(
    r"(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)(?:[-.]?(?P<suffix>[A-Za-z0-9]+))?"
)

# A looser version, e.g. just "8.3" without patch.
LOOSE_VERSION_RE = re.compile(r"(?P<major>\d+)\.(?P<minor>\d+)(?:\.(?P<patch>\d+))?")


def _presence_finding(host: str, port: int, scheme: str, path: str, reason: str, evidence: str) -> Finding:
    return Finding(
        host=host, port=port, scheme=scheme, path=path,
        php_version=None, major=None, minor=None, patch=None,
        vulnerable=None,
        reason=reason,
        evidence=evidence,
        cves=list(CVE_IDS),
        version_unknown=True,
    )


@dataclass
class Finding:
    host: str
    port: int
    scheme: str
    path: str
    php_version: Optional[str]
    major: Optional[int]
    minor: Optional[int]
    patch: Optional[int]
    vulnerable: Optional[bool]
    reason: str
    evidence: str
    cves: list = field(default_factory=list)
    branch_no_fix: bool = False
    version_unknown: bool = False

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "scheme": self.scheme,
            "path": self.path,
            "php_version": self.php_version,
            "major": self.major,
            "minor": self.minor,
            "patch": self.patch,
            "vulnerable": self.vulnerable,
            "reason": self.reason,
            "evidence": self.evidence,
            "cves": self.cves,
            "branch_no_fix": self.branch_no_fix,
            "version_unknown": self.version_unknown,
        }


# ---------------------------------------------------------------------------
# HTTP probing
# ---------------------------------------------------------------------------


def make_request(
    url: str,
    timeout: float,
    https_verify: bool = True,
    extra_headers: Optional[dict] = None,
) -> tuple[Optional[int], dict, bytes]:
    """Perform a GET request. Returns (status, headers, body). Non-2xx/3xx
    still return the response when available (e.g. 404 with headers)."""
    headers = {"User-Agent": USER_AGENT}
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(url, headers=headers, method="GET")
    ctx = None
    if url.startswith("https://"):
        ctx = ssl.create_default_context()
        if not https_verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.status, dict(resp.headers), resp.read(65536)
    except urllib.error.HTTPError as e:
        body = b""
        try:
            body = e.read(65536)
        except Exception:
            pass
        return e.code, dict(e.headers or {}), body
    except (urllib.error.URLError, socket.timeout, ConnectionError, OSError) as e:
        log.debug("Request failed %s: %s", url, e)
        return None, {}, b""


def probe_http(
    host: str,
    port: int,
    scheme: str,
    paths: list[str],
    timeout: float,
    https_verify: bool,
    path_traversal: bool = False,
    deep_presence: bool = False,
) -> Optional[Finding]:
    """Probe one host:port for PHP fingerprints."""
    base = f"{scheme}://{host}:{port}"

    # Step 1: baseline check on each path for X-Powered-By.
    for path in paths:
        url = base + path
        status, headers, _body = make_request(url, timeout, https_verify)
        if not headers:
            continue
        powered = headers.get("X-Powered-By", "")
        if powered and "PHP" in powered:
            m = VERSION_RE.search(powered)
            if m:
                return _finding_from_match(host, port, scheme, path, m, powered)
            lm = LOOSE_VERSION_RE.search(powered)
            if lm:
                return _finding_from_match(host, port, scheme, path, lm, powered)
            return Finding(
                host=host, port=port, scheme=scheme, path=path,
                php_version=None, major=None, minor=None, patch=None,
                vulnerable=None,
                reason="PHP detected via X-Powered-By but version unparseable",
                evidence=powered,
                cves=list(CVE_IDS),
                version_unknown=True,
            )
        # Look for Set-Cookie indicating PHP session handling.
        set_cookie = headers.get("Set-Cookie", "")
        if "PHPSESSID=" in set_cookie or "PHP_SESSION_ID=" in set_cookie:
            return Finding(
                host=host, port=port, scheme=scheme, path=path,
                php_version=None, major=None, minor=None, patch=None,
                vulnerable=None,
                reason="PHP session cookie observed; PHP present but version unknown",
                evidence=set_cookie,
                cves=list(CVE_IDS),
                version_unknown=True,
            )

    # Step 2: retry with ?PHPSESSID to force Set-Cookie if PHP is present.
    for path in paths:
        url = base + path + ("?" if "?" not in path else "&") + "PHPSESSID=php2shellprobe1234567890"
        status, headers, _body = make_request(url, timeout, https_verify)
        if not headers:
            continue
        set_cookie = headers.get("Set-Cookie", "")
        if "PHPSESSID=" in set_cookie or "PHP_SESSION_ID=" in set_cookie:
            return Finding(
                host=host, port=port, scheme=scheme, path=path,
                php_version=None, major=None, minor=None, patch=None,
                vulnerable=None,
                reason="PHP session cookie observed via probe; PHP present but version unknown",
                evidence=set_cookie,
                cves=list(CVE_IDS),
                version_unknown=True,
            )
        powered = headers.get("X-Powered-By", "")
        if powered and "PHP" in powered:
            m = VERSION_RE.search(powered) or LOOSE_VERSION_RE.search(powered)
            if m:
                return _finding_from_match(host, port, scheme, path, m, powered)

    # Step 2b: deep presence probes. All benign plain GETs, no payloads. These
    # detect the PHP runtime itself and work even when expose_php = Off.
    if deep_presence:
        marker = uuid.uuid4().hex[:12]
        _s, _h, body = make_request(f"{base}/nonexistent-{marker}.php", timeout, https_verify)
        if body and b"File not found." in body:
            return _presence_finding(
                host, port, scheme, f"/nonexistent-{marker}.php",
                "php-fpm 'File not found.' response observed; PHP runtime present, version unknown",
                "File not found.",
            )
        for probe_path, marker_text, label in (
            ("/fpm-ping", b"pong", "php-fpm ping endpoint responded; PHP-FPM present"),
            ("/ping", b"pong", "php-fpm ping endpoint responded; PHP-FPM present"),
            ("/fpm-status", b"pool:", "php-fpm status page observed; PHP-FPM present"),
            ("/status", b"pool:", "php-fpm status page observed; PHP-FPM present"),
        ):
            _s, _h, body = make_request(base + probe_path, timeout, https_verify)
            if body and marker_text in body:
                return _presence_finding(host, port, scheme, probe_path, label, label)
        error_markers = (
            b"Fatal error", b"Parse error", b"Uncaught ", b"Deprecated: ",
            b"Undefined variable", b"Undefined index",
        )
        for path in paths:
            _s, _h, body = make_request(base + path, timeout, https_verify)
            if body and any(mk in body for mk in error_markers):
                evidence = next(mk.decode(errors="replace") for mk in error_markers if mk in body)
                return _presence_finding(
                    host, port, scheme, path,
                    "PHP error signature in response body; PHP runtime present, version unknown",
                    evidence,
                )

    # Step 3: optional CGI-handler probes (still non-exploiting).
    if path_traversal:
        for prefix in ["/cgi-bin/php", "/cgi-bin/php5", "/cgi-bin/php7", "/cgi-bin/php8", "/cgi-bin/php-cgi"]:
            for suffix in ["?/**", "?-s", "?-d", "?-v"]:
                url = base + prefix + suffix
                status, headers, _body = make_request(url, timeout, https_verify)
                if not headers:
                    continue
                powered = headers.get("X-Powered-By", "")
                if powered and "PHP" in powered:
                    m = VERSION_RE.search(powered) or LOOSE_VERSION_RE.search(powered)
                    if m:
                        return _finding_from_match(host, port, scheme, prefix, m, powered)
    return None


def _finding_from_match(
    host: str, port: int, scheme: str, path: str,
    m: "re.Match", evidence: str,
) -> Finding:
    major = int(m.group("major"))
    minor = int(m.group("minor"))
    patch = int(m.group("patch")) if m.group("patch") else None
    version_str = f"{major}.{minor}.{patch if patch is not None else 0}"
    branch = (major, minor)

    if branch not in FIXED_VERSIONS:
        return Finding(
            host=host, port=port, scheme=scheme, path=path,
            php_version=version_str, major=major, minor=minor, patch=patch,
            vulnerable=True,
            reason=f"PHP branch {major}.{minor}.x has no fix released (no patched version published)",
            evidence=evidence,
            cves=list(CVE_IDS),
            branch_no_fix=True,
        )

    fixed = FIXED_VERSIONS[branch]
    fixed_major, fixed_minor, fixed_patch = [int(x) for x in fixed.split(".")]
    eff_patch = patch if patch is not None else 0
    if (major, minor, eff_patch) < (fixed_major, fixed_minor, fixed_patch):
        return Finding(
            host=host, port=port, scheme=scheme, path=path,
            php_version=version_str, major=major, minor=minor, patch=patch,
            vulnerable=True,
            reason=f"PHP {version_str} < fixed {fixed} for branch {major}.{minor}.x",
            evidence=evidence,
            cves=list(CVE_IDS),
        )
    return Finding(
        host=host, port=port, scheme=scheme, path=path,
        php_version=version_str, major=major, minor=minor, patch=patch,
        vulnerable=False,
        reason=f"PHP {version_str} >= fixed {fixed} for branch {major}.{minor}.x",
        evidence=evidence,
        cves=[],
    )


def probe_host(
    host: str,
    ports: list[tuple[int, str]],
    paths: list[str],
    timeout: float,
    https_verify: bool,
    path_traversal: bool,
    deep_presence: bool = False,
    fpm_port: Optional[int] = None,
) -> list[Finding]:
    """Try a list of (port, scheme) combinations for one host."""
    findings = []
    for port, scheme in ports:
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.close()
        except OSError:
            log.debug("%s:%d unreachable", host, port)
            continue
        f = probe_http(host, port, scheme, paths, timeout, https_verify, path_traversal, deep_presence)
        if f:
            findings.append(f)
    if fpm_port is not None and not findings:
        try:
            sock = socket.create_connection((host, fpm_port), timeout=timeout)
            sock.close()
            findings.append(Finding(
                host=host, port=fpm_port, scheme="tcp", path="",
                php_version=None, major=None, minor=None, patch=None,
                vulnerable=None,
                reason="TCP port open where php-fpm commonly listens (connect-only check; no FastCGI data sent)",
                evidence=f"tcp connect to {host}:{fpm_port} succeeded",
                cves=list(CVE_IDS),
                version_unknown=True,
            ))
        except OSError:
            log.debug("%s:%d (fpm) unreachable", host, fpm_port)
    return findings


def expand_targets(args) -> list[str]:
    if args.target:
        return [args.target]
    if args.subnet:
        net = ipaddress.ip_network(args.subnet, strict=False)
        return [str(ip) for ip in net.hosts()]
    raise ValueError("Provide --target or --subnet")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="PHP CVE-2026-109618/109619 network scanner")
    parser.add_argument("--subnet", help="CIDR subnet to scan, e.g. 10.0.0.0/24")
    parser.add_argument("--target", help="single host to scan")
    parser.add_argument("--port", type=int, action="append", help="specific port(s) to check; repeatable")
    parser.add_argument("--https", action="store_true", help="probe HTTPS ports only (443, 8443)")
    parser.add_argument("--http", action="store_true", help="probe HTTP ports only (80, 8080, 8000)")
    parser.add_argument("--paths", "--wordlist", dest="paths", help="file with one path per line to try instead of defaults")
    parser.add_argument("--threads", type=int, default=64)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--output", help="write JSON findings to this file")
    parser.add_argument("--csv", help="write CSV findings to this file")
    parser.add_argument("--insecure", action="store_true", help="skip TLS cert verification for HTTPS probes")
    parser.add_argument("--path-traversal", action="store_true", help="add non-destructive CGI probes")
    parser.add_argument("--deep-presence", action="store_true",
                        help="run extra benign presence probes (php-fpm 404/ping/status, PHP error signatures)")
    parser.add_argument("--fpm-port", type=int, default=None,
                        help="TCP-connect-only check of a php-fpm port (e.g. 9000); no FastCGI data is sent")
    parser.add_argument("-v", "--verbose", action="count", default=0)
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose > 1 else (logging.INFO if args.verbose else logging.WARNING),
        format="%(levelname)s: %(message)s",
    )

    if not args.subnet and not args.target:
        parser.error("Provide --subnet or --target")

    paths = list(DEFAULT_PATHS)
    if args.paths:
        custom = [line.strip() for line in Path(args.paths).read_text().splitlines() if line.strip()]
        if custom:
            paths = custom

    if args.port:
        if args.https:
            ports = [(p, "https") for p in args.port]
        elif args.http:
            ports = [(p, "http") for p in args.port]
        else:
            ports = [(p, "https") for p in args.port] + [(p, "http") for p in args.port]
    else:
        if args.https:
            ports = [(p, "https") for p in DEFAULT_PORTS_HTTPS]
        elif args.http:
            ports = [(p, "http") for p in DEFAULT_PORTS_HTTP]
        else:
            ports = [(443, "https")] + [(p, "http") for p in DEFAULT_PORTS_HTTP]

    targets = expand_targets(args)
    log.info("Scanning %d target(s) with %d thread(s)", len(targets), args.threads)

    findings: list[Finding] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {
            pool.submit(
                probe_host, t, ports, paths, args.timeout,
                not args.insecure, args.path_traversal, args.deep_presence, args.fpm_port,
            ): t
            for t in targets
        }
        for fut in concurrent.futures.as_completed(futures):
            t = futures[fut]
            try:
                res = fut.result()
            except Exception as e:
                log.debug("error scanning %s: %s", t, e)
                continue
            findings.extend(res)

    findings.sort(key=lambda f: (f.host, f.port))

    # Console summary.
    print(f"Scanned {len(targets)} target(s). {len(findings)} finding(s).")
    if not findings:
        print("No PHP fingerprints found. This does not prove absence of PHP;")
        print("consider trying a wider path list or checking application logs.")
        return 0

    vuln = [f for f in findings if f.vulnerable]
    safe = [f for f in findings if f.vulnerable is False]
    unknown = [f for f in findings if f.vulnerable is None]

    if vuln:
        print()
        print(f"== POTENTIALLY VULNERABLE ({len(vuln)}) ==")
        for f in vuln:
            tag = "NO-FIX" if f.branch_no_fix else "PATCH"
            print(f"  [{tag}] {f.scheme}://{f.host}:{f.port}{f.path}  PHP {f.php_version or 'unknown'}  {f.reason}")
    if unknown:
        print()
        print(f"== PHP PRESENT, VERSION UNKNOWN ({len(unknown)}) ==")
        for f in unknown:
            print(f"  [UNKNOWN] {f.scheme}://{f.host}:{f.port}{f.path}  {f.reason}")
    if safe:
        print()
        print(f"== PATCHED / SAFE ({len(safe)}) ==")
        for f in safe:
            print(f"  [OK] {f.scheme}://{f.host}:{f.port}{f.path}  PHP {f.php_version}  {f.reason}")

    if args.output:
        Path(args.output).write_text(json.dumps([f.to_dict() for f in findings], indent=2))
        print()
        print(f"JSON written to {args.output}")
    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["host", "port", "scheme", "path", "php_version", "vulnerable", "reason", "evidence"])
            for f in findings:
                w.writerow([f.host, f.port, f.scheme, f.path, f.php_version, f.vulnerable, f.reason, f.evidence])
        print(f"CSV written to {args.csv}")

    return 0


if __name__ == "__main__":
    sys.exit(main())

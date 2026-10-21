#!/usr/bin/env python3
"""
php_cve_scanner.py
==================

Network scanner for CVE-2026-109618 ("PHP2Shell" OOM-bailout memory corruption)
and CVE-2026-109619 (stale-global-state use-after-free), both reachable through
web requests under the conditions described by the official advisories.

Fixed in:
    PHP 8.2 -> 8.2.35
    PHP 8.3 -> 8.3.36
    PHP 8.4 -> 8.4.27
    PHP 8.5 -> 8.5.12

PHP 8.1 and earlier have no fixed upstream maintenance release. Vendor and
source backports exist, so exact package/build provenance is required.

Detection strategy (all safe methods only):
  1. Look for the "X-Powered-By" response header (most common leak).
  2. Look for an organically emitted PHP session cookie without retaining its
     value, which confirms PHP but does not reveal the exact version.
  3. Probe common PHP entry points and CGI paths (index.php, info.php,
     cgi-bin/php*, etc.) to widen coverage.

Usage examples:
    python php_cve_scanner.py --subnet 10.0.0.0/24
    python php_cve_scanner.py --target 10.0.0.15
    python php_cve_scanner.py --target 10.0.0.15 --port 8080 --https
    python php_cve_scanner.py --subnet 10.0.0.0/24 --threads 200 --output out.json
    python php_cve_scanner.py --target 10.0.0.15 --wordlist paths.txt
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
# Supported upstream branches and their first fixed releases. Other branches
# require vendor/source provenance rather than a numeric guess.
FIXED_VERSIONS = {
    (8, 2): "8.2.35",
    (8, 3): "8.3.36",
    (8, 4): "8.4.27",
    (8, 5): "8.5.12",
}

DEFAULT_PORTS_HTTP = [80, 8080, 8000]
DEFAULT_PORTS_HTTPS = [443, 8443]

DEFAULT_PATHS = [
    "/",
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
DEFAULT_MAX_HOSTS = 65536

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
) -> tuple[Optional[int], dict[str, list[str]], bytes]:
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
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    handlers = [urllib.request.ProxyHandler({}), NoRedirect()]
    if url.startswith("https://"):
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    opener = urllib.request.build_opener(*handlers)

    def normalise(message) -> dict[str, list[str]]:
        result: dict[str, list[str]] = {}
        if message is None:
            return result
        for name in message.keys():
            key = name.lower()
            if key not in result:
                result[key] = list(message.get_all(name, []))
        return result

    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, normalise(resp.headers), resp.read(65536)
    except urllib.error.HTTPError as e:
        body = b""
        try:
            body = e.read(65536)
        except Exception:
            pass
        return e.code, normalise(e.headers), body
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
    deep_presence: bool = False,
) -> Optional[Finding]:
    """Probe one host:port for PHP fingerprints."""
    url_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    base = f"{scheme}://{url_host}:{port}"

    # Step 1: baseline check on each path for X-Powered-By.
    for path in paths:
        url = base + path
        status, headers, _body = make_request(url, timeout, https_verify)
        if not headers:
            continue
        powered = " ".join(headers.get("x-powered-by", []))
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
        cookies = headers.get("set-cookie", [])
        php_cookie = next((value for value in cookies if "PHPSESSID=" in value or "PHP_SESSION_ID=" in value), "")
        if php_cookie:
            cookie_name = "PHPSESSID" if "PHPSESSID=" in php_cookie else "PHP_SESSION_ID"
            cookie_value = php_cookie.split(cookie_name + "=", 1)[1].split(";", 1)[0]
            return Finding(
                host=host, port=port, scheme=scheme, path=path,
                php_version=None, major=None, minor=None, patch=None,
                vulnerable=None,
                reason="PHP session cookie observed; PHP present but version unknown",
                evidence=f"Set-Cookie: {cookie_name}=<redacted>; value_length={len(cookie_value)}",
                cves=list(CVE_IDS),
                version_unknown=True,
            )

    # Step 2: deep presence probes. All are ordinary GETs. These
    # detect the PHP runtime itself and work even when expose_php = Off.
    if deep_presence:
        marker = uuid.uuid4().hex[:12]
        _s, _h, body = make_request(f"{base}/nonexistent-{marker}.php", timeout, https_verify)
        if _s == 404 and body.strip() == b"File not found.":
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
            if _s == 200 and body and marker_text in body:
                return _presence_finding(host, port, scheme, probe_path, label, label)
        error_markers = (
            b"Fatal error", b"Parse error", b"Uncaught ", b"Deprecated: ",
            b"Undefined variable", b"Undefined index",
        )
        for path in paths:
            _s, _h, body = make_request(base + path, timeout, https_verify)
            if _s is not None and _s >= 400 and body and any(mk in body for mk in error_markers):
                evidence = next(mk.decode(errors="replace") for mk in error_markers if mk in body)
                return _presence_finding(
                    host, port, scheme, path,
                    "PHP error signature in response body; PHP runtime present, version unknown",
                    evidence,
                )

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

    suffix = m.groupdict().get("suffix")
    if suffix:
        return Finding(
            host=host, port=port, scheme=scheme, path=path,
            php_version=version_str + suffix, major=major, minor=minor, patch=patch,
            vulnerable=None,
            reason=f"Pre-release or suffixed PHP version '{version_str + suffix}' requires build verification",
            evidence=evidence, cves=list(CVE_IDS), version_unknown=True,
        )

    if branch not in FIXED_VERSIONS:
        if branch > max(FIXED_VERSIONS):
            return Finding(
                host=host, port=port, scheme=scheme, path=path,
                php_version=version_str, major=major, minor=minor, patch=patch,
                vulnerable=None,
                reason=f"PHP branch {major}.{minor}.x is newer than the advisory table; verify build provenance",
                evidence=evidence, cves=list(CVE_IDS), version_unknown=True,
            )
        return Finding(
            host=host, port=port, scheme=scheme, path=path,
            php_version=version_str, major=major, minor=minor, patch=patch,
            vulnerable=True,
            reason=(f"PHP branch {major}.{minor}.x has no fixed upstream release; "
                    "a vendor or source backport may exist and must be verified"),
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
    deep_presence: bool = False,
    fpm_port: Optional[int] = None,
) -> tuple[list[Finding], int]:
    """Try a list of (port, scheme) combinations for one host."""
    findings = []
    reachable = 0
    for port, scheme in ports:
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.close()
        except OSError:
            log.debug("%s:%d unreachable", host, port)
            continue
        reachable += 1
        f = probe_http(host, port, scheme, paths, timeout, https_verify, deep_presence)
        if f:
            findings.append(f)
    if fpm_port is not None and not findings:
        try:
            sock = socket.create_connection((host, fpm_port), timeout=timeout)
            sock.close()
            reachable += 1
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
    return findings, reachable


def expand_targets(args) -> list[str]:
    if args.target:
        return [args.target]
    if args.subnet:
        net = ipaddress.ip_network(args.subnet, strict=False)
        host_count = max(0, net.num_addresses - (2 if net.version == 4 and net.prefixlen < 31 else 0))
        if host_count > args.max_hosts:
            raise ValueError(
                f"subnet expands to {host_count} hosts, above --max-hosts {args.max_hosts}"
            )
        return [str(ip) for ip in net.hosts()]
    raise ValueError("Provide --target or --subnet")


def main(argv=None) -> int:
    class _Parser(argparse.ArgumentParser):
        """argparse exits 2 on usage errors, which collides with this tool's
        exit-code contract (2 = affected evidence found). Route usage errors
        to exit 1 (command error) instead."""
        def error(self, message):
            self.print_usage(sys.stderr)
            self.exit(1, f"{self.prog}: error: {message}\n")

    parser = _Parser(description="PHP CVE-2026-109618/109619 network scanner")
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
    parser.add_argument("--deep-presence", action="store_true",
                        help="run extra benign presence probes (php-fpm 404/ping/status, PHP error signatures)")
    parser.add_argument("--fpm-port", type=int, default=None,
                        help="TCP-connect-only check of a php-fpm port (e.g. 9000); no FastCGI data is sent")
    parser.add_argument("-v", "--verbose", action="count", default=0)
    parser.add_argument("--max-hosts", type=int, default=DEFAULT_MAX_HOSTS,
                        help=f"refuse CIDRs larger than this many hosts (default {DEFAULT_MAX_HOSTS})")
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
        if any(port < 1 or port > 65535 for port in args.port):
            parser.error("--port values must be between 1 and 65535")
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
            ports = [(p, "https") for p in DEFAULT_PORTS_HTTPS] + [
                (p, "http") for p in DEFAULT_PORTS_HTTP
            ]

    if args.fpm_port is not None and not 1 <= args.fpm_port <= 65535:
        parser.error("--fpm-port must be between 1 and 65535")

    if args.threads < 1:
        parser.error("--threads must be at least 1")
    if args.max_hosts < 1:
        parser.error("--max-hosts must be at least 1")
    try:
        targets = expand_targets(args)
    except ValueError as exc:
        parser.error(str(exc))
    log.info("Scanning %d target(s) with %d thread(s)", len(targets), args.threads)

    findings: list[Finding] = []
    reachable = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
        target_iter = iter(targets)
        pending: dict[concurrent.futures.Future, str] = {}

        def submit_next() -> bool:
            try:
                target = next(target_iter)
            except StopIteration:
                return False
            future = pool.submit(
                probe_host, target, ports, paths, args.timeout,
                not args.insecure, args.deep_presence, args.fpm_port,
            )
            pending[future] = target
            return True

        for _ in range(min(len(targets), args.threads * 2)):
            submit_next()
        while pending:
            done, _ = concurrent.futures.wait(
                pending, return_when=concurrent.futures.FIRST_COMPLETED
            )
            for future in done:
                target = pending.pop(future)
                try:
                    res, reached = future.result()
                except Exception as exc:
                    log.debug("error scanning %s: %s", target, exc)
                else:
                    findings.extend(res)
                    reachable += reached
                submit_next()

    findings.sort(key=lambda f: (f.host, f.port))

    # Console summary.
    print(f"Scanned {len(targets)} target(s); {reachable} reachable endpoint(s); {len(findings)} finding(s).")
    if not findings:
        print("No PHP fingerprints found. This does not prove absence of PHP;")
        print("consider trying a wider path list or checking application logs.")
        if args.output:
            Path(args.output).write_text("[]\n", encoding="utf-8")
            print(f"JSON written to {args.output}")
        if args.csv:
            with open(args.csv, "w", newline="", encoding="utf-8") as fh:
                csv.writer(fh).writerow(
                    ["host", "port", "scheme", "path", "php_version", "vulnerable", "reason", "evidence"]
                )
            print(f"CSV written to {args.csv}")
        return 1 if reachable == 0 else 0

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
        print(f"== REPORTED AT UPSTREAM FIXED VERSION ({len(safe)}) ==")
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

    if vuln:
        return 2
    if unknown:
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())

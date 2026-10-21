# SBOM - PHP2Shell Detection Suite

Software bill of materials for the tooling in this directory. Generated
2026-10-22 (Australia/Adelaide).

## 1. Suite components

| Component | File | Role | Language | Version |
|-----------|------|------|----------|---------|
| php2shell-network-scanner | php_cve_scanner.py | Safe network PHP fingerprint and version triage | Python 3 | 1.2 |
| php2shell-local-audit | php_cve_audit_local.py | Local package, binary, module and process inventory | Python 3 | 1.2 |
| php2shell-binary-check | php_binary_check.py | Static OOM-patch evidence checker | Python 3 | 1.1 |
| php2shell-mock-server | test_mock_server.py | Test harness: mock PHP banner server | Python 3 | 1.0 |
| php2shell-tests | test_suite.py | Positive and negative regression suite | Python 3 | 1.0 |
| php2shell-runbook-pwsh | run_scan.ps1 | Reference exit-code consumer for scheduled-task/pipeline use | PowerShell 5.1+ | 1.0 |
| php2shell-runbook-sh | run_scan.sh | Reference exit-code consumer for cron/CI use | POSIX bash | 1.0 |
| cve-analysis | CVE_ANALYSIS.md | Patch-diff root-cause analysis, signature derivation, distro validation | Markdown | 1.0 |

## 2. External (third-party) dependencies

None. Every tool uses only the Python standard library. There are no pip
packages, no vendored libraries, no native extensions and no network fetches
at runtime beyond the scan traffic the user directs.

## 3. Standard library modules used

All modules below are part of CPython. "Since" is the Python version in which
the module (or the specific API used) became available; all are present in
every supported release (3.10+).

### php_cve_scanner.py

| Module | Purpose | Since |
|--------|---------|-------|
| argparse | CLI parsing | 2.7 |
| concurrent.futures | ThreadPoolExecutor for parallel scanning | 3.2 |
| csv | CSV report output | 2.7 |
| ipaddress | CIDR subnet expansion | 3.3 |
| json | JSON report output | 2.7 |
| logging | Diagnostics | 2.7 |
| re | Version-string extraction | any |
| sys | Exit codes | any |
| urllib.error | HTTP error handling | 3.0 |
| urllib.request | HTTP GET probing, TLS context | 3.0 |
| ssl | TLS context for HTTPS probes (incl. --insecure) | 2.6 |
| socket | TCP reachability pre-check | any |
| uuid | Random per-probe path marker for --deep-presence | 2.5 |
| dataclasses | Finding structure | 3.7 |
| pathlib | Output file writing | 3.4 |
| typing | Optional type hints | 3.5 |

### php_cve_audit_local.py

| Module | Purpose | Since |
|--------|---------|-------|
| argparse | CLI parsing | 2.7 |
| csv | CSV report output | 2.7 |
| glob | Common PHP runtime/module path discovery | any |
| json | JSON report output | 2.7 |
| os | Executable access checks | any |
| re | Version-string extraction, package version parsing | any |
| shutil | which() for binary discovery on PATH | 3.3 |
| subprocess | php --version queries, dpkg/rpm/ps/tasklist | 2.7 |
| sys | Platform detection, exit codes | any |
| dataclasses | AuditResult structure | 3.7 |
| pathlib | Binary reading for signature check, output writing | 3.4 |
| typing | Optional type hints | 3.5 |

### php_binary_check.py

| Module | Purpose | Since |
|--------|---------|-------|
| argparse | CLI parsing | 2.7 |
| json | JSON output | 2.7 |
| re | PHP runtime filename applicability | any |
| sys | Exit codes | any |
| pathlib | Binary reading | 3.4 |

### test_mock_server.py

| Module | Purpose | Since |
|--------|---------|-------|
| http.server | Mock HTTP server | 3.0 |
| threading | serve_forever thread | 2.7 |
| time | Server lifetime | any |

## 4. External commands invoked (php_cve_audit_local.py only)

These are OS-provided tools the audit shells out to, per platform. None are
bundled; they exist on any normal target system.

| Command | Platform | Purpose |
|---------|----------|---------|
| dpkg-query -W | Debian/Ubuntu | Installed PHP runtime package inventory |
| dpkg --compare-versions | Ubuntu/Debian | Native vendor package-floor comparison |
| rpm -qa | RHEL/SUSE/openSUSE | Installed PHP package inventory |
| ps -eo pid,comm,args | Linux/macOS | Running php-fpm/php-cgi detection |
| tasklist /FO CSV /NH | Windows | Running php process detection |

The Windows install-path scan reads the filesystem directly (no external
command) under the common prefixes C:\php, C:\php8, C:\Program Files\PHP,
C:\xampp\php.

## 5. Network behaviour

| Tool | Outbound traffic |
|------|------------------|
| php_cve_scanner.py | HTTP GET to user-specified targets only. No telemetry, no update checks, no external API calls. |
| php_cve_audit_local.py | None. Entirely local. |
| php_binary_check.py | None. Entirely local. |
| test_mock_server.py | Listens on 127.0.0.1:8080 only. |

## 6. Embedded reference data

### CVE metadata

| Field | Value |
|-------|-------|
| CVE-2026-109618 | PHP OOM-bailout memory corruption; fixed by fallible-allocation rework |
| CVE-2026-109619 | Stale request-owned error, session, object and extension state across worker requests |
| Fixed versions | 8.2.35, 8.3.36, 8.4.27, 8.5.12 |
| Older branches | No fixed upstream maintenance release; vendor/source backports may exist |
| Advisories | GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp |

### Binary signature strings (corroborating CVE-2026-109618 OOM evidence)

| String | Requirement | Verified against |
|--------|-------------|------------------|
| memory_hard_limit_percent | required | all 8 upstream tarballs (8.2.34/35, 8.3.35/36, 8.4.26/27, 8.5.11/12) |
| ZEND_MM_MAX_ALLOCS | required | same |
| Hard memory limit of | required | same |
| zend_mm_set_max_allocs | optional (may be stripped) | same |
| Allowed memory size of %zu bytes exhausted at %s:%d ... | corroborating (new format) | same |
| Allowed memory size of %zu bytes exhausted (tried to allocate %zu bytes) | corroborating (old format) | same |

Distro controls: Debian 12 security pool php8.2-cli 8.2.34 (signatures absent) /
8.2.35 (present); Remi EL9 php-cli 8.2.34 (absent) / 8.2.35 (present).
Remi 8.2.35 RPM sha256 verified against repo repodata:
6e330204f30fecb0bb34a8639f737c0dfab26313df593a644a9f125e80c550ff.

## 7. Data produced

| Tool | Output | Format |
|------|--------|--------|
| php_cve_scanner.py | findings.json / findings.csv (--output/--csv) | JSON array of finding objects; CSV rows |
| php_cve_audit_local.py | audit.json / audit.csv (--json/--csv) | JSON array of result objects; CSV rows |
| php_binary_check.py | results.json (--json) | JSON array of per-file results |

All outputs are advisory-only findings with evidence strings. HTTP cookie
values are redacted; no payloads or exploit data are produced.

## 8. File integrity (SHA-256)

Computed over the final state of each file. Re-verify after any local edit.

| File | Size (bytes) | SHA-256 |
|------|--------------|---------|
| CVE_ANALYSIS.md | 9576 | bfe70c38efdc8397839be09a904ff554382f01c250e087f83e899dba00f871f7 |
| php_binary_check.py | 7646 | 4a89739740a363ec839ea1c288632723605e2ff3c9f92da9e13c097e80d4a445 |
| php_cve_audit_local.py | 18714 | dff2d6320ced6d935e0cf520539f2f53f2257333d1a27b46581b9a0b09fd569e |
| php_cve_scanner.py | 23909 | ef89f0a9ef10170745227ab4939e95c36ff352079318823064ff9dd7fc9077b0 |
| README.md | 16193 | 920855993d1857fd0e3d714ad124bb444e761e48311c4dbce4c928021cf40405 |
| SBOM.md | self-referential; verify at deployment | |
| test_mock_server.py | 1800 | b0e70bc3fa9591e77ae07494c5b27aa154deb8022592c61b8c35cfad92af50c8 |
| test_suite.py | 4516 | b4978f0baf65d62372d0426ea460c66d29e7e7c8bc5a6e3ec494147d963aa137 |
| run_scan.ps1 | 3793 | 45f50b386725fd8841f5fdf090072700c46a40a7e5428498c674e61ddef12685 |
| run_scan.sh | 1873 | 1beac595c88a87da7135d38057bf94b447289ecded04ed36d1fd393e2ae02aae |

Note: SBOM.md's own hash is self-referential and therefore left blank; every
other file, including README.md, carries its final hash above. Compute the
SBOM's hash separately at deployment:

    (Get-FileHash SBOM.md -Algorithm SHA256).Hash

Then verify the rest of the suite against section 8:

    # PowerShell
    Get-ChildItem -File | Where-Object Name -match '\.(py|md)$' | ForEach-Object { "{0}  {1}" -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower(), $_.Name }
    # bash
    sha256sum *.py *.md

## 9. Known limitations of this SBOM

1. Component versions are suite-internal labels, not published
   releases; there is no package registry entry.
2. The "Since" column reflects CPython 3.x availability of the APIs as used;
   it is not a guarantee for alternative interpreters (PyPy, etc.).
3. Signature strings are data rather than source attestation. They corroborate
   the OOM patch family and do not independently prove every stale-state reset.
4. Distro validation currently covers Debian (dpkg family) and Remi (RPM
   family). Other distros' packages were not downloaded or checked; see
   CVE_ANALYSIS.md for what that means for verdict trust.

# SBOM - PHP2Shell Detection Suite

Software bill of materials for the tooling in this directory. Generated
2026-10-22 (Australia/Adelaide).

## 1. Suite components

| Component | File | Role | Language | Version |
|-----------|------|------|----------|---------|
| php2shell-network-scanner | php_cve_scanner.py | Network PHP fingerprint and version classification | Python 3 | 1.1 |
| php2shell-local-audit | php_cve_audit_local.py | Local host PHP inventory with binary-signature reconciliation | Python 3 | 1.1 |
| php2shell-binary-check | php_binary_check.py | Standalone binary fix-presence checker | Python 3 | 1.0 |
| php2shell-mock-server | test_mock_server.py | Test harness: mock PHP banner server | Python 3 | 1.0 |
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
| json | JSON report output | 2.7 |
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
| dpkg -l | Debian/Ubuntu | Installed PHP package inventory |
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
| CVE-2026-109619 | Stale-global-state use-after-free (PG(http_globals) not cleared at request shutdown) |
| Fixed versions | 8.2.35, 8.3.36, 8.4.27, 8.5.12 |
| Branches without fix | <= 8.1 (8.1 security-EOL) |
| Advisories | GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp |

### Binary signature strings (ground truth for fix detection)

| String | Requirement | Verified against |
|--------|-------------|------------------|
| memory_hard_limit_percent | required | all 8 upstream tarballs (8.2.34/35, 8.3.35/36, 8.4.26/27, 8.5.11/12) |
| ZEND_MM_MAX_ALLOCS | required | same |
| Hard memory limit of | required | same |
| zend_mm_set_max_allocs | optional (may be stripped) | same |
| Allowed memory size of %zu bytes exhausted at %s:%d ... | corroborating (new format) | same |
| Allowed memory size of %zu bytes exhausted (tried to allocate %zu bytes) | corroborating (old format) | same |

Distro validation: Debian 12 security pool php8.2-cli 8.2.34 (VULNERABLE) /
8.2.35 (PATCHED); Remi EL9 php-cli 8.2.34 (VULNERABLE) / 8.2.35 (PATCHED).
Remi 8.2.35 RPM sha256 verified against repo repodata:
6e330204f30fecb0bb34a8639f737c0dfab26313df593a644a9f125e80c550ff.

## 7. Data produced

| Tool | Output | Format |
|------|--------|--------|
| php_cve_scanner.py | findings.json / findings.csv (--output/--csv) | JSON array of finding objects; CSV rows |
| php_cve_audit_local.py | audit.json / audit.csv (--json/--csv) | JSON array of result objects; CSV rows |
| php_binary_check.py | results.json (--json) | JSON array of per-file results |

All outputs are advisory-only findings with evidence strings; none contain
credentials, payloads or exploit data.

## 8. File integrity (SHA-256)

Computed over the final state of each file. Re-verify after any local edit.

| File | Size (bytes) | SHA-256 |
|------|--------------|---------|
| CVE_ANALYSIS.md | 9248 | 3fb8ff38fa46d3ec99cd73833f8f77948258e8dd2b840117e1b05e6898b9c9f3 |
| php_binary_check.py | 5970 | 41ffd098829e7f6a37153f592bad8b25f7be13e61f5ea49355736317e0ecc127 |
| php_cve_audit_local.py | 11561 | 8e943e9b671239599fc81f32ed7e307a371544c2efbefee7c68e4c37e4ccbc26 |
| php_cve_scanner.py | 20653 | 116ef1eba6063b421a5de6a4767403e8edc40f148c100eaba9bbd68b3fc31962 |
| README.md | 14519 | eb60ea2eb75903842d0bd03c21d651bcd3e4db1efc04d2263b10a54bb9ad8b58 |
| SBOM.md | self-referential; verify at deployment | |
| test_mock_server.py | 1800 | b0e70bc3fa9591e77ae07494c5b27aa154deb8022592c61b8c35cfad92af50c8 |

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

1. Component versions (1.0/1.1) are suite-internal labels, not published
   releases; there is no package registry entry.
2. The "Since" column reflects CPython 3.x availability of the APIs as used;
   it is not a guarantee for alternative interpreters (PyPy, etc.).
3. The signature strings are data, not code: if the upstream fix is ever
   re-released with different strings (unlikely; they are INI names and error
   formats), section 6 must be updated together with the tool constants.
4. Distro validation currently covers Debian (dpkg family) and Remi (RPM
   family). Other distros' packages were not downloaded or checked; see
   CVE_ANALYSIS.md for what that means for verdict trust.

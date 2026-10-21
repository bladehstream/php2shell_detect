# PHP2Shell Detection Suite (CVE-2026-109618 / CVE-2026-109619)

Detection and audit tooling for the two "PHP2Shell" advisories published by
the PHP security team in October 2026. Both are memory-corruption bugs
reachable by any HTTP request against a vanilla PHP installation; no specific
application code is required. Suite contents:

| File | Purpose | Runs on |
|------|---------|---------|
| php_cve_scanner.py | Network scanner: fingerprints PHP over HTTP and classifies versions against fixed thresholds | Any machine with network reachability to targets |
| php_cve_audit_local.py | Local host audit: inventories PHP binaries, packages and processes, with binary-signature verification | The host being audited (or pushed via config management) |
| php_binary_check.py | Standalone checker: detects the actual fix inside a compiled PHP binary, independent of its version string | Any machine that can read the binary file |
| test_mock_server.py | Local mock web server for validating the scanner before production use | Anywhere |
| CVE_ANALYSIS.md | Root-cause analysis from diffing the official php-src tarballs, signature derivation and distro validation | Documentation |
| SBOM.md | Software bill of materials for this suite | Documentation |

Both CVEs are fixed in PHP 8.2.35, 8.3.36, 8.4.27 and 8.5.12. PHP 8.1 and
earlier receive no fix (8.1 is security-EOL) and must be treated as vulnerable
regardless of patch level.

## 1. How detection works

The suite uses four independent detection methods, ordered from widest reach
to highest certainty. Understanding the layering matters: no single method is
conclusive on its own, and the ones that are conclusive require access the
network scanner does not have.

### 1.1 Network fingerprinting (php_cve_scanner.py, default mode)

Sends plain GET requests and reads response headers:

1. X-Powered-By header. PHP embeds its version here unless expose_php is
   turned off. The most common leak and the default first probe.
2. Session-cookie probe. If no banner appears, the scanner appends a
   PHPSESSID query parameter to each path; a PHP session Set-Cookie response
   confirms the runtime without revealing the version.
3. Path probing. Twelve default paths (index.php, info.php, phpinfo.php,
   cgi-bin/php handlers, etc.), overridable with --paths.
4. CGI handler probes (--path-traversal flag). Additional benign probes for
   hosts running PHP through cgi-bin handlers rather than mod_php or FPM.

Every version found is compared against the fixed threshold for its branch:

| Branch | First fixed version |
|--------|---------------------|
| 8.2    | 8.2.35              |
| 8.3    | 8.3.36              |
| 8.4    | 8.4.27              |
| 8.5    | 8.5.12              |
| <= 8.1 | no fix exists       |

Output buckets:

- PATCH: version detected, below the fixed version for its branch.
- NO-FIX: branch has no fix at all (7.4, 8.0, 8.1 and older).
- UNKNOWN: PHP present but version unreadable.
- OK: at or above the fixed version for its branch.

### 1.2 Deep presence probing (--deep-presence)

Catches hosts that hide their banner (expose_php = Off) and never emit
session cookies on the probed paths. Three additional benign GET checks:

1. php-fpm missing-script fingerprint. A request for a random nonexistent
   .php path gets an exact "File not found." 404 body when it reaches the
   FastCGI backend. Static servers and other runtimes do not produce this
   exact response.
2. fpm-ping / fpm-status endpoints. Default nginx + php-fpm configs expose
   /fpm-ping ("pong") and /fpm-status ("pool:" table); /ping and /status
   variants are also probed.
3. PHP error signatures in response bodies ("Fatal error", "Parse error",
   "Deprecated: ", "Undefined variable", "Undefined index"), which identify
   the runtime even with all metadata hidden.

None of these touch any code path related to either CVE. Findings are
reported as UNKNOWN version, PHP present, because none of them reveal the
version.

### 1.3 FastCGI port check (--fpm-port 9000)

A TCP connect-only check of a port where php-fpm commonly listens. No FastCGI
protocol data is sent. An open 9000 on a host that is silent on HTTP ports is
a strong php-fpm hint, but the port could be another service, so it is
reported as a lead rather than a verdict.

### 1.4 Binary signature verification (php_binary_check.py and the local audit)

The definitive method. Diffing the official php-src tarballs for each
affected/fixed pair (see CVE_ANALYSIS.md) shows that the fix introduced
strings that exist in every fixed build and none of the affected builds:

    memory_hard_limit_percent    (new INI directive)
    ZEND_MM_MAX_ALLOCS           (env var read at request startup)
    Hard memory limit of         (new hard-limit error message)

All three are required. A fourth (zend_mm_set_max_allocs, a symbol name) is
checked but optional, since release builds may strip it. Two more signals
corroborate: the new OOM format variant ("Allowed memory size of %zu bytes
exhausted at %s:%d") should be present in patched builds, while the old
format alone supports a VULNERABLE verdict.

The checker reports PATCHED, VULNERABLE or UNKNOWN with per-string evidence.
UNKNOWN (partial match) means possible partial backport or a build compiled
without ZEND_MM_LIMIT; it never guesses.

This method is immune to the classic version-string problem: Linux distros
frequently backport security fixes without bumping the reported version, so a
host claiming "8.2.34" may actually be fixed. The signature check resolves
that ambiguity in both directions - it also catches a custom build claiming a
fixed version while lacking the fix.

Validated against real distro packages (Debian 12 security pool and Remi EL9,
both affected and fixed builds, with the Remi 8.2.35 RPM sha256-verified
against its repo's published repodata). Full validation table in
CVE_ANALYSIS.md. For these two distros, version and signature verdicts agree
for this fix; the mismatch-detection path remains the safety net for distros
that were not tested.

### 1.5 What the local audit combines

php_cve_audit_local.py inventories PHP from three angles and reconciles the
evidence:

1. Binaries on PATH (php, php8.2 ... php5.6), each checked with
   php --version AND the binary signature probe.
2. OS packages via dpkg -l (Debian/Ubuntu) or rpm -qa (RHEL/SUSE), filtered
   to PHP packages; on Windows, common install paths.
3. Running processes (php-fpm, php-cgi, tasklist on Windows) so versions the
   package manager no longer tracks are not missed.

Where version and signature agree, the verdict is simple. Where they
disagree, the audit reports the discrepancy explicitly:

- version says vulnerable, signatures present: backported fix, treat as
  PATCHED (this is the silent-backport catch).
- version says fixed, signatures absent: possible custom/foreign build,
  manual review.
- partial signature match: manual review.

## 2. Prerequisites

### For the network scanner (php_cve_scanner.py)

- Python 3.10 or newer (developed and tested on 3.13). Standard library
  only - no third-party packages (see SBOM.md).
- Network reachability from the scanning host to the target subnet on the
  ports you configure (defaults: 80, 8080, 8000 HTTP; 443, 8443 HTTPS).
- Authorisation to scan the target range. The scanner is passive (GET only,
  fixed User-Agent string "php2shell-cve-scanner/1.0 ...") but any network
  scan is still a scan: run it inside your authorised window and tell your
  SOC the User-Agent to expect.
- Sufficient file descriptors/thread quota for your --threads setting
  (default 64).

### For the local audit (php_cve_audit_local.py)

- Python 3.10+ on the target host, or any Python able to run over SSH/WinRM.
- No third-party packages. No admin rights needed: everything it reads
  (PATH binaries, package databases via dpkg/rpm, process lists) is
  readable on a normal system. It never writes outside the output files
  you name.
- For deployment at scale: whatever config-management channel you already
  run (Ansible, Salt, SCCM, Intune). One JSON per host, aggregated centrally.

### For the binary checker (php_binary_check.py)

- Python 3.10+, standard library only.
- Read access to the PHP binary or shared library under test. For mod_php the
  relevant file is the module, e.g. /usr/lib/apache2/modules/libphp8.2.so.

### For the mock server (test_mock_server.py)

- Python 3.10+, standard library only. Binds 127.0.0.1:8080 for 20 seconds.

## 3. Usage

### Network scan of a subnet

    python php_cve_scanner.py --subnet 10.0.0.0/24 --threads 128 --output findings.json --csv findings.csv

### Single host, custom port, internal TLS

    python php_cve_scanner.py --target 10.0.0.15 --port 8443 --https --insecure

### Deep presence mode (hidden PHP)

    python php_cve_scanner.py --subnet 10.0.0.0/24 --deep-presence

### FastCGI port lead

    python php_cve_scanner.py --subnet 10.0.0.0/24 --fpm-port 9000

### Custom path list

    python php_cve_scanner.py --target 10.0.0.15 --paths mypaths.txt

### Local audit of a host

    python php_cve_audit_local.py --json audit.json --csv audit.csv

### Binary check

    python php_binary_check.py /usr/bin/php
    python php_binary_check.py /usr/lib/apache2/modules/libphp8.2.so
    python php_binary_check.py C:\php\php8.dll
    python php_binary_check.py C:\php\binaries\ --dir

### Validate before production use

    # terminal 1
    python test_mock_server.py
    # terminal 2
    python php_cve_scanner.py --target 127.0.0.1 --port 8080 --http

The mock server serves four paths with different fake banners (8.2.34
vulnerable, 8.3.36 patched, 7.4.33 no-fix, 8.5.11 vulnerable) plus a php-fpm
"File not found." fingerprint on random missing .php paths, so all detection
paths can be exercised locally.

## 4. Interpreting results

- A PATCH or NO-FIX network finding is a strong signal but not proof: distros
  may backport fixes without bumping the reported version string. Cross-check
  with the local audit or binary checker before declaring a host clean, and
  before declaring it vulnerable enough to warrant emergency change control.
- An OK from the network scanner means the banner reports a fixed version;
  combined with the backport caveat this is good-faith evidence, not proof.
- A binary-signature PATCHED verdict is the strongest remotely verifiable
  evidence available and overrides the version string in the local audit's
  reconciliation.
- Absence of any network finding does not prove absence of PHP. expose_php =
  Off hides the banner; apps may not emit session cookies on probed paths;
  WAFs, unusual paths and firewalled FastCGI listeners all reduce
  visibility. Deep-presence mode narrows this gap substantially but the only
  complete closure is the local audit.
- For audit trails, keep the JSON output: every finding carries its evidence
  (header value, cookie string, signature hits) not just the verdict.

## 5. Safety notes

- The scanner only issues GET requests with a fixed User-Agent string, so it
  is easy to recognise and filter in web logs.
- No probe in this suite sends a payload, exercises any code path connected
  to either CVE, or attempts exploitation. A behavioural vulnerability probe
  (one that distinguishes vulnerable from patched by triggering the bug)
  would by definition exercise the crash path on the target's own php-fpm
  workers and is deliberately not implemented. If you need behavioural
  confirmation, that is controlled incident-response or pentest work in a
  maintenance window, not a scanning task.
- The --fpm-port check opens one TCP connection and closes it; some
  intrusion-detection systems log bare connects. Tell your SOC.
- Rate: default 64 threads is gentle. Scale --threads to taste but be aware
  of load balancers, rate limiters and php-fpm worker pool exhaustion on
  small targets.
- Run from a management subnet or jump host. No agent install on targets.

## 6. Limitations and honesty about certainty

1. Version strings can lie in both directions (backported fixes that do not
   bump the version; custom builds that claim a version they do not have).
   The binary signature check is the corrective, and it is validated on
   Debian and Remi packages, but not yet on Ubuntu, Alpine, SUSE, Oracle
   Linux or Amazon Linux builds. If those are in your estate, run the local
   audit on one host per distro first and check for version/signature
   mismatch flags before full rollout.
2. Static or packed binaries may not show strings on disk that exist in the
   decompressed in-memory image. Rare for distro PHP; reported as UNKNOWN.
3. Exotic builds compiled without ZEND_MM_LIMIT lack the "Hard memory limit
   of" string even when patched; reported as UNKNOWN, never guessed.
4. Distro source packages apply their own patch series on top of upstream.
   The validation against Debian and Remi covers the two most common
   packaging styles; if you audit a distro with heavier patching, verify one
   package against that distro's patched source before trusting VULNERABLE.
5. Network silence is not proof of absence (see 1.2/1.3). Only the local
   audit closes the gap completely.
6. The signature set is specific to this fix. When the next PHP security
   release ships, the signatures must be re-derived by diffing the new
   affected/fixed pair; the strings describe this fix's architecture
   (fallible allocation + delayed OOM), not PHP generally.
7. The analysis in CVE_ANALYSIS.md used only official php.net tarballs plus
   the two distro validations noted. The NCSC-NL php2shell advisory
   (https://github.com/NCSC-NL/php2shell/blob/main/README.md) independently
   documents the same bug class with consistent mitigations and hunt
   indicators; that agreement is a useful external cross-check.

## 7. Quick reference

    # network sweep
    python php_cve_scanner.py --subnet 10.0.0.0/24 --threads 128 --output findings.json --csv findings.csv

    # hidden-PHP hunt
    python php_cve_scanner.py --subnet 10.0.0.0/24 --deep-presence --fpm-port 9000

    # host audit
    python php_cve_audit_local.py --json audit.json

    # ground truth on a binary
    python php_binary_check.py /usr/bin/php

## 8. Files and integrity

SHA-256 hashes for every file in this suite are recorded in SBOM.md. Verify
before deployment:

    # PowerShell
    Get-ChildItem php2shell-scanner -File | ForEach-Object { (Get-FileHash $_.FullName -Algorithm SHA256).Hash }
    # bash
    sha256sum php2shell-scanner/*

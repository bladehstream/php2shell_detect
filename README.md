# PHP2Shell Detection Suite (CVE-2026-109618 / CVE-2026-109619)

Defensive inventory tooling for the two "PHP2Shell" advisories published by
the PHP security team in October 2026. The suite uses safe HTTP fingerprinting,
authenticated host inventory, package provenance and static OOM-patch
indicators. It does not send multipart, memory-exhaustion, FastCGI execution
or PHP-CGI command-line probes. Suite contents:

| File | Purpose | Runs on |
|------|---------|---------|
| php_cve_scanner.py | Network scanner: fingerprints PHP over HTTP and classifies versions against fixed thresholds | Any machine with network reachability to targets |
| php_cve_audit_local.py | Local host audit: inventories PHP binaries, packages, Apache modules and running processes | The host being audited (or pushed via config management) |
| php_binary_check.py | Static OOM-patch evidence for an identified compiled PHP binary or library | Any machine that can read the binary file |
| test_mock_server.py | Local mock web server for validating the scanner before production use | Anywhere |
| test_suite.py | Positive and negative automated regression tests | Anywhere |
| CVE_ANALYSIS.md | Root-cause analysis from diffing the official php-src tarballs, signature derivation and distro validation | Documentation |
| SBOM.md | Software bill of materials for this suite | Documentation |

Both CVEs are fixed upstream in PHP 8.2.35, 8.3.36, 8.4.27 and 8.5.12. PHP
8.1 and earlier have no fixed upstream maintenance release, but vendor and
source backports exist. Exact package/build provenance is required.

## 1. How detection works

The suite layers network leads, local package/runtime evidence and static
binary indicators. No single method is universally conclusive.

### 1.1 Network fingerprinting (php_cve_scanner.py, default mode)

Sends plain GET requests and reads response headers:

1. X-Powered-By header. PHP embeds its version here unless expose_php is
   turned off. The most common leak and the default first probe.
2. Organic PHP session cookies. Values are redacted; only the cookie name and
   value length are retained.
3. Path probing. Common paths (index.php, info.php, phpinfo.php,
   cgi-bin/php handlers, etc.), overridable with --paths.

Redirects and environment proxies are disabled to prevent findings being
misattributed to another host. Response headers are handled case-insensitively
and duplicate headers are preserved.

Every version found is compared against the fixed threshold for its branch:

| Branch | First fixed version |
|--------|---------------------|
| 8.2    | 8.2.35              |
| 8.3    | 8.3.36              |
| 8.4    | 8.4.27              |
| 8.5    | 8.5.12              |
| <= 8.1 | no fixed upstream maintenance release; verify vendor/source backport |

Output buckets:

- PATCH: version detected, below the fixed version for its branch.
- NO-FIX: branch has no fixed upstream release; vendor/source evidence is needed.
- UNKNOWN: PHP present but version unreadable.
- OK: at or above the fixed version for its branch.

### 1.2 Deep presence probing (--deep-presence)

Catches some hosts that hide their banner. Three additional ordinary GET checks:

1. php-fpm missing-script fingerprint. A request for a random nonexistent
   .php path gets an exact "File not found." 404 body when it reaches the
   FastCGI backend. This is still heuristic evidence and can be imitated.
2. fpm-ping / fpm-status endpoints. Default nginx + php-fpm configs expose
   /fpm-ping ("pong") and /fpm-status ("pool:" table); /ping and /status
   variants are also probed.
3. PHP error signatures in error responses. Application or documentation
   content can imitate these strings, so they remain leads.

None of these touch any code path related to either CVE. Findings are
reported as UNKNOWN version, PHP present, because none of them reveal the
version.

### 1.3 FastCGI port check (--fpm-port 9000)

A TCP connect-only check of a port where php-fpm commonly listens. No FastCGI
protocol data is sent. An open 9000 on a host that is silent on HTTP ports is
a strong php-fpm hint, but the port could be another service, so it is
reported as a lead rather than a verdict.

### 1.4 Binary signature verification (php_binary_check.py and the local audit)

Diffing the official php-src tarballs for each affected/fixed pair (see
CVE_ANALYSIS.md) found strings introduced by the new OOM memory manager:

    memory_hard_limit_percent    (new INI directive)
    ZEND_MM_MAX_ALLOCS           (env var read at request startup)
    Hard memory limit of         (new hard-limit error message)

All three are required for a positive OOM-signature result. A fourth
(`zend_mm_set_max_allocs`) is optional because release builds may strip it.

The checker reports OOM_FIX_SIGNATURES_PRESENT, OOM_FIX_SIGNATURES_ABSENT,
PARTIAL_OOM_FIX_SIGNATURES or NOT_PHP_RUNTIME. It validates ELF/PE/Mach-O and
PHP applicability before interpreting strings.

These signatures are corroborating evidence for the CVE-2026-109618 OOM-fix
family. They do not independently prove that every CVE-2026-109619 state-reset
change was included in a vendor/custom backport. A complete fixed verdict
requires upstream or vendor package/source provenance covering both CVEs.

Validated against real distro packages (Debian 12 security pool and Remi EL9,
both affected and fixed builds, with the Remi 8.2.35 RPM sha256-verified
against its repo's published repodata). Full validation table in
CVE_ANALYSIS.md. For these two distros, version and signature verdicts agree
for this fix; the mismatch-detection path remains the safety net for distros
that were not tested.

### 1.5 What the local audit combines

php_cve_audit_local.py inventories PHP from several angles:

1. PATH and common CLI/FPM/CGI/cPanel/Plesk/CloudLinux/Remi/LiteSpeed paths.
2. Narrowly matched DPKG/RPM PHP runtime packages, including published Ubuntu
   package floors for both CVEs.
3. Running PHP-family processes resolved through `/proc/<pid>/exe` on Linux.
4. Loaded Apache `libphp*.so` modules found through `/proc/<pid>/maps`.
5. Common Windows PHP paths and process names (with less complete provenance).

Package and process evidence are reported separately. A fixed package on disk
does not prove that old workers restarted. Confirm loaded paths, process start
times, service restarts and container image digests before closure.

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
- No third-party packages. Elevated rights improve access to other users'
  `/proc/<pid>/maps`; without them, inaccessible process evidence is skipped.
  It never writes outside the output files you name.
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

    python -m unittest -v test_suite.py

    # terminal 1
    python test_mock_server.py
    # terminal 2
    python php_cve_scanner.py --target 127.0.0.1 --port 8080 --http

The mock server serves four paths with different fake banners (8.2.34
vulnerable, 8.3.36 patched, 7.4.33 no-fix, 8.5.11 vulnerable) plus a php-fpm
"File not found." fingerprint on random missing .php paths, so all detection
paths can be exercised locally.

Exit codes are automation-friendly: `0` means no affected/unknown result,
`1` means no configured network endpoint was reachable or the command failed,
`2` means affected evidence was found, and `3` means PHP evidence requires
 manual provenance review.
Command-line usage errors also exit 1, not 2, so that a malformed invocation
can never be mistaken for an affected finding.

Reference consumers that translate this contract into operationally labelled
results (PASS / FAIL-INFRA / FAIL-AFFECTED / REVIEW) are included:

    # PowerShell (works with -File, scheduled tasks)
    .\run_scan.ps1 -Mode scan -Subnet 10.20.0.0/24
    .\run_scan.ps1 -Mode audit
    .\run_scan.ps1 -Mode scan -Target 10.0.0.5 -ExtraArgs "--port,8080,--http"

    # bash
    ./run_scan.sh scan --subnet 10.20.0.0/24
    ./run_scan.sh audit

Both write timestamped JSON/CSV into --OutputDir or PHP2SHELL_OUTDIR
(default ./php2shell-results), print a human-readable verdict, emit a JSON
summary object, and propagate the tool's exit code so CI can gate on it.
Adapt these rather than re-deriving the mapping in each downstream script.

## 4. Interpreting results

- A PATCH or NO-FIX network finding is a strong signal but not proof: distros
  may backport fixes without bumping the reported version string. Cross-check
  with the local audit or binary checker before declaring a host clean, and
  before declaring it vulnerable enough to warrant emergency change control.
- An OK from the network scanner means the banner reports a fixed version;
  combined with the backport caveat this is good-faith evidence, not proof.
- OOM fix signatures corroborate CVE-2026-109618 remediation but do not, by
  themselves, prove the complete CVE-2026-109619 state-reset patch.
- Absence of any network finding does not prove absence of PHP. expose_php =
  Off hides the banner; apps may not emit session cookies on probed paths;
  WAFs, unusual paths and firewalled FastCGI listeners all reduce
  visibility. Deep-presence mode narrows this gap; package, process, container,
  appliance and cloud inventory are still required for complete coverage.
- For audit trails, keep the JSON output. Cookie values are deliberately
  redacted; evidence retains only cookie name and value length.

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
- PHP-CGI `-s`, `-d` and `-v` query options are deliberately not sent. They
  test an unrelated CGI surface and can disclose source or change behavior.
- Redirects and environment proxies are disabled to avoid sending internal
  targets elsewhere or attributing a destination's PHP to the original host.
- Rate: default 64 threads is gentle. Scale --threads to taste but be aware
  of load balancers, rate limiters and php-fpm worker pool exhaustion on
  small targets.
- Run from a management subnet or jump host. No agent install on targets.

## 6. Limitations and honesty about certainty

1. Version strings can lie in both directions (backported fixes that do not
   bump the version; custom builds that claim a version they do not have).
   Binary signatures are corroborating evidence, validated on
   Debian and Remi packages, but not yet on Ubuntu, Alpine, SUSE, Oracle
   Linux or Amazon Linux builds. If those are in your estate, run the local
   audit on one host per distro first and check for version/signature
   mismatch flags before full rollout.
2. Static or packed binaries may not expose the expected strings on disk.
   Partial or absent evidence must be reconciled with vendor provenance.
3. Exotic builds compiled without relevant memory-limit features can lack
   strings even when patched; absence is medium-confidence evidence.
4. Distro source packages apply their own patch series on top of upstream.
   The validation against Debian and Remi covers the two most common
   packaging styles; if you audit a distro with heavier patching, verify one
   package against that distro's patched source before trusting VULNERABLE.
5. Network silence is not proof of absence. The local audit also cannot see
   every container, appliance, network filesystem or proprietary runtime.
6. The signature set is specific to this fix. When the next PHP security
   release ships, the signatures must be re-derived by diffing the new
   affected/fixed pair; the strings describe this fix's architecture
   (fallible allocation + delayed OOM), not PHP generally.
7. The analysis in CVE_ANALYSIS.md used only official php.net tarballs plus
   the two distro validations noted. The NCSC-NL php2shell advisory
   (https://github.com/NCSC-NL/php2shell/blob/main/README.md) independently
   documents the same bug class with consistent mitigations and hunt
   indicators; that agreement is a useful external cross-check.

The audit also embeds NCSC-NL/Canonical fixed package floors for Trusty PHP
5.5, Xenial 7.0, Bionic 7.2, Focal 7.4, Jammy 8.1, Noble 8.3, Resolute 8.5
and Stonking 8.5. Some older packages require Ubuntu Pro/ESM. Other vendors
must be evaluated against their own advisories.

This suite inventories exposure; it is not a compromise detector. PHP notes
that some paths may leave no predictable log entry. Expel recommends also
monitoring for PHP/web workers spawning shells or downloaders, changed PHP
files in web roots, unexpected outbound connections, and spikes in fatal
errors, memory exhaustion or crashing workers. Updating and restarting every
FPM, mod_php and long-running PHP worker remains the only complete fix.

## 7. Quick reference

    # network sweep
    python php_cve_scanner.py --subnet 10.0.0.0/24 --threads 128 --output findings.json --csv findings.csv

    # hidden-PHP hunt
    python php_cve_scanner.py --subnet 10.0.0.0/24 --deep-presence --fpm-port 9000

    # host audit
    python php_cve_audit_local.py --json audit.json

    # corroborating OOM-patch evidence on a binary
    python php_binary_check.py /usr/bin/php

## 8. Files and integrity

SHA-256 hashes for every file in this suite are recorded in SBOM.md. Verify
before deployment:

    # PowerShell
    Get-ChildItem -File | Where-Object Name -match '\.(py|md)$' | ForEach-Object { (Get-FileHash $_.FullName -Algorithm SHA256).Hash }
    # bash
    sha256sum *.py *.md

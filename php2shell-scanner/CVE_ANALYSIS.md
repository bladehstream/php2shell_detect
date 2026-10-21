# CVE-2026-109618 / CVE-2026-109619 - Patch Diff Analysis

Analysis based on diffing the official php-src tarballs:

    php-8.2.34 <-> php-8.2.35
    php-8.3.35 <-> php-8.3.36
    php-8.4.26 <-> php-8.4.27
    php-8.5.11 <-> php-8.5.12

## What the fix actually changes

### CVE-2026-109618 - OOM bailout memory corruption

The pre-fix memory manager treats an allocation failure at the memory limit as
a "bailout": it longjmps to a safe state and continues execution. Across the
request-parsing and VM paths this bailout can leave partially-constructed data
structures in place, which an attacker can groom into exploitable memory
corruption. Upstream's fix is a structural rework rather than a local patch:

1. Fallible allocation family. New femalloc/fecalloc/ferealloc/safe_femalloc/
   safe_ferealloc (and fpemalloc/persistent variants) return NULL on
   would-exceed-limit instead of bailout. Added in Zend/zend_alloc.c/.h.
2. Delayed OOM state machine. New zend_oom_state enum (NONE/PENDING/HANDLING/
   HANDLED) and EG(delayed_oom) struct carrying message/filename/lineno.
   zend_handle_delayed_oom() defers the fatal until a VM interrupt checkpoint,
   so the request unwinds cleanly instead of mid-opcode. Added to
   zend_vm_def.h interrupt helper and every frameless/internal call site.
3. Request parsing aborts on OOM. php_variables.c now returns FAILURE from
   add_post_var/add_post_vars when ZEND_HAS_OOM() is true, rfc1867.c bails out
   of multipart parsing, and SAPI.c calls zend_handle_delayed_oom() after
   post handling. Before the fix, parsing continued and registered
   partially-constructed variables after the bailout.
4. Hard memory limit. New memory_hard_limit_percent INI directive (default
   200% of memory_limit, or a fixed 1G buffer when memory_limit >= 1G).
   Enforced in the allocator with a new error string.
5. array_init() -> array_init_singleton() in variable registration paths
   (php_variables.c), reducing allocations during GPC registration.

### CVE-2026-109619 - stale global state use-after-free

php_request_shutdown() destroyed PG(http_globals)[0..NUM_TRACK_VARS] (the
GET/POST/COOKIE/... superglobals) but left the slots pointing at freed zvals.
Anything touching them before the next php_request_startup() - including RINIT
of an extension loaded later, or a second request in the same process on SAPIs
that skip full re-initialisation - dereferenced freed memory.

The fix:

1. ZVAL_UNDEF(&PG(http_globals)[i]) immediately after each zval_ptr_dtor.
2. EG(delayed_oom).state = ZEND_OOM_STATE_NONE at both start and end of
   shutdown, so stale OOM state cannot leak across requests either.
3. PG(modules_activated) = 0 on shutdown, so anything checking it before
   re-activation sees the correct state.
4. clear_last_error() before shutdown_memory_manager(), closing a related
   last-error use-after-free window.
5. php_child_init() now calls php_clear_stat_cache(true, NULL, 0), so a
   forked FPM child does not inherit a stale stat cache.

Both fixes are in the same release because both were coordinated by the PHP
security team; the shared root cause is that request-state cleanup and
allocation-failure handling assumed a single clean request lifecycle.

## Ground-truth binary signatures

The diff shows the fix introduced strings that exist in every fixed build and
none of the affected builds, verified against all eight tarballs:

    memory_hard_limit_percent       (new INI directive name)
    ZEND_MM_MAX_ALLOCS              (env var read at request startup)
    Hard memory limit of            (new hard-limit error message)
    zend_mm_set_max_allocs          (new API symbol; may be stripped)

Verification matrix:

    php-8.2.34  0 hits  VULNERABLE
    php-8.2.35  19 hits PATCHED
    php-8.3.35  0 hits  VULNERABLE
    php-8.3.36  19 hits PATCHED
    php-8.4.26  0 hits  VULNERABLE
    php-8.4.27  19 hits PATCHED
    php-8.5.11  0 hits  VULNERABLE
    php-8.5.12  19 hits PATCHED

This matters because Linux distributions frequently backport security fixes
without bumping the version string, so a host reporting "PHP 8.2.34" from a
distro package may actually be fixed. A version check alone cannot tell; the
binary string check can.

### Validation against real distro packages

The signatures were validated against actual distro-built binaries, not just
upstream tarballs:

| Package | Version claim | Signature verdict | Expected | Result |
|---------|---------------|-------------------|----------|--------|
| Debian 12 security: php8.2-cli_8.2.34-1~deb12u1 | 8.2.34 | 0/3 hits | VULNERABLE | pass |
| Debian 12 security: php8.2-cli_8.2.35-1~deb12u1 | 8.2.35 | 3/3 hits | PATCHED | pass |
| Remi EL9: php-cli-8.2.34-1.module_php.8.2.el9.remi | 8.2.34 | 0/3 hits | VULNERABLE | pass |
| Remi EL9: php-cli-8.2.35-1.module_php.8.2.el9.remi | 8.2.35 | 3/3 hits | PATCHED | pass |

Details:

- Debian packages came from security.debian.org (pool/updates/main/p/php8.2).
  Both the last-affected (8.2.34) and fixed (8.2.35) builds were checked;
  /usr/bin/php8.2 extracted from each package's data.tar.xz.
- Remi packages came from rpms.remirepo.net (enterprise/9/php82/x86_64), with
  the 8.2.35 RPM's sha256 verified against the repo's primary.xml repodata
  (6e330204f30fecb0bb34a8639f737c0dfab26313df593a644a9f125e80c550ff) before
  use. /usr/bin/php extracted from each RPM's zstd+cpio payload.
- In every case the binary's embedded version string matched the package
  version claim, so the signature verdicts are correctly attributed.
- Remi ships unpatched upstream versions rather than backports, so its 8.2.34
  is genuinely vulnerable; Debian backports most fixes into 8.2.34 between
  releases but the OOM rework only arrived with 8.2.35 there as well.

Consequence for the backport caveat above: at least for these two distros and
this specific fix, version-string verdicts and signature verdicts agree.
Whether other distros (Ubuntu, Alpine, SUSE, Oracle Linux, Amazon Linux) ship
the OOM rework without bumping their version epoch remains to be checked, but
the signature check now has a proven correct baseline on both .deb and .rpm
packaging, and its mismatch detection path (version vs signature disagreement)
is exactly how a silent backport would be caught on such a distro.

Tools using these signatures:

- php_binary_check.py - standalone checker for any binary/library, including
  a --dir mode for scanning a filesystem image or package directory tree.
- php_cve_audit_local.py - the local audit now combines the version check with
  the binary signature check and reports the reconciled verdict, flagging
  version-string/backport mismatches explicitly instead of guessing.

## Also interesting: what else shipped in the same release

The fixed versions contain a large amount of OOM-related hardening beyond the
two CVEs (the diffs touch 430-734 files per branch). Notable items that
suggest the memory-manager rework is the leading edge of a broader hardening
campaign, worth watching for follow-up advisories:

- ZEND_MM_MAX_ALLOCS env var and exit status 121 (ZEND_MM_MAX_ALLOCS_EXIT_STATUS)
  for fuzzing/reproduction harnesses, read in php_request_startup().
- memory_hard_limit_percent INI (PHP_INI_ALL, so settable per-directory).
- php_child_init() stat-cache clearing.
- New phpt tests: oom_request_parsing.phpt, oom_request_parsing_next_request.phpt,
  oom_shutdown_function_next_request.phpt and 80+ OOM-focused tests in
  Zend/tests/, indicating systematic coverage of bailout paths.
- rfc1867.c now filters multipart headers it does not use and deduplicates,
  separate hardening for the multipart parser.

## External cross-reference

The NCSC Netherlands php2shell advisory
(https://github.com/NCSC-NL/php2shell/blob/main/README.md) independently
documents the same vulnerability class. Their mitigation list matches the
code paths identified here: session.upload_progress.enabled=0 and
fatal_error_backtraces=0 reduce exposure to the OOM bailout path,
memory_limit and post_max_size sizing affects trigger feasibility, and their
hunt indicators (unexpected OOM fatal errors, worker crashes following large
POST or multipart requests) correspond to the trigger conditions in the
upstream oom_request_parsing.phpt tests. The agreement between an independent
national CERT analysis and the patch diff is a strong signal the root-cause
assessment is correct.

## Caveats

- The signature check reads the raw binary. Staticly-linked or UPX-packed
  binaries will still match if strings are present in the decompressed image
  in memory, but not from the on-disk file. This is rare for PHP distro
  packages; flag it for manual review via the partial-match path.
- Some exotic builds (e.g. some hardened/custom-built PHP) may compile out
  ZEND_MM_LIMIT entirely, in which case the "Hard memory limit of" string is
  absent even in a patched build; the tool reports this as partial match
  (UNKNOWN) rather than guessing.
- Only the official php.net tarballs were used for this analysis. Distro
  source packages (e.g. Debian's php8.2_8.2.34-1.debian.tar.xz) apply their
  own patch series and may reorder or rename; if you audit distro packages,
  verify against the distro's patched source before trusting a VULNERABLE
  verdict.

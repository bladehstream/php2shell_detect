#!/usr/bin/env bash
# Reference consumer for php_cve_scanner.py / php_cve_audit_local.py exit codes.
#
# Exit contract (README.md):
#   0  completed; no affected and no unknown PHP evidence
#   1  command error, or (scanner only) zero endpoints reachable
#   2  affected (vulnerable) evidence found
#   3  PHP evidence requires manual provenance review
#
# Usage:
#   ./run_scan.sh scan  --subnet 10.20.0.0/24
#   ./run_scan.sh audit
#   ./run_scan.sh scan  --target 10.20.0.5 --https --insecure

set -u

MODE="${1:-}"; shift || true
OUTDIR="${PHP2SHELL_OUTDIR:-./php2shell-results}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)" || {
    echo "could not resolve scanner directory" >&2
    exit 1
}

case "$MODE" in
  scan|audit) ;;
  *)
    echo "usage: $0 {scan|audit} [tool arguments...]" >&2
    exit 1
    ;;
esac

if ! command -v python3 >/dev/null 2>&1 && ! command -v python >/dev/null 2>&1; then
    echo "python is required on PATH" >&2
    exit 1
fi
PY="$(command -v python3 || command -v python)"

if [ "$MODE" = scan ] && [ $# -eq 0 ]; then
    echo "scan mode requires target arguments (e.g. --subnet x.x.x.x/yy)" >&2
    exit 1
fi

if ! mkdir -p "$OUTDIR"; then
    echo "could not create output directory: $OUTDIR" >&2
    exit 1
fi
STAMP="$(date +%Y%m%d-%H%M%S)"

if [ "$MODE" = scan ]; then
    JSON="$OUTDIR/findings-$STAMP.json"
    CSV="$OUTDIR/findings-$STAMP.csv"
    TOOL="$SCRIPT_DIR/php_cve_scanner.py"
    ARGS=("$TOOL" --output "$JSON" --csv "$CSV" "$@")
else
    JSON="$OUTDIR/audit-$STAMP.json"
    CSV="$OUTDIR/audit-$STAMP.csv"
    TOOL="$SCRIPT_DIR/php_cve_audit_local.py"
    ARGS=("$TOOL" --json "$JSON" --csv "$CSV" "$@")
fi

if [ ! -f "$TOOL" ]; then
    echo "scanner component not found: $TOOL" >&2
    exit 1
fi

"$PY" "${ARGS[@]}"
CODE=$?

# Do not interpret an arbitrary interpreter failure code as a security result.
# Codes 0/2/3 are trusted only with valid JSON plus the expected CSV artifact.
RESULTS_VALID=false
if [ "$CODE" -eq 0 ] || [ "$CODE" -eq 2 ] || [ "$CODE" -eq 3 ]; then
    if [ -f "$JSON" ] && [ -f "$CSV" ] && \
       "$PY" -c 'import json,sys; json.load(open(sys.argv[1], encoding="utf-8"))' "$JSON"; then
        RESULTS_VALID=true
    else
        echo "expected result files are missing or invalid; treating this as an infrastructure failure" >&2
        CODE=1
    fi
fi

case $CODE in
  0) echo "COMPLETE-NO-FINDINGS: no affected or reviewable PHP evidence was observed; absence of evidence is not proof of remediation." ;;
  1) echo "FAIL-INFRA: command error or no reachable endpoint; not a security result." >&2 ;;
  2) echo "FAIL-AFFECTED: affected PHP evidence found; review $JSON and $CSV." >&2 ;;
  3) echo "REVIEW: PHP evidence needs manual provenance review; assign $JSON and $CSV." >&2 ;;
  *) echo "UNKNOWN-EXIT ($CODE): treat as tool failure." >&2 ;;
esac

"$PY" -c 'import json,sys; print(json.dumps({"mode":sys.argv[1],"exit_code":int(sys.argv[2]),"summary":sys.argv[3],"results_valid":sys.argv[4]=="true","json":sys.argv[5],"csv":sys.argv[6]}))' \
    "$MODE" "$CODE" \
    "$(case $CODE in 0) echo complete-no-findings;; 1) echo infra-fail;; 2) echo affected-found;; 3) echo manual-review;; *) echo unknown;; esac)" \
    "$RESULTS_VALID" "$JSON" "$CSV"

exit $CODE

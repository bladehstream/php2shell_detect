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

mkdir -p "$OUTDIR"
STAMP="$(date +%Y%m%d-%H%M%S)"

if [ "$MODE" = scan ]; then
    JSON="$OUTDIR/findings-$STAMP.json"
    CSV="$OUTDIR/findings-$STAMP.csv"
    ARGS=(php_cve_scanner.py --output "$JSON" --csv "$CSV" "$@")
else
    JSON="$OUTDIR/audit-$STAMP.json"
    CSV="$OUTDIR/audit-$STAMP.csv"
    ARGS=(php_cve_audit_local.py --json "$JSON" --csv "$CSV" "$@")
fi

"$PY" "${ARGS[@]}"
CODE=$?

case $CODE in
  0) echo "PASS: completed with no affected or unknown PHP evidence." ;;
  1) echo "FAIL-INFRA: command error or no reachable endpoint; not a security result." >&2 ;;
  2) echo "FAIL-AFFECTED: affected PHP evidence found; review $JSON and $CSV." >&2 ;;
  3) echo "REVIEW: PHP evidence needs manual provenance review; assign $JSON and $CSV." >&2 ;;
  *) echo "UNKNOWN-EXIT ($CODE): treat as tool failure." >&2 ;;
esac

exit $CODE

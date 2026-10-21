#requires -Version 5.1
<#
.SYNOPSIS
    Reference consumer for php_cve_scanner.py / php_cve_audit_local.py exit codes.

.DESCRIPTION
    The tools' exit contract (documented in README.md):
        0  scan/audit completed; no affected and no unknown PHP evidence
        1  command error, or (scanner only) zero endpoints reachable
        2  affected (vulnerable) evidence found
        3  PHP evidence found that requires manual provenance review

    This wrapper translates that contract into a CI/SOC-friendly result:
    a structured summary object and a pass/fail style exit suitable for
    scheduled-task or pipeline gating, with findings files left in place
    for humans to review. It never swallows the findings; it only decides
    what the exit code means operationally.

.EXAMPLE
    .\run_scan.ps1 -Mode scan -Subnet 10.20.0.0/24 -OutputDir .\results
    .\run_scan.ps1 -Mode audit -OutputDir .\results
    .\run_scan.ps1 -Mode scan -Target 10.0.0.5 -ExtraArgs "--port,8080,--http"
#>
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("scan", "audit")]
    [string]$Mode,

    [string]$Subnet,
    [string]$Target,
    [string]$OutputDir = ".\php2shell-results",
    # Single comma-separated string: reliable to pass from -File, scheduled
    # tasks and command lines. Split on commas, trimming whitespace.
    [string]$ExtraArgs = ""
)

$ErrorActionPreference = "Stop"

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Error "python is required on PATH but was not found."
    exit 1
}

if ($Mode -eq "scan" -and -not $Subnet -and -not $Target) {
    Write-Error "scan mode requires -Subnet or -Target."
    exit 1
}

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$null = New-Item -ItemType Directory -Force -Path $OutputDir

if ($Mode -eq "scan") {
    $json = Join-Path $OutputDir "findings-$stamp.json"
    $csv = Join-Path $OutputDir "findings-$stamp.csv"
    $args = @("php_cve_scanner.py", "--output", $json, "--csv", $csv)
    if ($Subnet) { $args += @("--subnet", $Subnet) }
    if ($Target) { $args += @("--target", $Target) }
} else {
    $json = Join-Path $OutputDir "audit-$stamp.json"
    $csv = Join-Path $OutputDir "audit-$stamp.csv"
    $args = @("php_cve_audit_local.py", "--json", $json, "--csv", $csv)
}

$extra = @()
if ($ExtraArgs) {
    $extra = $ExtraArgs.Split(",") | ForEach-Object { $_.Trim() } | Where-Object { $_ }
}
$args += $extra

# -Wait with no timeout: scan duration depends on subnet size; callers
# scheduling this should size their window accordingly.
$proc = Start-Process -FilePath "python" -ArgumentList $args -NoNewWindow -Wait -PassThru
$code = $proc.ExitCode

switch ($code) {
    0 {
        Write-Host "PASS: completed with no affected or unknown PHP evidence."
        $summary = "pass"
    }
    1 {
        Write-Warning "FAIL-INFRA: command error or no reachable endpoint. Check connectivity and arguments; this is not a security result."
        $summary = "infra-fail"
    }
    2 {
        Write-Warning "FAIL-AFFECTED: affected PHP evidence found. Review $json and $csv, then remediate."
        $summary = "affected-found"
    }
    3 {
        Write-Warning "REVIEW: PHP evidence requires manual provenance review. Assign $json and $csv to an analyst."
        $summary = "manual-review"
    }
    default {
        Write-Warning "UNKNOWN-EXIT ($code): treat as tool failure, escalate."
        $summary = "unknown"
    }
}

[PSCustomObject]@{
    mode = $Mode
    exit_code = $code
    summary = $summary
    json = (Resolve-Path $OutputDir).Path
} | ConvertTo-Json | Write-Output

# Propagate the tool's code so callers that care about the raw contract
# can still distinguish; CI systems wanting simple pass/fail can treat
# 0 as pass and anything else as needing attention.
exit $code

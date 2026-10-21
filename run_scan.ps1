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

$pythonCommand = Get-Command python -ErrorAction SilentlyContinue
$pythonPrefix = @()
if (-not $pythonCommand) {
    $pythonCommand = Get-Command py -ErrorAction SilentlyContinue
    if ($pythonCommand) { $pythonPrefix = @("-3") }
}
if (-not $pythonCommand) {
    $pythonCommand = Get-Command python3 -ErrorAction SilentlyContinue
}
if (-not $pythonCommand) {
    Write-Warning "python, py, or python3 is required on PATH but was not found."
    exit 1
}
$pythonExe = $pythonCommand.Source

if ($Mode -eq "scan" -and -not $Subnet -and -not $Target) {
    Write-Warning "scan mode requires -Subnet or -Target."
    exit 1
}
if ($Mode -eq "scan" -and $Subnet -and $Target) {
    Write-Warning "scan mode accepts either -Subnet or -Target, not both."
    exit 1
}

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$null = New-Item -ItemType Directory -Force -Path $OutputDir
$resolvedOutputDir = (Resolve-Path -LiteralPath $OutputDir).Path

if ($Mode -eq "scan") {
    $tool = Join-Path $PSScriptRoot "php_cve_scanner.py"
    $json = Join-Path $resolvedOutputDir "findings-$stamp.json"
    $csv = Join-Path $resolvedOutputDir "findings-$stamp.csv"
    $toolArgs = @($tool, "--output", $json, "--csv", $csv)
    if ($Subnet) { $toolArgs += @("--subnet", $Subnet) }
    if ($Target) { $toolArgs += @("--target", $Target) }
} else {
    $tool = Join-Path $PSScriptRoot "php_cve_audit_local.py"
    $json = Join-Path $resolvedOutputDir "audit-$stamp.json"
    $csv = Join-Path $resolvedOutputDir "audit-$stamp.csv"
    $toolArgs = @($tool, "--json", $json, "--csv", $csv)
}

if (-not (Test-Path -LiteralPath $tool -PathType Leaf)) {
    Write-Warning "Scanner component not found: $tool"
    exit 1
}

$extra = @()
if ($ExtraArgs) {
    $extra = $ExtraArgs.Split(",") | ForEach-Object { $_.Trim() } | Where-Object { $_ }
}
$toolArgs += $extra

$invokeArgs = @($pythonPrefix) + $toolArgs
& $pythonExe @invokeArgs
$code = $LASTEXITCODE

# Security-result codes are trusted only when the tool produced parseable
# evidence files. This prevents an interpreter/tool launch error that happens
# to return 2 or 3 from being mislabeled as a security finding.
$resultsValid = $false
if ($code -in @(0, 2, 3)) {
    if ((Test-Path -LiteralPath $json -PathType Leaf) -and
        (Test-Path -LiteralPath $csv -PathType Leaf)) {
        try {
            $null = Get-Content -LiteralPath $json -Raw | ConvertFrom-Json
            $resultsValid = $true
        } catch {
            Write-Warning "Result JSON is missing or invalid: $json"
        }
    } else {
        Write-Warning "Expected result files were not produced; treating this as an infrastructure failure."
    }
    if (-not $resultsValid) { $code = 1 }
}

switch ($code) {
    0 {
        Write-Host "COMPLETE-NO-FINDINGS: no affected or reviewable PHP evidence was observed; absence of evidence is not proof of remediation."
        $summary = "complete-no-findings"
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
    results_valid = $resultsValid
    json = $json
    csv = $csv
} | ConvertTo-Json | Write-Output

# Propagate the tool's code so callers that care about the raw contract
# can still distinguish; CI systems wanting simple pass/fail can treat
# 0 as pass and anything else as needing attention.
exit $code

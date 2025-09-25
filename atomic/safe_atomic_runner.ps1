<#
.SYNOPSIS
    SAFE Atomic Red Team Test Runner - DRY RUN BY DEFAULT
.DESCRIPTION
    Shows test details only. Requires explicit ATOMIC_EXECUTE=true environment variable to run
#>
param(
    [string[]]$Techniques = @("T1059.001"),
    [switch]$ShowDetailsOnly = $true,
    [switch]$GetPrereqsOnly = $false
)

$canExecute = $env:ATOMIC_EXECUTE -eq "true"

if (-not $ShowDetailsOnly -and -not $GetPrereqsOnly -and -not $canExecute) {
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "    EXECUTION BLOCKED FOR SAFETY" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "To execute tests, set:" -ForegroundColor Yellow
    Write-Host '   $env:ATOMIC_EXECUTE = "true"' -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Defaulting to safe mode..." -ForegroundColor Green
    $ShowDetailsOnly = $true
}

try {
    Import-Module invoke-atomicredteam -Force -ErrorAction Stop
} catch {
    Write-Host "Invoke-AtomicRedTeam not installed" -ForegroundColor Yellow
    exit 1
}

foreach ($technique in $Techniques) {
    Write-Host "`n[*] Technique: $technique" -ForegroundColor Cyan
    
    if ($ShowDetailsOnly) {
        Write-Host "[SAFE MODE] Showing details only:" -ForegroundColor Green
        Invoke-AtomicTest $technique -ShowDetails
    }
    elseif ($GetPrereqsOnly) {
        Write-Host "[SAFE MODE] Getting prerequisites:" -ForegroundColor Green
        Invoke-AtomicTest $technique -GetPrereqs
    }
    else {
        Write-Host "[DANGEROUS] Executing test:" -ForegroundColor Red
        Invoke-AtomicTest $technique
    }
}

if ($ShowDetailsOnly -or $GetPrereqsOnly) {
    Write-Host "`n[SAFE] No destructive actions taken" -ForegroundColor Green
}

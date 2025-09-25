<#
.SYNOPSIS
    Safe Atomic Red Team Test Runner with guardrails
.DESCRIPTION
    Runs atomic tests with safety checks and review-first approach
#>
param(
    [string[]]$Techniques = @("T1059.001"),
    [switch]$ExecuteTests = $false,
    [switch]$Force = $false
)

# Safety check
if ($ExecuteTests -and -not $Force) {
    Write-Host "===========================================" -ForegroundColor Red
    Write-Host "     ATOMIC RED TEAM SAFETY CHECK" -ForegroundColor Yellow
    Write-Host "===========================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "You are about to run DESTRUCTIVE tests!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Checklist:" -ForegroundColor Yellow
    Write-Host "[ ] Running in isolated VM?" -ForegroundColor Yellow
    Write-Host "[ ] VM snapshot taken?" -ForegroundColor Yellow
    Write-Host "[ ] No production systems accessible?" -ForegroundColor Yellow
    Write-Host "[ ] Understand the test impacts?" -ForegroundColor Yellow
    Write-Host ""
    
    $confirm = Read-Host "Type 'EXECUTE TESTS' to proceed (or press Enter to abort)"
    if ($confirm -ne "EXECUTE TESTS") {
        Write-Host "Aborted. Use -Force to bypass this check (AT YOUR OWN RISK)" -ForegroundColor Green
        exit 0
    }
}

Import-Module invoke-atomicredteam -Force -ErrorAction Stop

foreach ($technique in $Techniques) {
    Write-Host "`n[*] Technique: $technique" -ForegroundColor Cyan
    
    # Always show details first
    Write-Host "[*] Test Details:" -ForegroundColor Green
    Invoke-AtomicTest $technique -ShowDetails
    
    if ($ExecuteTests) {
        Write-Host "[*] Getting prerequisites..." -ForegroundColor Yellow
        Invoke-AtomicTest $technique -GetPrereqs
        
        Write-Host "[*] EXECUTING TEST..." -ForegroundColor Red
        Invoke-AtomicTest $technique
        
        Write-Host "[*] Cleaning up..." -ForegroundColor Green
        Invoke-AtomicTest $technique -Cleanup
    } else {
        Write-Host "[*] Review mode only. Use -ExecuteTests to run" -ForegroundColor Green
    }
}

Write-Host "`n[+] Complete. Always review logs for IOCs!" -ForegroundColor Green

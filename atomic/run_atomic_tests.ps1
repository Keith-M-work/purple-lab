param(
    [string[]]$Techniques = @("T1003","T1059.001"),
    [string]$LogPath = "atomic_tests_$(Get-Date -Format yyyyMMdd_HHmmss).log"
)

# Safety: default to dry-run unless RUN_ATOMIC=1
if ($env:RUN_ATOMIC -ne "1") {
    Write-Host "DRY RUN: Atomic tests will NOT execute." -ForegroundColor Yellow
    Write-Host "To run tests, set environment variable RUN_ATOMIC=1 and re-run the script." -ForegroundColor Yellow
    Write-Host "Example (PowerShell): $env:RUN_ATOMIC = '1'; .\\atomic\\run_atomic_tests.ps1" -ForegroundColor Cyan
    exit 0
}

# --- Actual execution block (only runs when RUN_ATOMIC=1) ---
Import-Module invoke-atomicredteam -Force

foreach ($technique in $Techniques) {
    Write-Host "[*] Running tests for $technique" -ForegroundColor Green
    try {
        # Show details and prerqs first
        Invoke-AtomicTest $technique -ShowDetails | Out-File -Append $LogPath
        Invoke-AtomicTest $technique -GetPrereqs | Out-File -Append $LogPath

        # Execute tests (careful!)
        Invoke-AtomicTest $technique | Out-File -Append $LogPath

        # Cleanup
        Invoke-AtomicTest $technique -Cleanup | Out-File -Append $LogPath
    } catch {
        Write-Host "Error running $technique: $_" -ForegroundColor Red
    }
}

Write-Host "[+] Atomic tests complete. Results in $LogPath" -ForegroundColor Green

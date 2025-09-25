# Automated Atomic Red Team Test Runner
param(
    [string[]]$Techniques = @("T1003", "T1059.001", "T1055"),
    [string]$LogPath = "atomic_tests_$(Get-Date -Format yyyyMMdd_HHmmss).log"
)

Import-Module invoke-atomicredteam -Force

foreach ($technique in $Techniques) {
    Write-Host "[*] Running tests for $technique" -ForegroundColor Green
    
    # Get test details
    $tests = Get-AtomicTechnique -Path $technique
    
    # Run each test
    Invoke-AtomicTest $technique -ShowDetails | Out-File -Append $LogPath
    Invoke-AtomicTest $technique -GetPrereqs | Out-File -Append $LogPath
    Invoke-AtomicTest $technique | Out-File -Append $LogPath
    
    # Cleanup
    Invoke-AtomicTest $technique -Cleanup | Out-File -Append $LogPath
}

Write-Host "[+] Testing complete. Results in $LogPath" -ForegroundColor Green

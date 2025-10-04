rule Suspicious_PowerShell {
    meta:
        description = "Detects suspicious PowerShell patterns"
        author = "Keith M"
        date = "2025-01-20"
    strings:
        $s1 = "Invoke-WebRequest" nocase
        $s2 = "DownloadString" nocase
        $s3 = "IEX" nocase
        $s4 = "powershell -enc" nocase
        $s5 = "bypass" nocase
    condition:
        2 of them
}

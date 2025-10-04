rule Embedded_Mimikatz_Like {
    meta:
        description = "Detects patterns similar to embedded Mimikatz"
        author = "Keith M"
        date = "2025-01-20"
    strings:
        $s1 = "sekurlsa::logonpasswords" nocase
        $s2 = "mimikatz" nocase
        $s3 = "gentilkiwi" nocase
        $s4 = "lsadump" nocase
    condition:
        any of them
}

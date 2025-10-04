rule CobaltStrike_Beacon {
    meta:
        description = "Detects Cobalt Strike beacon patterns"
        author = "Keith M"
        date = "2025-01-20"
        reference = "https://github.com/Neo23x0/signature-base"
    strings:
        $s1 = "%%IMPORT%%" fullword
        $s2 = "%%EXECUTE%%" fullword
        $s3 = "ReflectiveLoader"
        $s4 = "beacon.dll" nocase
        $s5 = { 48 89 5C 24 08 57 48 83 EC 20 48 8B 59 10 }
    condition:
        uint16(0) == 0x5a4d and (
            2 of ($s*) or
            $s5
        )
}

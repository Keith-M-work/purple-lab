rule Ransomware_Generic {
    meta:
        description = "Generic ransomware indicators"
        author = "Keith M"
        date = "2025-01-20"
    strings:
        $note1 = "Your files have been encrypted" nocase
        $note2 = "pay the ransom" nocase
        $note3 = "bitcoin address" nocase
        $note4 = "tor browser" nocase
        $cmd1 = "vssadmin delete shadows" nocase
        $cmd2 = "bcdedit /set {default} recoveryenabled no" nocase
        $cmd3 = "wbadmin delete catalog" nocase
        $ext1 = ".locked"
        $ext2 = ".encrypted"
        $ext3 = ".crypto"
    condition:
        2 of ($note*) or 
        2 of ($cmd*) or 
        (1 of ($cmd*) and 1 of ($ext*))
}

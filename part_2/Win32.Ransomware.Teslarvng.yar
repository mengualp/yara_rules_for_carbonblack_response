rule Win32_Ransomware_Teslarvng : tc_detection malicious
{
    meta:
 		score = 7

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "TESLARVNG"
        description         = "Yara rule that detects Teslarvng ransomware."

        tc_detection_type   = "Ransomware"
        tc_detection_name   = "Teslarvng"
        tc_detection_factor = 5

    strings:

        $encrypt_files_p1 = {
            53 8B DC 83 EC ?? 83 E4 ?? 83 C4 ?? 55 8B 6B ?? 89 6C 24 ?? 8B EC 6A ?? 68 ?? ?? ?? 
            ?? 64 A1 ?? ?? ?? ?? ?? ?? ?? ?? A8 ?? 00 00 A1 ?? ?? ?? ?? ?? ?? ?? ?? EC 56 57 50 
            8D 45 ?? 64 A3 ?? ?? ?? ?? ?? ?? ?? ?? C9 89 4D ?? 89 4D ?? 8B 73 ?? 8B 43 ?? 89 75 
            ?? 89 45 ?? 3B F0 0F 84 ?? ?? ?? ?? 8B 15 ?? ?? ?? ?? 8B 06 8D 04 40 C1 E0 ?? 89 45 
            ?? 8B 04 02 8B 40 ?? 8B 30 3B F0 0F 84 ?? ?? ?? ?? A1 ?? ?? ?? ?? ?? ?? ?? ?? 3D ?? 
            ?? ?? ?? 10 89 ?? ?? ?? ?? E3 ?? 00 0F 43 05 ?? ?? ?? ?? 89 45 ?? C6 45 ?? ?? 33 C0 
            83 C9 ?? 66 89 45 ?? 89 4D ?? 8D 4D ?? 8B 47 ?? 40 C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? 
            ?? ?? ?? 50 C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 7F ?? ?? 8B 
            C7 72 ?? 8B 07 FF 77 ?? 8D 4D ?? 50 E8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 8D 4D ?? E8 
            ?? ?? ?? ?? C6 45 ?? ?? 8D 4D ?? 6A ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 45 ?? ?? ?? 
            ?? ?? 8D 95 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 33 C9 68 ?? ?? ?? ?? 0F 10 00 0F 11 85 
            ?? ?? ?? ?? F3 0F 7E 40 ?? 83 4D ?? ?? 66 0F D6 45 ?? 66 89 08 8D 8D ?? ?? ?? ?? C7 
            40 ?? ?? ?? ?? ?? C7 40 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? C6 45 ?? ?? 8D 85 ?? 
            ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 6A ?? 0F 43 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? 6A ?? 
            6A ?? 68 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 89 45 ?? 83 F8 ?? 74 ?? 6A ?? 8D 4D ?? 51
        }

        $encrypt_files_p2 = {
            FF 75 ?? FF 75 ?? 50 FF 15 ?? ?? ?? ?? FF 75 ?? FF 15 ?? ?? ?? ?? FF 75 ?? FF 15 ?? 
            ?? ?? ?? C6 45 ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 65 ?? ?? C6 45 ?? ?? 8D 8D 
            ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 65 ?? ?? C6 45 ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8B 4D ?? 
            8B 41 ?? 89 45 ?? 83 78 ?? ?? 8B 48 ?? 89 4D ?? 72 ?? 8B 00 89 45 ?? C6 45 ?? ?? 33 
            C0 83 4D ?? ?? 8D 4D ?? 66 89 45 ?? 8B 47 ?? 40 C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? 
            ?? ?? 50 C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 7F ?? ?? 8B 47 
            ?? 72 ?? 8B 3F 50 57 8D 4D ?? E8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? 
            ?? ?? 68 ?? ?? ?? ?? 8D 55 ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? C6 45 ?? ?? 
            8D 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 6A ?? 0F 43 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 
            ?? 6A ?? 6A ?? 68 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 8B F8 83 FF ?? 74 ?? 6A ?? 8D 45 
            ?? 50 FF 75 ?? FF 75 ?? 57 FF 15 ?? ?? ?? ?? 57 FF 15 ?? ?? ?? ?? 57 FF 15 ?? ?? ?? 
            ?? C6 45 ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 65 ?? ?? C6 45 ?? ?? 8D 4D ?? E8 
            ?? ?? ?? ?? 8B 15 ?? ?? ?? ?? 8B 45 ?? 8B 36 8B 4D ?? 8B 04 02 3B 70 ?? 0F 85 ?? ?? 
            ?? ?? 8B 75 ?? 83 C6 ?? 89 75 ?? 3B 75 ?? 0F 85 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 8D 
            4B ?? E8 ?? ?? ?? ?? 8B 4D ?? 64 89 0D ?? ?? ?? ?? 59 5F 5E 8B 4D ?? 33 CD E8 ?? ?? 
            ?? ?? 8B E5 5D 8B E3 5B C2
        }

        $find_files = {
            FF D6 83 F8 ?? 0F 85 ?? ?? ?? ?? 8D 43 ?? 50 BA ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? 
            ?? ?? ?? 83 C4 ?? C6 45 ?? ?? 83 78 ?? ?? 72 ?? 8B 00 B2 ?? 8B C8 E8 ?? ?? ?? ?? C6 
            45 ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? C6 45 ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? C6 45 
            ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? C6 45 ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? C6 45 ?? 
            ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 0F 1F 40 ?? 8D 85 ?? ?? ?? ?? 50 
            FF B5 ?? ?? ?? ?? 33 C9 8B 85 ?? ?? ?? ?? 03 8D ?? ?? ?? ?? 83 D0 ?? 50 51 FF B5 ?? 
            ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? C6 45 ?? ?? F6 85 ?? ?? ?? ?? ?? 0F 84 ?? 
            ?? ?? ?? BA ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8B C8 90 66 8B 31 66 3B 32 75 ?? 66 85 F6 
            74 ?? 66 8B 71 ?? 66 3B 72 ?? 75 ?? 83 C1 ?? 83 C2 ?? 66 85 F6 75 ?? 33 C9 EB ?? 1B 
            C9 83 C9 ?? 85 C9 74 ?? B9 ?? ?? ?? ?? 66 8B 10 66 3B 11 75 ?? 66 85 D2 74 ?? 66 8B 
            50 ?? 66 3B 51 ?? 75 ?? 83 C0 ?? 83 C1 ?? 66 85 D2 75 ?? 33 C0 EB ?? 1B C0 83 C8 ?? 
            85 C0 74 ?? 8B 45 ?? 8D 8D ?? ?? ?? ?? 51 3B 45 ?? 74 ?? 8B C8 E8 ?? ?? ?? ?? 83 45 
            ?? ?? EB ?? 50 8D 4D ?? E8 ?? ?? ?? ?? EB ?? 8D 85 ?? ?? ?? ?? 50 8D 4D ?? E8 ?? ?? 
            ?? ?? 8D 85 ?? ?? ?? ?? 50 57 FF 15 ?? ?? ?? ?? 8B F0 C6 45 ?? ?? FF B5 ?? ?? ?? ?? 
            E8 ?? ?? ?? ?? 83 C4 ?? 85 F6 0F 85 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? FF D6 83 F8 ?? 0F 
            84 ?? ?? ?? ?? FF D6 8B D0 
        }

        $enum_shares_p1 = {
            55 8B EC 6A ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 A1 ?? ?? ?? ?? 
            33 C5 89 45 ?? 56 57 50 8D 45 ?? 64 A3 ?? ?? ?? ?? ?? ?? ?? ?? 45 FC 00 00 00 00 8D 
            75 ?? 83 7D ?? ?? 6A ?? 0F 43 75 ?? 6A ?? 6A ?? FF 15 ?? ?? ?? ?? 8B F8 B8 ?? ?? ?? 
            ?? 56 66 89 45 ?? FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 89 45 ?? FF 15 ?? ?? ?? ?? 66 89 
            45 ?? 8D 45 ?? 50 68 ?? ?? ?? ?? 57 C7 45 ?? ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 6A ?? 8D 
            45 ?? 50 57 FF 15 ?? ?? ?? ?? 8D 45 ?? C7 45 ?? ?? ?? ?? ?? 50 8D 45 ?? 89 7D ?? 50 
            8D 45 ?? C7 45 ?? ?? ?? ?? ?? 50 6A ?? 6A ?? 89 7D ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? 
            ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0 0F 8E ?? ?? ?? ?? 83 7D ?? ?? 0F 87 ?? ?? ?? ?? 
            83 7D ?? ?? 0F 86 ?? ?? ?? ?? 57 FF 15 ?? ?? ?? ?? 83 7D ?? ?? 8D 4D ?? 8B 75 ?? 0F 
            43 4D ?? 03 F1 C7 45 ?? ?? ?? ?? ?? 83 7D ?? ?? 8D 4D ?? C7 45 ?? ?? ?? ?? ?? 0F 43 
            4D ?? 33 C0 66 89 45 ?? 8B C6 2B C1 89 4D ?? 50 8D 4D ?? C7 45 ?? ?? ?? ?? ?? C7 45 
            ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? E8 ?? 
            ?? ?? ?? FF 75 ?? 8D 4D ?? 56 FF 75 ?? E8 ?? ?? ?? ?? C6 45 ?? ?? 8D 4D ?? 83 7D ?? 
            ?? 8D 45 ?? 6A ?? 0F 43 45 ?? 51 8D 4D ?? 51 6A ?? 8D 4D ?? 51 6A ?? 50 FF 15 ?? ?? 
            ?? ?? 85 C0 74 ?? 3D ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 0F 57 C0 C7 45 ?? ?? ?? ?? ?? 66
        }

        $enum_shares_p2 = {
            0F D6 45 ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C6 45 ?? 
            ?? 33 F6 8B 55 ?? 85 D2 0F 84 ?? ?? ?? ?? 33 FF 8B 4D ?? 8B 44 39 ?? 85 C0 74 ?? 3D 
            ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 8B 14 39 33 C0 66 89 45 ?? 8B C2 C7 45 ?? ?? ?? ?? ?? 
            C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 8D 48 ?? C7 45 ?? ?? ?? ?? ?? 89 4D ?? 66 
            8B 08 83 C0 ?? 66 85 C9 75 ?? 2B 45 ?? 8D 4D ?? D1 F8 50 52 E8 ?? ?? ?? ?? C6 45 ?? 
            ?? 8B 45 ?? 3B 45 ?? 74 ?? 0F 10 45 ?? C7 40 ?? ?? ?? ?? ?? 0F 11 00 F3 0F 7E 45 ?? 
            66 0F D6 40 ?? 33 C0 83 45 ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 66 89 45 
            ?? EB ?? 8D 4D ?? 51 50 8D 4D ?? E8 ?? ?? ?? ?? C6 45 ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 
            8B 55 ?? 46 83 C7 ?? 3B F2 0F 82 ?? ?? ?? ?? 8B 45 ?? 8B 75 ?? 3B 45 ?? 0F 84 ?? ?? 
            ?? ?? FF 76 ?? E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 85 ?? ?? ?? ?? 8B 46 ?? 83 7D ?? ?? 
            8B 7D ?? 89 45 ?? 8D 45 ?? 0F 43 45 ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? 
            ?? ?? ?? ?? ?? 89 45 ?? 83 FF ?? 73 ?? 0F 10 00 C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 0F 11 
            85 ?? ?? ?? ?? EB ?? 8B F7 8D 8D ?? ?? ?? ?? B8 ?? ?? ?? ?? 83 CE ?? 3B F0 0F 47 F0
        }

        $enum_shares_p3 = { 
            8D 46 ?? 50 E8 ?? ?? ?? ?? 8D 0C 7D ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 51 FF 75 ?? 50 E8 
            ?? ?? ?? ?? 83 C4 ?? 89 B5 ?? ?? ?? ?? 89 BD ?? ?? ?? ?? C6 45 ?? ?? 8B 45 ?? 8B 7D 
            ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 89 45 ?? 
            3B F8 0F 84 ?? ?? ?? ?? 2B C7 C1 F8 ?? 69 F0 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 89 85 ?? 
            ?? ?? ?? 8D 0C 76 89 45 ?? 8D 04 C8 89 45 ?? 8D 85 ?? ?? ?? ?? 89 45 ?? C6 45 ?? ?? 
            0F 57 C0 8B B5 ?? ?? ?? ?? 66 0F D6 45 ?? C7 45 ?? ?? ?? ?? ?? 89 75 ?? 89 75 ?? 89 
            45 ?? C6 45 ?? ?? 66 90 57 8B CE E8 ?? ?? ?? ?? 83 C6 ?? 83 C7 ?? 89 75 ?? 3B 7D ?? 
            75 ?? 89 75 ?? C6 45 ?? ?? 89 75 ?? C7 45 ?? ?? ?? ?? ?? C6 45 ?? ?? C6 45 ?? ?? 8D 
            85 ?? ?? ?? ?? 8B 4D ?? 50 8D 45 ?? 50 E8 ?? ?? ?? ?? C6 45 ?? ?? 8D 8D ?? ?? ?? ?? 
            E8 ?? ?? ?? ?? C6 45 ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 75 ?? FF 76 ?? E8 ?? 
            ?? ?? ?? 83 C4 ?? 85 C0 0F 85 ?? ?? ?? ?? C6 45 ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? EB ?? 
            8B 75 ?? FF 75 ?? FF 15 ?? ?? ?? ?? 8B 06 F0 FF 08 C6 45 ?? ?? 8D 4D ?? E8 ?? ?? ?? 
            ?? EB ?? 57 FF 15 ?? ?? ?? ?? 8B 75
        }
        
    condition:
        uint16(0) == 0x5A4D and
        (
            all of ($enum_shares_p*)
        ) and
        (
            $find_files
        ) and
        (
            all of ($encrypt_files_p*)
        )
}
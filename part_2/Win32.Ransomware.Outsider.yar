rule Win32_Ransomware_Outsider : tc_detection malicious
{
    meta:
 		score = 7

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "OUTSIDER"
        description         = "Yara rule that detects Outsider ransomware."

        tc_detection_type   = "Ransomware"
        tc_detection_name   = "Outsider"
        tc_detection_factor = 5

    strings:

        $encrypt_files_p1 = {
            55 8B EC 81 EC ?? ?? ?? ?? 53 56 57 8D 45 ?? 8B D9 50 6A ?? 5E 56 FF 35 ?? ?? ?? ?? 
            89 5D ?? FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 6A ?? 6A ?? FF 15 ?? ?? ?? ?? 50 
            FF 15 ?? ?? ?? ?? 8B F8 89 7D ?? 85 FF 0F 84 ?? ?? ?? ?? 8D 55 ?? 89 75 ?? 8B CF 2B 
            D7 8A 04 0A 88 01 41 83 EE ?? 75 ?? 6A ?? 8D 45 ?? 50 57 56 6A ?? 56 FF 35 ?? ?? ?? 
            ?? FF 15 ?? ?? ?? ?? 56 68 ?? ?? ?? ?? 6A ?? 56 6A ?? 68 ?? ?? ?? ?? 53 FF 15 ?? ?? 
            ?? ?? 89 45 ?? 83 F8 ?? 0F 84 ?? ?? ?? ?? 89 75 ?? 89 75 ?? 53 FF 15 ?? ?? ?? ?? 8D 
            04 43 83 E8 ?? 66 83 38 ?? 75 ?? FF B6 ?? ?? ?? ?? 2B C3 83 C0 ?? D1 F8 8D 04 43 50 
            FF 15 ?? ?? ?? ?? 89 45 ?? 85 C0 74 ?? FF B6 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? FF 75 ?? 
            8B F0 FF 15 ?? ?? ?? ?? 3B C6 74 ?? 8B 75 ?? 83 C6 ?? 89 75 ?? 83 FE ?? 72 ?? EB ?? 
            C7 45 ?? ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? FF D6 50 FF 15 ?? ?? ?? 
            ?? 89 45 ?? 85 C0 0F 84 ?? ?? ?? ?? 8B 7D ?? 8B D8 33 C0 50 8D 45 ?? 50 68 ?? ?? ?? 
            ?? 53 57 FF 15 ?? ?? ?? ?? 8B 4D ?? 33 C0 89 4D ?? 3B C8 76 ?? 8B F8 8B C7 25 ?? ?? 
            ?? ?? 79 ?? 48 83 C8 ?? 40 89 45 ?? 75 ?? 8B C7 99 83 E2 ?? 03 C2 C1 F8 ?? 99 52 50
        }

        $encrypt_files_p2 = {
            51 51 8D 55 ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 4D ?? 83 C4 ?? 8B 45 ?? 8A 84 05 
            ?? ?? ?? ?? 30 04 1F 47 8B C7 99 85 D2 72 ?? 77 ?? 3B C1 72 ?? 8B 4D ?? 8B 7D ?? 6A 
            ?? F7 D9 8B C1 6A ?? 99 52 50 57 FF 15 ?? ?? ?? ?? 33 C0 50 8D 45 ?? 50 FF 75 ?? 53 
            57 FF 15 ?? ?? ?? ?? 83 7D ?? ?? 74 ?? 81 7D ?? ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 53 33 
            C0 50 FF D6 50 FF 15 ?? ?? ?? ?? 8B 7D ?? 8B 5D ?? 6A ?? 33 C0 C7 45 ?? ?? ?? ?? ?? 
            50 0F 57 C0 66 0F 13 45 ?? FF 75 ?? FF 75 ?? FF 75 ?? FF 15 ?? ?? ?? ?? 33 C0 50 8D 
            45 ?? 50 6A ?? 8D 45 ?? 50 FF 75 ?? FF 15 ?? ?? ?? ?? 33 C0 50 8D 45 ?? 50 6A ?? 57 
            FF 75 ?? FF 15 ?? ?? ?? ?? FF 75 ?? FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? FF D6 50 
            FF 15 ?? ?? ?? ?? 8B F0 85 F6 74 ?? 68 ?? ?? ?? ?? 53 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 
            56 FF 15 ?? ?? ?? ?? 83 C4 ?? 56 53 FF 15 ?? ?? ?? ?? 56 33 F6 56 FF 15 ?? ?? ?? ?? 
            50 FF 15 ?? ?? ?? ?? EB ?? 33 F6 57 56 FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 5F 5E 
            5B 8B E5 5D C3 
        }

        $find_files = {
            8B EC 83 E4 ?? 81 EC ?? ?? ?? ?? 53 8B 1D ?? ?? ?? ?? 56 57 68 ?? ?? ?? ?? 6A ?? FF 
            D3 50 FF 15 ?? ?? ?? ?? 8B F0 85 F6 0F 84 ?? ?? ?? ?? FF 75 ?? 68 ?? ?? ?? ?? 68 ?? 
            ?? ?? ?? 56 FF 15 ?? ?? ?? ?? 83 C4 ?? 8D 44 24 ?? 50 56 FF 15 ?? ?? ?? ?? 83 F8 ?? 
            0F 84 ?? ?? ?? ?? 8B D8 33 FF FF B7 ?? ?? ?? ?? 8D 44 24 ?? 50 FF 15 ?? ?? ?? ?? 85 
            C0 0F 84 ?? ?? ?? ?? 83 C7 ?? 83 FF ?? 72 ?? 8D 44 24 ?? 50 FF 75 ?? 68 ?? ?? ?? ?? 
            68 ?? ?? ?? ?? 56 FF 15 ?? ?? ?? ?? 8B 44 24 ?? 83 C4 ?? A8 ?? 74 ?? 68 ?? ?? ?? ?? 
            8D 44 24 ?? 50 FF 15 ?? ?? ?? ?? 85 C0 74 ?? 68 ?? ?? ?? ?? 8D 44 24 ?? 50 FF 15 ?? 
            ?? ?? ?? 85 C0 74 ?? 56 E8 ?? ?? ?? ?? 59 EB ?? 8B 44 24 ?? A8 ?? 74 ?? 68 ?? ?? ?? 
            ?? 8D 44 24 ?? 50 FF 15 ?? ?? ?? ?? 85 C0 75 ?? 68 ?? ?? ?? ?? 8D 44 24 ?? 50 FF 15 
            ?? ?? ?? ?? 85 C0 74 ?? 8B CE E8 ?? ?? ?? ?? 8D 44 24 ?? 50 53 FF 15 ?? ?? ?? ?? 85 
            C0 0F 85 ?? ?? ?? ?? 53 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 75 ?? 68 ?? ?? ?? ?? 68 
            ?? ?? ?? ?? 56 FF 15 ?? ?? ?? ?? 83 C4 ?? 8B CE E8 ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? 56 
            6A ?? FF D3 50 FF 15 ?? ?? ?? ?? 5F 5E 5B 8B E5 5D C3 
        }

        $enum_resources = {
            55 8B EC 83 E4 ?? 83 EC ?? 83 0C 24 ?? 8D 44 24 ?? 53 56 57 50 FF 75 ?? C7 44 24 ?? 
            ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? FF 15 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 8B 44 24 ?? 
            83 C0 ?? 50 6A ?? FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 8B F8 85 FF 74 ?? EB ?? 33 
            DB 39 5C 24 ?? 76 ?? 8D 77 ?? F6 46 ?? ?? 74 ?? 8D 46 ?? 50 E8 ?? ?? ?? ?? EB ?? FF 
            36 E8 ?? ?? ?? ?? 43 83 C6 ?? 59 3B 5C 24 ?? 72 ?? 8D 44 24 ?? 50 57 8D 44 24 ?? 50 
            FF 74 24 ?? FF 15 ?? ?? ?? ?? 85 C0 74 ?? 57 6A ?? FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? 
            ?? ?? FF 74 24 ?? FF 15 ?? ?? ?? ?? 5F 5E 5B 8B E5 5D C3 
        }

    condition:
        uint16(0) == 0x5A4D and 
        (
            $enum_resources
        ) and 
        (
            $find_files
        ) and 
        (
            all of ($encrypt_files_p*)
        )
}
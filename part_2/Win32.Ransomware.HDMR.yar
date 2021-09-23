rule Win32_Ransomware_HDMR : tc_detection malicious
{
    meta:
 		score = 7

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "HDMR"
        description         = "Yara rule that detects HDMR ransomware."

        tc_detection_type   = "Ransomware"
        tc_detection_name   = "HDMR"
        tc_detection_factor = 5

    strings:

        $find_files_p1 = {
            55 8B EC 83 E4 ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 33 C4 89 84 24 ?? ?? 
            ?? ?? 53 56 8B 75 ?? 57 33 C0 68 ?? ?? ?? ?? 50 8D 8C 24 ?? ?? ?? ?? 51 89 74 24 ?? 
            66 89 84 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 56 8D 94 24 ?? ?? ?? ?? 68 ?? ?? ?? 
            ?? 52 FF 15 ?? ?? ?? ?? 83 C4 ?? 8D 44 24 ?? 50 8D 8C 24 ?? ?? ?? ?? 51 FF 15 ?? ?? 
            ?? ?? 89 44 24 ?? 83 F8 ?? 0F 84 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? EB 
            ?? 8D 49 ?? 8B 74 24 ?? F6 44 24 ?? ?? 0F 84 ?? ?? ?? ?? B9 ?? ?? ?? ?? 8D 44 24 ?? 
            66 8B 10 66 3B 11 75 ?? 66 85 D2 74 ?? 66 8B 50 ?? 66 3B 51 ?? 75 ?? 83 C0 ?? 83 C1 
            ?? 66 85 D2 75 ?? 33 C0 EB ?? 1B C0 83 D8 ?? 85 C0 0F 84 ?? ?? ?? ?? B9 ?? ?? ?? ?? 
            8D 44 24 ?? 66 8B 10 66 3B 11 75 ?? 66 85 D2 74 ?? 66 8B 50 ?? 66 3B 51 ?? 75 ?? 83 
            C0 ?? 83 C1 ?? 66 85 D2 75 ?? 33 C0 EB ?? 1B C0 83 D8 ?? 85 C0 0F 84 ?? ?? ?? ?? 8D
        }

        $find_files_p2 = { 
            54 24 ?? 68 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? 8D 44 24 
            ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? 6A ?? 8D 4C 24 
            ?? 68 ?? ?? ?? ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? 6A ?? 8D 54 24 
            ?? 68 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? 6A ?? 8D 44 24 
            ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? 8D 4C 24 ?? 68 
            ?? ?? ?? ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? 8D 54 24 ?? 68 ?? ?? 
            ?? ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? 33 C0 68 ?? ?? ?? ?? 50 8D 
            8C 24 ?? ?? ?? ?? 51 66 89 84 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 8D 54 24 ?? 52 
            56 8D 84 24 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 8D 8C 24 ?? ?? ?? ?? 51 
            E8 ?? ?? ?? ?? 83 C4 ?? E9 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? E8 ?? ?? ?? ?? 8B F0 83 
            C4 ?? 85 F6 74 ?? 8B 44 24 ?? 8D 54 24 ?? 52 50 68 ?? ?? ?? ?? 56 FF 15 ?? ?? ?? ?? 
            8B 0D ?? ?? ?? ?? 83 C4 ?? 3B 0D ?? ?? ?? ?? 7C ?? 8D 49 ?? 6A ?? FF 15 ?? ?? ?? ?? 
            8B 15 ?? ?? ?? ?? 3B 15 ?? ?? ?? ?? 7D ?? 68 ?? ?? ?? ?? FF D7 FF 05 ?? ?? ?? ?? 68 
            ?? ?? ?? ?? FF D3 6A ?? 6A ?? 56 68 ?? ?? ?? ?? 6A ?? 6A ?? FF 15 ?? ?? ?? ?? 50 FF 
            15 ?? ?? ?? ?? 8B 74 24 ?? 8D 44 24 ?? 50 56 FF 15 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? 
            ?? 56 FF 15 ?? ?? ?? ?? 8B 8C 24 ?? ?? ?? ?? 5F 5E 5B 33 CC E8 ?? ?? ?? ?? 8B E5 5D 
            C3
        }

        $encrypt_files_p1 = {
            55 8B EC 83 E4 ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 33 C4 89 84 24 ?? ?? 
            ?? ?? 53 56 57 33 C0 8B D9 68 ?? ?? ?? ?? 50 8D 8C 24 ?? ?? ?? ?? 51 89 5C 24 ?? 66 
            89 84 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 8D 94 24 ?? ?? ?? ?? 52 6A ?? 6A ?? 6A 
            ?? 53 E8 ?? ?? ?? ?? 83 C4 ?? 66 83 BC 24 ?? ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? BF ?? ?? 
            ?? ?? 33 F6 8D 84 24 ?? ?? ?? ?? 57 50 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 ?? ?? ?? 
            ?? 83 C6 ?? 83 C7 ?? 81 FE ?? ?? ?? ?? 72 ?? 6A ?? 68 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 
            68 ?? ?? ?? ?? 53 FF 15 ?? ?? ?? ?? 8B D8 83 FB ?? 0F 84 ?? ?? ?? ?? 8D 4C 24 ?? 51 
            53 FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 8B 44 24 ?? 85 C0 0F 8C ?? ?? ?? ?? 8B 
            7C 24 ?? 7F ?? 83 FF ?? 0F 82 ?? ?? ?? ?? 8B F0 89 7C 24 ?? 89 74 24 ?? 85 C0 7C ?? 
            7F ?? 83 FF ?? 76 ?? 6A ?? 6A ?? 6A ?? 53 C7 44 24 ?? ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 
            33 C0 50 8D 54 24 ?? 52 89 44 24 ?? 89 44 24 ?? 66 89 44 24 ?? 88 44 24 ?? 6A ?? 8D 
            44 24 ?? 50 53 C6 44 24 ?? ?? FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 8B C7 83 E8 
            ?? 8B CE 83 D9 ?? 33 F6 39 44 24 ?? 75 ?? 3B F1 75 ?? 8B 4C 24 ?? 3B 0D ?? ?? ?? ?? 
            0F 84 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 53 FF 15 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 50 
            E8 ?? ?? ?? ?? 83 C4 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 6A ?? 8D 54 24 ?? 6A ?? 52 C6 44
        }

        $encrypt_files_p2 = { 
            24 ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 33 F6 E8 ?? ?? ?? ?? 25 ?? ?? ?? ?? 79 ?? 48 0D ?? 
            ?? ?? ?? 40 88 44 34 ?? 46 83 FE ?? 7C ?? 8B 44 24 ?? BE ?? ?? ?? ?? 85 C0 0F 8F ?? 
            ?? ?? ?? 0F 8C ?? ?? ?? ?? 81 FF ?? ?? ?? ?? 0F 83 ?? ?? ?? ?? 85 C0 0F 8C ?? ?? ?? 
            ?? 7F ?? 85 FF 0F 84 ?? ?? ?? ?? 85 C0 7F ?? 7C ?? 3B FE 73 ?? 6A ?? 6A ?? 50 57 E8 
            ?? ?? ?? ?? 8B F7 2B F0 56 E8 ?? ?? ?? ?? 8B F8 33 C0 83 C4 ?? 89 44 24 ?? 89 44 24 
            ?? 3B F8 74 ?? 50 8D 44 24 ?? 50 56 57 53 FF 15 ?? ?? ?? ?? 85 C0 74 ?? 39 74 24 ?? 
            75 ?? 6A ?? 6A ?? 6A ?? 53 FF 15 ?? ?? ?? ?? 56 57 8D 44 24 ?? E8 ?? ?? ?? ?? 83 C4 
            ?? 6A ?? 8D 4C 24 ?? 51 56 57 53 FF 15 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 53 FF 15 
            ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? 83 C4 ?? 5F 5E 5B 8B 8C 24 ?? ?? ?? ?? 33 CC E8 ?? ?? 
            ?? ?? 8B E5 5D C3 53 FF 15 ?? ?? ?? ?? 85 FF 0F 84 ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? 83 
            C4 ?? 5F 5E 5B 8B 8C 24 ?? ?? ?? ?? 33 CC E8 ?? ?? ?? ?? 8B E5 5D C3 6A ?? 68 ?? ?? 
            ?? ?? 50 57 E8 ?? ?? ?? ?? 8B C8 89 44 24 ?? B8 ?? ?? ?? ?? F7 E9 C1 FA ?? 8B C2 C1 
            E8 ?? 03 C2 69 C0 ?? ?? ?? ?? 8B D1 2B D0 85 D2 7E ?? 41 89 4C 24 ?? 33 C0 89 44 24 
            ?? 3B C8 0F 8E ?? ?? ?? ?? 89 44 24 ?? EB ?? 90 8B 7C 24 ?? 8B 44 24 ?? 8B 4C 24
        }

        $encrypt_files_p3 = { 
            99 2B F8 1B CA 89 7C 24 ?? 89 4C 24 ?? 0F 88 ?? ?? ?? ?? 7F ?? 85 FF 0F 84 ?? ?? ?? 
            ?? 8B C6 99 3B CA 7F ?? 7C ?? 3B F8 73 ?? 6A ?? 6A ?? 51 57 E8 ?? ?? ?? ?? 8B F7 2B 
            F0 85 F6 0F 8E ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 8B F8 33 C0 83 C4 ?? 89 44 24 ?? 89 44 
            24 ?? 3B F8 0F 84 ?? ?? ?? ?? 50 8D 44 24 ?? 50 56 57 53 FF 15 ?? ?? ?? ?? 85 C0 0F 
            84 ?? ?? ?? ?? 39 74 24 ?? 0F 85 ?? ?? ?? ?? 6A ?? 6A ?? 8B CE F7 D9 51 53 FF 15 ?? 
            ?? ?? ?? 56 57 8D 44 24 ?? E8 ?? ?? ?? ?? 83 C4 ?? 6A ?? 8D 54 24 ?? 52 56 57 53 FF 
            15 ?? ?? ?? ?? 85 C0 74 ?? 57 E8 ?? ?? ?? ?? 83 C4 ?? 81 FE ?? ?? ?? ?? 7C ?? 83 7C 
            24 ?? ?? 7C ?? 7F ?? 81 7C 24 ?? ?? ?? ?? ?? 72 ?? 6A ?? 6A ?? 68 ?? ?? ?? ?? 53 FF 
            15 ?? ?? ?? ?? 8B 44 24 ?? 81 44 24 ?? ?? ?? ?? ?? 40 89 44 24 ?? 3B 44 24 ?? 0F 8C 
            ?? ?? ?? ?? EB ?? 53 FF 15 ?? ?? ?? ?? EB ?? 53 FF 15 ?? ?? ?? ?? 85 FF 74 ?? 57 E8 
            ?? ?? ?? ?? 83 C4 ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8D 4C 24 ?? E8 ?? ?? ?? ?? 68 
            ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 53 FF 15 ?? ?? ?? ?? 68
        }

        $encrypt_files_p4 = {  
            8D 84 24 ?? ?? ?? ?? 6A ?? 50 E8 ?? ?? ?? ?? 8B 44 24 ?? 83 C4 ?? B9 ?? ?? ?? ?? 8D 
            74 24 ?? 8D BC 24 ?? ?? ?? ?? F3 A5 8B 4C 24 ?? 6A ?? 89 8C 24 ?? ?? ?? ?? 8B D0 8D 
            4C 24 ?? 51 C1 FA ?? 68 ?? ?? ?? ?? 8D 94 24 ?? ?? ?? ?? 89 84 24 ?? ?? ?? ?? A1 ?? 
            ?? ?? ?? 52 53 C7 44 24 ?? ?? ?? ?? ?? 89 84 24 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 53 FF 
            15 ?? ?? ?? ?? 33 C0 68 ?? ?? ?? ?? 50 8D 8C 24 ?? ?? ?? ?? 51 66 89 84 24 ?? ?? ?? 
            ?? E8 ?? ?? ?? ?? 8B 74 24 ?? 83 C4 ?? 68 ?? ?? ?? ?? 56 68 ?? ?? ?? ?? 8D 94 24 ?? 
            ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 8D 94 24 ?? ?? ?? ?? 52 56 FF 15 ?? ?? ?? ?? 5F 5E 
            5B 8B 8C 24 ?? ?? ?? ?? 33 CC E8 ?? ?? ?? ?? 8B E5 5D C3 53 FF 15 ?? ?? ?? ?? 8B 8C 
            24 ?? ?? ?? ?? 5F 5E 5B 33 CC E8 ?? ?? ?? ?? 8B E5 5D C3
        }

        $find_MS_xchange_backups_p1 = {
            55 8B EC 83 E4 ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 33 C4 89 84 24 ?? ?? 
            ?? ?? 53 56 57 68 ?? ?? ?? ?? 8D 44 24 ?? 6A ?? 50 E8 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? 
            8B 1D ?? ?? ?? ?? B0 ?? 88 44 24 ?? 88 44 24 ?? B0 ?? 83 C4 ?? C6 44 24 ?? ?? C7 44 
            24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 66 C7 44 24 ?? ?? ?? C7 44 24 ?? ?? ?? ?? 
            ?? 88 44 24 ?? C7 44 24 ?? ?? ?? ?? ?? 66 C7 44 24 ?? ?? ?? C6 44 24 ?? ?? 88 44 24 
            ?? 88 44 24 ?? BE ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 8B FF 68 ?? ?? ?? ?? 8D 8C 24 
            ?? ?? ?? ?? 6A ?? 51 C6 84 24 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 56 8D 54 24 ?? 
            52 8D 84 24 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 6A ?? 8D 4C 24 ?? 6A ?? 51 
            E8 ?? ?? ?? ?? 83 C4 ?? 33 C0 33 D2 89 44 24 ?? 89 44 24 ?? 89 44 24 ?? 89 44 24 ?? 
            8D 44 24 ?? 50 8D 4C 24 ?? 51 52 52 52 52 52 52 66 89 54 24 ?? 8D 94 24 ?? ?? ?? ?? 
            52 6A ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? FF D3 6A ?? FF D7 83 C6 ?? 
            FF 4C 24 ?? 0F 85 ?? ?? ?? ?? BE ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? EB ?? 8D 49 ?? 
            68 ?? ?? ?? ?? 8D 84 24 ?? ?? ?? ?? 6A ?? 50 C6 84 24 ?? ?? ?? ?? ?? E8
        }

        $find_MS_xchange_backups_p2 = { 
            83 C4 ?? 56 8D 4C 24 ?? 51 8D 94 24 ?? ?? ?? ?? 68 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 6A 
            ?? 8D 44 24 ?? 6A ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 33 C0 33 C9 8D 54 24 ?? 52 89 44 24 
            ?? 89 44 24 ?? 89 44 24 ?? 89 44 24 ?? 8D 44 24 ?? 50 51 51 51 51 51 51 66 89 4C 24 
            ?? 8D 8C 24 ?? ?? ?? ?? 51 6A ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? FF 
            D3 6A ?? FF D7 83 C6 ?? FF 4C 24 ?? 0F 85 ?? ?? ?? ?? 33 D2 68 ?? ?? ?? ?? 52 8D 84 
            24 ?? ?? ?? ?? 50 66 89 94 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 68 ?? ?? ?? ?? 68 
            ?? ?? ?? ?? 8D 94 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 33 C0 B1 ?? EB ?? 8D 49 ?? 
            30 88 ?? ?? ?? ?? 40 3D ?? ?? ?? ?? 72 ?? 68 ?? ?? ?? ?? 8D 8C 24 ?? ?? ?? ?? 6A ?? 
            51 C6 84 24 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 68 ?? ?? ?? ?? 8D 94 24 ?? ?? ?? 
            ?? 52 8D 84 24 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 8C 24 ?? ?? ?? ?? 68 ?? ?? 
            ?? ?? 51 E8 ?? ?? ?? ?? 8B F0 83 C4 ?? 85 F6 74 ?? 56 68 ?? ?? ?? ?? 6A ?? 68 ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 83 C4 ?? 6A ?? 8D 54 24 ?? 6A ?? 52 E8 ?? ?? 
            ?? ?? 83 C4 ?? 33 C0 8D 4C 24 ?? 51 8D 54 24 ?? 52 50 50 50 50 50 50 89 44 24 ?? 89 
            44 24 ?? 89 44 24 ?? 89 44 24 ?? 66 89 44 24 ?? 8D 84 24 ?? ?? ?? ?? 50 6A ?? C7 44 
            24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? FF D3 8B 8C 24 ?? ?? ?? ?? 5F 5E 5B 33 CC 
            E8 ?? ?? ?? ?? 8B E5 5D C3
        }

    condition:
        uint16(0) == 0x5A4D and 
        (
            all of ($find_files_p*)
        ) and 
        (
            all of ($encrypt_files_p*)
        ) and 
        (
            all of ($find_MS_xchange_backups_p*)
        )
}
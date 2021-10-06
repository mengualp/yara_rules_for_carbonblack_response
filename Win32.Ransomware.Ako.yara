rule Win32_Ransomware_Ako : tc_detection malicious
{
    meta:
 		score = 7

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "AKO"
        description         = "Yara rule that detects Ako ransomware."

        tc_detection_type   = "Ransomware"
        tc_detection_name   = "Ako"
        tc_detection_factor = 5

    strings:

        $encrypt_network_shares_win32_p1 = {
            55 8B EC 6A ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 81 EC ?? ?? ?? ?? A1 ?? ?? ?? ?? 
            33 C5 89 45 ?? 50 8D 45 ?? 64 A3 ?? ?? ?? ?? 89 4D ?? 8B 45 ?? 50 8D 4D ?? E8 ?? ?? 
            ?? ?? 8B 4D ?? 81 C1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 C8 85 C9 0F 85 ?? ?? ?? ?? 8B 
            4D ?? E8 ?? ?? ?? ?? 0F B6 D0 85 D2 0F 85 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8D 45 
            ?? 50 8B 4D ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 8D 4D ?? E8 ?? ?? ?? ?? 0F B6 D0 85 D2 0F 
            85 ?? ?? ?? ?? 8D 45 ?? 50 8B 4D ?? 83 C1 ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 4D ?? 
            E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 51 8B 4D ?? E8 ?? ?? ?? ?? 50 8D 95 
            ?? ?? ?? ?? 52 8B 4D ?? E8 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 E8 ?? 
            ?? ?? ?? 83 C4 ?? 50 8D 8D ?? ?? ?? ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 50 8D 4D ?? E8 ?? 
            ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8D ?? 
            ?? ?? ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 55 ?? 52 
            68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 50 8D 8D ?? ?? ?? ?? 51 
            E8 ?? ?? ?? ?? 83 C4 ?? 50 8D 4D ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8
        }

        $encrypt_network_shares_win32_p2 = {
            8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8B 4D ?? E8 ?? ?? ?? ?? 50 8D 95 ?? 
            ?? ?? ?? 52 8B 4D ?? E8 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? 
            ?? ?? 83 C4 ?? 50 8D 8D ?? ?? ?? ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 50 8D 4D ?? E8 ?? ?? 
            ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8B 4D ?? E8 ?? ?? ?? ?? 50 8D 95 ?? ?? ?? ?? 52 
            8B 4D ?? E8 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 
            ?? 50 8D 8D ?? ?? ?? ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 50 8D 4D ?? E8 ?? ?? ?? ?? 8D 8D 
            ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? 
            ?? ?? ?? 68 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? 
            ?? 8D 4D ?? E8 ?? ?? ?? ?? 8D 55 ?? 52 8D 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 4D ?? 
            E8 ?? ?? ?? ?? 0F B6 C8 85 C9 0F 85 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? EB ?? 8B 55 ?? 
            83 C2 ?? 89 55 ?? 8D 4D ?? E8 ?? ?? ?? ?? 39 45 ?? 73 ?? 83 7D ?? ?? 76 ?? 8B 45
        }

        $encrypt_network_shares_win32_p3 = {
            33 D2 B9 ?? ?? ?? ?? F7 F1 85 D2 75 ?? 6A ?? 68 ?? ?? ?? ?? 8B 55 ?? 52 8D 4D ?? E8 
            ?? ?? ?? ?? 8B 45 ?? 83 C0 ?? 89 45 ?? EB ?? 68 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 
            8D 4D ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 50 8D 55 ?? 52 8D 4D ?? E8 ?? ?? ?? ?? 8D 4D ?? 
            E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 
            8B 4D ?? E8 ?? ?? ?? ?? 50 8D 8D ?? ?? ?? ?? 51 8B 4D ?? E8 ?? ?? ?? ?? 50 E8 ?? ?? 
            ?? ?? 83 C4 ?? 50 8D 95 ?? ?? ?? ?? 52 8D 4D ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 
            ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? 
            ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 4D ?? E8 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? 
            ?? 50 8B 4D ?? E8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 50 8D 8D ?? ?? ?? ?? 51 8D 
            4D ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? 
            ?? C6 45 ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? 
            ?? 8A 45 ?? EB ?? 8D 4D ?? E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? 
            ?? ?? 32 C0 8B 4D ?? 64 89 0D ?? ?? ?? ?? 59 8B 4D ?? 33 CD E8 ?? ?? ?? ?? 8B E5 5D 
            C2
        }

        $find_files_win32_p1 = {
            8B FF 55 8B EC 51 8B 4D ?? 53 57 33 DB 8D 51 ?? 66 8B 01 83 C1 ?? 66 3B C3 75 ?? 8B 
            7D ?? 2B CA D1 F9 8B C7 41 F7 D0 89 4D ?? 3B C8 76 ?? 6A ?? 58 EB ?? 56 8D 5F ?? 03 
            D9 6A ?? 53 E8 ?? ?? ?? ?? 8B F0 59 59 85 FF 74 ?? 57 FF 75 ?? 53 56 E8 ?? ?? ?? ?? 
            83 C4 ?? 85 C0 75 ?? FF 75 ?? 2B DF 8D 04 7E FF 75 ?? 53 50 E8 ?? ?? ?? ?? 83 C4 ?? 
            85 C0 75 ?? 8B 7D ?? 8B CF E8 ?? ?? ?? ?? 8B D8 85 DB 74 ?? 56 E8 ?? ?? ?? ?? 59 EB 
            ?? 8B 47 ?? 89 30 83 47 ?? ?? 33 DB 6A ?? E8 ?? ?? ?? ?? 59 8B C3 5E 5F 5B 8B E5 5D 
            C3 33 C0 50 50 50 50 50 E8 ?? ?? ?? ?? CC 8B FF 55 8B EC 81 EC ?? ?? ?? ?? A1 ?? ?? 
            ?? ?? 33 C5 89 45 ?? 8B 55 ?? 8B 4D ?? 53 8B 5D ?? 89 8D ?? ?? ?? ?? 56 57 3B D3 74 
            ?? 0F B7 02 8D 8D ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 84 C0 75 ?? 83 EA ?? 3B D3 75 ?? 8B
        }

        $find_files_win32_p2 = {
            8D ?? ?? ?? ?? 0F B7 32 83 FE ?? 75 ?? 8D 43 ?? 3B D0 74 ?? 51 33 FF 57 57 53 E8 ?? 
            ?? ?? ?? 83 C4 ?? EB ?? 56 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 2B D3 0F B6 C0 D1 FA 42 
            F7 D8 68 ?? ?? ?? ?? 1B C0 33 FF 23 C2 89 85 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 57 50 E8 
            ?? ?? ?? ?? 83 C4 ?? 8D 85 ?? ?? ?? ?? 57 57 57 50 57 53 FF 15 ?? ?? ?? ?? 8B F0 8B 
            85 ?? ?? ?? ?? 83 FE ?? 75 ?? 50 57 57 53 E8 ?? ?? ?? ?? 83 C4 ?? 8B F8 83 FE ?? 74 
            ?? 56 FF 15 ?? ?? ?? ?? 8B C7 8B 4D ?? 5F 5E 33 CD 5B E8 ?? ?? ?? ?? 8B E5 5D C3 8B 
            48 ?? 2B 08 C1 F9 ?? 6A ?? 89 8D ?? ?? ?? ?? 59 66 39 8D ?? ?? ?? ?? 75 ?? 66 39 BD 
            ?? ?? ?? ?? 74 ?? 66 39 8D ?? ?? ?? ?? 75 ?? 66 39 BD ?? ?? ?? ?? 74 ?? 50 FF B5 ?? 
            ?? ?? ?? 8D 85 ?? ?? ?? ?? 53 50 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 75 ?? 8D 85 ?? ?? ?? 
            ?? 50 56 FF 15 ?? ?? ?? ?? 6A ?? 85 C0 8B 85 ?? ?? ?? ?? 59 75 ?? 8B 10 8B 40 ?? 8B 
            8D ?? ?? ?? ?? 2B C2 C1 F8 ?? 3B C8 0F 84 ?? ?? ?? ?? 68 ?? ?? ?? ?? 2B C1 6A ?? 50 
            8D 04 8A 50 E8 ?? ?? ?? ?? 83 C4 ?? E9
        }

        $encrypt_files_win32_p1 = {
            55 8B EC 6A ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 81 EC ?? ?? ?? ?? A1 ?? ?? ?? ?? 
            33 C5 89 45 ?? 50 8D 45 ?? 64 A3 ?? ?? ?? ?? 89 4D ?? 83 7D ?? ?? 74 ?? 83 7D ?? ?? 
            75 ?? 32 C0 E9 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? 8B 45 ?? 50 8B 4D ?? E8 ?? ?? ?? ?? 
            89 85 ?? ?? ?? ?? 81 BD ?? ?? ?? ?? ?? ?? ?? ?? 73 ?? 32 C0 E9 ?? ?? ?? ?? C7 45 ?? 
            ?? ?? ?? ?? 33 C9 89 4D ?? 8D 55 ?? 52 8B 45 ?? 50 FF 15 ?? ?? ?? ?? 85 C0 75 ?? 32 
            C0 E9 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 6A ?? 8B 8D ?? ?? ?? ?? 
            51 8D 4D ?? E8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? C7 45 ?? ?? 
            ?? ?? ?? 33 D2 89 55 ?? C7 45 ?? ?? ?? ?? ?? 33 C0 89 45 ?? 0F 57 C0 66 0F 13 85 ?? 
            ?? ?? ?? EB ?? 8B 8D ?? ?? ?? ?? 81 C1 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 83 D2 ?? 89 8D 
            ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 3B 45 ?? 0F 8F ?? ?? ?? ?? 7C ?? 8B 
            8D ?? ?? ?? ?? 3B 4D ?? 0F 83 ?? ?? ?? ?? 0F 57 C0 66 0F 13 45 ?? 6A ?? 8D 55 ?? 52
        }

        $encrypt_files_win32_p2 = {
            8B 45 ?? 50 8B 4D ?? 51 8B 55 ?? 52 FF 15 ?? ?? ?? ?? 85 C0 75 ?? C6 45 ?? ?? 8D 4D 
            ?? E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8A 45 ?? E9 ?? ?? ?? ?? 6A ?? 8D 45 ?? 50 
            68 ?? ?? ?? ?? 6A ?? 8D 4D ?? E8 ?? ?? ?? ?? 50 8B 4D ?? 51 FF 15 ?? ?? ?? ?? 85 C0 
            75 ?? C6 45 ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8A 45 ?? E9 ?? ?? 
            ?? ?? 6A ?? 8D 55 ?? 52 8B 45 ?? 50 8B 4D ?? 51 8B 55 ?? 52 FF 15 ?? ?? ?? ?? 85 C0 
            75 ?? C6 45 ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8A 45 ?? E9 ?? ?? 
            ?? ?? C7 45 ?? ?? ?? ?? ?? EB ?? 8B 45 ?? 05 ?? ?? ?? ?? 89 45 ?? 8B 4D ?? 3B 4D ?? 
            0F 83 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 03 45 ?? 50 6A ?? 8D 4D ?? 
            E8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8B 95 ?? ?? ?? ?? 52 68 ?? ?? ?? ?? 8D 45 
            ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 50 6A ?? 8B 4D ?? 51 8B 4D ?? E8 ?? ?? ?? ?? 0F B6 D0 
            85 D2 75 ?? C6 45 ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8A 45 ?? E9 
            ?? ?? ?? ?? 6A ?? 8D 45 ?? 50 8B 8D ?? ?? ?? ?? 51 8D 4D ?? E8 ?? ?? ?? ?? 50 8B 55 
            ?? 52 FF 15 ?? ?? ?? ?? 85 C0 75 ?? C6 45 ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8D 4D ?? E8 
            ?? ?? ?? ?? 8A 45 ?? E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? 83 7D ?? ?? 75 ?? EB ?? E9 ?? ?? 
            ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 33 C0 89 85 ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? 89 4D
            ?? 8B 95 ?? ?? ?? ?? 89 55 ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 33 C0 89 85
        }

        $encrypt_files_win32_p3 = {
            8B 8D ?? ?? ?? ?? 89 4D ?? 8B 95 ?? ?? ?? ?? 89 55 ?? 6A ?? 8D 45 ?? 50 8B 4D ?? 51 
            8B 55 ?? 52 8B 45 ?? 50 FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 6A ?? 8D 4D ?? 51 
            8B 4D ?? 83 C1 ?? E8 ?? ?? ?? ?? 50 8B 4D ?? 83 C1 ?? E8 ?? ?? ?? ?? 50 8B 55 ?? 52 
            FF 15 ?? ?? ?? ?? 85 C0 74 ?? 8B 4D ?? 83 C1 ?? E8 ?? ?? ?? ?? 39 45 ?? 75 ?? 0F 57 
            C0 66 0F 13 45 ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 8B 45 ?? 89 45 ?? 8B 4D 
            ?? 89 4D ?? 8B 55 ?? 89 55 ?? 6A ?? 8D 45 ?? 50 6A ?? 8D 4D ?? 51 8B 55 ?? 52 FF 15 
            ?? ?? ?? ?? 85 C0 74 ?? 83 7D ?? ?? 75 ?? C6 45 ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8D 4D 
            ?? E8 ?? ?? ?? ?? 8A 45 ?? EB ?? C6 45 ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? 
            ?? ?? ?? 8A 45 ?? 8B 4D ?? 64 89 0D ?? ?? ?? ?? 59 8B 4D ?? 33 CD E8 ?? ?? ?? ?? 8B 
            E5 5D C2
        }

    condition:
        uint16(0) == 0x5A4D and
        (
            all of ($find_files_win32_p*)
        ) and
        (
            all of ($encrypt_files_win32_p*)
        ) and
        (
            all of ($encrypt_network_shares_win32_p*)
        )
}
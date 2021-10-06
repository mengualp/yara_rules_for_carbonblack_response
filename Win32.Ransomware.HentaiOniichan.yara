rule Win32_Ransomware_HentaiOniichan : tc_detection malicious
{
    meta:
 		score = 7

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "HENTAIONIICHAN"
        description         = "Yara rule that detects Hentai Oniichan ransomware."

        tc_detection_type   = "Ransomware"
        tc_detection_name   = "HentaiOniichan"
        tc_detection_factor = 5

    strings:

        $find_files_p1 = {
            8B FF 55 8B EC 81 EC ?? ?? ?? ?? A1 ?? ?? ?? ?? 33 C5 89 45 ?? 8B 4D ?? 8B 55 ?? 53 
            57 8B 7D ?? 89 95 ?? ?? ?? ?? 3B CF 74 ?? 8A 01 3C ?? 74 ?? 3C ?? 74 ?? 3C ?? 74 ?? 
            51 57 E8 ?? ?? ?? ?? 59 59 8B C8 3B CF 75 ?? 8B 95 ?? ?? ?? ?? 8A 01 88 85 ?? ?? ?? 
            ?? 3C ?? 75 ?? 8D 47 ?? 3B C8 74 ?? 52 33 DB 53 53 57 E8 ?? ?? ?? ?? 83 C4 ?? E9 ?? 
            ?? ?? ?? 8A 85 ?? ?? ?? ?? 33 DB 3C ?? 74 ?? 3C ?? 74 ?? 3C ?? 8A C3 75 ?? B0 ?? 2B 
            CF 0F B6 C0 41 89 9D ?? ?? ?? ?? F7 D8 89 9D ?? ?? ?? ?? 56 1B C0 89 9D ?? ?? ?? ?? 
            23 C1 89 9D ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 89 9D ?? ?? ?? ?? 88 9D ?? ?? ?? ?? E8 ?? 
            ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 50 57 E8 ?? ?? ?? ?? 83 C4 ?? 8D 8D ?? ?? ?? ?? F7 D8
        }

        $find_files_p2 = {
            1B C0 53 53 53 51 F7 D0 23 85 ?? ?? ?? ?? 53 50 FF 15 ?? ?? ?? ?? 8B F0 83 FE ?? 75 
            ?? FF B5 ?? ?? ?? ?? 53 53 57 E8 ?? ?? ?? ?? 83 C4 ?? 8B D8 E9 ?? ?? ?? ?? 8B 85 ?? 
            ?? ?? ?? 8B 48 ?? 2B 08 C1 F9 ?? 89 8D ?? ?? ?? ?? 89 9D ?? ?? ?? ?? 89 9D ?? ?? ?? 
            ?? 89 9D ?? ?? ?? ?? 89 9D ?? ?? ?? ?? 89 9D ?? ?? ?? ?? 88 9D ?? ?? ?? ?? E8 ?? ?? 
            ?? ?? 50 8D 85 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? 
            ?? 83 C4 ?? F7 D8 1B C0 F7 D0 23 85 ?? ?? ?? ?? 80 38 ?? 75 ?? 8A 48 ?? 84 C9 74 ?? 
            80 F9 ?? 75 ?? 38 58 ?? 74 ?? FF B5 ?? ?? ?? ?? FF B5 ?? ?? ?? ?? 57 50 E8 ?? ?? ?? 
            ?? 83 C4 ?? 89 85 ?? ?? ?? ?? 85 C0 75 ?? 38 9D ?? ?? ?? ?? 74 ?? FF B5 ?? ?? ?? ?? 
            E8 ?? ?? ?? ?? 59 8D 85 ?? ?? ?? ?? 50 56 FF 15 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 
            8B 85 ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? 8B 10 8B 40 ?? 2B C2 C1 F8 ?? 3B C8 74 ?? 68 ?? 
            ?? ?? ?? 2B C1 6A ?? 50 8D 04 8A 50 E8 ?? ?? ?? ?? 83 C4 ?? EB ?? 38 9D ?? ?? ?? ?? 
            74 ?? FF B5 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 59 8B D8 56 FF 15 ?? ?? ?? 
            ?? 80 BD ?? ?? ?? ?? ?? 5E 74 ?? FF B5 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 8B C3 8B 4D ?? 
            5F 33 CD 5B E8 ?? ?? ?? ?? C9 C3 
        }

        $inject_code_into_process = {
            33 C0 C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 50 6A ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 66 89 85 
            ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B F8 C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 
            50 57 FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 0F 1F 84 00 ?? ?? ?? ?? 8B C6 8D 8D 
            ?? ?? ?? ?? 66 8B 11 66 3B 10 75 ?? 66 85 D2 74 ?? 66 8B 51 ?? 66 3B 50 ?? 75 ?? 83 
            C1 ?? 83 C0 ?? 66 85 D2 75 ?? 33 C0 EB ?? 1B C0 83 C8 ?? 85 C0 75 ?? FF B5 ?? ?? ?? 
            ?? 50 6A ?? FF 15 ?? ?? ?? ?? 8B F0 85 F6 74 ?? FF 15 ?? ?? ?? ?? 39 85 ?? ?? ?? ?? 
            74 ?? 6A ?? 56 FF 15 ?? ?? ?? ?? 56 FF 15 ?? ?? ?? ?? 8B B5 ?? ?? ?? ?? 8D 85 ?? ?? 
            ?? ?? 50 57 FF 15 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 57 FF 15 ?? ?? ?? ?? C6 45 ?? 
            ?? 8B 55 ?? 83 FA ?? 72 ?? 8B 4D ?? 42 8B C1 81 FA ?? ?? ?? ?? 72 ?? 8B 49 ?? 83 C2 
            ?? 2B C1 83 C0 ?? 83 F8 ?? 0F 87 ?? ?? ?? ?? 52 51 E8 ?? ?? ?? ?? 83 C4 ?? C6 45 ?? 
            ?? 8B 55 ?? 83 FA ?? 72 ?? 8B 4D ?? 42 8B C1 81 FA ?? ?? ?? ?? 72 ?? 8B 49 ?? 83 C2 
            ?? 2B C1 83 C0 ?? 83 F8 ?? 0F 87 ?? ?? ?? ?? 52 51 E8 ?? ?? ?? ?? 83 C4 ?? 8B 8D ?? 
            ?? ?? ?? 83 C1 ?? 89 8D ?? ?? ?? ?? 3B 8D ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 8B 45 ?? 8B 
            4D ?? 85 C9 74 ?? 51 8B D0 E8 ?? ?? ?? ?? 8B 4D ?? B8 ?? ?? ?? ?? 8B 75 ?? 83 C4 ?? 
            2B CE F7 E9 C1 FA ?? 8B C2 C1 E8 ?? 03 C2 8D 0C 40 8B C6 C1 E1 ?? 81 F9 ?? ?? ?? ?? 
            72 ?? 8B 76 ?? 83 C1 ?? 2B C6 83 C0 ?? 83 F8 ?? 77 ?? 51 56 E8 ?? ?? ?? ?? 83 C4 ?? 
            8B 4D ?? 64 89 0D ?? ?? ?? ?? 59 5F 5E 8B 4D ?? 33 CD E8 ?? ?? ?? ?? 8B E5 5D 8B E3 
            5B C3 E8
        }

        $remote_connection_p1 = {
            68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 8D 45 ?? C7 45 
            ?? ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 0F 28 45 
            ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? 
            ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 66 0F EF 85 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 
            C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 0F 29 45 ?? 0F 28 45 
            ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? 
            ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 66 0F EF 85 ?? ?? ?? ?? 50 0F 29 45 ?? E8 ?? 
            ?? ?? ?? 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 8D 45 
            ?? C7 45 ?? ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 
            0F 28 45 ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? 
            ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 66 0F EF 85 ?? ?? ?? ?? 0F 29 45 ?? 
            C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 
            0F 28 45 ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? 
            ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 66 0F EF 85 ?? ?? ?? ?? C7 45 ?? ?? 
            ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 0F 29 45
        }

        $remote_connection_p2 = {
            0F 28 45 ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? 
            ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 66 0F EF 85 ?? ?? ?? ?? 50 0F 29 45 
            ?? E8 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? FF B5 ?? ?? ?? ?? 0F 43 95 
            ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? 
            ?? 85 C0 75 ?? 8B 85 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 6A ?? 8B 40 ?? 03 C8 33 C0 39 41 
            ?? 0F 94 C0 8D 04 85 ?? ?? ?? ?? 0B 41 ?? 50 E8 ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? B8 ?? 
            ?? ?? ?? 2B C1 83 F8 ?? 0F 82 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 51 
            0F 43 85 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 50 6A ?? 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 
            FF B5 ?? ?? ?? ?? E8 ?? ?? ?? ?? C6 45 ?? ?? 8D 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 
            0F 43 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 45 ?? 6A ?? 6A ?? 50 E8 ?? ?? ?? 
            ?? 83 C4 ?? 8D 4D ?? E8 ?? ?? ?? ?? C6 45 ?? ?? 8D 8D ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 
            ?? 8B 85 ?? ?? ?? ?? 0F 43 8D ?? ?? ?? ?? 03 C1 50 51 8D 85 ?? ?? ?? ?? 50 8D 4D ?? 
            E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 0F 43 
            85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 83 C4 ?? 8B F0 83 FA ?? 72 ?? 8B 
            8D ?? ?? ?? ?? 8D 14 55 ?? ?? ?? ?? 8B C1 81 FA ?? ?? ?? ?? 72 ?? 8B 49 ?? 83 C2 ?? 
            2B C1 83 C0 ?? 83 F8 ?? 0F 87 ?? ?? ?? ?? 52 51 E8 ?? ?? ?? ?? 83 C4
        }

        $encrypt_files = {
            8B FF 55 8B EC 83 EC ?? 8B 4D ?? 89 4D ?? 53 56 8B 75 ?? 57 8B 7D ?? 89 7D ?? 85 C9 
            0F 84 ?? ?? ?? ?? 85 FF 75 ?? E8 ?? ?? ?? ?? 83 20 ?? E8 ?? ?? ?? ?? C7 00 ?? ?? ?? 
            ?? E8 ?? ?? ?? ?? 83 C8 ?? E9 ?? ?? ?? ?? 8B C6 8B D6 C1 FA ?? 83 E0 ?? 6B C0 ?? 89 
            55 ?? 8B 14 95 ?? ?? ?? ?? 89 45 ?? 8A 5C 02 ?? 80 FB ?? 74 ?? 80 FB ?? 75 ?? 8B C1 
            F7 D0 A8 ?? 74 ?? 8B 45 ?? F6 44 02 ?? ?? 74 ?? 6A ?? 6A ?? 6A ?? 56 E8 ?? ?? ?? ?? 
            83 C4 ?? 56 E8 ?? ?? ?? ?? 59 84 C0 74 ?? 84 DB 74 ?? FE CB 80 FB ?? 0F 87 ?? ?? ?? 
            ?? FF 75 ?? 8D 45 ?? 57 50 E8 ?? ?? ?? ?? 83 C4 ?? 8B F0 E9 ?? ?? ?? ?? FF 75 ?? 8D 
            45 ?? 57 56 50 E8 ?? ?? ?? ?? 83 C4 ?? EB ?? 8B 45 ?? 8B 0C 85 ?? ?? ?? ?? 8B 45 ?? 
            80 7C 01 ?? ?? 7D ?? 0F BE C3 83 E8 ?? 74 ?? 83 E8 ?? 74 ?? 83 E8 ?? 0F 85 ?? ?? ?? 
            ?? FF 75 ?? 8D 45 ?? 57 56 50 E8 ?? ?? ?? ?? EB ?? FF 75 ?? 8D 45 ?? 57 56 50 E8 ?? 
            ?? ?? ?? EB ?? FF 75 ?? 8D 45 ?? 57 56 50 E8 ?? ?? ?? ?? EB ?? 8B 4C 01 ?? 8D 7D ?? 
            33 C0 AB 6A ?? AB AB 8D 45 ?? 50 FF 75 ?? FF 75 ?? 51 FF 15 ?? ?? ?? ?? 85 C0 75 ?? 
            FF 15 ?? ?? ?? ?? 89 45 ?? 8D 75 ?? 8D 7D ?? A5 A5 A5 8B 45 ?? 85 C0 75 ?? 8B 45 ?? 
            85 C0 74 ?? 6A ?? 5E 3B C6 75 ?? E8 ?? ?? ?? ?? C7 00 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 
            30 E9 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 59 E9 ?? ?? ?? ?? 8B 7D ?? 8B 45 ?? 8B 4D ?? 8B 
            04 85 ?? ?? ?? ?? F6 44 08 ?? ?? 74 ?? 80 3F ?? 74 ?? E8 ?? ?? ?? ?? C7 00 ?? ?? ?? 
            ?? E8 ?? ?? ?? ?? 83 20 ?? E9 ?? ?? ?? ?? 2B 45 ?? EB ?? 33 C0 5F 5E 5B C9 C3 
        }

    condition:
        uint16(0) == 0x5A4D and
        (
            $inject_code_into_process
        ) and
        (
            all of ($find_files_p*)
        ) and
        (
            $encrypt_files
        ) and
        (
            all of ($remote_connection_p*)
        )
}
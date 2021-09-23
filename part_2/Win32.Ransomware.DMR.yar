rule Win32_Ransomware_DMR : tc_detection malicious
{
    meta:
 		score = 7

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "DMR"
        description         = "Yara rule that detects DMR ransomware."

        tc_detection_type   = "Ransomware"
        tc_detection_name   = "DMR"
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
            1B C0 53 53 53 51 F7 D0 23 85 ?? ?? ?? ?? 53 50 FF 15 ?? ?? ?? ?? 8B F0 83 FE ?? 75 
            ?? FF B5 ?? ?? ?? ?? 53 53 57 E8 ?? ?? ?? ?? 83 C4 ?? 8B D8 E9 ?? ?? ?? ?? 8B 85 ?? 
            ?? ?? ?? 8B 48 ?? 2B 08 C1 F9 ?? 89 8D ?? ?? ?? ?? 89 9D ?? ?? ?? ?? 89 9D ?? ?? ?? 
            ?? 89 9D ?? ?? ?? ?? 89 9D ?? ?? ?? ?? 89 9D ?? ?? ?? ?? 88 9D ?? ?? ?? ?? E8 ?? ?? 
            ?? ?? 50 8D 85 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? 
            ?? 83 C4 ?? F7 D8 1B C0 F7 D0 23 85 ?? ?? ?? ?? 80 38 ?? 75 ?? 8A 48 ?? 84 C9 74
        }

        $find_files_p2 = {
            80 F9 ?? 75 ?? 38 58 ?? 74 ?? FF B5 ?? ?? ?? ?? FF B5 ?? ?? ?? ?? 57 50 E8 ?? ?? ?? 
            ?? 83 C4 ?? 89 85 ?? ?? ?? ?? 85 C0 75 ?? 38 9D ?? ?? ?? ?? 74 ?? FF B5 ?? ?? ?? ?? 
            E8 ?? ?? ?? ?? 59 8D 85 ?? ?? ?? ?? 50 56 FF 15 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 
            8B 85 ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? 8B 10 8B 40 ?? 2B C2 C1 F8 ?? 3B C8 74 ?? 68 ?? 
            ?? ?? ?? 2B C1 6A ?? 50 8D 04 8A 50 E8 ?? ?? ?? ?? 83 C4 ?? EB ?? 38 9D ?? ?? ?? ?? 
            74 ?? FF B5 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 59 8B D8 56 FF 15 ?? ?? ?? 
            ?? 80 BD ?? ?? ?? ?? ?? 5E 74 ?? FF B5 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 8B C3 8B 4D ?? 
            5F 33 CD 5B E8 ?? ?? ?? ?? C9 C3
        }

        $encrypt_files_p1 = {
            55 8B EC 6A ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 81 EC ?? ?? ?? ?? A1 ?? ?? ?? ?? 
            33 C5 89 45 ?? 56 57 50 8D 45 ?? 64 A3 ?? ?? ?? ?? 8B F1 89 B5 ?? ?? ?? ?? C7 45 ?? 
            ?? ?? ?? ?? 8D 45 ?? 83 7D ?? ?? 68 ?? ?? ?? ?? 0F 43 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 
            ?? 85 C0 0F 85 ?? ?? ?? ?? 83 7D ?? ?? 8D 45 ?? 68 ?? ?? ?? ?? 0F 43 45 ?? 50 E8 ?? 
            ?? ?? ?? 83 C4 ?? 85 C0 0F 85 ?? ?? ?? ?? 88 85 ?? ?? ?? ?? 8D 55 ?? FF B5 ?? ?? ?? 
            ?? 8D 4D ?? E8 ?? ?? ?? ?? 83 C4 ?? 8D 4D ?? C6 45 ?? ?? E8 ?? ?? ?? ?? C6 45 ?? ?? 
            8B 55 ?? 88 85 ?? ?? ?? ?? 83 FA ?? 72 ?? 8B 4D ?? 8D 14 55 ?? ?? ?? ?? 8B C1 81 FA 
            ?? ?? ?? ?? 72 ?? 8B 49 ?? 83 C2 ?? 2B C1 83 C0 ?? 83 F8 ?? 0F 87 ?? ?? ?? ?? 52 51 
            E8 ?? ?? ?? ?? 8A 85 ?? ?? ?? ?? 83 C4 ?? 84 C0 0F 84 ?? ?? ?? ?? C6 85 ?? ?? ?? ?? 
            ?? 8D 55 ?? FF B5 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 83 C4 ?? C6 45 ?? ?? 8D 45 ?? 
            83 7D ?? ?? 0F 43 45 ?? 50 FF 15 ?? ?? ?? ?? 83 E0 ?? 8D 4D ?? 83 7D ?? ?? 50 0F 43
        }

        $encrypt_files_p2 = {
            4D ?? 51 FF 15 ?? ?? ?? ?? 8D 45 ?? 50 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? 
            ?? 8D 85 ?? ?? ?? ?? C6 45 ?? ?? 6A ?? 50 E8 ?? ?? ?? ?? 83 7D ?? ?? 8D 45 ?? 8D 8D 
            ?? ?? ?? ?? 0F 43 45 ?? 50 E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8B 40 ?? C7 84 05 ?? ?? 
            ?? ?? ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8B 48 ?? 8D 41 ?? 89 84 0D ?? ?? ?? ?? 8D BE ?? 
            ?? ?? ?? C6 45 ?? ?? 83 7F ?? ?? 8B C7 89 BD ?? ?? ?? ?? 72 ?? 8B 07 83 7F ?? ?? 75 
            ?? 0F B6 00 3C ?? 75 ?? 33 C0 EB ?? 1B C0 83 C8 ?? 85 C0 75 ?? C7 86 ?? ?? ?? ?? ?? 
            ?? ?? ?? B8 ?? ?? ?? ?? EB ?? 8B 86 ?? ?? ?? ?? 6A ?? 50 8D 4D ?? C7 45 ?? ?? ?? ?? 
            ?? C7 45 ?? ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? C6 45 ?? ?? 8D 4D ?? 8B 86 ?? ?? 
            ?? ?? 83 7D ?? ?? 99 0F 43 4D ?? 52 50 51 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 8D ?? 
            ?? ?? ?? 8B 55 ?? 3B CA 77 ?? 83 7D ?? ?? 8D 45 ?? 89 4D ?? 0F 43 45 ?? C6 04 01 ?? 
            EB ?? 8B 45 ?? 8B F9 2B FA 2B C2 3B F8 77 ?? 83 7D ?? ?? 8D 75 ?? 57 0F 43 75 ?? 03
        }

        $encrypt_files_p3 = {
            F2 89 4D ?? 6A ?? 56 E8 ?? ?? ?? ?? C6 04 3E ?? 83 C4 ?? 8B B5 ?? ?? ?? ?? EB ?? 6A 
            ?? 57 C6 85 ?? ?? ?? ?? ?? 8D 4D ?? FF B5 ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? 8B BD ?? ?? 
            ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 75 ?? 8B 85 ?? ?? ?? ?? 8D 8D ?? ?? ?? 
            ?? 6A ?? 8B 40 ?? 03 C8 33 C0 39 41 ?? 0F 94 C0 8D 04 85 ?? ?? ?? ?? 0B 41 ?? 50 E8 
            ?? ?? ?? ?? 83 7D ?? ?? 8D 45 ?? 0F 43 45 ?? 83 BD ?? ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 
            6A ?? 6A ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? 6A ?? 50 8D 8D ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8B 48 ?? 89 8D ?? ?? ?? ?? 8B 01 FF 50 ?? 8D 
            85 ?? ?? ?? ?? C6 45 ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 8D ?? ?? ?? ?? 50 E8 ?? ?? 
            ?? ?? C6 45 ?? ?? 8B 8D ?? ?? ?? ?? 85 C9 74 ?? 8B 01 8B 40 ?? FF D0 85 C0 74 ?? 8B 
            08 6A ?? 8B 11 8B C8 FF D2 8B 85 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 33 D2 8B 40 ?? 03 C8 
            B8 ?? ?? ?? ?? 39 51 ?? 0F 45 C2 EB ?? 8B 85 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 8B 40 ?? 
            03 C8 33 C0 39 41 ?? 0F 94 C0 8D 04 85 ?? ?? ?? ?? 0B 41 ?? 6A ?? 50 E8 ?? ?? ?? ?? 
            81 C6 ?? ?? ?? ?? 8D 45 ?? 3B F0 74 ?? 83 7D ?? ?? 8B CE FF 75 ?? 0F 43 45 ?? 50 E8 
            ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 8D 4D ?? C7 45 ?? ?? ?? ?? ?? C7 45
        }

        $encrypt_files_p4 = {
            C6 45 ?? ?? E8 ?? ?? ?? ?? C6 45 ?? ?? 83 7F ?? ?? 8B 47 ?? 72 ?? 8B 3F 83 F8 ?? 75 
            ?? 0F B6 07 3C ?? 75 ?? 33 C0 EB ?? 1B C0 83 C8 ?? 8B BD ?? ?? ?? ?? 85 C0 75 ?? 8D 
            45 ?? 50 83 EC ?? 8D 87 ?? ?? ?? ?? 8B CC 89 A5 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 EC 
            ?? C6 45 ?? ?? 8B CC 56 E8 ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? EB ?? 8B BD ?? ?? 
            ?? ?? 8D 45 ?? 3B F0 74 ?? 83 7D ?? ?? 8B CE FF 75 ?? 0F 43 45 ?? 50 E8 ?? ?? ?? ?? 
            8D 45 ?? 3B C6 74 ?? 83 7E ?? ?? 8B C6 72 ?? 8B 06 FF 76 ?? 8D 4D ?? 50 E8 ?? ?? ?? 
            ?? 6A ?? 68 ?? ?? ?? ?? 8B CE E8 ?? ?? ?? ?? 83 7E ?? ?? 8B C6 72 ?? 8B 06 C7 46 ?? 
            ?? ?? ?? ?? 8D 55 ?? C6 00 ?? 8D 8D ?? ?? ?? ?? 83 7D ?? ?? FF 75 ?? 0F 43 55 ?? E8 
            ?? ?? ?? ?? 83 C4 ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 75 ?? 8B 85 ?? ?? ?? ?? 
            8D 8D ?? ?? ?? ?? 6A ?? 8B 40 ?? 03 C8 33 C0 39 41 ?? 0F 94 C0 8D 04 85 ?? ?? ?? ?? 
            0B 41 ?? 50 E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 8D 4D ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? 
            ?? ?? C6 45 ?? ?? 51 8B C8 E8 ?? ?? ?? ?? 8B F0 8D 85 ?? ?? ?? ?? C6 45 ?? ?? 50 8D 
            4D ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? 51 8B C8 E8 ?? ?? ?? ?? 8B C8 C6 
            45 ?? ?? 8B 41 ?? 8B 51 ?? 2B C2 83 F8 ?? 72 ?? 83 79 ?? ?? 8D 42 ?? 89 41 ?? 8B C1 
            72 ?? 8B 01 66 C7 04 02 ?? ?? EB ?? 6A ?? 68 ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? FF B5 
            ?? ?? ?? ?? 6A ?? E8 ?? ?? ?? ?? 8B C8 C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? 
            ?? ?? ?? ?? ?? 0F 10 01 0F 11 85 ?? ?? ?? ?? F3 0F 7E 41 ?? 66 0F D6 85 ?? ?? ?? ?? 
            C7 41 ?? ?? ?? ?? ?? C7 41 ?? ?? ?? ?? ?? C6 01 ?? C6 45 ?? ?? 8B 95 ?? ?? ?? ?? 8B
        }

        $encrypt_files_p5 = {
            C2 8B 8D ?? ?? ?? ?? 2B C1 83 F8 ?? 72 ?? 8D 41 ?? 83 FA ?? 89 85 ?? ?? ?? ?? 8D 85 
            ?? ?? ?? ?? 0F 43 85 ?? ?? ?? ?? C7 04 01 ?? ?? ?? ?? C6 44 01 ?? ?? 8D 85 ?? ?? ?? 
            ?? EB ?? 6A ?? 68 ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? FF B5 ?? ?? ?? 
            ?? 6A ?? E8 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 
            0F 10 00 0F 11 85 ?? ?? ?? ?? F3 0F 7E 40 ?? 66 0F D6 85 ?? ?? ?? ?? C7 40 ?? ?? ?? 
            ?? ?? C7 40 ?? ?? ?? ?? ?? C6 00 ?? 8D 47 ?? C6 45 ?? ?? 50 8D 8D ?? ?? ?? ?? E8 ?? 
            ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 0F 10 00 0F 11 
            85 ?? ?? ?? ?? F3 0F 7E 40 ?? 66 0F D6 85 ?? ?? ?? ?? C7 40 ?? ?? ?? ?? ?? C7 40 ?? 
            ?? ?? ?? ?? C6 00 ?? C6 45 ?? ?? 8B 95 ?? ?? ?? ?? 8B C2 8B 8D ?? ?? ?? ?? 2B C1 83 
            F8 ?? 72 ?? 8D 41 ?? 83 FA ?? 89 85 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 0F 43 85 ?? ?? ?? 
            ?? 66 C7 04 08 ?? ?? 8D 85 ?? ?? ?? ?? EB ?? 6A ?? 68 ?? ?? ?? ?? C6 85 ?? ?? ?? ?? 
            ?? 8D 8D ?? ?? ?? ?? FF B5 ?? ?? ?? ?? 6A ?? E8 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? 
            ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 0F 10 00 0F 11 85 ?? ?? ?? ?? F3 0F 7E 40 ?? 66 
            0F D6 85 ?? ?? ?? ?? C7 40 ?? ?? ?? ?? ?? C7 40 ?? ?? ?? ?? ?? C6 00 ?? C6 45
        }

        $encrypt_files_p6 = {
            8B BD ?? ?? ?? ?? 8B C7 8B 8D ?? ?? ?? ?? 2B C1 8B 56 ?? 3B D0 76 ?? 8B 46 ?? 2B C2 
            3B C1 72 ?? 83 FF ?? 8D 85 ?? ?? ?? ?? 51 0F 43 85 ?? ?? ?? ?? 8B CE 50 6A ?? E8 ?? 
            ?? ?? ?? EB ?? 56 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 
            85 ?? ?? ?? ?? ?? ?? ?? ?? 0F 10 00 0F 11 85 ?? ?? ?? ?? F3 0F 7E 40 ?? 66 0F D6 85 
            ?? ?? ?? ?? C6 00 ?? C7 40 ?? ?? ?? ?? ?? C7 40 ?? ?? ?? ?? ?? C6 45 ?? ?? 8B 95 ?? 
            ?? ?? ?? 8B C2 8B 8D ?? ?? ?? ?? 2B C1 6A ?? 68 ?? ?? ?? ?? 83 F8 ?? 72 ?? 83 FA ?? 
            8D B5 ?? ?? ?? ?? 8D 41 ?? 0F 43 B5 ?? ?? ?? ?? 03 F1 89 85 ?? ?? ?? ?? 56 E8 ?? ?? 
            ?? ?? 83 C4 ?? C6 46 ?? ?? 8D 85 ?? ?? ?? ?? EB ?? C6 85 ?? ?? ?? ?? ?? 8D 8D ?? ?? 
            ?? ?? FF B5 ?? ?? ?? ?? 6A ?? E8 ?? ?? ?? ?? 0F 10 00 0F 11 45 ?? F3 0F 7E 40 ?? 66 
            0F D6 45 ?? C7 40 ?? ?? ?? ?? ?? C7 40 ?? ?? ?? ?? ?? C6 00 ?? C6 45 ?? ?? 8B 95 ?? 
            ?? ?? ?? 83 FA ?? 72 ?? 8B 8D ?? ?? ?? ?? 42 8B C1 81 FA ?? ?? ?? ?? 72 ?? 8B 49 ?? 
            83 C2 ?? 2B C1 83 C0 ?? 83 F8 ?? 0F 87 ?? ?? ?? ?? 52 51 E8 ?? ?? ?? ?? 83 C4 ?? C7 
            85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? C6 45 
            ?? ?? 8B 95 ?? ?? ?? ?? 83 FA ?? 72 ?? 8B 8D ?? ?? ?? ?? 42 8B C1 81 FA ?? ?? ?? ?? 
            72 ?? 8B 49 ?? 83 C2 ?? 2B C1 83 C0 ?? 83 F8 ?? 0F 87 ?? ?? ?? ?? 52 51 E8 ?? ?? ?? 
            ?? 83 C4 ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C6 85 ?? ?? 
            ?? ?? ?? C6 45 ?? ?? 8B 95 ?? ?? ?? ?? 83 FA ?? 72 ?? 8B 8D ?? ?? ?? ?? 42 8B C1 81
        }

        $encrypt_files_p7 = {
            FA ?? ?? ?? ?? 72 ?? 8B 49 ?? 83 C2 ?? 2B C1 83 C0 ?? 83 F8 ?? 0F 87 ?? ?? ?? ?? 52 
            51 E8 ?? ?? ?? ?? 83 C4 ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? 
            ?? C6 85 ?? ?? ?? ?? ?? C6 45 ?? ?? 8B 95 ?? ?? ?? ?? 83 FA ?? 72 ?? 8B 8D ?? ?? ?? 
            ?? 42 8B C1 81 FA ?? ?? ?? ?? 72 ?? 8B 49 ?? 83 C2 ?? 2B C1 83 C0 ?? 83 F8 ?? 0F 87 
            ?? ?? ?? ?? 52 51 E8 ?? ?? ?? ?? 83 C4 ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? 
            ?? ?? ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? C6 45 ?? ?? 8B 95 ?? ?? ?? ?? 83 FA ?? 72 ?? 
            8B 8D ?? ?? ?? ?? 42 8B C1 81 FA ?? ?? ?? ?? 72 ?? 8B 49 ?? 83 C2 ?? 2B C1 83 C0 ?? 
            83 F8 ?? 0F 87 ?? ?? ?? ?? 52 51 E8 ?? ?? ?? ?? 83 C4 ?? C7 85 ?? ?? ?? ?? ?? ?? ?? 
            ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? C6 45 ?? ?? 8B 95 ?? ?? ?? ?? 
            83 FA ?? 72 ?? 8B 8D ?? ?? ?? ?? 42 8B C1 81 FA ?? ?? ?? ?? 72 ?? 8B 49 ?? 83 C2 ?? 
            2B C1 83 C0 ?? 83 F8 ?? 0F 87 ?? ?? ?? ?? 52 51 E8 ?? ?? ?? ?? 83 C4 ?? C7 85 ?? ?? 
            ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? C6 45 ?? ?? 8B
        }

        $encrypt_files_p8 = {
            95 ?? ?? ?? ?? 83 FA ?? 72 ?? 8B 8D ?? ?? ?? ?? 8D 14 55 ?? ?? ?? ?? 8B C1 81 FA ?? 
            ?? ?? ?? 72 ?? 8B 49 ?? 83 C2 ?? 2B C1 83 C0 ?? 83 F8 ?? 0F 87 ?? ?? ?? ?? 52 51 E8 
            ?? ?? ?? ?? 83 C4 ?? 33 C0 C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? 
            ?? 66 89 85 ?? ?? ?? ?? C6 45 ?? ?? 8B 95 ?? ?? ?? ?? 83 FA ?? 72 ?? 8B 8D ?? ?? ?? 
            ?? 42 8B C1 81 FA ?? ?? ?? ?? 72 ?? 8B 49 ?? 83 C2 ?? 2B C1 83 C0 ?? 83 F8 ?? 0F 87 
            ?? ?? ?? ?? 52 51 E8 ?? ?? ?? ?? 83 C4 ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? 
            ?? ?? ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? C6 45 ?? ?? 8B 95 ?? ?? ?? ?? 83 FA ?? 72 ?? 
            8B 8D ?? ?? ?? ?? 8D 14 55 ?? ?? ?? ?? 8B C1 81 FA ?? ?? ?? ?? 72 ?? 8B 49 ?? 83 C2 
            ?? 2B C1 83 C0 ?? 83 F8 ?? 0F 87 ?? ?? ?? ?? 52 51 E8 ?? ?? ?? ?? 83 C4 ?? 33 C0 C7 
            85 ?? ?? ?? ?? ?? ?? ?? ?? 83 EC ?? 66 89 85 ?? ?? ?? ?? 8D 45 ?? C7 85 ?? ?? ?? ?? 
            ?? ?? ?? ?? 8B CC 50 E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 8B F0 
            C6 45 ?? ?? 83 7E ?? ?? 72 ?? 8B 36 83 EC ?? 8D 85 ?? ?? ?? ?? 8B CC 50 E8 ?? ?? ?? 
            ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 83 78 ?? ?? 72 ?? 8B 00 56 50 E8 ?? ?? 
            ?? ?? 8B 95 ?? ?? ?? ?? 83 C4 ?? 83 FA ?? 72 ?? 8B 8D ?? ?? ?? ?? 8D 14 55 ?? ?? ?? 
            ?? 8B C1 81 FA ?? ?? ?? ?? 72 ?? 8B 49 ?? 83 C2 ?? 2B C1 83 C0 ?? 83 F8 ?? 0F 87 ?? 
            ?? ?? ?? 52 51 E8 ?? ?? ?? ?? 83 C4 ?? 8B 95 ?? ?? ?? ?? 33 C0 C7 85 ?? ?? ?? ?? ?? 
            ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 66 89 85 ?? ?? ?? ?? 83 FA ?? 72 ?? 8B 8D ?? 
            ?? ?? ?? 8D 14 55 ?? ?? ?? ?? 8B C1 81 FA ?? ?? ?? ?? 72 ?? 8B 49 ?? 83 C2 ?? 2B C1
        }

        $encrypt_files_p9 = {
            83 C0 ?? 83 F8 ?? 0F 87 ?? ?? ?? ?? 52 51 E8 ?? ?? ?? ?? 83 C4 ?? 8B 55 ?? 83 FA ?? 
            72 ?? 8B 4D ?? 42 8B C1 81 FA ?? ?? ?? ?? 72 ?? 8B 49 ?? 83 C2 ?? 2B C1 83 C0 ?? 83 
            F8 ?? 0F 87 ?? ?? ?? ?? 52 51 E8 ?? ?? ?? ?? 83 C4 ?? 8B 55 ?? 83 FA ?? 72 ?? 8B 4D 
            ?? 42 8B C1 81 FA ?? ?? ?? ?? 72 ?? 8B 49 ?? 83 C2 ?? 2B C1 83 C0 ?? 83 F8 ?? 0F 87 
            ?? ?? ?? ?? 52 51 E8 ?? ?? ?? ?? 83 C4 ?? 8B 55 ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? 
            ?? ?? ?? C6 45 ?? ?? 83 FA ?? 72 ?? 8B 4D ?? 42 8B C1 81 FA ?? ?? ?? ?? 72 ?? 8B 49 
            ?? 83 C2 ?? 2B C1 83 C0 ?? 83 F8 ?? 0F 87 ?? ?? ?? ?? 52 51 E8 ?? ?? ?? ?? 83 C4 ?? 
            8D 8D ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? 
            ?? 8B 55 ?? 83 FA ?? 72 ?? 8B 8D ?? ?? ?? ?? 42 8B C1 81 FA ?? ?? ?? ?? 72 ?? 8B 49 
            ?? 83 C2 ?? 2B C1 83 C0 ?? 83 F8 ?? 0F 87 ?? ?? ?? ?? 52 51 E8 ?? ?? ?? ?? 83 C4 ?? 
            8B 55 ?? 83 FA ?? 72 ?? 8B 4D ?? 8D 14 55 ?? ?? ?? ?? 8B C1 81 FA ?? ?? ?? ?? 72 ?? 
            8B 49 ?? 83 C2 ?? 2B C1 83 C0 ?? 83 F8 ?? 77 ?? 52 51 E8 ?? ?? ?? ?? 83 C4 ?? 8B 55 
            ?? 83 FA ?? 72 ?? 8B 4D ?? 42 8B C1 81 FA ?? ?? ?? ?? 72 ?? 8B 49 ?? 83 C2 ?? 2B C1 
            83 C0 ?? 83 F8 ?? 77 ?? 52 51 E8 ?? ?? ?? ?? 83 C4 ?? 8B 4D ?? 64 89 0D ?? ?? ?? ?? 
            59 5F 5E 8B 4D ?? 33 CD E8 ?? ?? ?? ?? 8B E5 5D C2 ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? 
            ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8
        }

    condition:
        uint16(0) == 0x5A4D and
        (
            all of ($find_files_p*)
        ) and
        (
            all of ($encrypt_files_p*)
        )
}
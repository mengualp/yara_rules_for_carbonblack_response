rule Win32_Ransomware_Ferrlock : tc_detection malicious
{
    meta:
 		score = 7

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "FERRLOCK"
        description         = "Yara rule that detects Ferrlock ransomware."

        tc_detection_type   = "Ransomware"
        tc_detection_name   = "Ferrlock"
        tc_detection_factor = 5

    strings:

        $search_files_p1 = {
            8B FF 55 8B EC 51 8B 4D ?? 8D 51 ?? 8A 01 41 84 C0 75 ?? 57 8B 7D ?? 2B CA 8B C7 41 
            F7 D0 89 4D ?? 3B C8 76 ?? 6A ?? 58 EB ?? 53 56 8D 5F ?? 03 D9 6A ?? 53 E8 ?? ?? ?? 
            ?? 8B F0 59 59 85 FF 74 ?? 57 FF 75 ?? 53 56 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 75 ?? FF 
            75 ?? 2B DF 8D 04 3E FF 75 ?? 53 50 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 75 ?? 8B 5D ?? 8B 
            CB E8 ?? ?? ?? ?? 33 FF 89 45 ?? 85 C0 74 ?? 56 E8 ?? ?? ?? ?? 8B 75 ?? 59 EB ?? 8B 
            43 ?? 89 30 8B F7 83 43 ?? ?? 57 E8 ?? ?? ?? ?? 59 8B C6 5E 5B 5F 8B E5 5D C3 33 FF 
            57 57 57 57 57 E8 ?? ?? ?? ?? CC 8B FF 55 8B EC 81 EC ?? ?? ?? ?? A1 ?? ?? ?? ?? 33 
            C5 89 45 ?? 8B 4D ?? 53 8B 5D ?? 57 8B 7D ?? 89 9D ?? ?? ?? ?? EB ?? 8A 01 3C ?? 74 
            ?? 3C ?? 74 ?? 3C ?? 74 ?? 51 57 E8 ?? ?? ?? ?? 59 59 8B C8 3B CF 75 ?? 8A 11 80 FA 
            ?? 75 ?? 8D 47 ?? 3B C8 74 ?? 53 33 DB 53 53 57 E8 ?? ?? ?? ?? 83 C4 ?? EB ?? 33 DB
        }

        $search_files_p2 = {
            80 FA ?? 74 ?? 80 FA ?? 74 ?? 8A C3 80 FA ?? 75 ?? B0 ?? 0F B6 C0 2B CF 41 F7 D8 56 
            1B C0 23 C1 68 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 53 50 E8 ?? ?? ?? ?? 
            83 C4 ?? 8D 85 ?? ?? ?? ?? 53 53 53 50 53 57 FF 15 ?? ?? ?? ?? 8B F0 8B 85 ?? ?? ?? 
            ?? 83 FE ?? 75 ?? 50 53 53 57 E8 ?? ?? ?? ?? 83 C4 ?? 8B D8 83 FE ?? 74 ?? 56 FF 15 
            ?? ?? ?? ?? 8B C3 5E 8B 4D ?? 5F 33 CD 5B E8 ?? ?? ?? ?? 8B E5 5D C3 8B 48 ?? 2B 08 
            C1 F9 ?? 89 8D ?? ?? ?? ?? 80 BD ?? ?? ?? ?? ?? 75 ?? 8A 8D ?? ?? ?? ?? 84 C9 74 ?? 
            80 F9 ?? 75 ?? 38 9D ?? ?? ?? ?? 74 ?? 50 FF B5 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 57 50 
            E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 75 ?? 8D 85 ?? ?? ?? ?? 50 56 FF 15 ?? ?? ?? ?? 85 C0 
            8B 85 ?? ?? ?? ?? 75 ?? 8B 10 8B 40 ?? 8B 8D ?? ?? ?? ?? 2B C2 C1 F8 ?? 3B C8 0F 84 
            ?? ?? ?? ?? 68 ?? ?? ?? ?? 2B C1 6A ?? 50 8D 04 8A 50 E8 ?? ?? ?? ?? 83 C4 ?? E9
        }

        $enum_rsrc = {
            6A ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 4D ?? 8B 45 ?? 8D 4D ?? 83 4D ?? ?? 51 50 6A 
            ?? 6A ?? 6A ?? C7 45 ?? ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? FF 75 
            ?? 6A ?? FF 15 ?? ?? ?? ?? 8B F0 85 F6 0F 84 ?? ?? ?? ?? EB ?? 33 DB 39 5D ?? 7E ?? 
            8D 7E ?? F7 47 ?? ?? ?? ?? ?? 74 ?? 8D 47 ?? 89 45 ?? 8B 45 ?? 8B 00 8B 48 ?? 85 C9 
            74 ?? 8B 01 8D 55 ?? 52 FF 50 ?? EB ?? FF 37 8D 4D ?? E8 ?? ?? ?? ?? 83 65 ?? ?? 8D 
            45 ?? 50 8B 45 ?? 8B 48 ?? E8 ?? ?? ?? ?? 83 4D ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 43 83 
            C7 ?? 3B 5D ?? 7C ?? 83 4D ?? ?? C7 45 ?? ?? ?? ?? ?? 8D 45 ?? 50 56 8D 45 ?? 50 FF 
            75 ?? FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 56 FF 15 ?? ?? ?? ?? FF 75 ?? FF 15 
            ?? ?? ?? ?? E8 ?? ?? ?? ?? C2 ?? ?? E8 ?? ?? ?? ?? CC 55 8B EC 6A ?? 68 ?? ?? ?? ?? 
            64 A1 ?? ?? ?? ?? 50 56 A1 ?? ?? ?? ?? 33 C5 50 8D 45 ?? 64 A3 ?? ?? ?? ?? 8B F1 83 
            65 ?? ?? 8B 4E ?? 85 C9 74 ?? 8B 11 3B CE 0F 95 C0 0F B6 C0 50 FF 52 ?? 83 66 ?? ?? 
            8B 4D ?? 64 89 0D ?? ?? ?? ?? 59 5E 8B E5 5D C3 
        }

        $create_test_file_p1 = {
            68 ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 8D 4D ?? E8 ?? ?? ?? ?? 33 DB 8D 55 
            ?? 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 89 5D ?? E8 ?? ?? ?? ?? 59 8D 45 ?? C6 45 ?? ?? 
            50 8D 4D ?? 89 5D ?? 89 5D ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 4D ?? C6 45 ?? ?? E8 
            ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 83 CB ?? 8B 3D ?? ?? ?? ?? E9 ?? ?? ?? ?? 83 65 ?? ?? 
            8D 4D ?? 83 65 ?? ?? 56 E8 ?? ?? ?? ?? C6 45 ?? ?? 8D 4D ?? FF 75 ?? 8B 45 ?? 2B 45 
            ?? 50 8D 45 ?? 50 E8 ?? ?? ?? ?? 83 7D ?? ?? 8D 45 ?? 8B 55 ?? 8D 4D ?? 0F 43 45 ?? 
            83 7D ?? ?? 0F 43 4D ?? 3B 55 ?? 75 ?? 52 50 51 E8 ?? ?? ?? ?? 83 C4 ?? C6 85 ?? ?? 
            ?? ?? ?? 85 C0 74 ?? C6 85 ?? ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 80 BD ?? ?? ?? ?? 
            ?? 8D 4D ?? 0F 85 ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 83 C6 ?? 3B F7 0F 85 ?? ?? 
            ?? ?? 83 7D ?? ?? 8D 45 ?? 8B 35 ?? ?? ?? ?? BF ?? ?? ?? ?? 0F 43 45 ?? 33 C9 51 57
        }

        $create_test_file_p2 = {
            6A ?? 51 51 68 ?? ?? ?? ?? 50 FF D6 3B C3 0F 84 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 83 
            7D ?? ?? 8D 45 ?? 0F 43 45 ?? 50 FF 15 ?? ?? ?? ?? 83 7D ?? ?? 8D 45 ?? 0F 43 45 ?? 
            33 C9 51 57 6A ?? 51 51 68 ?? ?? ?? ?? 50 FF D6 8B F8 3B FB 0F 84 ?? ?? ?? ?? 6A ?? 
            57 FF 15 ?? ?? ?? ?? 8B F0 85 F6 75 ?? 57 FF 15 ?? ?? ?? ?? E9 ?? ?? ?? ?? E8 ?? ?? 
            ?? ?? E9 ?? ?? ?? ?? 6A ?? 58 3B F0 0F 42 F0 03 F0 56 E8 ?? ?? ?? ?? 59 6A ?? 89 85 
            ?? ?? ?? ?? 8D 45 ?? 50 56 8B B5 ?? ?? ?? ?? 56 57 FF 15 ?? ?? ?? ?? 83 7D ?? ?? 75 
            ?? 57 FF 15 ?? ?? ?? ?? EB ?? 83 7D ?? ?? 8D 45 ?? FF 75 ?? 0F 43 45 ?? 8D 55 ?? 50 
            8B CE E8 ?? ?? ?? ?? 59 59 33 DB 53 53 53 57 FF 15 ?? ?? ?? ?? 53 8D 45 ?? 50 FF 75 
            ?? 56 57 FF 15 ?? ?? ?? ?? 57 FF 15 ?? ?? ?? ?? 83 7D ?? ?? 8D 4D ?? 8D 45 ?? 0F 43 
            4D ?? 83 7D ?? ?? 51 0F 43 45 ?? 50 FF 15 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 59 8D 4D ?? 
            E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8B C3 E8 ?? 
            ?? ?? ?? C3 
        }

        $encrypt_files_p1 = {
            68 ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 8D ?? ?? ?? ?? 33 F6 8D 4D ?? 89 B5 
            ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 75 ?? 8D 4D ?? 68 ?? ?? ?? ?? 89 75 ?? 89 75 ?? E8 ?? 
            ?? ?? ?? 68 ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 83 7D ?? ?? 8D 7D ?? 8B D8 8B 45 
            ?? 0F 43 7D ?? 59 3B D8 77 ?? 85 DB 74 ?? 2B C3 40 03 C7 89 85 ?? ?? ?? ?? 2B C7 50 
            6A ?? 57 EB ?? 53 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 74 ?? 8B 85 ?? ?? 
            ?? ?? 46 2B C6 50 6A ?? 56 E8 ?? ?? ?? ?? 8B F0 83 C4 ?? 85 F6 75 ?? EB ?? 2B F7 EB 
            ?? 83 CE ?? 83 FE ?? 74 ?? 83 7D ?? ?? 8D 45 ?? FF 75 ?? 0F 43 45 ?? 50 51 56 8D 4D 
            ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 33 F6 8D 85 ?? ?? ?? ?? 56 50 E8 ?? ?? ?? ?? C7 85 
            ?? ?? ?? ?? ?? ?? ?? ?? 83 C4 ?? C6 45 ?? ?? 8D 85 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? 
            ?? ?? ?? 8D 8D ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85
        }

        $encrypt_files_p2 = {
            50 E8 ?? ?? ?? ?? 6A ?? 5F 89 7D ?? 8B 85 ?? ?? ?? ?? 8B 40 ?? C7 84 05 ?? ?? ?? ??
            ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8B 48 ?? 51 8D 41 ?? 89 84 0D ?? ?? ?? ?? 8D 8D ?? ??
            ?? ?? E8 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 68 ?? ?? ?? ?? C6 45 ?? ??
            E8 ?? ?? ?? ?? C6 45 ?? ?? 8B C8 C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 8D 8D ?? ??
            ?? ?? E8 ?? ?? ?? ?? C6 45 ?? ?? 8D 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 51 0F 43 85
            ?? ?? ?? ?? 51 50 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ??
            8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 39 B5 ?? ?? ?? ?? 74 ?? 83 7D ?? ?? 8D
            55 ?? FF 75 ?? 0F 43 55 ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 8D 8D ?? ?? ?? ?? E8
            ?? ?? ?? ?? 85 C0 75 ?? 8B 85 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 56 8B 40 ?? 03 C8 8B 51
            ?? 83 CA ?? 8B C2 0B C7 39 71 ?? 0F 44 D0 52 E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ??
            ?? ?? ?? 8D 85 ?? ?? ?? ?? C6 45 ?? ?? 50 C7 85 ?? ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? ??
            ?? 59 8D 4D ?? E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? C3 
        }

    condition:
        uint16(0) == 0x5A4D and 
        (
            $enum_rsrc
        ) and 
        (
            all of ($search_files_p*)
        ) and 
        (
            all of ($create_test_file_p*)
        ) and 
        (
            all of ($encrypt_files_p*)
        )
}
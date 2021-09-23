rule Win32_Ransomware_Ouroboros : tc_detection malicious
{
    meta:
 		score = 7

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "OUROBOROS"
        description         = "Yara rule that detects Ouroboros ransomware."

        tc_detection_type   = "Ransomware"
        tc_detection_name   = "Ouroboros"
        tc_detection_factor = 5

    strings:

        $remote_connection_p1 = {
            55 8B EC 6A ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 81 EC ?? ?? ?? ?? A1 ?? ?? ?? ?? 
            33 C5 89 45 ?? 56 50 8D 45 ?? 64 A3 ?? ?? ?? ?? 8B 75 ?? 8D 8D ?? ?? ?? ?? 6A ?? 68 
            ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C6 85 ?? ?? 
            ?? ?? ?? E8 ?? ?? ?? ?? 6A ?? 8D 85 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 50 8D 8D ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? C6 45 ?? ?? 83 FA ?? 72 ?? 8B 8D ?? ?? ?? ?? 
            42 8B C1 81 FA ?? ?? ?? ?? 72 ?? 8B 49 ?? 83 C2 ?? 2B C1 83 C0 ?? 83 F8 ?? 0F 87 ?? 
            ?? ?? ?? 52 51 E8 ?? ?? ?? ?? 83 C4 ?? 6A ?? 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C7 85 
            ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? C7 85 ?? 
            ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? E8 ?? ?? ?? 
            ?? 6A ?? 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 
            C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 85
        }

        $remote_connection_p2 = {
            C6 45 ?? ?? 50 6A ?? 8D 85 ?? ?? ?? ?? 50 8D 4D ?? E8 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 
            C6 45 ?? ?? 83 FA ?? 72 ?? 8B 8D ?? ?? ?? ?? 42 8B C1 81 FA ?? ?? ?? ?? 72 ?? 8B 49 
            ?? 83 C2 ?? 2B C1 83 C0 ?? 83 F8 ?? 0F 87 ?? ?? ?? ?? 52 51 E8 ?? ?? ?? ?? 83 C4 ?? 
            C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? 8B 
            95 ?? ?? ?? ?? C6 45 ?? ?? 83 FA ?? 72 ?? 8B 8D ?? ?? ?? ?? 42 8B C1 81 FA ?? ?? ?? 
            ?? 72 ?? 8B 49 ?? 83 C2 ?? 2B C1 83 C0 ?? 83 F8 ?? 0F 87 ?? ?? ?? ?? 52 51 E8 ?? ?? 
            ?? ?? 83 C4 ?? FF 75 ?? 8D 45 ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? FF 75 ?? 8D 8D ?? ?? 
            ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 50 8D 45 ?? C6 85 ?? ?? ?? ?? ?? 50 E8 ?? ?? ?? 
            ?? 8D 4D ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 8D 4D ?? E8 
            ?? ?? ?? ?? 50 8B CE C7 06 ?? ?? ?? ?? C6 46 ?? ?? E8 ?? ?? ?? ?? 8B 55 ?? 83 FA ?? 
            72 ?? 8B 4D ?? 42 8B C1 81 FA ?? ?? ?? ?? 72 ?? 8B 49 ?? 83 C2 ?? 2B C1 83 C0 ?? 83
        }
            
        $remote_connection_p3 = {
            F8 ?? 0F 87 ?? ?? ?? ?? 52 51 E8 ?? ?? ?? ?? 83 C4 ?? 8B 45 ?? C7 45 ?? ?? ?? ?? ?? 
            C7 45 ?? ?? ?? ?? ?? C6 45 ?? ?? FF 70 ?? 8D 45 ?? 50 8B C8 E8 ?? ?? ?? ?? 6A ?? FF 
            75 ?? E8 ?? ?? ?? ?? 8B 55 ?? 83 C4 ?? 83 FA ?? 72 ?? 8B 4D ?? 42 8B C1 81 FA ?? ?? 
            ?? ?? 72 ?? 8B 49 ?? 83 C2 ?? 2B C1 83 C0 ?? 83 F8 ?? 0F 87 ?? ?? ?? ?? 52 51 E8 ?? 
            ?? ?? ?? 83 C4 ?? 8B 55 ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C6 45 ?? ?? 83 
            FA ?? 72 ?? 8B 4D ?? 42 8B C1 81 FA ?? ?? ?? ?? 72 ?? 8B 49 ?? 83 C2 ?? 2B C1 83 C0 
            ?? 83 F8 ?? 0F 87 ?? ?? ?? ?? 52 51 E8 ?? ?? ?? ?? 83 C4 ?? 8B 45 ?? C7 45 ?? ?? ?? 
            ?? ?? C7 45 ?? ?? ?? ?? ?? C6 45 ?? ?? FF 70 ?? 8D 45 ?? 50 8B C8 E8 ?? ?? ?? ?? 6A 
            ?? FF 75 ?? E8 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 83 C4 ?? 83 FA ?? 72 ?? 8B 8D ?? ?? ?? 
            ?? 42 8B C1 81 FA ?? ?? ?? ?? 72 ?? 8B 49 ?? 83 C2 ?? 2B C1 83 C0 ?? 83 F8 ?? 0F 87 
            ?? ?? ?? ?? 52 51 E8 ?? ?? ?? ?? 83 C4 ?? 8B 8D ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? 
            ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? 85 C9 74 ?? 8B 95 ?? ?? ?? 
            ?? 8B C1 2B D1 81 FA ?? ?? ?? ?? 72 ?? 8B 49 ?? 83 C2 ?? 2B C1 83 C0 ?? 83 F8 ?? 0F 
            87 ?? ?? ?? ?? 52 51 E8 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 83 C4 ?? C7 85 ?? 
            ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 
            8B C6 8B 4D ?? 64 89 0D ?? ?? ?? ?? 59 5E 8B 4D ?? 33 CD E8 ?? ?? ?? ?? 8B E5 5D C3
        }

        $remote_connection_p4 = { 
            8B 55 ?? C7 06 ?? ?? ?? ?? C6 46 ?? ?? 83 FA ?? 72 ?? 8B 4D ?? 42 8B C1 81 FA ?? ?? 
            ?? ?? 72 ?? 8B 49 ?? 83 C2 ?? 2B C1 83 C0 ?? 83 F8 ?? 0F 87 ?? ?? ?? ?? 52 51 E8 ?? 
            ?? ?? ?? 83 C4 ?? 8B 45 ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C6 45 ?? ?? FF 
            70 ?? 8D 45 ?? 50 8B C8 E8 ?? ?? ?? ?? 6A ?? FF 75 ?? E8 ?? ?? ?? ?? 8B 55 ?? 83 C4 
            ?? 83 FA ?? 72 ?? 8B 4D ?? 42 8B C1 81 FA ?? ?? ?? ?? 72 ?? 8B 49 ?? 83 C2 ?? 2B C1 
            83 C0 ?? 83 F8 ?? 0F 87 ?? ?? ?? ?? 52 51 E8 ?? ?? ?? ?? 83 C4 ?? 8B 55 ?? C7 45 ?? 
            ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C6 45 ?? ?? 83 FA ?? 72 ?? 8B 4D ?? 42 8B C1 81 FA 
            ?? ?? ?? ?? 72 ?? 8B 49 ?? 83 C2 ?? 2B C1 83 C0 ?? 83 F8 ?? 0F 87 ?? ?? ?? ?? 52 51 
            E8 ?? ?? ?? ?? 83 C4 ?? 8B 45 ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C6 45 ?? 
            ?? FF 70 ?? 8D 45 ?? 50 8B C8 E8 ?? ?? ?? ?? 6A ?? FF 75 ?? E8 ?? ?? ?? ?? 8B 95 ?? 
            ?? ?? ?? 83 C4 ?? 83 FA ?? 72 ?? 8B 8D ?? ?? ?? ?? 42 8B C1 81 FA ?? ?? ?? ?? 72 ?? 
            8B 49 ?? 83 C2 ?? 2B C1 83 C0 ?? 83 F8 ?? 77 ?? 52 51 E8 ?? ?? ?? ?? 83 C4 ?? 8B 8D 
            ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C6 85 ?? ?? 
            ?? ?? ?? 85 C9 0F 84 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 8B C1 2B D1 81 FA ?? ?? ?? ?? 0F 
            82 ?? ?? ?? ?? 8B 49 ?? 83 C2 ?? 2B C1 83 C0 ?? 83 F8 ?? 0F 86 ?? ?? ?? ?? E8 ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? E8
        }

        $find_files = {
            8B FF 55 8B EC 51 8B 4D ?? 8D 51 ?? 8A 01 41 84 C0 75 ?? 2B CA 83 C8 ?? 57 8B 7D ?? 
            41 2B C7 89 4D ?? 3B C8 76 ?? 6A ?? 58 EB ?? 53 56 8D 5F ?? 03 D9 6A ?? 53 E8 ?? ?? 
            ?? ?? 8B F0 59 59 85 FF 74 ?? 57 FF 75 ?? 53 56 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 75 ?? 
            FF 75 ?? 2B DF 8D 04 3E FF 75 ?? 53 50 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 75 ?? 8B 4D ?? 
            56 E8 ?? ?? ?? ?? 6A ?? 8B F0 E8 ?? ?? ?? ?? 59 8B C6 5E 5B 5F 8B E5 5D C3 33 C0 50 
            50 50 50 50 E8 ?? ?? ?? ?? CC 8B FF 55 8B EC 81 EC ?? ?? ?? ?? A1 ?? ?? ?? ?? 33 C5 
            89 45 ?? 8B 4D ?? 53 8B 5D ?? 56 8B 75 ?? 57 89 B5 ?? ?? ?? ?? EB ?? 8A 01 3C ?? 74 
            ?? 3C ?? 74 ?? 3C ?? 74 ?? 51 53 E8 ?? ?? ?? ?? 59 59 8B C8 3B CB 75 ?? 8A 11 80 FA 
            ?? 75 ?? 8D 43 ?? 3B C8 74 ?? 56 33 FF 57 57 53 E8 ?? ?? ?? ?? 83 C4 ?? EB ?? 33 FF 
            80 FA ?? 74 ?? 80 FA ?? 74 ?? 80 FA ?? 74 ?? 8B C7 EB ?? 33 C0 40 0F B6 C0 2B CB 41 
            F7 D8 68 ?? ?? ?? ?? 1B C0 23 C1 89 85 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 57 50 E8 ?? ?? 
            ?? ?? 83 C4 ?? 8D 85 ?? ?? ?? ?? 57 57 57 50 57 53 FF 15 ?? ?? ?? ?? 8B F0 8B 85 ?? 
            ?? ?? ?? 83 FE ?? 75 ?? 50 57 57 53 E8 ?? ?? ?? ?? 83 C4 ?? 8B F8 83 FE ?? 74 ?? 56 
            FF 15 ?? ?? ?? ?? 8B C7 8B 4D ?? 5F 5E 33 CD 5B E8 ?? ?? ?? ?? 8B E5 5D C3 8B 48 ?? 
            2B 08 C1 F9 ?? 89 8D ?? ?? ?? ?? 80 BD ?? ?? ?? ?? ?? 75 ?? 8A 8D ?? ?? ?? ?? 84 C9 
            74 ?? 80 F9 ?? 75 ?? 80 BD ?? ?? ?? ?? ?? 74 ?? 50 FF B5 ?? ?? ?? ?? 8D 85 ?? ?? ?? 
            ?? 53 50 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 75 ?? 8D 85 ?? ?? ?? ?? 50 56 FF 15 ?? ?? ?? 
            ?? 85 C0 8B 85 ?? ?? ?? ?? 75 ?? 8B 10 8B 40 ?? 8B 8D ?? ?? ?? ?? 2B C2 C1 F8 ?? 3B 
            C8 0F 84 ?? ?? ?? ?? 68 ?? ?? ?? ?? 2B C1 6A ?? 50 8D 04 8A 50 E8 ?? ?? ?? ?? 83 C4 
            ?? E9
        }

        $encrypt_files_p1 = {
            83 EC ?? 8B 44 24 ?? 53 55 56 8B F1 89 44 24 ?? 57 8B 7C 24 ?? 8B 6E ?? 3B FD 77 ?? 
            8B DE 83 FD ?? 72 ?? 8B 1E 57 50 53 89 7E ?? E8 ?? ?? ?? ?? 83 C4 ?? C6 04 1F ?? 8B 
            C6 5F 5E 5D 5B 83 C4 ?? C2 ?? ?? 81 FF ?? ?? ?? ?? 0F 87 ?? ?? ?? ?? 8B DF 83 CB ?? 
            81 FB ?? ?? ?? ?? 76 ?? BB ?? ?? ?? ?? EB ?? 8B CD B8 ?? ?? ?? ?? D1 E9 2B C1 3B E8 
            76 ?? BB ?? ?? ?? ?? EB ?? 8D 04 29 3B D8 0F 42 D8 33 C9 8B C3 83 C0 ?? 0F 92 C1 F7 
            D9 0B C8 51 8B CE E8 ?? ?? ?? ?? 57 FF 74 24 ?? 89 44 24 ?? 50 89 7E ?? 89 5E ?? E8 
            ?? ?? ?? ?? 8B 5C 24 ?? 83 C4 ?? C6 04 1F ?? 83 FD ?? 72 ?? 8B 06 45 81 FD ?? ?? ?? 
            ?? 72 ?? 8B 48 ?? 83 C5 ?? 2B C1 83 C0 ?? 83 F8 ?? 77 ?? 8B C1 55 50 E8 ?? ?? ?? ?? 
            83 C4 ?? 5F 89 1E 8B C6 5E 5D 5B 83 C4 ?? C2 ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? CC 
            CC CC CC CC 83 EC ?? 53 55 8B 6C 24 ?? 56 57 8B F9 8B 4C 24 ?? 89 4C 24 ?? 8B 5F ?? 
            3B EB 77 ?? 89 7C 24 ?? 8B C7 83 FB ?? 72 ?? 8B 07 89 44 24 ?? 8D 34 6D
        }

        $encrypt_files_p2 = {
            89 6F ?? 56 51 50 E8 ?? ?? ?? ?? 8B 44 24 ?? 83 C4 ?? 33 C9 66 89 0C 06 8B C7 5F 5E 
            5D 5B 83 C4 ?? C2 ?? ?? 81 FD ?? ?? ?? ?? 0F 87 ?? ?? ?? ?? 8B F5 83 CE ?? 81 FE ?? 
            ?? ?? ?? 76 ?? BE ?? ?? ?? ?? EB ?? 8B CB B8 ?? ?? ?? ?? D1 E9 2B C1 3B D8 76 ?? BE 
            ?? ?? ?? ?? EB ?? 8D 04 19 3B F0 0F 42 F0 33 C9 8B C6 83 C0 ?? 0F 92 C1 F7 D9 0B C8 
            51 8B CF E8 ?? ?? ?? ?? 89 77 ?? 8D 34 6D ?? ?? ?? ?? 56 FF 74 24 ?? 89 44 24 ?? 50 
            89 6F ?? E8 ?? ?? ?? ?? 8B 6C 24 ?? 33 C0 83 C4 ?? 66 89 04 2E 83 FB ?? 72 ?? 8B 07 
            8D 1C 5D ?? ?? ?? ?? 81 FB ?? ?? ?? ?? 72 ?? 8B 48 ?? 83 C3 ?? 2B C1 83 C0 ?? 83 F8 
            ?? 77 ?? 8B C1 53 50 E8 ?? ?? ?? ?? 83 C4 ?? 89 2F 8B C7 5F 5E 5D 5B 83 C4 ?? C2 ?? 
            ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? CC 8B 44 24 ?? 83 EC ?? 83 E0 ?? 89 41 ?? 8B 49 ?? 
            23 C8 75 ?? 83 C4 ?? C2 ?? ?? 56 F6 C1 ?? 74 ?? BE ?? ?? ?? ?? EB ?? F6 C1 ?? BE ?? 
            ?? ?? ?? B8 ?? ?? ?? ?? 0F 44 F0 8D 44 24 ?? 6A ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 4C 
            24 ?? 50 56 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 ?? 50 E8 ?? ?? ?? ?? 5E 
        }

        $encrypt_files_angus_version = {
            6A ?? 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? 
            ?? ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? E8 ?? ?? ?? 
            ?? 50 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 8B 85 
            ?? ?? ?? ?? 0F 43 8D ?? ?? ?? ?? 03 C1 83 BD ?? ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 0F 43 
            8D ?? ?? ?? ?? 50 51 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? C7 85 ?? ?? ?? ?? ?? 
            ?? ?? ?? B9 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 39 8D ?? ?? ?? ?? 8D 85 ?? ?? 
            ?? ?? C6 85 ?? ?? ?? ?? ?? 0F 42 8D ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 51 0F 43 85 ?? 
            ?? ?? ?? 8D 8D ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 
            C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 83 FA ?? 72 ?? 8B 8D ?? ?? ?? ?? 42 8B C1 81 FA ?? ?? 
            ?? ?? 72 ?? 8B 49 ?? 83 C2 ?? 2B C1 83 C0 ?? 83 F8 ?? 0F 87 ?? ?? ?? ?? 52 51 E8 ?? 
            ?? ?? ?? 83 C4 ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C6 85 
            ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? C7 85 ?? 
            ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? E8 ?? ?? ?? 
            ?? C6 45 ?? ?? 8D 8D ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 
            C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 
            C6 45 ?? ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? 
            ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 8D 8D 
            ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? C6 45 ?? ?? E8
        }
        
    condition:
        uint16(0) == 0x5A4D and
        (
            $find_files
        ) and
        (
            (
                all of ($encrypt_files_p*)
            ) or
            (
                $encrypt_files_angus_version
            )
        ) and
        (
            all of ($remote_connection_p*)
        )
}
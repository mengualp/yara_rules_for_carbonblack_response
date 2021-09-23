rule Win32_Ransomware_VHDLocker : tc_detection malicious
{
    meta:
 		score = 7

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "VHDLOCKER"
        description         = "Yara rule that detects VHDLocker ransomware."

        tc_detection_type   = "Ransomware"
        tc_detection_name   = "VHDLocker"
        tc_detection_factor = 5

    strings:

        $encrypt_files_p1 = {
            55 8B EC 6A ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 
            ?? ?? ?? ?? 33 C5 89 45 ?? 53 56 57 50 8D 45 ?? 64 A3 ?? ?? ?? ?? 8B 45 ?? 6A ?? 68 
            ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 68 ?? ?? ?? ?? 50 89 85 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 
            8B D8 89 9D ?? ?? ?? ?? 83 FB ?? 0F 84 ?? ?? ?? ?? 8B 45 ?? 8B 4D ?? 50 51 E8 ?? ?? 
            ?? ?? 83 C4 ?? 0B C2 74 ?? 53 FF 15 ?? ?? ?? ?? B0 ?? E9 ?? ?? ?? ?? 68 ?? ?? ?? ?? 
            33 DB 8D 95 ?? ?? ?? ?? 53 52 C6 85 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 68 ?? ?? 
            ?? ?? 8D 85 ?? ?? ?? ?? 53 50 88 9D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 89 9D ?? ?? 
            ?? ?? 89 9D ?? ?? ?? ?? 33 F6 8B FF 6A ?? 53 E8 ?? ?? ?? ?? 88 44 35 ?? 46 83 FE ?? 
            7C ?? 8D 4D ?? 51 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? BF ?? ?? ?? ?? B8 ?? ?? ?? ?? 8D 
            B5 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 89 9D ?? ?? ?? ?? 88 9D ?? ?? ?? ?? E8 
            ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 52 8B CE 89 5D ?? E8 ?? ?? ?? ?? 81 EC ?? ?? ?? ?? 8D 
            85 ?? ?? ?? ?? 8B F4 89 A5 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 ?? 6A ?? 50 8D 8D ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? 81 C4 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 72 ?? 8B 8D
        }

        $encrypt_files_p2 = {
            51 E8 ?? ?? ?? ?? 83 C4 ?? 8B BD ?? ?? ?? ?? 53 53 33 C9 51 33 C0 50 57 FF 15 ?? ?? 
            ?? ?? 85 C0 75 ?? 57 FF 15 ?? ?? ?? ?? 32 C0 E9 ?? ?? ?? ?? 53 8D 95 ?? ?? ?? ?? 52 
            68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 57 89 9D ?? ?? ?? ?? 89 9D ?? ?? ?? ?? 89 9D ?? 
            ?? ?? ?? 89 9D ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 83 F8 ?? 0F 85 ?? ?? ?? ?? 8B 35 ?? ?? 
            ?? ?? 8B 85 ?? ?? ?? ?? 3B C3 0F 84 ?? ?? ?? ?? 6A ?? F7 D8 99 53 52 50 57 FF 15 ?? 
            ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 51 8B 8D ?? ?? ?? ?? 8D 95 ?? ?? 
            ?? ?? 52 8D 95 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 8D 8D ?? ?? ?? ?? 51 50 8D 95 ?? ?? ?? 
            ?? 52 57 FF D6 85 C0 0F 84 ?? ?? ?? ?? 39 9D ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 81 BD ?? 
            ?? ?? ?? ?? ?? ?? ?? 0F 82 ?? ?? ?? ?? 39 9D ?? ?? ?? ?? 77 ?? 81 BD ?? ?? ?? ?? ?? 
            ?? ?? ?? 0F 82 ?? ?? ?? ?? 83 85 ?? ?? ?? ?? ?? 8B 15 ?? ?? ?? ?? 11 9D ?? ?? ?? ?? 
            83 FA ?? 0F 84 ?? ?? ?? ?? 53 53 33 C9 51 33 C0 50 52 FF 15 ?? ?? ?? ?? A1 ?? ?? ?? 
            ?? 50 FF 15 ?? ?? ?? ?? 8B 9D ?? ?? ?? ?? 8B C3 8D 50 ?? 66 8B 08 83 C0 ?? 66 85 C9
        }

        $encrypt_files_p3 = {
            75 ?? 2B C2 6A ?? D1 F8 8D 8D ?? ?? ?? ?? 51 8D 14 00 A1 ?? ?? ?? ?? 52 53 50 FF D6 
            8B 15 ?? ?? ?? ?? 6A ?? 8D 8D ?? ?? ?? ?? 51 6A ?? 68 ?? ?? ?? ?? 52 FF D6 8B 15 ?? 
            ?? ?? ?? 6A ?? 8D 85 ?? ?? ?? ?? 50 6A ?? 8D 4D ?? 51 52 FF D6 8B 0D ?? ?? ?? ?? 6A 
            ?? 8D 85 ?? ?? ?? ?? 50 6A ?? 68 ?? ?? ?? ?? 51 FF D6 8B 0D ?? ?? ?? ?? 6A ?? 8D 95 
            ?? ?? ?? ?? 52 6A ?? 8D 85 ?? ?? ?? ?? 50 51 FF D6 EB ?? 8B 9D ?? ?? ?? ?? 6A ?? 33 
            C9 51 51 B8 ?? ?? ?? ?? 50 57 FF 15 ?? ?? ?? ?? 85 C0 74 ?? 33 DB EB ?? 83 85 ?? ?? 
            ?? ?? ?? 11 9D ?? ?? ?? ?? 53 8D 95 ?? ?? ?? ?? 52 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 
            50 57 FF 15 ?? ?? ?? ?? 83 F8 ?? 0F 84 ?? ?? ?? ?? 8B 9D ?? ?? ?? ?? 8B 4D ?? 8B 55 
            ?? 8B B5 ?? ?? ?? ?? 51 52 8D BD ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 8D 85 
            ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 8D ?? 
            ?? ?? ?? 68 ?? ?? ?? ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 8B D6 52 FF 15 ?? ?? ?? ?? 33 C9 
            51 51 33 C0 51 50 A1 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 51 FF 15 ?? 
            ?? ?? ?? 8D 95 ?? ?? ?? ?? 52 53 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 94 C0 8B 4D ?? 64 
            89 0D ?? ?? ?? ?? 59 5F 5E 5B 8B 4D ?? 33 CD E8 ?? ?? ?? ?? 8B E5 5D C3 
        }

        $find_files_p1 = {
            55 8B EC 81 EC ?? ?? ?? ?? A1 ?? ?? ?? ?? 33 C5 89 45 ?? 53 56 68 ?? ?? ?? ?? 33 F6 
            8D 8D ?? ?? ?? ?? 33 C0 56 51 66 89 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 57 8D 95 
            ?? ?? ?? ?? 68 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? 
            ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 8D ?? ?? ?? ?? 51 8D 95 ?? ?? ?? ?? 
            52 FF 15 ?? ?? ?? ?? 8B D8 89 9D ?? ?? ?? ?? 83 FB ?? 0F 84 ?? ?? ?? ?? EB ?? 8D 9B 
            ?? ?? ?? ?? 8A 85 ?? ?? ?? ?? A8 ?? 0F 85 ?? ?? ?? ?? A8 ?? 0F 84 ?? ?? ?? ?? 57 8D 
            85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 8D ?? ?? ?? ?? 51 8D 95 
            ?? ?? ?? ?? 68 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? 
            ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 68 ?? ?? ?? 
            ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 75 ?? 8D 95 ?? ?? ?? ?? 52 FF 15 ?? ?? ?? ?? E9 
            ?? ?? ?? ?? B9 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 66 8B 10 66 3B 11 75 ?? 66 3B D6 74 ?? 
            66 8B 50 ?? 66 3B 51 ?? 75 ?? 83 C0 ?? 83 C1 ?? 66 3B D6 75 ?? 33 C0 EB ?? 1B C0 83
        }

        $find_files_p2 = {
            D8 ?? 3B C6 0F 84 ?? ?? ?? ?? B9 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 66 8B 10 66 3B 11 75 
            ?? 66 3B D6 74 ?? 66 8B 50 ?? 66 3B 51 ?? 75 ?? 83 C0 ?? 83 C1 ?? 66 3B D6 75 ?? 33 
            C0 EB ?? 1B C0 83 D8 ?? 3B C6 0F 84 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 BB ?? ?? ?? ?? 
            E8 ?? ?? ?? ?? 8B 9D ?? ?? ?? ?? E9 ?? ?? ?? ?? B9 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 90 
            66 8B 10 66 3B 11 75 ?? 66 3B D6 74 ?? 66 8B 50 ?? 66 3B 51 ?? 75 ?? 83 C0 ?? 83 C1 
            ?? 66 3B D6 75 ?? 33 C0 EB ?? 1B C0 83 D8 ?? 3B C6 0F 84 ?? ?? ?? ?? B9 ?? ?? ?? ?? 
            8D 85 ?? ?? ?? ?? 8B FF 66 8B 10 66 3B 11 75 ?? 66 3B D6 74 ?? 66 8B 50 ?? 66 3B 51 
            ?? 75 ?? 83 C0 ?? 83 C1 ?? 66 3B D6 75 ?? 33 C0 EB ?? 1B C0 83 D8 ?? 3B C6 0F 84 ?? 
            ?? ?? ?? 57 8D 8D ?? ?? ?? ?? 68 ?? ?? ?? ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 8D 95 ?? ?? 
            ?? ?? 52 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? 8B 85 
            ?? ?? ?? ?? 8B D1 83 C4 ?? 0B D0 89 B5 ?? ?? ?? ?? 89 B5 ?? ?? ?? ?? 74 ?? 50 51 8D 
            85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 83 C4 ?? 3A C1 75 ?? 01 0D ?? ?? ?? 
            ?? 11 35 ?? ?? ?? ?? EB ?? 01 0D ?? ?? ?? ?? 11 35 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 51 
            53 FF 15 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 53 FF 15 ?? ?? ?? ?? 8B 4D ?? 5E 33 CD 
            B0 ?? 5B E8 ?? ?? ?? ?? 8B E5 5D C3 
        }

        $get_logical_drives_list_p1 = {
            8D 85 ?? ?? ?? ?? 50 57 89 BD ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 
            68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 68 ?? ?? ?? ?? 51 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 
            95 ?? ?? ?? ?? 68 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 57 68 ?? ?? ?? ?? 6A ?? 57 
            57 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 8B D8 83 FB ?? 0F 84 ?? ?? 
            ?? ?? 83 EC ?? 8B F4 89 7E ?? C7 46 ?? ?? ?? ?? ?? BF ?? ?? ?? ?? B8 ?? ?? ?? ?? 89 
            A5 ?? ?? ?? ?? C6 06 ?? E8 ?? ?? ?? ?? 8D B5 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 33 
            FF 89 7D ?? 83 78 ?? ?? 72 ?? 8B 00 8D 50 ?? 8D A4 24 ?? ?? ?? ?? 8A 08 40 84 C9 75 
            ?? 57 8D 8D ?? ?? ?? ?? 2B C2 51 50 83 EC ?? 8B F4 89 7E ?? C7 46 ?? ?? ?? ?? ?? BF 
            ?? ?? ?? ?? B8 ?? ?? ?? ?? 89 A5 ?? ?? ?? ?? C6 06 ?? E8 ?? ?? ?? ?? 8D B5 ?? ?? ?? 
            ?? E8 ?? ?? ?? ?? BE ?? ?? ?? ?? 83 C4 ?? 39 70 ?? 72 ?? 8B 00 50 53 FF 15 ?? ?? ?? 
            ?? 39 B5 ?? ?? ?? ?? 72 ?? 8B 95 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? C7 45 ?? ?? 
            ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C6 85 ?? ?? ?? 
            ?? ?? 39 B5 ?? ?? ?? ?? 72 ?? 8B 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 53 FF 15 
            ?? ?? ?? ?? B9 ?? ?? ?? ?? B8 ?? ?? ?? ?? 8D 64 24 ?? 66 8B 10 66 3B 11 75 ?? 66 85 
            D2 74 ?? 66 8B 50 ?? 66 3B 51 ?? 75 ?? 83 C0 ?? 83 C1 ?? 66 85 D2 75 ?? 33 C0 EB
        }

        $get_logical_drives_list_p2 = {
            1B C0 83 D8 ?? 85 C0 0F 85 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? BE ?? ?? ?? ?? 89 85 ?? ?? 
            ?? ?? 89 B5 ?? ?? ?? ?? BA ?? ?? ?? ?? 8B CE D3 E2 85 95 ?? ?? ?? ?? 0F 84 ?? ?? ?? 
            ?? 8D 4E ?? 66 89 8D ?? ?? ?? ?? 33 C9 6A ?? 51 8D 95 ?? ?? ?? ?? 52 C7 85 ?? ?? ?? 
            ?? ?? ?? ?? ?? 66 89 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 8D 85 ?? ?? ?? ?? 50 FF 
            15 ?? ?? ?? ?? 83 F8 ?? 0F 84 ?? ?? ?? ?? 83 F8 ?? 0F 84 ?? ?? ?? ?? 83 F8 ?? 0F 84 
            ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 51 BB ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 95 
            ?? ?? ?? ?? 6A ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 6A ?? 68 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 
            68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 8B D8 83 FB ?? 0F 84 ?? ?? ?? 
            ?? 83 EC ?? B8 ?? ?? ?? ?? 8B CC 89 A5 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D B5 ?? ?? ?? ?? 
            E8 ?? ?? ?? ?? 83 C4 ?? BF ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 39 78 ?? 72 ?? 8B 00 8D 
            50 ?? 8A 08 40 84 C9 75 ?? 6A ?? 8D 8D ?? ?? ?? ?? 51 2B C2 50 83 EC ?? B8 ?? ?? ?? 
            ?? 8B CC 89 A5 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D B5 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 
            39 78 ?? 72 ?? 8B 00 50 53 FF 15 ?? ?? ?? ?? 39 BD ?? ?? ?? ?? 72 ?? 8B 95 ?? ?? ?? 
            ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? BE ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 89 B5 ?? ?? ?? ?? 
            C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? 39 BD ?? ?? ?? ?? 72 ?? 8B 85 ?? 
            ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 53 89 B5 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? 
            ?? C6 85 ?? ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B B5 ?? ?? ?? ?? 46 89 B5 ?? ?? ?? ?? 83 
            FE ?? 0F 8C ?? ?? ?? ?? EB ?? 68 ?? ?? ?? ?? BB ?? ?? ?? ?? E8 ?? ?? ?? ?? B0 ?? 8B 
            4D ?? 64 89 0D ?? ?? ?? ?? 59 5F 5E 5B 8B 4D ?? 33 CD E8 ?? ?? ?? ?? 8B E5 5D C3 
        }
        
    condition:
        uint16(0) == 0x5A4D and
        (
            all of ($get_logical_drives_list_p*)
        ) and
        (
            all of ($find_files_p*)
        ) and 
        (
            all of ($encrypt_files_p*)
        )
}
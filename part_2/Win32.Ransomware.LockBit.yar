rule Win32_Ransomware_LockBit : tc_detection malicious
{
    meta:
 		score = 7

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "LOCKBIT"
        description         = "Yara rule that detects LockBit ransomware."

        tc_detection_type   = "Ransomware"
        tc_detection_name   = "LockBit"
        tc_detection_factor = 5

    strings:

        $enum_resources = {
            55 8B EC 83 EC ?? 57 8D 45 ?? C7 45 ?? ?? ?? ?? ?? 50 51 6A ?? 6A ?? 6A ?? C7 45 ?? 
            ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? FF 75 ?? 6A ?? FF 15 ?? ?? ?? 
            ?? 8B F8 89 7D ?? 85 FF 0F 84 ?? ?? ?? ?? 53 56 FF 75 ?? 6A ?? 57 E8 ?? ?? ?? ?? 83 
            C4 ?? 8D 45 ?? 50 57 8D 45 ?? 50 FF 75 ?? FF 15 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 
            33 DB 39 5D ?? 76 ?? 8B F7 0F 1F 80 ?? ?? ?? ?? F7 46 ?? ?? ?? ?? ?? 74 ?? 8B CE E8 
            ?? ?? ?? ?? 83 7F ?? ?? 74 ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B F8 83 C4 ?? 8B 45 
            ?? FF 70 ?? FF 15 ?? ?? ?? ?? 8D 04 45 ?? ?? ?? ?? 50 8B 45 ?? FF 70 ?? 57 E8 ?? ?? 
            ?? ?? 83 C4 ?? 8D 45 ?? 50 6A ?? 57 68 ?? ?? ?? ?? 6A ?? 6A ?? FF 15 ?? ?? ?? ?? 8B 
            0D ?? ?? ?? ?? 89 04 8D ?? ?? ?? ?? F0 FF 05 ?? ?? ?? ?? 8B 7D ?? 43 83 C6 ?? 3B 5D 
            ?? 72 ?? E9 ?? ?? ?? ?? 57 FF 15 ?? ?? ?? ?? FF 75 ?? FF 15 ?? ?? ?? ?? 5E 5B 85 C0 
            75 ?? B8 ?? ?? ?? ?? 5F 8B E5 5D C3 33 C0 5F 8B E5 5D C3 
        }

        $find_files_1 = {
            55 8B EC 81 EC ?? ?? ?? ?? 53 56 8B C1 C7 45 ?? ?? ?? ?? ?? 57 50 89 45 ?? 33 C9 8D 
            45 ?? C7 45 ?? ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 66 89 4D ?? 50 FF 15 ?? ?? ?? ?? 83 
            C4 ?? 8D 85 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 50 6A ?? 8D 85 ?? ?? ?? ?? 50 FF 15 ?? ?? 
            ?? ?? 8B F8 89 7D ?? 83 FF ?? 0F 84 ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? 33 C0 8B 35 ?? ?? 
            ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 66 89 45 ?? C7 45 ?? ?? ?? ?? ?? C7 
            45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 0F 1F 80 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 8D 
            45 ?? 50 FF D3 85 C0 0F 84 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 8D 45 ?? 50 FF D3 85 C0 
            0F 84 ?? ?? ?? ?? F6 85 ?? ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 68 ?? ?? 
            ?? ?? 50 FF D3 85 C0 0F 84 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 FF D3 85 
            C0 0F 84
        }

        $find_files_2 = {
            45 ?? 50 8D 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 83 C4 ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? 
            ?? ?? E9 ?? ?? ?? ?? 33 C9 66 39 8D ?? ?? ?? ?? 74 ?? 8D 40 ?? 41 66 83 38 ?? 75 ?? 
            83 F9 ?? 0F 8E ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 8B F0 56 68 ?? ?? 
            ?? ?? FF D3 85 C0 0F 84 ?? ?? ?? ?? 56 68 ?? ?? ?? ?? FF D3 85 C0 0F 84 ?? ?? ?? ?? 
            56 68 ?? ?? ?? ?? FF D3 85 C0 0F 84 ?? ?? ?? ?? 56 68 ?? ?? ?? ?? FF D3 85 C0 0F 84
        }
            
        $find_files_3 = {
            85 C0 0F 84 ?? ?? ?? ?? 56 68 ?? ?? ?? ?? FF D3 85 C0 0F 84 ?? ?? ?? ?? 56 68 ?? ?? 
            ?? ?? FF D3 85 C0 0F 84 ?? ?? ?? ?? 56 68 ?? ?? ?? ?? FF D3 85 C0 0F 84 ?? ?? ?? ?? 
            56 68 ?? ?? ?? ?? FF D3 85 C0 0F 84 ?? ?? ?? ?? 56 68 ?? ?? ?? ?? FF D3 85 C0 0F 84 
            ?? ?? ?? ?? 0F 28 05 ?? ?? ?? ?? 33 C9 0F 11 45 ?? C7 45 ?? ?? ?? ?? ?? 66 C7 45 ?? 
            ?? ?? 66 90 8A 45 ?? 30 44 0D ?? 41 83 F9 ?? 72 ?? 33 C0 C6 45 ?? ?? 66 89 45 ?? 8D 
            45 ?? 50 8D 45 ?? C7 45 ?? ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 83 
            C4 ?? 8D 85 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 50 FF D3 85 C0 0F 84 ?? ?? ?? ?? 8D 85 
            ?? ?? ?? ?? 50 68 ?? ?? ?? ?? FF D3 85 C0 0F 84 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 68 
            ?? ?? ?? ?? FF D3 85 C0 0F 84 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? FF D3 
            85 C0 0F 84 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? FF D3 85 C0 0F 84 ?? ?? 
            ?? ?? 8B 4D ?? 8D 95 ?? ?? ?? ?? 2B D1 0F B7 01 8D 49 ?? 66 89 44 11 ?? 66 85 C0 75 
            ?? 8D 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 8B F2 66 8B 02 83 C2 ?? 
            66 85 C0 75 ?? 8D BD ?? ?? ?? ?? 2B D6 83 C7 ?? 0F 1F 40 ?? 66 8B 47 ?? 83 C7 ?? 66 
            85 C0 75 ?? 8B 85 ?? ?? ?? ?? 8B CA C1 E9 ?? F3 A5 8B CA 83 E1 ?? F3 A4 A8 ?? 75 ?? 
            A8 ?? 74 ?? 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 85 C0 74 ?? 8D 8D 
            ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 7D ?? 8B 35 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 57 FF D6 
            83 F8 ?? 0F 84 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 83 F8 ?? 75 ?? 57 FF 15 ?? ?? ?? ?? 5F 
            5E 5B 8B E5 5D C3 
        }

        $encrypt_files_1 = {
            55 8B EC 81 EC ?? ?? ?? ?? 33 C0 C7 45 ?? ?? ?? ?? ?? 53 56 57 8B F9 C7 45 ?? ?? ?? 
            ?? ?? 89 7D ?? 66 89 45 ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 66 89 45 ?? C7 
            45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 66 
            89 45 ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85
        }

        $encrypt_files_2 = { 
            C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 89 85 ?? ?? ?? ?? C7 85
            ?? ?? ?? ?? ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B F8 33 DB 89 7D ?? 33 F6 0F 1F 00 8B 84
            B5 ?? ?? ?? ?? 85 C0 74 ?? 57 50 FF 15 ?? ?? ?? ?? 85 C0 B8 ?? ?? ?? ?? 0F 44 D8 46
            81 FE ?? ?? ?? ?? 7C ?? 8B 7D ?? 33 C0 66 89 85 ?? ?? ?? ?? 66 89 85 ?? ?? ?? ?? 8D
            85 ?? ?? ?? ?? 57 50 8D 85 ?? ?? ?? ?? 89 5D ?? 50 C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7
            85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ??
            ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ??
            ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? FF 15 ?? ?? ??
            ?? 8B 1D ?? ?? ?? ?? 83 C4 ?? 33 F6 8D 85 ?? ?? ?? ?? 50 FF 75 ?? FF 15 ?? ?? ?? ??
            85 C0 74 ?? 8D 85 ?? ?? ?? ?? 50 57 FF 15 ?? ?? ?? ?? 85 C0 75 ?? FF D3 83 F8 ?? 75
            ?? 8B CF E8 ?? ?? ?? ?? 83 F8 ?? 74 ?? 8B
        }
            
        $encrypt_files_3 = {
            CF E8 ?? ?? ?? ?? 83 F8 ?? 75 ?? 83 FE ?? 7D ?? 46 EB ?? 6A ?? 68 ?? ?? ?? ?? 6A ?? 
            6A ?? 6A ?? 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 8B D8 89 5D ?? 83 
            FB ?? 75 ?? 8B 1D ?? ?? ?? ?? EB ?? FF 35 ?? ?? ?? ?? 6A ?? FF 35 ?? ?? ?? ?? 53 FF 
            15 ?? ?? ?? ?? A3 ?? ?? ?? ?? 83 F8 ?? 75 ?? 53 FF 15 ?? ?? ?? ?? 33 C0 5F 5E 5B 8B 
            E5 5D C3 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B D8 83 C4 ?? 85 DB 75 ?? FF 75 ?? FF 15 
            ?? ?? ?? ?? 33 C0 5F 5E 5B 8B E5 5D C3 8B 45 ?? 8B 75 ?? 89 43 ?? 8D 43 ?? 50 56 C7 
            43 ?? ?? ?? ?? ?? C7 43 ?? ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0 75 ?? 53 FF 15 ?? ?? 
            ?? ?? 83 C4 ?? 56 FF 15 ?? ?? ?? ?? 33 C0 5F 5E 5B 8B E5 5D C3 8B 4B ?? 8B 43 ?? 85 
            C9 7F ?? 7C ?? 83 F8 ?? 72 ?? 83 E8 ?? C7 43 ?? ?? ?? ?? ?? 89 43 ?? 8B 43 ?? 83 D9 
            ?? 89 43 ?? 8B 43 ?? 89 43 ?? 8D 83 ?? ?? ?? ?? 6A ?? 50 89 4B ?? C7 43 ?? ?? ?? ?? 
            ?? 89 73 ?? E8 ?? ?? ?? ?? 6A ?? 8D 83 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 53 6A ?? 6A ?? 
            8D 73 ?? 56 FF 73 ?? FF 15 ?? ?? ?? ?? 89 45 ?? 85 C0 75 ?? FF 15 ?? ?? ?? ?? 3D ?? 
            ?? ?? ?? 74 ?? 56 8B 35 ?? ?? ?? ?? FF D6 83 C4 ?? 53 FF D6 83 C4 ?? FF 75 ?? FF 15 
            ?? ?? ?? ?? 8B 45 ?? 5F 5E 5B 8B E5 5D C3 F0 FF 05 ?? ?? ?? ?? 8B CF E8 ?? ?? ?? ?? 
            B8 ?? ?? ?? ?? F0 0F C1 05 ?? ?? ?? ?? 40 3D ?? ?? ?? ?? 7E ?? 8B 35 ?? ?? ?? ?? 6A 
            ?? FF D6 83 3D ?? ?? ?? ?? ?? 7D ?? 5F 5E B8 ?? ?? ?? ?? 5B 8B E5 5D C3
        }

    condition:
        uint16(0) == 0x5A4D and
        (
            $enum_resources
        ) and
        (
            all of ($find_files_*)
        ) and
        (
            all of ($encrypt_files_*)
        )
}
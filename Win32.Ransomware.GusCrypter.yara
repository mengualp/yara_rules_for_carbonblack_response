rule Win32_Ransomware_GusCrypter : tc_detection malicious
{
    meta:
 		score = 7

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "GUSCRYPTER"
        description         = "Yara rule that detects GusCrypter ransomware."

        tc_detection_type   = "Ransomware"
        tc_detection_name   = "GusCrypter"
        tc_detection_factor = 5

    strings:

        $find_files_p1 = {
            8A 01 41 84 C0 75 ?? 2B CA 8D 85 ?? ?? ?? ?? 51 50 8D 4D ?? E8 ?? ?? ?? ?? C6 45 ?? 
            ?? 8D 45 ?? 8B 5D ?? 83 FB ?? 8B 75 ?? 8B 4D ?? 0F 43 C6 83 F9 ?? 75 ?? 80 38 ?? 0F 
            84 ?? ?? ?? ?? 83 FB ?? 8D 45 ?? 0F 43 C6 83 F9 ?? 75 ?? BA ?? ?? ?? ?? 66 39 10 0F 
            84 ?? ?? ?? ?? 83 FB ?? 8D 55 ?? 0F 43 D6 83 F9 ?? 75 ?? 66 81 3A ?? ?? 75 ?? 80 7A 
            ?? ?? 0F 84 ?? ?? ?? ?? 83 FB ?? 8D 45 ?? 0F 43 C6 83 F9 ?? 75 ?? 81 38 ?? ?? ?? ?? 
            0F 84 ?? ?? ?? ?? 83 FB ?? 8D 55 ?? 0F 43 D6 83 F9 ?? 75 ?? 81 3A ?? ?? ?? ?? 75 ?? 
            66 81 7A ?? ?? ?? 75 ?? 80 7A ?? ?? 0F 84 ?? ?? ?? ?? 8B 45 ?? 8D 4D ?? 83 FB ?? 0F 
            43 CE 83 F8 ?? 75 ?? BA ?? ?? ?? ?? 8D 78 ?? 8B 01 3B 02 75 ?? 83 C1 ?? 83 C2 ?? 83 
            EF ?? 73 ?? 8A 01 3A 02 0F 84 ?? ?? ?? ?? 8B 45 ?? 83 FB ?? 8D 4D ?? 0F 43 CE 83 F8 
            ?? 75 ?? BA ?? ?? ?? ?? 8D 78 ?? 8B 01 3B 02 75 ?? 83 C1 ?? 83 C2 ?? 83 EF ?? 73 ?? 
            66 8B 01 66 3B 02 75 ?? 8A 41 ?? 3A 42 ?? 0F 84 ?? ?? ?? ?? 8B 45 ?? 83 FB ?? 8D 4D 
            ?? 0F 43 CE 83 F8 ?? 75 ?? BA ?? ?? ?? ?? 8D 78 ?? 8B 01 3B 02 75 ?? 83 C1 ?? 83 C2 
            ?? 83 EF ?? 73 ?? 66 8B 01 66 3B 02 75 ?? 8A 41 ?? 3A 42 ?? 0F 84 ?? ?? ?? ?? 8B 4D 
            ?? 8D 45 ?? 83 FB ?? 0F 43 C6 83 F9 ?? 75 ?? 81 38 ?? ?? ?? ?? 75 ?? 81 78 ?? ?? ?? 
            ?? ?? 75 ?? 80 78 ?? ?? 0F 84 ?? ?? ?? ?? 83 FB ?? 8D 45 ?? 0F 43 C6 83 F9 ?? 75
        }

        $find_files_p2 = {
            81 38 ?? ?? ?? ?? 75 ?? 80 78 ?? ?? 0F 84 ?? ?? ?? ?? 83 FB ?? 8D 45 ?? 0F 43 C6 83 
            F9 ?? 75 ?? 81 38 ?? ?? ?? ?? 75 ?? 81 78 ?? ?? ?? ?? ?? 75 ?? 81 78 ?? ?? ?? ?? ?? 
            0F 84 ?? ?? ?? ?? 83 FB ?? 8D 45 ?? 0F 43 C6 83 F9 ?? 75 ?? 81 38 ?? ?? ?? ?? 75 ?? 
            81 78 ?? ?? ?? ?? ?? 75 ?? 81 78 ?? ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 83 FB ?? 8D 4D ?? 
            0F 43 CE 83 7D ?? ?? 75 ?? BA ?? ?? ?? ?? BF ?? ?? ?? ?? 8B 01 3B 02 75 ?? 83 C1 ?? 
            83 C2 ?? 83 EF ?? 73 ?? 66 8B 01 66 3B 02 75 ?? 8A 41 ?? 3A 42 ?? 0F 84 ?? ?? ?? ?? 
            83 FB ?? 8D 45 ?? 0F 43 C6 83 7D ?? ?? 75 ?? 81 38 ?? ?? ?? ?? 75 ?? 81 78 ?? ?? ?? 
            ?? ?? 75 ?? 81 78 ?? ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 83 FB ?? 8D 4D ?? 0F 43 CE 83 7D 
            ?? ?? 75 ?? BA ?? ?? ?? ?? BF ?? ?? ?? ?? 8B 01 3B 02 75 ?? 83 C1 ?? 83 C2 ?? 83 EF 
            ?? 73 ?? 66 8B 01 66 3B 02 75 ?? 8A 41 ?? 3A 42 ?? 75 ?? B0 ?? EB ?? 32 C0 84 C0 75 
            ?? 8D 85 ?? ?? ?? ?? 50 8D 55 ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC ?? C6 45 ?? 
            ?? 8B CC 8B D0 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? E8 ?? ?? ?? ?? C6 45 ?? ?? 83 
            C4 ?? 8B 95 ?? ?? ?? ?? 83 FA ?? 72 ?? 8B 8D ?? ?? ?? ?? 42 8B C1 81 FA ?? ?? ?? ?? 
            72 ?? 8B 49 ?? 83 C2 ?? 2B C1 83 C0 ?? 83 F8 ?? 0F 87 ?? ?? ?? ?? 52 51 E8 ?? ?? ?? 
            ?? 83 C4 ?? 8B BD ?? ?? ?? ?? C6 45 ?? ?? 83 FB ?? 72 ?? 43 8B C6 81 FB ?? ?? ?? ?? 
            72 ?? 8B 76 ?? 83 C3 ?? 2B C6 83 C0 ?? 83 F8 ?? 0F 87 ?? ?? ?? ?? 53 56 E8 ?? ?? ?? 
            ?? 83 C4 ?? 8D 85 ?? ?? ?? ?? 50 57 FF 15 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 57 FF 
            15 
        }

        $encrypt_files_p1 = {
            88 84 05 ?? ?? ?? ?? 40 3D ?? ?? ?? ?? 7C ?? 33 FF 33 F6 8B C6 8A 9C 35 ?? ?? ?? ?? 
            99 F7 7D ?? 0F B6 04 0A 03 F8 0F B6 CB 03 F9 81 E7 ?? ?? ?? ?? 79 ?? 4F 81 CF ?? ?? 
            ?? ?? 47 8A 84 3D ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? 88 84 35 ?? ?? ?? ?? 46 88 9C 3D ?? 
            ?? ?? ?? 81 FE ?? ?? ?? ?? 7C ?? 83 7D ?? ?? 8D 45 ?? 68 ?? ?? ?? ?? 0F 43 45 ?? 50 
            E8 ?? ?? ?? ?? 8B D8 83 C4 ?? 85 DB 0F 85 ?? ?? ?? ?? 8B 4D ?? 32 D2 E8 ?? ?? ?? ?? 
            8B 55 ?? 83 FA ?? 72 ?? 8B 4D ?? 42 8B C1 81 FA ?? ?? ?? ?? 72 ?? 8B 49 ?? 83 C2 ?? 
            2B C1 83 C0 ?? 83 F8 ?? 0F 87 ?? ?? ?? ?? 52 51 E8 ?? ?? ?? ?? 83 C4 ?? 8B 55 ?? C7 
            45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C6 45 ?? ?? 83 FA ?? 0F 82 ?? ?? ?? ?? 8B 4D 
            ?? 42 8B C1 81 FA ?? ?? ?? ?? 0F 82 ?? ?? ?? ?? 8B 49 ?? 83 C2 ?? 2B C1 83 C0 ?? 83 
            F8 ?? 0F 87 ?? ?? ?? ?? E9 ?? ?? ?? ?? 83 7D ?? ?? 8D 45 ?? 68 ?? ?? ?? ?? 0F 43 45 
            ?? 50 E8 ?? ?? ?? ?? 8B F8 83 C4 ?? 89 BD ?? ?? ?? ?? 85 FF 0F 84 ?? ?? ?? ?? 33 F6 
            53 E8 ?? ?? ?? ?? 83 C4 ?? 88 85 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 75
        }

        $encrypt_files_p2 = { 
            0F BE 85 ?? ?? ?? ?? 57 50 E8 ?? ?? ?? ?? 46 83 C4 ?? 83 FE ?? 7C ?? 53 E8 ?? ?? ?? 
            ?? 83 C4 ?? 88 85 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 85 ?? ?? ?? ?? 83 
            7D ?? ?? 8D 4D ?? 8A 85 ?? ?? ?? ?? 0F 43 4D ?? C7 45 ?? ?? ?? ?? ?? 88 01 C6 41 ?? 
            ?? 33 C9 8B 75 ?? 8B C6 83 C0 ?? 0F 92 C1 F7 D9 0B C8 51 E8 ?? ?? ?? ?? 83 C4 ?? 8D 
            4D ?? 83 7D ?? ?? 8B F8 0F 43 4D ?? 56 57 51 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F BE 
            07 FF B5 ?? ?? ?? ?? 35 ?? ?? ?? ?? 83 C0 ?? 50 E8 ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? 8B 
            BD ?? ?? ?? ?? 83 C4 ?? E9 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 ?? 57 E8 ?? ?? ?? ?? 
            83 C4 ?? BA ?? ?? ?? ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 
            45 ?? 83 7D ?? ?? 0F 43 45 ?? 50 E8 ?? ?? ?? ?? 8B 4D ?? 83 C4 ?? 32 D2 C7 45 ?? ?? 
            ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 ?? 83 F8 ?? 0F 82 ?? ?? ?? ?? 8B 4D ?? 8D 50 ?? 8B C1 
            81 FA ?? ?? ?? ?? 72 ?? 8B 49 ?? 83 C2 ?? 2B C1 83 C0 ?? 83 F8 ?? 77 ?? 52 51 E8 ?? 
            ?? ?? ?? 83 C4 ?? E9 ?? ?? ?? ?? 52 51 E8 ?? ?? ?? ?? 83 C4 ?? 8B 4D ?? 64 89 0D ?? 
            ?? ?? ?? 59 5F 5E 5B 8B 4D ?? 33 CD E8 ?? ?? ?? ?? 8B E5 5D C3 
        }

        $misc_checks_p1 = {
            68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? 83 F8 ?? 74 ?? 50 E8 
            ?? ?? ?? ?? 83 C4 ?? BA ?? ?? ?? ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 
            83 C4 ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? 83 F8 ?? 74 
            ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? BA ?? ?? ?? ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 E8 ?? 
            ?? ?? ?? 83 C4 ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? 83 
            F8 ?? 74 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? BA ?? ?? ?? ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 
            50 E8 ?? ?? ?? ?? 83 C4 ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 ?? ?? 
            ?? ?? 83 F8 ?? 74 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? BA ?? ?? ?? ?? B9 ?? ?? ?? ?? E8 ?? 
            ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 
            84 ?? ?? ?? ?? 83 F8 ?? 74 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? BA ?? ?? ?? ?? B9 ?? ?? ?? 
            ?? E8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4
        }

        $misc_checks_p2 = { 
            85 C0 0F 84 ?? ?? ?? ?? 83 F8 ?? 74 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? BA ?? ?? ?? ?? B9 
            ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 
            83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? 83 F8 ?? 74 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? BA ?? ?? 
            ?? ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 68 ?? ?? ?? ?? E8 ?? 
            ?? ?? ?? 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? 83 F8 ?? 74 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 
            BA ?? ?? ?? ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 68 ?? ?? ?? 
            ?? E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? 83 F8 ?? 74 ?? 50 E8 ?? ?? ?? ?? 
            83 C4 ?? BA ?? ?? ?? ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 68 
            ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 74 ?? 83 F8 ?? 74 ?? 50 E8 ?? ?? ?? ?? 83 
            C4 ?? BA ?? ?? ?? ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 68 ?? 
            ?? ?? ?? FF 15 ?? ?? ?? ?? E9 
        }

    condition:
        uint16(0) == 0x5A4D and 
        (
            all of ($misc_checks_p*)
        ) and 
        (
            all of ($find_files_p*)
        ) and 
        (
            all of ($encrypt_files_p*)
        )
}
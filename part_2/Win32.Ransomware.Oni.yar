rule Win32_Ransomware_ONI : tc_detection malicious
{
    meta:
 		score = 7

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "ONI"
        description         = "Yara rule that detects Oni ransomware."

        tc_detection_type   = "Ransomware"
        tc_detection_name   = "ONI"
        tc_detection_factor = 5

    strings:

        $find_files = {
            8A 10 3A 11 75 ?? 84 D2 74 ?? 8A 50 ?? 3A 51 ?? 75 ?? 83 C0 ?? 83 C1 ?? 84 D2 75 ?? 
            33 C0 EB ?? 1B C0 83 C8 ?? 85 C0 0F 84 ?? ?? ?? ?? B9 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 
            8A 10 3A 11 75 ?? 84 D2 74 ?? 8A 50 ?? 3A 51 ?? 75 ?? 83 C0 ?? 83 C1 ?? 84 D2 75 ?? 
            33 C0 EB ?? 1B C0 83 C8 ?? 85 C0 0F 84 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 68 ?? ?? ?? 
            ?? 53 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? F6 85 ?? ?? ?? ?? 
            ?? 0F 84 ?? ?? ?? ?? 83 EC ?? 8B D4 C7 42 ?? ?? ?? ?? ?? C7 42 ?? ?? ?? ?? ?? C6 02 
            ?? 80 BD ?? ?? ?? ?? ?? 75 ?? 33 C9 EB ?? 8D 8D ?? ?? ?? ?? 8D 71 ?? 90 8A 01 41 84 
            C0 75 ?? 2B CE 51 8D 85 ?? ?? ?? ?? 8B CA 50 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 
            84 C0 74 ?? 83 EC ?? 8D 45 ?? 8B CC 6A ?? 6A ?? C7 41 ?? ?? ?? ?? ?? C7 41 ?? ?? ?? 
            ?? ?? 50 C6 01 ?? E8 ?? ?? ?? ?? 83 EC ?? 8D 45 ?? 8B CC 6A ?? 6A ?? C7 41 ?? ?? ?? 
            ?? ?? C7 41 ?? ?? ?? ?? ?? 50 C6 01 ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? 
            ?? 83 C4 ?? 8D 85 ?? ?? ?? ?? 50 57 FF 15 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 57 FF 
            15 ?? ?? ?? ?? 8B 45 ?? 83 F8 ?? 72 ?? 8B 4D ?? 40 3D ?? ?? ?? ?? 72 ?? F6 C1 ?? 75 
            ?? 8B 41 ?? 3B C1 73 ?? 2B C8 83 F9 ?? 72 ?? 83 F9 ?? 77 ?? 8B C8 51 E8 ?? ?? ?? ?? 
            83 C4 ?? 8B 45 ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C6 45 ?? ?? 83 F8 ?? 72 
            ?? 8B 4D ?? 40 3D ?? ?? ?? ?? 72 ?? F6 C1 ?? 75 ?? 8B 41 ?? 3B C1 73 ?? 2B C8 83 F9 
            ?? 72 ?? 83 F9 ?? 77 ?? 8B C8 51 E8 ?? ?? ?? ?? 83 C4 ?? 8B 4D ?? 5F 5E 33 CD 5B E8 
            ?? ?? ?? ?? 8B E5 5D C3 
        }

        $encrypt_files = {
            55 8B EC 83 EC ?? A1 ?? ?? ?? ?? 33 C5 89 45 ?? 56 57 8B 3D ?? ?? ?? ?? 8D 45 ?? 68 
            ?? ?? ?? ?? 6A ?? 33 F6 89 55 ?? 56 56 50 89 4D ?? 89 75 ?? FF D7 85 C0 75 ?? 68 ?? 
            ?? ?? ?? 6A ?? 50 50 8D 45 ?? 50 FF D7 8B 7D ?? 85 FF 0F 84 ?? ?? ?? ?? 53 8D 45 ?? 
            89 75 ?? 50 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B D0 E8 ?? ?? ?? ?? 8B D8 83 C4 ?? 85 
            DB 74 ?? 8D 45 ?? 50 6A ?? 6A ?? FF 75 ?? 53 57 FF 15 ?? ?? ?? ?? 53 6A ?? FF 15 ?? 
            ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 8B 5D ?? 85 DB 74 ?? 68 ?? ?? ?? ?? 6A ?? FF 15 ?? ?? 
            ?? ?? 50 FF 15 ?? ?? ?? ?? FF 75 ?? 8B F0 56 FF 15 ?? ?? ?? ?? FF 75 ?? FF 15 ?? ?? 
            ?? ?? 68 ?? ?? ?? ?? 89 45 ?? 8D 45 ?? 50 56 6A ?? 6A ?? 6A ?? 53 FF 15 ?? ?? ?? ?? 
            8B 4D ?? 85 C9 74 ?? 8B 45 ?? 89 01 53 FF 15 ?? ?? ?? ?? 6A ?? 57 FF 15 ?? ?? ?? ?? 
            5B 8B 4D ?? 8B C6 5F 33 CD 5E E8 ?? ?? ?? ?? 8B E5 5D C3 
        }

        $search_processes = {
            6A ?? 68 ?? ?? ?? ?? 8D 8C 24 ?? ?? ?? ?? C7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? C7 84 24 
            ?? ?? ?? ?? ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C 24 ?? ?? ?? ?? 
            E8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 8D 8C 24 ?? ?? ?? ?? C7 84 24 ?? ?? ?? ?? ?? ?? 
            ?? ?? C7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 B9 
            ?? ?? ?? ?? E8 ?? ?? ?? ?? C6 44 24 ?? ?? 8D 84 24 ?? ?? ?? ?? FF 74 24 ?? C7 05 ?? 
            ?? ?? ?? ?? ?? ?? ?? 50 8D 44 24 ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 50 C7 05 ?? ?? ?? 
            ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? BF ?? ?? ?? ?? 8D B4 24 ?? ?? ?? ?? 83 EE ?? 4F 83 7E 
            ?? ?? 72 ?? 8B 1E 8B CE 56 E8 ?? ?? ?? ?? 8B 46 ?? 40 3D ?? ?? ?? ?? 72 ?? F6 C3 ?? 
            75 ?? 8B 43 ?? 3B C3 73 ?? 2B D8 83 FB ?? 72 ?? 83 FB ?? 77 ?? 8B D8 53 E8 ?? ?? ?? 
            ?? 83 C4 ?? C7 46 ?? ?? ?? ?? ?? 83 7E ?? ?? C7 46 ?? ?? ?? ?? ?? 72 ?? 8B 06 EB ?? 
            8B C6 8B CE C6 00 ?? E8 ?? ?? ?? ?? 85 FF 75 ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 
            ?? 5F 5E 5B 8B E5 5D C3 E8 ?? ?? ?? ?? CC CC CC CC CC B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 
            6A ?? 68 ?? ?? ?? ?? B9 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 
            ?? ?? ?? ?? C6 05 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 C3 
        }

    condition:
        uint16(0) == 0x5A4D and 
        (
            $search_processes 
        ) and 
        (
            $find_files
        ) and 
        (
            $encrypt_files
        )
}
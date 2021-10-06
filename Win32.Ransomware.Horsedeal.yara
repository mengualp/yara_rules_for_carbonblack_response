rule Win32_Ransomware_Horsedeal : tc_detection malicious
{
    meta:
 		score = 7

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "HORSEDEAL"
        description         = "Yara rule that detects Horsedeal ransomware."

        tc_detection_type   = "Ransomware"
        tc_detection_name   = "Horsedeal"
        tc_detection_factor = 5

    strings:

        $search_processes = {
            55 8B EC 81 EC ?? ?? ?? ?? 56 6A ?? 6A ?? FF 15 ?? ?? ?? ?? 8B F0 83 FE ?? 74 ?? 8D 
            85 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 50 56 FF 15 ?? ?? ?? ?? 85 C0 74 ?? 53 
            FF 35 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 85 C0 75 ?? FF B5 ?? ?? ?? 
            ?? 50 6A ?? FF 15 ?? ?? ?? ?? 8B D8 83 FB ?? 74 ?? 6A ?? 53 FF 15 ?? ?? ?? ?? 53 FF 
            15 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 56 FF 15 ?? ?? ?? ?? 85 C0 75 ?? 5B 56 FF 15 ?? 
            ?? ?? ?? 5E C9 C3
        }

        $enum_resources = {
            55 8B EC 83 E4 ?? 83 EC ?? 83 0C 24 ?? 8D 44 24 ?? 53 56 57 50 FF 75 ?? C7 44 24 ?? 
            ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? FF 15 ?? ?? ?? ?? 85 C0 75 ?? 8B 4C 24 ?? E8 ?? ?? ?? 
            ?? 8B F0 85 F6 74 ?? EB ?? 33 DB 39 5C 24 ?? 76 ?? 8D 7E ?? F6 47 ?? ?? 74 ?? 8D 47 
            ?? 50 E8 ?? ?? ?? ?? EB ?? FF 37 E8 ?? ?? ?? ?? 43 83 C7 ?? 59 3B 5C 24 ?? 72 ?? 8D 
            44 24 ?? 50 56 8D 44 24 ?? 50 FF 74 24 ?? FF 15 ?? ?? ?? ?? 85 C0 74 ?? 8B CE E8 ?? 
            ?? ?? ?? FF 74 24 ?? FF 15 ?? ?? ?? ?? 5F 5E 5B 8B E5 5D C3
        }

        $find_files = {
            55 8B EC 83 E4 ?? 81 EC ?? ?? ?? ?? 80 3D ?? ?? ?? ?? ?? 53 56 8B 35 ?? ?? ?? ?? 57 
            8B 7D ?? 74 ?? 68 ?? ?? ?? ?? 57 FF D6 85 C0 0F 84 ?? ?? ?? ?? B9 ?? ?? ?? ?? E8 ?? 
            ?? ?? ?? 8B D8 85 DB 0F 84 ?? ?? ?? ?? 57 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 FF 15 ?? 
            ?? ?? ?? 83 C4 ?? 8D 44 24 ?? 50 53 FF 15 ?? ?? ?? ?? 89 44 24 ?? 83 F8 ?? 0F 84 ?? 
            ?? ?? ?? FF 35 ?? ?? ?? ?? 8D 44 24 ?? 50 FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 
            8D 44 24 ?? 50 57 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 FF 15 ?? ?? ?? ?? 8B 44 24 ?? 83 
            C4 ?? A8 ?? 74 ?? 68 ?? ?? ?? ?? 8D 44 24 ?? 50 FF D6 85 C0 74 ?? 68 ?? ?? ?? ?? 8D 
            44 24 ?? 50 FF D6 85 C0 74 ?? 53 E8 ?? ?? ?? ?? 59 EB ?? 8B 44 24 ?? A8 ?? 74 ?? 68 
            ?? ?? ?? ?? 8D 44 24 ?? 50 FF 15 ?? ?? ?? ?? 85 C0 75 ?? 68 ?? ?? ?? ?? 8D 44 24 ?? 
            50 FF D6 85 C0 74 ?? 68 ?? ?? ?? ?? 8D 44 24 ?? 50 FF D6 85 C0 74 ?? 8B CB E8 ?? ?? 
            ?? ?? 8D 44 24 ?? 50 FF 74 24 ?? FF 15 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? FF 74 24 
            ?? FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 57 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 FF 15 ?? ?? 
            ?? ?? 83 C4 ?? 33 FF 57 68 ?? ?? ?? ?? 6A ?? 57 6A ?? 68 ?? ?? ?? ?? 53 FF 15 ?? ?? 
            ?? ?? 8B F0 89 74 24 ?? 83 FE ?? 74 ?? 57 8B 3D ?? ?? ?? ?? 8D 44 24 ?? 50 68 ?? ?? 
            ?? ?? FF D7 50 68 ?? ?? ?? ?? 56 8B 35 ?? ?? ?? ?? FF D6 6A ?? 8D 44 24 ?? 50 FF 35 
            ?? ?? ?? ?? FF D7 8B 7C 24 ?? 50 FF 35 ?? ?? ?? ?? 57 FF D6 57 FF 15 ?? ?? ?? ?? 8B 
            CB E8 ?? ?? ?? ?? 5F 5E 5B 8B E5 5D C3
        }

        $encrypt_files_p1 = {
            55 8B EC B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 56 8B 35 ?? ?? ?? ?? 57 FF 35 ?? ?? ?? ?? 
            8B F9 89 7D ?? FF D6 FF 35 ?? ?? ?? ?? 8B D8 57 FF 15 ?? ?? ?? ?? 85 C0 74 ?? 50 FF 
            D6 3B C3 0F 84 ?? ?? ?? ?? 6A ?? 59 33 DB 89 4D ?? 8B C3 88 9C 05 ?? ?? ?? ?? 40 3D 
            ?? ?? ?? ?? 72 ?? 8D 85 ?? ?? ?? ?? 50 51 FF 35 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0 
            0F 84 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8B CB 89 45 ?? 8A 84 0D ?? ?? ?? ?? 88 44 0D ?? 
            41 83 F9 ?? 72 ?? 68 ?? ?? ?? ?? 8D 45 ?? 50 8D 85 ?? ?? ?? ?? 50 53 6A ?? 53 FF 35 
            ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 53 68 ?? ?? ?? ?? 6A ?? 58 50 53 6A ?? 68 ?? ?? ?? ?? 
            57 89 45 ?? FF 15 ?? ?? ?? ?? 8B D8 83 FB ?? 0F 84 ?? ?? ?? ?? 83 65 ?? ?? 57 FF D6 
            8D 0C 47 83 E9 ?? 66 83 39 ?? 75 ?? FF 35 ?? ?? ?? ?? 2B CF 83 C1 ?? D1 F9 8D 04 4F 
            50 FF 15 ?? ?? ?? ?? 89 45 ?? 85 C0 74 ?? FF 35 ?? ?? ?? ?? FF D6 FF 75 ?? 8B F0 FF 
            15 ?? ?? ?? ?? 3B C6 75 ?? 33 F6 46 EB ?? 8B 75 ?? 8D 45 ?? 50 53 FF 15 ?? ?? ?? ?? 
            8B 4D ?? 8B 45 ?? 85 C9 7F ?? 7C ?? 3D ?? ?? ?? ?? 77 ?? 33 F6 46 85 F6 74 ?? 8B 35 
            ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? 6A ?? 8D 45 ?? 50 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50
        }

        $encrypt_files_p2 = {
            53 FF 15 ?? ?? ?? ?? 6A ?? FF 75 ?? 8D 55 ?? 6A ?? FF 75 ?? 8D 8D ?? ?? ?? ?? E8 ?? 
            ?? ?? ?? 8B 45 ?? 83 C4 ?? F7 D8 99 6A ?? 6A ?? 52 50 53 FF D7 6A ?? 8D 45 ?? 50 FF 
            75 ?? 8D 85 ?? ?? ?? ?? 50 53 FF D6 81 7D ?? ?? ?? ?? ?? 74 ?? E9 ?? ?? ?? ?? 6A ?? 
            6A ?? 51 0F 57 C0 50 66 0F 13 45 ?? E8 ?? ?? ?? ?? 8B 4D ?? 2D ?? ?? ?? ?? 8B 35 ?? 
            ?? ?? ?? 8B 3D ?? ?? ?? ?? 83 DA ?? 89 45 ?? 8B 45 ?? 2D ?? ?? ?? ?? 89 55 ?? 89 45 
            ?? 8D 45 ?? 83 D9 ?? 89 45 ?? 89 4D ?? 6A ?? 6A ?? FF 70 ?? FF 30 53 FF D7 6A ?? 8D 
            45 ?? 50 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 53 FF 15 ?? ?? ?? ?? 6A ?? FF 75 ?? 8D 
            55 ?? 6A ?? FF 75 ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 ?? 83 C4 ?? F7 D8 99 6A 
            ?? 6A ?? 52 50 53 FF D7 6A ?? 8D 45 ?? 50 FF 75 ?? 8D 85 ?? ?? ?? ?? 50 53 FF D6 8B 
            45 ?? 83 C0 ?? 83 6D ?? ?? 89 45 ?? 75 ?? 8B 7D ?? 0F 57 C0 6A ?? 6A ?? 66 0F 13 45 
            ?? FF 75 ?? C7 45 ?? ?? ?? ?? ?? FF 75 ?? 53 FF 15 ?? ?? ?? ?? 6A ?? 8D 45 ?? 50 6A 
            ?? 8D 45 ?? 50 53 FF D6 6A ?? 8D 45 ?? 50 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 53 FF 
            D6 53 FF 15 ?? ?? ?? ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F0 85 F6 74 ?? 68 ?? ?? ?? 
            ?? 57 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 56 FF 15 ?? ?? ?? ?? 83 C4 ?? 56 57 FF 15 ?? ?? 
            ?? ?? 8B CE E8 ?? ?? ?? ?? 5F 5E 5B C9 C3
        }

    condition:
        uint16(0) == 0x5A4D and
        (
            $enum_resources
        ) and
        (
            $search_processes
        ) and
        (
            $find_files
        ) and
        (
            all of ($encrypt_files_p*)
        )
}
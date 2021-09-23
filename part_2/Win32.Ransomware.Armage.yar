rule Win32_Ransomware_Armage : tc_detection malicious
{
    meta:
 		score = 7

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "ARMAGE"
        description         = "Yara rule that detects Armage ransomware."

        tc_detection_type   = "Ransomware"
        tc_detection_name   = "Armage"
        tc_detection_factor = 5

    strings:

        $encrypt_files_p1 = {
            55 89 E5 53 8D 5D ?? 81 EC ?? ?? ?? ?? 89 4D ?? C7 45 ?? ?? ?? ?? ?? 89 5D ?? 8D 5D 
            ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 89 65 ?? 89 1C 24 E8 ?? ?? ?? ?? 8B 45 
            ?? 8D 50 ?? 8D 48 ?? C7 00 ?? ?? ?? ?? C7 40 ?? ?? ?? ?? ?? C6 40 ?? ?? 89 50 ?? 89 
            95 ?? ?? ?? ?? 8D 50 ?? 89 50 ?? 89 95 ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 04 24 
            ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 4D ?? 8D 5D ?? 83 EC ?? 89 5D ?? 
            8B 41 ?? 8B 51 ?? 8D 4D ?? 01 C2 89 04 24 89 54 24 ?? C7 45 ?? ?? ?? ?? ?? E8 ?? ?? 
            ?? ?? 8D 45 ?? 8D 5D ?? 83 EC ?? 89 5C 24 ?? 89 04 24 C7 45 ?? ?? ?? ?? ?? E8 ?? ?? 
            ?? ?? 8B 45 ?? 8D 5D ?? 39 D8 74 ?? 89 04 24 E8 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? E8 
            ?? ?? ?? ?? 8B 55 ?? 8B 4D ?? 89 42 ?? 8B 55 ?? 89 4C 24 ?? 89 04 24 29 CA 89 54 24 
            ?? E8 ?? ?? ?? ?? 8B 55 ?? 89 42 ?? 8B 42 ?? 89 04 24 E8 ?? ?? ?? ?? 8B 55 ?? 89 42 
            ?? 89 04 24 E8 ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 8B 55 ?? 
            8B 42 ?? 89 04 24 E8 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 8B 8D ?? 
            ?? ?? ?? 89 4C 24 ?? 89 85 ?? ?? ?? ?? 89 44 24 ?? 8B 55 ?? 8B 42 ?? 89 04 24 E8 ?? 
            ?? ?? ?? 8B 8D ?? ?? ?? ?? 89 4C 24 ?? 89 8D ?? ?? ?? ?? 89 4C 24 ?? 8B 85 ?? ?? ?? 
            ?? 89 44 24 ?? 8B 55 ?? 8B 42 ?? 89 04 24 E8 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 89 44 24 
            ?? 8B 85 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 8B 9D ?? ?? ?? ?? 89 5C 24 ?? 8B 8D ?? 
            ?? ?? ?? 89 4C 24 ?? 89 85 ?? ?? ?? ?? 89 44 24 ?? 8B 55 ?? 8B 42 ?? 89 04 24 E8 ?? 
            ?? ?? ?? 89 44 24 ?? 8B 85 ?? ?? ?? ?? 89 44 24 ?? 8D 45 ?? 89 04 24 E8
        } 

        $encrypt_files_p2 = {
            8B 55 ?? 8D 45 ?? 89 04 24 C7 45 ?? ?? ?? ?? ?? 8D 4A ?? E8 ?? ?? ?? ?? 8B 45 ?? 8D 
            55 ?? 83 EC ?? 39 D0 74 ?? 89 04 24 E8 ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 
            ?? ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? 
            ?? 8B 40 ?? 8B 80 ?? ?? ?? ?? 85 C0 89 85 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 8B 85 ?? ?? 
            ?? ?? 80 78 ?? ?? 74 ?? 0F BE 40 ?? 89 04 24 B9 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? E8 
            ?? ?? ?? ?? 83 EC ?? 89 C1 E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 
            8B 45 ?? 85 C0 74 ?? 89 04 24 E8 ?? ?? ?? ?? 8D 45 ?? 89 04 24 E8 ?? ?? ?? ?? 8B 5D 
            ?? C9 C3 90 8B 8D ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 
            8B 00 8B 50 ?? B8 ?? ?? ?? ?? 81 FA ?? ?? ?? ?? 74 ?? C7 04 24 ?? ?? ?? ?? 8B 8D ?? 
            ?? ?? ?? FF D2 83 EC ?? 0F BE C0 E9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C5 ?? 8B 45 ?? 89 
            85 ?? ?? ?? ?? 8B 45 ?? 85 C0 74 ?? 83 E8 ?? 74 ?? 83 E8 ?? 74 ?? 83 E8 ?? 74 ?? 83 
            E8 ?? 74 ?? 0F 0B 8B 45 ?? 8D 55 ?? 39 D0 74 ?? 89 04 24 E8 ?? ?? ?? ?? 8B 45 ?? 85 
            C0 74 ?? 89 04 24 E8 ?? ?? ?? ?? 8B 45 ?? 8B 40 ?? 3B 85 ?? ?? ?? ?? 74 ?? 89 04 24 
            E8 ?? ?? ?? ?? 8B 45 ?? 8B 40 ?? 39 85 ?? ?? ?? ?? 74 ?? 89 04 24 E8 ?? ?? ?? ?? 8B 
            85 ?? ?? ?? ?? 89 04 24 C7 45 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 ?? 8D 55 ?? 39 D0 
            75 ?? EB
        }

        $find_files_p1 = {
            55 89 E5 81 EC ?? ?? ?? ?? 8D 55 ?? 89 4D ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? 
            ?? C7 45 ?? ?? ?? ?? ?? 89 55 ?? 8D 55 ?? 89 65 ?? 89 14 24 E8 ?? ?? ?? ?? 8B 45 ?? 
            8B 4D ?? 83 C0 ?? 8B 51 ?? 89 45 ?? 8D 45 ?? 89 45 ?? 8B 45 ?? 89 55 ?? 8B 00 89 C1 
            89 45 ?? 01 D1 74 ?? 85 C0 75 ?? C7 04 24 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? E8 ?? ?? 
            ?? ?? 8B 45 ?? 83 F8 ?? 89 45 ?? 0F 87 ?? ?? ?? ?? 83 7D ?? ?? 0F 85 ?? ?? ?? ?? 8B 
            45 ?? 8D 55 ?? 0F B6 00 88 45 ?? B8 ?? ?? ?? ?? 89 45 ?? C6 04 02 ?? B8 ?? ?? ?? ?? 
            2B 45 ?? 83 F8 ?? 0F 86 ?? ?? ?? ?? 8D 4D ?? C7 44 24 ?? ?? ?? ?? ?? C7 04 24 ?? ?? 
            ?? ?? C7 45 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 ?? 83 EC ?? 89 44 24 ?? 8B 45 ?? 89 
            04 24 C7 45 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 4D ?? 8B 55 ?? 83 EC ?? 89 81 ?? ?? ?? 
            ?? 8D 4D ?? 39 CA 74 ?? 89 14 24 E8 ?? ?? ?? ?? 8B 45 ?? 8B 80 ?? ?? ?? ?? 83 F8
        }

        $find_files_p2 = {
            8B 45 ?? 0F 95 00 8D 45 ?? 89 04 24 E8 ?? ?? ?? ?? C9 C2 ?? ?? 8D 76 ?? 8D 45 ?? 8B 
            4D ?? 89 4C 24 ?? 8B 4D ?? 89 04 24 89 4C 24 ?? E8 ?? ?? ?? ?? 8B 45 ?? 8B 55 ?? E9 
            ?? ?? ?? ?? 8D 45 ?? 8D 4D ?? C7 44 24 ?? ?? ?? ?? ?? 89 04 24 C7 45 ?? ?? ?? ?? ?? 
            E8 ?? ?? ?? ?? 8B 55 ?? 83 EC ?? 89 45 ?? 89 55 ?? EB ?? C7 04 24 ?? ?? ?? ?? C7 45 
            ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C5 ?? 8B 45 ?? 89 45 ?? 8B 45 ?? 85 C0 74 ?? 83 E8 
            ?? 74 ?? 0F 0B 8B 45 ?? 8D 55 ?? 39 D0 74 ?? 89 04 24 E8 ?? ?? ?? ?? 8B 45 ?? 89 04 
            24 C7 45 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 90 66 90 55 89 E5 57 56 8D 45 ?? 53 83 EC ?? 
            89 45 ?? 8D 45 ?? 89 4D ?? C7 45 ?? ?? ?? ?? ?? 89 45 ?? C7 45 ?? ?? ?? ?? ?? C7 45 
            ?? ?? ?? ?? ?? 89 65 ?? 89 04 24 E8 ?? ?? ?? ?? 8B 5D ?? C6 45 ?? ?? 8B 83 ?? ?? ?? 
            ?? 83 F8 ?? 74 ?? 8D 53 ?? 89 04 24 89 54 24 ?? C7 45 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 
            83 EC ?? 85 C0 0F 95 45 ?? 0F B6 45 ?? 8B 75 ?? 88 06 8B 45 ?? 89 04 24 E8 ?? ?? ?? 
            ?? 0F B6 45 ?? 8D 65 ?? 5B 5E 5F 5D C3
        }

        $enum_resources_p1 = {
            55 B8 ?? ?? ?? ?? 89 E5 E8 ?? ?? ?? ?? 29 C4 8D 45 ?? 89 8D ?? ?? ?? ?? 89 A5 ?? ?? 
            ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? C7 85 ?? ?? 
            ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 8D 85 ?? ?? 
            ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? 8B 45 
            ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? 89 44 24 ?? 
            C7 85 ?? ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC ?? 85 C0 74 ?? C7 85 ?? ?? ?? ?? 
            ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? C9 C2 ?? ?? 
            8D 85 ?? ?? ?? ?? 89 44 24 ?? 8D 85 ?? ?? ?? ?? 89 44 24 ?? 8D 85 ?? ?? ?? ?? 89 44 
            24 ?? 8B 85 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 83 EC ?? 85 C0 75 ?? 8D 85 ?? ?? ?? 
            ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 85 C0 75 ?? EB 
            ?? 8D B4 26 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? F6 40 ?? ?? 0F 85 ?? ?? ?? ?? 83 85 ?? ?? 
            ?? ?? ?? 83 85 ?? ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 3B 85 ?? ?? ?? ?? 0F 83
        }

        $enum_resources_p2 = { 
            8B 85 ?? ?? ?? ?? F6 40 ?? ?? 74 ?? 8B 40 ?? 89 C2 89 85 ?? ?? ?? ?? 8D 85 ?? ?? ?? 
            ?? 85 D2 89 85 ?? ?? ?? ?? B8 ?? ?? ?? ?? 74 ?? 89 14 24 E8 ?? ?? ?? ?? 03 85 ?? ?? 
            ?? ?? 89 44 24 ?? 8B 85 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 89 04 24 C7 85 ?? ?? ?? ?? ?? 
            ?? ?? ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 83 EC ?? 8B 48 ?? 3B 48 ?? 0F 84 ?? ?? ?? 
            ?? 85 C9 74 ?? 8D 41 ?? 8B 95 ?? ?? ?? ?? 89 01 8B 85 ?? ?? ?? ?? 01 C2 89 04 24 89 
            54 24 ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 83 EC ?? 8B 
            48 ?? 8B 85 ?? ?? ?? ?? 83 C1 ?? 89 48 ?? 8B 85 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 39 C8 
            0F 84 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? F6 40 ?? ?? 0F 84 ?? ?? 
            ?? ?? 89 04 24 8B 8D ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC 
            ?? E9 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 89 0C 24 89 44 24 ?? 8B 8D ?? ?? ?? ?? C7 85 ?? 
            ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC ?? EB
        }

    condition:
        uint16(0) == 0x5A4D and 
        (
            all of ($enum_resources_p*) 
        ) and 
        (
            all of ($find_files_p*)
        ) and 
        (
            all of ($encrypt_files_p*)
        )
}
rule Win64_Ransomware_Vovalex : tc_detection malicious
{
    meta:
 		score = 7

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "VOVALEX"
        description         = "Yara rule that detects Vovalex ransomware."

        tc_detection_type   = "Ransomware"
        tc_detection_name   = "Vovalex"
        tc_detection_factor = 5

    strings:

        $encrypt_files = {
            48 8D 95 ?? ?? ?? ?? 48 8B 85 ?? ?? ?? ?? 48 89 85 ?? ?? ?? ?? 48 8B BD ?? ?? ?? ?? 
            48 89 BD ?? ?? ?? ?? 48 8D 8D ?? ?? ?? ?? 48 83 EC ?? E8 ?? ?? ?? ?? 48 83 C4 ?? 48 
            89 85 ?? ?? ?? ?? 48 89 95 ?? ?? ?? ?? 48 83 BD ?? ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 48 
            8B 9D ?? ?? ?? ?? 48 8B 53 ?? 48 8B 03 48 89 85 ?? ?? ?? ?? 48 89 95 ?? ?? ?? ?? 48 
            8D 8D ?? ?? ?? ?? 48 83 EC ?? E8 ?? ?? ?? ?? 48 83 C4 ?? 83 F8 ?? 75 ?? 48 8B B5 ?? 
            ?? ?? ?? 48 8B 56 ?? 48 8B 06 48 89 85 ?? ?? ?? ?? 48 89 95 ?? ?? ?? ?? 48 8D 95 ?? 
            ?? ?? ?? 8B 8D ?? ?? ?? ?? 48 83 EC ?? E8 ?? ?? ?? ?? 48 83 C4 ?? 48 8B 9D ?? ?? ?? 
            ?? 48 8B 53 ?? 48 8B 03 48 89 85 ?? ?? ?? ?? 48 89 95 ?? ?? ?? ?? 48 8D 8D ?? ?? ?? 
            ?? 48 83 EC ?? E8 ?? ?? ?? ?? 48 83 C4 ?? 48 3D ?? ?? ?? ?? 0F 87 ?? ?? ?? ?? 48 83 
            EC ?? 48 8B 85 ?? ?? ?? ?? 48 89 85 ?? ?? ?? ?? 48 8B 9D ?? ?? ?? ?? 48 89 9D ?? ?? 
            ?? ?? 48 8D B5 ?? ?? ?? ?? 56 48 89 85 ?? ?? ?? ?? 48 89 9D ?? ?? ?? ?? 48 8D 15 ?? 
            ?? ?? ?? 48 89 95 ?? ?? ?? ?? 48 C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ?? 
            48 89 8D ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 89 85 ?? ?? ?? ?? 48 8D 9D ?? ?? ?? ?? 
            48 89 9D ?? ?? ?? ?? 48 C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 48 8D 95 ?? ?? ?? ?? 48 8D 0D 
            ?? ?? ?? ?? 48 83 EC ?? E8 ?? ?? ?? ?? 48 83 C4 ?? 48 89 85 ?? ?? ?? ?? 48 89 95 ?? 
            ?? ?? ?? 4C 8D 8D ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 89 85 ?? ?? ?? ?? 48 8B 1D ?? 
            ?? ?? ?? 48 89 9D ?? ?? ?? ?? 4C 8D 85 ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ?? 48 89 8D ?? 
            ?? ?? ?? 48 8B 15 ?? ?? ?? ?? 48 89 95 ?? ?? ?? ?? 48 8D 95 ?? ?? ?? ?? B9 ?? ?? ?? 
            ?? 48 83 EC ?? E8 ?? ?? ?? ?? 48 83 C4
        }

        $find_files_p1 = {
            48 89 C6 48 8D 0D ?? ?? ?? ?? 48 83 EC ?? E8 ?? ?? ?? ?? 48 83 C4 ?? 48 89 C1 48 83 
            EC ?? E8 ?? ?? ?? ?? 48 83 C4 ?? 48 89 06 48 89 56 ?? 48 8D 0D ?? ?? ?? ?? 48 83 EC 
            ?? E8 ?? ?? ?? ?? 48 83 C4 ?? 48 89 C1 48 83 EC ?? E8 ?? ?? ?? ?? 48 83 C4 ?? 48 89 
            46 ?? 48 89 56 ?? 48 8D 0D ?? ?? ?? ?? 48 83 EC ?? E8 ?? ?? ?? ?? 48 83 C4 ?? 48 89 
            C1 48 83 EC ?? E8 ?? ?? ?? ?? 48 83 C4 ?? 48 89 46 ?? 48 89 56 ?? 48 8D 0D ?? ?? ?? 
            ?? 48 83 EC ?? E8 ?? ?? ?? ?? 48 83 C4 ?? 48 89 C1 48 83 EC ?? E8 ?? ?? ?? ?? 48 83 
            C4 ?? 48 89 46 ?? 48 89 56 ?? 48 8D 0D ?? ?? ?? ?? 48 83 EC ?? E8 ?? ?? ?? ?? 48 83 
            C4 ?? 48 89 C1 48 83 EC ?? E8 ?? ?? ?? ?? 48 83 C4 ?? 48 89 46 ?? 48 89 56 ?? 48 8D 
            0D ?? ?? ?? ?? 48 83 EC ?? E8 ?? ?? ?? ?? 48 83 C4 ?? 48 89 C1 48 83 EC ?? E8 ?? ?? 
            ?? ?? 48 83 C4 ?? 48 89 46 ?? 48 89 56 ?? 48 89 B5 ?? ?? ?? ?? 48 C7 85 ?? ?? ?? ?? 
            ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? B8 ?? ?? ?? ?? 48 89 85 ?? ?? ?? ?? 48 89 95 ?? ?? 
            ?? ?? BA ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? 48 83 EC ?? E8 ?? ?? ?? ?? 48 83 C4 ?? 48
        }

        $find_files_p2 = {
            89 C3 48 8B 95 ?? ?? ?? ?? 48 8B 85 ?? ?? ?? ?? 48 89 03 48 89 53 ?? 48 8D 15 ?? ?? 
            ?? ?? BF ?? ?? ?? ?? 48 89 7B ?? 48 89 53 ?? 48 8D 0D ?? ?? ?? ?? B8 ?? ?? ?? ?? 48 
            89 43 ?? 48 89 4B ?? 48 89 9D ?? ?? ?? ?? 48 C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 45 31 C0 
            4C 89 85 ?? ?? ?? ?? 4C 8D A5 ?? ?? ?? ?? 49 C7 04 24 ?? ?? ?? ?? 49 8B 14 24 48 89 
            95 ?? ?? ?? ?? 4C 89 85 ?? ?? ?? ?? 4C 8D AD ?? ?? ?? ?? 49 B9 ?? ?? ?? ?? ?? ?? ?? 
            ?? 4D 89 4D ?? 49 8B 4D ?? 48 89 8D ?? ?? ?? ?? 4C 89 85 ?? ?? ?? ?? 4C 8D B5 ?? ?? 
            ?? ?? 4D 89 06 49 8B 16 48 8D 8D ?? ?? ?? ?? 48 83 EC ?? E8 ?? ?? ?? ?? 48 83 C4 ?? 
            45 31 C0 41 3B C0 7E ?? 41 BF ?? ?? ?? ?? 4C 89 85 ?? ?? ?? ?? 4C 8D 8D ?? ?? ?? ?? 
            4D 69 D7 ?? ?? ?? ?? 4D 89 11 4C 89 D2 48 8D 8D ?? ?? ?? ?? 48 83 EC ?? E8 ?? ?? ?? 
            ?? 48 83 C4 ?? 45 31 C0 41 3B C0 79 ?? 4C 89 85 ?? ?? ?? ?? 48 8D 8D ?? ?? ?? ?? 48 
            C7 01 ?? ?? ?? ?? 48 8B 01 48 89 85 ?? ?? ?? ?? 48 8B 95 ?? ?? ?? ?? 48 8D 8D ?? ?? 
            ?? ?? 48 83 EC ?? E8 ?? ?? ?? ?? 48 83 C4 ?? 85 C0 7E ?? 48 8B 9D ?? ?? ?? ?? 48 B8 
            ?? ?? ?? ?? ?? ?? ?? ?? 48 F7 EB 
        }

    condition:
        uint16(0) == 0x5A4D and
        (
            all of ($find_files_p*)
        ) and
        (
            $encrypt_files
        )
}
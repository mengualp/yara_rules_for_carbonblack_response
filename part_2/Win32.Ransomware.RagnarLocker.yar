rule Win32_Ransomware_RagnarLocker : tc_detection malicious
{
    meta:
 		score = 7

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "RAGNARLOCKER"
        description         = "Yara rule that detects RagnarLocker ransomware."

        tc_detection_type   = "Ransomware"
        tc_detection_name   = "RagnarLocker"
        tc_detection_factor = 5

    strings:

        $find_files_p1 = {
            55 8B EC 81 EC ?? ?? ?? ?? 33 C0 B9 ?? ?? ?? ?? 53 8B 1D ?? ?? ?? ?? 56 8B 75 ?? 57 
            8D BD ?? ?? ?? ?? F3 AB 8B 3D ?? ?? ?? ?? 39 45 ?? 0F 84 ?? ?? ?? ?? 8D 45 ?? 50 8D 
            85 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 56 FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? FF 75 
            ?? 8D 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 75 ?? FF 15 ?? ?? ?? ?? 
            8D 85 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 50 FF D3 
        }

        $find_files_p2 = {
            68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 FF D7 85 C0 0F 84 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 
            85 ?? ?? ?? ?? 50 FF D7 85 C0 0F 84 ?? ?? ?? ?? F6 85 ?? ?? ?? ?? ?? 0F 84 ?? ?? ?? 
            ?? 83 FB ?? 75 ?? C7 45 ?? ?? ?? ?? ?? 33 F6 C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? 
            ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? 
            ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? 
            ?? C7 45 ?? ?? ?? ?? ?? FF 74 B5 ?? 8D 85 ?? ?? ?? ?? 50 FF D7 85 C0 0F 84 ?? ?? ?? 
            ?? 46 83 FE ?? 7C ?? 33 C0 85 C0 0F 85 ?? ?? ?? ?? 8D 45 ?? 50 8D 85 ?? ?? ?? ?? 50 
            68 ?? ?? ?? ?? FF 75 ?? FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 
            50 FF 75 ?? FF 15 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 
            FF D6 8D 85 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 
            85 ?? ?? ?? ?? 50 FF D6 6A ?? 8D 85 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 
            8D 85 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 50 FF D6 6A ?? 8D 85 ?? ?? ?? ?? 53 50 E8 ?? 
            ?? ?? ?? 83 C4 ?? 8D 85 ?? ?? ?? ?? 50 FF 75 ?? FF 15 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? 
            ?? ?? 8B 45 ?? 8B 1D ?? ?? ?? ?? 8B 75 ?? 50 FF 15 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 
            56 FF D3 
        }

        $find_files_p3 = {
            33 F6 C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? 
            ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 90 FF 74 B5 ?? 
            53 FF D7 85 C0 74 ?? 46 83 FE ?? 72 ?? 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 
            8B 45 ?? 8B 75 ?? 8D 8D ?? ?? ?? ?? 51 50 FF 15 ?? ?? ?? ?? 85 C0 74 ?? 8B 45 ?? E9 
            ?? ?? ?? ?? 5F 5E 32 C0 5B 8B E5 5D C3 FF 75 ?? FF 15 ?? ?? ?? ?? 5F 5E B0 ?? 5B 8B 
            E5 5D C3 
        }

        $encrypt_files_p1 = {
            56 8B 75 ?? 68 ?? ?? ?? ?? 56 FF 15 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 
            83 C4 ?? 68 ?? ?? ?? ?? 50 FF D7 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF D7 56 8B 35 ?? ?? 
            ?? ?? 68 ?? ?? ?? ?? FF D6 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF D6 68 ?? ?? ?? ?? 8D 85 
            ?? ?? ?? ?? 50 FF D6 6A ?? 6A ?? 68 ?? ?? ?? ?? 6A ?? FF 15 ?? ?? ?? ?? 8D 85 ?? ?? 
            ?? ?? 50 68 ?? ?? ?? ?? FF D6 FF 75 ?? 8D 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 8D 85 
            ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 6A ?? 6A ?? 8B F0 FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? 
            ?? ?? 8B F8 C7 45 ?? ?? ?? ?? ?? 8D 45 ?? 50 6A ?? 68 ?? ?? ?? ?? 56 8D 85 ?? ?? ?? 
            ?? 50 FF 15 ?? ?? ?? ?? 85 C0 74 ?? FF 75 ?? 6A ?? FF 15 ?? ?? ?? ?? 50 FF 15
        }
        
        $encrypt_files_p2 = {
            8D 45 ?? 50 57 68 ?? ?? ?? ?? 56 8D 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 85 C0 75 ?? 
            57 50 FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 
            68 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 89 45 ?? 85 C0 74 ?? 8B 35 ?? ?? ?? 
            ?? 8D 4D ?? 6A ?? 51 FF 75 ?? FF 75 ?? 50 FF D6 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 57 68 
            ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 83 
            C4 ?? 8D 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 6A ?? 8D 4D ?? 51 50 8D 85 ?? ?? ?? ?? 
            50 FF 75 ?? FF D6 8B 45 ?? 50 FF 15 ?? ?? ?? ?? A1 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? 
            ?? ?? ?? FF D0 FF 75 ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? BF ?? ?? 
            ?? ?? 89 45 ?? 8D 57 ?? 8B CF D3 E8 A8 ?? 0F 84 ?? ?? ?? ?? 8D 47 ?? C7 45 ?? ?? ?? 
            ?? ?? 66 89 45 ?? 33 F6 33 C0 50 50 50 50 50 68 ?? ?? ?? ?? 50 66 89 45 ?? 8D 45 ?? 
            50 FF 15 ?? ?? ?? ?? 89 45 ?? 8D 45 ?? 50 FF 15 ?? ?? ?? ?? 83 F8 ?? 0F 84 ?? ?? ?? 
            ?? 83 7D ?? ?? 0F 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? 
            ?? 66 8B 85 ?? ?? ?? ?? 66 3B 45 ?? 75 ?? 66 8B 85 ?? ?? ?? ?? 66 3B 45 ?? B8 ?? ?? 
            ?? ?? 0F 44 F0 8D 45 ?? C7 45 ?? ?? ?? ?? ?? 50 C7 45 ?? ?? ?? ?? ?? 8D 85 ?? ?? ?? 
            ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 50 C7 45 ?? ?? ?? ?? ?? FF 15 ?? ?? ?? 
            ?? 8D 45 ?? 50 8D 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? 
            ?? 50 FF 15 ?? ?? ?? ?? 6A ?? 8D 85 ?? ?? ?? ?? 56 50 E8 ?? ?? ?? ?? 83 C4 ?? BA ?? 
            ?? ?? ?? 83 EF ?? 8B 45 ?? 0F 89 ?? ?? ?? ?? 0F 57 C0 C7 85
        }

        $encrypt_files_p3 = {
            0F 29 85 ?? ?? ?? ?? 0F 29 85 ?? ?? ?? ?? 0F 29 85 ?? ?? ?? ?? 0F 29 85 ?? ?? ?? ?? 
            0F 29 45 ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 89 45 ?? 8D 45 ?? 50 68 
            ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 8D 45 ?? 50 6A ?? 6A ?? 6A ?? 68 
            ?? ?? ?? ?? FF 75 ?? FF 15 ?? ?? ?? ?? 6A ?? 8D 45 ?? 50 6A ?? FF 75 ?? FF 15 ?? ?? 
            ?? ?? B8 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 66 89 85 ?? ?? ?? ?? 8D 85 ?? ?? 
            ?? ?? 6A ?? 50 C7 85 ?? ?? ?? ?? ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 85 
            ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 
            FF 15 ?? ?? ?? ?? 83 C4 ?? 8D 45 ?? 50 8D 85 ?? ?? ?? ?? 50 6A ?? 6A ?? 6A ?? 6A ?? 
            6A ?? 6A ?? 8D 85 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 50 FF 75 ?? FF 15 ?? ?? ?? ?? 85 
            C0 74 ?? FF 75 ?? 8B 35 ?? ?? ?? ?? FF D6 FF 75 ?? FF D6 6A ?? FF 15
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
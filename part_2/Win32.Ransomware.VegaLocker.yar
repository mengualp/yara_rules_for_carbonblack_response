rule Win32_Ransomware_VegaLocker : tc_detection malicious
{
    meta:
 		score = 7

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "VEGALOCKER"
        description         = "Yara rule that detects VegaLocker ransomware."

        tc_detection_type   = "Ransomware"
        tc_detection_name   = "VegaLocker"
        tc_detection_factor = 5

    strings:

        $find_files = {                        
            55 8B EC 81 C4 ?? ?? ?? ?? 53 56 57 89 55 ?? 89 45 ?? 8B 45 ?? 89 45 ?? 68 ?? ?? ?? 
            ?? E8 ?? ?? ?? ?? 89 45 ?? 83 7D ?? ?? 74 ?? 68 ?? ?? ?? ?? 8B 45 ?? 50 E8 ?? ?? ?? 
            ?? 89 C3 85 DB 74 ?? 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 8B 45 ?? 50 FF D3 85 C0 74 
            ?? 8B 45 ?? 50 8D 85 ?? ?? ?? ?? 50 8B 45 ?? 50 E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 8B 45 
            ?? 80 38 ?? 75 ?? 8B 45 ?? 80 78 ?? ?? 0F 85 ?? ?? ?? ?? 8B 45 ?? 83 C0 ?? E8 ?? ?? 
            ?? ?? 8B F0 80 3E ?? 0F 84 ?? ?? ?? ?? 8D 46 ?? E8 ?? ?? ?? ?? 8B F0 80 3E ?? 0F 84 
            ?? ?? ?? ?? EB ?? 8B 75 ?? 83 C6 ?? 8B DE 2B 5D ?? 8D 43 ?? 50 8B 45 ?? 50 8D 85 ?? 
            ?? ?? ?? 50 E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 8D 46 ?? E8 ?? ?? ?? ?? 8B F8 8B C7 2B C6 
            03 C3 40 3D ?? ?? ?? ?? 0F 8F ?? ?? ?? ?? 8B C7 2B C6 40 50 56 8D 85 ?? ?? ?? ?? 03 
            C3 50 E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 89 45 
            ?? 83 7D ?? ?? 74 ?? 8B 45 ?? 50 E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 
            8D 53 ?? 03 C2 40 3D ?? ?? ?? ?? 7F ?? C6 84 1D ?? ?? ?? ?? ?? B8 ?? ?? ?? ?? 2B C3 
            48 50 8D 85 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 03 C3 40 50 E8 ?? ?? ?? ?? 8D 85 ?? ?? 
            ?? ?? 50 E8 ?? ?? ?? ?? 40 03 D8 8B F7 80 3E ?? 0F 85 ?? ?? ?? ?? 8B 45 ?? 50 8D 85 
            ?? ?? ?? ?? 50 8B 45 ?? 50 E8 ?? ?? ?? ?? 8B 45 ?? 5F 5E 5B 8B E5 5D C3 
        }

        $encrypt_files_p1 = {                        
            55 8B EC 81 C4 ?? ?? ?? ?? 53 56 57 33 C9 89 8D ?? ?? ?? ?? 89 8D ?? ?? ?? ?? 89 8D 
            ?? ?? ?? ?? 89 4D ?? 89 4D ?? 89 4D ?? 89 4D ?? 89 55 ?? 89 45 ?? 8D 45 ?? E8 ?? ?? 
            ?? ?? 8D 85 ?? ?? ?? ?? 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 
            FF 30 64 89 20 C6 85 ?? ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8D 85 
            ?? ?? ?? ?? 8B 55 ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? BA ?? ?? ?? 
            ?? E8 ?? ?? ?? ?? 85 C0 75 ?? 8B 85 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 
            89 85 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 89 85 ?? ?? 
            ?? ?? 8B 85 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8B 85 
            ?? ?? ?? ?? 89 85 ?? ?? ?? ?? EB ?? 33 C0 5A 59 59 64 89 10 E9 ?? ?? ?? ?? 8D 85 ?? 
            ?? ?? ?? E8 ?? ?? ?? ?? 6A ?? 8B 45 ?? E8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 33 C0 55 68 
            ?? ?? ?? ?? 64 FF 30 64 89 20 6A ?? 8B 4D ?? B2 ?? A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 
            45 ?? 8B 45 ?? 8B 10 FF 12 89 85 ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 8D 45 ?? BA ?? ?? ?? 
            ?? E8 ?? ?? ?? ?? 8D 45 ?? E8 ?? ?? ?? ?? 8B D0 B9 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? 
            ?? 8B 45 ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 74 ?? FF B5 ?? ?? ?? ?? FF B5 ?? ?? ?? ?? 
            33 D2 8B 45 ?? 8B 08 FF 51 ?? A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B D0 B9 ?? ?? ?? ?? 8B 
            45 ?? E8 ?? ?? ?? ?? FF B5 ?? ?? ?? ?? FF B5 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? C6 
            85 ?? ?? ?? ?? ?? EB ?? C6 85 ?? ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 33 C0 5A 59 59 
            64 89 10 EB ?? E9 ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30
        }

        $encrypt_files_p2 = {                        
            64 89 20 8B 45 ?? E8 ?? ?? ?? ?? 33 C0 5A 59 59 64 89 10 EB ?? E9 ?? ?? ?? ?? E8 ?? 
            ?? ?? ?? E8 ?? ?? ?? ?? 80 BD ?? ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 6A ?? 8B 4D ?? B2 ?? 
            A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 45 ?? 8B 45 ?? 8B 10 FF 12 89 85 ?? ?? ?? ?? 89 95 
            ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 75 ?? 83 BD ?? ?? ?? ?? ?? 0F 86 ?? ?? ?? ?? EB ?? 
            0F 8E ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 75 ?? 81 BD ?? ?? ?? ?? ?? ?? ?? ?? 76 ?? EB 
            ?? 7E ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? EB ?? 8B 85 ?? 
            ?? ?? ?? 89 85 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8D 45 ?? E8 ?? ?? ?? 
            ?? 8D 45 ?? E8 ?? ?? ?? ?? BB ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B D0 8D 85 
            ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 8D 45 ?? E8 ?? ?? ?? ?? 83 FB ?? 7F ?? 
            B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B D0 8D 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 95 ?? ?? ?? 
            ?? 8D 45 ?? E8 ?? ?? ?? ?? 43 83 FB ?? 75 ?? 8B 85 ?? ?? ?? ?? 8B D0 8D 45 ?? E8 ?? 
            ?? ?? ?? 8D 45 ?? E8 ?? ?? ?? ?? 8B D0 8B 8D ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 83 
            BD ?? ?? ?? ?? ?? 75 ?? 81 BD ?? ?? ?? ?? ?? ?? ?? ?? 75 ?? 8D 45 ?? BA
        }

        $encrypt_files_p3 = {                        
            E8 ?? ?? ?? ?? 8D 45 ?? E8 ?? ?? ?? ?? 8B D0 B9 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 
            EB ?? 8D 45 ?? E8 ?? ?? ?? ?? FF B5 ?? ?? ?? ?? FF B5 ?? ?? ?? ?? 33 D2 8B 45 ?? 8B 
            08 FF 51 ?? 83 BD ?? ?? ?? ?? ?? 75 ?? 81 BD ?? ?? ?? ?? ?? ?? ?? ?? 75 ?? 8D 45 ?? 
            E8 ?? ?? ?? ?? 8B D0 B9 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? E8 ?? ?? 
            ?? ?? 8B D0 B9 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 55 E8 ?? ?? ?? ?? 59 55 E8 ?? ?? 
            ?? ?? 59 EB ?? 55 E8 ?? ?? ?? ?? 59 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B D0 B9 ?? ?? ?? 
            ?? 8B 45 ?? E8 ?? ?? ?? ?? 55 E8 ?? ?? ?? ?? 59 C6 85 ?? ?? ?? ?? ?? 8B 45 ?? E8 ?? 
            ?? ?? ?? 80 BD ?? ?? ?? ?? ?? 74 ?? 8B 85 ?? ?? ?? ?? 50 8B 45 ?? E8 ?? ?? ?? ?? 50 
            E8 ?? ?? ?? ?? 33 C0 5A 59 59 64 89 10 EB ?? E9 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 
            64 FF 30 64 89 20 8B 45 ?? E8 ?? ?? ?? ?? 33 C0 5A 59 59 64 89 10 EB ?? E9 ?? ?? ?? 
            ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8D 85 ?? ?? 
            ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? 
            ?? 8D 45 ?? E8 ?? ?? ?? ?? 8D 45 ?? E8 ?? ?? ?? ?? 8D 45 ?? E8 ?? ?? ?? ?? 8D 45 ?? 
            BA ?? ?? ?? ?? E8 ?? ?? ?? ?? C3 
        }

    condition:
        uint16(0) == 0x5A4D and 
        (
            $find_files
        ) and 
        (
            all of ($encrypt_files_p*)
        )
}
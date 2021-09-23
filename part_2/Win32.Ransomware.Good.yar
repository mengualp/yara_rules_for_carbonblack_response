rule Win32_Ransomware_Good : tc_detection malicious
{
    meta:
 		score = 7

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "GOOD"
        description         = "Yara rule that detects Good ransomware."

        tc_detection_type   = "Ransomware"
        tc_detection_name   = "Good"
        tc_detection_factor = 5

    strings:

        $find_files = {
            FF D7 53 85 C0 75 ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 5F 5E 5B 8B E5 5D C3 8D 
            85 ?? ?? ?? ?? 50 FF D7 53 85 C0 75 ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 5F 5E 
            5B 8B E5 5D C3 8D 85 ?? ?? ?? ?? 50 FF D7 53 85 C0 75 ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? 
            ?? 83 C4 ?? 5F 5E 5B 8B E5 5D C3 8D 85 ?? ?? ?? ?? 50 FF D7 53 85 C0 75 ?? 68 ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 5F 5E 5B 8B E5 5D C3 8D 85 ?? ?? ?? ?? 50 FF D7 53 85 
            C0 75 ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 5F 5E 5B 8B E5 5D C3 8B 3D ?? ?? ?? 
            ?? 33 C0 66 89 45 ?? 8D 45 ?? 50 8D 85 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 50 C7 45 ?? 
            ?? ?? ?? ?? FF D7 83 C4 ?? 8D 85 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? 
            ?? 8B D8 83 FB ?? 75 ?? 8D 85 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 
            5F 5E 5B 8B E5 5D C3 
        }

        $remote_connection = {
            55 8B EC 53 8B 5D ?? 57 53 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 7D ?? 83 C4 ?? 8B 0F 8B 
            C1 83 E8 ?? 74 ?? 83 E8 ?? 74 ?? 83 E8 ?? 74 ?? 51 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 
            C4 ?? EB ?? 68 ?? ?? ?? ?? EB ?? 68 ?? ?? ?? ?? EB ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 
            83 C4 ?? 53 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 4F ?? 83 C4 ?? 8B C1 83 E8 ?? 74 ?? 83 
            E8 ?? 74 ?? 83 E8 ?? 74 ?? 51 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? EB ?? 68 ?? ?? 
            ?? ?? EB ?? 68 ?? ?? ?? ?? EB ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 53 68 ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? 8B 47 ?? 83 C4 ?? 83 F8 ?? 77 ?? FF 24 85 ?? ?? ?? ?? 68 ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? EB ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? EB ?? 68 
            ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? EB ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? EB 
            ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? EB ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 
            ?? EB ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? EB ?? 50 68 ?? ?? ?? ?? E8 ?? ?? ?? 
            ?? 83 C4 ?? FF 77 ?? 53 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 47 ?? 83 C4 ?? A8 ?? 74 ?? 
            68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 47 ?? 83 C4 ?? A8 ?? 74 ?? 68 ?? ?? ?? ?? E8 ?? ?? 
            ?? ?? 83 C4 ?? 83 7F ?? ?? 75 ?? 56 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 8B F0 FF 
            77 ?? FF 15 ?? ?? ?? ?? 8D 04 45 ?? ?? ?? ?? 50 FF 77 ?? 56 E8 ?? ?? ?? ?? 83 C4 ?? 
            8D 45 ?? 50 6A ?? 56 68 ?? ?? ?? ?? 6A ?? 6A ?? FF 15 ?? ?? ?? ?? 5E FF 77 ?? 53 68 
            ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 77 ?? 53 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 77 ?? 53 68 
            ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 77 ?? 53 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 5F 5B 
            5D C3 
        }

        $encrypt_files = {
            68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 8B C8 8B F2 83 C4 ?? 2B CE 8D 71 ?? 
            66 90 0F B7 0A 8D 52 ?? 66 89 4C 32 ?? 66 85 C9 75 ?? 50 FF 35 ?? ?? ?? ?? FF 15 ?? 
            ?? ?? ?? 8B 35 ?? ?? ?? ?? 47 89 7D ?? E9 ?? ?? ?? ?? FF 75 ?? 8D 85 ?? ?? ?? ?? C7 
            45 ?? ?? ?? ?? ?? FF 75 ?? 50 E8 ?? ?? ?? ?? 85 C0 75 ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? 
            ?? 8B 35 ?? ?? ?? ?? 83 C4 ?? EB ?? 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? C7 85 ?? ?? ?? 
            ?? ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 50 8D 85 ?? ?? ?? 
            ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 83 C4 ?? 8D 85 ?? ?? ?? ?? 50 
            8D 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? EB ?? 68 ?? ?? ?? ?? EB ?? 
            8D 85 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 8D 85 ?? ?? ?? ?? 50 53 
            FF D6 8B 3D ?? ?? ?? ?? 83 F8 ?? 0F 84 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 83 F8 ?? 74 ?? 
            8D 85 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 5F 5E 5B 8B E5 5D C3 53 
            FF 15 ?? ?? ?? ?? 85 C0 75 ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 5F 5E 5B 8B E5 
            5D C3
        }

    condition:
        uint16(0) == 0x5A4D and
        (
            $find_files
        ) and
        (
            $encrypt_files
        ) and
        (
            $remote_connection
        )
}
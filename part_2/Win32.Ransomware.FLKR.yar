rule Win32_Ransomware_FLKR : tc_detection malicious
{
    meta:
 		score = 7

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "FLKR"
        description         = "Yara rule that detects FLKR ransomware."

        tc_detection_type   = "Ransomware"
        tc_detection_name   = "FLKR"
        tc_detection_factor = 5

    strings:

        $search_and_encrypt_p1 = {
            81 EC ?? ?? ?? ?? A1 ?? ?? ?? ?? 33 C4 89 84 24 ?? ?? ?? ?? 53 55 56 57 8B BC 24 ?? 
            ?? ?? ?? 57 89 7C 24 ?? FF 15 ?? ?? ?? ?? 8B 2D ?? ?? ?? ?? 68 ?? ?? ?? ?? 57 89 44 
            24 ?? FF D5 8D 44 24 ?? 50 57 FF 15 ?? ?? ?? ?? 89 44 24 ?? 83 F8 ?? 0F 84 ?? ?? ?? 
            ?? 8B 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 4C 24 ?? 51 FF D6 85 C0 0F 84 ?? ?? ?? ?? 68 
            ?? ?? ?? ?? 8D 54 24 ?? 52 FF D6 85 C0 0F 84 ?? ?? ?? ?? 8B 44 24 ?? 8D 4C 24 ?? 51 
            57 C6 04 07 ?? FF D5 F6 44 24 ?? ?? 0F 84 ?? ?? ?? ?? 8D 5C 24 ?? E8 ?? ?? ?? ?? 84 
            C0 0F 85 ?? ?? ?? ?? 8A 0F 33 D2 84 C9 74 ?? BE ?? ?? ?? ?? 8B C7 2B F7 88 0C 06 8A 
            48 ?? 40 42 84 C9 75 ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? C6 82 ?? ?? ?? ?? ?? C6 82 ?? 
            ?? ?? ?? ?? FF D5 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F0 83 C4 ?? 85 F6 
            74 ?? 56 68 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 83 C4 
            ?? 68 ?? ?? ?? ?? 57 FF D5 57 E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 33 C0 38 44 24 ?? 74 
        }

        $search_and_encrypt_p2 = {
            40 80 7C 04 ?? ?? 75 ?? 8A 4C 04 ?? 80 F9 ?? 75 ?? 80 7C 04 ?? ?? 75 ?? 80 7C 04 ?? 
            ?? 75 ?? 80 7C 04 ?? ?? 74 ?? 80 F9 ?? 75 ?? B3 ?? 38 5C 04 ?? 75 ?? 80 7C 04 ?? ?? 
            75 ?? 80 7C 04 ?? ?? 75 ?? 57 FF 15 ?? ?? ?? ?? 85 C0 74 ?? FF 05 ?? ?? ?? ?? E9 ?? 
            ?? ?? ?? FF 05 ?? ?? ?? ?? E9 ?? ?? ?? ?? B3 ?? B2 ?? 80 F9 ?? 75 ?? 38 5C 04 ?? 75 
            ?? 80 7C 04 ?? ?? 75 ?? 38 5C 04 ?? 75 ?? 32 D2 80 F9 ?? 75 ?? 80 7C 04 ?? ?? 75 ?? 
            80 7C 04 ?? ?? 75 ?? 80 7C 04 ?? ?? 75 ?? 32 D2 80 F9 ?? 75 ?? 80 7C 04 ?? ?? 75 ?? 
            80 7C 04 ?? ?? 75 ?? 80 7C 04 ?? ?? 0F 84 ?? ?? ?? ?? 84 D2 0F 84 ?? ?? ?? ?? 8A 0F 
            33 D2 84 C9 74 ?? 8D B4 24 ?? ?? ?? ?? 8B C7 2B F7 8D A4 24 ?? ?? ?? ?? 88 0C 06 8A 
            48 ?? 40 42 84 C9 75 ?? A1 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 89 84 24 ?? ?? ?? ?? 0F B6 
            05 ?? ?? ?? ?? C6 84 14 ?? ?? ?? ?? ?? 8B 15 ?? ?? ?? ?? 89 94 24 ?? ?? ?? ?? 8B 15 
            ?? ?? ?? ?? 88 84 24 ?? ?? ?? ?? 33 C0 6A ?? 89 8C 24 ?? ?? ?? ?? 89 94 24 ?? ?? ?? 
            ?? 89 84 24 ?? ?? ?? ?? 89 84 24 ?? ?? ?? ?? 89 84 24 ?? ?? ?? ?? 88 84 24 ?? ?? ?? 
            ?? E8 ?? ?? ?? ?? 83 C4 ?? 8B D8 68 ?? ?? ?? ?? 89 5C 24 ?? E8 ?? ?? ?? ?? 8B 0D ?? 
            ?? ?? ?? 8B 15 ?? ?? ?? ?? 8B E8 A1 ?? ?? ?? ?? 89 8C 24 ?? ?? ?? ?? 8B 0D ?? ?? ?? 
            ?? 89 84 24 ?? ?? ?? ?? 0F B6 05 ?? ?? ?? ?? 89 94 24 ?? ?? ?? ?? 66 8B 15 ?? ?? ?? 
            ?? 89 8C 24 ?? ?? ?? ?? 83 C4 ?? 8D 8C 24 ?? ?? ?? ?? 8D 74 24 ?? 89 6C 24 ?? 66 89 
        }

        $search_and_encrypt_p3 = {
            94 24 ?? ?? ?? ?? 88 84 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8C 24 ?? ?? ?? ?? 68 ?? ?? 
            ?? ?? 51 E8 ?? ?? ?? ?? 8B F0 83 C4 ?? 85 F6 0F 84 ?? ?? ?? ?? 8D 94 24 ?? ?? ?? ?? 
            52 8D 84 24 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 8D 8C 24 ?? ?? ?? ?? 68 ?? ?? ?? ?? 51 
            E8 ?? ?? ?? ?? 8B F8 83 C4 ?? 85 FF 74 ?? 56 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 75 ?? 56 
            68 ?? ?? ?? ?? 8D 94 24 ?? ?? ?? ?? 6A ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 8D 44 24 ?? 50 
            8D 84 24 ?? ?? ?? ?? 8B C8 E8 ?? ?? ?? ?? 57 68 ?? ?? ?? ?? 8D 8C 24 ?? ?? ?? ?? 6A 
            ?? 51 E8 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 74 ?? 57 E8 ?? ?? ?? ?? 83 C4 
            ?? 56 E8 ?? ?? ?? ?? 8B 7C 24 ?? 83 C4 ?? FF 05 ?? ?? ?? ?? 8D 94 24 ?? ?? ?? ?? 52 
            FF 15 ?? ?? ?? ?? BE ?? ?? ?? ?? 2B F0 8D 84 24 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 03 
            C6 50 8D 8C 24 ?? ?? ?? ?? 51 8B D1 52 FF 15 ?? ?? ?? ?? 8D 84 24 ?? ?? ?? ?? 50 FF 
            15 ?? ?? ?? ?? 85 C0 75 ?? FF 05 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 ?? 55 E8 ?? ?? 
            ?? ?? 8B 2D ?? ?? ?? ?? 83 C4 ?? 8B 74 24 ?? 8D 4C 24 ?? 51 56 FF 15 ?? ?? ?? ?? 85 
            C0 0F 85 ?? ?? ?? ?? 56 FF 15 
        }

    condition:
        uint16(0) == 0x5A4D and (all of ($search_and_encrypt_p*))
}
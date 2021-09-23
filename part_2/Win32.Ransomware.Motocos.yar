rule Win32_Ransomware_Motocos : tc_detection malicious
{
    meta:
 		score = 7

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "MOTOCOS"
        description         = "Yara rule that detects Motocos ransomware."

        tc_detection_type   = "Ransomware"
        tc_detection_name   = "Motocos"
        tc_detection_factor = 5

    strings:

        $generate_key = {
            55 8B EC 83 C4 ?? 53 89 4D ?? 89 55 ?? 8B D8 8B 45 ?? E8 ?? ?? ?? ?? 8B 45 ?? E8 ??
            ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 83 7D ?? ?? 74 ?? 8B 45 ?? 8B 15
            ?? ?? ?? ?? 8B 12 E8 ?? ?? ?? ?? 75 ?? B9 ?? ?? ?? ?? B2 ?? A1 ?? ?? ?? ?? E8 ?? ??
            ?? ?? E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 8B C3 E8 ?? ?? ?? ?? 89 45 ?? 33 D2 55 68 ?? ??
            ?? ?? 64 FF 32 64 89 22 8B 4D ?? 8B 55 ?? 8B C3 E8 ?? ?? ?? ?? 89 45 ?? 33 D2 55 68
            ?? ?? ?? ?? 64 FF 32 64 89 22 8B 45 ?? 85 C0 74 ?? 83 E8 ?? 8B 00 8B D8 89 5D ?? 80
            7D ?? ?? 75 ?? 8B 5D ?? 03 DB 53 8D 45 ?? B9 ?? ?? ?? ?? 8B 15 ?? ?? ?? ?? E8 ?? ??
            ?? ?? 83 C4 ?? 53 8D 45 ?? 50 8B 45 ?? 50 6A ?? 80 7D ?? ?? F5 1B C0 50 6A ?? 8B 45
            ?? 50 E8 ?? ?? ?? ?? 83 F8 ?? 1B C0 40 84 C0 75 ?? B9 ?? ?? ?? ?? B2 ?? A1 ?? ?? ??
            ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 ?? 50 8D 45 ?? B9 ?? ?? ?? ?? 8B 15 ?? ?? ??
            ?? E8 ?? ?? ?? ?? 83 C4 ?? 8B 45 ?? 8B 55 ?? 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0
            5A 59 59 64 89 10 68 ?? ?? ?? ?? 8B 45 ?? 50 E8 ?? ?? ?? ?? C3 E9 ?? ?? ?? ?? EB ??
            33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? 6A ?? 8B 45 ?? 50 E8 ?? ?? ?? ?? C3 E9 ?? ??
            ?? ?? EB ?? 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8D 45 ?? E8 ?? ?? ?? ?? 8D 45 ??
            8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? C3 E9 ?? ?? ?? ?? EB ?? 5B 8B E5 5D C2
        }

        $encrypt_files = {
            55 8B EC 83 C4 ?? 53 56 57 33 C9 89 4D ?? 89 4D ?? 89 55 ?? 8B 45 ?? E8 ?? ?? ?? ??
            33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 C6 45 ?? ?? 33 D2 55 68 ?? ?? ?? ?? 64 FF
            32 64 89 22 B2 ?? 8B 45 ?? E8 ?? ?? ?? ?? B2 ?? 8B 45 ?? E8 ?? ?? ?? ?? E8 ?? ?? ??
            ?? 8B D8 8B C3 8B D8 F6 C3 ?? 74 ?? 66 83 E3 ?? B2 ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B C3
            E8 ?? ?? ?? ?? 8B D0 B1 ?? 8B 45 ?? E8 ?? ?? ?? ?? 6A ?? 6A ?? 8B 4D ?? B2 ?? A1 ??
            ?? ?? ?? E8 ?? ?? ?? ?? 89 45 ?? B2 ?? A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 45 ?? 33 D2
            55 68 ?? ?? ?? ?? 64 FF 32 64 89 22 8B 45 ?? 8B 10 FF 12 8B C8 8B 55 ?? A1 ?? ?? ??
            ?? E8 ?? ?? ?? ?? 8B C8 8B 55 ?? 8B 45 ?? E8 ?? ?? ?? ?? 88 45 ?? 33 C0 5A 59 59 64
            89 10 68 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? C3 E9 ?? ?? ??
            ?? EB ?? 80 7D ?? ?? 75 ?? 8D 45 ?? 50 8B 45 ?? 89 45 ?? C6 45 ?? ?? B8 ?? ?? ?? ??
            89 45 ?? C6 45 ?? ?? 8D 55 ?? B9 ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 ??
            E8 ?? ?? ?? ?? 50 8B 45 ?? E8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 F8 ?? 1B C0 40 88 45
            ?? 33 C0 5A 59 59 64 89 10 E9 ?? ?? ?? ?? E9
        }

        $find_files = {
            55 8B EC 83 C4 ?? 53 56 57 33 C9 89 4D ?? 8B FA 89 45 ?? 33 C0 55 68 ?? ?? ?? ?? 64
            FF 30 64 89 20 8D 45 ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B D8 85 DB 7C ?? 8B 45 ?? 66
            83 3C 58 ?? 75 ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8D 45 ?? E8 ?? ?? ?? ??
            8B 75 ?? 85 F6 74 ?? 83 EE ?? 8B 36 8D 45 ?? 50 8D 53 ?? 8B CE 8B 45 ?? E8 ?? ?? ??
            ?? 8B C7 8B 55 ?? E8 ?? ?? ?? ?? 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8D 45 ?? E8
            ?? ?? ?? ?? C3 E9 ?? ?? ?? ?? EB ?? 8B C7 E8 ?? ?? ?? ?? 33 C0 5A 59 59 64 89 10 68
            ?? ?? ?? ?? 8D 45 ?? E8 ?? ?? ?? ?? C3 E9 ?? ?? ?? ?? EB ?? 5F 5E 5B 59 59 5D C3
        }

    condition:
        uint16(0) == 0x5A4D and
        (
            $generate_key
        ) and
        (
            $find_files
        ) and
        (
            $encrypt_files
        )
}
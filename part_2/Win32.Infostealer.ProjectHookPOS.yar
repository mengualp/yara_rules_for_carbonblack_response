rule Win32_Infostealer_ProjectHookPOS : tc_detection malicious
{
    meta:
 		score = 7

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "PROJECTHOOKPOS"
        description         = "Yara rule that detects ProjectHookPOS infostealer."

        tc_detection_type   = "Infostealer"
        tc_detection_name   = "ProjectHookPOS"
        tc_detection_factor = 5

    strings:
        $calc_luhn = {
            55 8B EC 83 C4 ?? 53 56 57 33 C9 89 4D ?? 89 55 ?? 8B 45 ?? E8 ?? ?? ?? ?? 33 C0 55 
            68 ?? ?? ?? ?? 64 FF 30 64 89 20 C6 45 ?? ?? 33 C0 89 45 ?? 8B 45 ?? 85 C0 74 ?? 8B 
            D0 83 EA ?? 66 83 3A ?? 74 ?? 8D 45 ?? 8B 55 ?? E8 ?? ?? ?? ?? 85 C0 74 ?? 83 E8 ?? 
            8B 00 25 ?? ?? ?? ?? 79 ?? 48 83 C8 ?? 40 85 C0 0F 94 C3 8B 45 ?? 85 C0 74 ?? 8B D0 
            83 EA ?? 66 83 3A ?? 74 ?? 8D 45 ?? 8B 55 ?? E8 ?? ?? ?? ?? 85 C0 74 ?? 83 E8 ?? 8B 
            00 8B F0 85 F6 7E ?? BF ?? ?? ?? ?? 8D 45 ?? 8B 55 ?? 0F B7 54 7A ?? E8 ?? ?? ?? ?? 
            8B 45 ?? 83 CA ?? E8 ?? ?? ?? ?? 0F B6 D0 66 83 FA ?? 75 ?? C6 45 ?? ?? EB ?? 84 DB 
            74 ?? 0F B6 C0 0F B6 80 ?? ?? ?? ?? 01 45 ?? EB ?? 0F B6 C0 01 45 ?? 80 F3 ?? 47 4E 
            75 ?? 8B 45 ?? B9 ?? ?? ?? ?? 99 F7 F9 85 D2 75 ?? 80 7D ?? ?? 74 ?? 33 DB EB ?? B3 
            ?? 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8D 45 ?? E8 ?? ?? ?? ?? 8D 45 ?? E8 ?? ?? 
            ?? ?? C3 E9 ?? ?? ?? ?? EB ?? 8B C3 5F 5E 5B 8B E5 5D C3 
        }

        $track_1_reverse = {
            55 8B EC 83 C4 ?? 53 56 33 DB 89 5D ?? 8B F1 89 55 ?? 8B 45 ?? E8 ?? ?? ?? ?? 33 C0 
            55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8B C6 33 D2 E8 ?? ?? ?? ?? 8B 45 ?? 85 C0 74 ?? 
            8B D0 83 EA ?? 66 83 3A ?? 74 ?? 8D 45 ?? 8B 55 ?? E8 ?? ?? ?? ?? 85 C0 74 ?? 83 E8 
            ?? 8B 00 8B D8 83 FB ?? 7C ?? 8D 45 ?? 50 B9 ?? ?? ?? ?? 8B D3 8B 45 ?? E8 ?? ?? ?? 
            ?? 8B 55 ?? 8B C6 E8 ?? ?? ?? ?? 4B 85 DB 75 ?? 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? 
            ?? 8D 45 ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? C3 E9 ?? ?? ?? ?? EB ?? 5E 5B 59 59 5D C3 
        }

        $check_validity_1 = {
            8B D0 83 EA ?? 66 83 3A ?? 74 ?? 8D 45 ?? 8B 55 ?? E8 ?? ?? ?? ?? 66 83 38 ?? 75 ?? 
            8B 45 ?? 85 C0 74 ?? 8B D0 83 EA ?? 66 83 3A ?? 74 ?? 8D 45 ?? 8B 55 ?? E8 ?? ?? ?? 
            ?? 66 83 78 ?? ?? 0F 94 C0 EB ?? 33 C0 84 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? 85 C0 74 ?? 
            8B D0 83 EA ?? 66 83 3A ?? 74 ?? 8D 45 ?? 8B 55 ?? E8 ?? ?? ?? ?? 66 83 78 ?? ?? 0F 
            85 ?? ?? ?? ?? 8B 45 ?? 85 C0 74 ?? 8B D0 83 EA ?? 66 83 3A ?? 74 ?? 8D 45 ?? 8B 55 
            ?? E8 ?? ?? ?? ?? BE ?? ?? ?? ?? 66 81 78 ?? ?? ?? 73 ?? 0F B6 40 ?? 0F B6 C0 0F A3 
            06 72 ?? 33 C0 EB 
        }

        $encode_and_send_1 = {
            64 89 20 B2 ?? A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B D8 33 C9 B2 ?? A1 ?? ?? ?? ?? E8 ?? 
            ?? ?? ?? 8B F0 8D 4D ?? 8B 55 ?? 8B C7 E8 ?? ?? ?? ?? 8B 4D ?? 8D 45 ?? BA ?? ?? ?? 
            ?? E8 ?? ?? ?? ?? 8B 55 ?? 8B C3 8B 08 FF 51 ?? 8D 45 ?? 8B 4D ?? BA ?? ?? ?? ?? E8 
            ?? ?? ?? ?? 8B 55 ?? 8B C3 8B 08 FF 51 ?? 8D 45 ?? 8B 4D ?? BA ?? ?? ?? ?? E8 ?? ?? 
            ?? ?? 8B 55 ?? 8B C3 8B 08 FF 51 ?? 8D 45 ?? 8B 4D ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 
            8B 55 ?? 8B C3 8B 08 FF 51 ?? 8B C6 E8 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 
            C6 E8 ?? ?? ?? ?? 05 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 ?? 50 8B CB BA 
            ?? ?? ?? ?? 8B C6 E8 ?? ?? ?? ?? 8B C3 E8 ?? ?? ?? ?? 8B C6 E8
        }

        $form_create_1 = {
            8D 55 ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 
            ?? E8 ?? ?? ?? ?? 8B D0 8D 45 ?? E8 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 6A ?? 8D 55 
            ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 ?? E8 
            ?? ?? ?? ?? 50 8D 55 ?? A1 ?? ?? ?? ?? 8B 00 E8 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 
            50 E8 ?? ?? ?? ?? 8D 55 ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 ?? BA ?? ?? ?? ?? E8 
            ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B D0 8D 45 ?? E8 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? 
            ?? ?? 84 C0 0F 84
        }

        $form_create_2 = {
            33 C9 B2 ?? A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B D8 8B C3 E8 ?? ?? ?? ?? 05 ?? ?? ?? ?? 
            BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 4D ?? BA ?? ?? ?? ?? 8B C3 E8 ?? ?? ?? ?? 8D 55 ?? 
            B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 ?? E8 ?? 
            ?? ?? ?? 8B D0 8D 45 ?? E8 ?? ?? ?? ?? 8B 45 ?? 33 C9 BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 
            8B C3 E8
        }

        $form_create_3 = {
            B2 ?? A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B D8 BA ?? ?? ?? ?? 8B C3 E8 ?? ?? ?? ?? 33 C9 
            BA ?? ?? ?? ?? 8B C3 E8 ?? ?? ?? ?? 8D 55 ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 ?? 
            BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B D0 8D 45 ?? E8 ?? ?? ?? ?? 
            8B 4D ?? BA ?? ?? ?? ?? 8B C3 E8 ?? ?? ?? ?? 8B C3 E8 ?? ?? ?? ?? 33 C9 BA ?? ?? ?? 
            ?? 8B C3 E8 ?? ?? ?? ?? 33 C9 BA ?? ?? ?? ?? 8B C3 E8 ?? ?? ?? ?? 8B C3 E8 ?? ?? ?? 
            ?? 8B C3 E8 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 8B 09 B2 ?? A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 
            A3 ?? ?? ?? ?? BA ?? ?? ?? ?? A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 68 ?? ?? ?? ?? A1 ?? 
            ?? ?? ?? E8 ?? ?? ?? ?? B2 ?? A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B C6 E8 ?? ?? ?? ?? 84 
            C0 74
        }

    condition:
        uint16(0) == 0x5A4D and
        ($calc_luhn and $track_1_reverse and $check_validity_1 and $encode_and_send_1 and
        $form_create_1 and $form_create_2 and $form_create_3)

}
import "pe"

rule Win32_Ransomware_DirtyDecrypt : tc_detection malicious
{
    meta:
 		score = 7

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "DIRTYDECRYPT"
        description         = "Yara rule that detects DirtyDecrypt ransomware."

        tc_detection_type   = "Ransomware"
        tc_detection_name   = "DirtyDecrypt"
        tc_detection_factor = 5

    strings:
        $dd_ep = {
            55 8B EC 83 EC ?? E8 ?? ?? ?? ?? 85 C0 0F 84 BF 00 00 00 C7 45 ?? ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 89 45 ?? 83 7D ?? ?? 74
            1F 6A ?? 6A ?? 68 ?? ?? ?? ?? 6A ?? 8B 45 ?? 50 E8 ?? ?? ?? ?? 85 C0 74 07 C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? EB
            09 8B 4D ?? 83 C1 ?? 89 4D ?? 83 7D ?? ?? 73 15 6A ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 55 ?? 89 44 95 ?? EB DC 6A ?? 68
            ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 45 ?? 6A ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 45 ?? 8B 45 ?? 50 8B 4D ?? 51 E8 ?? ?? ?? ??
            8B 15 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 51 E8 ?? ?? ?? ?? 6A ?? 6A ?? 6A
            ?? 8D 55 ?? 52 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A ?? FF 15 ?? ?? ?? ?? 33 C0 8B E5 5D C2 ?? ??
        }

        $dd_hash = {
            55 8B EC 83 EC ?? C7 45 ?? ?? ?? ?? ?? 83 7D ?? ?? 0F 84 D5 00 00 00 83 7D ?? ?? 0F 84 CB 00 00 00 83 7D ?? ?? 0F 84 C1
            00 00 00 83 7D ?? ?? 0F 84 B7 00 00 00 83 7D ?? ?? 0F 84 AD 00 00 00 83 7D ?? ?? 0F 84 A3 00 00 00 C7 45 ?? ?? ?? ?? ??
            8D 45 ?? 50 6A ?? 6A ?? 68 ?? ?? ?? ?? 8B 4D ?? 51 FF 15 ?? ?? ?? ?? 85 C0 75 02 EB 6F 83 7D ?? ?? 76 2A 6A ?? 6A ?? 8B
            55 ?? 52 8B 45 ?? 50 FF 15 ?? ?? ?? ?? 85 C0 75 02 EB 51 8B 4D ?? 83 E9 ?? 89 4D ?? 8B 55 ?? 83 C2 ?? 89 55 ?? 6A ?? 8B
            45 ?? 50 8B 4D ?? 51 8B 55 ?? 52 FF 15 ?? ?? ?? ?? 85 C0 75 02 EB 25 6A ?? 6A ?? 8B 45 ?? 50 8B 4D ?? 51 8B 55 ?? 52 8B
            45 ?? 50 FF 15 ?? ?? ?? ?? 89 45 ?? 33 C9 0F 85 74 FF FF FF 83 7D ?? ?? 74 0A 8B 55 ?? 52 FF 15 ?? ?? ?? ?? 8B 45 ?? 8B
            E5 5D C2 ?? ??
        }

        $dd_getkey = {
            55 8B EC 83 EC ?? C7 45 ?? ?? ?? ?? ?? 83 7D ?? ?? 74 31 C7 45 ?? ?? ?? ?? ?? 6A ?? 8D 45 ?? 50 8D 4D ?? 51 6A ?? 8B 55
            ?? 52 FF 15 ?? ?? ?? ?? 85 C0 75 07 C7 45 ?? ?? ?? ?? ?? 8B 45 ?? C1 E8 ?? 89 45 ?? 8B 45 ?? 8B E5 5D C2 ?? ??
        }

        $dd_destroykey = {
            55 8B EC 83 7D ?? ?? 74 0A 8B 45 ?? 50 FF 15 ?? ?? ?? ?? 5D C2 
        }

        $dd_importkey = {
            55 8B EC 51 C7 45 ?? ?? ?? ?? ?? 8D 45 ?? 50 6A ?? 6A ?? 8B 4D ?? 8B 51 ?? 52 8B 45 ?? 8B 08 51 8B 55 ?? 52 FF 15 ?? ??
            ?? ?? 8B 45 ?? 8B E5 5D C2 ?? ??
        }

        $dd_decrypt = {
            55 8B EC 83 EC ?? C7 45 ?? ?? ?? ?? ?? 83 7D ?? ?? 0F 84 22 01 00 00 83 7D ?? ?? 0F 84 18 01 00 00 83 7D ?? ?? 0F 84 0E
            01 00 00 83 7D ?? ?? 0F 84 04 01 00 00 83 7D ?? ?? 0F 84 FA 00 00 00 8B 45 ?? 50 E8 ?? ?? ?? ?? 89 45 ?? 8B 45 ?? 33 D2
            F7 75 ?? 0F AF 45 ?? 89 45 ?? 8B 4D ?? 89 4D ?? 8B 55 ?? 8B 02 03 45 ?? 89 45 ?? 8B 4D ?? 8B 11 03 55 ?? 52 8B 45 ?? 8B
            08 51 6A ?? E8 ?? ?? ?? ?? 8B 55 ?? 89 02 8B 45 ?? 83 38 ?? 0F 84 A7 00 00 00 8B 4D ?? 8B 11 8B 45 ?? 03 10 89 55 ?? 83
            7D ?? ?? 74 61 6A ?? 8B 4D ?? 51 8B 55 ?? 52 8B 45 ?? 50 E8 ?? ?? ?? ?? 8B 4D ?? 51 8B 55 ?? 52 E8 ?? ?? ?? ?? 8B 45 ??
            89 45 ?? 8D 4D ?? 51 8B 55 ?? 52 6A ?? 6A ?? 6A ?? 8B 45 ?? 50 FF 15 ?? ?? ?? ?? 85 C0 75 02 EB 1D 8B 4D ?? 03 4D ?? 89
            4D ?? 8B 55 ?? 2B 55 ?? 89 55 ?? 8B 45 ?? 03 45 ?? 89 45 ?? EB 99 83 7D ?? ?? 75 15 8B 4D ?? 89 4D ?? 8B 55 ?? 8B 45 ??
            2B 02 8B 4D ?? 89 01 EB 18 8B 55 ?? 8B 02 50 8B 4D ?? 8B 11 52 6A ?? E8 ?? ?? ?? ?? 8B 4D ?? 89 01 8B 45 ?? 8B E5 5D C2
            ?? ??
        }

        $dd_encrypt = {
            55 8B EC 83 EC ?? C7 45 ?? ?? ?? ?? ?? 83 7D ?? ?? 0F 84 89 01 00 00 83 7D ?? ?? 0F 84 7F 01 00 00 83 7D ?? ?? 0F 84 75
            01 00 00 83 7D ?? ?? 0F 84 6B 01 00 00 83 7D ?? ?? 0F 84 61 01 00 00 8B 45 ?? 50 E8 ?? ?? ?? ?? 89 45 ?? 8B 4D ?? 83 E9
            ?? 89 4D ?? 8B 55 ?? 89 55 ?? 6A ?? 8D 45 ?? 50 6A ?? 6A ?? 6A ?? 6A ?? 8B 4D ?? 51 FF 15 ?? ?? ?? ?? 85 C0 0F 84 26 01
            00 00 8B 55 ?? 3B 55 ?? 76 08 8B 45 ?? 89 45 ?? EB 06 8B 4D ?? 89 4D ?? 8B 55 ?? 89 55 ?? 8B 45 ?? 33 D2 F7 75 ?? 0F AF
            45 ?? 8B 4D ?? 8B 11 03 D0 03 55 ?? 89 55 ?? 8B 45 ?? 50 8B 4D ?? 8B 11 52 6A ?? E8 ?? ?? ?? ?? 8B 4D ?? 89 01 8B 55 ??
            83 3A ?? 0F 84 CF 00 00 00 8B 45 ?? 8B 08 8B 55 ?? 03 0A 89 4D ?? 83 7D ?? ?? 0F 84 84 00 00 00 8B 45 ?? 3B 45 ?? 73 08
            8B 4D ?? 89 4D ?? EB 06 8B 55 ?? 89 55 ?? 8B 45 ?? 89 45 ?? 6A ?? 8B 4D ?? 51 8B 55 ?? 52 8B 45 ?? 50 E8 ?? ?? ?? ?? 8B
            4D ?? 89 4D ?? 8B 55 ?? 52 8D 45 ?? 50 8B 4D ?? 51 6A ?? 6A ?? 6A ?? 8B 55 ?? 52 FF 15 ?? ?? ?? ?? 85 C0 75 02 EB 2D 8B
            45 ?? 50 8B 4D ?? 51 E8 ?? ?? ?? ?? 8B 55 ?? 03 55 ?? 89 55 ?? 8B 45 ?? 2B 45 ?? 89 45 ?? 8B 4D ?? 03 4D ?? 89 4D ?? E9
            72 FF FF FF 83 7D ?? ?? 75 16 8B 55 ?? 8B 45 ?? 2B 02 8B 4D ?? 89 01 C7 45 ?? ?? ?? ?? ?? EB 18 8B 55 ?? 8B 02 50 8B 4D
            ?? 8B 11 52 6A ?? E8 ?? ?? ?? ?? 8B 4D ?? 89 01 8B 45 ?? 8B E5 5D C2 ?? ??
        }

        $dd_provparam = {
            55 8B EC 83 EC ?? 83 7D ?? ?? 0F 84 94 00 00 00 C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 6A ?? 8D 45 ?? 50 6A ?? 6A ??
            8B 4D ?? 51 FF 15 ?? ?? ?? ?? 85 C0 74 3F 8B 55 ?? 83 C2 ?? 52 E8 ?? ?? ?? ?? 89 45 ?? 83 7D ?? ?? 74 2A 6A ?? 8D 45 ??
            50 8B 4D ?? 51 6A ?? 8B 55 ?? 52 FF 15 ?? ?? ?? ?? 85 C0 75 10 8B 45 ?? 50 E8 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 6A ?? 8B
            4D ?? 51 FF 15 ?? ?? ?? ?? 83 7D ?? ?? 74 1D 6A ?? 6A ?? 6A ?? 8B 55 ?? 52 8D 45 ?? 50 FF 15 ?? ?? ?? ?? 8B 4D ?? 51 E8
            ?? ?? ?? ?? 8B E5 5D C2 ?? ??
        }

        $dd_acquirecontext = {
            55 8B EC 83 EC ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 83 7D ?? ?? 74 0B 8B 45 ?? 0D ?? ?? ?? ?? 89 45 ?? C7 45 ??
            ?? ?? ?? ?? 83 7D ?? ?? 75 07 C7 45 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 03 45 ?? 50 6A ?? 6A ?? 6A ?? 8D 4D ?? 51 E8 ?? ?? ??
            ?? 8B 55 ?? 52 6A ?? 8B 45 ?? 50 8D 4D ?? 51 8D 55 ?? 52 FF 15 ?? ?? ?? ?? 85 C0 75 39 8B 45 ?? 83 C8 ?? 50 6A ?? 8B 4D
            ?? 51 8D 55 ?? 52 8D 45 ?? 50 FF 15 ?? ?? ?? ?? 85 C0 75 1A 6A ?? 6A ?? 6A ?? 8D 4D ?? 51 8D 55 ?? 52 FF 15 ?? ?? ?? ??
            85 C0 75 02 EB 0E 6A ?? FF 15 ?? ?? ?? ?? 83 7D ?? ?? 74 9D 8B 45 ?? 8B E5 5D C2 ?? ??
        }

        $dd_mrwhite = {
            55 8B EC 81 EC ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 83 7D ?? ?? 0F 84 64 01 00 00 E8 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 6A ?? 8D
            85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 74 12 83 3D ?? ?? ?? ?? ?? 74 09 83 3D ?? ?? ?? ?? ?? 75 05 E9 13
            01 00 00 6A ?? 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? 51 E8 ?? ?? ?? ?? 85 C0 75 05 E9 F0 00 00 00 8B 95
            ?? ?? ?? ?? 52 6A ?? 6A ?? 6A ?? 8B 45 ?? 50 8D 8D ?? ?? ?? ?? 51 8D 95 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74
            05 E9 C0 00 00 00 8D 85 ?? ?? ?? ?? 50 8D 8D ?? ?? ?? ?? 51 E8 ?? ?? ?? ?? 85 C0 74 09 83 BD ?? ?? ?? ?? ?? 73 05 E9 9B
            00 00 00 8B 95 ?? ?? ?? ?? 52 8B 85 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0
            75 02 EB 72 8B 8D ?? ?? ?? ?? 89 8D ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 8B 02 83 C0 ?? 3B 85 ?? ?? ?? ?? 76 02 EB 51 8B 8D ??
            ?? ?? ?? 83 39 ?? 74 3E 0F B7 95 ?? ?? ?? ?? 83 FA ?? 75 32 8B 85 ?? ?? ?? ?? 8B 08 51 8B 95 ?? ?? ?? ?? 83 C2 ?? 52 6A
            ?? 8D 85 ?? ?? ?? ?? 50 8B 0D ?? ?? ?? ?? 51 8B 15 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 89 45 ?? 33 C0 0F 85 CD FE FF FF 8D 8D
            ?? ?? ?? ?? 51 E8 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 8B 45 ?? 8B E5 5D C2 ?? ??
        }

    condition:
        uint16(0) == 0x5A4D and ($dd_ep at pe.entry_point) and $dd_hash and $dd_getkey and $dd_destroykey and $dd_importkey and $dd_decrypt and $dd_encrypt
                               and $dd_provparam and $dd_acquirecontext and $dd_mrwhite
}
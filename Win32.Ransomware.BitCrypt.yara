import "pe"

rule Win32_Ransomware_BitCrypt : tc_detection malicious
{
    meta:
 		score = 7

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "BITCRYPT"
        description         = "Yara rule that detects BitCrypt ransomware."

        tc_detection_type   = "Ransomware"
        tc_detection_name   = "BitCrypt"
        tc_detection_factor = 5

    strings:
        $bc_bcdedit = {
            55 8B EC 6A ?? 53 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 B2 ?? A1 ?? ?? ??
            ?? E8 ?? ?? ?? ?? 8B D8 BA ?? ?? ?? ?? 8B C3 E8 ?? ?? ?? ?? 8D 45 ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 8B C3
            E8 ?? ?? ?? ?? 8B C3 E8 ?? ?? ?? ?? B2 ?? A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B D8 BA ?? ?? ?? ?? 8B C3 E8 ?? ?? ?? ?? 8D 45
            ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 8B C3 E8 ?? ?? ?? ?? 8B C3 E8 ?? ?? ?? ?? 33 C0 5A 59 59 64 89 10 68 ??
            ?? ?? ?? 6A ?? 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? 6A ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A ?? 6A ??
            68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? 6A ?? E8 ?? ?? ?? ?? C3
        }

        $bc_enum_drives_a_z = {
            55 8B EC 81 C4 ?? ?? ?? ?? 53 56 33 D2 89 95 ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 8B F0 33 C0 55 68 ?? ?? ??
            ?? 64 FF 30 64 89 20 B2 ?? A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 06 B3 ?? 8D 85 ?? ?? ?? ?? 8B D3 E8 ?? ?? ?? ?? 8D 85 ?? ??
            ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 95 ?? ?? ?? ??
            8D 45 ?? B1 ?? E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 8B D3 E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B
            85 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 E8 ?? 75 1B 8D 85 ?? ?? ?? ?? 8D 55 ?? E8 ?? ?? ?? ?? 8B 95 ?? ?? ??
            ?? 8B 06 8B 08 FF 51 ?? 43 80 FB ?? 0F 85 65 FF FF FF 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? BA ?? ??
            ?? ?? E8 ?? ?? ?? ?? C3
        }

        $bc_do_extensions_1 = {
            55 8B EC 81 C4 ?? ?? ?? ?? 53 56 57 33 DB 89 9D ?? ?? ?? ?? 89 9D ?? ?? ?? ?? 89 9D ?? ?? ?? ?? 89 9D ?? ?? ?? ?? 89 9D 
            ?? ?? ?? ?? 89 9D ?? ?? ?? ?? 89 4D ?? 89 55 ?? 89 45 ?? 8B 7D ?? 8B 5D ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? 
            ?? 8B 45 ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8D 85 ?? 
            ?? ?? ?? 8B 4D ?? 8B 55 ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? 84 C0 0F 85 81 01 00 00 E8 ?? ?? ?? ?? BA ?? 
            ?? ?? ?? 33 C0 E8 ?? ?? ?? ?? 8B F0 8B C3 8B 14 B5 ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 28 A0 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 
            50 8B 03 33 C9 BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 8B C3 E8 ?? ?? ?? ?? 8B 13 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 
            85 C0 75 C8 EB 28 A0 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 50 8B 03 33 C9 BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 8B 
            C3 E8 ?? ?? ?? ?? 8B 13 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 75 C8 FF 75 ?? 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 68 ?? ?? ?? 
            ?? 8D 95 ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF B5 ?? ?? ?? ?? 89 B5 ?? ?? ?? ?? DB 85 ?? ?? ?? ?? 83 C4 ?? DB 3C
        }

        $bc_do_extensions_2 = { 
            24 9B 8D 95 ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF B5 ?? ?? ?? ?? 8B C7 BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 85 ?? ?? 
            ?? ?? 8B 4D ?? 8B 55 ?? E8 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? E8 ?? ?? ?? 
            ?? E8 ?? ?? ?? ?? 8B 13 8D 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 17 8D 85 ?? ?? ?? ?? E8 ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 85 
            ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? B3 ?? EB 02 33 DB 33 C0 5A 59 59 64 89 10 EB 0C E9 ?? ?? ?? ?? 33 DB E8 ?? ?? 
            ?? ?? 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? 
            ?? ?? 8D 45 ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? C3 E9 ?? ?? ?? ?? EB D0 8B C3 5F 5E 5B 8B E5 5D C2 
        }

        $bc_do_files_1 = {
            55 8B EC 81 C4 ?? ?? ?? ?? 53 56 57 33 C9 89 8D ?? ?? ?? ?? 89 8D ?? ?? ?? ?? 89 8D ?? ?? ?? ?? 89 4D ?? 89 55 ?? 8B F0
            8D 85 ?? ?? ?? ?? 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 B3 ?? 8B 06 E8 ?? ?? ?? ??
            89 45 ?? 8B 16 8D 85 ?? ?? ?? ?? 8B 4D ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ??
            ?? 8B F8 85 FF 0F 85 91 00 00 00 F6 85 ?? ?? ?? ?? ?? 75 73 56 8D B5 ?? ?? ?? ?? 8D BD ?? ?? ?? ?? B9 ?? ?? ?? ?? F3 A5
            5E 8B 85 ?? ?? ?? ?? 89 45 ?? 8B 85 ?? ?? ?? ?? 89 45 ?? 8D 45 ?? 33 D2 E8 ?? ?? ?? ?? 83 C4 ?? DD 1C 24 9B 8D 45 ?? E8
            ?? ?? ?? ?? FF 75 ?? 68 ?? ?? ?? ?? FF 36 FF B5 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 95 ?? ??
            ?? ?? 8B 45 ?? 8B 40 ?? 8B 00 8B 08 FF 51 ?? 8D 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F8 85 FF 0F 84 6F FF FF FF 8D 85 ?? ??
            ?? ?? E8 ?? ?? ?? ?? 84 DB 0F 84 B7 00 00 00 8B 16 8D 85 ?? ?? ?? ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 8D
        }

        $bc_do_files_2 = {
            8D ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F8 85 FF 75 7E F6 85 ?? ?? ?? ?? ?? 74 64 8B 85 ?? ?? ?? ?? BA ?? ?? ??
            ?? E8 ?? ?? ?? ?? 74 52 8B 85 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 74 40 FF 36 FF B5 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8B
            C6 BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 ?? 50 8B C6 8B 55 ?? E8 57 FE FF FF 59 84 C0 75 04 33 DB EB 21 8B 55 ?? 42 8B C6
            B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F8 85 FF 74 82 8D 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0
            5A 59 59 64 89 10 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 8B 15 ?? ?? ?? ?? E8
            ?? ?? ?? ?? 8D 45 ?? E8 ?? ?? ?? ?? C3
        }

        $bc_main_1 = {
            55 8B EC B9 ?? ?? ?? ?? 6A ?? 6A ?? 49 75 F9 53 56 57 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64
            89 20 33 C0 A3 ?? ?? ?? ?? B2 ?? A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 55 ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 55 ?? B8 ?? ??
            ?? ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 55 ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 55 ?? B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? E8 ??
            ?? ?? ?? B8 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? BA ??
            ?? ?? ?? E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? BA ??
            ?? ?? ?? A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? C6 05 ?? ?? ?? ?? ?? 8D 45 ?? E8 ?? ?? ?? ?? 8B 55 ?? B8 ?? ?? ??
            ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8D 45 ?? 8B 0D ?? ?? ?? ??
            8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 84 C0 75 7A 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 8B
        }

        $bc_main_2 = {
            15 ?? ?? ?? ?? A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B D8 8D 45 ?? 8B 0D ?? ?? ?? ?? 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 ??
            E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 55 ?? 33 C0 E8 ?? ?? ?? ?? 8B 45 ?? 50 8D 45 ?? 8B 0D ?? ?? ?? ?? 8B 15
            ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 55 ?? 58 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 11 BA ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ??
            8B D8 B2 ?? A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 80 FB ?? 0F 85 ?? ?? ?? ?? C6 05 ?? ?? ?? ?? ?? B2 ?? A1 ?? ??
            ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 80 3D ?? ?? ?? ?? ?? 75 ED A1 ?? ?? ?? ?? 8B 10 FF 52 ?? 83 F8 ?? 0F
            8E ?? ?? ?? ?? A1 ?? ?? ?? ?? 8B 10 FF 52 ?? 99 F7 3D ?? ?? ?? ?? A3 ?? ?? ?? ?? A1 ?? ?? ?? ?? 8B 10 FF 52 ?? 99 F7 3D
            ?? ?? ?? ?? 89 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 48 85 C0 7C ?? 40 89 45 ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ??
        }

        $bc_main2 = {
            E8 ?? ?? ?? ?? 6A ?? 6A ?? 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 8D 45 ??
            BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 6A ?? 6A ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 80 3D
            ?? ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8D 45 ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? C3
        }

    condition:
        uint16(0) == 0x5A4D and ($bc_main_1 at pe.entry_point) and $bc_main_2 and $bc_main2 and $bc_bcdedit and $bc_enum_drives_a_z and
        $bc_do_extensions_1 and $bc_do_extensions_2 and $bc_do_files_1 and $bc_do_files_2
}
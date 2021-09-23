rule Win32_Ransomware_DogeCrypt : tc_detection malicious
{
    meta:
 		score = 7

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "DOGECRYPT"
        description         = "Yara rule that detects DogeCrypt ransomware."

        tc_detection_type   = "Ransomware"
        tc_detection_name   = "DogeCrypt"
        tc_detection_factor = 5

    strings:

        $encrypt_files_DogeCrypt_p1 = {
            50 E8 ?? ?? ?? ?? 8D 45 ?? C6 45 ?? ?? 50 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? C6 45 ?? 
            ?? BA ?? ?? ?? ?? 83 3D ?? ?? ?? ?? ?? 8B B5 ?? ?? ?? ?? 0F 43 15 ?? ?? ?? ?? 8B 85 
            ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 2B C6 89 B5 ?? ?? ?? ?? 3B C8 77 ?? 83 BD ?? ?? ?? ?? 
            ?? 8D 3C 31 8D 04 09 89 BD ?? ?? ?? ?? 50 8B 85 ?? ?? ?? ?? 8D B5 ?? ?? ?? ?? 0F 43 
            B5 ?? ?? ?? ?? 52 8D 04 46 50 E8 ?? ?? ?? ?? 83 C4 ?? 33 C0 66 89 04 7E EB ?? 51 52 
            C6 85 ?? ?? ?? ?? ?? FF B5 ?? ?? ?? ?? 51 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 7D ?? 
            ?? 8D 45 ?? 8B 35 ?? ?? ?? ?? 0F 43 45 ?? 6A ?? 68 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 68 
            ?? ?? ?? ?? 50 FF D6 8B F8 83 FF ?? 74 ?? 83 BD ?? ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 6A 
            ?? 0F 43 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 68 ?? ?? ?? ?? 50 FF D6 8B 
            F0 83 FE ?? 0F 85 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 83 FA ?? 72 ?? 8B 
            8D ?? ?? ?? ?? 8D 14 55 ?? ?? ?? ?? 8B C1 81 FA ?? ?? ?? ?? 72 ?? 8B 49 ?? 83 C2 ?? 
            2B C1 83 C0 ?? 83 F8 ?? 0F 87 ?? ?? ?? ?? 52 51 E8 ?? ?? ?? ?? 83 C4 ?? 8B 95 ?? ?? 
            ?? ?? 33 C0 C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 66 89 85 ?? 
            ?? ?? ?? 83 FA ?? 72 ?? 8B 8D ?? ?? ?? ?? 8D 14 55 ?? ?? ?? ?? 8B C1 81 FA ?? ?? ?? 
            ?? 72 ?? 8B 49 ?? 83 C2 ?? 2B C1 83 C0 ?? 83 F8 ?? 0F 87 ?? ?? ?? ?? 52 51 E8 ?? ?? 
            ?? ?? 83 C4 ?? 8B 95 ?? ?? ?? ?? 83 FA ?? 72 ?? 8B 8D ?? ?? ?? ?? 8D 14 55 ?? ?? ?? 
            ?? 8B C1 81 FA ?? ?? ?? ?? 72 ?? 8B 49 ?? 83 C2 ?? 2B C1 83 C0 ?? 83 F8 ?? 0F 87 ?? 
            ?? ?? ?? 52 51 E8 ?? ?? ?? ?? 83 C4 ?? 8B 95 ?? ?? ?? ?? 83 FA ?? 72 ?? 8B 8D ?? ?? 
            ?? ?? 8D 14 55 ?? ?? ?? ?? 8B C1 81 FA ?? ?? ?? ?? 72 ?? 8B 49 ?? 83 C2 ?? 2B C1 83
        }

        $encrypt_files_DogeCrypt_p2 = {
            C0 ?? 83 F8 ?? 0F 87 ?? ?? ?? ?? 52 51 E8 ?? ?? ?? ?? 83 C4 ?? 8B 95 ?? ?? ?? ?? 83 
            FA ?? 0F 82 ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? 8D 14 55 ?? ?? ?? ?? 8B C1 81 FA ?? ?? ?? 
            ?? 0F 82 ?? ?? ?? ?? 8B 49 ?? 83 C2 ?? 2B C1 83 C0 ?? 83 F8 ?? 0F 87 ?? ?? ?? ?? E9 
            ?? ?? ?? ?? 90 6A ?? 8D 85 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 57 FF 
            15 ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? BA ?? ?? ?? ?? 81 F9 ?? ?? ?? ?? 0F 42 DA 85 C0 74 
            ?? 85 C9 74 ?? 51 8D 85 ?? ?? ?? ?? 89 8D ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 50 6A ?? 
            53 6A ?? FF 35 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 6A ?? 8D 85 ?? ?? ?? ?? 50 FF B5 ?? ?? 
            ?? ?? 8D 85 ?? ?? ?? ?? 50 56 FF 15 ?? ?? ?? ?? EB ?? 56 8B 35 ?? ?? ?? ?? FF D6 57 
            FF D6 83 7D ?? ?? 8D 45 ?? 0F 43 45 ?? 50 FF 15 ?? ?? ?? ?? E9 ?? ?? ?? ?? 52 51 E8 
            ?? ?? ?? ?? 83 C4 ?? 8B 55 ?? 33 C0 66 89 85 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? 
            ?? 89 85 ?? ?? ?? ?? 83 FA ?? 72 ?? 8B 4D ?? 8D 14 55 ?? ?? ?? ?? 8B C1 81 FA ?? ?? 
            ?? ?? 72 ?? 8B 49 ?? 83 C2 ?? 2B C1 83 C0 ?? 83 F8 ?? 77 ?? 52 51 E8 ?? ?? ?? ?? 83 
            C4 ?? 8B 4D ?? 64 89 0D ?? ?? ?? ?? 59 5F 5E 5B 8B 4D ?? 33 CD E8 ?? ?? ?? ?? 8B E5 
            5D C3
        }

        $find_files_DogeCrypt = {
            8B FF 55 8B EC 51 8B 4D ?? 8D 51 ?? 8A 01 41 84 C0 75 ?? 57 8B 7D ?? 2B CA 8B C7 41 
            F7 D0 89 4D ?? 3B C8 76 ?? 6A ?? 58 EB ?? 53 56 8D 5F ?? 03 D9 6A ?? 53 E8 ?? ?? ?? 
            ?? 8B F0 59 59 85 FF 74 ?? 57 FF 75 ?? 53 56 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 75 ?? FF 
            75 ?? 2B DF 8D 04 3E FF 75 ?? 53 50 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 75 ?? 8B 5D ?? 8B 
            CB E8 ?? ?? ?? ?? 33 FF 89 45 ?? 85 C0 74 ?? 56 E8 ?? ?? ?? ?? 8B 75 ?? 59 EB ?? 8B 
            43 ?? 89 30 8B F7 83 43 ?? ?? 57 E8 ?? ?? ?? ?? 59 8B C6 5E 5B 5F 8B E5 5D C3 33 FF 
            57 57 57 57 57 E8 ?? ?? ?? ?? CC 8B FF 55 8B EC 81 EC ?? ?? ?? ?? A1 ?? ?? ?? ?? 33 
            C5 89 45 ?? 8B 4D ?? 53 8B 5D ?? 57 8B 7D ?? 89 9D ?? ?? ?? ?? EB ?? 8A 01 3C ?? 74 
            ?? 3C ?? 74 ?? 3C ?? 74 ?? 51 57 E8 ?? ?? ?? ?? 59 59 8B C8 3B CF 75 ?? 8A 11 80 FA 
            ?? 75 ?? 8D 47 ?? 3B C8 74 ?? 53 33 DB 53 53 57 E8 ?? ?? ?? ?? 83 C4 ?? EB ?? 33 DB 
            80 FA ?? 74 ?? 80 FA ?? 74 ?? 8A C3 80 FA ?? 75 ?? B0 ?? 0F B6 C0 2B CF 41 F7 D8 56 
            1B C0 23 C1 68 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 53 50 E8 ?? ?? ?? ?? 
            83 C4 ?? 8D 85 ?? ?? ?? ?? 53 53 53 50 53 57 FF 15 ?? ?? ?? ?? 8B F0 8B 85 ?? ?? ?? 
            ?? 83 FE ?? 75 ?? 50 53 53 57 E8 ?? ?? ?? ?? 83 C4 ?? 8B D8 83 FE ?? 74 ?? 56 FF 15 
            ?? ?? ?? ?? 8B C3 5E 8B 4D ?? 5F 33 CD 5B E8 ?? ?? ?? ?? 8B E5 5D C3 8B 48 ?? 2B 08 
            C1 F9 ?? 89 8D ?? ?? ?? ?? 80 BD ?? ?? ?? ?? ?? 75 ?? 8A 8D ?? ?? ?? ?? 84 C9 74 ?? 
            80 F9 ?? 75 ?? 38 9D ?? ?? ?? ?? 74 ?? 50 FF B5 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 57 50 
            E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 75 ?? 8D 85 ?? ?? ?? ?? 50 56 FF 15 ?? ?? ?? ?? 85 C0 
            8B 85 ?? ?? ?? ?? 75 ?? 8B 10 8B 40 ?? 8B 8D ?? ?? ?? ?? 2B C2 C1 F8 ?? 3B C8 0F 84 
            ?? ?? ?? ?? 68 ?? ?? ?? ?? 2B C1 6A ?? 50 8D 04 8A 50 E8 ?? ?? ?? ?? 83 C4 ?? E9 
        }

        $decrypt_DesucryptKeyContainer_DogeCrypt = {
            68 ?? ?? ?? ?? 8D 4D ?? C7 45 ?? ?? ?? ?? ?? 66 89 45 ?? E8 ?? ?? ?? ?? C7 45 ?? ?? 
            ?? ?? ?? 8D 55 ?? 83 7D ?? ?? 8B 5D ?? 8B 35 ?? ?? ?? ?? 0F 43 D3 A1 ?? ?? ?? ?? 8B 
            4D ?? 2B C6 89 75 ?? 3B C8 77 ?? 83 3D ?? ?? ?? ?? ?? 8D 3C 31 8D 04 09 89 3D ?? ?? 
            ?? ?? 50 8B 45 ?? BE ?? ?? ?? ?? 0F 43 35 ?? ?? ?? ?? 52 8D 04 46 50 E8 ?? ?? ?? ?? 
            83 C4 ?? 33 C0 66 89 04 7E EB ?? 51 52 C6 45 ?? ?? FF 75 ?? 51 B9 ?? ?? ?? ?? E8 ?? 
            ?? ?? ?? 8B 5D ?? C7 45 ?? ?? ?? ?? ?? 8B 45 ?? 83 F8 ?? 72 ?? 8D 0C 45 ?? ?? ?? ?? 
            8B C3 81 F9 ?? ?? ?? ?? 72 ?? 8B 5B ?? 83 C1 ?? 2B C3 83 C0 ?? 83 F8 ?? 0F 87 ?? ?? 
            ?? ?? 51 53 E8 ?? ?? ?? ?? 83 C4 ?? 83 3D ?? ?? ?? ?? ?? B8 ?? ?? ?? ?? 6A ?? 0F 43 
            05 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 68 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 
            8B F0 83 FE ?? 0F 84 ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? 8D 45 ?? 6A ?? 50 6A ?? 68 ?? ?? 
            ?? ?? 56 FF D3 83 F8 ?? 0F 85 ?? ?? ?? ?? BA ?? ?? ?? ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? 
            ?? 50 E8 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 8B F8 8D 45 ?? 6A ?? 
            50 C6 07 ?? FF 35 ?? ?? ?? ?? 57 56 FF D3 83 F8 ?? 75 ?? BA ?? ?? ?? ?? B9 ?? ?? ?? 
            ?? E8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 68 ?? ?? ?? ?? 6A ?? 6A ?? FF 35 ?? ?? 
            ?? ?? 57 FF 35 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 83 F8 ?? 75 ?? BA ?? ?? ?? ?? B9 ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 57 E8 ?? ?? ?? ?? 83 C4 ?? B8 ?? ?? 
            ?? ?? EB ?? 33 C0 8B 4D ?? 64 89 0D ?? ?? ?? ?? 59 5F 5E 5B 8B 4D ?? 33 CD E8 ?? ?? 
            ?? ?? 8B E5 5D C3 E8 ?? ?? ?? ?? E8
        }

    condition:
        uint16(0) == 0x5A4D and
        (
            $decrypt_DesucryptKeyContainer_DogeCrypt
        ) and
        (
            $find_files_DogeCrypt
        ) and
        (
            all of ($encrypt_files_DogeCrypt_p*)
        )
}
rule Win32_Ransomware_AnteFrigus : tc_detection malicious
{
    meta:
 		score = 7

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "ANTEFRIGUS"
        description         = "Yara rule that detects AnteFrigus ransomware."

        tc_detection_type   = "Ransomware"
        tc_detection_name   = "AnteFrigus"
        tc_detection_factor = 5

    strings:

        $find_files_p1 = {                        
            68 ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 ?? 8D 4D ?? 68 ?? ?? ?? ?? 8B D0 
            89 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 83 65 ?? ?? 8D 8D ?? ?? ?? ?? 83 7D ?? ?? 8D 45 
            ?? 51 0F 43 45 ?? 50 FF 15 ?? ?? ?? ?? 8B D8 83 FB ?? 0F 84 ?? ?? ?? ?? 33 C0 8D 7D 
            ?? AB AB AB 33 C0 89 45 ?? 89 45 ?? 89 45 ?? C6 45 ?? ?? F6 85 ?? ?? ?? ?? ?? 74 ?? 
            68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 68 ?? 
            ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 8D 85 ?? ?? 
            ?? ?? 50 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F0 8B 95 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 
            68 ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 59 8B D0 C6 45 ?? ?? 8B 4A ?? 8B 7A ?? 2B 
            CF 39 4E ?? 76 ?? 8B 46 ?? 2B 46 ?? 3B C7 72 ?? 83 7A ?? ?? 72 ?? 8B 12 57 52 51 8B 
            CE E8 ?? ?? ?? ?? EB ?? 56 8B CA E8 ?? ?? ?? ?? 50 8D 4D ?? E8 ?? ?? ?? ?? C6 85 ?? 
            ?? ?? ?? ?? 8D 45 ?? FF B5 ?? ?? ?? ?? 8D 4D ?? 50 E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? 
            ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 
            83 7D ?? ?? 8D 4D ?? 8B 45 ?? 0F 43 4D ?? 8D 04 41 8D 4D ?? 0F 43 4D ?? 51 50 51 8D 
            4D ?? E8 ?? ?? ?? ?? 8D 45 ?? C6 45 ?? ?? 83 65 ?? ?? 8D 4D ?? 83 65 ?? ?? 50 E8 ?? 
            ?? ?? ?? C6 45 ?? ?? 8D 75 ?? 83 7D ?? ?? 8B 55 ?? 0F 43 75 ?? 85 D2 74 ?? 83 C9 ?? 
            8D 42 ?? 3B C1 0F 42 C8 03 CE EB ?? 3B CE 74 ?? 49 80 39 ?? 75 ?? 2B CE EB ?? 83 C9 
            ?? 83 F9 ?? 0F 84 ?? ?? ?? ?? 83 65 ?? ?? 8D 71 ?? C7 45 ?? ?? ?? ?? ?? C6 45
        }

        $find_files_p2 = {                        
            3B D6 0F 82 ?? ?? ?? ?? 2B D6 8D 45 ?? 83 C9 ?? 83 FA ?? 0F 42 CA 83 7D ?? ?? 51 0F 
            43 45 ?? 8D 4D ?? 03 C6 50 E8 ?? ?? ?? ?? 83 EC ?? C6 45 ?? ?? 8B CC 8D 45 ?? 50 83 
            61 ?? ?? 83 61 ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 83 F8 ?? 0F 85 ?? ?? ?? 
            ?? 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 6A ?? 50 E8 ?? ?? ?? ?? 59 59 8D 8D ?? ?? ?? ?? 
            E8 ?? ?? ?? ?? 51 51 8D 45 ?? C6 45 ?? ?? 50 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A ?? 
            6A ?? 6A ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 8D 8D ?? ?? ?? ?? 
            E8 ?? ?? ?? ?? BF ?? ?? ?? ?? 8B 70 ?? 03 30 3B F7 7D ?? 8D 4D ?? E8 ?? ?? ?? ?? 8D 
            8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 3B F7 7D ?? 8D 4D ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 
            E8 ?? ?? ?? ?? 8D 4D ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? 
            ?? ?? F6 85 ?? ?? ?? ?? ?? 74 ?? 8B 45 ?? 8D 4D ?? 51 3B 45 ?? 74 ?? 8B C8 E8 ?? ?? 
            ?? ?? 83 45 ?? ?? EB ?? 50 8D 4D ?? E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8D 4D ?? 
            C6 45 ?? ?? E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 53 FF 15 ?? ?? ?? ?? 85 C0 0F 85 ?? 
            ?? ?? ?? 53 FF 15 ?? ?? ?? ?? 8B 7D ?? 8B 75 ?? 6A ?? 5B 3B F7 74 ?? 56 E8 ?? ?? ?? 
            ?? 03 F3 59 3B F7 75 ?? 8B 7D ?? 8B 75 ?? 85 F6 74 ?? 3B F7 74 ?? 8B CE E8 ?? ?? ?? 
            ?? 03 F3 3B F7 75 ?? 8B 75 ?? 8B 45 ?? 2B C6 99 F7 FB 6B C0 ?? 50 56 E8 ?? ?? ?? ?? 
            59 59 8D 4D ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? C3 E8
        }

        $remote_connection_p1 = {                        
            55 8D AC 24 ?? ?? ?? ?? 81 EC ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 
            81 EC ?? ?? ?? ?? A1 ?? ?? ?? ?? 33 C5 89 85 ?? ?? ?? ?? 53 56 57 50 8D 45 ?? 64 A3 
            ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 50 BA ?? ?? ?? ?? 8D 8D ?? ?? ?? 
            ?? E8 ?? ?? ?? ?? C6 45 ?? ?? C7 04 24 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? 
            ?? ?? 83 C4 ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? 51 8B C8 E8 ?? ?? ?? ?? 50 8D 4D ?? E8 
            ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 45 ?? C6 45 ?? ?? 50 8D 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 
            ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? 51 8B C8 E8 ?? ?? ?? ?? 50 8D 4D ?? E8 ?? ?? ?? ?? 
            68 ?? ?? ?? ?? 8D 45 ?? C6 45 ?? ?? 50 8D 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 8D ?? 
            ?? ?? ?? C6 45 ?? ?? 51 8B C8 E8 ?? ?? ?? ?? 50 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 
            4D ?? E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? 
            ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? C6 45 ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? 
            ?? 83 BD ?? ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 8B BD ?? ?? ?? ?? 8D B5 ?? ?? ?? ?? 0F 43 
            8D ?? ?? ?? ?? 03 F9 C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 8D 8D ?? ?? 
            ?? ?? 0F 43 B5 ?? ?? ?? ?? 33 C0 66 89 85 ?? ?? ?? ?? 33 DB 8B C7 89 9D
        }

        $remote_connection_p2 = {                        
            2B C6 50 E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 89 45 ?? C6 45 ?? ?? EB ?? 66 0F BE 06 8D 
            8D ?? ?? ?? ?? 0F B7 C0 50 E8 ?? ?? ?? ?? 46 3B F7 75 ?? 53 53 53 53 68 ?? ?? ?? ?? 
            C6 45 ?? ?? 88 5D ?? FF 15 ?? ?? ?? ?? 8B D8 85 DB 0F 84 ?? ?? ?? ?? 6A ?? 33 C0 50 
            6A ?? 50 50 6A ?? 68 ?? ?? ?? ?? 53 FF 15 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? 89 45 ?? 85 
            C0 74 ?? 6A ?? 68 ?? ?? ?? ?? 33 C9 51 51 51 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 FF 15 
            ?? ?? ?? ?? 8B F0 85 F6 74 ?? 33 C0 50 50 50 50 56 FF 15 ?? ?? ?? ?? 85 C0 74 ?? 68 
            ?? ?? ?? ?? 8D 45 ?? 6A ?? 50 E8 ?? ?? ?? ?? 51 8D 4D ?? E8 ?? ?? ?? ?? C6 45 ?? ?? 
            83 7D ?? ?? 0F 85 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 56 FF D7 FF 75 ?? FF D7 53 FF 
            D7 80 7D ?? ?? 74 ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? 
            ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? 
            ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 
            8B 4D ?? 64 89 0D ?? ?? ?? ?? 59 5F 5E 5B 8B 8D ?? ?? ?? ?? 33 CD E8 ?? ?? ?? ?? 81 
            C5 ?? ?? ?? ?? C9 C3 8B 85 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 3D ?? ?? ?? ?? 73 ?? 
            8D 95 ?? ?? ?? ?? C6 84 05 ?? ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? C6 45 ?? ?? 8D 85 
            ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 56 FF 15 ?? ?? ?? ?? 85 C0 75 ?? 
            E9 ?? ?? ?? ?? E8
        }

        $encrypt_files_p1 = {                        
            66 39 03 0F 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 59 59 33 C0 8D 8D ?? 
            ?? ?? ?? 68 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? C6 45 ?? 
            ?? 8D 95 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? B9 ?? ?? ?? ?? FF B5 ?? ?? ?? ?? 0F 43 95 
            ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 59 59 8D 85 ?? ?? ?? ?? C7 85 ?? ?? ?? 
            ?? ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 8D 8D 
            ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A ?? 5B C6 45 ?? ?? 8D 8D ?? ?? ?? ?? 39 9D ?? ?? ?? ?? 
            8B 85 ?? ?? ?? ?? 0F 43 8D ?? ?? ?? ?? 8D 04 41 8D 8D ?? ?? ?? ?? 0F 43 8D ?? ?? ?? 
            ?? 51 50 51 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 89 
            85 ?? ?? ?? ?? 88 85 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? C6 45 ?? ?? 50 BA ?? ?? ?? ?? 8D 
            4D ?? E8 ?? ?? ?? ?? C6 45 ?? ?? C7 04 24 ?? ?? ?? ?? 50 8D 45 ?? 50 E8 ?? ?? ?? ?? 
            83 C4 ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? 51 8B C8 E8 ?? ?? ?? ?? 50 8D 4D ?? E8 ?? ?? 
            ?? ?? C6 45 ?? ?? 68 ?? ?? ?? ?? 8D 45 ?? 50 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8D
        }

        $encrypt_files_p2 = {                        
            8D ?? ?? ?? ?? 83 C4 ?? 3B C8 74 ?? 33 C9 88 4D ?? 8D 8D ?? ?? ?? ?? FF 75 ?? 50 E8 
            ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? 
            ?? ?? ?? 8D 4D ?? C6 45 ?? ?? E8 ?? ?? ?? ?? BE ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 56 E8 
            ?? ?? ?? ?? 56 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 6A ?? 33 C0 59 89 85 ?? 
            ?? ?? ?? 89 8D ?? ?? ?? ?? 88 85 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 89 8D ?? ?? ?? ?? 88 
            85 ?? ?? ?? ?? BF ?? ?? ?? ?? C6 45 ?? ?? 57 50 8D 45 ?? 50 E8 ?? ?? ?? ?? 59 8D 4D 
            ?? E8 ?? ?? ?? ?? 33 C0 C6 45 ?? ?? 57 50 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 59 8D 
            8D ?? ?? ?? ?? E8 ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 6A ?? 59 99 F7 F9 8D 4D ?? 
            52 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A ?? 59 99 F7 F9 8D 8D ?? ?? ?? ?? 52 E8 ?? ?? ?? 
            ?? 83 EB ?? 75 ?? 8D 95 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 8D 8D 
            ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 8D 95 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 
            E8 ?? ?? ?? ?? 57 8D 85 ?? ?? ?? ?? C6 45 ?? ?? 53 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 8D 
            ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 51 68 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? 
            ?? ?? ?? 39 9D ?? ?? ?? ?? 74 ?? 83 BD ?? ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? FF B5 ?? ?? 
            ?? ?? 0F 43 95 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 8D 8D ?? ?? ?? ?? E8 
            ?? ?? ?? ?? BE ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 56 8D 4D ?? E8 ?? ?? ?? ?? 59 8D 8D ?? 
            ?? ?? ?? C6 45 ?? ?? 51 8B C8 E8 ?? ?? ?? ?? 50 8D 4D ?? E8 ?? ?? ?? ?? 56 8D 45 ?? 
            C6 45 ?? ?? 50 8D 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? 51
        }

        $encrypt_files_p3 = {                        
            8B C8 E8 ?? ?? ?? ?? 50 8D 4D ?? E8 ?? ?? ?? ?? 56 8D 45 ?? C6 45 ?? ?? 50 8D 85 ?? 
            ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? 51 8B C8 E8 ?? ?? 
            ?? ?? 50 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 4D ?? 
            E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8D 4D ?? C6 45 ?? ?? 
            E8 ?? ?? ?? ?? 8B F3 39 B5 ?? ?? ?? ?? 76 ?? 83 BD ?? ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 
            8D 8D ?? ?? ?? ?? 0F 43 85 ?? ?? ?? ?? 8A 04 30 04 ?? 88 45 ?? FF 75 ?? E8 ?? ?? ?? 
            ?? 46 3B B5 ?? ?? ?? ?? 72 ?? 8B F3 39 B5 ?? ?? ?? ?? 76 ?? 83 BD ?? ?? ?? ?? ?? 8D 
            85 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 0F 43 85 ?? ?? ?? ?? 8A 04 30 2C ?? 88 45 ?? FF 75 
            ?? E8 ?? ?? ?? ?? 46 3B B5 ?? ?? ?? ?? 72 ?? 8D 85 ?? ?? ?? ?? BA ?? ?? ?? ?? 50 8D 
            8D ?? ?? ?? ?? E8 ?? ?? ?? ?? C6 45 ?? ?? C7 04 24 ?? ?? ?? ?? 50 8D 85 ?? ?? ?? ?? 
            50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 6A ?? 68 ?? 
            ?? ?? ?? FF 15 ?? ?? ?? ?? 57 8D 85 ?? ?? ?? ?? 53 50 E8 ?? ?? ?? ?? 59 59 8D 8D ?? 
            ?? ?? ?? E8 ?? ?? ?? ?? C6 45 ?? ?? 8D 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 51 0F 43
        }

        $encrypt_files_p4 = {                        
            85 ?? ?? ?? ?? 51 50 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? BE ?? ?? 
            ?? ?? 0F 84 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? BA ?? ?? ?? ?? 50 8D 8D ?? ?? ?? ?? E8 ?? 
            ?? ?? ?? 56 50 8D 85 ?? ?? ?? ?? C6 45 ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 8D ?? ?? 
            ?? ?? C6 45 ?? ?? 51 8B C8 E8 ?? ?? ?? ?? 50 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? 
            ?? ?? ?? 8D 85 ?? ?? ?? ?? C6 45 ?? ?? 50 8D 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 8D 
            ?? ?? ?? ?? C6 45 ?? ?? 51 8B C8 E8 ?? ?? ?? ?? 50 8D 4D ?? E8 ?? ?? ?? ?? 68 ?? ?? 
            ?? ?? 8D 45 ?? C6 45 ?? ?? 50 8D 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 8D ?? ?? ?? ?? 
            C6 45 ?? ?? 51 8B C8 E8 ?? ?? ?? ?? 50 8D 4D ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 45 
            ?? C6 45 ?? ?? 50 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8B D0 C6 45 ?? ?? 8D 
            8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? 
            ?? 8D 4D ?? E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8D 8D ?? 
            ?? ?? ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 45 ?? 
            ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 
            59 59 68 ?? ?? ?? ?? 51 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 51 8D 8D ?? 
            ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 51 8D 8D ?? ?? ?? ?? C6 45 ?? ?? 
            E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 51 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 68 ?? 
            ?? ?? ?? 51 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 51 8D 8D ?? 
            ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 8D 
            8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 
            ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 8D
        }

        $encrypt_files_p5 = {                        
            85 ?? ?? ?? ?? 53 50 E8 ?? ?? ?? ?? 59 59 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? C6 45 ?? 
            ?? 8D 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 51 0F 43 85 ?? ?? ?? ?? 51 50 8D 8D ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? BA ?? 
            ?? ?? ?? 50 8D 4D ?? E8 ?? ?? ?? ?? 56 50 8D 45 ?? C6 45 ?? ?? 50 E8 ?? ?? ?? ?? 83 
            C4 ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? 51 8B C8 E8 ?? ?? ?? ?? 50 8D 8D ?? ?? ?? ?? E8 
            ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? C6 45 ?? ?? 50 8D 85 ?? ?? ?? ?? 50 E8 
            ?? ?? ?? ?? 83 C4 ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? 51 8B C8 E8 ?? ?? ?? ?? 50 8D 4D 
            ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 45 ?? C6 45 ?? ?? 50 8D 85 ?? ?? ?? ?? 50 E8 ?? 
            ?? ?? ?? 83 C4 ?? 8D 8D ?? ?? ?? ?? C6 45 ?? ?? 51 8B C8 E8 ?? ?? ?? ?? 50 8D 4D ?? 
            E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 45 ?? C6 45 ?? ?? 50 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? 
            ?? ?? 83 C4 ?? 8B D0 C6 45 ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8D
        }

        $encrypt_files_p6 = {                        
            E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 4D ?? E8 
            ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 4D 
            ?? E8 ?? ?? ?? ?? 8D 4D ?? C6 45 ?? ?? E8 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? 
            ?? 83 EC ?? 8D 85 ?? ?? ?? ?? 8B CC 89 65 ?? 50 89 59 ?? 89 59 ?? E8 ?? ?? ?? ?? 83 
            EC ?? C6 45 ?? ?? 8B CC 89 65 ?? 8D 85 ?? ?? ?? ?? 50 89 59 ?? 89 59 ?? E8 ?? ?? ?? 
            ?? 83 EC ?? C6 45 ?? ?? 8B CC 89 65 ?? 8D 85 ?? ?? ?? ?? 50 89 59 ?? 89 59 ?? E8 ?? 
            ?? ?? ?? 83 EC ?? C6 45 ?? ?? 8B CC 8D 85 ?? ?? ?? ?? 50 89 59 ?? 89 59 ?? E8 ?? ?? 
            ?? ?? C6 45 ?? ?? E8 ?? ?? ?? ?? FF B5 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? 
            8D 95 ?? ?? ?? ?? 83 C4 ?? 8B F0 83 BD ?? ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 0F 43 95 ?? 
            ?? ?? ?? 03 CA 83 BD ?? ?? ?? ?? ?? 0F 43 85 ?? ?? ?? ?? 2B C8 51 50 56 E8 ?? ?? ?? 
            ?? 56 E8 ?? ?? ?? ?? 83 C4 ?? 53 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 FF 15 ?? ?? ?? ?? 
            68
        }

    condition:
        uint16(0) == 0x5A4D and 
        (
            all of ($find_files_p*)
        ) and 
        (
            all of ($encrypt_files_p*)
        ) and 
        (
            all of ($remote_connection_p*)
        )
}
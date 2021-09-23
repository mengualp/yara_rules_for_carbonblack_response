rule ByteCode_MSIL_Ransomware_Cring : tc_detection malicious
{
    meta:
 		score = 7

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "CRING"
        description         = "Yara rule that detects Cring ransomware."

        tc_detection_type   = "Ransomware"
        tc_detection_name   = "Cring"
        tc_detection_factor = 5

    strings:

        $find_files_p1 = {
            28 ?? ?? ?? ?? 0A 16 0B 2B ?? 06 07 9A 0C 08 6F ?? ?? ?? ?? 19 2E ?? 08 6F ?? ?? ?? ?? 
            18 33 ?? 08 6F ?? ?? ?? ?? 2C ?? 08 6F ?? ?? ?? ?? 02 17 28 ?? ?? ?? ?? 6F ?? ?? ?? ?? 
            0D 2B ?? 09 6F ?? ?? ?? ?? 28 ?? ?? ?? ?? 09 6F ?? ?? ?? ?? 2D ?? DE ?? 09 2C ?? 09 6F 
            ?? ?? ?? ?? DC 07 17 58 0B 07 06 8E 69 32 ?? 2A 
        }

        $find_files_p2 = {
            02 7B ?? ?? ?? ?? 0B 07 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 16 0A DD ?? 
            ?? ?? ?? 02 15 7D ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? 3A ?? ?? 
            ?? ?? 14 0C 02 7B ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 28 ?? ?? ?? ?? 0C DE ?? 26 DE ?? 08 2C 
            ?? 02 08 7D ?? ?? ?? ?? 02 16 7D ?? ?? ?? ?? 2B ?? 02 7B ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 
            9A 0D 02 09 7D ?? ?? ?? ?? 02 17 7D ?? ?? ?? ?? 17 0A DD ?? ?? ?? ?? 02 15 7D ?? ?? ?? 
            ?? 02 02 7B ?? ?? ?? ?? 17 58 7D ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 8E 69 
            32 ?? 02 14 7D ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 39 ?? ?? ?? ?? 14 0C 02 7B ?? ?? ?? ?? 28 
            ?? ?? ?? ?? 0C DE ?? 26 DE ?? 08 39 ?? ?? ?? ?? 02 08 7D ?? ?? ?? ?? 02 16 7D ?? ?? ?? 
            ?? 38 ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 9A 13 ?? 02 11 ?? 02 7B ?? ?? ?? 
            ?? 02 7B ?? ?? ?? ?? 28 ?? ?? ?? ?? 6F ?? ?? ?? ?? 7D ?? ?? ?? ?? 02 1F ?? 7D ?? ?? ?? 
            ?? 2B ?? 02 7B ?? ?? ?? ?? 6F ?? ?? ?? ?? 13 ?? 02 11 ?? 7D ?? ?? ?? ?? 02 18 7D ?? ?? 
            ?? ?? 17 0A DE ?? 02 1F ?? 7D ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 6F ?? ?? ?? ?? 2D ?? 02 28 
            ?? ?? ?? ?? 02 14 7D ?? ?? ?? ?? 02 02 7B ?? ?? ?? ?? 17 58 7D ?? ?? ?? ?? 02 7B ?? ?? 
            ?? ?? 02 7B ?? ?? ?? ?? 8E 69 3F ?? ?? ?? ?? 02 14 7D ?? ?? ?? ?? 16 0A DE ?? 02 28 ?? 
            ?? ?? ?? DC 06 2A 
        }

        $encrypt_files = {
            16 0A 73 ?? ?? ?? ?? 0B 07 6F ?? ?? ?? ?? 1E 5B 8D ?? ?? ?? ?? 0C 07 6F ?? ?? ?? ?? 1E 
            5B 8D ?? ?? ?? ?? 0D 73 ?? ?? ?? ?? 13 ?? 11 ?? 08 6F ?? ?? ?? ?? 11 ?? 09 6F ?? ?? ?? 
            ?? DE ?? 11 ?? 2C ?? 11 ?? 6F ?? ?? ?? ?? DC 08 8E 69 09 8E 69 58 8D ?? ?? ?? ?? 13 ?? 
            08 11 ?? 08 8E 69 28 ?? ?? ?? ?? 09 16 11 ?? 08 8E 69 09 8E 69 28 ?? ?? ?? ?? 11 ?? 04 
            28 ?? ?? ?? ?? 13 ?? 11 ?? 8E 69 28 ?? ?? ?? ?? 13 ?? 07 08 09 6F ?? ?? ?? ?? 13 ?? 02 
            19 73 ?? ?? ?? ?? 13 ?? 03 18 73 ?? ?? ?? ?? 13 ?? 11 ?? 11 ?? 17 73 ?? ?? ?? ?? 13 ?? 
            11 ?? 11 ?? 16 11 ?? 8E 69 6F ?? ?? ?? ?? 11 ?? 11 ?? 16 11 ?? 8E 69 6F ?? ?? ?? ?? 11 
            ?? 11 ?? 20 ?? ?? ?? ?? 6F ?? ?? ?? ?? DE ?? 11 ?? 2C ?? 11 ?? 6F ?? ?? ?? ?? DC 11 ?? 
            2C ?? 11 ?? 6F ?? ?? ?? ?? DC 11 ?? 2C ?? 11 ?? 6F ?? ?? ?? ?? DC 11 ?? 2C ?? 11 ?? 6F 
            ?? ?? ?? ?? DC 17 0A DE ?? 07 2C ?? 07 6F ?? ?? ?? ?? DC 06 2A 
        }

    condition:
        uint16(0) == 0x5A4D and
        (
            all of ($find_files_p*)
        ) and
        (
            $encrypt_files
        )
}
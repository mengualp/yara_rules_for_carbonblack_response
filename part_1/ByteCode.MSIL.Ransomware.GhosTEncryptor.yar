rule ByteCode_MSIL_Ransomware_GhosTEncryptor : tc_detection malicious
{
    meta:
 		score = 7

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "GHOSTENCRYPTOR"
        description         = "Yara rule that detects GhosTEncryptor ransomware."

        tc_detection_type   = "Ransomware"
        tc_detection_name   = "GhosTEncryptor"
        tc_detection_factor = 5

    strings:

        $enum_folders = {
            17 8D ?? ?? ?? ?? 0A 06 16 72 ?? ?? ?? ?? A2 03 28 ?? ?? ?? ?? 0B 16 0C 38 ?? ?? ?? ?? 
            07 08 9A 0D 02 09 28 ?? ?? ?? ?? 2C ?? 09 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? 2D ?? 09 72 ?? 
            ?? ?? ?? 6F ?? ?? ?? ?? 2D ?? 09 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? 2D ?? 09 72 ?? ?? ?? ?? 
            6F ?? ?? ?? ?? 2D ?? 09 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? 2D ?? 09 72 ?? ?? ?? ?? 6F ?? ?? 
            ?? ?? 2D ?? 09 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? 2D ?? 02 02 7B ?? ?? ?? ?? 09 72 ?? ?? ?? 
            ?? 28 ?? ?? ?? ?? 7D ?? ?? ?? ?? 02 09 28 ?? ?? ?? ?? 26 08 17 58 0C 08 07 8E 69 3F ?? 
            ?? ?? ?? 02 7B ?? ?? ?? ?? 06 17 6F ?? ?? ?? ?? 2A
        }

        $encrypt_folder_p1 = {
            1F ?? 8D ?? ?? ?? ?? 25 16 72 ?? ?? ?? ?? A2 25 17 72 ?? ?? ?? ?? A2 25 18 72 ?? ?? ?? 
            ?? A2 25 19 72 ?? ?? ?? ?? A2 25 1A 72 ?? ?? ?? ?? A2 25 1B 72 ?? ?? ?? ?? A2 25 1C 72 
            ?? ?? ?? ?? A2 25 1D 72 ?? ?? ?? ?? A2 25 1E 72 ?? ?? ?? ?? A2 25 1F ?? 72 ?? ?? ?? ?? 
            A2 25 1F ?? 72 ?? ?? ?? ?? A2 25 1F ?? 72
        }

        $encrypt_folder_p2 = {
            A2 0A 03 28 ?? ?? ?? ?? 0B 03 28 ?? ?? ?? ?? 0C 16 0D 2B ?? 07 09 9A 28 ?? ?? ?? ?? 13
            ?? 06 11 ?? 28 ?? ?? ?? ?? 2C ?? 02 07 09 9A 04 28 ?? ?? ?? ?? 09 17 58 0D 09 07 8E 69
            32 ?? 16 13 ?? 2B ?? 02 08 11 ?? 9A 04 28 ?? ?? ?? ?? 11 ?? 17 58 13 ?? 11 ?? 08 8E 69 
            32 ?? 2A
        }

        $deep_search_p1 = {
            17 8D ?? ?? ?? ?? 0A 06 16 72 ?? ?? ?? ?? A2 7E ?? ?? ?? ?? 0B 02 0C 16 0D 38 ?? ?? ?? 
            ?? 08 09 9A 28 ?? ?? ?? ?? 13 ?? 16 13 ?? 38 ?? ?? ?? ?? 11 ?? 11 ?? 9A 13 ?? 11 ?? 72 
            ?? ?? ?? ?? 6F ?? ?? ?? ?? 3A ?? ?? ?? ?? 11 ?? 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? 3A ?? ?? 
            ?? ?? 11 ?? 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? 3A ?? ?? ?? ?? 11 ?? 72
        } 

        $deep_search_p2 = {
            6F ?? ?? ?? ?? 2D ?? 11 ?? 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? 2D ?? 11 ?? 72 ?? ?? ?? ?? 6F
            ?? ?? ?? ?? 2D ?? 11 ?? 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? 2C ?? 07 11 ?? 72 ?? ?? ?? ?? 28
            ?? ?? ?? ?? 0B 11 ?? 17 58 13 ?? 11 ?? 11 ?? 8E 69 3F ?? ?? ?? ?? 09 17 58 0D 09 08 8E
            69 3F ?? ?? ?? ?? 07 06 17 6F ?? ?? ?? ?? 2A
        }

    condition:
        uint16(0) == 0x5A4D and
        (
            $enum_folders
        ) and
        (
            all of ($deep_search_p*)
        ) and
        (
            all of ($encrypt_folder_p*)
        )
}
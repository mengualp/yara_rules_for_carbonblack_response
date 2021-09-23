rule ByteCode_MSIL_Ransomware_Dusk : tc_detection malicious
{
    meta:
 		score = 7

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "DUSK"
        description         = "Yara rule that detects Dusk ransomware."

        tc_detection_type   = "Ransomware"
        tc_detection_name   = "Dusk"
        tc_detection_factor = 5

    strings:

        $encrypt_files_p1 = {
            03 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 04 6F ?? ?? ?? ?? 0A 28 ?? ?? ?? ?? 06 6F ?? ?? ?? ??
            0A 06 28 ?? ?? ?? ?? 0B 03 07 28 ?? ?? ?? ?? 03 03 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ??
            ?? ?? ?? DE ?? 26 DE ?? 2A
        }

        $encrypt_files_p2 = {
            14 0A 1E 8D ?? ?? ?? ?? 25 D0 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0B 73 ?? ?? ?? ?? 0C 73 ?? ??
            ?? ?? 0D 09 20 ?? ?? ?? ?? 6F ?? ?? ?? ?? 09 20 ?? ?? ?? ?? 6F ?? ?? ?? ?? 03 07 20 ??
            ?? ?? ?? 73 ?? ?? ?? ?? 13 ?? 09 11 ?? 09 6F ?? ?? ?? ?? 1E 5B 6F ?? ?? ?? ?? 6F ?? ??
            ?? ?? 09 11 ?? 09 6F ?? ?? ?? ?? 1E 5B 6F ?? ?? ?? ?? 6F ?? ?? ?? ?? 09 17 6F ?? ?? ??
            ?? 08 09 6F ?? ?? ?? ?? 17 73 ?? ?? ?? ?? 13 ?? 11 ?? 02 16 02 8E 69 6F ?? ?? ?? ?? 11
            ?? 6F ?? ?? ?? ?? DE ?? 11 ?? 2C ?? 11 ?? 6F ?? ?? ?? ?? DC 08 6F ?? ?? ?? ?? 0A DE ??
            09 2C ?? 09 6F ?? ?? ?? ?? DC 08 2C ?? 08 6F ?? ?? ?? ?? DC 06 2A
        }

        $dusk_delete_itself = {
            72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0A 1A 8D ?? ?? ?? ?? 25 16
            72 ?? ?? ?? ?? A2 25 17 72 ?? ?? ?? ?? 03 28 ?? ?? ?? ?? A2 25 18 72 ?? ?? ?? ?? 28 ??
            ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? A2 25 19 72 ?? ?? ?? ?? A2 0B 06 07 28 ?? ?? ??
            ?? 06 06 28 ?? ?? ?? ?? 18 60 28 ?? ?? ?? ?? 20 ?? ?? ?? ?? 28 ?? ?? ?? ?? 06 73 ?? ??
            ?? ?? 25 17 6F ?? ?? ?? ?? 25 16 6F ?? ?? ?? ?? 28 ?? ?? ?? ?? 26 04 28 ?? ?? ?? ?? 28
            ?? ?? ?? ?? DE ?? 26 DE ?? 2A
        }

        $find_files = {
            20 ?? ?? ?? ?? 72 ?? ?? ?? ?? A2 25 20 ?? ?? ?? ?? 72 ?? ?? ?? ?? A2 25 20 ?? ?? ?? ??
            72 ?? ?? ?? ?? A2 0A 1F ?? 8D ?? ?? ?? ?? 25 16 1F ?? 28 ?? ?? ?? ?? A2 25 17 1E 28 ??
            ?? ?? ?? A2 25 18 1F ?? 28 ?? ?? ?? ?? A2 25 19 1F ?? 28 ?? ?? ?? ?? A2 25 1A 1F ?? 28
            ?? ?? ?? ?? A2 25 1B 1B 28 ?? ?? ?? ?? A2 25 1C 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 72 ?? ??
            ?? ?? 28 ?? ?? ?? ?? A2 25 1D 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ??
            ?? A2 25 1E 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? A2 25 1F ?? 72
            ?? ?? ?? ?? 28 ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? A2 0B 16 0C 2B ?? 07 08 9A 0D
            1F ?? 28 ?? ?? ?? ?? 13 ?? 09 72 ?? ?? ?? ?? 17 28 ?? ?? ?? ?? 13 ?? 16 13 ?? 2B ?? 11
            ?? 11 ?? 9A 28 ?? ?? ?? ?? 13 ?? 06 11 ?? 28 ?? ?? ?? ?? 2C ?? 02 11 ?? 11 ?? 9A 11 ??
            28 ?? ?? ?? ?? 11 ?? 17 58 13 ?? 11 ?? 11 ?? 8E 69 32 ?? 00 02 09 28 ?? ?? ?? ?? DE ??
            26 DE ?? 08 17 58 0C 08 07 8E 69 32 ?? 02 7B ?? ?? ?? ?? 6F ?? ?? ?? ?? 20 ?? ?? ?? ??
            28 ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ??
            ?? 26 DE ?? 26 DE ?? 20 ?? ?? ?? ?? 28 ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 72 ?? ?? ?? ?? 20
            ?? ?? ?? ?? 6F ?? ?? ?? ?? 2A
        }

    condition:
        uint16(0) == 0x5A4D and
        (
            $find_files
        ) and
        (
            all of ($encrypt_files_p*)
        ) and
        (
            $dusk_delete_itself
        )
}
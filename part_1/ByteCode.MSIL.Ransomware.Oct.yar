rule ByteCode_MSIL_Ransomware_Oct : tc_detection malicious
{
    meta:
 		score = 7

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "OCT"
        description         = "Yara rule that detects Oct ransomware."

        tc_detection_type   = "Ransomware"
        tc_detection_name   = "Oct"
        tc_detection_factor = 5

    strings:

        $encrypt_files = {
            1E 8D ?? ?? ?? ?? 25 D0 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0A 03 0B 07 18 73 ?? ?? ?? ?? 0C 73
            ?? ?? ?? ?? 0D 09 20 ?? ?? ?? ?? 6F ?? ?? ?? ?? 09 20 ?? ?? ?? ?? 6F ?? ?? ?? ?? 04 06
            20 ?? ?? ?? ?? 73 ?? ?? ?? ?? 13 ?? 09 11 ?? 09 6F ?? ?? ?? ?? 1E 5B 6F ?? ?? ?? ?? 6F
            ?? ?? ?? ?? 09 11 ?? 09 6F ?? ?? ?? ?? 1E 5B 6F ?? ?? ?? ?? 6F ?? ?? ?? ?? 09 19 6F ??
            ?? ?? ?? 09 17 6F ?? ?? ?? ?? 08 09 6F ?? ?? ?? ?? 17 73 ?? ?? ?? ?? 13 ?? 02 19 73 ??
            ?? ?? ?? 13 ?? 2B ?? 11 ?? 11 ?? D2 6F ?? ?? ?? ?? 11 ?? 6F ?? ?? ?? ?? 25 13 ?? 15 33
            ?? 11 ?? 6F ?? ?? ?? ?? 11 ?? 6F ?? ?? ?? ?? 08 6F ?? ?? ?? ?? 02 28 ?? ?? ?? ?? DE ??
            13 ?? 11 ?? 6F ?? ?? ?? ?? 28 ?? ?? ?? ?? DE ?? 2A
        }

        $find_files = {
            16 0A 38 ?? ?? ?? ?? 16 0B 2B ?? 02 06 9A 28 ?? ?? ?? ?? 2C ?? 02 06 9A 73 ?? ?? ?? ??
            0C 08 72 ?? ?? ?? ?? 03 07 9A 28 ?? ?? ?? ?? 17 6F ?? ?? ?? ?? 0D 09 13 ?? 16 13 ?? 2B
            ?? 11 ?? 11 ?? 9A 13 ?? 11 ?? 6F ?? ?? ?? ?? 11 ?? 6F ?? ?? ?? ?? 05 28 ?? ?? ?? ?? 1E
            8D ?? ?? ?? ?? 25 D0 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 11 ?? 17 58 13 ?? 11 ??
            11 ?? 8E 69 32 ?? 07 17 58 0B 07 03 8E 69 32 ?? 06 17 58 0A 06 02 8E 69 3F ?? ?? ?? ??
            2A 
        }

        $collect_env_and_start_enc_proc = {
            19 8D ?? ?? ?? ?? 0B 07 16 16 28 ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? A2 07 17 1B
            28 ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? A2 07 18 1F ?? 28 ?? ?? ?? ?? 72 ?? ?? ??
            ?? 28 ?? ?? ?? ?? A2 07 1F ?? 8D ?? ?? ?? ?? 0C 08 16 72 ?? ?? ?? ?? A2 08 17 72 ?? ??
            ?? ?? A2 08 18 72 ?? ?? ?? ?? A2 08 19 72 ?? ?? ?? ?? A2 08 1A 72 ?? ?? ?? ?? A2 08 1B
            72 ?? ?? ?? ?? A2 08 1C 72 ?? ?? ?? ?? A2 08 1D 72 ?? ?? ?? ?? A2 08 1E 72 ?? ?? ?? ??
            A2 08 1F ?? 72 ?? ?? ?? ?? A2 08 1F ?? 72 ?? ?? ?? ?? A2 08 1F ?? 72 ?? ?? ?? ?? A2 08
            1F ?? 72 ?? ?? ?? ?? A2 08 1F ?? 72 ?? ?? ?? ?? A2 08 1F ?? 72 ?? ?? ?? ?? A2 08 1F ??
            72 ?? ?? ?? ?? A2 08 1F ?? 72 ?? ?? ?? ?? A2 08 1F ?? 72 ?? ?? ?? ?? A2 08 1F ?? 72 ??
            ?? ?? ?? A2 08 1F ?? 72 ?? ?? ?? ?? A2 08 1F ?? 72 ?? ?? ?? ?? A2 08 1F ?? 72 ?? ?? ??
            ?? A2 08 1F ?? 72 ?? ?? ?? ?? A2 08 1F ?? 72 ?? ?? ?? ?? A2 08 72 ?? ?? ?? ?? 72 ?? ??
            ?? ?? 28 ?? ?? ?? ?? 16 28 ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 73 ?? ?? ?? ?? 0A
            06 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? DE ?? 06 2C ?? 06 6F ?? ?? ?? ?? DC 72 ?? ?? ?? ?? 16
            28 ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 26 7E ?? ?? ?? ?? 72 ?? ??
            ?? ?? 28 ?? ?? ?? ?? 2C ?? 28 ?? ?? ?? ?? 2A
        }

    condition:
        uint16(0) == 0x5A4D and
        (
            $collect_env_and_start_enc_proc
        ) and
        (
            $find_files
        ) and
        (
            $encrypt_files
        )
}
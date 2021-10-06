rule ByteCode_MSIL_Ransomware_Fantom : tc_detection malicious
{
    meta:
 		score = 7

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "FANTOM"
        description         = "Yara rule that detects Fantom ransomware."

        tc_detection_type   = "Ransomware"
        tc_detection_name   = "Fantom"
        tc_detection_factor = 5

    strings:

        $encrypt_files_1 = {
            00 72 ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 28 ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 28 ?? ?? ?? ??
            26 DE ?? 26 DE ?? 02 28 ?? ?? ?? ?? 13 ?? 02 28 ?? ?? ?? ?? 02 28 ?? ?? ?? ?? 02 28
            ?? ?? ?? ?? 1F ?? 28 ?? ?? ?? ?? [1-2] 02 72 ?? ?? ?? ?? 7D ?? ?? ?? ?? 02 [1-2] 20
            ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 28 ?? ?? ?? ?? 7D ?? ?? ?? ?? 28 ?? ?? ?? ?? 11 ?? 6F
            ?? ?? ?? ?? 13 ?? 02 11 ?? 28 ?? ?? ?? ?? 7D ?? ?? ?? ?? 02 02 7B ?? ?? ?? ?? 02 7B
            ?? ?? ?? ?? 28 ?? ?? ?? ?? 7D ?? ?? ?? ?? 02 28 ?? ?? ?? ?? 20 ?? ?? ?? ?? 8D ?? ??
            ?? ?? 13 ?? 11 ?? 16
        }

        $encrypt_files_2 = {
            72 ?? ?? ?? ?? A2 11 ?? 17 72 ?? ?? ?? ?? A2 11 ?? 18 72 ?? ?? ?? ?? A2 11 ??
            19 72 ?? ?? ?? ?? A2 11 ?? 1A 72 ?? ?? ?? ?? A2 11 ?? 1B 72 ?? ?? ?? ?? A2 11
            ?? 1C 72 ?? ?? ?? ?? A2 11 ?? 1D 72 ?? ?? ?? ?? A2 11 ?? 1E 72 ?? ?? ?? ?? A2
            11 ?? 1F ?? 72 ?? ?? ?? ?? A2 11 ?? 1F ?? 72 ?? ?? ?? ?? A2 11 ?? 1F ?? 72 ??
            ?? ?? ?? A2 11 ?? 1F ?? 72 ?? ?? ?? ?? A2 11 ?? 1F ?? 72 ?? ?? ?? ?? A2 11 ??
            1F ?? 72 ?? ?? ?? ?? A2 11 ?? 1F ?? 72 ?? ?? ?? ?? A2 11 ?? 1F ?? 72 ?? ?? ??
            ?? A2 11 ?? 1F ?? 72 ?? ?? ?? ?? A2 11 ?? 1F ?? 72 ?? ?? ?? ?? A2 11 ?? 1F ??
            72 ?? ?? ?? ?? A2 11 ?? 1F ?? 72 ?? ?? ?? ?? A2 11 ?? 1F ?? 72 ?? ?? ?? ?? A2
            11 ?? 1F ?? 72 ?? ?? ?? ?? A2 11 ?? 1F ?? 72 ?? ?? ?? ?? A2 11 ?? 1F ?? 72 ??
            ?? ?? ?? A2 11 ?? 1F ?? 72 ?? ?? ?? ?? A2 11 ?? 1F ?? 72 ?? ?? ?? ?? A2 11 ??
            1F ?? 72 ?? ?? ?? ?? A2 11 ?? 1F ?? 72 ?? ?? ?? ?? A2 11 ?? 1F ?? 72 ?? ?? ??
            ?? A2 11 ?? 1F ?? 72 ?? ?? ?? ?? A2 11 ?? 1F ?? 72 ?? ?? ?? ?? A2 11 ?? 1F ??
            72 ?? ?? ?? ?? A2 11 ?? 1F ?? 72 ?? ?? ?? ?? A2 11 ?? 1F ?? 72 ?? ?? ?? ?? A2
            11 ?? 1F ?? 72 ?? ?? ?? ?? A2 11 ?? 1F ?? 72 ?? ?? ?? ?? A2 11 ?? 1F ?? 72 ??
            ?? ?? ?? A2 11 ?? 1F ?? 72 ?? ?? ?? ?? A2 11 ?? 1F ?? 72 ?? ?? ?? ?? A2 11 ??
            1F ?? 72 ?? ?? ?? ?? A2 11 ?? 1F ?? 72 ?? ?? ?? ?? A2 11 ?? 1F ?? 72 ?? ?? ??
            ?? A2 11 ?? 1F ?? 72 ?? ?? ?? ?? A2 11 ?? 1F ?? 72 ?? ?? ?? ?? A2 11 ?? 1F ??
            72 ?? ?? ?? ?? A2 11 ?? 1F ?? 72 ?? ?? ?? ?? A2 11 ?? 1F ?? 72 ?? ?? ?? ?? A2
            11 ?? 1F ?? 72 ?? ?? ?? ?? A2 11 ?? 1F ?? 72 ?? ?? ?? ?? A2 11 ?? 1F ?? 72 ??
            ?? ?? ?? A2 11 ?? 1F ?? 72 ?? ?? ?? ?? A2 11 ?? 1F ?? 72 ?? ?? ?? ?? A2 11 ??
            1F ?? 72 ?? ?? ?? ?? A2 11 ?? 1F ?? 72 ?? ?? ?? ?? A2 11 ?? 1F ?? 72 ?? ?? ??
            ?? A2 11 ?? 1F ?? 72 ?? ?? ?? ?? A2 11 ?? 1F ?? 72 ?? ?? ?? ?? A2 11 ?? 1F ??
            72 ?? ?? ?? ?? A2 11 ?? 1F ?? 72 ?? ?? ?? ?? A2 11 ?? 1F ?? 72 ?? ?? ?? ?? A2
            11 ?? 1F ?? 72 ?? ?? ?? ?? A2 11 ?? 1F ?? 72 ?? ?? ?? ?? A2 11 ?? 1F ?? 72 ??
            ?? ?? ?? A2 11 ?? 1F ?? 72 ?? ?? ?? ?? A2 11 ?? 1F ?? 72 ?? ?? ?? ?? A2 11
        }

        $lockfile = {
            02 7B ?? ?? ?? ?? 16 FE ?? 3A ?? ?? ?? ?? 21 EA 17 ?? ?? ?? ?? ?? ?? ??
            03 73 ?? ?? ?? ?? [2-4] 6F ?? ?? ?? ?? [2-4] 21 00 65 CD 1D
            00 00 00 00 FE ?? 16 FE ?? 2D ?? [2-4] FE ?? 16 FE ?? 2D ?? 03 28
            ?? ?? ?? ?? ?? 28 ?? ?? ?? ?? 04 6F ?? ?? ?? ?? [1-2] 28 ?? ?? ?? ?? [1-2]
            6F ?? ?? ?? ?? [1-2] 02 ?? [1-2] 28 ?? ?? ?? ?? [1-2] 03 [1-2] 28 ?? ??
            ?? ?? 03 03 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? [1-2] ?? FE ??
            16 FE ?? 2D ?? 2B ?? 03 03 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ??
            2B ?? 03 28 ?? ?? ?? ?? ?? 28 ?? ?? ?? ?? 04 6F ?? ?? ?? ?? [1-2] 28 ??
            ?? ?? ?? [1-2] 6F ?? ?? ?? ?? [1-2] 02 ?? [1-2] 28 ?? ?? ?? ?? [1-2] 03
            [1-2] 28 ?? ?? ?? ?? 03 03 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ??
            2A
        }

        $lockdir = {
            03 28 ?? ?? ?? ?? 0A 03 28 ?? ?? ?? ?? 0B 16 0C 08 06 8E 69 FE ?? 2C ??
            00 06 08 9A 28 ?? ?? ?? ?? 0D 05 09 28 ?? ?? ?? ?? 16 FE ?? 2D ?? 02 25
            7B ?? ?? ?? ?? 17 58 7D ?? ?? ?? ?? 02 06 08 9A 04 28 ?? ?? ?? ?? DE ??
            26 DE ?? 26 DE ?? 08 17 58 0C 2B ?? 16 0C 08 07 8E 69 FE ?? 2C ?? 00 02
            07 08 9A 04 05 28 ?? ?? ?? ?? 02 07 08 9A 04 28 ?? ?? ?? ?? DE ?? 26 DE
            ?? 26 DE ?? 08 17 58 0C 2B ?? 2A
        }

        $sendkey = {
            00 02 7C ?? ?? ?? ?? 28 ?? ?? ?? ?? 0A 73 ?? ?? ?? ?? 0B 73 ?? ?? ?? ??
            0C 08 72 ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 6F ?? ?? ?? ?? 08 72 ?? ?? ?? ??
            02 7B ?? ?? ?? ?? 6F ?? ?? ?? ?? 08 72 ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 6F
            ?? ?? ?? ?? 08 72 ?? ?? ?? ?? 06 6F ?? ?? ?? ?? 07 03 72 ?? ?? ?? ?? 08
            6F ?? ?? ?? ?? 26 07 6F ?? ?? ?? ?? DE ?? 26 DE ?? 2A
        }

    condition:
        uint16(0) == 0x5A4D and
        (
            (all of ($encrypt_files_*)) and
            $lockfile and
            $lockdir and
            $sendkey
        )
}
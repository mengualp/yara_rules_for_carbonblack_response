/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/

rule Maldoc_CVE_2017_11882 : Exploit {
    meta:
 		score = 7
        description = "Detects maldoc With exploit for CVE_2017_11882"
        author = "Marc Salinas (@Bondey_m)"
        reference = "c63ccc5c08c3863d7eb330b69f96c1bcf1e031201721754132a4c4d0baff36f8"
        date = "2017-10-20"
    strings:
        $s0 = "Equation"
        $s1 = "1c000000020"
        $h0 = {1C 00 00 00 02 00}

    condition: 
        $s0 and ($h0 or $s1)
}

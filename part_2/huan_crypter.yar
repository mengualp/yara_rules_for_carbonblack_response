import "pe"

rule CRYPTER_Huan {
   meta:
    score = 7
      description = "Detects samples crypted with Huan PE Loader"
      author = "Marius 'f0wL' Genheimer"
      reference = "https://github.com/frkngksl/Huan"
      date = "2021-08-21"
      tlp = "WHITE"
      
   strings:
      $s0 = ".huan" fullword ascii
      $s1 = "[+] Imported DLL Name: " fullword ascii
      $s2 = "[+] Binary is running" fullword ascii
      $s3 = "[+] All headers are copied" fullword ascii
      $s4 = "[+] Data is decrypted! " fullword ascii
      $s5 = "[+] All sections are copied" fullword ascii
      $s6 = "[!] Import Table not found" fullword ascii
      $s7 = "[+] Cannot load to the preferable address" fullword ascii
      
   condition:
      uint16(0) == 0x5a4d
      and pe.imphash() == "f7fd6adbeced3adfa337ae23987ee13e"
      and 4 of ($s*)
}

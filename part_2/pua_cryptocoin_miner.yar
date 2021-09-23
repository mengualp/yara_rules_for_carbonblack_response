
rule CoinMiner_Strings {
   meta:
      description = "Detects mining pool protocol string in Executable"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth"
      score = 5
      reference = "https://minergate.com/faq/what-pool-address"
      date = "2018-01-04"
   strings:
      $s1 = "stratum+tcp://" ascii
      $s2 = "\"normalHashing\": true,"
   condition:
      filesize < 600KB and 1 of them
}

rule CoinHive_Javascript_MoneroMiner {
   meta:
      description = "Detects CoinHive - JavaScript Crypto Miner"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth"
      score = 5
      reference = "https://coinhive.com/documentation/miner"
      date = "2018-01-04"
   strings:
      $s2 = "CoinHive.CONFIG.REQUIRES_AUTH" fullword ascii
   condition:
      filesize < 65KB and 1 of them
}

rule PUA_CryptoMiner_Jan19_1 {
   meta:
      description = "Detects Crypto Miner strings"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2019-01-31"
      hash1 = "ede858683267c61e710e367993f5e589fcb4b4b57b09d023a67ea63084c54a05"
   strings:
      $s1 = "Stratum notify: invalid Merkle branch" fullword ascii
      $s2 = "-t, --threads=N       number of miner threads (default: number of processors)" fullword ascii
      $s3 = "User-Agent: cpuminer/" ascii
      $s4 = "hash > target (false positive)" fullword ascii
      $s5 = "thread %d: %lu hashes, %s khash/s" fullword ascii
   condition:
      filesize < 1000KB and 1 of them
}

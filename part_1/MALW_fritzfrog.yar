rule MALW_fritzfrog
{
    meta:
 		score = 7
       
        description = "Rule to detect Fritzfrog"
        author = "Marc Rivero | McAfee ATR Team"
        date = "2020-08-20"
        rule_version = "v1"
        malware_type = "botnet"
        malware_family = "Botnet:W32/Fritzfrog"
        actor_type = "Cybercrime"
        hash1 = "103b8404dc64c9a44511675981a09fd01395ee837452d114f1350c295357c046"
        actor_type = "Cybercrime"
        actor_group = "Unknown"
    
    strings:
        
        $pattern = { 7F454C4602010100000000000000000002003E000100000090D34500000000004000000000000000C8010000000000000000000040003800070040000D000300060000000400000040000000000000004000400000000000400040000000000088010000000000008801000000000000001000000000000004000000040000009C0F0000000000009C0F4000000000009C0F400000000000640000000000000064000000000000000400000000000000010000000500000000000000000000000000400000000000000040000000000083F23E000000000083F23E00000000000010000000000000010000000400000000003F000000000000007F000000000000007F00000000006C834500000000006C834500000000000010000000000000010000000600000000908400000000000090C400000000000090C4000000000060EC0400000000005809070000000000001000000000000051E574640600000000000000000000000000000000000000000000000000000000000000000000000000000000000000080000000000000080150465002A000000000000000000000000000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000100000006000000000000000010400000000000001000000000000083E23E00000000000000000000000000100000000000000000000000000000004100000001000000020000000000000000007F000000000000003F0000000000C0271B0000000000000000000000000020000000000000000000000000000000720000000300000000000000000000000000000000000000C0275A00000000007C000000000000000000000000000000010000000000000000000000000000004900000001000000020000000000000040289A000000000040285A0000000000D83600000000000000000000000000002000000000000000000000000000000053000000010000000200000000000000185F9A0000000000185F5A0000000000380D0000000000000000000000000000080000000000000000000000000000005D000000010000000200000000000000506C9A0000000000506C5A0000000000000000000000000000000000000000000100000000000000000000000000000067000000010000000200000000000000606C9A0000000000606C5A00000000000C172A0000000000000000000000000020000000000000000000000000000000070000000100000003000000000000000090C400000000000090840000000000004B0300000000000000000000000000200000000000000000000000000000001200000001000000030000000000000000DBC7000000000000DB87000000000050A101000000000000000000000000002000000000000000000000000000000018000000080000000300000000000000607CC90000000000607C890000000000D0E80100000000000000000000000000200000000000000000000000000000001D0000000800000003000000000000004065CB000000000040658B00000000001834000000000000000000000000000020000000000000000000000000000000270000000700000002000000000000009C0F4000000000009C0F00000000000064000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 }

    condition:

        uint16(0) == 0x457f and
        filesize < 26000KB and
        all of them 
    
}

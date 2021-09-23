rule RANSOM_Suncrypt
{

    meta:
 		score = 7

        description = "Rule to detect SunCrypt ransomware"
        author = "McAfee ATR Team"
        date = "2020-10-02"
        rule_version = "v1"
        malware_type = "ransomware"
        malware_family = "Ransomware:W32/Suncrypt"
        actor_type = "Cybercrime"
        actor_group = "Unknown"
        hash1 = "3090bff3d16b0b150444c3bfb196229ba0ab0b6b826fa306803de0192beddb80"
        hash2 = "63ba6db8c81c60dd9f1a0c7c4a4c51e2e56883f063509ed7b543ad7651fd8806"

    strings:

        $pattern = { 77??2F475263????78??58436463????77??7A??5263????78??5846534D5A4678??48475263??????6B??????4D5A4679??7A??5263????78??584C5163????7A??44475264??5778??58526163????30????475264??30????58556463????31????475264??73??6B??????63????32????4752646C73??6B??????38????32??5047526477??6A??5738????68????????41555039????496C46374931????46446F62????414146442F565169????????????5039????466D4A526669??????????64??63????4F6D38????414169??????????586F69??????????33????30????69????????????6F41444141414974??38????41554542516167??2F5665??4478??434A526679??6666????64??63????4F6D444141414169??????????33??69????????????77??33????2F33????2F33????36??49464141434478??7A??64667A??64??7A??64??6A??73??7A??2F34??454449584164??517A??4F74??69??????????5834??5558672F33????2F33????36??6E362F2F39????59584164??517A??4F73??69??????????33??69????????????554B30????69????????????30????5838????5830????5549554974??4446434C525268????????30??39????77??444A77??574C37495073??4D5A4634??62????65??70??6B??????73??4634??54475265??31????586C5963????35????????65????78??586F63????4636??2F47526570??78??5872??63????37475047526531??78??5875??4931????46446F534163????46442F565169????????????66??51616B??????52434C51416A??63????4C5252442F63????2F566679??78??434677??55454D38??????475368????????41496C462B????462B????4E454974??49496C49434974??454974??434974??454974??49414E494B496C4E39????4639????517A??5041514D6E44565976??555974??434974??434974??434974??494474??4E4855464D38????367A??4C525169??????????????6C72??51574466??68????????454D38??????6F74??434974??434974??434974??494374??4E496C4E2F5039??2F4974??435039????4F6A??2B????2F57566E4A77??574C37494873??41414141494E6C6C4143445A6141416733??514148554969??????????30??????44475266??75??6B??????4D5A4638????475266??73??6B??????4D5A4639????475266??6B??????33????5A462B????4752666B??????5867??73??4634??6E475265??79??6B??????4D5A4635????????65??68????????62????4635????????65??????????70??63????366E4C47526574??78??5873??4D5A4630????475264??70??6B??????73??4630??54475264??31????58565963????31????475264????78??585962????4632????47526470??78??5862????5A4633????475262????78??5739????5A4676??54475262??4478??58416463????77??4C475263????78??58445A63????78??37475263????78??5847554D5A4678??4C475263????78??584A5938????79??58475263??????6B??????38????7A??44475261526178??576C64??????70??584752616475??6B??????63????71??4847526170??78??5772??73??4672??6E47526131??????5775??38????72??2F475262????78??5778??38????73??58475262????78??5730??????4674??6E475262????78??5733????5A4675??434E5265??5136??4D46414142512F31????69????????????51554F677A??514141555039????496C466E4931????46446F4977??414146442F565169????????????6152516A??5877??5039????46442F565169????????????52434C514269????????????4932????502F2F2F31??????667A??565A434677??515A67??32????414142414855433677??4C526677??68????????2F2B????667A??31????46454974??434974??454974??4E4474??47484A4D69??????????414969??????????5838????36??6661414164??69??????????????6A??565978??2F31????68????????32????61414177??41434C5252434C514169??????????????74??454974??435039????5039????495045454974??45496C4249476F4561414177??41434C5252434C514169??????????????74??454974??435039????5039????495045454974??45496C42494974??45494E34??414231????74??454974??43476F49575776??42594E38????77??64??474C5252434C514169??????????????534A51534472??476F4561414177??41434C5252434C514169??????????????6F412F31????67??????69??????????456769??????????67????48554636??67??4141434C5252434C51416A??63????4C5252442F63????4C5252442F63????6F30????4141495045444974??454974??434974??454974??43412B??5352534E524167??69????????????38????73??69??????????6C462F4974??454974??43412B??51415935????????4F5774??2F4369??????????????45516130????4B4974??454974??454974??6D414E4D4168????????5838????74??454974??494974??6D414E4D416778??36??59424141434478??7A??73??64??6C4145414141417A??412B????50372F2F34??466C4D6E44565976??555974??434974??434974??45496C49424974??434974??42412B??414431????67??4164??517A??4F73??69??????????414569??????????6B??????67??????554969????????????4969??????????68????????4164??517A?? }

    condition:
    
        uint16(0) == 0x6441 and
        all of them
}

rule RANSOM_Suncrypt_decryptor
{
   meta:
 		score = 7

      description = "Rule to detect SunCrypt ransomware decryptor"
      author = "McAfee ATR Team"
      date = "2020-10-02"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransomware:W32/Suncrypt"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      hash1 = "a0f99367b0a0a358ed6e5ae25904016d02aef6aa7c0423c34aa3ec3fd6354310"
          
    strings:

        $pattern = { 558BEC81EC88000000837D08008BC10F101A89957CFFFFFF0F104A10898578FFFFFF0F1062200F106A300F115D940F114DA40F1165B40F116DC40F8E340200008B45D08B4DC48B55B08945F88B45CC8945E08B45C88945E88B45C08945F08B45BC8945F48B45B8538B5DA88945EC8B45AC568B75A48945D48B45A0578975DC8945E48B459403C68BF033F18B4DB4C1C61003CE8BF9337DDCC1C70C03C78945DC33C6C1C0088945D803C18B4DEC89458833C7C1C0078945848B459803C38BF03375E8C1C61003CE8BF933FBC1C70C03C78945E833C6C1C00889458C03C18B4DF48BD88945EC33DF8B459C0345D48B7DE48BF03375E003FAC1C61003CEC1C307894DF4334DD4C1C10C03C133F08945908B45F0C1C6088975800375F433CEC1C107894DE08B4DF833CFC1C11003C133D08945F0C1C20C8D043A8B7DF033C88945E48B45DCC1C10803F9894DF833D7C1C20703C38BC8334DF8C1C11003F18975FC315DFC8B5DFCC1C30C03C389459433C1C1C0088945F88945D003C633D88945F48945BC8B45E80345E08BC8C1C307334DD8C1C110895DFC895DA88B5DEC8D340F8BFE337DE0C1C70C03C789459833C1C1C0088945D88945C403C68B758833F88945F08945C08B459003C2C1C7078BC8897DD4334D8CC1C11003F1897DAC8B7DE433D6037D84C1C20C03C289459C33C1C1C0088945E88945C803C633D08945B48BC7C1C207334580C1C01003D88BCB334D84C1C10C03F98BF7897DE433F0897DA0C1C60803DE8975E08975CC895DEC8B45088BF333F1895DB88B5DFC488B4DD8C1C6078975DC8975A489450885C00F8F30FEFFFF0F106DC48B8578FFFFFF0F1065B45F0F105D948955B00F104DA48B957CFFFFFF5E5B0F10020F105210660FFED80F104230660FFED10F104A200F1118660FFECC660FFEC50F1150100F1148200F1140308BE55DC3CCCCCCCCCCCCCCCCCCCC558BEC83E4F081EC58020000568BC18B4D1489442420578BFA897C24283D000100000F82680A0000660F6E07660F70C800660F6E4704660F70D000660F6E4708660F70D800660F6E470C660F70E000660F6E4710660F70E800660F6E47148B7508660F70F000660F6E47188B550C660F70F8008D8EC0000000660F6E471C660F70C0000F29842430010000660F6E4720660F70C0000F29842440010000660F6E4724660F70C0000F29842450010000660F6E4728660F70C0000F29842460010000660F6E472C894C240C8D8AC0000000660F70C000894C241C8D8E800000000F29842470010000660F6E4738894C24148D8A80000000660F70C000894C24188D4E400F29842480010000660F6E473C894C242C8D4A40660F70C000C1E8080F298C24A00100000F299424B00100000F299C24C00100000F29A424D00100000F29AC24E00100000F29B424F00100000F29BC24000200000F29842490010000894C24108944242066660F1F8400000000000F2884243001000033C00B47308B4F340F298424800000000F288424400100000F298424900000000F288424500100000F294424600F288424600100000F298424100100000F28842470010000894C244C8944244883C0040F298C24D0000000F30F7E4C244883D1000F298424200100000F288424900100000F299424E00000000F2815A02B4200660F6CC90F29442430660FD4D10F2805B02B42000F29A424A0000000660FD4C10F28E20F29B42400010000660F62E0660F6AD00F28F40F299C24F00000000F28DD0F28AC2480010000660F62F20F297C24700F28FE660F6AE2894F348B4D140F295C24500F29AC24C00000000F29A424B00000000F29BC24400200000F29A4245002000089473085C90F84820400000F287C24708BC166900F28D3660FFE9424D0000000660FEFF2660F380035C02B42000F28DE660FFE9C24900000000F28C3660FEF4424500F28C8660F72F00C660F72D114660FEBC80F28C1660FFEC20F28942400010000660FFE9424E0000000660FEFF0660F380035D02B42000F29842490000000660FEFE2660F380025C02B42000F28C60F29742470660FFEC30F28DC660FFE5C24600F29842410020000660FEFC10F28C8660F72F007660F72D119660FEBC80F28C3660FEF8424000100000F298C24200200000F28C8660F72F00C660F72D114660FEBC80F28C1660FFEC20F28D7660FFE9424F0000000660FEFE0660F380025D02B42000F29442460660FEFEA660F38002DC02B42000F28C40F29A424B0000000660FFEC30F28DD660FFE9C24100100000F29842430020000660FEFC10F28F0660F72F007660F72D619660FEBF00F28C3660FEFC70F28C8660F72F00C660F72D114660FEBC80F28C1660FFEC20F28942480000000660FFE9424A0000000660FEFE8660F38002DD02B42000F294424500F28E50F29AC24C0000000660FFEE30F28C4660FEFC10F28F8660F72F007660F72D719660FEBF80F286C2430660FEFEA660F38002DC02B42000F28DD660FFE9C24200100000F28C3660FEF8424800000000F28C8660F72F00C660F72D114660FEBC80F28C1660FFEC20F28D6660FEFE8660FFE942490000000660F38002DD02B42000F298424A00000000F296C2430660FFEEB0F28C5660FEFC10F28C8660F72F007660F72D119660FEBC80F28442430660FEFC20F298C2480000000660F380005C02B42000F28D80F29442430660FFEDC0F28C3660FEFC60F287424700F28C8660F72F00C660F72D114660FEBC80F284424300F28E1660FFEE20F28D7660FFE542460660FEFC4660F380005D02B4200660FEFF20F29A424D0000000660F380035C02B42000F29442430660FFEC30F298424100100000F28DE660FEFC1660FFEDD0F28C8660F72F007660F72D119660FEBC80F28C3660FEFC70F298C24000100000F28C8660F72F00C660F72D114660FEBC80F28C1660FFEC20F28942480000000660FEFF00F298424E0000000660F380035D02B42000F28C6660FFEC30F29842420010000660FEFC10F28F8660F72F007660F72D719660FEBF8660FFE5424500F28A424B00000000F28AC24C0000000660FEFE2660F380025C02B42000F28DC660FFE9C24100200000F28C3660FEF8424800000000F28C8660F72F00C660F72D114660FEBC80F28C1660FFEC20F28942420020000660FFE9424A0000000660FEFE00F298424F0000000660FEFEA660F380025D02B4200660F38002DC02B42000F29A424B00000000F28C4660FFEC30F28DD660FFE9C24300200000F29842490000000660FEFC10F28C8660F72F007660F72D119660FEBC80F28C3660FEF8424200200000F298C24800000000F28C8660F72F00C660F72D114660FEBC80F28C1660FFEC20F298424A0000000660FEFE8660F38002DD02B42000F29AC24C00000000F28C5660FFEC30F29442460660FEFC10F28D8660F72F007660F72D319660FEBD80F295C245083E8010F8594FBFFFF0F297C24700F28BC24400200000F28AC24A0010000660FFEAC24D00000000F28A424C00100000F28DD660FFEA424F00000000F288C24B00100000F28D4660FFE8C24E00000000F288424D0010000660FFE8424A00000008B44242C8B7C2414660F62D9660F6AE90F28CB660F6AE0660F62D00F10068344241410660F6CCA660FEFC8660F6DDA0F110A0F10008B4424100F28CD660F6DEC660FEFD8660F6CCC0F28A424000200000F111883C0100F10078B7C2418660FFE642470660FEFC883442418100F28D4894424100F110F8B7C240C0F288C24F0010000660FFE8C24000100008344240C100F10078B7C241C8344241C10660FEFE80F28842430010000660FFE8424800000000F112F8B7C242C0F28AC24E0010000660FFE6C24500F28DD660F62D0660F62D9660F6AE90F28CB660F6AE00F104610660F6CCA660FEFC8660F6DDA0F114A100F1047100F28CD660F6DEC660FEFD8660F6CCC0F11188B4424140F10008B442418660FEFC80F11088B44240C0F10008B44241C660FEFE80F11280F28AC2440010000660FFEFE660FFEAC24900000000F28A424600100000F28DD660FFEA424100100000F288C24500100000F28D4660FFE4C24600F28842470010000660FFE84242001000083442410108B4424108344241410660F62D98344241810660F6AE90F28CB660F6AE0660F62D00F1046208344240C10660F6CCA660FEFC88344241C100F114A200F104720660F6DDA0F28CD660FEFD8660F6CCC0F11188B44241483442414100F28DF660F6DEC0F28A424800100000F10008B442418660FFEA424C0000000660FEFC883442418100F28D40F11088B44240C0F288C2450020000660FFE8C24B00000008344240C100F10008B44241C660F62D9660FEFE8660F6AF90F288424900100000F28CB660FFE4424300F11288B442410660F62D083C010660F6AE00F1046308344241C10660F6CCA660FEFC8660F6DDA0F114A30894424100F1047300F28CF660F6DFC660FEFD8660F6CCC0F11188B4424140F10008B442418660FEFC80F11088B44240C0F10008B44241C660FEFF881442410D000000081C70001000081442418D000000081C2000100008144241CD000000081C60001000081442414D00000008144240CD00000000F288C24A00100000F289424B00100000F289C24C00100000F28A424D00100000F28AC24E00100000F28B424F00100000F11388B4424240F28BC24000200002D00010000836C242001897C242C8B7C2428894424240F85E2F6FFFFEB068B550C8B75088954241083F8400F829A010000C1E80689442420660F1F4400000F10370F1057100F107F200F106F3085C90F84F60000008BC10F1F80000000000F28DA660FFEDE660FEFEB660F38002DC02B42000F28E5660FFEE70F28C4660FEFC20F28C8660F72F00C660F72D114660FEFC80F28D1660FFED3660FEFEA660F70D293660F38002DD02B42000F28DD660F70ED4E660FFEDC660F70E3390F28C3660FEFC10F28C8660F72F007660F72D119660FEFC8660FFED1660FEFEA660F38002DC02B4200660FFEE50F28C4660FEFC10F28D8660F72F00C660F72D314660FEFD80F28C3660FFEC2660F70F039660FEFE8660F38002DD02B42000F28C5660F70ED4E660FFEC4660F70F8930F28C8660FEFCB0F28D1 }

    condition:

        uint16(0) == 0x5a4d and
        filesize < 400KB and
        all of them
}

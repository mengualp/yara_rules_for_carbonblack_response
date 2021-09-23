/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"


rule Win32Toxic : tox ransomware
{
meta:
 		score = 7
	author = "@GelosSnake"
	date = "2015-06-02"
	description = "https://blogs.mcafee.com/mcafee-labs/meet-tox-ransomware-for-the-rest-of-us"
	hash0 = "70624c13be4d8a4c1361be38b49cb3eb"
	hash1 = "4f20d25cd3ae2e5c63d451d095d97046"
	hash2 = "e0473434cc83b57c4b579d585d4c4c57"
	hash3 = "c52090d184b63e5cc71b524153bb079e"
	hash4 = "7ac0b49baba9914b234cde62058c96a5"
	hash5 = "048c007de4902b6f4731fde45fa8e6a9"
	hash6 = "238ef3e35b14e304c87b9c62f18953a9"
	hash7 = "8908ccd681f66429c578a889e6e708e1"
	hash8 = "de9fe2b7d9463982cc77c78ee51e4d51"
	hash9 = "37add8d26a35a3dc9700b92b67625fa4"
	hash10 = "a0f30e89a3431fca1d389f90dba1d56e"
	hash11 = "d4d0658302c731003bf0683127618bd9"
	hash12 = "d1d89e1c7066f41c1d30985ac7b569db"
	hash13 = "97d52d7281dfae8ff9e704bf30ce2484"
	hash14 = "2cc85be01e86e0505697cf61219e66da"
	hash15 = "02ecfb44b9b11b846ea8233d524ecda3"
	hash16 = "703a6ebe71131671df6bc92086c9a641"
	hash17 = "df23629b4a4aed05d6a453280256c05a"
	hash18 = "07466ff2572f16c63e1fee206b081d11"
	hash19 = "792a1c0971775d32bad374b288792468"
	hash20 = "fb7fd5623fa6b7791a221fad463223cd"
	hash21 = "83a562aab1d66e5d170f091b2ae6a213"
	hash22 = "99214c8c9ff4653b533dc1b19a21d389"
	hash23 = "a92aec198eee23a3a9a145e64d0250ee"
	hash24 = "e0f7e6b96ca72b9755965b9dac3ce77e"
	hash25 = "f520fc947a6d5edb87aa01510bee9c8d"
	hash26 = "6d7babbe5e438539a9fa2c5d6128d3b4"
	hash27 = "3133c2231fcee5d6b0b4c988a5201da1"
	hash28 = "e5b1d198edc413376e0c0091566198e4"
	hash29 = "50515b5a6e717976823895465d5dc684"
	hash30 = "510389e8c7f22f2076fc7c5388e01220"
	hash31 = "60573c945aa3b8cfaca0bdb6dd7d2019"
	hash32 = "394187056697463eba97382018dfe151"
	hash33 = "045a5d3c95e28629927c72cf3313f4cd"
	hash34 = "70951624eb06f7db0dcab5fc33f49127"
	hash35 = "5def9e3f7b15b2a75c80596b5e24e0f4"
	hash36 = "35a42fb1c65ebd7d763db4abb26d33b0"
	hash37 = "b0030f5072864572f8e6ba9b295615fc"
	hash38 = "62706f48689f1ba3d1d79780010b8739"
	hash39 = "be86183fa029629ee9c07310cd630871"
	hash40 = "9755c3920d3a38eb1b5b7edbce6d4914"
	hash41 = "cb42611b4bed97d152721e8db5abd860"
	hash42 = "5475344d69fc6778e12dc1cbba23b382"
	hash43 = "8c1bf70742b62dec1b350a4e5046c7b6"
	hash44 = "6a6541c0f63f45eff725dec951ec90a7"
	hash45 = "a592c5bee0d81ee127cbfbcb4178afe8"
	hash46 = "b74c6d86ec3904f4d73d05b2797f1cc3"
	hash47 = "28d76fd4dd2dbfc61b0c99d2ad08cd8e"
	hash48 = "fc859ae67dc1596ac3fdd79b2ed02910"
	hash49 = "cb65d5e929da8ff5c8434fd8d36e5dfb"
	hash50 = "888dd1acce29cd37f0696a0284ab740a"
	hash51 = "0e3e231c255a5eefefd20d70c247d5f0"
	hash52 = "e5ebe35d934106f9f4cebbd84e04534b"
	hash53 = "3b580f1fa0c961a83920ce32b4e4e86d"
	hash54 = "d807a704f78121250227793ea15aa9c4"
	hash55 = "db462159bddc0953444afd7b0d57e783"
	hash56 = "2ed4945fb9e6202c10fad0761723cb0e"
	hash57 = "51183ab4fd2304a278e36d36b5fb990c"
	hash58 = "65d602313c585c8712ea0560a655ddeb"
	hash59 = "0128c12d4a72d14bb67e459b3700a373"
	hash60 = "5d3dfc161c983f8e820e59c370f65581"
	hash61 = "d4dd475179cd9f6180d5b931e8740ed6"
	hash62 = "5dd3782ce5f94686448326ddbbac934c"
	hash63 = "c85c6171a7ff05d66d497ad0d73a51ed"
	hash64 = "b42dda2100da688243fe85a819d61e2e"
	hash65 = "a5cf8f2b7d97d86f4d8948360f3db714"
	hash66 = "293cae15e4db1217ea72581836a6642c"
	hash67 = "56c3a5bae3cb1d0d315c1353ae67cf58"
	hash68 = "c86dc1d0378cc0b579a11d873ac944e7"
	hash69 = "54cef0185798f3ec1f4cb95fad4ddd7c"
	hash70 = "eb2eff9838043b67e8024ccadcfe1a8f"
	hash71 = "78778fe62ee28ef949eec2e7e5961ca8"
	hash72 = "e75c5762471a490d49b79d01da745498"
	hash73 = "1564d3e27b90a166a0989a61dc3bd646"
	hash74 = "59ba111403842c1f260f886d69e8757d"
	hash75 = "d840dfbe52a04665e40807c9d960cccc"
	hash76 = "77f543f4a8f54ecf84b15da8e928d3f9"
	hash77 = "bd9512679fdc1e1e89a24f6ebe0d5ad8"
	hash78 = "202f042d02be4f6469ed6f2e71f42c04"
	hash79 = "28f827673833175dd9094002f2f9b780"
	hash80 = "0ff10287b4c50e0d11ab998a28529415"
	hash81 = "644daa2b294c5583ce6aa8bc68f1d21f"
	hash82 = "1c9db47778a41775bbcb70256cc1a035"
	hash83 = "c203bc5752e5319b81cf1ca970c3ca96"
	hash84 = "656f2571e4f5172182fc970a5b21c0e7"
	hash85 = "c17122a9864e3bbf622285c4d5503282"
	hash86 = "f9e3a9636b45edbcef2ee28bd6b1cfbb"
	hash87 = "291ff8b46d417691a83c73a9d3a30cc9"
	hash88 = "1217877d3f7824165bb28281ccc80182"
	hash89 = "18419d775652f47a657c5400d4aef4a3"
	hash90 = "04417923bf4f2be48dd567dfd33684e2"
	hash91 = "31efe902ec6a5ab9e6876cfe715d7c84"
	hash92 = "a2e4472c5097d7433b91d65579711664"
	hash93 = "98854d7aba1874c39636ff3b703a1ed1"
	hash94 = "5149f0e0a56b33e7bbed1457aab8763f"
	hash95 = "7a4338193ce12529d6ae5cfcbb1019af"
	hash96 = "aa7f37206aba3cbe5e11d336424c549a"
	hash97 = "51cad5d45cdbc2940a66d044d5a8dabf"
	hash98 = "85edb7b8dee5b60e3ce32e1286207faa"
	hash99 = "34ca5292ae56fea78ba14abe8fe11f06"
	hash100 = "154187f07621a9213d77a18c0758960f"
	hash101 = "4e633f0478b993551db22afddfa22262"
	hash102 = "5c50e4427fe178566cada96b2afbc2d4"
	hash103 = "263001ac21ef78c31f4ca7ad2e7f191d"
	hash104 = "53fd9e7500e3522065a2dabb932d9dc5"
	hash105 = "48043dc55718eb9e5b134dac93ebb5f6"
	hash106 = "ca19a1b85363cfed4d36e3e7b990c8b6"
	hash107 = "41b5403a5443a3a84f0007131173c126"
	hash108 = "6f3833bc6e5940155aa804e58500da81"
	hash109 = "9bd50fcfa7ca6e171516101673c4e795"
	hash110 = "6d52ba0d48d5bf3242cd11488c75b9a7"
	hash111 = "c52afb663ff4165e407f53a82e34e1d5"
	hash112 = "5a16396d418355731c6d7bb7b21e05f7"
	hash113 = "05559db924e71cccee87d21b968d0930"
	hash114 = "824312bf8e8e7714616ba62997467fa8"
	hash115 = "dfec435e6264a0bfe47fc5239631903c"
	hash116 = "3512e7da9d66ca62be3418bead2fb091"
	hash117 = "7ad4df88db6f292e7ddeec7cf63fa2bc"
	hash118 = "d512da73d0ca103df3c9e7c074babc99"
	hash119 = "c622b844388c16278d1bc768dcfbbeab"
	hash120 = "170ffa1cd19a1cecc6dae5bdd10efb58"
	hash121 = "3a19c91c1c0baa7dd4a9def2e0b7c3e9"
	hash122 = "3b7ce3ceb8d2b85ab822f355904d47ce"
	hash123 = "a7bac2ace1f04a7ad440bd2f5f811edc"
	hash124 = "66594a62d8c98e1387ec8deb3fe39431"
	hash125 = "a1add9e5d7646584fd4140528d02e4c3"
	hash126 = "11328bbf5a76535e53ab35315321f904"
	hash127 = "048f19d79c953e523675e96fb6e417a9"
	hash128 = "eb65fc2922eafd62defd978a3215814b"
	hash129 = "51cc9987f86a76d75bf335a8864ec250"
	hash130 = "a7f91301712b5a3cc8c3ab9c119530ce"
	hash131 = "de976a5b3d603161a737e7b947fdbb9a"
	hash132 = "288a3659cc1aec47530752b3a31c232b"
	hash133 = "91da679f417040558059ccd5b1063688"
	hash134 = "4ce9a0877b5c6f439f3e90f52eb85398"
	hash135 = "1f9e097ff9724d4384c09748a71ef99d"
	hash136 = "7d8a64a94e71a5c24ad82e8a58f4b7e6"
	hash137 = "db119e3c6b57d9c6b739b0f9cbaeb6fd"
	hash138 = "52c9d25179bf010a4bb20d5b5b4e0615"
	hash139 = "4b9995578d51fb891040a7f159613a99"
	sample_filetype = "exe"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "n:;;t:;;t:;;t:;;t:;;t:;;t:;;t:;;t:;;t:;;t:;;t:;;t:;;t;<<t;<<t;<<t;<<t;<<t;<<t;<<t;<<t<<<t;<<t;<<t;<<"
	$string1 = "t;<<t;<<t<<<t<<"
	$string2 = ">>><<<"
condition:
	2 of them
}

        

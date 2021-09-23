rule Intezer_Vaccine_Trickbot
{
	meta:
 		score = 7
		copyright = "Intezer Labs"
		description = "Automatic YARA vaccination rule created based on the file's genes"
		author = "Intezer Labs"
		reference = "https://analyze.intezer.com"
		date = "2019-10-30"
		sha256 = "338a781fbabc5e80821a1a8a7a334232cd30cc12b521deeb359899fae88603ae"
	strings:
		$268446021_332 = { 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 89 ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? FF 1? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? FF 1? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? FF 1? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? FF 1? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? FF 1? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? FF 1? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? FF 1? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? FF 1? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? FF 1? ?? ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 0F 84 }
		$268498674_202 = { 48 ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 8B ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 8B ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 8B ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? 0F B7 ?? 89 ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? ?? ?? 83 ?? ?? ?? ?? 0F 86 }
		$268469893_197 = { 44 ?? ?? 4A ?? ?? ?? 48 ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 44 ?? ?? 4A ?? ?? ?? 48 ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? 44 ?? ?? 4A ?? ?? ?? FF 1? ?? ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? ?? FF 1? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? FF 1? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B7 ?? ?? ?? 0F B7 ?? ?? ?? 44 ?? ?? ?? ?? ?? 44 ?? ?? ?? ?? ?? 0F B7 ?? ?? ?? 44 ?? ?? ?? ?? ?? 44 ?? ?? ?? ?? 89 ?? ?? ?? 89 ?? ?? ?? 89 ?? ?? ?? 44 ?? ?? ?? ?? 4C ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B7 ?? ?? 4C ?? ?? ?? EB }
		$268529344_184 = { 5? 5? 5? 5? 41 ?? 41 ?? 41 ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 33 ?? 45 ?? ?? 48 ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? ?? 89 ?? ?? 66 ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? F2 ?? ?? ?? ?? F2 ?? ?? ?? ?? ?? ?? ?? F2 ?? ?? ?? ?? F2 ?? ?? ?? ?? ?? ?? ?? 4C ?? ?? ?? ?? ?? ?? 4C ?? ?? ?? ?? 48 ?? ?? F2 ?? ?? ?? ?? 48 ?? ?? ?? ?? 66 ?? ?? ?? ?? ?? 41 ?? ?? ?? 0F 10 ?? ?? ?? 4C ?? ?? ?? 4C ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? 0F 11 ?? ?? ?? ?? ?? 0F 11 ?? ?? 0F 11 ?? ?? ?? ?? ?? 4C ?? ?? ?? ?? ?? ?? 44 ?? ?? 0F 11 ?? ?? FF 5? ?? 8B ?? 85 ?? 79 }
		$268506144_165 = { 48 ?? ?? 48 ?? ?? ?? 4C ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 5? 5? 5? 41 ?? 41 ?? 41 ?? 41 ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 33 ?? 49 ?? ?? 4C ?? ?? 44 ?? ?? FF 1? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? 8B ?? E8 ?? ?? ?? ?? 41 ?? ?? ?? ?? ?? 4C ?? ?? ?? ?? 48 ?? ?? ?? 41 ?? ?? 44 ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? E8 ?? ?? ?? ?? 4C ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 44 ?? ?? 41 ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 49 ?? ?? E8 ?? ?? ?? ?? 8B ?? 85 ?? 0F 84 }
		$268445686_154 = { 48 ?? ?? ?? 33 ?? 41 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 45 ?? ?? 45 ?? ?? 33 ?? 33 ?? FF 1? ?? ?? ?? ?? 45 ?? ?? 45 ?? ?? 33 ?? 33 ?? 48 ?? ?? ?? ?? ?? ?? FF 1? ?? ?? ?? ?? 45 ?? ?? 33 ?? 48 ?? ?? ?? ?? ?? ?? 41 ?? ?? ?? 44 ?? ?? 8B ?? FF 1? ?? ?? ?? ?? 4C ?? ?? ?? ?? ?? ?? 4C ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? FF 1? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? BB ?? ?? ?? ?? 4C ?? ?? ?? 48 ?? ?? 89 ?? ?? ?? 4D ?? ?? 89 ?? ?? ?? 89 ?? ?? ?? FF 1? ?? ?? ?? ?? 85 ?? 0F 84 }
		$268530223_145 = { 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? FF 1? ?? ?? ?? ?? 48 ?? ?? ?? 0F 10 ?? ?? F2 ?? ?? ?? ?? 0F 29 ?? ?? ?? ?? ?? F2 ?? ?? ?? ?? ?? ?? ?? FF 1? ?? ?? ?? ?? 0F 10 ?? ?? F2 ?? ?? ?? ?? 48 ?? ?? ?? 0F 29 ?? ?? ?? ?? ?? F2 ?? ?? ?? ?? ?? ?? ?? FF 1? ?? ?? ?? ?? 0F 10 ?? ?? F2 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? 0F 29 ?? ?? ?? ?? ?? F2 ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? 74 }
		$268529698_136 = { 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? FF 1? ?? ?? ?? ?? 48 ?? ?? ?? 0F 10 ?? ?? F2 ?? ?? ?? ?? 0F 29 ?? ?? ?? ?? ?? F2 ?? ?? ?? ?? ?? ?? ?? FF 1? ?? ?? ?? ?? 0F 10 ?? ?? F2 ?? ?? ?? ?? B8 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 66 ?? ?? ?? 0F 29 ?? ?? ?? ?? ?? F2 ?? ?? ?? ?? ?? ?? ?? FF 1? ?? ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? 75 }
		$268519016_131 = { 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? E8 ?? ?? ?? ?? 4C ?? ?? ?? 4C ?? ?? ?? 4B ?? ?? ?? ?? 4C ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? BA ?? ?? ?? ?? 48 ?? ?? ?? ?? E8 ?? ?? ?? ?? 4C ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 45 ?? ?? 33 ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? F7 ?? 48 ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? E8 ?? ?? ?? ?? 4C ?? ?? 42 ?? ?? ?? ?? 4E ?? ?? ?? ?? 6B ?? ?? 48 ?? 4C ?? ?? 0F 8E }
		$268518816_127 = { 48 ?? ?? ?? ?? 5? 5? 5? 41 ?? 41 ?? 41 ?? 41 ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 33 ?? 48 ?? ?? 48 ?? ?? ?? ?? 44 ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 44 ?? ?? 8B ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? E8 ?? ?? ?? ?? 41 ?? ?? ?? ?? ?? 4C ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? 41 ?? ?? 45 ?? ?? FF 1? ?? ?? ?? ?? 85 ?? 0F 84 }
		$268522402_126 = { 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B ?? ?? ?? 44 ?? ?? ?? ?? 44 ?? ?? ?? ?? 89 ?? ?? ?? 8B ?? ?? ?? ?? ?? 4C ?? ?? ?? ?? BA ?? ?? ?? ?? 49 ?? ?? 89 ?? ?? ?? E8 ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 4C ?? ?? ?? ?? ?? ?? 03 ?? 48 ?? ?? ?? 4D ?? ?? 89 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 49 ?? ?? 48 ?? ?? 44 ?? ?? 89 ?? ?? ?? ?? ?? 4D ?? ?? 45 ?? ?? E8 ?? ?? ?? ?? 84 ?? 0F 84 }
		$268534864_123 = { 48 ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 4C ?? ?? ?? 5? 41 ?? 41 ?? 41 ?? 41 ?? 48 ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 45 ?? ?? 4C ?? ?? 4C ?? ?? ?? ?? 4C ?? ?? ?? ?? 4C ?? ?? ?? ?? 44 ?? ?? ?? ?? 44 ?? ?? ?? ?? 44 ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 49 ?? ?? 4C ?? ?? 45 ?? ?? 41 ?? ?? 44 ?? ?? ?? ?? 41 ?? ?? ?? 4C ?? ?? ?? 0F 85 }
		$268509936_115 = { 4C ?? ?? ?? ?? 89 ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? ?? 03 ?? 8B ?? 89 ?? ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? ?? 39 ?? ?? ?? ?? ?? ?? 0F 82 }
		$268516256_114 = { 48 ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 5? 41 ?? 41 ?? 48 ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 83 ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? ?? 4D ?? ?? 4C ?? ?? 33 ?? E8 ?? ?? ?? ?? 8D ?? ?? 48 ?? ?? ?? 33 ?? 44 ?? ?? E8 ?? ?? ?? ?? 83 ?? ?? 4C ?? ?? ?? 45 ?? ?? 33 ?? 48 ?? ?? 89 ?? ?? 89 ?? ?? 89 ?? ?? 89 ?? ?? FF 1? ?? ?? ?? ?? 85 ?? 0F 84 }
		$268515483_111 = { 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? 4C ?? ?? ?? ?? 4C ?? ?? ?? ?? ?? ?? 4C ?? ?? ?? 4C ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? BA ?? ?? ?? ?? 48 ?? ?? ?? ?? E8 ?? ?? ?? ?? 4C ?? ?? ?? ?? ?? ?? 41 ?? ?? ?? ?? 0F 86 }
		$268454000_107 = { 48 ?? ?? ?? ?? 5? 5? 5? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? FF 1? ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? FF 1? ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? 0F 84 }
		$268453664_104 = { 48 ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 41 ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? 49 ?? ?? 48 ?? ?? 33 ?? 48 ?? ?? ?? ?? 33 ?? 44 ?? ?? ?? 45 ?? ?? E8 ?? ?? ?? ?? 44 ?? ?? ?? 48 ?? ?? ?? ?? 33 ?? E8 ?? ?? ?? ?? 44 ?? ?? ?? ?? 44 ?? ?? ?? 44 ?? ?? ?? ?? ?? ?? ?? 66 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? 0F 84 }
		$268464239_102 = { 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? 0F B7 ?? 66 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? 48 ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? 0F B7 ?? ?? ?? ?? ?? ?? 8B ?? E8 ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? ?? 75 }
		$268543017_96 = { 48 ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? FF 1? ?? ?? ?? ?? 33 ?? 48 ?? ?? ?? ?? 44 ?? ?? ?? E8 ?? ?? ?? ?? 4C ?? ?? ?? ?? 48 ?? ?? ?? ?? 4C ?? ?? ?? ?? 48 ?? ?? ?? ?? 4C ?? ?? ?? ?? 4C ?? ?? ?? ?? 45 ?? ?? 45 ?? ?? 33 ?? 48 ?? ?? 44 ?? ?? ?? ?? 44 ?? ?? ?? ?? FF 1? ?? ?? ?? ?? 85 ?? 0F 85 }
		$268454624_95 = { 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 5? 41 ?? 41 ?? 41 ?? 41 ?? 48 ?? ?? 48 ?? ?? ?? ?? ?? ?? 45 ?? ?? 49 ?? ?? 45 ?? ?? 4C ?? ?? 48 ?? ?? ?? 45 ?? ?? ?? 45 ?? ?? 33 ?? 4C ?? ?? ?? 4C ?? ?? ?? 44 ?? ?? ?? 41 ?? ?? 41 ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? FF 1? ?? ?? ?? ?? 85 ?? 0F 84 }
		$268469280_94 = { 48 ?? ?? ?? ?? 5? 5? 5? 41 ?? 41 ?? 41 ?? 41 ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 45 ?? ?? B8 ?? ?? ?? ?? 4D ?? ?? 8B ?? 4C ?? ?? 66 ?? ?? ?? ?? ?? ?? 4C ?? ?? ?? ?? 44 ?? ?? ?? 44 ?? ?? ?? ?? 4C ?? ?? ?? 41 ?? ?? 41 ?? ?? 89 ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 85 ?? 0F 84 }
		$268480382_94 = { 41 ?? ?? ?? 48 ?? ?? ?? 33 ?? 66 ?? ?? FF 1? ?? ?? ?? ?? 41 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? E8 ?? ?? ?? ?? 45 ?? ?? ?? ?? 48 ?? ?? ?? 4D ?? ?? 48 ?? ?? 48 ?? ?? E8 ?? ?? ?? ?? 4E ?? ?? ?? B8 ?? ?? ?? ?? 66 ?? ?? ?? 45 ?? ?? 8D ?? ?? 4C ?? ?? 66 ?? ?? ?? 0F B7 ?? 66 ?? ?? 74 }
		$268540899_92 = { 44 ?? ?? ?? ?? ?? ?? 48 ?? ?? 41 ?? ?? E8 ?? ?? ?? ?? 44 ?? ?? ?? 4D ?? ?? 4C ?? ?? ?? 48 ?? ?? 8B ?? ?? ?? ?? ?? 89 ?? ?? 8B ?? ?? ?? ?? ?? 49 ?? ?? 89 ?? ?? 8B ?? ?? ?? ?? ?? 49 ?? ?? 89 ?? ?? 33 ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 ?? 85 ?? 0F 84 }
		$268466378_92 = { 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? E8 ?? ?? ?? ?? 8D ?? ?? 48 ?? ?? ?? ?? E8 ?? ?? ?? ?? 4C ?? ?? ?? ?? 4C ?? ?? ?? 4D ?? ?? BA ?? ?? ?? ?? 48 ?? ?? 4C ?? ?? ?? ?? E8 ?? ?? ?? ?? 4C ?? ?? ?? ?? ?? ?? 49 ?? ?? ?? 33 ?? 48 ?? ?? E8 ?? ?? ?? ?? 85 ?? 0F 84 }
		$268477782_91 = { 41 ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? 33 ?? 45 ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? 66 ?? ?? ?? ?? ?? 41 ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? 66 ?? ?? ?? ?? ?? 44 ?? ?? ?? ?? 44 ?? ?? ?? ?? 66 ?? ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? ?? ?? FF 5? ?? 85 ?? 0F 88 }
		$268523872_88 = { 48 ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 5? 41 ?? 41 ?? 48 ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 83 ?? ?? ?? 83 ?? ?? ?? 4D ?? ?? 41 ?? ?? 4C ?? ?? 33 ?? 48 ?? ?? ?? 44 ?? ?? ?? 45 ?? ?? 33 ?? 33 ?? C7 ?? ?? ?? ?? ?? ?? FF 1? ?? ?? ?? ?? 85 ?? 0F 84 }
		$268461472_88 = { 5? 5? 5? 5? 41 ?? 41 ?? 41 ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 45 ?? ?? 4C ?? ?? 4C ?? ?? ?? ?? ?? ?? 4C ?? ?? ?? ?? ?? ?? 44 ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 41 ?? ?? 41 ?? ?? 45 ?? ?? 4C ?? ?? ?? 0F 84 }
		$268449716_87 = { 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 4C ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? 4C ?? ?? ?? ?? 48 ?? ?? ?? ?? 4C ?? ?? ?? ?? 41 ?? ?? ?? ?? ?? 48 ?? ?? 4C ?? ?? ?? ?? 4C ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 ?? 0F 84 }
		$268483152_86 = { 48 ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 4C ?? ?? ?? 5? 41 ?? 41 ?? 48 ?? ?? 48 ?? ?? ?? 33 ?? 4D ?? ?? 49 ?? ?? 48 ?? ?? ?? 48 ?? ?? 89 ?? ?? 44 ?? ?? ?? 45 ?? ?? BA ?? ?? ?? ?? 45 ?? ?? C7 ?? ?? ?? ?? ?? ?? FF 1? ?? ?? ?? ?? 4C ?? ?? 48 ?? ?? ?? 0F 84 }
		$268518128_85 = { 48 ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 5? 41 ?? 41 ?? 48 ?? ?? ?? 33 ?? 49 ?? ?? 4C ?? ?? 48 ?? ?? ?? 21 ?? ?? C7 ?? ?? ?? ?? ?? ?? 44 ?? ?? ?? 45 ?? ?? BA ?? ?? ?? ?? 45 ?? ?? 33 ?? C7 ?? ?? ?? ?? ?? ?? FF 1? ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? ?? 0F 84 }
		$268458586_83 = { 44 ?? ?? ?? ?? 44 ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? 4C ?? ?? ?? 44 ?? ?? ?? 45 ?? ?? ?? ?? 48 ?? ?? ?? ?? 41 ?? ?? C1 ?? ?? 41 ?? ?? C1 ?? ?? 41 ?? ?? C1 ?? ?? 41 ?? ?? 6B ?? ?? C1 ?? ?? 81 E? ?? ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? 3B ?? 0F 82 }
		$268447593_82 = { 0F BE ?? ?? ?? 0F BE ?? ?? ?? 83 ?? ?? C1 ?? ?? 8D ?? ?? 88 ?? ?? ?? 0F BE ?? ?? ?? 83 ?? ?? C1 ?? ?? 0F BE ?? ?? ?? 83 ?? ?? C1 ?? ?? 03 ?? 88 ?? ?? ?? 0F BE ?? ?? ?? 83 ?? ?? C1 ?? ?? 0F BE ?? ?? ?? 03 ?? 88 ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? EB }
		$268494007_82 = { 41 ?? ?? ?? ?? ?? ?? ?? 44 ?? ?? ?? 49 ?? ?? 41 ?? ?? 41 ?? ?? 0F AF ?? 41 ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? E8 ?? ?? ?? ?? 44 ?? ?? ?? 48 ?? ?? 48 ?? ?? E8 ?? ?? ?? ?? 44 ?? ?? ?? 49 ?? ?? 48 ?? ?? E8 ?? ?? ?? ?? 41 ?? ?? 44 ?? ?? 0F 82 }
		$268463202_82 = { 83 ?? ?? ?? ?? 83 ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 44 ?? ?? ?? ?? 48 ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? ?? ?? 4C ?? ?? ?? ?? 4C ?? ?? 33 ?? 48 ?? ?? ?? ?? FF 1? ?? ?? ?? ?? 8B ?? ?? ?? 85 ?? 0F 45 ?? ?? ?? EB }
		$268481984_81 = { 48 ?? ?? ?? ?? 5? 5? 5? 41 ?? 41 ?? 41 ?? 41 ?? 48 ?? ?? 48 ?? ?? ?? 45 ?? ?? 4D ?? ?? 4C ?? ?? 4C ?? ?? 33 ?? 41 ?? ?? ?? ?? ?? 49 ?? ?? 41 ?? ?? 4C ?? ?? ?? 4C ?? ?? ?? 4C ?? ?? ?? 44 ?? ?? ?? E8 ?? ?? ?? ?? BF ?? ?? ?? ?? 45 ?? ?? ?? 0F 84 }
		$268447291_81 = { 0F BE ?? ?? ?? 0F BE ?? ?? ?? 83 ?? ?? C1 ?? ?? 8D ?? ?? 88 ?? ?? ?? 0F BE ?? ?? ?? 83 ?? ?? C1 ?? ?? 0F BE ?? ?? ?? 83 ?? ?? C1 ?? ?? 03 ?? 88 ?? ?? ?? 0F BE ?? ?? ?? 83 ?? ?? C1 ?? ?? 0F BE ?? ?? ?? 03 ?? 88 ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? EB }
		$268508143_79 = { 48 ?? ?? ?? ?? F2 ?? ?? ?? ?? ?? B8 ?? ?? ?? ?? 66 ?? ?? ?? ?? 48 ?? ?? ?? ?? FF C? F2 ?? ?? ?? ?? 89 ?? ?? ?? 48 ?? ?? 4C ?? ?? ?? ?? 0F 10 ?? ?? ?? 48 ?? ?? ?? ?? 0F 29 ?? ?? ?? FF 5? ?? 48 ?? ?? ?? ?? 8B ?? FF 1? ?? ?? ?? ?? 85 ?? 78 }
		$268507690_79 = { F2 ?? ?? ?? ?? ?? 66 ?? ?? ?? ?? 48 ?? ?? ?? ?? FF C? 48 ?? ?? ?? ?? 4C ?? ?? ?? ?? F2 ?? ?? ?? ?? 89 ?? ?? ?? 89 ?? ?? ?? 48 ?? ?? 0F 10 ?? ?? ?? 48 ?? ?? ?? ?? 0F 29 ?? ?? ?? FF 5? ?? 48 ?? ?? ?? ?? 8B ?? FF 1? ?? ?? ?? ?? 85 ?? 0F 88 }
		$268444438_78 = { 21 ?? ?? ?? ?? ?? 21 ?? ?? ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 4C ?? ?? ?? ?? 4C ?? ?? ?? ?? ?? ?? 33 ?? 48 ?? ?? ?? ?? FF 1? ?? ?? ?? ?? 85 ?? 0F 84 }
		$268455952_78 = { 48 ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 5? 41 ?? 41 ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 83 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? ?? 49 ?? ?? 4D ?? ?? 44 ?? ?? E8 ?? ?? ?? ?? 85 ?? 0F 84 }
		$268454723_77 = { 45 ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? C7 ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? 44 ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? 4C ?? ?? ?? 4C ?? ?? ?? ?? 45 ?? ?? ?? 45 ?? ?? ?? 48 ?? ?? ?? 45 ?? ?? 44 ?? ?? ?? ?? FF 1? ?? ?? ?? ?? 85 ?? 0F 84 }
		$268533808_77 = { 48 ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 41 ?? 48 ?? ?? ?? 33 ?? 4D ?? ?? 49 ?? ?? 48 ?? ?? ?? 48 ?? ?? 89 ?? ?? 44 ?? ?? ?? 45 ?? ?? BA ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? FF 1? ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? ?? 0F 84 }
		$268468656_77 = { 48 ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 5? 5? 41 ?? 48 ?? ?? ?? 33 ?? 49 ?? ?? 4C ?? ?? 48 ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? 44 ?? ?? ?? 45 ?? ?? BA ?? ?? ?? ?? 89 ?? ?? 8B ?? C7 ?? ?? ?? ?? ?? ?? FF 1? ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? ?? 0F 84 }
		$268499399_75 = { 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? 0F B7 ?? 89 ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? 83 ?? ?? ?? ?? 0F 86 }
		$268523019_74 = { 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B ?? ?? 48 ?? ?? ?? ?? F7 ?? 4C ?? ?? 1B ?? 45 ?? ?? 81 E? ?? ?? ?? ?? 89 ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? FF 1? ?? ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? 0F 84 }
		$268479028_73 = { 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? E8 ?? ?? ?? ?? 4C ?? ?? ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 4C ?? ?? 48 ?? ?? ?? ?? 83 ?? ?? ?? ?? 33 ?? 33 ?? FF 1? ?? ?? ?? ?? 33 ?? 39 ?? ?? ?? ?? ?? ?? 0F 84 }
		$268540995_73 = { 8B ?? ?? 44 ?? ?? ?? 44 ?? ?? ?? 89 ?? ?? ?? ?? ?? 8B ?? ?? 89 ?? ?? 89 ?? ?? ?? ?? ?? 8B ?? ?? 49 ?? ?? 89 ?? ?? ?? ?? ?? 48 ?? ?? ?? 49 ?? ?? 48 ?? ?? ?? ?? 44 ?? ?? ?? ?? ?? ?? FF 1? ?? ?? ?? ?? 45 ?? ?? 85 ?? 0F 84 }
		$268459888_72 = { 48 ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 5? 5? 41 ?? 48 ?? ?? ?? 33 ?? 44 ?? ?? 45 ?? ?? 48 ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? 44 ?? ?? ?? BA ?? ?? ?? ?? 89 ?? ?? C7 ?? ?? ?? ?? ?? ?? FF 1? ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? ?? 0F 84 }
		$268507287_72 = { 8A ?? ?? 8A ?? ?? 33 ?? C0 ?? ?? 8A ?? C0 ?? ?? C0 ?? ?? 80 E? ?? 02 ?? 88 ?? ?? 8A ?? ?? 8A ?? C0 ?? ?? 02 ?? ?? C0 ?? ?? 88 ?? ?? 24 ?? 48 ?? ?? ?? 32 ?? 88 ?? ?? 0F B7 ?? 66 ?? ?? 8A ?? ?? 48 ?? ?? ?? 88 ?? ?? 33 }
		$268505024_72 = { 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 5? 5? 41 ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 83 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? ?? 49 ?? ?? 4C ?? ?? E8 ?? ?? ?? ?? 85 ?? 0F 84 }
		$268462992_71 = { 48 ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 4C ?? ?? ?? 5? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 49 ?? ?? 44 ?? ?? 33 ?? 48 ?? ?? ?? ?? 33 ?? B9 ?? ?? ?? ?? 45 ?? ?? FF 1? ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? 0F 84 }
		$268536096_71 = { 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 5? 41 ?? 41 ?? 41 ?? 41 ?? 48 ?? ?? ?? 8B ?? ?? 4C ?? ?? 48 ?? ?? 33 ?? 33 ?? 41 ?? ?? 89 ?? ?? ?? 4D ?? ?? 45 ?? ?? 8B ?? 8B ?? E8 ?? ?? ?? ?? 4C ?? ?? 48 ?? ?? 0F 84 }
		$268538368_67 = { 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 5? 5? 5? 41 ?? 41 ?? 41 ?? 41 ?? 48 ?? ?? 48 ?? ?? ?? 45 ?? ?? 49 ?? ?? 4D ?? ?? 48 ?? ?? 48 ?? ?? 45 ?? ?? 4C ?? ?? ?? 4C ?? ?? ?? 4C ?? ?? ?? 44 ?? ?? ?? ?? ?? ?? 0F 84 }
		$268466474_67 = { 33 ?? 48 ?? ?? ?? ?? 44 ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 4C ?? ?? ?? ?? ?? ?? 4C ?? ?? ?? ?? 33 ?? 44 ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? FF 1? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 85 ?? 0F 85 }
		$268505376_65 = { 48 ?? ?? ?? ?? 5? 5? 5? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 83 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? ?? 48 ?? ?? E8 ?? ?? ?? ?? 85 ?? 0F 84 }
		$268469378_64 = { 48 ?? ?? ?? 45 ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 44 ?? ?? ?? ?? 44 ?? ?? ?? ?? 44 ?? ?? ?? ?? 44 ?? ?? ?? ?? 45 ?? ?? B2 ?? 44 ?? ?? ?? ?? 44 ?? ?? ?? ?? FF 1? ?? ?? ?? ?? 85 ?? 0F 84 }
		$268506337_64 = { 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? E8 ?? ?? ?? ?? 4C ?? ?? ?? ?? ?? ?? 4C ?? ?? ?? 41 ?? ?? 49 ?? ?? 48 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D ?? ?? 33 ?? 48 ?? ?? E8 ?? ?? ?? ?? 4C ?? ?? 48 ?? ?? 0F 84 }
		$268522280_64 = { 33 ?? 49 ?? ?? E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 4C ?? ?? 8D ?? ?? 4C ?? ?? 4C ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 44 ?? ?? 89 ?? ?? ?? ?? ?? 4D ?? ?? E8 ?? ?? ?? ?? 4C ?? ?? 48 ?? ?? 0F 84 }
		$268442659_63 = { 8B ?? ?? ?? ?? ?? BA ?? ?? ?? ?? 44 ?? ?? ?? 3B ?? 44 ?? ?? ?? 03 ?? 48 ?? ?? ?? ?? ?? ?? 83 ?? ?? 0F 4F ?? 89 ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? 48 }
		$268541099_62 = { 41 ?? ?? ?? 41 ?? ?? ?? ?? 48 ?? ?? ?? 41 ?? ?? ?? ?? 41 ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? 41 ?? ?? ?? ?? ?? 49 ?? ?? 44 ?? ?? 44 ?? ?? FF 1? ?? ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? 0F 84 }
		$268541165_62 = { 48 ?? ?? ?? ?? 41 ?? ?? E8 ?? ?? ?? ?? 45 ?? ?? 33 ?? 48 ?? ?? 48 ?? ?? ?? ?? E8 ?? ?? ?? ?? 4C ?? ?? ?? ?? 48 ?? ?? ?? 45 ?? ?? 4C ?? ?? ?? 49 ?? ?? E8 ?? ?? ?? ?? 45 ?? ?? 85 ?? 0F 84 }
		$268518947_62 = { 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? E8 ?? ?? ?? ?? 4C ?? ?? ?? 4C ?? ?? ?? ?? ?? ?? 4C ?? ?? ?? ?? 48 ?? ?? ?? 41 ?? ?? 4C ?? ?? ?? ?? E8 ?? ?? ?? ?? 44 ?? ?? 44 ?? ?? ?? 39 ?? ?? 0F 8E }
		$268441904_60 = { 33 ?? 41 ?? ?? 44 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 ?? 8B ?? 8D ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 41 ?? ?? 48 ?? ?? 48 ?? ?? E8 ?? ?? ?? ?? 8B ?? 48 ?? ?? E8 ?? ?? ?? ?? 85 ?? 0F 84 }
		$268439680_59 = { 48 ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 5? 41 ?? 41 ?? 41 ?? 41 ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 33 ?? 4C ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 0F 85 }
		$268468064_57 = { 5? 5? 5? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 83 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? ?? E8 ?? ?? ?? ?? 85 ?? 0F 84 }
		$268445216_57 = { 48 ?? ?? ?? ?? 5? 5? 5? 41 ?? 41 ?? 48 ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 83 ?? ?? ?? 33 ?? 49 ?? ?? 4D ?? ?? 44 ?? ?? 48 ?? ?? 83 ?? ?? 0F 82 }
		$268486752_56 = { 48 ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 5? 41 ?? 41 ?? 41 ?? 41 ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 33 ?? 49 ?? ?? 45 ?? ?? 44 ?? ?? 4C ?? ?? 85 ?? 0F 8E }
		$268472138_54 = { 48 ?? ?? ?? ?? ?? ?? 4C ?? ?? ?? ?? 45 ?? ?? 45 ?? ?? BA ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? FF 1? ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? ?? 0F 84 }
		$268442767_52 = { 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? 8B ?? ?? ?? ?? ?? BA ?? ?? ?? ?? 3B ?? 0F 44 ?? 89 }
		$268540624_52 = { 48 ?? ?? ?? ?? 5? 5? 5? 5? 41 ?? 41 ?? 41 ?? 41 ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 33 ?? 48 ?? ?? 48 ?? ?? 8B ?? 48 ?? ?? ?? ?? 39 ?? ?? ?? ?? ?? 0F 85 }
		$268522944_52 = { 48 ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 5? 5? 41 ?? 48 ?? ?? ?? ?? ?? ?? 33 ?? 4D ?? ?? 49 ?? ?? 48 ?? ?? 48 ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? 89 ?? ?? 39 ?? ?? 0F 84 }
		$268454288_51 = { 48 ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 5? 5? 41 ?? 48 ?? ?? ?? ?? ?? ?? 83 ?? ?? ?? 48 ?? ?? 48 ?? ?? ?? 49 ?? ?? 49 ?? ?? 4C ?? ?? E8 ?? ?? ?? ?? 85 ?? 0F 84 }
		$268540845_50 = { 44 ?? ?? ?? 49 ?? ?? 41 ?? ?? ?? ?? ?? 48 ?? ?? ?? 49 ?? ?? 48 ?? ?? 48 ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? FF 1? ?? ?? ?? ?? 4C ?? ?? 48 ?? ?? 0F 84 }
		$268531008_50 = { 5? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? FF 1? ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? 0F 84 }
		$268494171_48 = { 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? E8 ?? ?? ?? ?? 4C ?? ?? ?? ?? 8D ?? ?? 4C ?? ?? 48 ?? ?? E8 ?? ?? ?? ?? 8D ?? ?? 85 ?? 0F 45 ?? 48 ?? ?? E8 }
		$268482069_46 = { 49 ?? ?? ?? E8 ?? ?? ?? ?? 49 ?? ?? ?? 48 ?? ?? E8 ?? ?? ?? ?? 4C ?? ?? ?? 49 ?? ?? ?? 33 ?? 48 ?? ?? 4C ?? ?? E8 ?? ?? ?? ?? 85 ?? 0F 84 }
		$268474946_46 = { 48 ?? ?? ?? ?? 4C ?? ?? ?? ?? 44 ?? ?? 48 ?? ?? 49 ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? 85 ?? 0F 84 }
		$268492100_46 = { 48 ?? ?? ?? ?? 44 ?? ?? 48 ?? ?? ?? ?? 4D ?? ?? 44 ?? ?? 48 ?? ?? ?? ?? 1B ?? 83 ?? ?? 83 ?? ?? 4D ?? ?? 0F 44 ?? 48 ?? ?? ?? ?? 41 ?? C3 }
		$268460688_46 = { 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 5? 5? 41 ?? 41 ?? 41 ?? 48 ?? ?? 48 ?? ?? ?? 33 ?? 45 ?? ?? 4D ?? ?? 49 ?? ?? 4C ?? ?? 49 ?? ?? 85 ?? 0F 84 }
		$268445844_45 = { FF 1? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 89 ?? ?? ?? 4C ?? ?? ?? 48 ?? ?? 4D ?? ?? 89 ?? ?? ?? 89 ?? ?? ?? FF 1? ?? ?? ?? ?? 85 ?? 0F 84 }
		$268452060_45 = { 8B ?? 33 ?? C1 ?? ?? 8D ?? ?? ?? 89 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 ?? B9 ?? ?? ?? ?? 48 ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? 0F 84 }
		$268439743_44 = { 48 ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? FF 1? ?? ?? ?? ?? 33 ?? B9 ?? ?? ?? ?? BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? 0F 84 }
		$268522532_44 = { 44 ?? ?? ?? ?? ?? ?? 4C ?? ?? 33 ?? 45 ?? ?? ?? 48 ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? 0F 84 }
		$268444266_44 = { 48 ?? ?? ?? 48 ?? ?? ?? ?? BB ?? ?? ?? ?? 48 ?? ?? ?? ?? 44 ?? ?? 45 ?? ?? BA ?? ?? ?? ?? 89 ?? ?? ?? FF 1? ?? ?? ?? ?? 85 ?? 0F 84 }
		$268520883_44 = { 8B ?? ?? 48 ?? ?? 44 ?? ?? 0F AF ?? ?? 8B ?? 48 ?? ?? ?? E8 ?? ?? ?? ?? 8B ?? ?? 8D ?? ?? 89 ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? 5? C3 }
		$268474996_43 = { 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 45 ?? ?? 45 ?? ?? FF 1? ?? ?? ?? ?? 85 ?? 0F 88 }
		$268532593_43 = { 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 45 ?? ?? FF 1? ?? ?? ?? ?? 85 ?? 0F 88 }
		$268531392_43 = { 48 ?? ?? 48 ?? ?? ?? 5? 5? 5? 48 ?? ?? ?? ?? ?? ?? 33 ?? 49 ?? ?? 48 ?? ?? 48 ?? ?? C7 ?? ?? ?? ?? ?? ?? 89 ?? ?? 39 ?? ?? 0F 84 }
		$268477706_42 = { 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? FF 9? ?? ?? ?? ?? 85 ?? 0F 88 }
		$268443943_42 = { 48 ?? ?? ?? 41 ?? ?? ?? ?? ?? 48 ?? ?? ?? 41 ?? ?? ?? 4C ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? FF 1? ?? ?? ?? ?? 33 ?? 85 ?? 0F 84 }
		$268529836_42 = { 0F 10 ?? ?? F2 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? 0F 29 ?? ?? F2 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? 74 }
		$268448347_42 = { 48 ?? ?? ?? ?? ?? ?? 33 ?? 41 ?? ?? ?? ?? ?? 44 ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? FF 1? ?? ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? 0F 84 }
		$268445942_41 = { E8 ?? ?? ?? ?? 33 ?? 41 ?? ?? ?? ?? ?? 49 ?? ?? 44 ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? FF 1? ?? ?? ?? ?? 4C ?? ?? 48 ?? ?? 0F 84 }
		$268524585_41 = { 48 ?? ?? ?? ?? 33 ?? 41 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? 4C ?? ?? ?? 49 ?? ?? ?? 33 ?? E8 ?? ?? ?? ?? 85 ?? 0F 84 }
		$268479980_41 = { 49 ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? 49 ?? ?? 49 ?? ?? E8 ?? ?? ?? ?? 84 ?? 0F 85 }
		$268536691_41 = { 48 ?? ?? ?? 48 ?? ?? ?? 4C ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 44 ?? ?? E8 ?? ?? ?? ?? 44 ?? ?? 89 ?? ?? 83 ?? ?? 41 ?? ?? 0F 87 }
		$268446387_41 = { BB ?? ?? ?? ?? 41 ?? ?? ?? ?? ?? 33 ?? 49 ?? ?? 44 ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? FF 1? ?? ?? ?? ?? 4C ?? ?? 48 ?? ?? 0F 84 }
		$268493872_40 = { 48 ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 41 ?? 41 ?? 41 ?? 48 ?? ?? ?? 8B ?? ?? 48 ?? ?? 83 ?? ?? 0F 82 }
		$268507647_39 = { 48 ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? FF 5? ?? 8B ?? B9 ?? ?? ?? ?? 39 ?? ?? ?? ?? ?? 0F 8E }
		$268448183_38 = { 49 ?? ?? FF 1? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? FF C? 4C ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? 0F 84 }
		$268469544_38 = { 48 ?? ?? ?? ?? 41 ?? ?? ?? ?? ?? 48 ?? ?? ?? 41 ?? ?? ?? 4C ?? ?? ?? 48 ?? ?? ?? ?? FF 1? ?? ?? ?? ?? 85 ?? 0F 84 }
		$268464342_37 = { 0F B7 ?? ?? ?? ?? ?? ?? 8B ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 }
		$268472203_37 = { 4C ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 41 ?? ?? 45 ?? ?? 44 ?? ?? ?? 89 ?? ?? 45 ?? ?? E8 ?? ?? ?? ?? 85 ?? 0F 88 }
		$268540680_37 = { 8B ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 4C ?? ?? ?? ?? ?? ?? B8 ?? ?? ?? ?? 66 ?? ?? ?? ?? 0F 85 }
		$268479493_37 = { 48 ?? ?? ?? 4C ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 41 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 44 ?? ?? 89 ?? ?? 83 ?? ?? 0F 85 }
		$268462100_36 = { 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 4C ?? ?? 48 ?? ?? ?? ?? ?? ?? 8B ?? 48 ?? ?? ?? ?? ?? ?? 83 ?? ?? 0F 85 }
		$268515443_36 = { 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? 4C ?? ?? ?? ?? 44 ?? ?? 49 ?? ?? 48 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 ?? 0F 84 }
		$268508065_36 = { 48 ?? ?? ?? ?? 48 ?? ?? FF 5? ?? 48 ?? ?? 4C ?? ?? ?? ?? 33 ?? 48 ?? ?? 48 ?? ?? ?? ?? FF 5? ?? 85 ?? 0F 88 }
		$268493916_36 = { 8B ?? 33 ?? 48 ?? ?? ?? E8 ?? ?? ?? ?? 8B ?? ?? 33 ?? 4C ?? ?? E8 ?? ?? ?? ?? 45 ?? ?? 4C ?? ?? 85 ?? 0F 84 }
		$268444399_35 = { 44 ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 4C ?? ?? 8B ?? 48 ?? ?? ?? ?? FF 1? ?? ?? ?? ?? 85 ?? 0F 84 }
		$268508105_34 = { 48 ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? FF 5? ?? 8B ?? 39 ?? ?? ?? ?? ?? 0F 8E }
		$268506700_34 = { 8B ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? FF C? 48 ?? ?? ?? 49 ?? ?? ?? 89 ?? ?? ?? 3B ?? ?? 0F 8C }
		$268457073_34 = { 48 ?? ?? ?? 4C ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 41 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? 83 ?? ?? 0F 85 }
		$268540807_34 = { 44 ?? ?? ?? 33 ?? 41 ?? ?? ?? ?? ?? 48 ?? ?? 44 ?? ?? ?? ?? FF 1? ?? ?? ?? ?? 4C ?? ?? 48 ?? ?? 0F 84 }
		$268480321_34 = { 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B7 ?? ?? ?? ?? ?? 4C ?? ?? ?? ?? ?? ?? EB }
		$268519151_32 = { E8 ?? ?? ?? ?? 4C ?? ?? 48 ?? ?? ?? 42 ?? ?? ?? ?? 4C ?? ?? ?? ?? 6B ?? ?? 48 ?? 4C ?? ?? 0F 8E }
		$268491929_31 = { 41 ?? ?? ?? 41 ?? ?? ?? ?? 49 ?? ?? ?? C1 ?? ?? C1 ?? ?? 03 ?? 48 ?? 48 ?? ?? 49 ?? ?? 0F 84 }
		$268447697_31 = { 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 0F B6 ?? ?? ?? 88 ?? 48 ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? ?? ?? EB }
		$268445987_30 = { E8 ?? ?? ?? ?? 4C ?? ?? ?? ?? ?? ?? 49 ?? ?? 44 ?? ?? 49 ?? ?? E8 ?? ?? ?? ?? 85 ?? 0F 84 }
		$268477628_30 = { 33 ?? B9 ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? 0F 84 }
		$268541799_30 = { 44 ?? ?? ?? ?? ?? ?? 48 ?? ?? 41 ?? ?? 4C ?? ?? ?? E8 ?? ?? ?? ?? 4C ?? ?? 48 ?? ?? 0F 84 }
		$268448313_30 = { 48 ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 41 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 4C ?? ?? 48 ?? ?? 0F 84 }
		$268447387_30 = { 48 ?? ?? ?? 48 ?? ?? ?? ?? 0F B6 ?? ?? ?? 88 ?? 48 ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? ?? ?? EB }
		$268448494_29 = { 4C ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 41 ?? ?? ?? ?? ?? 49 ?? ?? E8 ?? ?? ?? ?? 85 ?? 0F 85 }
		$268469511_29 = { FF 1? ?? ?? ?? ?? 4C ?? ?? ?? ?? BA ?? ?? ?? ?? 48 ?? ?? FF 1? ?? ?? ?? ?? 85 ?? 0F 84 }
		$268440472_29 = { 4D ?? ?? 49 ?? ?? 48 ?? ?? E8 ?? ?? ?? ?? 41 ?? ?? 48 ?? ?? E8 ?? ?? ?? ?? 84 ?? 0F 84 }
		$268507804_28 = { 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? FF 9? ?? ?? ?? ?? 85 ?? 0F 88 }
		$268533889_28 = { 4C ?? ?? ?? ?? 4C ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? FF 1? ?? ?? ?? ?? 85 ?? 0F 84 }
		$268445308_28 = { 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? 4C ?? ?? ?? 44 ?? ?? ?? E8 ?? ?? ?? ?? 85 ?? 0F 84 }
		$268463920_27 = { 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 0F 85 }
		$268507773_27 = { 48 ?? ?? ?? ?? 33 ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? FF 5? ?? 85 ?? 0F 88 }
		$268524371_27 = { 48 ?? ?? ?? ?? ?? ?? FF 1? ?? ?? ?? ?? 48 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 ?? 0F 84 }
		$268445277_27 = { 48 ?? ?? 48 ?? ?? ?? ?? ?? ?? 4C ?? ?? ?? 44 ?? ?? ?? E8 ?? ?? ?? ?? 85 ?? 0F 84 }
		$268477752_26 = { 48 ?? ?? ?? ?? ?? ?? 4C ?? ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? FF 5? ?? 85 ?? 0F 88 }
		$268441496_26 = { 4C ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? BF ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 0F 85 }
		$268482119_25 = { 4C ?? ?? ?? 49 ?? ?? ?? 33 ?? 49 ?? ?? E8 ?? ?? ?? ?? 45 ?? ?? 85 ?? 0F 84 }
		$268536736_25 = { 48 ?? ?? ?? 48 ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? ?? 41 ?? ?? ?? 0F 85 }
		$268529627_25 = { 48 ?? ?? ?? ?? ?? ?? 45 ?? ?? 48 ?? ?? E8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 0F 8D }
		$268527280_25 = { 4C ?? ?? ?? ?? ?? ?? 49 ?? ?? ?? 33 ?? 49 ?? ?? E8 ?? ?? ?? ?? 85 ?? 0F 84 }
		$268527309_24 = { 49 ?? ?? ?? 4C ?? ?? ?? ?? 49 ?? ?? ?? 33 ?? E8 ?? ?? ?? ?? 85 ?? 0F 84 }
		$268478392_24 = { 48 ?? ?? ?? 48 ?? ?? 48 ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? 0F 84 }
		$268516415_23 = { 8B ?? ?? 33 ?? FF C? 48 ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? 0F 84 }
		$268443917_22 = { 4C ?? ?? ?? BA ?? ?? ?? ?? 48 ?? ?? FF 1? ?? ?? ?? ?? 85 ?? 0F 84 }
		$268524559_22 = { 48 ?? ?? ?? ?? ?? ?? 4D ?? ?? 48 ?? ?? E8 ?? ?? ?? ?? 85 ?? 0F 84 }
		$268516390_21 = { 8D ?? ?? 33 ?? 48 ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? 0F 84 }
		$268463067_21 = { 4C ?? ?? ?? ?? 8D ?? ?? 48 ?? ?? FF 1? ?? ?? ?? ?? 85 ?? 0F 84 }
		$268540721_20 = { 49 ?? ?? ?? ?? 49 ?? ?? 48 ?? ?? ?? 81 3? ?? ?? ?? ?? 0F 85 }
		$268506313_20 = { 33 ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 4C ?? ?? 48 ?? ?? 0F 84 }
		$268462140_19 = { 44 ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? 48 ?? ?? 0F 84 }
		$268461800_19 = { 48 ?? ?? ?? BA ?? ?? ?? ?? FF 1? ?? ?? ?? ?? 85 ?? 0F 84 }
		$268519187_19 = { 48 ?? ?? ?? 48 ?? ?? ?? E8 ?? ?? ?? ?? 33 ?? 85 ?? 0F 84 }
		$268444376_19 = { 8B ?? ?? ?? 33 ?? E8 ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? 0F 84 }
		$268444600_19 = { 48 ?? ?? ?? ?? 48 ?? ?? ?? FF 1? ?? ?? ?? ?? 85 ?? 0F 84 }
		$268541072_18 = { 0F B7 ?? ?? 45 ?? ?? 48 ?? ?? ?? 66 ?? ?? ?? ?? 0F 83 }
		$268514208_17 = { 8B ?? 33 ?? E8 ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? 0F 84 }
		$268458673_17 = { 8B ?? 2B ?? 44 ?? ?? ?? 41 ?? ?? ?? ?? ?? ?? 0F 87 }
		$268510055_16 = { 8B ?? ?? ?? ?? ?? ?? 39 ?? ?? ?? ?? ?? ?? 0F 83 }
		$268464219_16 = { 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? 83 ?? ?? 0F 84 }
		$268532450_16 = { 49 ?? ?? 41 ?? ?? E8 ?? ?? ?? ?? 44 ?? ?? 0F 82 }
		$268459347_15 = { 49 ?? ?? ?? 48 ?? ?? 49 ?? ?? 4C ?? ?? 0F 82 }
		$268508425_15 = { 48 ?? ?? ?? 8B ?? E8 ?? ?? ?? ?? 85 ?? 0F 84 }
		$268491527_14 = { 0F B6 ?? 83 ?? ?? 49 ?? ?? 83 ?? ?? 0F 82 }
		$268510260_14 = { 48 ?? ?? ?? ?? ?? ?? ?? 0F BE ?? 85 ?? 74 }
		$268498900_14 = { 48 ?? ?? ?? ?? 8B ?? ?? 39 ?? ?? ?? 0F 83 }
		$268508260_13 = { BB ?? ?? ?? ?? 3B ?? ?? ?? ?? ?? 0F 8C }
		$268506405_13 = { 48 ?? ?? 89 ?? ?? ?? 41 ?? ?? ?? 0F 8E }
		$268480025_13 = { 48 ?? ?? ?? 44 ?? ?? ?? ?? ?? ?? 0F 84 }
		$268468125_12 = { 48 ?? ?? E8 ?? ?? ?? ?? 85 ?? 0F 84 }
		$268443872_12 = { 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? 0F 84 }
		$268450593_12 = { 4C ?? ?? ?? ?? ?? ?? ?? 85 ?? 0F 8F }

	condition:
		50 of them
}
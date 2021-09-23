rule IndiaAlfa_One
{
	meta:
 		score = 7
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"

	strings:
		$ = "HwpFilePathCheck.dll"
		$ = "AdobeArm.exe"
		$ = "OpenDocument"
		
	condition:
		2 of them

}

rule IndiaAlfa_Two
{
	meta:
 		score = 7
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"

	strings:
		$ = "ExePath: %s\nXlsPath: %s\nTmpPath: %s\n"
		
	condition:
		any of them

}
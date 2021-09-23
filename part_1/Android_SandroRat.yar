import "androguard"


rule SandroRat
{
	meta:
 		score = 7
		author = "Jacob Soo Lead Re"
		date = "21-May-2016"
		description = "This rule detects SandroRat"
		source = "https://blogs.mcafee.com/mcafee-labs/sandrorat-android-rat-targeting-polish-banking-users-via-e-mail-phishing/"

	condition:
		androguard.activity(/net.droidjack.server/i) 
}

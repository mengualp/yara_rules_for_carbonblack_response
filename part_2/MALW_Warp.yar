/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule WarpCode : Warp Family 
{
    meta:
 		score = 7
        description = "Warp code features"
        author = "Seth Hardy"
        last_modified = "2014-07-10"
    
    strings:
        // character replacement
        $ = { 80 38 2B 75 03 C6 00 2D 80 38 2F 75 03 C6 00 5F }
    
    condition:
        any of them
}

rule WarpStrings : Warp Family
{
    meta:
 		score = 7
        description = "Warp Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-07-10"
        
    strings:
        $ = "/2011/n325423.shtml?"
        $ = "wyle"
        $ = "\\~ISUN32.EXE"

    condition:
       any of them
}

rule Warp : Family
{
    meta:
 		score = 7
        description = "Warp"
        author = "Seth Hardy"
        last_modified = "2014-07-10"
        
    condition:
        WarpCode or WarpStrings
}
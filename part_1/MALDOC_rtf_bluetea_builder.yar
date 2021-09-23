rule rtf_bluetea_builder {

    meta:
 		score = 7

	    description = "Rule to detect the RTF files created to distribute BlueTea trojan"
	    author = "Marc Rivero | McAfee ATR Team"
	    date = "2020-04-21"
	    rule_version = "v1"
        malware_type = "maldoc"
        malware_family = "Maldoc:W32/BlueTea"
        actor_type = "Cybercrime"
        actor_group = "Unknown"
	    reference = "https://blog.360totalsecurity.com/en/bluetea-action-drive-the-life-trojan-update-email-worm-module-and-spread-through-covid-19-outbreak/"
	    hash = "4a3eeaed22342967a95302a4f087b25f50d61314facc6791f756dcd113d4f277"

    strings:

      /*

		  7B5C727466315C616465666C616E67313032355C616E73695C616E73696370673933365C7563325C616465666633313530375C64656666305C73747368666462636833313530355C73747368666C6F636833313530365C73747368666869636833313530365C73747368666269305C6465666C616E67313033335C6465666C616E676665323035325C7468656D656C616E67313033335C7468656D656C616E676665323035325C7468656D656C616E676373307B5C666F6E7474626C7B5C66305C6662696469205C66726F6D616E5C6663686172736574305C66707271327B5C2A5C70616E6F73652030323032303630333035303430353032303330347D54696D6573204E657720526F6D616E3B7D0D0A7B5C6631335C6662696469205C666E696C5C66636861727365743133345C66707271327B5C2A5C70616E6F73652030323031303630303033303130313031303130317D5C2763625C2763655C2763635C2765357B5C2A5C66616C742053696D53756E7D3B7D7B5C6633345C6662696469205C66726F6D616E5C6663686172736574305C66707271327B5C2A5C70616E6F73652030323034303530333035303430363033303230347D43616D62726961204D6174683B7D0D0A7B5C6633375C6662696469205C6673776973735C6663686172736574305C66707271327B5C2A5C70616E6F73652030323066303530323032303230343033303230347D43616C696272693B7D7B5C6633385C6662696469205C666E696C5C66636861727365743133345C66707271327B5C2A5C70616E6F73652030323031303630303033303130313031303130317D405C2763625C2763655C2763635C2765353B7D0D0A7B5C666C6F6D616A6F725C6633313530305C6662696469205C66726F6D616E5C6663686172736574305C66707271327B5C2A5C70616E6F73652030323032303630333035303430353032303330347D54696D6573204E657720526F6D616E3B7D7B5C6664626D616A6F725C6633313530315C6662696469205C666E696C5C66636861727365743133345C66707271327B5C2A5C70616E6F73652030323031303630303033303130313031303130317D5C2763625C2763655C2763635C2765357B5C2A5C66616C742053696D53756E7D3B7D0D0A7B5C6668696D616A6F725C6633313530325C6662696469205C66726F6D616E5C6663686172736574305C66707271327B5C2A5C70616E6F73652030323034303530333035303430363033303230347D43616D627269613B7D7B5C6662696D616A6F725C6633313530335C6662696469205C66726F6D616E5C6663686172736574305C66707271327B5C2A5C70616E6F73652030323032303630333035303430353032303330347D54696D6573204E657720526F6D616E3B7D0D0A7B5C666C6F6D696E6F725C6633313530345C6662696469205C66726F6D616E5C6663686172736574305C66707271327B5C2A5C70616E6F73652030323032303630333035303430353032303330347D54696D6573204E657720526F6D616E3B7D7B5C6664626D696E6F725C6633313530355C6662696469205C666E696C5C66636861727365743133345C66707271327B5C2A5C70616E6F73652030323031303630303033303130313031303130317D5C2763625C2763655C2763635C2765357B5C2A5C66616C742053696D53756E7D3B7D0D0A7B5C6668696D696E6F725C6633313530365C6662696469205C6673776973735C6663686172736574305C66707271327B5C2A5C70616E6F73652030323066303530323032303230343033303230347D43616C696272693B7D7B5C6662696D696E6F725C6633313530375C6662696469205C66726F6D616E5C6663686172736574305C66707271327B5C2A5C70616E6F73652030323032303630333035303430353032303330347D54696D6573204E657720526F6D616E3B7D7B5C6634305C6662696469205C66726F6D616E5C66636861727365743233385C66707271322054696D6573204E657720526F6D616E2043453B7D0D0A7B5C6634315C6662696469205C66726F6D616E5C66636861727365743230345C66707271322054696D6573204E657720526F6D616E204379723B7D7B5C6634335C6662696469205C66726F6D616E5C66636861727365743136315C66707271322054696D6573204E657720526F6D616E20477265656B3B7D7B5C6634345C6662696469205C66726F6D616E5C66636861727365743136325C66707271322054696D6573204E657720526F6D616E205475723B7D7B5C6634355C6662696469205C66726F6D616E5C66636861727365743137375C66707271322054696D6573204E657720526F6D616E2028486562726577293B7D0D0A7B5C6634365C6662696469205C66726F6D616E5C66636861727365743137385C66707271322054696D6573204E657720526F6D616E2028417261626963293B7D7B5C6634375C6662696469205C66726F6D616E5C66636861727365743138365C66707271322054696D6573204E657720526F6D616E2042616C7469633B7D7B5C6634385C6662696469205C66726F6D616E5C66636861727365743136335C66707271322054696D6573204E657720526F6D616E2028566965746E616D657365293B7D0D0A7B5C663137325C6662696469205C666E696C5C6663686172736574305C66707271322053696D53756E205765737465726E7B5C2A5C66616C742053696D53756E7D3B7D7B5C663338305C6662696469205C66726F6D616E5C66636861727365743233385C66707271322043616D62726961204D6174682043453B7D7B5C663338315C6662696469205C66726F6D616E5C66636861727365743230345C66707271322043616D62726961204D617468204379723B7D7B5C663338335C6662696469205C66726F6D616E5C66636861727365743136315C66707271322043616D62726961204D61746820477265656B3B7D0D0A7B5C663338345C6662696469205C66726F6D616E5C66636861727365743136325C66707271322043616D62726961204D617468205475723B7D7B5C663338375C6662696469205C66726F6D616E5C66636861727365743138365C66707271322043616D62726961204D6174682042616C7469633B7D7B5C663338385C6662696469205C66726F6D616E5C66636861727365743136335C66707271322043616D62726961204D6174682028566965746E616D657365293B7D7B5C663431305C6662696469205C6673776973735C66636861727365743233385C66707271322043616C696272692043453B7D0D0A7B5C663431315C6662696469205C6673776973735C66636861727365743230345C66707271322043616C69627269204379723B7D7B5C663431335C6662696469205C6673776973735C66636861727365743136315C66707271322043616C6962726920477265656B3B7D7B5C663431345C6662696469205C6673776973735C66636861727365743136325C66707271322043616C69627269205475723B7D7B5C663431375C6662696469205C6673776973735C66636861727365743138365C66707271322043616C696272692042616C7469633B7D0D0A7B5C663431385C6662696469205C6673776973735C66636861727365743136335C66707271322043616C696272692028566965746E616D657365293B7D7B5C663432325C6662696469205C666E696C5C6663686172736574305C667072713220405C2763625C2763655C2763635C276535205765737465726E3B7D7B5C666C6F6D616A6F725C6633313530385C6662696469205C66726F6D616E5C66636861727365743233385C66707271322054696D6573204E657720526F6D616E2043453B7D0D0A7B5C666C6F6D616A6F725C6633313530395C6662696469205C66726F6D616E5C66636861727365743230345C66707271322054696D6573204E657720526F6D616E204379723B7D7B5C666C6F6D616A6F725C6633313531315C6662696469205C66726F6D616E5C66636861727365743136315C66707271322054696D6573204E657720526F6D616E20477265656B3B7D7B5C666C6F6D616A6F725C6633313531325C6662696469205C66726F6D616E5C66636861727365743136325C66707271322054696D6573204E657720526F6D616E205475723B7D0D0A7B5C666C6F6D616A6F725C6633313531335C6662696469205C66726F6D616E5C66636861727365743137375C66707271322054696D6573204E657720526F6D616E2028486562726577293B7D7B5C666C6F6D616A6F725C6633313531345C6662696469205C66726F6D616E5C66636861727365743137385C66707271322054696D6573204E657720526F6D616E2028417261626963293B7D7B5C666C6F6D616A6F725C6633313531355C6662696469205C66726F6D616E5C66636861727365743138365C66707271322054696D6573204E657720526F6D616E2042616C7469633B7D0D0A7B5C666C6F6D616A6F725C6633313531365C6662696469205C66726F6D616E5C66636861727365743136335C66707271322054696D6573204E657720526F6D616E2028566965746E616D657365293B7D7B5C6664626D616A6F725C6633313532305C6662696469205C666E696C5C6663686172736574305C66707271322053696D53756E205765737465726E7B5C2A5C66616C742053696D53756E7D3B7D7B5C6668696D616A6F725C6633313532385C6662696469205C66726F6D616E5C66636861727365743233385C66707271322043616D627269612043453B7D0D0A7B5C6668696D616A6F725C6633313532395C6662696469205C66726F6D616E5C66636861727365743230345C66707271322043616D62726961204379723B7D7B5C6668696D616A6F725C6633313533315C6662696469205C66726F6D616E5C66636861727365743136315C66707271322043616D6272696120477265656B3B7D7B5C6668696D616A6F725C6633313533325C6662696469205C66726F6D616E5C66636861727365743136325C66707271322043616D62726961205475723B7D0D0A7B5C6668696D616A6F725C6633313533355C6662696469205C66726F6D616E5C66636861727365743138365C66707271322043616D627269612042616C7469633B7D7B5C6668696D616A6F

		  */
      $sequence = { 7B??72??6631??????65666C616E6731??32??????????69??????????????67????36??75??32??????656666????35????????656666????????73??666462????33??35????????74??68????????68????????36??73??73??66??????68????????36??73??73??6662????5C646566??616E6731??33??5C646566??616E67666532??35????????656D656C616E6731??33??5C74??656D656C616E67666532??35????????656D656C616E6763????7B??666F6E74??62??????6630??????69??????????????6D616E5C6663????72??6574??5C6670??71??7B??2A??????6E6F73??20??32??32??3630??30??????????30??30??30????????????73??4E6577??526F6D616E3B????0A????6631??5C6662????69??????????6C5C6663????72??6574??33????6670??71??7B??2A??????6E6F73??20??32??31??3630??30??30??30??30??30??30??7D??2763????2763????2763????276535????????66616C74??5369????????????7D??5C6633????6662????69??????????6D616E5C6663????72??6574??5C6670??71??7B??2A??????6E6F73??20??32??34??35????????30????3630??30??30????????????72??6120????74??3B????0A????6633??5C6662????69??????????69????????????6172??6574??5C6670??71??7B??2A??????6E6F73??20??32??6630??????????30??30????33??32??34??43616C69????????????5C6633??5C6662????69??????????6C5C6663????72??6574??33????6670??71??7B??2A??????6E6F73??20??32??31??3630??30??30??30??30??30??30??7D??5C2763????2763????2763????276535????????7B??666C6F6D616A??72??6633??35????????62????69??????????6D616E5C6663????72??6574??5C6670??71??7B??2A??????6E6F73??20??32??32??3630??30??????????30??30??30????????????73??4E6577??526F6D616E3B????5C666462????6A??72??6633??35????????62????69??????????6C5C6663????72??6574??33????6670??71??7B??2A??????6E6F73??20??32??31??3630??30??30??30??30??30??30??7D??2763????2763????2763????276535????????66616C74??5369????????????7D??0A????66??????616A??72??6633??35????????62????69??????????6D616E5C6663????72??6574??5C6670??71??7B??2A??????6E6F73??20??32??34??35????????30????3630??30??30????????????72??613B????5C6662????616A??72??6633??35????????62????69??????????6D616E5C6663????72??6574??5C6670??71??7B??2A??????6E6F73??20??32??32??3630??30??????????30??30??30????????????73??4E6577??526F6D616E3B????0A????666C6F6D69????????????31??????????62????69??????????6D616E5C6663????72??6574??5C6670??71??7B??2A??????6E6F73??20??32??32??3630??30??????????30??30??30????????????73??4E6577??526F6D616E3B????5C666462????6E6F72??6633??35????????62????69??????????6C5C6663????72??6574??33????6670??71??7B??2A??????6E6F73??20??32??31??3630??30??30??30??30??30??30??7D??2763????2763????2763????276535????????66616C74??5369????????????7D??0A????66??????69????????????31??????????62????69??????????69????????????6172??6574??5C6670??71??7B??2A??????6E6F73??20??32??6630??????????30??30????33??32??34??43616C69????????????5C6662????69????????????31??????????62????69??????????6D616E5C6663????72??6574??5C6670??71??7B??2A??????6E6F73??20??32??32??3630??30??????????30??30??30????????????73??4E6577??526F6D616E3B????5C6634??5C6662????69??????????6D616E5C6663????72??6574??33??5C6670??71??20??????6573??4E6577??526F6D616E20????3B????0A????6634??5C6662????69??????????6D616E5C6663????72??6574??30????6670??71??20??????6573??4E6577??526F6D616E20????72??7D??5C6634??5C6662????69??????????6D616E5C6663????72??6574??3631??????72??32??5469????????????77??526F6D616E20????6565??????7B??6634??5C6662????69??????????6D616E5C6663????72??6574??3632??????72??32??5469????????????77??526F6D616E20??????3B????5C6634??5C6662????69??????????6D616E5C6663????72??6574??37375C6670??71??20??????6573??4E6577??526F6D616E20??486562????77??3B????0A????6634??5C6662????69??????????6D616E5C6663????72??6574??3738??????72??32??5469????????????77??526F6D616E20??4172??62????29??7D??5C6634??5C6662????69??????????6D616E5C6663????72??6574??38??5C6670??71??20??????6573??4E6577??526F6D616E20????6C74??63??7D??5C6634??5C6662????69??????????6D616E5C6663????72??6574??3633??????72??32??5469????????????77??526F6D616E20??5669????????????73??29??7D??0A????6631??32??????69??????????????6C5C6663????72??6574??5C6670??71??20????6D5375??20????73??6572??7B??2A??????6C74??5369????????????7D??5C6633??30??????69??????????????6D616E5C6663????72??6574??33??5C6670??71??20????6D62????6120????74??20????3B????5C6633??31??????69??????????????6D616E5C6663????72??6574??30????6670??71??20????6D62????6120????74??20????72??7D??5C6633??33??????69??????????????6D616E5C6663????72??6574??3631??????72??32??43616D62????6120????74??20????6565??????0D????????33??34??6662????69??????????6D616E5C6663????72??6574??3632??????72??32??43616D62????6120????74??20??????3B????5C6633??375C6662????69??????????6D616E5C6663????72??6574??38??5C6670??71??20????6D62????6120????74??20????6C74??63??7D??5C6633??38??????69??????????????6D616E5C6663????72??6574??3633??????72??32??43616D62????6120????74??20??5669????????????73??29??7D??5C6634??30??????69??????????????69????????????6172??6574??33??5C6670??71??20????6C69????????????3B????0A????6634??31??????69??????????????69????????????6172??6574??30????6670??71??20????6C69????????????72??7D??5C6634??33??????69??????????????69????????????6172??6574??3631??????72??32??43616C69????????????6565??????7B??6634??34??6662????69??????????69????????????6172??6574??3632??????72??32??43616C69????????????72??7D??5C6634??375C6662????69??????????69????????????6172??6574??38??5C6670??71??20????6C69????????????6C74??63??7D??0A????6634??38??????69??????????????69????????????6172??6574??3633??????72??32??43616C69????????????69????????????73??29??7D??5C6634??32??????69??????????????6C5C6663????72??6574??5C6670??71??20????2763????2763????2763????276535????????74??72??3B????5C666C6F6D616A??72??6633??35????????62????69??????????6D616E5C6663????72??6574??33??5C6670??71??20??????6573??4E6577??526F6D616E20????3B????0A????666C6F6D616A??72??6633??35????????62????69??????????6D616E5C6663????72??6574??30????6670??71??20??????6573??4E6577??526F6D616E20????72??7D??5C666C6F6D616A??72??6633??35????????62????69??????????6D616E5C6663????72??6574??3631??????72??32??5469????????????77??526F6D616E20????6565??????7B??666C6F6D616A??72??6633??35????????62????69??????????6D616E5C6663????72??6574??3632??????72??32??5469????????????77??526F6D616E20??????3B????0A????666C6F6D616A??72??6633??35????????62????69??????????6D616E5C6663????72??6574??37375C6670??71??20??????6573??4E6577??526F6D616E20??486562????77??3B????5C666C6F6D616A??72??6633??35????????62????69??????????6D616E5C6663????72??6574??3738??????72??32??5469????????????77??526F6D616E20??4172??62????29??7D??5C666C6F6D616A??72??6633??35????????62????69??????????6D616E5C6663????72??6574??38??5C6670??71??20??????6573??4E6577??526F6D616E20????6C74??63??7D??0A????666C6F6D616A??72??6633??35????????62????69??????????6D616E5C6663????72??6574??3633??????72??32??5469????????????77??526F6D616E20??5669????????????73??29??7D??5C666462????6A??72??6633??35????????62????69??????????6C5C6663????72??6574??5C6670??71??20????6D5375??20????73??6572??7B??2A??????6C74??5369????????????7D??5C66??????616A??72??6633??35????????62????69??????????6D616E5C6663????72??6574??33??5C6670??71??20????6D62????6120????3B????0A????66??????616A??72??6633??35????????62????69??????????6D616E5C6663????72??6574??30????6670??71??20????6D62????6120????72??7D??5C66??????616A??72??6633??35????????62????69??????????6D616E5C6663????72??6574??3631??????72??32??43616D62????6120????6565??????7B??66??????616A??72??6633??35????????62????69??????????6D616E5C6663????72??6574??3632??????72??32??43616D62????6120??????3B????0A????66??????616A??72??6633??35????????62????69??????????6D616E5C6663????72??6574??38??5C6670??71??20????6D62????6120????6C74??63??7D??5C66??????616A?? }

    condition:

      uint16(0) == 0x5c7b and
		  filesize < 100KB and
		  all of them
}

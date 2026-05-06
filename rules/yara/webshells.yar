/*
 * YARA-Forge YARA Rule Package
 * https://github.com/YARAHQ/yara-forge
 * 
 * Rule Package Information
 * Name: core 
 * Description: Default YARA Rule Package - Core
 * YARA-Forge Version: 0.9.1
 * YARA-QA Commit: 7f1c7f4ad5b5164aa49361bf2a772795202d7e36
 * Minimum Quality: 70
 * Force Include Importance Level: 80
 * Force Exclude Importance Level: 50
 * Minimum Age (in days): 1
 * Minimum Score: 65
 * Creation Date: 2026-05-03
 * Number of Rules: 4960
 * Skipped: 3066 (age), 894 (quality), 961 (score), 2039 (importance)
 */

import "dotnet"
import "hash"
import "pe"


/*
 * YARA Rule Set
 * Repository Name: R3c0nst
 * Repository: https://github.com/fboldewin/YARA-rules/
 * Retrieval Date: 2026-05-03
 * Git Commit: 54e9e6899b258b72074b2b4db6909257683240c2
 * Number of Rules: 19
 * Skipped: 5 (age), 2 (quality), 0 (score), 0 (importance)
 *
 * 
 * LICENSE
 * 
 * NO LICENSE SET
 */

rule ARKBIRD_SOLG_APT_UNC2452_Webshell_Chopper_Mar_2021_1 : FILE
{
	meta:
		description = "Detect exploit listener in the exchange configuration for Webshell Chopper used by UNC2452 group"
		author = "Arkbird_SOLG"
		id = "174af8e1-0df0-5ad7-ac7d-a208f64cb765"
		date = "2021-03-07"
		modified = "2021-03-07"
		reference = "Internal Research"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-03-07/UNC2452/APT_UNC2452_Webshell_Chopper_Mar_2021_1.yar#L1-L26"
		license_url = "N/A"
		logic_hash = "77bd7e5c10aa9cf2b407b37a76954b4eed163e36653e1fb3cde5de853f824cf0"
		score = 75
		quality = 73
		tags = "FILE"

	strings:
		$l1 = { 20 68 74 74 70 3a 2f 2f ?? 2f 3c 73 63 72 69 70 74 20 4c 61 6e 67 75 61 67 65 3d 22 63 23 22 20 72 75 6e 61 74 3d 22 73 65 72 76 65 72 22 3e 76 6f 69 64 20 50 61 67 65 5f 4c 6f 61 64 28 6f 62 6a 65 63 74 20 73 65 6e 64 65 72 2c 20 45 76 65 6e 74 41 72 67 73 20 65 29 7b 69 66 20 28 52 65 71 75 65 73 74 2e 46 69 6c 65 73 2e 43 6f 75 6e 74 21 3d 30 29 20 7b 20 52 65 71 75 65 73 74 2e 46 69 6c 65 73 5b 30 5d 2e 53 61 76 65 41 73 28 53 65 72 76 65 72 2e 4d 61 70 50 61 74 68 28 22 [5-14] 22 29 29 3b 7d 7d 3c 2f 73 63 72 69 70 74 3e }
		$l2 = { 68 74 74 70 3a 2f 2f ?? 2f 73 63 72 69 70 74 20 6c 61 6e 67 75 61 67 65 3d 22 4a 53 63 72 69 70 74 22 20 72 75 6e 61 74 3d 22 73 65 72 76 65 72 22 3e 66 75 6e 63 74 69 6f 6e 20 50 61 67 65 5f 4c 6f 61 64 28 29 7b 65 76 61 6c 28 [-] 2c 22 75 6e 73 61 66 65 22 29 3b 7d 3c 2f 73 63 72 69 70 74 3e }
		$c1 = { 5c 4f 41 42 20 28 44 65 66 61 75 6c 74 20 57 65 62 20 53 69 74 65 29 }
		$c2 = "ExternalUrl" fullword ascii
		$c3 = { 49 49 53 3a 2f 2f [10-30] 2f 57 33 53 56 43 2f [1-3] 2f 52 4f 4f 54 2f 4f 41 42 }
		$c4 = "FrontEnd\\HttpProxy\\OAB" fullword ascii
		$c5 = "/Configuration/Schema/ms-Exch-OAB-Virtual-Directory" fullword ascii

	condition:
		filesize > 1KB and 1 of ( $l* ) and 3 of ( $c* )
}

rule VOLEXITY_Webshell_Aspx_Regeorgtunnel : FILE MEMORY
{
	meta:
		description = "A variation of the reGeorgtunnel open-source webshell."
		author = "threatintel@volexity.com"
		id = "b8aa27c9-a28a-5051-8f81-1184f28842ed"
		date = "2021-03-02"
		modified = "2024-10-18"
		reference = "https://github.com/sensepost/reGeorg/blob/master/tunnel.aspx"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2021/2021-03-02 - Operation Exchange Marauder/indicators/yara.yar#L26-L56"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		hash = "406b680edc9a1bb0e2c7c451c56904857848b5f15570401450b73b232ff38928"
		logic_hash = "ea3d0532cb609682922469e8272dc8061efca3b3ae27df738ef2646e30404c6f"
		score = 75
		quality = 80
		tags = "FILE, MEMORY"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "high"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 4979
		version = 4

	strings:
		$s1 = "System.Net.Sockets"
		$s2 = "System.Text.Encoding.Default.GetString(Convert.FromBase64String(StrTr(Request.Headers.Get"
		$t1 = ".Split('|')"
		$t2 = "Request.Headers.Get"
		$t3 = ".Substring("
		$t4 = "new Socket("
		$t5 = "IPAddress ip;"

	condition:
		all of ( $s* ) or all of ( $t* )
}

rule VOLEXITY_Apt_Webshell_Aspx_Sportsball : FILE MEMORY
{
	meta:
		description = "The SPORTSBALL webshell, observed in targeted Microsoft Exchange attacks in 2021. SPORTSBALL was later discovered to be a variant of HYPERSHELL, a publicly available webshell."
		author = "threatintel@volexity.com"
		id = "25b23a4c-8fc7-5d6f-b4b5-46fe2c1546d8"
		date = "2021-03-01"
		modified = "2025-07-24"
		reference = "https://github.com/misterch0c/APT34/blob/e62f3d14ec78bea5c98d3c895162ca1e47676c18/Webshells_and_Panel/HyperShell/HyperShell/Shell/simple.aspx"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2021/2021-03-02 - Operation Exchange Marauder/indicators/yara.yar#L57-L89"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		hash = "2fa06333188795110bba14a482020699a96f76fb1ceb80cbfa2df9d3008b5b0a"
		logic_hash = "5ec5e52922e97a3080d397b69b2f42f09daa995271e218ea085fa2ec4e3abad2"
		score = 75
		quality = 80
		tags = "FILE, MEMORY"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 4968
		version = 6

	strings:
		$uniq1 = "HttpCookie newcook = new HttpCookie(\"fqrspt\", HttpContext.Current.Request.Form"
		$uniq2 = "ZN2aDAB4rXsszEvCLrzgcvQ4oi5J1TuiRULlQbYwldE="
		$s1 = "Result.InnerText = string.Empty;"
		$s2 = "newcook.Expires = DateTime.Now.AddDays("
		$s3 = "System.Diagnostics.Process process = new System.Diagnostics.Process();"
		$s4 = "process.StandardInput.WriteLine(HttpContext.Current.Request.Form[\""
		$s5 = "else if (!string.IsNullOrEmpty(HttpContext.Current.Request.Form[\""
		$s6 = "<input type=\"submit\" value=\"Upload\" />"

	condition:
		any of ( $uniq* ) or all of ( $s* )
}

rule VOLEXITY_Webshell_Jsp_Regeorg : FILE MEMORY
{
	meta:
		description = "Detects the reGeorg webshells' JSP version."
		author = "threatintel@volexity.com"
		id = "205ee383-4298-5469-a509-4ce3eaf9dd0e"
		date = "2022-03-08"
		modified = "2024-09-20"
		reference = "https://github.com/SecWiki/WebShell-2/blob/master/reGeorg-master/tunnel.jsp"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2022/2022-08-10 Mass exploitation of (Un)authenticated Zimbra RCE CVE-2022-27925/yara.yar#L57-L86"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		logic_hash = "cecb71605d9112d509823c26e40e1cf9cd6db581db448db5c9ffc63a2bfe529e"
		score = 75
		quality = 80
		tags = "FILE, MEMORY"
		hash1 = "f9b20324f4239a8c82042d8207e35776d6777b6305974964cd9ccc09d431b845"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 6575
		version = 5

	strings:
		$magic = "socketChannel.connect(new InetSocketAddress(target, port))" ascii
		$a1 = ".connect(new InetSocketAddress" ascii
		$a2 = ".configureBlocking(false)" ascii
		$a3 = ".setHeader(" ascii
		$a4 = ".getHeader(" ascii
		$a5 = ".flip();" ascii

	condition:
		$magic or all of ( $a* )
}

rule VOLEXITY_Webshell_Jsp_Converge : FILE MEMORY CVE_2022_26134
{
	meta:
		description = "Detects CONVERGE - a file upload webshell observed in incident involving compromise of Confluence server via CVE-2022-26134."
		author = "threatintel@volexity.com"
		id = "2a74678e-cb00-567c-a2e0-2e095f3e5ee8"
		date = "2022-06-01"
		modified = "2024-09-20"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2022/2022-06-02 Active Exploitation Of Confluence 0-day/indicators/yara.yar#L1-L21"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		logic_hash = "bb48516342eddd48c35e6db0eb74f95e116dc723503552b99ba721b5bdb391e5"
		score = 75
		quality = 80
		tags = "FILE, MEMORY, CVE-2022-26134"
		os = "all"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 6788
		version = 5

	strings:
		$s1 = "if (request.getParameter(\"name\")!=null && request.getParameter(\"name\").length()!=0){" ascii

	condition:
		$s1
}

rule VOLEXITY_Webshell_Java_Realcmd : FILE MEMORY
{
	meta:
		description = "Detects the RealCMD webshell, one of the payloads for BEHINDER."
		author = "threatintel@volexity.com"
		id = "60b30ccc-bcfa-51e6-a3f5-88037d19213e"
		date = "2022-06-01"
		modified = "2024-07-30"
		reference = "https://github.com/Freakboy/Behinder/blob/master/src/main/java/vip/youwe/sheller/payload/java/RealCMD.java"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2022/2022-06-02 Active Exploitation Of Confluence 0-day/indicators/yara.yar#L61-L84"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		logic_hash = "e09f2a23674fd73296dd4d1fabf1a2c812bfe69ff02abc96a4be35af6a18e512"
		score = 75
		quality = 80
		tags = "FILE, MEMORY"
		hash1 = "a9a30455d6f3a0a8cd0274ae954aa41674b6fd52877fafc84a9cb833fd8858f6"
		os = "all"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 6786
		version = 4

	strings:
		$fn1 = "runCmd" wide ascii fullword
		$fn2 = "RealCMD" ascii wide fullword
		$fn3 = "buildJson" ascii wide fullword

	condition:
		all of ( $fn* )
}

rule VOLEXITY_Apt_Webshell_Pl_Complyshell : UTA0178 FILE MEMORY
{
	meta:
		description = "Detection for the COMPLYSHELL webshell."
		author = "threatintel@volexity.com"
		id = "6b44b5bc-a75f-573c-b9c3-562b7874e408"
		date = "2023-12-13"
		modified = "2024-01-12"
		reference = "TIB-20231215"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2024/2024-01-10 Ivanti Connect Secure/indicators/yara.yar#L3-L25"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		logic_hash = "ff46691f1add20cff30fe996e2fb199ce42408e86d5642a8a43c430f2245b1f5"
		score = 75
		quality = 80
		tags = "UTA0178, FILE, MEMORY"
		hash1 = "8bc8f4da98ee05c9d403d2cb76097818de0b524d90bea8ed846615e42cb031d2"
		os = "linux"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 9995
		version = 4

	strings:
		$s = "eval{my $c=Crypt::RC4->new("

	condition:
		$s
}

rule SEKOIA_Apt_Unk_Hrserv_Webshell_Strings : FILE
{
	meta:
		description = "Detects HrServ web shell based on strings"
		author = "Sekoia.io"
		id = "684fd41c-9ea6-4f4e-8db4-82325a2ff80b"
		date = "2023-11-23"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_unk_hrserv_webshell_strings.yar#L1-L23"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "b5650e08227bbdb82c635bd67abae57e3107be9126639619809bfbe2a7ffee89"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "open file error!"
		$ = "create file error!"
		$ = "[!] CreatePipe failed."
		$ = "[!] CreateProcess failed."
		$ = "[!] CreateProcess success,no result return."
		$ = "; cadataIV="
		$ = "cadataKey="

	condition:
		uint16be( 0 ) == 0x4d5a and filesize < 300KB and 5 of them
}

rule SEKOIA_Tool_Webshell_B374K_Strings : FILE
{
	meta:
		description = "Detects b374k webshell"
		author = "Sekoia.io"
		id = "f53fc668-e1fc-4b85-b850-59aceefb6418"
		date = "2024-09-06"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/tool_webshell_b374k_strings.yar#L1-L21"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		hash = "1d27b23fceecbb9e854c41f6a8fb878e"
		hash = "71fd853a3f3efc3dc2846e866187ee59"
		hash = "187e001c32487d0d68197ddb7e7796c3"
		hash = "6eac497dfc1020a8475e95542fad197e"
		hash = "61c6a0bc15efa442853f04bb276ac96e"
		logic_hash = "b085a50d50fc1fd06d6f75397cf1fa6fa1bc4a0d18b56ed3458990f4abde0632"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "$func('$x','ev'.'al'.'("
		$ = "(ba'.'se'.'64'.'_de'.'co'.'de($x)))"

	condition:
		2 of them and filesize < 1MB
}

rule SEKOIA_Generic_Php_Webshell : FILE
{
	meta:
		description = "Detects generic webshell"
		author = "Sekoia.io"
		id = "415a96bd-11a4-40e7-8335-ac1f1a99d17c"
		date = "2023-12-08"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/generic_php_webshell.yar#L1-L15"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "617264a785b8e9e87a39e12d7b72963d94e0686a174716347369fe71ab7a78af"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "system($_POST['a']);"

	condition:
		all of them and filesize < 500
}

rule SEKOIA_Apt_Oilrig_Webshell : FILE
{
	meta:
		description = "Detects a webshell used by OilRig"
		author = "Sekoia.io"
		id = "53955117-5176-4682-89ad-1503faba42aa"
		date = "2024-10-23"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_oilrig_webshell.yar#L1-L18"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "0e0879bafa1becf7e4aef008229a79ab8e0c50eda03232abd5cbb8fc59f482d3"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "string d = com;"
		$ = "string p = fu;"
		$ = "#@rt12!@$$$nnMF##"
		$ = "messi(d)))"

	condition:
		2 of them and filesize < 80KB
}

rule SEKOIA_Tool_Pivotnacci_Webshell : FILE
{
	meta:
		description = "Detects pivotnacci webshell"
		author = "Sekoia.io"
		id = "729b6381-b59d-46fe-9ad4-b8b68fb0ceea"
		date = "2024-04-22"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/tool_pivotnacci_webshell.yar#L1-L23"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "a57792915b4c888547ebe0b08b928e4bc32b3526c98a3ccc9fca0193cedee20a"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "if (cmd == SEND_OPERATION) {"
		$ = "Response.BinaryWrite(newBuff)"
		$ = "Request.Headers.Get(ID_HEADER)"
		$ = "[$READ_BUFFER_SESSION_KEY . $connection_id]"
		$ = "extract_session_readbuf($conn_id"
		$ = "Failed connecting to target $addr:$port : $errstr"
		$ = "void handle_post(String cmd)"
		$ = "SocketChannel socketChannel = this.get_socket(socket_id"
		$ = "this.get_svc().compareTo(this.get_hostname())"

	condition:
		3 of them and filesize < 10KB
}

rule SEKOIA_Weevely_Webshell_Payload : FILE
{
	meta:
		description = "Detects weevely webshell"
		author = "Sekoia.io"
		id = "f2879c6e-3d1b-41be-8b1d-4f0503fd4b29"
		date = "2024-04-22"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/weevely_webshell_payload.yar#L1-L17"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "bb02ec519d77526cc81ebd7743336b333b9498f79079f7008970cf1bb51c4948"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = "<?php include \""
		$s2 = ".basename(__FILE__).\""
		$s3 = ";__HALT_COMPILER(); ?>"

	condition:
		all of them and filesize < 1MB and @s1 == 0 and @s2 < @s3
}

rule SEKOIA_Webshell_Wso_Webshell_Strings
{
	meta:
		description = "Detects the WSO webshells"
		author = "Sekoia.io"
		id = "84340792-73a4-4d61-9957-6cfa1f6444a7"
		date = "2022-04-22"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/webshell_wso_webshell_strings.yar#L1-L20"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "4d6966a34dc8e7390913857144da106affea14668d1c2c11a05be62a6e625c8f"
		score = 75
		quality = 80
		tags = ""
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "decrypt($str,$pwd){$pwd=base64_encode($pwd);"
		$ = "prototype(md5($_SERVER['HTTP_HOST'])"
		$ = "$_COOKIE[md5($_SERVER['HTTP_HOST'])."
		$ = "set(a,c,p1,p2,p3,charset)"
		$ = "(($p & 0x0008) ? (($p & 0x0400)"
		$ = "gcc','lcc','cc','ld','make','php"

	condition:
		3 of them
}

rule SEKOIA_Webshell_Icesword_Strings : FILE
{
	meta:
		description = "Detects icesword webshell"
		author = "Sekoia.io"
		id = "2c6b3cec-4200-4386-8cd5-4004c9b5b96a"
		date = "2024-11-22"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/webshell_icesword_strings.yar#L1-L20"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		hash = "0447352827e61696304a8e3d34e1d270"
		hash = "f49cfcda0abdefa385eda7ec7e7a5411"
		hash = "e1518388375ba772ed20503ec6dc6c8a"
		hash = "ecf08cd6af127e01f913354529174a23"
		logic_hash = "25ea8c1f4756595e63f09dfdfd1cb0e9bbf1d05e46150e22993de95d9f758385"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "&fsAction=rename&newName="
		$ = "&fsAction=copyto&dstPath="

	condition:
		2 of them and filesize < 100KB
}

rule SYNACKTIV_SYNACKTIV_WEBSHELL_ASPX_Suo5_May25 : WEBSHELL COMMODITY FILE
{
	meta:
		description = "Detects the .NET version of the suo5 webshell"
		author = "Synacktiv, Maxence Fossat [@cybiosity]"
		id = "d30a7232-f00b-45ab-9419-f43b1611445a"
		date = "2025-05-12"
		modified = "2025-05-12"
		reference = "https://www.synacktiv.com/en/publications/open-source-toolset-of-an-ivanti-csa-attacker"
		source_url = "https://github.com/synacktiv/synacktiv-rules/blob/d234cc4da0783db7dca56ae8dd5252afdc248df8/2025/offensive_tools/webshell_aspx_suo5.yar#L1-L46"
		license_url = "https://github.com/synacktiv/synacktiv-rules/blob/d234cc4da0783db7dca56ae8dd5252afdc248df8/LICENSE.md"
		hash = "06710575d20cacd123f83eb82994879367e07f267e821873bf93f4db6312a97b"
		hash = "e6979d7df0876679fc2481aa68fcec5b6ddc82d854f63da2bddb674064384f9a"
		hash = "3bbbef1b4ead98c61fba60dd6291fe1ff08f5eac54d820e47c38d348e4a7b1ec"
		hash = "345c383dd439eb523b01e1087a0866e13f04ff53bb8cc11f3c70b4a382f10c7e"
		hash = "838840dd76ff34cee45996fdc9a87856c9a0f14138e65cb9eb6603ed157d1515"
		hash = "d9657ac8dd562bdd39e8fcc1fff37ddced10f7f3f118d9cd4da6118a223dcc45"
		logic_hash = "68dc29b2cedc26e638eaa12bf2a2d0415de323097baf5ea61dba52bd20b5beee"
		score = 75
		quality = 80
		tags = "WEBSHELL, COMMODITY, FILE"
		license = "DRL-1.1"
		tlp = "TLP:CLEAR"
		pap = "PAP:CLEAR"

	strings:
		$user_agent = ".Equals(\"Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.1.2.3\")" ascii
		$header = "Response.AddHeader(\"X-Accel-Buffering\", \"no\")" ascii
		$xor = /= \(byte\)\(\w{1,1023}\[\w{1,1023}\] \^ \w{1,1023}\);/
		$s1 = "Request.Headers.Get(\"User-Agent\")" ascii
		$s2 = "if (Request.ContentType.Equals(\"application/plain\"))" ascii
		$s3 = "Response.ContentType = \"application/octet-stream\";" ascii
		$s4 = "= Request.BinaryRead(Request.ContentLength);" ascii
		$s5 = "= Response.OutputStream;" ascii
		$s6 = "new TcpClient()" ascii
		$s7 = ".BeginConnect(" ascii
		$s8 = ".GetStream().Write(" ascii
		$s9 = "new BinaryWriter(" ascii
		$s10 = "new BinaryReader(" ascii
		$s11 = ".ReadBytes(4)" ascii
		$s12 = "BitConverter.GetBytes((Int32)" ascii
		$s13 = "BitConverter.ToInt32(" ascii
		$s14 = "Array.Reverse(" ascii
		$s15 = "new Random().NextBytes(" ascii

	condition:
		filesize < 100KB and ( $user_agent or ( ( $header or $xor ) and 8 of ( $s* ) ) or 12 of ( $s* ) )
}
/*
 * YARA Rule Set
 * Repository Name: ArtifactDrop
 * Repository: https://github.com/matthieugras/artifact-drop/
 * Retrieval Date: 2026-05-03
 * Git Commit: d2bcbe820bc134a4ed672ef6013498f856561af4
 * Number of Rules: 1
 * Skipped: 0 (age), 0 (quality), 0 (score), 0 (importance)
 *
 * 
 * LICENSE
 * 
 * NO LICENSE SET
 */

rule SIGNATURE_BASE_WEBSHELL_ASPX_DLL_Moveit_Jun23_1 : FILE
{
	meta:
		description = "Detects compiled ASPX web shells found being used in MOVEit Transfer exploitation"
		author = "Florian Roth"
		id = "47db8602-9a9e-5efc-b8b9-fbc4f3c8d4e9"
		date = "2023-06-01"
		modified = "2023-12-05"
		reference = "https://www.trustedsec.com/blog/critical-vulnerability-in-progress-moveit-transfer-technical-analysis-and-recommendations/?utm_content=251159938&utm_medium=social&utm_source=twitter&hss_channel=tw-403811306"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/vuln_moveit_0day_jun23.yar#L2-L22"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "47c2ec1e833852941434586b61d6f435b9acb32b2ff48e0a9e8006e0f9ff8056"
		score = 85
		quality = 85
		tags = "FILE"
		hash1 = "6cbf38f5f27e6a3eaf32e2ac73ed02898cbb5961566bb445e3c511906e2da1fa"

	strings:
		$x1 = "human2_aspx" ascii fullword
		$x2 = "X-siLock-Comment" wide
		$x3 = "x-siLock-Step1" wide
		$a1 = "MOVEit.DMZ.Core.Data" ascii fullword

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 40KB and ( 1 of ( $x* ) and $a1 ) or all of them
}

rule SIGNATURE_BASE_WEBSHELL_ASPX_Moveit_Jun23_1 : FILE
{
	meta:
		description = "Detects ASPX web shells as being used in MOVEit Transfer exploitation"
		author = "Florian Roth"
		id = "2c789b9c-5ec5-5fd1-84e3-6bf7735a9488"
		date = "2023-06-01"
		modified = "2023-12-05"
		reference = "https://www.rapid7.com/blog/post/2023/06/01/rapid7-observed-exploitation-of-critical-moveit-transfer-vulnerability/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/vuln_moveit_0day_jun23.yar#L24-L41"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "436f9a503ad938541faa8f34604310ba6d932e40a41dc189ccd293b7191a7621"
		score = 85
		quality = 85
		tags = "FILE"
		hash1 = "2413b5d0750c23b07999ec33a5b4930be224b661aaf290a0118db803f31acbc5"
		hash2 = "48367d94ccb4411f15d7ef9c455c92125f3ad812f2363c4d2e949ce1b615429a"
		hash3 = "e8012a15b6f6b404a33f293205b602ece486d01337b8b3ec331cd99ccadb562e"

	strings:
		$s1 = "X-siLock-Comment" ascii fullword
		$s2 = "]; string x = null;" ascii
		$s3 = ";  if (!String.Equals(pass, " ascii

	condition:
		filesize < 150KB and 2 of them
}

rule SIGNATURE_BASE_WEBSHELL_JAVA_Versamem_JAR_Aug24_1 : FILE
{
	meta:
		description = "Detects VersaMem Java webshell samples (as used by Volt Typhoon)"
		author = "blacklotuslabs (modified by Florian Roth and X__Junior)"
		id = "9b666e61-cfa8-58b3-a362-772cd907c57c"
		date = "2024-08-27"
		modified = "2024-08-29"
		reference = "https://x.com/ryanaraine/status/1828440883315999117"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_volttyphoon_versamem.yar#L2-L24"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "d21558eb6c8e700b8a4cb86fdaa5487179828152af68828e878397859d6d3952"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$sa1 = "com.versa.vnms.ui.TestMain"
		$sa2 = "captureLoginPasswordCode"
		$sa3 = "com/versa/vnms/ui/services/impl/VersaAuthenticationServiceImpl"
		$sa4 = "/tmp/.temp.data"
		$sa5 = "getInsertCode"
		$sa6 = "VersaMem"
		$sa7 = "Versa-Auth"
		$sb1 = "/tmp/.java_pid"
		$sb2 = {2f 75 73 72 2f 62 69 6e 2f 70 67 72 65 70 01 00 02 2d 66 01 00 25 6f 72 67 2e 61 70 61 63 68 65 2e 63 61 74 61 6c 69 6e 61 2e 73 74 61 72 74 75 70 2e 42 6f 6f 74 73 74 72 61 70 07}

	condition:
		filesize < 5MB and ( 3 of them or all of ( $sb* ) )
}

rule SIGNATURE_BASE_FE_APT_Webshell_PL_STEADYPULSE_1
{
	meta:
		description = "Detects samples mentioned in PulseSecure report"
		author = "Mandiant"
		id = "49457fbb-9288-565f-909d-e8228c21c1e4"
		date = "2021-04-16"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_pulsesecure.yar#L265-L284"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		hash = "168976797d5af7071df257e91fcc31ce1d6e59c72ca9e2f50c8b5b3177ad83cc"
		logic_hash = "a0e3ebdd02ccf5cc8fc0a83c1d0224aed45dc5094eb85bd855e5b74b34e3aaaf"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s1 = "parse_parameters"
		$s2 = "s/\\+/ /g"
		$s3 = "s/%(..)/pack("
		$s4 = "MIME::Base64::encode($"
		$s5 = "$|=1;"
		$s6 = "RC4("
		$s7 = "$FORM{'cmd'}"

	condition:
		all of them
}

rule SIGNATURE_BASE_APT_MAL_CN_Wocao_Webshell_Console_Jsp
{
	meta:
		description = "Strings from the console.jsp webshell"
		author = "Fox-IT SRT"
		id = "1afdfc34-d2e3-58c7-80ea-ee5632e42469"
		date = "2019-12-20"
		modified = "2023-12-05"
		reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_op_wocao.yar#L318-L335"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "e70c15ef10b63a011edbcedc773a8e2917fd915c3ecc273c3bf2b78eb10fc570"
		score = 75
		quality = 85
		tags = ""

	strings:
		$a = "String strLogo = request.getParameter(\"image\")"
		$b = "!strLogo.equals(\"web.gif\")"
		$c = "<font color=red>Save Failed!</font>"
		$d = "<font color=red>Save Success!</font>"
		$e = "Save path:<br><input type=text"
		$f = "if (newfile.exists() && newfile.length()>0) { out.println"

	condition:
		1 of them
}

rule SIGNATURE_BASE_APT_MAL_CN_Wocao_Webshell_Index_Jsp
{
	meta:
		description = "Strings from the index.jsp socket tunnel"
		author = "Fox-IT SRT"
		id = "9c226ccd-6c69-523c-bca4-371e55274667"
		date = "2019-12-20"
		modified = "2023-12-05"
		reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_op_wocao.yar#L337-L353"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "870dad9fb5456f8edbd9f3c2d0b8764cf1143399626ce4df53c93919bcb1a0cb"
		score = 75
		quality = 85
		tags = ""

	strings:
		$x1 = "X-CMD"
		$x2 = "X-STATUS"
		$x3 = "X-TARGET"
		$x4 = "X-ERROR"
		$a = "out.print(\"All seems fine.\");"

	condition:
		all of ( $x* ) and $a
}

rule SIGNATURE_BASE_APT_MAL_CN_Wocao_Webshell_Ver_Jsp
{
	meta:
		description = "Strings from the ver.jsp webshell"
		author = "Fox-IT SRT"
		id = "b2828b84-8934-5111-9345-683a07025070"
		date = "2019-12-20"
		modified = "2023-12-05"
		reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_op_wocao.yar#L355-L372"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "ada6de4b07a76e79bb17793cda2b51f96554a35992a73f59c360487638ae3be3"
		score = 75
		quality = 85
		tags = ""

	strings:
		$a = "String strLogo = request.getParameter(\"id\")"
		$b = "!strLogo.equals(\"256\")"
		$c = "boolean chkos = msg.startsWith"
		$d = "while((c = er.read()) != -1)"
		$e = "out.print((char)c);}in.close()"
		$f = "out.print((char)c);}er.close()"

	condition:
		1 of them
}

rule SIGNATURE_BASE_APT_MAL_CN_Wocao_Webshell_Webinfo
{
	meta:
		description = "Generic strings from webinfo.war webshells"
		author = "Fox-IT SRT"
		id = "b8477f62-f3f6-5526-b0e3-9b794fefaa1f"
		date = "2019-12-20"
		modified = "2023-12-05"
		reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_op_wocao.yar#L374-L394"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "711737a56067f24f422cc7d5aeba4389741fe18a0e66f2715fce626c3b6aef19"
		score = 75
		quality = 85
		tags = ""

	strings:
		$var1 = "String strLogo = request.getParameter"
		$var2 = "String content = request.getParameter(\"content\");"
		$var3 = "String basePath=request.getScheme()"
		$var4 = "!strLogo.equals("
		$var5 = "if(path!=null && !path.equals(\"\") && content!=null"
		$var6 = "File newfile=new File(path);"
		$str1 = "Save Success!"
		$str2 = "Save Failed!"

	condition:
		2 of ( $var* ) or ( all of ( $str* ) and 1 of ( $var* ) )
}


rule SIGNATURE_BASE_WEBSHELL_ASPX_Xsltransform_Aug21 : FILE
{
	meta:
		description = "Detects an ASPX webshell utilizing XSL Transformations"
		author = "Max Altgelt"
		id = "44254084-a717-59e6-a3ac-eca3c1c864a8"
		date = "2020-02-23"
		modified = "2023-12-05"
		reference = "https://gist.github.com/JohnHammond/cdae03ca5bc2a14a735ad0334dcb93d6"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/webshell_xsl_transform.yar#L1-L19"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "3ac0b50adc4c56769d0248e213e9426a22e0f5086bf081da57f835ff1c77b716"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$csharpshell = "Language=\"C#\"" nocase
		$x1 = "<root>1</root>"
		$x2 = ".LoadXml(System.Text.Encoding.UTF8.GetString(System.Convert.FromBase64String("
		$s1 = "XsltSettings.TrustedXslt"
		$s2 = "Xml.XmlUrlResolver"
		$s3 = "FromBase64String(Request[\""

	condition:
		filesize < 500KB and $csharpshell and ( 1 of ( $x* ) or all of ( $s* ) )
}

rule SIGNATURE_BASE_WEBSHELL_ASPX_Proxyshell_Aug21_2 : FILE
{
	meta:
		description = "Detects webshells dropped by ProxyShell exploitation based on their file header (must be PST), size and content"
		author = "Florian Roth (Nextron Systems)"
		id = "a351a466-695e-570e-8c7f-9c6c0534839c"
		date = "2021-08-13"
		modified = "2025-11-03"
		reference = "https://www.bleepingcomputer.com/news/microsoft/microsoft-exchange-servers-are-getting-hacked-via-proxyshell-exploits/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/expl_proxyshell.yar#L35-L48"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "4ede197d482f0a9e553ba857b5049e7b7405e3df92460e19418fa0653c844982"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "Page Language=" ascii nocase

	condition:
		uint32( 0 ) == 0x4e444221 and filesize < 2MB and $s1
}

rule SIGNATURE_BASE_WEBSHELL_ASPX_Proxyshell_Aug21_3 : FILE
{
	meta:
		description = "Detects webshells dropped by ProxyShell exploitation based on their file header (must be DER), size and content"
		author = "Max Altgelt"
		id = "a7bca62b-c8f1-5a38-81df-f3d4582a590b"
		date = "2021-08-23"
		modified = "2025-11-03"
		reference = "https://twitter.com/gossithedog/status/1429175908905127938?s=12"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/expl_proxyshell.yar#L50-L64"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "f071aaa8918b359f786f2ac7447eeaedb5a6fca9e0a0c0e8820e011244424503"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "Page Language=" ascii nocase

	condition:
		uint16( 0 ) == 0x8230 and filesize < 10KB and $s1
}

rule SIGNATURE_BASE_WEBSHELL_ASPX_Proxyshell_Sep21_1 : FILE
{
	meta:
		description = "Detects webshells dropped by ProxyShell exploitation based on their file header (must be PST) and base64 decoded request"
		author = "Tobias Michalski"
		id = "d0d23e17-6b6a-51d1-afd9-59cc2404bcd8"
		date = "2021-09-17"
		modified = "2025-11-03"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/expl_proxyshell.yar#L66-L80"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		hash = "219468c10d2b9d61a8ae70dc8b6d2824ca8fbe4e53bbd925eeca270fef0fd640"
		logic_hash = "233ec15dff8da5f2beaa931eb06849aa37e548947c1068d688a1695d977605d8"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s = ".FromBase64String(Request["

	condition:
		uint32( 0 ) == 0x4e444221 and any of them
}

rule SIGNATURE_BASE_WEBSHELL_ASPX_Proxyshell_Exploitation_Aug21_1 : FILE
{
	meta:
		description = "Detects unknown malicious loaders noticed in August 2021"
		author = "Florian Roth (Nextron Systems)"
		id = "1fa563fc-c91c-5f4e-98f1-b895e1acb4f4"
		date = "2021-08-25"
		modified = "2025-11-03"
		reference = "https://twitter.com/VirITeXplorer/status/1430206853733097473"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/expl_proxyshell.yar#L107-L119"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "8a2417bb85c7f91d98143d2f4c26d30416b3a01ba8abc1445ccfae5609825b4d"
		score = 90
		quality = 85
		tags = "FILE"

	strings:
		$x1 = ");eval/*asf" ascii

	condition:
		filesize < 600KB and 1 of them
}

rule SIGNATURE_BASE_WEBSHELL_ASPX_Proxyshell_Aug15 : FILE
{
	meta:
		description = "Webshells iisstart.aspx and Logout.aspx"
		author = "Moritz Oettle"
		id = "b1e6c0f3-787f-59b8-8123-4045522047ca"
		date = "2021-09-04"
		modified = "2025-11-03"
		reference = "https://github.com/hvs-consulting/ioc_signatures/tree/main/Proxyshell"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/expl_proxyshell.yar#L121-L152"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "46c37f1d80c777acafa6ee64d7df18a6b94768f4463d9196027111a84a63a24f"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$g1 = "language=\"JScript\"" ascii
		$g2 = "function getErrorWord" ascii
		$g3 = "errorWord" ascii
		$g4 = "Response.Redirect" ascii
		$g5 = "function Page_Load" ascii
		$g6 = "runat=\"server\"" ascii
		$g7 = "Request[" ascii
		$g8 = "eval/*" ascii
		$s1 = "AppcacheVer" ascii
		$s3 = "LaTkWfI64XeDAXZS6pU1KrsvLAcGH7AZOQXjrFkT816RnFYJQR" ascii
		$fp1 = "<input type=\"submit\" Value=\"Refresh This Page\""

	condition:
		filesize < 1KB and ( 1 of ( $s* ) or 4 of ( $g* ) ) and not 1 of ( $fp* )
}

rule SIGNATURE_BASE_WEBSHELL_Mailbox_Export_PST_Proxyshell_Aug26 : FILE
{
	meta:
		description = "Webshells generated by an Mailbox export to PST and stored as aspx: 570221043.aspx 689193944.aspx luifdecggoqmansn.aspx"
		author = "Moritz Oettle"
		id = "6aea414f-d27c-5202-84f8-b8620782fc90"
		date = "2021-09-04"
		modified = "2025-11-03"
		reference = "https://github.com/hvs-consulting/ioc_signatures/tree/main/Proxyshell"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/expl_proxyshell.yar#L154-L180"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "07acbf74a4bf169fc128cd085759f33e89917e217703b3c6557ba5f954822fd4"
		score = 85
		quality = 85
		tags = "FILE"

	strings:
		$x1 = "!BDN"
		$g1 = "Page language=" ascii
		$g2 = "<%@ Page" ascii
		$g3 = "Request.Item[" ascii
		$g4 = "\"unsafe\");" ascii
		$g5 = "<%eval(" ascii
		$g6 = "script language=" ascii
		$g7 = "Request[" ascii
		$s1 = "gold8899" ascii
		$s2 = "exec_code" ascii
		$s3 = "orangenb" ascii

	condition:
		filesize < 500KB and $x1 at 0 and ( 1 of ( $s* ) or 3 of ( $g* ) )
}

rule SIGNATURE_BASE_WEBSHELL_Proxyshell_Exploitation_Nov21_1
{
	meta:
		description = "Detects webshells dropped by DropHell malware"
		author = "Florian Roth (Nextron Systems)"
		id = "300eaadf-db0c-5591-84fc-abdf7cdd90c1"
		date = "2021-11-01"
		modified = "2025-11-03"
		reference = "https://www.deepinstinct.com/blog/do-not-exchange-it-has-a-shell-inside"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/expl_proxyshell.yar#L257-L271"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "d9812d3f53c346c4e318609e0c7de66811b27ffa7528a6ddeb6ac8436da59ef5"
		score = 85
		quality = 85
		tags = ""

	strings:
		$s01 = ".LoadXml(System.Text.Encoding.UTF8.GetString(System.Convert.FromBase64String(Request[" ascii wide
		$s02 = "new System.IO.MemoryStream()" ascii wide
		$s03 = "Transform(" ascii wide

	condition:
		all of ( $s* )
}

rule SIGNATURE_BASE_WEBSHELL_SECRETSAUCE_Jul23_1 : CVE_2023_3519 FILE
{
	meta:
		description = "Detects SECRETSAUCE PHP webshells (found after an exploitation of Citrix NetScaler ADC CVE-2023-3519)"
		author = "Florian Roth"
		id = "db0542e7-648e-5f60-9838-e07498f58b51"
		date = "2023-07-24"
		modified = "2023-12-05"
		reference = "https://www.mandiant.com/resources/blog/citrix-zero-day-espionage"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/expl_citrix_netscaler_adc_exploitation_cve_2023_3519.yar#L79-L100"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "c762d46ae43a3e10453c2ee17039812a06086ac85bdb000cf8308f5196a9dee2"
		score = 85
		quality = 85
		tags = "CVE-2023-3519, FILE"

	strings:
		$sa1 = "for ($x=0; $x<=1; $x++) {" ascii
		$sa2 = "$_REQUEST[" ascii
		$sa3 = "@eval" ascii
		$sb1 = "public $cmd;" ascii
		$sb2 = "return @eval($a);" ascii
		$sb3 = "$z->run($z->get('openssl_public_decrypt'));"

	condition:
		filesize < 100KB and ( all of ( $sa* ) or 2 of ( $sb* ) )
}

rule SIGNATURE_BASE_WEBSHELL_JSP_Nov21_1 : FILE
{
	meta:
		description = "Detects JSP webshells"
		author = "Florian Roth (Nextron Systems)"
		id = "117eed28-c44e-5983-b4c7-b555fc06d923"
		date = "2021-11-23"
		modified = "2023-12-05"
		reference = "https://www.ic3.gov/Media/News/2021/211117-2.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/expl_spring4shell.yar#L2-L17"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "1dac7706421961c71ba6f8d7a223b80e4b77bf206bfb64ee18c7cc894b062a3c"
		score = 70
		quality = 85
		tags = "FILE"

	strings:
		$x1 = "request.getParameter(\"pwd\")" ascii
		$x2 = "excuteCmd(request.getParameter(" ascii
		$x3 = "getRuntime().exec (request.getParameter(" ascii
		$x4 = "private static final String PW = \"whoami\"" ascii

	condition:
		filesize < 400KB and 1 of them
}

rule SIGNATURE_BASE_EXPL_POC_Springcore_0Day_Webshell_Mar22_1 : FILE
{
	meta:
		description = "Detects webshell found after SpringCore exploitation attempts POC script"
		author = "Florian Roth (Nextron Systems)"
		id = "e7047c98-3c60-5211-9ad5-2bfdfb35d493"
		date = "2022-03-30"
		modified = "2023-12-05"
		reference = "https://twitter.com/vxunderground/status/1509170582469943303"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/expl_spring4shell.yar#L36-L50"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "17282b66899356a6051f0b47a7a3f02265737283d760f2256e03a2b934bb63b8"
		score = 70
		quality = 85
		tags = "FILE"

	strings:
		$x1 = ".getInputStream(); int a = -1; byte[] b = new byte[2048];"
		$x2 = "if(\"j\".equals(request.getParameter(\"pwd\")"
		$x3 = ".getRuntime().exec(request.getParameter(\"cmd\")).getInputStream();"

	condition:
		filesize < 200KB and 1 of them
}

rule SIGNATURE_BASE_WEBSHELL_ASPX_Mar21_1 : FILE
{
	meta:
		description = "Detects ASPX Web Shells"
		author = "Florian Roth (Nextron Systems)"
		id = "52884135-6b86-5e3e-a866-36a812d5a9af"
		date = "2021-03-12"
		modified = "2025-11-03"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/thor-webshells.yar#L9930-L9956"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "0c20163871bf424c0b594c4b75d35e782df03761552f792474761c603ddb8478"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "10b6e82125a2ddf3cc31a238e0d0c71a64f902e0d77171766713affede03174d"
		hash2 = "170bee832df176aac0a3c6c7d5aa3fee413b4572030a24c994a97e70f6648ffc"
		hash3 = "31c4d1fc81c052e269866deff324dffb215e7d481a47a2b6357a572a3e685d90"
		hash4 = "41b5c26ac194439612b68e9ec6a638eceaf00842c347ffa551eb009ef6c015a3"
		hash5 = "4b645bc773acde2b3cc204e77ac27c3f6991046c3b75f42d12bc90ec29cff9e3"
		hash6 = "602bb701b78895d4de32f5e78f3c511e5298ba244b29641b11a7c1c483789859"
		hash7 = "7ac47a17c511e25c06a53a1c7a5fbbf05f41f047a4a40b71afa81ce7b59f4b03"
		hash8 = "9a5097d0e8dc29a2814adac070c80fd4b149b33e56aaaf9235af9e87b0501d91"
		hash9 = "9efb5932c0753e45504fc9e8444209b92c2bdf22e63b1c1a44e2d52cb62b4548"
		hash10 = "d40b16307d6434c3281374c0e1bbc0f6db388883e7f6266c3c81de0694266882"

	strings:
		$s1 = ".StartInfo.FileName = 'cmd.exe';" ascii
		$s2 = "<xsl:template match=\"\"/root\"\">" ascii fullword
		$s3 = "<?xml version=\"\"1.0\"\"?><root>test</root>\";" ascii fullword

	condition:
		uint16( 0 ) == 0x253c and filesize < 6KB and all of them
}

rule SIGNATURE_BASE_WEBSHELL_PAS_Webshell : FILE
{
	meta:
		description = "Detects P.A.S. PHP webshell - Based on DHS/FBI JAR-16-2029 (Grizzly  Steppe)"
		author = "FR/ANSSI/SDO (modified by Florian Roth)"
		id = "862aab77-936e-524c-8669-4f48730f4ed5"
		date = "2021-02-15"
		modified = "2024-05-25"
		reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_sandworm_centreon.yar#L10-L28"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "977ee0fdf0e92ccea6b71fea7b2c7aed2965c6966d8af86230ccb0f95b286694"
		score = 70
		quality = 85
		tags = "FILE"

	strings:
		$php = "<?php"
		$strreplace = "(str_replace("
		$md5 = ".substr(md5(strrev($"
		$gzinflate = "gzinflate"
		$cookie = "_COOKIE"
		$isset = "isset"

	condition:
		( filesize > 20KB and filesize < 200KB ) and all of them
}

rule SIGNATURE_BASE_WEBSHELL_PAS_Webshell_Ziparchivefile
{
	meta:
		description = "Detects an archive file created by P.A.S. for download operation"
		author = "FR/ANSSI/SDO (modified by Florian Roth)"
		id = "081cc65b-e51c-59fc-a518-cd986e8ee2f7"
		date = "2021-02-15"
		modified = "2024-05-25"
		reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_sandworm_centreon.yar#L30-L42"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "c15e7022f45ec211ba635d6cd31bab16f4fb0d3038fb19d5765e0f751c14a826"
		score = 80
		quality = 85
		tags = ""

	strings:
		$s1 = "Archive created by P.A.S. v."

	condition:
		$s1
}

rule SIGNATURE_BASE_WEBSHELL_PAS_Webshell_Perlnetworkscript : FILE
{
	meta:
		description = "Detects PERL scripts created by P.A.S. webshell"
		author = "FR/ANSSI/SDO"
		id = "1625b63f-ead7-5712-92b4-0ce6ecc49fd4"
		date = "2021-02-15"
		modified = "2024-05-25"
		reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_sandworm_centreon.yar#L44-L62"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "b170c07a005e737c8069f2cc63f869d4d3ff6593b3bfca5bcaf02d7808da6852"
		score = 90
		quality = 85
		tags = "FILE"

	strings:
		$pl_start = "#!/usr/bin/perl\n$SIG{'CHLD'}='IGNORE'; use IO::Socket; use FileHandle;"
		$pl_status = "$o=\" [OK]\";$e=\" Error: \""
		$pl_socket = "socket(SOCKET, PF_INET, SOCK_STREAM,$tcp) or die print \"$l$e$!$l"
		$msg1 = "print \"$l OK! I\\'m successful connected.$l\""
		$msg2 = "print \"$l OK! I\\'m accept connection.$l\""

	condition:
		filesize < 6000 and ( $pl_start at 0 and all of ( $pl* ) ) or any of ( $msg* )
}

rule SIGNATURE_BASE_WEBSHELL_PAS_Webshell_Sqldumpfile
{
	meta:
		description = "Detects SQL dump file created by P.A.S. webshell"
		author = "FR/ANSSI/SDO"
		id = "4c26feeb-3031-5c91-9eeb-4b5fe9702e39"
		date = "2021-02-15"
		modified = "2024-05-25"
		reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_sandworm_centreon.yar#L64-L76"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "c34abcada22fdf462fd66cc2da18ab9e54215defc6f7a7a95b5a80d1155a2ffe"
		score = 90
		quality = 85
		tags = ""

	strings:
		$ = "-- [ SQL Dump created by P.A.S. ] --"

	condition:
		1 of them
}

rule SIGNATURE_BASE_M_Hunting_Webshell_LIGHTWIRE_2 : FILE
{
	meta:
		description = "Detects LIGHTWIRE based on the RC4 decoding and execution 1-liner."
		author = "Mandiant (modified by Florian Roth)"
		id = "9451da63-c68e-51e8-b4b1-c3082d46fbf6"
		date = "2024-01-11"
		modified = "2024-01-12"
		reference = "https://www.mandiant.com/resources/blog/suspected-apt-targets-ivanti-zero-day"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_report_ivanti_mandiant_jan24.yar#L60-L81"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		hash = "3d97f55a03ceb4f71671aa2ecf5b24e9"
		logic_hash = "37b22a6c45dd53bc7b3f0c75cc5072e990246fea24591d192176c0b496e92084"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "eval{my"
		$s2 = "Crypt::RC4->new(\""
		$s3 = "->RC4(decode_base64(CGI::param('"
		$s4 = ";eval $"
		$s5 = "\"Compatibility check: $@\";}"

	condition:
		filesize < 10KB and all of them
}

rule SIGNATURE_BASE_Hvs_APT37_Webshell_Img_Thumbs_Asp : FILE
{
	meta:
		description = "Webshell named img.asp, thumbs.asp or thumb.asp used by APT37"
		author = "Moritz Oettle"
		id = "e45d4507-81de-5f72-9ce2-4f0e3e5c62b1"
		date = "2020-12-15"
		modified = "2023-12-05"
		reference = "https://www.hvs-consulting.de/media/downloads/ThreatReport-Lazarus.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_lazarus_dec20.yar#L68-L95"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		hash = "94d2448d3794ae3f29678a7337473d259b5cfd1c7f703fe53ee6c84dd10a48ef"
		logic_hash = "58ccee11c08330c8cd4148e623a2e59e024d6d5f3067331dbdd962d0f6a8daa4"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "strMsg = \"E : F\"" fullword ascii
		$s2 = "strMsg = \"S : \" & Len(fileData)" fullword ascii
		$s3 = "Left(workDir, InStrRev(workDir, \"/\")) & \"video\""
		$a1 = "Server.CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
		$a2 = "Dim tmpPath, workDir" fullword ascii
		$a3 = "Dim objFSO, objTextStream" fullword ascii
		$a4 = "workDir = Request.ServerVariables(\"URL\")" fullword ascii
		$a5 = "InStrRev(workDir, \"/\")" ascii
		$g1 = "WriteFile = 0" fullword ascii
		$g2 = "fileData = Request.Form(\"fp\")" fullword ascii
		$g3 = "fileName = Request.Form(\"fr\")" fullword ascii
		$g4 = "Err.Clear()" fullword ascii
		$g5 = "Option Explicit" fullword ascii

	condition:
		filesize < 2KB and ( ( 1 of ( $s* ) ) or ( 3 of ( $a* ) ) or ( 5 of ( $g* ) ) )
}

rule SIGNATURE_BASE_Hvs_APT37_Webshell_Template_Query_Asp : FILE
{
	meta:
		description = "Webshell named template-query.aspimg.asp used by APT37"
		author = "Moritz Oettle"
		id = "dc006b46-4c51-59cd-8b7d-adbfec86cd2e"
		date = "2020-12-15"
		modified = "2023-12-05"
		reference = "https://www.hvs-consulting.de/media/downloads/ThreatReport-Lazarus.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_lazarus_dec20.yar#L97-L120"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		hash = "961a66d01c86fa5982e0538215b17fb9fae2991331dfea812b8c031e2ceb0d90"
		logic_hash = "d8bd017e9103bddb0b8a86effa8a4b0617b54bd643bcc36b6f678a3e60f8559f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$g1 = "server.scripttimeout=600" fullword ascii
		$g2 = "response.buffer=true" fullword ascii
		$g3 = "response.expires=-1" fullword ascii
		$g4 = "session.timeout=600" fullword ascii
		$a1 = "redhat hacker" ascii
		$a2 = "want_pre.asp" ascii
		$a3 = "vgo=\"admin\"" ascii
		$a4 = "ywc=false" ascii
		$s1 = "public  br,ygv,gbc,ydo,yka,wzd,sod,vmd" fullword ascii

	condition:
		filesize > 70KB and filesize < 200KB and ( ( 1 of ( $s* ) ) or ( 2 of ( $a* ) ) or ( 3 of ( $g* ) ) )
}

rule SIGNATURE_BASE_WEBSHELL_PHP_Unknown_1 : FILE
{
	meta:
		description = "obfuscated php webshell"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "93d01a4c-4c18-55d2-b682-68a1f6460889"
		date = "2021-01-07"
		modified = "2023-04-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/gen_webshells.yar#L867-L889"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		hash = "12ce6c7167b33cc4e8bdec29fb1cfc44ac9487d1"
		hash = "cf4abbd568ce0c0dfce1f2e4af669ad2"
		logic_hash = "ce2d4c87c001a45febf7eac5474aa0d24ea73067f9154203ef5653bf77e7028f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		importance = 70

	strings:
		$sp0 = /^<\?php \$[a-z]{3,30} = '/ wide ascii
		$sp1 = "=explode(chr(" wide ascii
		$sp2 = "; if (!function_exists('" wide ascii
		$sp3 = " = NULL; for(" wide ascii

	condition:
		filesize < 300KB and all of ( $sp* )
}

rule SIGNATURE_BASE_WEBSHELL_PHP_In_Htaccess : FILE
{
	meta:
		description = "Use Apache .htaccess to execute php code inside .htaccess"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "0f5edff9-22b2-50c9-ae81-72698ea8e7db"
		date = "2021-01-07"
		modified = "2023-07-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/gen_webshells.yar#L2755-L2777"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		hash = "c026d4512a32d93899d486c6f11d1e13b058a713"
		hash = "d79e9b13a32a9e9f3fa36aa1a4baf444bfd2599a"
		hash = "e1d1091fee6026829e037b2c70c228344955c263"
		hash = "c026d4512a32d93899d486c6f11d1e13b058a713"
		hash = "8c9e65cd3ef093cd9c5b418dc5116845aa6602bc92b9b5991b27344d8b3f7ef2"
		logic_hash = "0652a4cb0cb6c61afece5c2e4cbf2f281714509f0d828047f2e3ccd411602115"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		importance = 70

	strings:
		$hta = "AddType application/x-httpd-php .htaccess" wide ascii

	condition:
		filesize < 100KB and $hta
}

rule SIGNATURE_BASE_WEBSHELL_JSP_Generic_Processbuilder : FILE
{
	meta:
		description = "Generic JSP webshell which uses processbuilder to execute user input"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "2a7c5f44-24a1-5f43-996e-945c209b79b1"
		date = "2021-01-07"
		modified = "2023-04-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/gen_webshells.yar#L5962-L5999"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		hash = "82198670ac2072cd5c2853d59dcd0f8dfcc28923"
		hash = "c05a520d96e4ebf9eb5c73fc0fa446ceb5caf343"
		hash = "347a55c174ee39ec912d9107e971d740f3208d53af43ea480f502d177106bbe8"
		hash = "d0ba29b646274e8cda5be1b940a38d248880d9e2bba11d994d4392c80d6b65bd"
		logic_hash = "fffc173cc23e158e319e48097243a64da232151e441c39e4b6ecc2565a82d862"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		importance = 70

	strings:
		$exec = "ProcessBuilder" fullword wide ascii
		$start = "start" fullword wide ascii
		$input1 = "getParameter" fullword ascii wide
		$input2 = "getHeaders" fullword ascii wide
		$input3 = "getInputStream" fullword ascii wide
		$input4 = "getReader" fullword ascii wide
		$req1 = "request" fullword ascii wide
		$req2 = "HttpServletRequest" fullword ascii wide
		$req3 = "getRequest" fullword ascii wide

	condition:
		filesize < 2000 and ( any of ( $input* ) and any of ( $req* ) ) and $exec and $start
}

rule SIGNATURE_BASE_WEBSHELL_Cookie_Post_Obfuscation : FILE
{
	meta:
		description = "Detects webshell using cookie POST"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "cc5ded80-5e58-5b25-86d1-1c492042c740"
		date = "2023-01-28"
		modified = "2023-04-05"
		reference = "https://github.com/SigmaHQ/Detection-Rule-License/blob/main/LICENSE.Detection.Rules.md"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/gen_webshells.yar#L6882-L6908"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		hash = "d08a00e56feb78b7f6599bad6b9b1d8626ce9a6ea1dfdc038358f4c74e6f65c9"
		hash = "2ce5c4d31682a5a59b665905a6f698c280451117e4aa3aee11523472688edb31"
		hash = "ff732d91a93dfd1612aed24bbb4d13edb0ab224d874f622943aaeeed4356c662"
		hash = "a3b64e9e065602d2863fcab641c75f5d8ec67c8632db0f78ca33ded0f4cea257"
		hash = "d41abce305b0dc9bd3a9feb0b6b35e8e39db9e75efb055d0b1205a9f0c89128e"
		hash = "333560bdc876fb0186fae97a58c27dd68123be875d510f46098fc5a61615f124"
		hash = "2efdb79cdde9396ff3dd567db8876607577718db692adf641f595626ef64d3a4"
		hash = "e1bd3be0cf525a0d61bf8c18e3ffaf3330c1c27c861aede486fd0f1b6930f69a"
		hash = "f8cdedd21b2cc29497896ec5b6e5863cd67cc1a798d929fd32cdbb654a69168a"
		logic_hash = "87229859ca3ee8f8b79360603c421528cda2ecefcc46d4080236d09b2dd510fb"
		score = 75
		quality = 85
		tags = "FILE"
		importance = 70

	strings:
		$s1 = "]($_COOKIE, $_POST) as $"
		$s2 = "function"
		$s3 = "Array"

	condition:
		( uint16( 0 ) == 0x3f3c and filesize < 100KB and ( all of them ) )
}

rule SIGNATURE_BASE_WEBSHELL_ASP_Embedded_Mar21_1 : FILE
{
	meta:
		description = "Detects ASP webshells"
		author = "Florian Roth (Nextron Systems)"
		id = "7cf7db9d-8f8a-51db-a0e6-84748e8f9e1f"
		date = "2021-03-05"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_hafnium.yar#L2-L16"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "4a8b4cea6f53dad9771cb694ec55f305f04dfdbd8e663154cad672ca414c138c"
		score = 85
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "<script runat=\"server\">" nocase
		$s2 = "new System.IO.StreamWriter(Request.Form["
		$s3 = ".Write(Request.Form["

	condition:
		filesize < 100KB and all of them
}

rule SIGNATURE_BASE_APT_WEBSHELL_HAFNIUM_Secchecker_Mar21_1 : FILE
{
	meta:
		description = "Detects HAFNIUM SecChecker webshell"
		author = "Florian Roth (Nextron Systems)"
		id = "73db3d78-7ece-53be-9efb-d19801993d5e"
		date = "2021-03-05"
		modified = "2023-12-05"
		reference = "https://twitter.com/markus_neis/status/1367794681237667840"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_hafnium.yar#L18-L33"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "e0e4df860bdde7d5c277f596535c493d926095be6f46f6ba41b6177afbfc5cd9"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "b75f163ca9b9240bf4b37ad92bc7556b40a17e27c2b8ed5c8991385fe07d17d0"

	strings:
		$x1 = "<%if(System.IO.File.Exists(\"c:\\\\program files (x86)\\\\fireeye\\\\xagt.exe" ascii
		$x2 = "\\csfalconservice.exe\")){Response.Write( \"3\");}%></head>" ascii fullword

	condition:
		uint16( 0 ) == 0x253c and filesize < 1KB and 1 of them or 2 of them
}

rule SIGNATURE_BASE_APT_WEBSHELL_HAFNIUM_Chopper_Webshell : APT HAFNIUM WEBSHELL FILE
{
	meta:
		description = "Detects Chopper WebShell Injection Variant (not only Hafnium related)"
		author = "Markus Neis,Swisscom"
		id = "25dcf166-4aea-5680-b161-c5fc8d74b987"
		date = "2021-03-05"
		modified = "2023-12-05"
		reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_hafnium.yar#L50-L65"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "c185a8da2a18fa59a8eeb36dbd95ba12c9c61717efc5f2d19d2d5b27ee243f2b"
		score = 75
		quality = 85
		tags = "APT, HAFNIUM, WEBSHELL, FILE"

	strings:
		$x1 = "runat=\"server\">" nocase
		$s1 = "<script language=\"JScript\" runat=\"server\">function Page_Load(){eval(Request" nocase
		$s2 = "protected void Page_Load(object sender, EventArgs e){System.IO.StreamWriter sw = new System.IO.StreamWriter(Request.Form[\"p\"] , false, Encoding.Default);sw.Write(Request.Form[\"f\"]);"
		$s3 = "<script language=\"JScript\" runat=\"server\"> function Page_Load(){eval (Request[\"" nocase

	condition:
		filesize < 10KB and $x1 and 1 of ( $s* )
}

rule SIGNATURE_BASE_APT_WEBSHELL_Tiny_Webshell : APT HAFNIUM WEBSHELL FILE
{
	meta:
		description = "Detects WebShell Injection"
		author = "Markus Neis,Swisscom"
		id = "aa2fcecc-4c8b-570d-a81a-5dfb16c04e05"
		date = "2021-03-05"
		modified = "2023-12-05"
		reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_hafnium.yar#L67-L82"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		hash = "099c8625c58b315b6c11f5baeb859f4c"
		logic_hash = "9309f9b57353b6fe292048d00794699a8637a3e6e429c562fb36c7e459003a3b"
		score = 75
		quality = 85
		tags = "APT, HAFNIUM, WEBSHELL, FILE"

	strings:
		$x1 = "<%@ Page Language=\"Jscript\" Debug=true%>"
		$s1 = "=Request.Form(\""
		$s2 = "eval("

	condition:
		filesize < 300 and all of ( $s* ) and $x1
}

rule SIGNATURE_BASE_WEBSHELL_ASPX_Simpleseesharp : WEBSHELL UNCLASSIFIED FILE
{
	meta:
		description = "A simple ASPX Webshell that allows an attacker to write further files to disk."
		author = "threatintel@volexity.com"
		id = "469fdf5c-e09e-5d44-a2e6-0864dcd0e18a"
		date = "2021-03-01"
		modified = "2023-12-05"
		reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_hafnium.yar#L121-L136"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		hash = "893cd3583b49cb706b3e55ecb2ed0757b977a21f5c72e041392d1256f31166e2"
		logic_hash = "6f62249a68bae94e5cbdb4319ea5cde9dc071ec7a4760df3aafe78bc1e072c30"
		score = 75
		quality = 85
		tags = "WEBSHELL, UNCLASSIFIED, FILE"

	strings:
		$header = "<%@ Page Language=\"C#\" %>"
		$body = "<% HttpPostedFile thisFile = Request.Files[0];thisFile.SaveAs(Path.Combine"

	condition:
		$header at 0 and $body and filesize < 1KB
}

rule SIGNATURE_BASE_WEBSHELL_ASPX_Fileexplorer_Mar21_1 : FILE
{
	meta:
		description = "Detects Chopper like ASPX Webshells"
		author = "Florian Roth (Nextron Systems)"
		id = "edcaa2a8-6fea-584e-90c2-307a2dfc9f7f"
		date = "2021-03-31"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_hafnium.yar#L363-L397"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "7b4ffd222b38e76455fff2650b72bdcaff281323103f342b427013cd3fffdc21"
		score = 80
		quality = 85
		tags = "FILE"
		hash1 = "a8c63c418609c1c291b3e731ca85ded4b3e0fba83f3489c21a3199173b176a75"

	strings:
		$x1 = "<span style=\"background-color: #778899; color: #fff; padding: 5px; cursor: pointer\" onclick=" ascii
		$xc1 = { 3C 61 73 70 3A 48 69 64 64 65 6E 46 69 65 6C 64
               20 72 75 6E 61 74 3D 22 73 65 72 76 65 72 22 20
               49 44 3D 22 ?? ?? ?? ?? ?? 22 20 2F 3E 3C 62 72
               20 2F 3E 3C 62 72 20 2F 3E 20 50 72 6F 63 65 73
               73 20 4E 61 6D 65 3A 3C 61 73 70 3A 54 65 78 74
               42 6F 78 20 49 44 3D }
		$xc2 = { 22 3E 43 6F 6D 6D 61 6E 64 3C 2F 6C 61 62 65 6C
               3E 3C 69 6E 70 75 74 20 69 64 3D 22 ?? ?? ?? ??
               ?? 22 20 74 79 70 65 3D 22 72 61 64 69 6F 22 20
               6E 61 6D 65 3D 22 74 61 62 73 22 3E 3C 6C 61 62
               65 6C 20 66 6F 72 3D 22 ?? ?? ?? ?? ?? 22 3E 46
               69 6C 65 20 45 78 70 6C 6F 72 65 72 3C 2F 6C 61
               62 65 6C 3E 3C 25 2D 2D }
		$r1 = "(Request.Form[" ascii
		$s1 = ".Text + \" Created!\";" ascii
		$s2 = "DriveInfo.GetDrives()" ascii
		$s3 = "Encoding.UTF8.GetString(FromBase64String(str.Replace(" ascii
		$s4 = "encodeURIComponent(btoa(String.fromCharCode.apply(null, new Uint8Array(bytes))));;"

	condition:
		uint16( 0 ) == 0x253c and filesize < 100KB and ( 1 of ( $x* ) or 2 of them ) or 4 of them
}

rule SIGNATURE_BASE_WEBSHELL_ASPX_Chopper_Like_Mar21_1 : FILE
{
	meta:
		description = "Detects Chopper like ASPX Webshells"
		author = "Florian Roth (Nextron Systems)"
		id = "a4dc1880-865f-5e20-89a2-3a642c453ef9"
		date = "2021-03-31"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_hafnium.yar#L399-L416"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "baa9eb1e3c4ac5ce49d27b1c3f75c8b6590567e25d98761a8b704478f2cee970"
		score = 85
		quality = 85
		tags = "FILE"
		hash1 = "ac44513e5ef93d8cbc17219350682c2246af6d5eb85c1b4302141d94c3b06c90"

	strings:
		$s1 = "http://f/<script language=\"JScript\" runat=\"server\">var _0x" ascii
		$s2 = "));function Page_Load(){var _0x" ascii
		$s3 = ";eval(Request[_0x" ascii
		$s4 = "','orange','unsafe','" ascii

	condition:
		filesize < 3KB and 1 of them or 2 of them
}

rule SIGNATURE_BASE_WEBSHELL_ASPX_Sharepoint_Drop_CVE_2025_53770_Jul25 : CVE_2025_53770 FILE
{
	meta:
		description = "Detects ASPX web shell dropped during the exploitation of SharePoint RCE vulnerability CVE-2025-53770"
		author = "Florian Roth"
		id = "136ab1a3-647b-5196-9e08-12c3b913bd55"
		date = "2025-07-20"
		modified = "2025-07-25"
		reference = "https://research.eye.security/sharepoint-under-siege/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/expl_sharepoint_jul25.yar#L1-L20"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		hash = "27c45b8ed7b8a7e5fff473b50c24028bd028a9fe8e25e5cea2bf5e676e531014"
		hash = "92bb4ddb98eeaf11fc15bb32e71d0a63256a0ed826a03ba293ce3a8bf057a514"
		hash = "b336f936be13b3d01a8544ea3906193608022b40c28dd8f1f281e361c9b64e93"
		logic_hash = "3c7bb848fc73418d5a3ecae6e9f637a7d07bf45a75b1bd0a278fdbfae428d619"
		score = 80
		quality = 85
		tags = "CVE-2025-53770, FILE"

	strings:
		$x1 = "var sy = System.Reflection.Assembly.Load(" ascii
		$x2 = "Response.Write(cg.ValidationKey+" ascii
		$s1 = "<script runat=\"server\" language=\"c#\" CODEPAGE=\"65001\">" ascii fullword

	condition:
		filesize < 4KB and 1 of ( $x* ) or all of them
}

rule SIGNATURE_BASE_APT_WEBSHELL_PHP_Sandworm_May20_1 : FILE
{
	meta:
		description = "Detects GIF header PHP webshell used by Sandworm on compromised machines"
		author = "Florian Roth (Nextron Systems)"
		id = "b9ec02c2-fa83-5f21-95cf-3528047b2d01"
		date = "2020-05-28"
		modified = "2023-12-05"
		reference = "https://media.defense.gov/2020/May/28/2002306626/-1/-1/0/CSA%20Sandworm%20Actors%20Exploiting%20Vulnerability%20in%20Exim%20Transfer%20Agent%2020200528.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_sandworm_exim_expl.yar#L86-L101"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "0d10f618c7b465c7691d6054e994a76f56c12eb0a36d2d98b5accd2c1e2c1da7"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "dc074464e50502459038ac127b50b8c68ed52817a61c2f97f0add33447c8f730"
		hash2 = "538d713cb47a6b5ec6a3416404e0fc1ebcbc219a127315529f519f936420c80e"

	strings:
		$h1 = "GIF89a <?php $" ascii
		$s1 = "str_replace(" ascii

	condition:
		filesize < 10KB and $h1 at 0 and $s1
}

rule SIGNATURE_BASE_APT_Webshell_SUPERNOVA_1 : FILE
{
	meta:
		description = "SUPERNOVA is a .NET web shell backdoor masquerading as a legitimate SolarWinds web service handler. SUPERNOVA inspects and responds to HTTP requests with the appropriate HTTP query strings, Cookies, and/or HTML form values (e.g. named codes, class, method, and args). This rule is looking for specific strings and attributes related to SUPERNOVA."
		author = "FireEye"
		id = "73a27fa2-a846-5f4b-8182-064ac06c71a8"
		date = "2020-12-14"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_solarwinds_sunburst.yar#L80-L99"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "8471e6b3675e7e9ccfe5b81ab4c599668f2de528f3b179a675f50aa1fd7814b2"
		score = 85
		quality = 81
		tags = "FILE"

	strings:
		$compile1 = "CompileAssemblyFromSource"
		$compile2 = "CreateCompiler"
		$context = "ProcessRequest"
		$httpmodule = "IHttpHandler" ascii
		$string1 = "clazz"
		$string2 = "//NetPerfMon//images//NoLogo.gif" wide
		$string3 = "SolarWinds" ascii nocase wide

	condition:
		uint16( 0 ) == 0x5a4d and uint32( uint32( 0x3C ) ) == 0x00004550 and filesize < 10KB and pe.imports ( "mscoree.dll" , "_CorDllMain" ) and $httpmodule and $context and all of ( $compile* ) and all of ( $string* )
}

rule SIGNATURE_BASE_APT_Webshell_SUPERNOVA_2 : FILE
{
	meta:
		description = "This rule is looking for specific strings related to SUPERNOVA. SUPERNOVA is a .NET web shell backdoor masquerading as a legitimate SolarWinds web service handler. SUPERNOVA inspects and responds to HTTP requests with the appropriate HTTP query strings, Cookies, and/or HTML form values (e.g. named codes, class, method, and args)."
		author = "FireEye"
		id = "c39bf9ba-fd62-5619-92b6-1633375ef197"
		date = "2020-12-14"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_solarwinds_sunburst.yar#L100-L118"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "96e344bd2ba3ee07784852db3e9935352762c2fa7b6be88f00cac10a90706ffc"
		score = 85
		quality = 83
		tags = "FILE"

	strings:
		$dynamic = "DynamicRun"
		$solar = "Solarwinds" nocase
		$string1 = "codes"
		$string2 = "clazz"
		$string3 = "method"
		$string4 = "args"

	condition:
		uint16( 0 ) == 0x5a4d and uint32( uint32( 0x3C ) ) == 0x00004550 and filesize < 10KB and 3 of ( $string* ) and $dynamic and $solar
}
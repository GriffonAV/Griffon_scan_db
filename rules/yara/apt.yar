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

rule CAPE_Adaptixbeacon
{
	meta:
		description = "AdaptixBeacon Payload"
		author = "enzok"
		id = "ae0bc10c-cfcd-59d4-8c24-34a03debe370"
		date = "2025-06-16"
		modified = "2025-10-28"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/781161f232730012ce5fc49cbe0cf2e57b3f6868/data/yara/CAPE/AdaptixBeacon.yar#L1-L18"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/781161f232730012ce5fc49cbe0cf2e57b3f6868/LICENSE"
		hash = "f78f5803be5704420cbb2e0ac3c57fcb3d9cdf443fbf1233c069760bee115b5d"
		logic_hash = "2c1d09cd5e19e5a09dde65411691afd5922959d4a7b5232b28ebf56f26d2f07d"
		score = 75
		quality = 70
		tags = ""
		cape_type = "AdaptixBeacon Payload"

	strings:
		$conf_1 = {8D ?? ?? E8 [3] 00 4? 89 [1-2] 4? 8B 4C 24 ?? E8 [3] 00 4? 8B 53 48 66 [0-1] 89 04 ?? E8}
		$conf_2 = {E8 [3] 00 48 8B 4C 24 ?? 48 89 43 78 E8 [3] 00 48 8B 4C 24 ?? 89 83 80 00 00 00 E8 [3] 00 03 83 80 00 00 00 48 8B 4C 24}
		$conf_3 = {E8 [3] 00 4? 8B 4C 24 ?? 4? 89 ?? 4? 89 43 58 E8 [3] 00 4? 8B 4C 24 ?? 4? 89 ?? 4? 89 43 60 E8 [3] 00 4? 8B 4C 24 ?? 4? 89 ?? 4? 89 43 68}
		$conf_4 = {8D ?? ?? 4? 89 ?? FF ?? 4? 89 ?? 4? 89 ?? 4? 8B ?? FF ?? ?? 4? 8B ?? 48 66 ?? 89 ?? ?? EB}
		$conf_5 = {48 89 ?? 4? 89 ?? FF ?? 4? 89 ?? 4? 89 D9 4? 89 ?? ?? 4? 8B 03 FF ?? ?? 4? 89 ?? 4? 89 ?? 4? 89 ?? ?? 4? 8B 03 FF ?? ?? 4? 89}
		$wininet_1 = {B9 77 00 00 00 [0-4] E8 [4] B9 69 00 00 00 88 ?4 24 [0-4] E8 [4] B9 6E 00 00 00 88 ?4 24}
		$wininet_2 = {B9 69 00 00 00 88 ?4 24 [0-4] E8 [4] B9 6E 00 00 00 88 ?4 24 [0-4] E8 [4] B9 65 00 00 00 88 ?4 24}

	condition:
		1 of ( $conf_* ) and 1 of ( $wininet_* )
}

rule DEADBITS_Dnspionage : APT DNSCHANGER FILE
{
	meta:
		description = "No description has been set in the source file - DeadBits"
		author = "Adam Swanda"
		id = "9f740645-60dc-5376-94ad-59d8efbf1942"
		date = "2019-07-18"
		modified = "2019-07-19"
		reference = "https://github.com/deadbits/yara-rules"
		source_url = "https://github.com/deadbits/yara-rules//blob/d002f7ecee23e09142a3ac3e79c84f71dda3f001/rules/DNSpionage.yara#L1-L47"
		license_url = "N/A"
		logic_hash = "f20c71d0698d98cc58fa199c708ec7bf5cb0ec62503a20b532e752dab9aab920"
		score = 75
		quality = 78
		tags = "APT, DNSCHANGER, FILE"
		Description = "Attempts to detect DNSpionage PE samples"
		Author = "Adam M. Swanda"

	strings:
		$x00 = "/Loginnn?id=" fullword ascii
		$hdr0 = "Content-Disposition: fo" fullword ascii
		$hdr1 = "Content-Type: multi" fullword ascii
		$ua0 = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.80 Safari/537.36" fullword ascii
		$ua1 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246" fullword ascii
		$str0 = "send command result error! status code is: " fullword ascii
		$str1 = "uploading command result form" fullword ascii
		$str2 = "log.txt" fullword ascii
		$str3 = "http host not found in config!" fullword ascii
		$str4 = "send command result" fullword ascii
		$str5 = "download error. status code: " fullword ascii
		$str6 = "get command with dns" fullword ascii
		$str7 = "dns host not found in config!" fullword ascii
		$str8 = "command result is: " fullword ascii
		$str9 = "command result size: " fullword ascii
		$str10 = "connection type not found in config!" fullword ascii
		$str11 = "commands: " fullword ascii
		$str12 = "command is: " fullword ascii
		$str13 = "port not found in config!" fullword ascii
		$str14 = "download filename not found! " fullword ascii
		$str15 = "base64 key not found in config!" fullword ascii
		$str16 = "download filename is: " fullword ascii
		$str17 = "config json is not valid" fullword ascii
		$str18 = "config file will be changed from server!" fullword ascii

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 1000KB and ( ( 5 of ( $str* ) ) or ( $x00 and ( 1 of ( $hdr* ) ) and 1 of ( $ua* ) ) )
}

rule DEADBITS_APT34_VALUEVAULT : APT34 INFOSTEALER WINMALWARE FILE
{
	meta:
		description = "No description has been set in the source file - DeadBits"
		author = "Adam Swanda"
		id = "11d08fe7-9080-5393-b566-6f01e3eec18b"
		date = "2019-07-22"
		modified = "2020-02-02"
		reference = "https://www.fireeye.com/blog/threat-research/2019/07/hard-pass-declining-apt34-invite-to-join-their-professional-network.html"
		source_url = "https://github.com/deadbits/yara-rules//blob/d002f7ecee23e09142a3ac3e79c84f71dda3f001/rules/APT34_VALUEVAULT.yara#L1-L63"
		license_url = "N/A"
		logic_hash = "311eed153920b29b8d9e99651fe62259d685140d12bb073001e0576811a01198"
		score = 75
		quality = 78
		tags = "APT34, INFOSTEALER, WINMALWARE, FILE"
		Description = "Information stealing malware used by APT34, written in Go."

	strings:
		$fsociety = "fsociety.dat" ascii
		$powershell = "New-Object -ComObject Shell.Application" ascii
		$gobuild = "Go build ID: " ascii
		$gopath01 = "browsers-password-cracker" ascii nocase
		$gopath02 = "main.go" ascii nocase
		$gopath03 = "mozilla.go" ascii nocase
		$gopath04 = "ie.go" ascii nocase
		$str1 = "main.Decrypt" ascii fullword
		$str3 = "main.NewBlob" ascii fullword
		$str4 = "main.CheckFileExist" ascii fullword
		$str5 = "main.CopyFileToDirectory" ascii fullword
		$str6 = "main.CrackChromeBased" ascii fullword
		$str7 = "main.CrackIE" ascii fullword
		$str8 = "main.decipherPassword" ascii fullword
		$str9 = "main.DecodeUTF16" ascii fullword
		$str10 = "main.getHashTable" ascii fullword
		$str11 = "main.getHistory" ascii fullword
		$str12 = "main.getHistoryWithPowerShell" ascii fullword
		$str13 = "main.getHistoryFromRegistery" ascii fullword
		$str14 = "main.main" ascii fullword
		$str15 = "main.DecryptAESFromBase64" ascii fullword
		$str16 = "main.DecryptAES" ascii fullword
		$str17 = "main.CrackMozila" ascii fullword
		$str18 = "main.decodeLoginData" ascii fullword
		$str19 = "main.decrypt" ascii fullword
		$str20 = "main.removePadding" ascii fullword
		$str21 = "main.getLoginData" ascii fullword
		$str22 = "main.isMasterPasswordCorrect" ascii fullword
		$str23 = "main.decrypt3DES" ascii fullword
		$str24 = "main.getKey" ascii fullword
		$str25 = "main.manageMasterPassword" ascii fullword
		$str26 = "main.getFirefoxProfiles" ascii fullword
		$str27 = "main._Cfunc_DumpVault" ascii fullword
		$str28 = "main.CrackIEandEdgeNew" ascii fullword
		$str29 = "main.init.ializers" ascii fullword
		$str30 = "main.init" ascii fullword

	condition:
		uint16( 0 ) == 0x5a4d and ( ( 10 of ( $str* ) and 3 of ( $gopath* ) ) or ( $fsociety and $powershell and $gobuild ) or ( $fsociety and 10 of ( $str* ) ) )
}

rule DEADBITS_APT34_PICKPOCKET : APT APT34 INFOSTEALER WINMALWARE FILE
{
	meta:
		description = "Detects the PICKPOCKET malware used by APT34, a browser credential-theft tool identified by FireEye in May 2018"
		author = "Adam Swanda"
		id = "71db5c74-4964-5c5e-a830-242bfd0a2158"
		date = "2019-07-22"
		modified = "2019-07-22"
		reference = "https://www.fireeye.com/blog/threat-research/2019/07/hard-pass-declining-apt34-invite-to-join-their-professional-network.html"
		source_url = "https://github.com/deadbits/yara-rules//blob/d002f7ecee23e09142a3ac3e79c84f71dda3f001/rules/APT34_PICKPOCKET.yara#L1-L30"
		license_url = "N/A"
		logic_hash = "7063cff3eb42c4468e01c9b214161cd306f7126f66650d99d43168730d1dc83a"
		score = 75
		quality = 80
		tags = "APT, APT34, INFOSTEALER, WINMALWARE, FILE"

	strings:
		$s1 = "SELECT * FROM moz_logins;" ascii fullword
		$s2 = "\\nss3.dll" ascii fullword
		$s3 = "SELECT * FROM logins;" ascii fullword
		$s4 = "| %Q || substr(name,%d+18) ELSE name END WHERE tbl_name=%Q COLLATE nocase AND (type='table' OR type='index' OR type='trigger');" ascii fullword
		$s5 = "\\Login Data" ascii fullword
		$s6 = "%s\\Mozilla\\Firefox\\profiles.ini" ascii fullword
		$s7 = "Login Data" ascii fullword
		$s8 = "encryptedUsernamencryptedPasswor" ascii fullword
		$s10 = "%s\\Mozilla\\Firefox\\%s" ascii fullword
		$s11 = "encryptedUsername" ascii fullword
		$s12 = "2013-12-06 14:53:30 27392118af4c38c5203a04b8013e1afdb1cebd0d" ascii fullword
		$s13 = "27392118af4c38c5203a04b8013e1afdb1cebd0d" ascii
		$s15 = "= 'table' AND name!='sqlite_sequence'   AND coalesce(rootpage,1)>0" ascii fullword
		$s18 = "[*] FireFox :" fullword wide
		$s19 = "[*] Chrome :" fullword wide
		$s20 = "username_value" ascii fullword

	condition:
		uint16( 0 ) == 0x5a4d and ( 8 of them or all of them )
}

rule DEADBITS_APT34_LONGWATCH : APT34 WINMALWARE KEYLOGGER FILE
{
	meta:
		description = "No description has been set in the source file - DeadBits"
		author = "Adam Swanda"
		id = "74a6a408-2f0e-567d-8968-c304d258df81"
		date = "2019-07-22"
		modified = "2019-07-22"
		reference = "https://www.fireeye.com/blog/threat-research/2019/07/hard-pass-declining-apt34-invite-to-join-their-professional-network.html"
		source_url = "https://github.com/deadbits/yara-rules//blob/d002f7ecee23e09142a3ac3e79c84f71dda3f001/rules/APT34_LONGWATCH.yara#L1-L43"
		license_url = "N/A"
		logic_hash = "8f9ed228325800baea3a2874c71337709c04d93419d4d56821a791dbce6f4582"
		score = 75
		quality = 78
		tags = "APT34, WINMALWARE, KEYLOGGER, FILE"
		Description = "APT34 Keylogger"

	strings:
		$log = "c:\\windows\\temp\\log.txt" ascii fullword
		$clipboard = "---------------CLIPBOARD------------" ascii fullword
		$func0 = "\"Main Invoked.\"" ascii fullword
		$func1 = "\"Main Returned.\"" ascii fullword
		$logger3 = ">---------------------------------------------------" ascii fullword
		$logger4 = "[ENTER]" ascii fullword
		$logger5 = "[CapsLock]" ascii fullword
		$logger6 = "[CRTL]" ascii fullword
		$logger7 = "[PAGE_UP]" ascii fullword
		$logger8 = "[PAGE_DOWN]" ascii fullword
		$logger9 = "[HOME]" ascii fullword
		$logger10 = "[LEFT]" ascii fullword
		$logger11 = "[RIGHT]" ascii fullword
		$logger12 = "[DOWN]" ascii fullword
		$logger13 = "[PRINT]" ascii fullword
		$logger14 = "[PRINT SCREEN]" ascii fullword
		$logger15 = "[INSERT]" ascii fullword
		$logger16 = "[SLEEP]" ascii fullword
		$logger17 = "[PAUSE]" ascii fullword
		$logger18 = "[TAB]" ascii fullword
		$logger19 = "[ESC]" ascii fullword
		$logger20 = "[DEL]" ascii fullword
		$logger21 = "[ALT]" ascii fullword

	condition:
		uint16( 0 ) == 0x5a4d and $log and all of ( $func* ) and all of ( $logger* ) and $clipboard
}

rule ESET_Apt_Windows_TA410_Tendyron_Dropper
{
	meta:
		description = "TA410 Tendyron Dropper"
		author = "ESET Research"
		id = "8d1e16d9-b5c2-5427-a0b4-7dd00a9df5ec"
		date = "2020-12-09"
		modified = "2022-04-27"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/ta410/ta410.yar#L34-L53"
		license_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/LICENSE"
		logic_hash = "45f7300a4b85624ad3fda5c73a24f53f53cb7990def4d84e04dcd8e5747f4f2e"
		score = 75
		quality = 80
		tags = ""
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$s1 = "Global\\{F473B3BE-08EE-4710-A727-9E248F804F4A}" wide
		$s2 = "Global\\8D32CCB321B2" wide
		$s3 = "Global\\E4FE94F75490" wide
		$s4 = "Program Files (x86)\\Internet Explorer\\iexplore.exe" wide
		$s5 = "\\RPC Control\\OLE" wide
		$s6 = "ALPC Port" wide

	condition:
		int16 ( 0 ) == 0x5A4D and 4 of them
}

rule ESET_Apt_Windows_TA410_Tendyron_Installer
{
	meta:
		description = "TA410 Tendyron Installer"
		author = "ESET Research"
		id = "95ccad1c-99fb-5d38-aec0-650db3e06b35"
		date = "2020-12-09"
		modified = "2022-04-27"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/ta410/ta410.yar#L55-L73"
		license_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/LICENSE"
		logic_hash = "9c3afb924747614f27c31cf2c3d98f4932a9d11597a3ac94263bf93be02801da"
		score = 75
		quality = 80
		tags = ""
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$s1 = "Tendyron" wide
		$s2 = "OnKeyToken_KEB.dll" wide
		$s3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide
		$s4 = "Global\\8D32CCB321B2"
		$s5 = "\\RTFExploit\\"

	condition:
		int16 ( 0 ) == 0x5A4D and 3 of them
}

rule ESET_Apt_Windows_TA410_Tendyron_Downloader
{
	meta:
		description = "TA410 Tendyron Downloader"
		author = "ESET Research"
		id = "afd8a2a7-8d58-5a96-b9e0-6f8b859e83c5"
		date = "2020-12-09"
		modified = "2022-04-27"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/ta410/ta410.yar#L75-L107"
		license_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/LICENSE"
		logic_hash = "16030a78ae9af8783f5913644294ceff861c8264ead8ca99435032be6d7949ef"
		score = 75
		quality = 80
		tags = ""
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$chunk_1 = {
            8A 10
            80 F2 5C
            80 C2 5C
            88 10
            40
            83 E9 01
            75 ??
        }
		$s1 = "startModule" fullword

	condition:
		int16 ( 0 ) == 0x5A4D and all of them
}

rule ESET_Apt_Windows_TA410_X4_Strings
{
	meta:
		description = "Matches various strings found in TA410 X4"
		author = "ESET Research"
		id = "e6af4516-8b79-5182-8571-7dd530632ddc"
		date = "2020-10-09"
		modified = "2022-04-27"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/ta410/ta410.yar#L109-L125"
		license_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/LICENSE"
		logic_hash = "d4b2321a6d0eb0ca8d7c47596af2a45c22b3aef15d1832d64d6588a62cab312a"
		score = 75
		quality = 74
		tags = ""
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$s1 = "[X]InLoadSC" ascii wide nocase
		$s3 = "MachineKeys\\Log\\rsa.txt" ascii wide nocase
		$s4 = "MachineKeys\\Log\\output.log" ascii wide nocase

	condition:
		any of them
}

rule ESET_Apt_Windows_TA410_X4_Hash_Values : FILE
{
	meta:
		description = "Matches X4 hash function found in TA410 X4"
		author = "ESET Research"
		id = "859bb977-82d0-5314-b1a8-fb3bb06a1b28"
		date = "2020-10-09"
		modified = "2022-04-27"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/ta410/ta410.yar#L127-L149"
		license_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/LICENSE"
		logic_hash = "bcf3891ff888ca99af9aa0e239b29241ae819022607fb829c5731267add308ea"
		score = 75
		quality = 80
		tags = "FILE"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$s1 = {D1 10 76 C2 B6 03}
		$s2 = {71 3E A8 0D}
		$s3 = {DC 78 94 0E}
		$s4 = {40 0D E7 D6 06}
		$s5 = {83 BB FD E8 06}
		$s6 = {92 9D 9B FF EC 03}
		$s7 = {DD 0E FC FA F5 03}
		$s8 = {15 60 1E FB F5 03}

	condition:
		uint16( 0 ) == 0x5a4d and 4 of them
}

rule ESET_Apt_Windows_TA410_X4_Hash_Fct : FILE
{
	meta:
		description = "Matches X4 hash function found in TA410 X4"
		author = "ESET Research"
		id = "5ca435a4-7c6e-594d-8c4d-d577735884e6"
		date = "2020-10-09"
		modified = "2022-04-27"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/ta410/ta410.yar#L151-L187"
		license_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/LICENSE"
		logic_hash = "3b2d44cb7685a99e9aeb08f886f6876d43ee99d1e52e40705c3fa97ce3bfa9a0"
		score = 75
		quality = 80
		tags = "FILE"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$chunk_1 = {
            0F B6 01
            84 C0
            74 ??
            48 69 D2 83 00 00 00
            48 0F BE C0
            48 03 D0
            48 FF C1
            E9 ?? ?? ?? ??
        }

	condition:
		uint16( 0 ) == 0x5a4d and any of them
}

rule ESET_Apt_Windows_TA410_Lookback_Decryption : FILE
{
	meta:
		description = "Matches encryption/decryption function used by LookBack."
		author = "ESET Research"
		id = "91947c6b-f357-5cf8-8522-4dcd517d01cb"
		date = "2021-10-12"
		modified = "2022-04-27"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/ta410/ta410.yar#L189-L254"
		license_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/LICENSE"
		logic_hash = "016dca6be654fcd193acc481e6a998efbb77e7ebd09b26614422be1136dd02c0"
		score = 75
		quality = 80
		tags = "FILE"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$initialize = {
            8B C6           //mov eax, esi
            99              //cdq
            83 E2 03        //and edx, 3
            03 C2           //add eax, edx
            C1 F8 02        //sar eax, 2
            8A C8           //mov cl, al
            02 C0           //add al, al
            02 C8           //add cl, al
            88 4C 34 10         //mov byte ptr [esp + esi + 0x10], cl
            46              //inc esi
            81 FE 00 01 00 00       //cmp esi, 0x100
            72 ??
        }
		$generate = {
            8A 94 1C 10 01 ?? ??    //mov dl, byte ptr [esp + ebx + 0x110]
            8D 8C 24 10 01 ?? ??    //lea ecx, [esp + 0x110]
            0F B6 C3        //movzx eax, bl
            0F B6 44 04 10      //movzx eax, byte ptr [esp + eax + 0x10]
            32 C2           //xor al, dl
            02 F0           //add dh, al
            0F B6 C6        //movzx eax, dh
            03 C8           //add ecx, eax
            0F B6 01        //movzx eax, byte ptr [ecx]
            88 84 1C 10 01 ?? ??    //mov byte ptr [esp + ebx + 0x110], al
            43              //inc ebx
            88 11           //mov byte ptr [ecx], dl
            81 FB 00 06 00 00       //cmp ebx, 0x600
            72 ??           //jb 0x10025930
        }
		$decrypt = {
            0F B6 C6        //movzx eax, dh
            8D 8C 24 10 01 ?? ??    //lea ecx, [esp + 0x110]
            03 C8           //add ecx, eax
            8A 19           //mov bl, byte ptr [ecx]
            8A C3           //mov al, bl
            02 C6           //add al, dh
            FE C6           //inc dh
            02 F8           //add bh, al
            0F B6 C7        //movzx eax, bh
            8A 94 04 10 01 ?? ??    //mov dl, byte ptr [esp + eax + 0x110]
            88 9C 04 10 01 ?? ??    //mov byte ptr [esp + eax + 0x110], bl
            88 11           //mov byte ptr [ecx], dl
            0F B6 C2        //movzx eax, dl
            0F B6 CB        //movzx ecx, bl
            33 C8           //xor ecx, eax
            8A 84 0C 10 01 ?? ??    //mov al, byte ptr [esp + ecx + 0x110]
            30 04 2E        //xor byte ptr [esi + ebp], al
            46              //inc esi
            3B F7           //cmp esi, edi
            7C ??           //jl 0x10025980
        }

	condition:
		uint16( 0 ) == 0x5a4d and all of them
}

rule ESET_Apt_Windows_TA410_Lookback_Loader : FILE
{
	meta:
		description = "Matches the modified function in LookBack libcurl loader."
		author = "ESET Research"
		id = "d0aac4f6-f72f-5adf-8f8f-9251bad70131"
		date = "2021-10-12"
		modified = "2022-04-27"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/ta410/ta410.yar#L256-L309"
		license_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/LICENSE"
		logic_hash = "98390dd664227ad747e5572771d12e7ebd2475d26db27e85508347ac6f44f3bf"
		score = 75
		quality = 80
		tags = "FILE"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$chunk_1 = {
            FF 15 ?? ?? ?? ??      //call dword ptr [0x100530e0]
            6A 40          //push 0x40
            68 00 10 00 00     //push 0x1000
            68 F0 04 00 00     //push 0x4f0
            6A 00          //push 0
            FF 15 ?? ?? ?? ??      //call dword ptr [0x100530d4]
            8B E8          //mov ebp, eax
            B9 3C 01 00 00     //mov ecx, 0x13c
            BE 60 30 06 10     //mov esi, 0x10063060
            8B FD          //mov edi, ebp
            68 F0 04 00 00     //push 0x4f0
            F3 A5          //rep movsd dword ptr es:[edi], dword ptr [esi]
            55             //push ebp
            E8 ?? ?? ?? ??     //call 0x100258d0
            8B 0D ?? ?? ?? ??      //mov ecx, dword ptr [0x100530e4]
            A1 ?? ?? ?? ??     //mov eax, dword ptr [0x100530c8]
            68 6C 02 00 00     //push 0x26c
            89 4C 24 ??        //mov dword ptr [esp + 0x1c], ecx
            89 44 24 ??        //mov dword ptr [esp + 0x20], eax
            FF 15 ?? ?? ?? ??      //call dword ptr [0x10063038]
            8B D8          //mov ebx, eax
            B9 9B 00 00 00     //mov ecx, 0x9b
            BE 50 35 06 10     //mov esi, 0x10063550
            8B FB          //mov edi, ebx
            68 6C 02 00 00      //push 0x26c
            F3 A5          //rep movsd dword ptr es:[edi], dword ptr [esi]
            53             //push ebx
            E8 ?? ?? ?? ??     //call 0x100258d0
            83 C4 14           //add esp, 0x14
            8D 44 24 ??        //lea eax, [esp + 0x10]
            50             //push eax
            53             //push ebx
            8D 44 24 ??        //lea eax, [esp + 0x3c]
            50             //push eax
            A1 ?? ?? ?? ??     //mov eax, dword ptr [0x10063058]
            FF 74 24 ??        //push dword ptr [esp + 0x28]
            03 C5          //add eax, ebp
            FF D0          //call eax
        }

	condition:
		uint16( 0 ) == 0x5a4d and all of them
}


rule ESET_Apt_Windows_TA410_Lookback_Strings : FILE
{
	meta:
		description = "Matches multiple strings and export names in TA410 LookBack."
		author = "ESET Research"
		id = "b693c468-5abf-579d-bc03-67f67339feb9"
		date = "2021-10-12"
		modified = "2022-04-27"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/ta410/ta410.yar#L311-L331"
		license_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/LICENSE"
		logic_hash = "d17ed604e3691c20fe489f95197b7b802ec951ed13d538fa6643449485b326b2"
		score = 75
		quality = 80
		tags = "FILE"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$s1 = "SodomMainFree" ascii wide
		$s2 = "SodomMainInit" ascii wide
		$s3 = "SodomNormal.bin" ascii wide
		$s4 = "SodomHttp.bin" ascii wide
		$s5 = "sodom.ini" ascii wide
		$s6 = "SodomMainProc" ascii wide

	condition:
		uint16( 0 ) == 0x5a4d and ( 2 of them or pe.exports ( "SodomBodyLoad" ) or pe.exports ( "SodomBodyLoadTest" ) )
}

rule ESET_Apt_Windows_TA410_Lookback_HTTP : FILE
{
	meta:
		description = "Matches LookBack's hardcoded HTTP request"
		author = "ESET Research"
		id = "ca4ee437-5ac9-5715-90fb-e0e74a817bb5"
		date = "2021-10-12"
		modified = "2022-04-27"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/ta410/ta410.yar#L333-L349"
		license_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/LICENSE"
		logic_hash = "0e777f56136cd11d62abdf4f120410d5fe9cd522cfc06afbf085414a96279bf7"
		score = 75
		quality = 80
		tags = "FILE"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$s1 = "POST http://%s/status.php?r=%d%d HTTP/1.1\x0d\nAccept: text/html, application/xhtml+xml, */*\x0d\nAccept-Language: en-us\x0d\nUser-Agent: %s\x0d\nContent-Type: application/x-www-form-urlencoded\x0d\nAccept-Encoding: gzip, deflate\x0d\nHost: %s\x0d\nContent-Length: %d\x0d\nConnection: Keep-Alive\x0d\nCache-Control: no-cache\x0d\n\x0d\n" ascii wide
		$s2 = "id=1&op=report&status="

	condition:
		uint16( 0 ) == 0x5a4d and all of them
}

rule ESET_Apt_Windows_TA410_Lookback_Magic : FILE
{
	meta:
		description = "Matches message header creation in LookBack."
		author = "ESET Research"
		id = "5a40a307-772b-5600-9e58-f4bc6dfe6711"
		date = "2021-10-12"
		modified = "2022-04-27"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/ta410/ta410.yar#L351-L377"
		license_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/LICENSE"
		logic_hash = "442a08a77fd2db03e507c0d5a32b17ab4e5936a209f7af23ef3c33a4b9f3d0d5"
		score = 75
		quality = 80
		tags = "FILE"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$s1 = {
            C7 03 C2 2E AB 48           //mov dword ptr [ebx], 0x48ab2ec2
            ( A1 | 8B 15 ) ?? ?? ?? ??      //mov (eax | edx), x
            [0-1]               //push ebp
            89 ?3 04            //mov dword ptr [ebc + 4], reg
            8B 4? 24 ??             //mov reg, dword ptr [esp + X]
            89 4? 08            //mov dword ptr [ebx + 8], ??
            89 ?? 0C            //mov dword ptr [ebx + 0xc], ??
            8B 4? 24 ??             //mov reg, dword ptr [esp + X]
            [1-2]               //push 1 or 2 args
            E8 ?? ?? ?? ??          //call
        }

	condition:
		uint16( 0 ) == 0x5a4d and all of them
}

rule ESET_Apt_Windows_TA410_Flowcloud_Loader_Strings : FILE
{
	meta:
		description = "Matches various strings found in TA410 FlowCloud first stage."
		author = "ESET Research"
		id = "a3fb894f-8e26-5cbd-a1f2-8a9ab1db0901"
		date = "2021-10-12"
		modified = "2022-04-27"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/ta410/ta410.yar#L379-L415"
		license_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/LICENSE"
		logic_hash = "3c90723e009ffe2603910566ac52a324256676ee3ff128d94427681010e10e8b"
		score = 75
		quality = 78
		tags = "FILE"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$key = "y983nfdicu3j2dcn09wur9*^&initialize(y4r3inf;'fdskaf'SKF"
		$s2 = "startModule" fullword
		$s4 = "auto_start_module" wide
		$s5 = "load_main_module_after_install" wide
		$s6 = "terminate_if_fail" wide
		$s7 = "clear_run_mru" wide
		$s8 = "install_to_vista" wide
		$s9 = "load_ext_module" wide
		$s10 = "sll_only" wide
		$s11 = "fail_if_already_installed" wide
		$s12 = "clear_hardware_info" wide
		$s13 = "av_check" wide fullword
		$s14 = "check_rs" wide
		$s15 = "check_360" wide
		$s16 = "responsor.dat" wide ascii
		$s17 = "auto_start_after_install_check_anti" wide fullword
		$s18 = "auto_start_after_install" wide fullword
		$s19 = "extern_config.dat" wide fullword
		$s20 = "is_hhw" wide fullword
		$s21 = "SYSTEM\\Setup\\PrintResponsor" wide
		$event = "Global\\Event_{201a283f-e52b-450e-bf44-7dc436037e56}" wide ascii
		$s23 = "invalid encrypto hdr while decrypting"

	condition:
		uint16( 0 ) == 0x5a4d and ( $key or $event or 5 of ( $s* ) )
}

rule ESET_Apt_Windows_TA410_Flowcloud_Header_Decryption : FILE
{
	meta:
		description = "Matches the function used to decrypt resources headers in TA410 FlowCloud"
		author = "ESET Research"
		id = "403c1845-bc25-5a49-8553-8a0be18d6970"
		date = "2026-01-03"
		modified = "2022-04-27"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/ta410/ta410.yar#L417-L496"
		license_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/LICENSE"
		logic_hash = "74b6c42bf2de159b2b0a15637e6bd94069367e3000c887714d6e3b50aa3646be"
		score = 75
		quality = 80
		tags = "FILE"
		license = "BSD 2-Clause"

	strings:
		$chunk_1 = {
            8B 1E
            8B CF
            D3 CB
            8D 0C 28
            83 C7 06
            30 18
            8B 1E
            D3 CB
            8D 0C 02
            30 58 ??
            8B 1E
            D3 CB
            8B 4C 24 ??
            03 C8
            30 58 ??
            8B 1E
            D3 CB
            8B 4C 24 ??
            03 C8
            30 58 ??
            8B 1E
            D3 CB
            8B 4C 24 ??
            03 C8
            83 C0 06
            30 58 ??
            8B 1E
            D3 CB
            30 58 ??
            83 FF 10
            72 ??
        }

	condition:
		uint16( 0 ) == 0x5a4d and all of them
}

rule ESET_Apt_Windows_TA410_Flowcloud_Dll_Hijacking_Strings : FILE
{
	meta:
		description = "Matches filenames inside TA410 FlowCloud malicious DLL."
		author = "ESET Research"
		id = "6636d4d0-0a7f-5971-a7f4-58803042d874"
		date = "2021-10-12"
		modified = "2022-04-27"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/ta410/ta410.yar#L498-L517"
		license_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/LICENSE"
		logic_hash = "e8082d4216364a12ba395f772b5caed94b3068d26a2b3a97ef711d61a82f65b3"
		score = 75
		quality = 80
		tags = "FILE"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$dat1 = "emedres.dat" wide
		$dat2 = "vviewres.dat" wide
		$dat3 = "setlangloc.dat" wide
		$dll1 = "emedres.dll" wide
		$dll2 = "vviewres.dll" wide
		$dll3 = "setlangloc.dll" wide

	condition:
		uint16( 0 ) == 0x5a4d and ( all of ( $dat* ) or all of ( $dll* ) )
}

rule ESET_Apt_Windows_TA410_Flowcloud_Malicious_Dll_Antianalysis : FILE
{
	meta:
		description = "Matches anti-analysis techniques used in TA410 FlowCloud hijacking DLL."
		author = "ESET Research"
		id = "b38a1d4d-5053-5a6d-be8c-c00261936417"
		date = "2021-10-12"
		modified = "2022-04-27"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/ta410/ta410.yar#L519-L552"
		license_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/LICENSE"
		logic_hash = "8f14352118d32a43c17f70bd753acc48bd314965f10ab97818e8a434bbda96d9"
		score = 75
		quality = 80
		tags = "FILE"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$chunk_1 = {
            33 C0
            E8 ?? ?? ?? ??
            83 C0 10
            3D 00 00 00 80
            7D 01
            EB FF
            E0 50
            C3
        }

	condition:
		uint16( 0 ) == 0x5a4d and all of them
}


rule ESET_Apt_Windows_TA410_Flowcloud_Pdb : FILE
{
	meta:
		description = "Matches PDB paths found in TA410 FlowCloud."
		author = "ESET Research"
		id = "8bf25768-941e-55c6-bd21-f6b614c9d75d"
		date = "2021-10-12"
		modified = "2022-04-27"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/ta410/ta410.yar#L554-L567"
		license_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/LICENSE"
		logic_hash = "ff95ab0f8e68efe612a6e0d70cebd8bf815d6b5e3877c098ac0761382dc310d6"
		score = 75
		quality = 80
		tags = "FILE"
		license = "BSD 2-Clause"
		version = "1"

	condition:
		uint16( 0 ) == 0x5a4d and ( pe.pdb_path contains "\\FlowCloud\\trunk\\" or pe.pdb_path contains "\\flowcloud\\trunk\\" )
}

rule ESET_Apt_Windows_TA410_Flowcloud_Shellcode_Decryption : FILE
{
	meta:
		description = "Matches the decryption function used in TA410 FlowCloud self-decrypting DLL"
		author = "ESET Research"
		id = "8af7b2fa-be40-5ec8-8413-1c982a463a9a"
		date = "2021-10-12"
		modified = "2022-04-27"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/ta410/ta410.yar#L569-L615"
		license_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/LICENSE"
		logic_hash = "939ffe6a41c957aa5d6c012484b2deab49a5e71a4b7e203a41c180f872803921"
		score = 75
		quality = 80
		tags = "FILE"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$chunk_1 = {
            33 D2
            8B 45 ??
            BB 6B 04 00 00
            F7 F3
            81 C2 A8 01 00 00
            81 E2 FF 00 00 00
            8B 7D ??
            33 C9
            EB ??
            30 14 39
            00 14 39
            41
            3B 4D ??
            72 ??
        }

	condition:
		uint16( 0 ) == 0x5a4d and all of them
}

rule ESET_Apt_Windows_TA410_Flowcloud_Fcclient_Strings : FILE
{
	meta:
		description = "Strings found in fcClient/rescure.dat module."
		author = "ESET Research"
		id = "876bae0b-2612-559b-9ead-b633a3789663"
		date = "2021-10-12"
		modified = "2022-04-27"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/ta410/ta410.yar#L617-L639"
		license_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/LICENSE"
		logic_hash = "c05b7031a5aec1bcf29eca06c010c402edeb24a093a2043dbc21781dff22c7fe"
		score = 75
		quality = 80
		tags = "FILE"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$s1 = "df257bdd-847c-490e-9ef9-1d7dc883d3c0"
		$s2 = "\\{2AFF264E-B722-4359-8E0F-947B85594A9A}"
		$s3 = "Global\\{26C96B51-2B5D-4D7B-BED1-3DCA4848EDD1}" wide
		$s4 = "{804423C2-F490-4ac3-BFA5-13DEDE63A71A}" wide
		$s5 = "{A5124AF5-DF23-49bf-B0ED-A18ED3DEA027}" wide
		$s6 = "XXXModule_func.dll"
		$driver1 = "\\drivers\\hidmouse.sys" wide fullword
		$driver2 = "\\drivers\\hidusb.sys" wide fullword

	condition:
		uint16( 0 ) == 0x5a4d and ( any of ( $s* ) or all of ( $driver* ) )
}

rule ESET_Apt_Windows_TA410_Flowcloud_Fcclientdll_Strings : FILE
{
	meta:
		description = "Strings found in fcClientDll/responsor.dat module."
		author = "ESET Research"
		id = "80ecaf51-406f-590c-8f9c-59672683de02"
		date = "2021-10-12"
		modified = "2022-04-27"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/ta410/ta410.yar#L641-L669"
		license_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/LICENSE"
		logic_hash = "3a93f58cf14b57a96157077ec14aa6fb181e3da80f4ba46c0379a58b67c08a0e"
		score = 75
		quality = 80
		tags = "FILE"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$s1 = "http://%s/html/portlet/ext/draco/resources/draco_manager.swf/[[DYNAMIC]]/1"
		$s2 = "Cookie: COOKIE_SUPPORT=true; JSESSIONID=5C7E7A60D01D2891F40648DAB6CB3DF4.jvm1; COMPANY_ID=10301; ID=666e7375545678695645673d; PASSWORD=7a4b48574d746470447a303d; LOGIN=6863303130; SCREEN_NAME=4a2b455377766b657451493d; GUEST_LANGUAGE_ID=en-US"
		$fc_msg = ".fc_net.msg"
		$s4 = "\\pipe\\namedpipe_keymousespy_english" wide
		$s5 = "8932910381748^&*^$58876$%^ghjfgsa413901280dfjslajflsdka&*(^7867=89^&*F(^&*5678f5ds765f76%&*%&*5"
		$s6 = "cls_{CACB140B-0B82-4340-9B05-7983017BA3A4}" wide
		$s7 = "HTTP/1.1 200 OK\x0d\nServer: Apache-Coyote/1.1\x0d\nPragma: No-cache\x0d\nCache-Control: no-cache\x0d\nExpires: Thu, 01 Jan 1970 08:00:00 CST\x0d\nLast-Modified: Fri, 27 Apr 2012 08:11:04 GMT\x0d\nContent-Type: application/xml\x0d\nContent-Length: %d\x0d\nDate: %s GMT"
		$sql1 = "create table if not exists table_filed_space"
		$sql2 = "create table if not exists clipboard"
		$sql3 = "create trigger if not exists file_after_delete after delete on file"
		$sql4 = "create trigger if not exists file_data_after_insert after insert on file_data"
		$sql5 = "create trigger if not exists file_data_after_delete after delete on file_data"
		$sql6 = "create trigger if not exists file_data_after_update after update on file_data"
		$sql7 = "insert into file_data(file_id, ofs, data, status)"

	condition:
		uint16( 0 ) == 0x5a4d and ( any of ( $s* ) or #fc_msg >= 8 or 4 of ( $sql* ) )
}

rule ESET_Apt_Windows_TA410_Rootkit_Strings : FILE
{
	meta:
		description = "Strings found in TA410's Rootkit"
		author = "ESET Research"
		id = "a6a97721-571e-5414-9b00-5789d7bcd078"
		date = "2021-10-12"
		modified = "2022-04-27"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/ta410/ta410.yar#L671-L697"
		license_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/LICENSE"
		logic_hash = "1d3ad63508c5e4bca32b9a44b738cb4a7384ccfa5704ce329260adb342ea4e60"
		score = 75
		quality = 80
		tags = "FILE"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$driver1 = "\\Driver\\kbdclass" wide
		$driver2 = "\\Driver\\mouclass" wide
		$device1 = "\\Device\\KeyboardClass0" wide
		$device2 = "\\Device\\PointerClass0" wide
		$driver3 = "\\Driver\\tcpip" wide
		$device3 = "\\Device\\tcp" wide
		$driver4 = "\\Driver\\nsiproxy" wide
		$device4 = "\\Device\\Nsi" wide
		$reg1 = "\\Registry\\Machine\\SYSTEM\\Setup\\AllowStart\\ceipCommon" wide
		$reg2 = "RHH%d" wide
		$reg3 = "RHP%d" wide
		$s1 = "\\SystemRoot\\System32\\drivers\\hidmouse.sys" wide

	condition:
		uint16( 0 ) == 0x5a4d and all of ( $s1 , $reg* ) and ( all of ( $driver* ) or all of ( $device* ) )
}


rule ESET_Apt_Windows_TA410_Flowcloud_V5_Resources : FILE
{
	meta:
		description = "Matches sequence of PE resource IDs found in TA410 FlowCloud version 5.0.2"
		author = "ESET Research"
		id = "05a233f0-a823-5154-a47d-cede722d4710"
		date = "2021-10-12"
		modified = "2022-04-27"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/ta410/ta410.yar#L699-L720"
		license_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/LICENSE"
		logic_hash = "58f75dda53c6d4b3d88f464c452d855ac6dc88add5f4fba2641f52e7a1ae00ed"
		score = 75
		quality = 80
		tags = "FILE"
		license = "BSD 2-Clause"
		version = "1"

	condition:
		uint16( 0 ) == 0x5a4d and pe.number_of_resources >= 13 and for 12 resource in pe.resources : ( resource.type == 10 and resource.language == 1033 and ( resource.name_string == "1\x000\x000\x00" or resource.name_string == "1\x000\x000\x000\x00" or resource.name_string == "1\x000\x000\x000\x000\x00" or resource.name_string == "1\x000\x000\x001\x00" or resource.name_string == "1\x000\x001\x00" or resource.name_string == "1\x000\x002\x00" or resource.name_string == "1\x000\x003\x00" or resource.name_string == "1\x000\x004\x00" or resource.name_string == "1\x000\x005\x00" or resource.name_string == "1\x000\x006\x00" or resource.name_string == "1\x000\x007\x00" or resource.name_string == "1\x000\x008\x00" or resource.name_string == "1\x000\x009\x00" or resource.name_string == "1\x001\x000\x00" or resource.name_string == "2\x000\x000\x000\x00" or resource.name_string == "2\x000\x000\x001\x00" ) )
}


rule ESET_Apt_Windows_TA410_Flowcloud_V4_Resources : FILE
{
	meta:
		description = "Matches sequence of PE resource IDs found in TA410 FlowCloud version 4.1.3"
		author = "ESET Research"
		id = "57b98823-439f-5a2c-a8cb-ac5e98953b06"
		date = "2021-10-12"
		modified = "2022-04-27"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/ta410/ta410.yar#L722-L741"
		license_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/LICENSE"
		logic_hash = "7b475cfddb5f995f7e8e3293b8e6ae59a9e36143998bc444499b5dce467f8e9d"
		score = 75
		quality = 80
		tags = "FILE"
		license = "BSD 2-Clause"
		version = "1"

	condition:
		uint16( 0 ) == 0x5a4d and pe.number_of_resources >= 6 and for 5 resource in pe.resources : ( resource.type == 10 and resource.language == 1033 and ( resource.name_string == "1\x000\x000\x000\x000\x00" or resource.name_string == "1\x000\x000\x000\x001\x00" or resource.name_string == "1\x000\x000\x000\x002\x00" or resource.name_string == "1\x000\x000\x000\x003\x00" or resource.name_string == "1\x000\x000\x000\x004\x00" or resource.name_string == "1\x000\x000\x000\x005\x00" or resource.name_string == "1\x000\x001\x000\x000\x00" ) )
}

rule ESET_Apt_Windows_Invisimole_Logs : FILE
{
	meta:
		description = "Detects log files with collected created by InvisiMole's RC2CL backdoor"
		author = "ESET Research"
		id = "151883ad-1f44-55b4-b12a-f0d399527189"
		date = "2021-05-17"
		modified = "2021-05-17"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/invisimole/invisimole.yar#L54-L77"
		license_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/LICENSE"
		logic_hash = "d42423ccc768f1823c76d5cb2aec26434c796fc35bd4e2fbf435fcf7997d3ff0"
		score = 75
		quality = 80
		tags = "FILE"
		license = "BSD 2-Clause"
		version = "1"

	condition:
		uint32( 0 ) == 0x08F1CAA1 or uint32( 0 ) == 0x08F1CAA2 or uint32( 0 ) == 0x08F1CCC0 or uint32( 0 ) == 0x08F2AFC0 or uint32( 0 ) == 0x083AE4DF or uint32( 0 ) == 0x18F2CBB1 or uint32( 0 ) == 0x1900ABBA or uint32( 0 ) == 0x24F2CEA1 or uint32( 0 ) == 0xDA012193 or uint32( 0 ) == 0xDA018993 or uint32( 0 ) == 0xDA018995 or uint32( 0 ) == 0xDD018991
}

rule ESET_Apt_Windows_Invisimole_SFX_Dropper : FILE
{
	meta:
		description = "Detects trojanized InvisiMole files: patched RAR SFX droppers with added InvisiMole blobs (config encrypted XOR 2A at the end of a file)"
		author = "ESET Research"
		id = "08490bcd-3139-5fac-9c6c-5a32acb7217a"
		date = "2021-05-17"
		modified = "2021-05-17"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/invisimole/invisimole.yar#L79-L95"
		license_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/LICENSE"
		logic_hash = "6ca248d42c1e889988e5931d80df071cb20e623fb0c4a208044cabe073f71ce4"
		score = 75
		quality = 80
		tags = "FILE"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$encrypted_config = {5F 59 4F 58 19 18 04 4E 46 46 2A 5D 59 5A 58 43 44 5E 4C 7D 2A 0F 2A 59 2A 78 2A 4B 2A 58 2A 0E 2A 6F 2A 72 2A 4B 2A 0F 2A 4E 2A 04 2A 0F 2A 4E 2A 76 2A 0F 2A 79 2A 2A 2A 79 42 4F 46 46 6F 52 4F 49 5F 5E 4F 7D 2A 79 42 4F 46 46 19 18 04 4E 46 46 2A 7C 43 58 5E 5F 4B 46 6B 46 46 45 49 2A 66 45 4B 4E 66 43 48 58 4B 58 53 6B}

	condition:
		uint16( 0 ) == 0x5A4D and $encrypted_config
}

rule ESET_Apt_Windows_Invisimole_CPL_Loader : FILE
{
	meta:
		description = "CPL loader"
		author = "ESET Research"
		id = "feff8627-6085-5835-ac1b-d4522245f7db"
		date = "2021-05-17"
		modified = "2021-05-17"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/invisimole/invisimole.yar#L97-L118"
		license_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/LICENSE"
		logic_hash = "cd5c19e14faa7fd3758b30193ccf2bed3692ad29d8216466523ca25d2abcfe88"
		score = 75
		quality = 80
		tags = "FILE"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$s1 = "WScr%steObject(\"WScr%s.Run(\"::{20d04fe0-3a%s30309d}\\\\::{21EC%sDD-08002B3030%s\", 0);"
		$s2 = "\\Control.js" wide
		$s3 = "\\Control Panel.lnk" wide
		$s4 = "FPC 3.0.4 [2019/04/13] for x86_64 - Win64"
		$s5 = "FPC 3.0.4 [2019/04/13] for i386 - Win32"
		$s6 = "imageapplet.dat" wide
		$s7 = "wkssvmtx"

	condition:
		uint16( 0 ) == 0x5A4D and ( 3 of them )
}


rule ESET_Apt_Windows_Invisimole_Wrapper_DLL
{
	meta:
		description = "Detects InvisiMole wrapper DLL with embedded RC2CL and RC2FM backdoors, by export and resource names"
		author = "ESET Research"
		id = "b9609b09-3ef5-5793-a3aa-4692cec367d9"
		date = "2021-05-17"
		modified = "2021-05-17"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/invisimole/invisimole.yar#L120-L138"
		license_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/LICENSE"
		logic_hash = "156bc5bc7b0ed5c77a5a15e7799a3077d40150896476a60935cf21a9afe36856"
		score = 75
		quality = 80
		tags = ""
		license = "BSD 2-Clause"
		version = "1"

	condition:
		pe.exports( "GetDataLength" ) and for any y in ( 0 .. pe.number_of_resources - 1 ) : ( pe.resources [ y ] . type == pe.RESOURCE_TYPE_RCDATA and pe.resources [ y ] . name_string == "R\x00C\x002\x00C\x00L\x00" ) and for any y in ( 0 .. pe.number_of_resources - 1 ) : ( pe.resources [ y ] . type == pe.RESOURCE_TYPE_RCDATA and pe.resources [ y ] . name_string == "R\x00C\x002\x00F\x00M\x00" )
}

rule ESET_Apt_Windows_Invisimole_DNS_Downloader : FILE
{
	meta:
		description = "InvisiMole DNS downloader"
		author = "ESET Research"
		id = "1caa6c8b-3798-556e-835e-885b7f3f4511"
		date = "2021-05-17"
		modified = "2021-05-17"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/invisimole/invisimole.yar#L140-L170"
		license_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/LICENSE"
		logic_hash = "88d6ed7ec1331153d19afc18473a4be2b214ad8af29fcf7051a2a8e40e088231"
		score = 75
		quality = 80
		tags = "FILE"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$d = "DnsQuery_A"
		$s1 = "Wireshark-is-running-{9CA78EEA-EA4D-4490-9240-FC01FCEF464B}" xor
		$s2 = "AddIns\\" ascii wide xor
		$s3 = "pcornomeex." xor
		$s4 = "weriahsek.rxe" xor
		$s5 = "dpmupaceex." xor
		$s6 = "TCPViewClass" xor
		$s7 = "PROCMON_WINDOW_CLASS" xor
		$s8 = "Key%C"
		$s9 = "AutoEx%C" xor
		$s10 = "MSO~"
		$s11 = "MDE~"
		$s12 = "DNS PLUGIN, Step %d" xor
		$s13 = "rundll32.exe \"%s\",StartUI"

	condition:
		(( uint16( 0 ) == 0x5A4D ) or ESET_Invisimole_Blob_PRIVATE ) and $d and 5 of ( $s* )
}

rule ESET_Apt_Windows_Invisimole : FILE
{
	meta:
		description = "InvisiMole magic values, keys and strings"
		author = "ESET Research"
		id = "4d48996b-9792-57ba-a302-349220323712"
		date = "2021-05-17"
		modified = "2021-05-17"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/invisimole/invisimole.yar#L215-L255"
		license_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/LICENSE"
		logic_hash = "7a2cff9febe77d718089ba4e1a33f3487594588892e418cec685bf22b156fa2b"
		score = 75
		quality = 80
		tags = "FILE"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$s1 = "CryptProtectData"
		$s2 = "CryptUnprotectData"
		$s3 = {9E 01 3A AD}
		$s4 = "GET /getversion2a/%d%.2X%.2X/U%sN HTTP/1.1"
		$s5 = "PULSAR_LOADER.dll"
		$check_magic_old_32 = {3? F9 FF D0 DE}
		$check_magic_old_64 = {3? 64 FF D0 DE}
		$check_magic_new_32 = {81 3? 86 DA 11 CE}
		$check_magic_new_64 = {81 3? 64 DA 11 CE}

	condition:
		(( uint16( 0 ) == 0x5A4D ) or ESET_Invisimole_Blob_PRIVATE ) and ( any of ( $check_magic* ) ) and ( 2 of ( $s* ) )
}

rule ESET_Apt_Windows_Invisimole_C2 : FILE
{
	meta:
		description = "InvisiMole C&C servers"
		author = "ESET Research"
		id = "9279c8cd-2c16-5f90-a7f5-e668d57c805b"
		date = "2021-05-17"
		modified = "2021-05-17"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/invisimole/invisimole.yar#L257-L297"
		license_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/LICENSE"
		logic_hash = "aff8456ce7a9ebe875c02e51c09b77ee7b1fddfc11d4ad236e12c8c5240a01a8"
		score = 75
		quality = 78
		tags = "FILE"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$s1 = "46.165.220.228" ascii wide
		$s2 = "80.255.3.66" ascii wide
		$s3 = "85.17.26.174" ascii wide
		$s4 = "185.193.38.55" ascii wide
		$s5 = "194.187.249.157" ascii wide
		$s6 = "195.154.255.211" ascii wide
		$s7 = "153.re" ascii wide fullword
		$s8 = "adstat.red" ascii wide
		$s9 = "adtrax.net" ascii wide
		$s10 = "akamai.sytes.net" ascii wide
		$s11 = "amz-eu401.com" ascii wide
		$s12 = "blabla234342.sytes.net" ascii wide
		$s13 = "mx1.be" ascii wide fullword
		$s14 = "statad.de" ascii wide
		$s15 = "time.servehttp.com" ascii wide
		$s16 = "upd.re" ascii wide fullword
		$s17 = "update.xn--6frz82g" ascii wide
		$s18 = "updatecloud.sytes.net" ascii wide
		$s19 = "updchecking.sytes.net" ascii wide
		$s20 = "wlsts.net" ascii wide
		$s21 = "ro2.host" ascii wide fullword
		$s22 = "2ld.xyz" ascii wide fullword
		$s23 = "the-haba.com" ascii wide
		$s24 = "82.202.172.134" ascii wide
		$s25 = "update.xn--6frz82g" ascii wide

	condition:
		(( uint16( 0 ) == 0x5A4D ) or ESET_Invisimole_Blob_PRIVATE ) and $s21 and any of them
}

rule FIREEYE_RT_APT_Hacktool_Win64_EXCAVATOR_2 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "4b7640e8-5621-5cc3-8ac9-84347f23f5eb"
		date = "2020-12-02"
		date = "2020-12-02"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/EXCAVATOR/production/yara/APT_HackTool_Win64_EXCAVATOR_2.yar#L4-L19"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "4fd62068e591cbd6f413e1c2b8f75442"
		logic_hash = "14263c17323cd78df10f7f101bd7a9c74f7818b34a2e42125d45205067399381"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$api1 = "PssCaptureSnapshot" fullword
		$api2 = "MiniDumpWriteDump" fullword
		$dump = { C7 [2-5] FD 03 00 AC 4C 8D 4D ?? 41 B8 1F 00 10 00 8B [2-5] 48 8B 4D ?? E8 [4] 89 [2-5] 83 [2-5] 00 74 ?? 48 8B 4D ?? FF 15 [4] 33 C0 E9 [4] 41 B8 10 00 00 00 33 D2 48 8D 8D [4] E8 [4] 48 8D 05 [4] 48 89 85 [4] 48 C7 85 [8] 48 C7 44 24 30 00 00 00 00 C7 44 24 28 80 00 00 00 C7 44 24 20 01 00 00 00 45 33 C9 45 33 C0 BA 00 00 00 10 48 8D 0D [4] FF 15 [4] 48 89 85 [4] 48 83 BD [4] FF 75 ?? 48 8B 4D ?? FF 15 [4] 33 C0 EB [0-17] 48 8D [5] 48 89 ?? 24 30 48 C7 44 24 28 00 00 00 00 48 C7 44 24 20 00 00 00 00 41 B9 02 00 00 00 4C 8B 85 [4] 8B [1-5] 48 8B 4D ?? E8 }
		$enable_dbg_pri = { 4C 8D 45 ?? 48 8D 15 [4] 33 C9 FF 15 [4] 85 C0 0F 84 [4] C7 45 ?? 01 00 00 00 B8 0C 00 00 00 48 6B C0 00 48 8B 4D ?? 48 89 4C 05 ?? B8 0C 00 00 00 48 6B C0 00 C7 44 05 ?? 02 00 00 00 FF 15 [4] 4C 8D 45 ?? BA 20 00 00 00 48 8B C8 FF 15 [4] 85 C0 74 ?? 48 C7 44 24 28 00 00 00 00 48 C7 44 24 20 00 00 00 00 45 33 C9 4C 8D 45 ?? 33 D2 48 8B 4D ?? FF 15 }

	condition:
		(( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x020B ) ) and all of them
}

rule FIREEYE_RT_APT_Hacktool_Win64_EXCAVATOR_1 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "e593b589-747d-53c2-a39a-57485e4f7641"
		date = "2020-11-30"
		date = "2020-11-30"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/EXCAVATOR/production/yara/APT_HackTool_Win64_EXCAVATOR_1.yar#L4-L19"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "6a9a114928554c26675884eeb40cc01b"
		logic_hash = "aa06628ddef0f95c4217b97a3476a0ee12e00d04c4827a512730598f3c80f1f6"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 3

	strings:
		$api1 = "PssCaptureSnapshot" fullword
		$api2 = "MiniDumpWriteDump" fullword
		$dump = { BA FD 03 00 AC [0-8] 41 B8 1F 00 10 00 48 8B ?? FF 15 [4] 85 C0 0F 85 [2] 00 00 [0-2] 48 8D 05 [5] 89 ?? 24 30 ( C7 44 24 28 80 00 00 00 48 8D 0D ?? ?? ?? ?? | 48 8D 0D ?? ?? ?? ?? C7 44 24 28 80 00 00 00 ) 45 33 C9 [0-5] 45 33 C0 C7 44 24 20 01 00 00 00 BA 00 00 00 10 [0-10] FF 15 [4] 48 8B ?? 48 83 F8 FF ( 74 | 0F 84 ) [1-4] 48 8B 4C 24 ?? 48 8D 44 24 ?? 48 89 44 24 30 ( 41 B9 02 00 00 00 | 44 8D 4D 02 ) ?? 89 ?? 24 28 4C 8B ?? 8B [2] 89 ?? 24 20 FF 15 [4] 48 8B ?? FF 15 [4] 48 8B ?? FF 15 [4] FF 15 [4] 48 8B 54 24 ?? 48 8B C8 FF 15 }
		$lsass = { 6C 73 61 73 [6] 73 2E 65 78 [6] 65 }

	condition:
		(( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x020B ) ) and all of them
}

rule FIREEYE_RT_APT_Loader_Win32_REDFLARE_2 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "6a585401-bfd3-5aad-b484-09b6a30d9af5"
		date = "2020-11-27"
		date = "2020-11-27"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/REDFLARE/production/yara/APT_Loader_Win32_REDFLARE_2.yar#L4-L17"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "4e7e90c7147ee8aa01275894734f4492"
		logic_hash = "98dfb71adbde4f8965e612c19f0965d8fa95805825569290fdf72eb1d86cfb70"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$inject = { 83 F8 01 [4-50] 6A 00 6A 00 68 04 00 00 08 6A 00 6A 00 6A 00 6A 00 5? [10-70] FF 15 [4] 85 C0 [1-20] 6A 04 68 00 10 00 00 5? 6A 00 5? [1-10] FF 15 [4-8] 85 C0 [1-20] 5? 5? 5? 8B [1-4] 5? 5? FF 15 [4] 85 C0 [1-20] 6A 20 [4-20] FF 15 [4] 85 C0 [1-40] 01 00 01 00 [2-20] FF 15 [4] 85 C0 [1-30] FF 15 [4] 85 C0 [1-20] FF 15 [4] 83 F8 FF }
		$s1 = "ResumeThread"

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x010B ) and all of them
}

rule FIREEYE_RT_APT_Loader_Raw64_REDFLARE_1 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "8e937f6a-404f-53bd-9de2-ed63b1cf48b2"
		date = "2020-11-27"
		date = "2020-11-27"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/REDFLARE/production/yara/APT_Loader_Raw64_REDFLARE_1.yar#L4-L16"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "5e14f77f85fd9a5be46e7f04b8a144f5"
		logic_hash = "dac122ccece8a6dd35a5fe9d37860a612aa50ab469b79f4375dbe776f60c7b57"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$load = { EB ?? 58 48 8B 10 4C 8B 48 ?? 48 8B C8 [1-10] 48 83 C1 ?? 48 03 D1 FF }

	condition:
		( uint16( 0 ) != 0x5A4D ) and all of them
}

rule FIREEYE_RT_APT_Builder_PY_REDFLARE_1
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "3b5ad25d-ce66-572e-9a91-40a73b8fd447"
		date = "2020-11-27"
		date = "2020-11-27"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/REDFLARE/production/yara/APT_Builder_PY_REDFLARE_1.yar#L4-L22"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "d0a830403e56ebaa4bfbe87dbfdee44f"
		logic_hash = "1948cadb7242eb69bffbc222802ce9c1af38d7a846da09b6343b1449fe054e42"
		score = 75
		quality = 75
		tags = ""
		rev = 1

	strings:
		$1 = "LOAD_OFFSET_32 = 0x612"
		$2 = "LOAD_OFFSET_64 = 0x611"
		$3 = "class RC4:"
		$4 = "struct.pack('<Q' if is64b else '<L'"
		$5 = "stagerConfig['comms']['config']"
		$6 = "_x86.dll"
		$7 = "_x64.dll"

	condition:
		all of them and @1 [ 1 ] < @2 [ 1 ] and @2 [ 1 ] < @3 [ 1 ] and @3 [ 1 ] < @4 [ 1 ] and @4 [ 1 ] < @5 [ 1 ]
}

rule FIREEYE_RT_APT_Loader_Win64_REDFLARE_1 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "dc162f26-66d3-5359-b1d7-ef2208b359e2"
		date = "2020-11-27"
		date = "2020-11-27"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/REDFLARE/production/yara/APT_Loader_Win64_REDFLARE_1.yar#L4-L17"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "f20824fa6e5c81e3804419f108445368"
		logic_hash = "2cae245a6aa36dccc2228cccefdc4ca0eb278901f063e072a369000f67d73a55"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$alloc_n_load = { 41 B9 40 00 00 00 41 B8 00 30 00 00 33 C9 [1-10] FF 50 [4-80] F3 A4 [30-120] 48 6B C9 28 [3-20] 48 6B C9 28 }
		$const_values = { 0F B6 ?? 83 C? 20 83 F? 6D [2-20] 83 C? 20 83 F? 7A }

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x020B ) and all of them
}

rule FIREEYE_RT_APT_Loader_Win32_REDFLARE_1 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "b8a2c388-3b27-5075-b0ee-2773ae0c67ad"
		date = "2020-11-27"
		date = "2020-11-27"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/REDFLARE/production/yara/APT_Loader_Win32_REDFLARE_1.yar#L4-L17"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "01d68343ac46db6065f888a094edfe4f"
		logic_hash = "f9165aabe4bad215211cf98559099030ddb8a76175fbfcfee3c6f25d7614bdad"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$alloc_n_load = { 6A 40 68 00 30 00 00 [0-20] 6A 00 [0-20] FF D0 [4-60] F3 A4 [30-100] 6B C0 28 8B 4D ?? 8B 4C 01 10 8B 55 ?? 6B D2 28 }
		$const_values = { 0F B6 ?? 83 C? 20 83 F? 6D [2-20] 83 C? 20 83 F? 7A }

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x010B ) and all of them
}

rule FIREEYE_RT_APT_Keylogger_Win32_REDFLARE_1 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "ad14db66-d640-5712-b2c8-a3d42d5a90f3"
		date = "2020-12-01"
		date = "2020-12-01"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/REDFLARE/production/yara/APT_Keylogger_Win32_REDFLARE_1.yar#L4-L17"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "d7cfb9fbcf19ce881180f757aeec77dd"
		logic_hash = "aebbaa050bee3775ffac4214ea4ab58284384e7eb41e66ee4838b9359e72821e"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 2

	strings:
		$create_window = { 6A 00 68 [4] 6A 00 6A 00 68 00 00 00 80 68 00 00 00 80 68 00 00 00 80 68 00 00 00 80 68 00 00 CF 00 68 [4] 68 [4] 6A 00 FF 15 }
		$keys_check = { 6A 14 [0-5] FF [1-5] 6A 10 [0-5] FF [1-5] B9 00 80 FF FF 66 85 C1 75 ?? 68 A0 00 00 00 FF [1-5] B9 00 80 FF FF 66 85 C1 75 ?? 68 A1 00 00 00 FF [1-5] B9 00 80 FF FF 66 85 C1 74 }

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x010B ) and all of them
}

rule FIREEYE_RT_APT_Loader_Win64_REDFLARE_2 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "043f4e29-710d-5e17-a0ed-82cd3a565194"
		date = "2020-11-27"
		date = "2020-11-27"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/REDFLARE/production/yara/APT_Loader_Win64_REDFLARE_2.yar#L4-L18"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "100d73b35f23b2fe84bf7cd37140bf4d"
		logic_hash = "9fad845ed963fae46ac7ddc44407d5f6ed0a061f6a106764b9f912ef718279b4"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$alloc = { 45 8B C0 33 D2 [2-6] 00 10 00 00 [2-6] 04 00 00 00 [1-6] FF 15 [4-60] FF 15 [4] 85 C0 [4-40] 20 00 00 00 [4-40] FF 15 [4] 85 C0 }
		$inject = { 83 F8 01 [2-20] 33 C0 45 33 C9 [3-10] 45 33 C0 [3-10] 33 D2 [30-100] FF 15 [4] 85 C0 [20-100] 01 00 10 00 [0-10] FF 15 [4] 85 C0 [4-30] FF 15 [4] 85 C0 [2-20] FF 15 [4] 83 F8 FF }
		$s1 = "ResumeThread" fullword

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x020B ) and all of them
}

rule FIREEYE_RT_APT_Loader_Raw32_REDFLARE_1 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "8f8ec27f-afac-5da5-b76f-b984e14e0066"
		date = "2020-11-27"
		date = "2020-11-27"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/REDFLARE/production/yara/APT_Loader_Raw32_REDFLARE_1.yar#L4-L16"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "4022baddfda3858a57c9cbb0d49f6f86"
		logic_hash = "05ed89bd82600b4d5ef01ece2e0a9bd84e968988fd2bda1bab4ec316a9a9906b"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$load = { EB ?? 58 [0-4] 8B 10 8B 48 [1-3] 8B C8 83 C1 ?? 03 D1 83 E9 [1-3] 83 C1 [1-4] FF D? }

	condition:
		( uint16( 0 ) != 0x5A4D ) and all of them
}

rule FIREEYE_RT_APT_Downloader_Win32_REDFLARE_1 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "e8d7ee31-568e-58ac-98ad-49baa2eb37ea"
		date = "2020-11-27"
		date = "2020-11-27"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/REDFLARE/production/yara/APT_Downloader_Win32_REDFLARE_1.yar#L4-L17"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "05b99d438dac63a5a993cea37c036673"
		logic_hash = "a340a2a732a9b1aa74ca9d84009a88d1b14b6a03140a859384c0d6e745e4a90a"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$const = "Cookie: SID1=%s" fullword
		$http_req = { 00 00 08 80 81 3D [4] BB 01 00 00 75 [1-10] 00 00 80 00 [1-4] 00 10 00 00 [1-4] 00 20 00 00 89 [1-10] 6A 00 8B [1-8] 5? 6A 00 6A 00 6A 00 8B [1-8] 5? 68 [4] 8B [1-8] 5? FF 15 [4-40] 6A 14 E8 }

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x010B ) and all of them
}

rule FIREEYE_RT_APT_Controller_Linux_REDFLARE_1 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "79a69740-7209-5c56-ad6f-eb4d0b29beaf"
		date = "2020-12-02"
		date = "2020-12-02"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/REDFLARE/production/yara/APT_Controller_Linux_REDFLARE_1.yar#L4-L19"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "79259451ff47b864d71fb3f94b1774f3, 82773afa0860d668d7fe40e3f22b0f3e"
		logic_hash = "d6b0cc5f386da9bff8a8293f2b3857406044ab42f7c1bb23d5096052a3c42ce4"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$1 = "/RedFlare/gorat_server"
		$2 = "RedFlare/sandals"
		$3 = "goratsvr.CommandResponse" fullword
		$4 = "goratsvr.CommandRequest" fullword

	condition:
		( uint32( 0 ) == 0x464c457f ) and all of them
}

rule FIREEYE_RT_APT_Keylogger_Win64_REDFLARE_1 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "3c980f5a-c775-5c25-ba28-91a93a1b9a85"
		date = "2020-12-01"
		date = "2020-12-01"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/REDFLARE/production/yara/APT_Keylogger_Win64_REDFLARE_1.yar#L4-L17"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "fbefb4074f1672a3c29c1a47595ea261"
		logic_hash = "26fe577ba637c484d9a8ccc2173b5892a76328a90a39a2bebbae6bd2a6329485"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$create_window = { 41 B9 00 00 CF 00 [4-40] 33 C9 [2-10] 00 00 00 80 [2-10] 00 00 00 80 [2-10] 00 00 00 80 [2-10] 00 00 00 80 FF 15 }
		$keys_check = { B9 14 00 00 00 FF 15 [4-8] B9 10 00 00 00 FF 15 [4] BE 00 80 FF FF 66 85 C6 75 ?? B9 A0 00 00 00 FF 15 [4] 66 85 C6 75 ?? B9 A1 00 00 00 FF 15 [4] 66 85 C6 74 }

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x020B ) and all of them
}

rule FIREEYE_RT_APT_Downloader_Win64_REDFLARE_1 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "15a5e22b-84b0-5b36-8772-1d496ac447b2"
		date = "2020-11-27"
		date = "2020-11-27"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/REDFLARE/production/yara/APT_Downloader_Win64_REDFLARE_1.yar#L4-L17"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "9529c4c9773392893a8a0ab8ce8f8ce1"
		logic_hash = "1b9bece6083403615841c752eac48fd20095e918d6e175563dd122be2885d875"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 2

	strings:
		$const = "Cookie: SID1=%s" fullword
		$http_req = { 00 00 08 80 81 3D [4] BB 01 00 00 75 [1-10] 00 00 80 00 [1-4] 00 10 00 00 [1-4] 00 20 00 00 89 [6-20] 00 00 00 00 [6-20] 00 00 00 00 [2-10] 00 00 00 00 45 33 C9 [4-20] 48 8D 15 [4] 48 8B 0D [4] FF 15 [4-50] B9 14 00 00 00 E8 }

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x020B ) and all of them
}

rule FIREEYE_RT_APT_Loader_Win32_PGF_2 : FILE
{
	meta:
		description = "base dlls: /lib/payload/techniques/dllmain/"
		author = "FireEye"
		id = "e11a626b-ce91-5f6c-a514-9a8a02a29cbd"
		date = "2020-11-25"
		date = "2020-11-25"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/PGF/production/yara/APT_Loader_Win32_PGF_2.yar#L4-L19"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "04eb45f8546e052fe348fda2425b058c"
		logic_hash = "d69f3f31c4964fe933295563e08bdbb36abadd6611541b9ffa55b6829ced1d21"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$sb1 = { 6A ?? FF 15 [4-16] 8A ?? 04 [0-16] 8B ?? 1C [0-64] 0F 10 ?? 66 0F EF C8 0F 11 [0-32] 30 [2] 8D [2] 4? 83 [2] 7? }
		$sb2 = { 8B ?? 08 [0-16] 6A 40 68 00 30 00 00 5? 6A 00 [0-32] FF 15 [4-32] 5? [0-16] E8 [4-64] C1 ?? 04 [0-32] 8A [2] 3? [2] 4? 3? ?? 24 ?? 7? }
		$sb3 = { 8B ?? 3C [0-16] 03 [1-64] 0F B? ?? 14 [0-32] 83 ?? 18 [0-32] 66 3? ?? 06 [4-32] 68 [4] 5? FF 15 [4-16] 85 C0 [2-32] 83 ?? 28 0F B? ?? 06 }

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x010B ) and all of them
}

rule FIREEYE_RT_APT_Loader_Win64_PGF_2 : FILE
{
	meta:
		description = "base dlls: /lib/payload/techniques/dllmain/"
		author = "FireEye"
		id = "5253cb2a-28fd-57ab-be3d-f11cf2ea24cf"
		date = "2020-11-25"
		date = "2020-11-25"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/PGF/production/yara/APT_Loader_Win64_PGF_2.yar#L4-L19"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "4326a7e863928ffbb5f6bdf63bb9126e"
		logic_hash = "074f6d9ad78ecd4dd8e3d0b5c8b0f61a48374f3935b85c4222305b207b447ec7"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 2

	strings:
		$sb1 = { B9 [4] FF 15 [4-32] 8B ?? 1C [0-16] 0F B? ?? 04 [0-64] F3 0F 6F 00 [0-64] 66 0F EF C8 [0-64] F3 0F 7F 08 [0-64] 30 ?? 48 8D 40 01 48 83 ?? 01 7? }
		$sb2 = { 44 8B ?? 08 [0-32] 41 B8 00 30 00 00 [0-16] FF 15 [4-32] 48 8B C8 [0-16] E8 [4-64] 4D 8D 49 01 [0-32] C1 ?? 04 [0-64] 0F B? [2-16] 41 30 ?? FF 45 3? ?? 7? }
		$sb3 = { 63 ?? 3C [0-16] 03 [1-32] 0F B? ?? 14 [0-16] 8D ?? 18 [0-16] 03 [1-16] 66 ?? 3B ?? 06 7? [1-64] 48 8D 15 [4-32] FF 15 [4-16] 85 C0 [2-32] 41 0F B? ?? 06 }

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x020B ) and all of them
}

rule FIREEYE_RT_APT_Loader_Win32_PGF_1 : FILE
{
	meta:
		description = "base dlls: /lib/payload/techniques/unmanaged_exports/"
		author = "FireEye"
		id = "1af4f2ce-c540-5836-a749-43a0b08609b1"
		date = "2020-11-25"
		date = "2020-11-25"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/PGF/production/yara/APT_Loader_Win32_PGF_1.yar#L4-L19"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "383161e4deaf7eb2ebeda2c5e9c3204c"
		logic_hash = "d3fb0bd7b678b19ee2e0e846f4e13e4ce7e2629ecda123f34ef52f2af42d2a8e"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$sb1 = { 6A ?? FF 15 [4-32] 8A ?? 04 [0-32] 8B ?? 89 ?? 8B [2] 89 [2] 8B [2] 89 ?? 08 8B [2] 89 [2] 8B [2] 89 [2-64] 8B [5] 83 ?? 01 89 [5] 83 [5-32] 0F B6 [1-2] 0F B6 [1-2] 33 [1-16] 88 ?? EB }
		$sb2 = { 6A 40 [0-32] 68 00 30 00 00 [0-32] 6A 00 [0-16] FF 15 [4-32] 89 45 [4-64] E8 [4-32] 83 ?? 01 [4-80] 0F B6 [1-64] 33 [1-32] 88 [2-64] FF ( D? | 55 ) }
		$sb3 = { 8B ?? 08 03 ?? 3C [2-32] 0F B? ?? 14 [0-32] 8D [2] 18 [2-64] 0F B? ?? 06 [3-64] 6B ?? 28 }

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x010B ) and all of them
}

rule FIREEYE_RT_APT_Loader_Win_PGF_2 : FILE
{
	meta:
		description = "PE rich header matches PGF backdoor"
		author = "FireEye"
		id = "595c9e2a-3d9d-5366-9449-de1bcf333f78"
		date = "2020-12-08"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/PGF/production/yara/APT_Loader_Win_PGF_2.yar#L4-L21"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "226b1ac427eb5a4dc2a00cc72c163214"
		logic_hash = "b8c024c6b4c3ce9915700b62da8a1f12440215b46f3a56078707f5257e575811"
		score = 75
		quality = 75
		tags = "FILE"
		md5_2 = "2398ed2d5b830d226af26dedaf30f64a"
		md5_3 = "24a7c99da9eef1c58f09cf09b9744d7b"
		md5_4 = "aeb0e1d0e71ce2a08db9b1e5fb98e0aa"
		rev = 4

	strings:
		$rich1 = { A8 B7 17 3A EC D6 79 69 EC D6 79 69 EC D6 79 69 2F D9 24 69 E8 D6 79 69 E5 AE EC 69 EA D6 79 69 EC D6 78 69 A8 D6 79 69 E5 AE EA 69 EF D6 79 69 E5 AE FA 69 D0 D6 79 69 E5 AE EB 69 ED D6 79 69 E5 AE FD 69 E2 D6 79 69 CB 10 07 69 ED D6 79 69 E5 AE E8 69 ED D6 79 69 }
		$rich2 = { C1 CF 75 A4 85 AE 1B F7 85 AE 1B F7 85 AE 1B F7 8C D6 88 F7 83 AE 1B F7 0D C9 1A F6 87 AE 1B F7 0D C9 1E F6 8F AE 1B F7 0D C9 1F F6 8F AE 1B F7 0D C9 18 F6 84 AE 1B F7 DE C6 1A F6 86 AE 1B F7 85 AE 1A F7 BF AE 1B F7 84 C3 12 F6 81 AE 1B F7 84 C3 E4 F7 84 AE 1B F7 84 C3 19 F6 84 AE 1B F7 }
		$rich3 = { D6 60 82 B8 92 01 EC EB 92 01 EC EB 92 01 EC EB 9B 79 7F EB 94 01 EC EB 1A 66 ED EA 90 01 EC EB 1A 66 E9 EA 98 01 EC EB 1A 66 E8 EA 9A 01 EC EB 1A 66 EF EA 90 01 EC EB C9 69 ED EA 91 01 EC EB 92 01 ED EB AF 01 EC EB 93 6C E5 EA 96 01 EC EB 93 6C 13 EB 93 01 EC EB 93 6C EE EA 93 01 EC EB }
		$rich4 = { 41 36 64 33 05 57 0A 60 05 57 0A 60 05 57 0A 60 73 CA 71 60 01 57 0A 60 0C 2F 9F 60 04 57 0A 60 0C 2F 89 60 3D 57 0A 60 0C 2F 8E 60 0A 57 0A 60 05 57 0B 60 4A 57 0A 60 0C 2F 99 60 06 57 0A 60 73 CA 67 60 04 57 0A 60 0C 2F 98 60 04 57 0A 60 0C 2F 80 60 04 57 0A 60 22 91 74 60 04 57 0A 60 0C 2F 9B 60 04 57 0A 60 }

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and filesize < 15MB and ( ( $rich1 at 128 ) or ( $rich2 at 128 ) or ( $rich3 at 128 ) or ( $rich4 at 128 ) )
}

rule FIREEYE_RT_APT_Loader_Win64_PGF_4 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "4c93ba76-d3a5-568d-88b8-79a6ebc2edbb"
		date = "2020-11-26"
		date = "2020-11-26"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/PGF/production/yara/APT_Loader_Win64_PGF_4.yar#L4-L17"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "3bb34ebd93b8ab5799f4843e8cc829fa"
		logic_hash = "fcc92674e58ec6418d7c709e3f3bc2e1ec859fe0cb444412964a978fb69f5234"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$sb1 = { 41 B9 04 00 00 00 41 B8 00 10 00 00 BA [4] B9 00 00 00 00 [0-32] FF [1-24] 7? [1-150] 8B 45 [0-32] 44 0F B? ?? 8B [2-16] B? CD CC CC CC [0-16] C1 ?? 04 [0-16] C1 ?? 02 [0-16] C1 ?? 02 [0-16] 48 8? 05 [4-32] 31 [1-4] 88 }
		$sb2 = { C? 45 ?? 48 [0-32] B8 [0-64] FF [0-32] E0 [0-32] 41 B8 40 00 00 00 BA 0C 00 00 00 48 8B [2] 48 8B [2-32] FF [1-16] 48 89 10 8B 55 ?? 89 ?? 08 48 8B [2] 48 8D ?? 02 48 8B 45 18 48 89 02 }

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x020B ) and all of them
}

rule FIREEYE_RT_APT_Loader_Win32_PGF_4 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "d46d9ae9-cb7d-5a25-9ee2-766097c14af6"
		date = "2020-11-26"
		date = "2020-11-26"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/PGF/production/yara/APT_Loader_Win32_PGF_4.yar#L4-L17"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "4414953fa397a41156f6fa4f9462d207"
		logic_hash = "4256bfd3713f330d76cad9d1ddbba91e588dbca2e2b6842e9482525805ddc1e8"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$sb1 = { C7 44 24 0C 04 00 00 00 C7 44 24 08 00 10 00 00 [4-32] C7 04 24 00 00 00 00 [0-32] FF [1-16] 89 45 ?? 83 7D ?? 00 [2-150] 0F B? ?? 8B [2] B? CD CC CC CC 89 ?? F7 ?? C1 ?? 04 89 ?? C1 ?? 02 [0-32] 0F B? [5-32] 3? [1-16] 88 }
		$sb2 = { C? 45 ?? B8 [0-4] C? 45 ?? 00 [0-64] FF [0-32] E0 [0-32] C7 44 24 08 40 00 00 00 [0-32] C7 44 24 04 07 00 00 00 [0-32] FF [1-64] 89 ?? 0F B? [2-3] 89 ?? 04 0F B? [2] 88 ?? 06 8B ?? 08 8D ?? 01 8B 45 0C }

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x010B ) and all of them
}

rule FIREEYE_RT_APT_Loader_Win64_PGF_5 : FILE
{
	meta:
		description = "PGF payload, generated rule based on symfunc/8167a6d94baca72bac554299d7c7f83c"
		author = "FireEye"
		id = "4fa4a1d6-cb63-582d-801c-b4c89c44d9ca"
		date = "2020-12-08"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/PGF/production/yara/APT_Loader_Win64_PGF_5.yar#L4-L18"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "150224a0ccabce79f963795bf29ec75b"
		logic_hash = "16495ad1e5ce4d4a79f4067f3d687911a1a0a3bfe4c6409ff9de4d111b1ddca6"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 3

	strings:
		$cond1 = { 4C 89 44 24 18 89 54 24 10 48 89 4C 24 08 48 83 EC 38 48 8B 4C 24 40 FF 15 13 FA FF FF 8B 44 24 48 89 44 24 20 83 7C 24 20 01 74 02 EB 17 48 8B 44 24 40 48 89 05 66 23 00 00 48 8B 4C 24 40 FF 15 EB F9 FF FF B8 01 00 00 00 48 83 C4 38 C3 }
		$cond2 = { 4C 89 44 24 18 89 54 24 10 48 89 4C 24 08 48 83 EC 38 48 8B 4C 24 40 FF 15 A3 FA FF FF 8B 44 24 48 89 44 24 20 83 7C 24 20 01 74 02 EB 17 48 8B 44 24 40 48 89 05 F6 20 00 00 48 8B 4C 24 40 FF 15 7B FA FF FF B8 01 00 00 00 48 83 C4 38 C3 }
		$cond3 = { 4C 89 44 24 18 89 54 24 10 48 89 4C 24 08 48 83 EC 38 48 8B 4C 24 40 FF ?? ?? ?? ?? ?? 8B 44 24 48 89 44 24 20 83 7C 24 2? ?1 74 ?? EB ?? 48 8B 44 24 40 48 ?? ?? ?? ?? ?? ?? 48 8B 4C 24 40 FF ?? ?? ?? ?? ?? B8 01 ?? ?? ?? 48 83 C4 38 C3 }
		$cond4 = { 4C 89 44 24 ?? 89 54 24 ?? 48 89 4C 24 ?? 48 83 EC 38 48 8B 4C 24 ?? FF 15 ?? ?? ?? ?? 8B 44 24 ?? 89 44 24 ?? 83 7C 24 ?? 01 74 ?? EB ?? 48 8B 44 24 ?? 48 89 05 ?? ?? ?? ?? 48 8B 4C 24 ?? FF 15 ?? ?? ?? ?? B8 01 00 00 00 48 83 C4 38 C3 }

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x020B ) and any of them
}

rule FIREEYE_RT_APT_Loader_Win32_PGF_3 : FILE
{
	meta:
		description = "PGF payload, generated rule based on symfunc/c02594972dbab6d489b46c5dee059e66. Identifies dllmain_hook x86 payloads."
		author = "FireEye"
		id = "adf91482-6e04-5d11-bc00-4b1c7a802c49"
		date = "2020-12-08"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/PGF/production/yara/APT_Loader_Win32_PGF_3.yar#L4-L20"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "4414953fa397a41156f6fa4f9462d207"
		logic_hash = "24d2caad1d740ccbff0cf111a05ecad20ed06f311d530d8de86050d916da32ce"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 4

	strings:
		$cond1 = { 55 89 E5 57 56 53 81 EC FC 06 00 00 C7 85 2C F9 FF FF 90 EE 01 6D C7 85 30 F9 FF FF 6C FE 01 6D 8D 85 34 F9 FF FF 89 28 BA CC 19 00 6D 89 50 04 89 60 08 8D 85 14 F9 FF FF 89 04 24 E8 BB A6 00 00 A1 48 A1 05 6D C7 85 18 F9 FF FF FF FF FF FF FF D0 C7 44 24 08 04 01 00 00 8D 95 B6 FD FF FF 89 54 24 04 89 04 24 E8 B8 AE 00 00 83 EC 0C 85 C0 0F 94 C0 84 C0 0F 85 8B 03 00 00 8D 45 BF 89 C1 E8 56 0B 01 00 8D 85 9C FD FF FF 8D 55 BF 89 54 24 04 8D 95 B6 FD FF FF 89 14 24 C7 85 18 F9 FF FF 01 00 00 00 89 C1 E8 DF B5 01 00 83 EC 08 8D 45 BF 89 C1 E8 52 0B 01 00 A1 4C A1 05 6D C7 85 18 F9 FF FF 02 00 00 00 FF D0 89 44 24 04 C7 04 24 08 00 00 00 E8 51 AE 00 00 83 EC 08 89 45 D0 83 7D D0 00 75 0F C7 85 10 F9 FF FF 00 00 00 00 E9 8C 02 00 00 C7 45 E4 00 00 00 00 C7 45 E0 00 00 00 00 C7 85 74 F9 FF FF 28 04 00 00 8D 85 74 F9 FF FF 89 44 24 04 8B 45 D0 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 EF AD 00 00 83 EC 08 89 45 DC 83 7D DC 00 74 67 8D 85 9C FD FF FF C7 44 24 04 00 00 00 00 8D 95 74 F9 FF FF 83 C2 20 89 14 24 89 C1 E8 82 FF 00 00 83 EC 08 83 F8 FF 0F 95 C0 84 C0 74 12 8B 85 88 F9 FF FF 89 45 E4 8B 85 8C F9 FF FF 89 45 E0 8D 85 74 F9 FF FF 89 44 24 04 8B 45 D0 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 84 AD 00 00 83 EC 08 89 45 DC EB 93 8B 45 D0 89 04 24 A1 2C A1 05 6D C7 85 18 F9 FF FF 02 00 00 00 FF D0 83 EC 04 83 7D E4 00 74 06 83 7D E0 00 75 0F C7 85 10 F9 FF FF 00 00 00 00 E9 AD 01 00 00 C7 04 24 0C 40 05 6D A1 5C A1 05 6D C7 85 18 F9 FF FF 02 00 00 00 FF D0 83 EC 04 C7 44 24 04 18 40 05 6D 89 04 24 A1 60 A1 05 6D FF D0 83 EC 08 89 45 CC 89 E8 89 45 D8 8D 85 6C F9 FF FF 89 44 24 04 8D 85 70 F9 FF FF 89 04 24 A1 54 A1 05 6D FF D0 83 EC 08 C7 45 D4 00 00 00 00 8B 55 D8 8B 85 6C F9 FF FF 39 C2 0F 83 F5 00 00 00 8B 45 D8 8B 00 3D FF 0F 00 00 0F 86 D8 00 00 00 8B 45 D8 8B 00 39 45 CC 73 19 8B 45 D8 8B 00 8B 55 CC 81 C2 00 10 00 00 39 D0 73 07 C7 45 D4 01 00 00 00 83 7D D4 00 0F 84 AF 00 00 00 8B 45 D8 8B 00 39 45 E4 0F 83 A1 00 00 00 8B 45 D8 8B 00 8B 4D E4 8B 55 E0 01 CA 39 D0 0F 83 8C 00 00 00 B9 00 00 00 00 B8 1C 00 00 00 83 E0 FC 89 C2 B8 00 00 00 00 89 8C 05 50 F9 FF FF 83 C0 04 39 D0 72 F2 8B 45 D8 8B 00 C7 44 24 08 1C 00 00 00 8D 95 50 F9 FF FF 89 54 24 04 89 04 24 A1 9C A1 05 6D C7 85 18 F9 FF FF 02 00 00 00 FF D0 83 EC 0C 8B 85 64 F9 FF FF 83 E0 20 85 C0 74 2E 8B 45 D8 8B 00 C7 44 24 04 30 14 00 6D 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 59 FC FF FF C7 85 10 F9 FF FF 00 00 00 00 EB 58 90 EB 01 90 83 45 D8 04 E9 FA FE FF FF 8B 45 E4 89 45 C8 8B 45 C8 8B 40 3C 89 C2 8B 45 E4 01 D0 89 45 C4 8B 45 C4 8B 50 28 8B 45 E4 01 D0 89 45 C0 C7 44 24 04 30 14 00 6D 8B 45 C0 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 FF FB FF FF C7 85 10 F9 FF FF 01 00 00 00 8D 85 9C FD FF FF 89 C1 E8 5D BC 01 00 83 BD 10 F9 FF FF 01 EB 70 8B 95 1C F9 FF FF 8B 85 18 F9 FF FF 85 C0 74 0C 83 E8 01 85 C0 74 2D 83 E8 01 0F 0B 89 95 10 F9 FF FF 8D 45 BF 89 C1 E8 48 08 01 00 8B 85 10 F9 FF FF 89 04 24 C7 85 18 F9 FF FF FF FF FF FF E8 A0 A6 00 00 89 95 10 F9 FF FF 8D 85 9C FD FF FF 89 C1 E8 FD BB 01 00 8B 85 10 F9 FF FF 89 04 24 C7 85 18 F9 FF FF FF FF FF FF E8 75 A6 00 00 90 8D 85 14 F9 FF FF 89 04 24 E8 76 A3 00 00 8D 65 F4 5B 5E 5F 5D C3 }
		$cond2 = { 55 89 E5 57 56 53 81 EC FC 06 00 00 C7 85 2C F9 FF FF B0 EF 3D 6A C7 85 30 F9 FF FF 8C FF 3D 6A 8D 85 34 F9 FF FF 89 28 BA F4 1A 3C 6A 89 50 04 89 60 08 8D 85 14 F9 FF FF 89 04 24 E8 B3 A6 00 00 A1 64 A1 41 6A C7 85 18 F9 FF FF FF FF FF FF FF D0 C7 44 24 08 04 01 00 00 8D 95 B6 FD FF FF 89 54 24 04 89 04 24 E8 B0 AE 00 00 83 EC 0C 85 C0 0F 94 C0 84 C0 0F 85 8B 03 00 00 8D 45 BF 89 C1 E8 4E 0B 01 00 8D 85 9C FD FF FF 8D 55 BF 89 54 24 04 8D 95 B6 FD FF FF 89 14 24 C7 85 18 F9 FF FF 01 00 00 00 89 C1 E8 D7 B5 01 00 83 EC 08 8D 45 BF 89 C1 E8 4A 0B 01 00 A1 68 A1 41 6A C7 85 18 F9 FF FF 02 00 00 00 FF D0 89 44 24 04 C7 04 24 08 00 00 00 E8 49 AE 00 00 83 EC 08 89 45 D0 83 7D D0 00 75 0F C7 85 10 F9 FF FF 00 00 00 00 E9 8C 02 00 00 C7 45 E4 00 00 00 00 C7 45 E0 00 00 00 00 C7 85 74 F9 FF FF 28 04 00 00 8D 85 74 F9 FF FF 89 44 24 04 8B 45 D0 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 E7 AD 00 00 83 EC 08 89 45 DC 83 7D DC 00 74 67 8D 85 9C FD FF FF C7 44 24 04 00 00 00 00 8D 95 74 F9 FF FF 83 C2 20 89 14 24 89 C1 E8 7A FF 00 00 83 EC 08 83 F8 FF 0F 95 C0 84 C0 74 12 8B 85 88 F9 FF FF 89 45 E4 8B 85 8C F9 FF FF 89 45 E0 8D 85 74 F9 FF FF 89 44 24 04 8B 45 D0 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 7C AD 00 00 83 EC 08 89 45 DC EB 93 8B 45 D0 89 04 24 A1 44 A1 41 6A C7 85 18 F9 FF FF 02 00 00 00 FF D0 83 EC 04 83 7D E4 00 74 06 83 7D E0 00 75 0F C7 85 10 F9 FF FF 00 00 00 00 E9 AD 01 00 00 C7 04 24 62 40 41 6A A1 78 A1 41 6A C7 85 18 F9 FF FF 02 00 00 00 FF D0 83 EC 04 C7 44 24 04 6E 40 41 6A 89 04 24 A1 7C A1 41 6A FF D0 83 EC 08 89 45 CC 89 E8 89 45 D8 8D 85 6C F9 FF FF 89 44 24 04 8D 85 70 F9 FF FF 89 04 24 A1 70 A1 41 6A FF D0 83 EC 08 C7 45 D4 00 00 00 00 8B 55 D8 8B 85 6C F9 FF FF 39 C2 0F 83 F5 00 00 00 8B 45 D8 8B 00 3D FF 0F 00 00 0F 86 D8 00 00 00 8B 45 D8 8B 00 39 45 CC 73 19 8B 45 D8 8B 00 8B 55 CC 81 C2 00 10 00 00 39 D0 73 07 C7 45 D4 01 00 00 00 83 7D D4 00 0F 84 AF 00 00 00 8B 45 D8 8B 00 39 45 E4 0F 83 A1 00 00 00 8B 45 D8 8B 00 8B 4D E4 8B 55 E0 01 CA 39 D0 0F 83 8C 00 00 00 B9 00 00 00 00 B8 1C 00 00 00 83 E0 FC 89 C2 B8 00 00 00 00 89 8C 05 50 F9 FF FF 83 C0 04 39 D0 72 F2 8B 45 D8 8B 00 C7 44 24 08 1C 00 00 00 8D 95 50 F9 FF FF 89 54 24 04 89 04 24 A1 C8 A1 41 6A C7 85 18 F9 FF FF 02 00 00 00 FF D0 83 EC 0C 8B 85 64 F9 FF FF 83 E0 20 85 C0 74 2E 8B 45 D8 8B 00 C7 44 24 04 30 14 3C 6A 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 59 FC FF FF C7 85 10 F9 FF FF 00 00 00 00 EB 58 90 EB 01 90 83 45 D8 04 E9 FA FE FF FF 8B 45 E4 89 45 C8 8B 45 C8 8B 40 3C 89 C2 8B 45 E4 01 D0 89 45 C4 8B 45 C4 8B 50 28 8B 45 E4 01 D0 89 45 C0 C7 44 24 04 30 14 3C 6A 8B 45 C0 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 FF FB FF FF C7 85 10 F9 FF FF 01 00 00 00 8D 85 9C FD FF FF 89 C1 E8 55 BC 01 00 83 BD 10 F9 FF FF 01 EB 70 8B 95 1C F9 FF FF 8B 85 18 F9 FF FF 85 C0 74 0C 83 E8 01 85 C0 74 2D 83 E8 01 0F 0B 89 95 10 F9 FF FF 8D 45 BF 89 C1 E8 40 08 01 00 8B 85 10 F9 FF FF 89 04 24 C7 85 18 F9 FF FF FF FF FF FF E8 98 A6 00 00 89 95 10 F9 FF FF 8D 85 9C FD FF FF 89 C1 E8 F5 BB 01 00 8B 85 10 F9 FF FF 89 04 24 C7 85 18 F9 FF FF FF FF FF FF E8 6D A6 00 00 90 8D 85 14 F9 FF FF 89 04 24 E8 6E A3 00 00 8D 65 F4 5B 5E 5F 5D C3 }
		$cond3 = { 55 89 E5 57 56 53 81 EC FC 06 00 00 C7 85 2C F9 FF FF F0 EF D5 63 C7 85 30 F9 FF FF CC FF D5 63 8D 85 34 F9 FF FF 89 28 BA 28 1B D4 63 89 50 04 89 60 08 8D 85 14 F9 FF FF 89 04 24 E8 BF A6 00 00 A1 64 A1 D9 63 C7 85 18 F9 FF FF FF FF FF FF FF D0 C7 44 24 08 04 01 00 00 8D 95 B6 FD FF FF 89 54 24 04 89 04 24 E8 BC AE 00 00 83 EC 0C 85 C0 0F 94 C0 84 C0 0F 85 8B 03 00 00 8D 45 BF 89 C1 E8 5A 0B 01 00 8D 85 9C FD FF FF 8D 55 BF 89 54 24 04 8D 95 B6 FD FF FF 89 14 24 C7 85 18 F9 FF FF 01 00 00 00 89 C1 E8 E3 B5 01 00 83 EC 08 8D 45 BF 89 C1 E8 56 0B 01 00 A1 68 A1 D9 63 C7 85 18 F9 FF FF 02 00 00 00 FF D0 89 44 24 04 C7 04 24 08 00 00 00 E8 55 AE 00 00 83 EC 08 89 45 D0 83 7D D0 00 75 0F C7 85 10 F9 FF FF 00 00 00 00 E9 8C 02 00 00 C7 45 E4 00 00 00 00 C7 45 E0 00 00 00 00 C7 85 74 F9 FF FF 28 04 00 00 8D 85 74 F9 FF FF 89 44 24 04 8B 45 D0 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 F3 AD 00 00 83 EC 08 89 45 DC 83 7D DC 00 74 67 8D 85 9C FD FF FF C7 44 24 04 00 00 00 00 8D 95 74 F9 FF FF 83 C2 20 89 14 24 89 C1 E8 86 FF 00 00 83 EC 08 83 F8 FF 0F 95 C0 84 C0 74 12 8B 85 88 F9 FF FF 89 45 E4 8B 85 8C F9 FF FF 89 45 E0 8D 85 74 F9 FF FF 89 44 24 04 8B 45 D0 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 88 AD 00 00 83 EC 08 89 45 DC EB 93 8B 45 D0 89 04 24 A1 44 A1 D9 63 C7 85 18 F9 FF FF 02 00 00 00 FF D0 83 EC 04 83 7D E4 00 74 06 83 7D E0 00 75 0F C7 85 10 F9 FF FF 00 00 00 00 E9 AD 01 00 00 C7 04 24 7E 40 D9 63 A1 7C A1 D9 63 C7 85 18 F9 FF FF 02 00 00 00 FF D0 83 EC 04 C7 44 24 04 8A 40 D9 63 89 04 24 A1 80 A1 D9 63 FF D0 83 EC 08 89 45 CC 89 E8 89 45 D8 8D 85 6C F9 FF FF 89 44 24 04 8D 85 70 F9 FF FF 89 04 24 A1 70 A1 D9 63 FF D0 83 EC 08 C7 45 D4 00 00 00 00 8B 55 D8 8B 85 6C F9 FF FF 39 C2 0F 83 F5 00 00 00 8B 45 D8 8B 00 3D FF 0F 00 00 0F 86 D8 00 00 00 8B 45 D8 8B 00 39 45 CC 73 19 8B 45 D8 8B 00 8B 55 CC 81 C2 00 10 00 00 39 D0 73 07 C7 45 D4 01 00 00 00 83 7D D4 00 0F 84 AF 00 00 00 8B 45 D8 8B 00 39 45 E4 0F 83 A1 00 00 00 8B 45 D8 8B 00 8B 4D E4 8B 55 E0 01 CA 39 D0 0F 83 8C 00 00 00 B9 00 00 00 00 B8 1C 00 00 00 83 E0 FC 89 C2 B8 00 00 00 00 89 8C 05 50 F9 FF FF 83 C0 04 39 D0 72 F2 8B 45 D8 8B 00 C7 44 24 08 1C 00 00 00 8D 95 50 F9 FF FF 89 54 24 04 89 04 24 A1 C8 A1 D9 63 C7 85 18 F9 FF FF 02 00 00 00 FF D0 83 EC 0C 8B 85 64 F9 FF FF 83 E0 20 85 C0 74 2E 8B 45 D8 8B 00 C7 44 24 04 30 14 D4 63 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 59 FC FF FF C7 85 10 F9 FF FF 00 00 00 00 EB 58 90 EB 01 90 83 45 D8 04 E9 FA FE FF FF 8B 45 E4 89 45 C8 8B 45 C8 8B 40 3C 89 C2 8B 45 E4 01 D0 89 45 C4 8B 45 C4 8B 50 28 8B 45 E4 01 D0 89 45 C0 C7 44 24 04 30 14 D4 63 8B 45 C0 89 04 24 C7 85 18 F9 FF FF 02 00 00 00 E8 FF FB FF FF C7 85 10 F9 FF FF 01 00 00 00 8D 85 9C FD FF FF 89 C1 E8 61 BC 01 00 83 BD 10 F9 FF FF 01 EB 70 8B 95 1C F9 FF FF 8B 85 18 F9 FF FF 85 C0 74 0C 83 E8 01 85 C0 74 2D 83 E8 01 0F 0B 89 95 10 F9 FF FF 8D 45 BF 89 C1 E8 4C 08 01 00 8B 85 10 F9 FF FF 89 04 24 C7 85 18 F9 FF FF FF FF FF FF E8 A4 A6 00 00 89 95 10 F9 FF FF 8D 85 9C FD FF FF 89 C1 E8 01 BC 01 00 8B 85 10 F9 FF FF 89 04 24 C7 85 18 F9 FF FF FF FF FF FF E8 79 A6 00 00 90 8D 85 14 F9 FF FF 89 04 24 E8 7A A3 00 00 8D 65 F4 5B 5E 5F 5D C3 }
		$cond4 = { 55 89 E5 57 56 53 81 EC FC 06 00 00 C7 85 ?? ?? ?? ?? 90 EE 01 6D C7 85 ?? ?? ?? ?? 6C FE 01 6D 8D 85 ?? ?? ?? ?? 89 28 BA CC 19 00 6D 89 50 ?? 89 60 ?? 8D 85 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? FF FF FF FF FF D0 C7 44 24 ?? 04 01 00 00 8D 95 ?? ?? ?? ?? 89 54 24 ?? 89 04 24 E8 ?? ?? ?? ?? 83 EC 0C 85 C0 0F 94 C0 84 C0 0F 85 ?? ?? ?? ?? 8D 45 ?? 89 C1 E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 8D 55 ?? 89 54 24 ?? 8D 95 ?? ?? ?? ?? 89 14 24 C7 85 ?? ?? ?? ?? 01 00 00 00 89 C1 E8 ?? ?? ?? ?? 83 EC 08 8D 45 ?? 89 C1 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 89 44 24 ?? C7 04 24 08 00 00 00 E8 ?? ?? ?? ?? 83 EC 08 89 45 ?? 83 7D ?? 00 75 ?? C7 85 ?? ?? ?? ?? 00 00 00 00 E9 ?? ?? ?? ?? C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 28 04 00 00 8D 85 ?? ?? ?? ?? 89 44 24 ?? 8B 45 ?? 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? 83 EC 08 89 45 ?? 83 7D ?? 00 74 ?? 8D 85 ?? ?? ?? ?? C7 44 24 ?? 00 00 00 00 8D 95 ?? ?? ?? ?? 83 C2 20 89 14 24 89 C1 E8 ?? ?? ?? ?? 83 EC 08 83 F8 FF 0F 95 C0 84 C0 74 ?? 8B 85 ?? ?? ?? ?? 89 45 ?? 8B 85 ?? ?? ?? ?? 89 45 ?? 8D 85 ?? ?? ?? ?? 89 44 24 ?? 8B 45 ?? 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? 83 EC 08 89 45 ?? EB ?? 8B 45 ?? 89 04 24 A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 83 EC 04 83 7D ?? 00 74 ?? 83 7D ?? 00 75 ?? C7 85 ?? ?? ?? ?? 00 00 00 00 E9 ?? ?? ?? ?? C7 04 24 0C 40 05 6D A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 83 EC 04 C7 44 24 ?? 18 40 05 6D 89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC 08 89 45 ?? 89 E8 89 45 ?? 8D 85 ?? ?? ?? ?? 89 44 24 ?? 8D 85 ?? ?? ?? ?? 89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC 08 C7 45 ?? 00 00 00 00 8B 55 ?? 8B 85 ?? ?? ?? ?? 39 C2 0F 83 ?? ?? ?? ?? 8B 45 ?? 8B 00 3D FF 0F 00 00 0F 86 ?? ?? ?? ?? 8B 45 ?? 8B 00 39 45 ?? 73 ?? 8B 45 ?? 8B 00 8B 55 ?? 81 C2 00 10 00 00 39 D0 73 ?? C7 45 ?? 01 00 00 00 83 7D ?? 00 0F 84 ?? ?? ?? ?? 8B 45 ?? 8B 00 39 45 ?? 0F 83 ?? ?? ?? ?? 8B 45 ?? 8B 00 8B 4D ?? 8B 55 ?? 01 CA 39 D0 0F 83 ?? ?? ?? ?? B9 00 00 00 00 B8 1C 00 00 00 83 E0 FC 89 C2 B8 00 00 00 00 89 8C 05 ?? ?? ?? ?? 83 C0 04 39 D0 72 ?? 8B 45 ?? 8B 00 C7 44 24 ?? 1C 00 00 00 8D 95 ?? ?? ?? ?? 89 54 24 ?? 89 04 24 A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 83 EC 0C 8B 85 ?? ?? ?? ?? 83 E0 20 85 C0 74 ?? 8B 45 ?? 8B 00 C7 44 24 ?? 30 14 00 6D 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 00 00 00 00 EB ?? 90 EB ?? 90 83 45 ?? 04 E9 ?? ?? ?? ?? 8B 45 ?? 89 45 ?? 8B 45 ?? 8B 40 ?? 89 C2 8B 45 ?? 01 D0 89 45 ?? 8B 45 ?? 8B 50 ?? 8B 45 ?? 01 D0 89 45 ?? C7 44 24 ?? 30 14 00 6D 8B 45 ?? 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 01 00 00 00 8D 85 ?? ?? ?? ?? 89 C1 E8 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 01 EB ?? 8B 95 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 85 C0 74 ?? 83 E8 01 85 C0 74 ?? 83 E8 01 0F 0B 89 95 ?? ?? ?? ?? 8D 45 ?? 89 C1 E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 89 04 24 C7 85 ?? ?? ?? ?? FF FF FF FF E8 ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 89 C1 E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 89 04 24 C7 85 ?? ?? ?? ?? FF FF FF FF E8 ?? ?? ?? ?? 90 8D 85 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 8D 65 ?? 5B 5E 5F 5D C3 }
		$cond5 = { 55 89 E5 57 56 53 81 EC FC 06 00 00 C7 85 ?? ?? ?? ?? B0 EF 3D 6A C7 85 ?? ?? ?? ?? 8C FF 3D 6A 8D 85 ?? ?? ?? ?? 89 28 BA F4 1A 3C 6A 89 50 ?? 89 60 ?? 8D 85 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? FF FF FF FF FF D0 C7 44 24 ?? 04 01 00 00 8D 95 ?? ?? ?? ?? 89 54 24 ?? 89 04 24 E8 ?? ?? ?? ?? 83 EC 0C 85 C0 0F 94 C0 84 C0 0F 85 ?? ?? ?? ?? 8D 45 ?? 89 C1 E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 8D 55 ?? 89 54 24 ?? 8D 95 ?? ?? ?? ?? 89 14 24 C7 85 ?? ?? ?? ?? 01 00 00 00 89 C1 E8 ?? ?? ?? ?? 83 EC 08 8D 45 ?? 89 C1 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 89 44 24 ?? C7 04 24 08 00 00 00 E8 ?? ?? ?? ?? 83 EC 08 89 45 ?? 83 7D ?? 00 75 ?? C7 85 ?? ?? ?? ?? 00 00 00 00 E9 ?? ?? ?? ?? C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 28 04 00 00 8D 85 ?? ?? ?? ?? 89 44 24 ?? 8B 45 ?? 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? 83 EC 08 89 45 ?? 83 7D ?? 00 74 ?? 8D 85 ?? ?? ?? ?? C7 44 24 ?? 00 00 00 00 8D 95 ?? ?? ?? ?? 83 C2 20 89 14 24 89 C1 E8 ?? ?? ?? ?? 83 EC 08 83 F8 FF 0F 95 C0 84 C0 74 ?? 8B 85 ?? ?? ?? ?? 89 45 ?? 8B 85 ?? ?? ?? ?? 89 45 ?? 8D 85 ?? ?? ?? ?? 89 44 24 ?? 8B 45 ?? 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? 83 EC 08 89 45 ?? EB ?? 8B 45 ?? 89 04 24 A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 83 EC 04 83 7D ?? 00 74 ?? 83 7D ?? 00 75 ?? C7 85 ?? ?? ?? ?? 00 00 00 00 E9 ?? ?? ?? ?? C7 04 24 62 40 41 6A A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 83 EC 04 C7 44 24 ?? 6E 40 41 6A 89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC 08 89 45 ?? 89 E8 89 45 ?? 8D 85 ?? ?? ?? ?? 89 44 24 ?? 8D 85 ?? ?? ?? ?? 89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC 08 C7 45 ?? 00 00 00 00 8B 55 ?? 8B 85 ?? ?? ?? ?? 39 C2 0F 83 ?? ?? ?? ?? 8B 45 ?? 8B 00 3D FF 0F 00 00 0F 86 ?? ?? ?? ?? 8B 45 ?? 8B 00 39 45 ?? 73 ?? 8B 45 ?? 8B 00 8B 55 ?? 81 C2 00 10 00 00 39 D0 73 ?? C7 45 ?? 01 00 00 00 83 7D ?? 00 0F 84 ?? ?? ?? ?? 8B 45 ?? 8B 00 39 45 ?? 0F 83 ?? ?? ?? ?? 8B 45 ?? 8B 00 8B 4D ?? 8B 55 ?? 01 CA 39 D0 0F 83 ?? ?? ?? ?? B9 00 00 00 00 B8 1C 00 00 00 83 E0 FC 89 C2 B8 00 00 00 00 89 8C 05 ?? ?? ?? ?? 83 C0 04 39 D0 72 ?? 8B 45 ?? 8B 00 C7 44 24 ?? 1C 00 00 00 8D 95 ?? ?? ?? ?? 89 54 24 ?? 89 04 24 A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 83 EC 0C 8B 85 ?? ?? ?? ?? 83 E0 20 85 C0 74 ?? 8B 45 ?? 8B 00 C7 44 24 ?? 30 14 3C 6A 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 00 00 00 00 EB ?? 90 EB ?? 90 83 45 ?? 04 E9 ?? ?? ?? ?? 8B 45 ?? 89 45 ?? 8B 45 ?? 8B 40 ?? 89 C2 8B 45 ?? 01 D0 89 45 ?? 8B 45 ?? 8B 50 ?? 8B 45 ?? 01 D0 89 45 ?? C7 44 24 ?? 30 14 3C 6A 8B 45 ?? 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 01 00 00 00 8D 85 ?? ?? ?? ?? 89 C1 E8 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 01 EB ?? 8B 95 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 85 C0 74 ?? 83 E8 01 85 C0 74 ?? 83 E8 01 0F 0B 89 95 ?? ?? ?? ?? 8D 45 ?? 89 C1 E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 89 04 24 C7 85 ?? ?? ?? ?? FF FF FF FF E8 ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 89 C1 E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 89 04 24 C7 85 ?? ?? ?? ?? FF FF FF FF E8 ?? ?? ?? ?? 90 8D 85 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 8D 65 ?? 5B 5E 5F 5D C3 }
		$cond6 = { 55 89 E5 57 56 53 81 EC FC 06 00 00 C7 85 ?? ?? ?? ?? F0 EF D5 63 C7 85 ?? ?? ?? ?? CC FF D5 63 8D 85 ?? ?? ?? ?? 89 28 BA 28 1B D4 63 89 50 ?? 89 60 ?? 8D 85 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? FF FF FF FF FF D0 C7 44 24 ?? 04 01 00 00 8D 95 ?? ?? ?? ?? 89 54 24 ?? 89 04 24 E8 ?? ?? ?? ?? 83 EC 0C 85 C0 0F 94 C0 84 C0 0F 85 ?? ?? ?? ?? 8D 45 ?? 89 C1 E8 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 8D 55 ?? 89 54 24 ?? 8D 95 ?? ?? ?? ?? 89 14 24 C7 85 ?? ?? ?? ?? 01 00 00 00 89 C1 E8 ?? ?? ?? ?? 83 EC 08 8D 45 ?? 89 C1 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 89 44 24 ?? C7 04 24 08 00 00 00 E8 ?? ?? ?? ?? 83 EC 08 89 45 ?? 83 7D ?? 00 75 ?? C7 85 ?? ?? ?? ?? 00 00 00 00 E9 ?? ?? ?? ?? C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 28 04 00 00 8D 85 ?? ?? ?? ?? 89 44 24 ?? 8B 45 ?? 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? 83 EC 08 89 45 ?? 83 7D ?? 00 74 ?? 8D 85 ?? ?? ?? ?? C7 44 24 ?? 00 00 00 00 8D 95 ?? ?? ?? ?? 83 C2 20 89 14 24 89 C1 E8 ?? ?? ?? ?? 83 EC 08 83 F8 FF 0F 95 C0 84 C0 74 ?? 8B 85 ?? ?? ?? ?? 89 45 ?? 8B 85 ?? ?? ?? ?? 89 45 ?? 8D 85 ?? ?? ?? ?? 89 44 24 ?? 8B 45 ?? 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? 83 EC 08 89 45 ?? EB ?? 8B 45 ?? 89 04 24 A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 83 EC 04 83 7D ?? 00 74 ?? 83 7D ?? 00 75 ?? C7 85 ?? ?? ?? ?? 00 00 00 00 E9 ?? ?? ?? ?? C7 04 24 7E 40 D9 63 A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 83 EC 04 C7 44 24 ?? 8A 40 D9 63 89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC 08 89 45 ?? 89 E8 89 45 ?? 8D 85 ?? ?? ?? ?? 89 44 24 ?? 8D 85 ?? ?? ?? ?? 89 04 24 A1 ?? ?? ?? ?? FF D0 83 EC 08 C7 45 ?? 00 00 00 00 8B 55 ?? 8B 85 ?? ?? ?? ?? 39 C2 0F 83 ?? ?? ?? ?? 8B 45 ?? 8B 00 3D FF 0F 00 00 0F 86 ?? ?? ?? ?? 8B 45 ?? 8B 00 39 45 ?? 73 ?? 8B 45 ?? 8B 00 8B 55 ?? 81 C2 00 10 00 00 39 D0 73 ?? C7 45 ?? 01 00 00 00 83 7D ?? 00 0F 84 ?? ?? ?? ?? 8B 45 ?? 8B 00 39 45 ?? 0F 83 ?? ?? ?? ?? 8B 45 ?? 8B 00 8B 4D ?? 8B 55 ?? 01 CA 39 D0 0F 83 ?? ?? ?? ?? B9 00 00 00 00 B8 1C 00 00 00 83 E0 FC 89 C2 B8 00 00 00 00 89 8C 05 ?? ?? ?? ?? 83 C0 04 39 D0 72 ?? 8B 45 ?? 8B 00 C7 44 24 ?? 1C 00 00 00 8D 95 ?? ?? ?? ?? 89 54 24 ?? 89 04 24 A1 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 02 00 00 00 FF D0 83 EC 0C 8B 85 ?? ?? ?? ?? 83 E0 20 85 C0 74 ?? 8B 45 ?? 8B 00 C7 44 24 ?? 30 14 D4 63 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 00 00 00 00 EB ?? 90 EB ?? 90 83 45 ?? 04 E9 ?? ?? ?? ?? 8B 45 ?? 89 45 ?? 8B 45 ?? 8B 40 ?? 89 C2 8B 45 ?? 01 D0 89 45 ?? 8B 45 ?? 8B 50 ?? 8B 45 ?? 01 D0 89 45 ?? C7 44 24 ?? 30 14 D4 63 8B 45 ?? 89 04 24 C7 85 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 01 00 00 00 8D 85 ?? ?? ?? ?? 89 C1 E8 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 01 EB ?? 8B 95 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 85 C0 74 ?? 83 E8 01 85 C0 74 ?? 83 E8 01 0F 0B 89 95 ?? ?? ?? ?? 8D 45 ?? 89 C1 E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 89 04 24 C7 85 ?? ?? ?? ?? FF FF FF FF E8 ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 89 C1 E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 89 04 24 C7 85 ?? ?? ?? ?? FF FF FF FF E8 ?? ?? ?? ?? 90 8D 85 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 8D 65 ?? 5B 5E 5F 5D C3 }

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x010B ) and any of them
}

rule FIREEYE_RT_APT_Loader_MSIL_PGF_1 : FILE
{
	meta:
		description = "base.cs"
		author = "FireEye"
		id = "39d9821f-86e8-528a-a0a9-287dbe325484"
		date = "2020-11-24"
		date = "2020-11-24"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/PGF/production/yara/APT_Loader_MSIL_PGF_1.yar#L4-L17"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "a495c6d11ff3f525915345fb762f8047"
		logic_hash = "4174ed53336f3951d26282dc81b99b2044ac6350d4b4c0074194a9b4acecefee"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$sb1 = { 72 [4] 6F [2] 00 0A 26 [0-16] 0? 6F [2] 00 0A [1-3] 0? 28 [2] 00 0A [0-1] 0? 72 [4-5] 0? 28 [2] 00 0A [0-1] 0? 6F [2] 00 0A 13 ?? 1? 13 ?? 38 [8-16] 91 [3-6] 8E 6? 5D 91 61 D2 9C 11 ?? 1? 58 13 [3-5] 8E 6? 3F }

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule FIREEYE_RT_APT_Loader_Win64_PGF_1 : FILE
{
	meta:
		description = "base dlls: /lib/payload/techniques/unmanaged_exports/"
		author = "FireEye"
		id = "1f2280c0-0fdd-5930-947a-931274bccd6f"
		date = "2020-11-25"
		date = "2020-11-25"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/PGF/production/yara/APT_Loader_Win64_PGF_1.yar#L4-L19"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "2b686a8b83f8e1d8b455976ae70dab6e"
		logic_hash = "2e84d614c34b0b7f93fa70fa3312f22e3ff23f2abd33b2e19c00dd6cba7dcfdc"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$sb1 = { B9 14 00 00 00 FF 15 [4-32] 0F B6 ?? 04 [0-32] F3 A4 [0-64] 0F B6 [2-3] 0F B6 [2-3] 33 [0-32] 88 [1-9] EB }
		$sb2 = { 41 B8 00 30 00 00 [0-32] FF 15 [8-64] 83 ?? 01 [4-80] 0F B6 [1-64] 33 [1-32] 88 [1-64] FF ( D? | 5? ) }
		$sb3 = { 48 89 4C 24 08 [4-64] 48 63 48 3C [0-32] 48 03 C1 [0-64] 0F B7 48 14 [0-64] 48 8D 44 08 18 [8-64] 0F B7 40 06 [2-32] 48 6B C0 28 }

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x020B ) and all of them
}

rule FIREEYE_RT_APT_Loader_Win64_PGF_3 : FILE
{
	meta:
		description = "PGF payload, generated rule based on symfunc/8a2f2236fdfaa3583ab89076025c6269. Identifies dllmain_hook x64 payloads."
		author = "FireEye"
		id = "340ea6d4-7111-520c-9bd4-0465a43ea235"
		date = "2020-12-08"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/PGF/production/yara/APT_Loader_Win64_PGF_3.yar#L4-L18"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "3bb34ebd93b8ab5799f4843e8cc829fa"
		logic_hash = "fd82bdec54a76eed12cc8820ef39899f31ea6df21d905530a0d53770b3d9901b"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 4

	strings:
		$cond1 = { 55 53 48 89 E5 48 81 EC 28 07 00 00 48 8B 05 80 8B 06 00 FF D0 48 89 C1 48 8D 85 98 FD FF FF 41 B8 04 01 00 00 48 89 C2 E8 5A B4 00 00 85 C0 0F 94 C0 84 C0 0F 85 16 03 00 00 48 8D 45 AF 48 89 C1 E8 E9 FE 00 00 48 8D 4D AF 48 8D 95 98 FD FF FF 48 8D 85 78 FD FF FF 49 89 C8 48 89 C1 E8 AC 96 01 00 48 8D 45 AF 48 89 C1 E8 F0 FE 00 00 48 8B 05 25 8B 06 00 FF D0 89 C2 B9 08 00 00 00 E8 6B B4 00 00 48 89 45 D0 48 83 7D D0 00 75 0A BB 00 00 00 00 E9 6C 02 00 00 48 C7 45 F0 00 00 00 00 C7 45 EC 00 00 00 00 C7 85 38 F9 FF FF 38 04 00 00 48 8D 95 38 F9 FF FF 48 8B 45 D0 48 89 C1 E8 AA B3 00 00 89 45 E8 83 7D E8 00 74 57 48 8D 85 38 F9 FF FF 48 8D 50 30 48 8D 85 78 FD FF FF 41 B8 00 00 00 00 48 89 C1 E8 61 F3 00 00 48 83 F8 FF 0F 95 C0 84 C0 74 14 48 8B 85 50 F9 FF FF 48 89 45 F0 8B 85 58 F9 FF FF 89 45 EC 48 8D 95 38 F9 FF FF 48 8B 45 D0 48 89 C1 E8 4F B3 00 00 89 45 E8 EB A3 48 8B 45 D0 48 89 C1 48 8B 05 20 8A 06 00 FF D0 48 83 7D F0 00 74 06 83 7D EC 00 75 0A BB 00 00 00 00 E9 B9 01 00 00 48 8D 0D 0E C8 05 00 48 8B 05 69 8A 06 00 FF D0 48 8D 15 0A C8 05 00 48 89 C1 48 8B 05 5E 8A 06 00 FF D0 48 89 45 C8 48 89 E8 48 89 45 E0 48 8D 95 28 F9 FF FF 48 8D 85 30 F9 FF FF 48 89 C1 48 8B 05 19 8A 06 00 FF D0 C7 45 DC 00 00 00 00 48 8B 55 E0 48 8B 85 28 F9 FF FF 48 39 C2 0F 83 0D 01 00 00 48 8B 45 E0 48 8B 00 48 3D FF 0F 00 00 0F 86 EC 00 00 00 48 8B 45 E0 48 8B 00 48 39 45 C8 73 1E 48 8B 45 E0 48 8B 00 48 8B 55 C8 48 81 C2 00 10 00 00 48 39 D0 73 07 C7 45 DC 01 00 00 00 83 7D DC 00 0F 84 BB 00 00 00 48 8B 45 E0 48 8B 00 48 39 45 F0 0F 83 AA 00 00 00 48 8B 45 E0 48 8B 00 8B 4D EC 48 8B 55 F0 48 01 CA 48 39 D0 0F 83 90 00 00 00 48 C7 85 F8 F8 FF FF 00 00 00 00 48 C7 85 00 F9 FF FF 00 00 00 00 48 C7 85 08 F9 FF FF 00 00 00 00 48 C7 85 10 F9 FF FF 00 00 00 00 48 C7 85 18 F9 FF FF 00 00 00 00 48 C7 85 20 F9 FF FF 00 00 00 00 48 8B 45 E0 48 8B 00 48 8D 95 F8 F8 FF FF 41 B8 30 00 00 00 48 89 C1 48 8B 05 01 8A 06 00 FF D0 8B 85 1C F9 FF FF 83 E0 20 85 C0 74 20 48 8B 45 E0 48 8B 00 48 8D 15 E0 F9 FF FF 48 89 C1 E8 D5 FC FF FF BB 00 00 00 00 EB 57 90 EB 01 90 48 83 45 E0 08 E9 DF FE FF FF 48 8B 45 F0 48 89 45 C0 48 8B 45 C0 8B 40 3C 48 63 D0 48 8B 45 F0 48 01 D0 48 89 45 B8 48 8B 45 B8 8B 40 28 89 C2 48 8B 45 F0 48 01 D0 48 89 45 B0 48 8B 45 B0 48 8D 15 87 F9 FF FF 48 89 C1 E8 7C FC FF FF BB 01 00 00 00 48 8D 85 78 FD FF FF 48 89 C1 E8 CB 9C 01 00 83 FB 01 EB 38 48 89 C3 48 8D 45 AF 48 89 C1 E8 37 FC 00 00 48 89 D8 48 89 C1 E8 4C AA 00 00 48 89 C3 48 8D 85 78 FD FF FF 48 89 C1 E8 9A 9C 01 00 48 89 D8 48 89 C1 E8 2F AA 00 00 90 48 81 C4 28 07 00 00 5B 5D C3 }
		$cond2 = { 55 53 48 89 E5 48 81 EC 28 07 00 00 48 8B 05 ?? ?? ?? ?? FF D0 48 89 C1 48 8D 85 ?? ?? ?? ?? 41 B8 04 01 00 00 48 89 C2 E8 ?? ?? ?? ?? 85 C0 0F 94 C0 84 C0 0F 85 ?? ?? ?? ?? 48 8D 45 ?? 48 89 C1 E8 ?? ?? ?? ?? 48 8D 4D ?? 48 8D 95 ?? ?? ?? ?? 48 8D 85 ?? ?? ?? ?? 49 89 C8 48 89 C1 E8 ?? ?? ?? ?? 48 8D 45 ?? 48 89 C1 E8 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? FF D0 89 C2 B9 08 00 00 00 E8 ?? ?? ?? ?? 48 89 45 ?? 48 83 7D ?? 00 75 ?? BB 00 00 00 00 E9 ?? ?? ?? ?? 48 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 38 04 00 00 48 8D 95 ?? ?? ?? ?? 48 8B 45 ?? 48 89 C1 E8 ?? ?? ?? ?? 89 45 ?? 83 7D ?? 00 74 ?? 48 8D 85 ?? ?? ?? ?? 48 8D 50 ?? 48 8D 85 ?? ?? ?? ?? 41 B8 00 00 00 00 48 89 C1 E8 ?? ?? ?? ?? 48 83 F8 FF 0F 95 C0 84 C0 74 ?? 48 8B 85 ?? ?? ?? ?? 48 89 45 ?? 8B 85 ?? ?? ?? ?? 89 45 ?? 48 8D 95 ?? ?? ?? ?? 48 8B 45 ?? 48 89 C1 E8 ?? ?? ?? ?? 89 45 ?? EB ?? 48 8B 45 ?? 48 89 C1 48 8B 05 ?? ?? ?? ?? FF D0 48 83 7D ?? 00 74 ?? 83 7D ?? 00 75 ?? BB 00 00 00 00 E9 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? FF D0 48 8D 15 ?? ?? ?? ?? 48 89 C1 48 8B 05 ?? ?? ?? ?? FF D0 48 89 45 ?? 48 89 E8 48 89 45 ?? 48 8D 95 ?? ?? ?? ?? 48 8D 85 ?? ?? ?? ?? 48 89 C1 48 8B 05 ?? ?? ?? ?? FF D0 C7 45 ?? 00 00 00 00 48 8B 55 ?? 48 8B 85 ?? ?? ?? ?? 48 39 C2 0F 83 ?? ?? ?? ?? 48 8B 45 ?? 48 8B 00 48 3D FF 0F 00 00 0F 86 ?? ?? ?? ?? 48 8B 45 ?? 48 8B 00 48 39 45 ?? 73 ?? 48 8B 45 ?? 48 8B 00 48 8B 55 ?? 48 81 C2 00 10 00 00 48 39 D0 73 ?? C7 45 ?? 01 00 00 00 83 7D ?? 00 0F 84 ?? ?? ?? ?? 48 8B 45 ?? 48 8B 00 48 39 45 ?? 0F 83 ?? ?? ?? ?? 48 8B 45 ?? 48 8B 00 8B 4D ?? 48 8B 55 ?? 48 01 CA 48 39 D0 0F 83 ?? ?? ?? ?? 48 C7 85 ?? ?? ?? ?? 00 00 00 00 48 C7 85 ?? ?? ?? ?? 00 00 00 00 48 C7 85 ?? ?? ?? ?? 00 00 00 00 48 C7 85 ?? ?? ?? ?? 00 00 00 00 48 C7 85 ?? ?? ?? ?? 00 00 00 00 48 C7 85 ?? ?? ?? ?? 00 00 00 00 48 8B 45 ?? 48 8B 00 48 8D 95 ?? ?? ?? ?? 41 B8 30 00 00 00 48 89 C1 48 8B 05 ?? ?? ?? ?? FF D0 8B 85 ?? ?? ?? ?? 83 E0 20 85 C0 74 ?? 48 8B 45 ?? 48 8B 00 48 8D 15 ?? ?? ?? ?? 48 89 C1 E8 ?? ?? ?? ?? BB 00 00 00 00 EB ?? 90 EB ?? 90 48 83 45 ?? 08 E9 ?? ?? ?? ?? 48 8B 45 ?? 48 89 45 ?? 48 8B 45 ?? 8B 40 ?? 48 63 D0 48 8B 45 ?? 48 01 D0 48 89 45 ?? 48 8B 45 ?? 8B 40 ?? 89 C2 48 8B 45 ?? 48 01 D0 48 89 45 ?? 48 8B 45 ?? 48 8D 15 ?? ?? ?? ?? 48 89 C1 E8 ?? ?? ?? ?? BB 01 00 00 00 48 8D 85 ?? ?? ?? ?? 48 89 C1 E8 ?? ?? ?? ?? 83 FB 01 EB ?? 48 89 C3 48 8D 45 ?? 48 89 C1 E8 ?? ?? ?? ?? 48 89 D8 48 89 C1 E8 ?? ?? ?? ?? 48 89 C3 48 8D 85 ?? ?? ?? ?? 48 89 C1 E8 ?? ?? ?? ?? 48 89 D8 48 89 C1 E8 ?? ?? ?? ?? 90 48 81 C4 28 07 00 00 5B 5D C3 }
		$cond3 = { 55 53 48 89 E5 48 81 EC 28 07 00 00 48 8B 05 C1 7C 06 00 FF D0 48 89 C1 48 8D 85 98 FD FF FF 41 B8 04 01 00 00 48 89 C2 E8 33 B4 00 00 85 C0 0F 94 C0 84 C0 0F 85 16 03 00 00 48 8D 45 AF 48 89 C1 E8 B2 FE 00 00 48 8D 4D AF 48 8D 95 98 FD FF FF 48 8D 85 78 FD FF FF 49 89 C8 48 89 C1 E8 75 96 01 00 48 8D 45 AF 48 89 C1 E8 B9 FE 00 00 48 8B 05 66 7C 06 00 FF D0 89 C2 B9 08 00 00 00 E8 3C B4 00 00 48 89 45 D0 48 83 7D D0 00 75 0A BB 00 00 00 00 E9 6C 02 00 00 48 C7 45 F0 00 00 00 00 C7 45 EC 00 00 00 00 C7 85 38 F9 FF FF 38 04 00 00 48 8D 95 38 F9 FF FF 48 8B 45 D0 48 89 C1 E8 83 B3 00 00 89 45 E8 83 7D E8 00 74 57 48 8D 85 38 F9 FF FF 48 8D 50 30 48 8D 85 78 FD FF FF 41 B8 00 00 00 00 48 89 C1 E8 2A F3 00 00 48 83 F8 FF 0F 95 C0 84 C0 74 14 48 8B 85 50 F9 FF FF 48 89 45 F0 8B 85 58 F9 FF FF 89 45 EC 48 8D 95 38 F9 FF FF 48 8B 45 D0 48 89 C1 E8 28 B3 00 00 89 45 E8 EB A3 48 8B 45 D0 48 89 C1 48 8B 05 69 7B 06 00 FF D0 48 83 7D F0 00 74 06 83 7D EC 00 75 0A BB 00 00 00 00 E9 B9 01 00 00 48 8D 0D 11 B9 05 00 48 8B 05 A2 7B 06 00 FF D0 48 8D 15 0D B9 05 00 48 89 C1 48 8B 05 97 7B 06 00 FF D0 48 89 45 C8 48 89 E8 48 89 45 E0 48 8D 95 28 F9 FF FF 48 8D 85 30 F9 FF FF 48 89 C1 48 8B 05 5A 7B 06 00 FF D0 C7 45 DC 00 00 00 00 48 8B 55 E0 48 8B 85 28 F9 FF FF 48 39 C2 0F 83 0D 01 00 00 48 8B 45 E0 48 8B 00 48 3D FF 0F 00 00 0F 86 EC 00 00 00 48 8B 45 E0 48 8B 00 48 39 45 C8 73 1E 48 8B 45 E0 48 8B 00 48 8B 55 C8 48 81 C2 00 10 00 00 48 39 D0 73 07 C7 45 DC 01 00 00 00 83 7D DC 00 0F 84 BB 00 00 00 48 8B 45 E0 48 8B 00 48 39 45 F0 0F 83 AA 00 00 00 48 8B 45 E0 48 8B 00 8B 4D EC 48 8B 55 F0 48 01 CA 48 39 D0 0F 83 90 00 00 00 48 C7 85 F8 F8 FF FF 00 00 00 00 48 C7 85 00 F9 FF FF 00 00 00 00 48 C7 85 08 F9 FF FF 00 00 00 00 48 C7 85 10 F9 FF FF 00 00 00 00 48 C7 85 18 F9 FF FF 00 00 00 00 48 C7 85 20 F9 FF FF 00 00 00 00 48 8B 45 E0 48 8B 00 48 8D 95 F8 F8 FF FF 41 B8 30 00 00 00 48 89 C1 48 8B 05 22 7B 06 00 FF D0 8B 85 1C F9 FF FF 83 E0 20 85 C0 74 20 48 8B 45 E0 48 8B 00 48 8D 15 59 FB FF FF 48 89 C1 E8 D5 FC FF FF BB 00 00 00 00 EB 57 90 EB 01 90 48 83 45 E0 08 E9 DF FE FF FF 48 8B 45 F0 48 89 45 C0 48 8B 45 C0 8B 40 3C 48 63 D0 48 8B 45 F0 48 01 D0 48 89 45 B8 48 8B 45 B8 8B 40 28 89 C2 48 8B 45 F0 48 01 D0 48 89 45 B0 48 8B 45 B0 48 8D 15 00 FB FF FF 48 89 C1 E8 7C FC FF FF BB 01 00 00 00 48 8D 85 78 FD FF FF 48 89 C1 E8 94 9C 01 00 83 FB 01 EB 38 48 89 C3 48 8D 45 AF 48 89 C1 E8 00 FC 00 00 48 89 D8 48 89 C1 E8 45 AA 00 00 48 89 C3 48 8D 85 78 FD FF FF 48 89 C1 E8 63 9C 01 00 48 89 D8 48 89 C1 E8 28 AA 00 00 90 48 81 C4 28 07 00 00 5B 5D C3 }
		$cond4 = { 55 53 48 89 E5 48 81 EC 28 07 00 00 48 8B 05 D3 8B 06 00 FF D0 48 89 C1 48 8D 85 98 FD FF FF 41 B8 04 01 00 00 48 89 C2 E8 65 B4 00 00 85 C0 0F 94 C0 84 C0 0F 85 16 03 00 00 48 8D 45 AF 48 89 C1 E8 EC FE 00 00 48 8D 4D AF 48 8D 95 98 FD FF FF 48 8D 85 78 FD FF FF 49 89 C8 48 89 C1 E8 AF 96 01 00 48 8D 45 AF 48 89 C1 E8 F3 FE 00 00 48 8B 05 78 8B 06 00 FF D0 89 C2 B9 08 00 00 00 E8 6E B4 00 00 48 89 45 D0 48 83 7D D0 00 75 0A BB 00 00 00 00 E9 6C 02 00 00 48 C7 45 F0 00 00 00 00 C7 45 EC 00 00 00 00 C7 85 38 F9 FF FF 38 04 00 00 48 8D 95 38 F9 FF FF 48 8B 45 D0 48 89 C1 E8 B5 B3 00 00 89 45 E8 83 7D E8 00 74 57 48 8D 85 38 F9 FF FF 48 8D 50 30 48 8D 85 78 FD FF FF 41 B8 00 00 00 00 48 89 C1 E8 64 F3 00 00 48 83 F8 FF 0F 95 C0 84 C0 74 14 48 8B 85 50 F9 FF FF 48 89 45 F0 8B 85 58 F9 FF FF 89 45 EC 48 8D 95 38 F9 FF FF 48 8B 45 D0 48 89 C1 E8 5A B3 00 00 89 45 E8 EB A3 48 8B 45 D0 48 89 C1 48 8B 05 73 8A 06 00 FF D0 48 83 7D F0 00 74 06 83 7D EC 00 75 0A BB 00 00 00 00 E9 B9 01 00 00 48 8D 0D 45 C8 05 00 48 8B 05 B4 8A 06 00 FF D0 48 8D 15 41 C8 05 00 48 89 C1 48 8B 05 A9 8A 06 00 FF D0 48 89 45 C8 48 89 E8 48 89 45 E0 48 8D 95 28 F9 FF FF 48 8D 85 30 F9 FF FF 48 89 C1 48 8B 05 6C 8A 06 00 FF D0 C7 45 DC 00 00 00 00 48 8B 55 E0 48 8B 85 28 F9 FF FF 48 39 C2 0F 83 0D 01 00 00 48 8B 45 E0 48 8B 00 48 3D FF 0F 00 00 0F 86 EC 00 00 00 48 8B 45 E0 48 8B 00 48 39 45 C8 73 1E 48 8B 45 E0 48 8B 00 48 8B 55 C8 48 81 C2 00 10 00 00 48 39 D0 73 07 C7 45 DC 01 00 00 00 83 7D DC 00 0F 84 BB 00 00 00 48 8B 45 E0 48 8B 00 48 39 45 F0 0F 83 AA 00 00 00 48 8B 45 E0 48 8B 00 8B 4D EC 48 8B 55 F0 48 01 CA 48 39 D0 0F 83 90 00 00 00 48 C7 85 F8 F8 FF FF 00 00 00 00 48 C7 85 00 F9 FF FF 00 00 00 00 48 C7 85 08 F9 FF FF 00 00 00 00 48 C7 85 10 F9 FF FF 00 00 00 00 48 C7 85 18 F9 FF FF 00 00 00 00 48 C7 85 20 F9 FF FF 00 00 00 00 48 8B 45 E0 48 8B 00 48 8D 95 F8 F8 FF FF 41 B8 30 00 00 00 48 89 C1 48 8B 05 54 8A 06 00 FF D0 8B 85 1C F9 FF FF 83 E0 20 85 C0 74 20 48 8B 45 E0 48 8B 00 48 8D 15 33 FA FF FF 48 89 C1 E8 D5 FC FF FF BB 00 00 00 00 EB 57 90 EB 01 90 48 83 45 E0 08 E9 DF FE FF FF 48 8B 45 F0 48 89 45 C0 48 8B 45 C0 8B 40 3C 48 63 D0 48 8B 45 F0 48 01 D0 48 89 45 B8 48 8B 45 B8 8B 40 28 89 C2 48 8B 45 F0 48 01 D0 48 89 45 B0 48 8B 45 B0 48 8D 15 DA F9 FF FF 48 89 C1 E8 7C FC FF FF BB 01 00 00 00 48 8D 85 78 FD FF FF 48 89 C1 E8 CE 9C 01 00 83 FB 01 EB 38 48 89 C3 48 8D 45 AF 48 89 C1 E8 3A FC 00 00 48 89 D8 48 89 C1 E8 4F AA 00 00 48 89 C3 48 8D 85 78 FD FF FF 48 89 C1 E8 9D 9C 01 00 48 89 D8 48 89 C1 E8 32 AA 00 00 90 48 81 C4 28 07 00 00 5B 5D C3 }

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x020B ) and any of them
}

rule FIREEYE_RT_APT_Loader_MSIL_PGF_2 : FILE
{
	meta:
		description = "base.js, ./lib/payload/techniques/jscriptdotnet/jscriptdotnet_payload.py"
		author = "FireEye"
		id = "c5f2ec90-cd9b-53ce-893b-e44192fcd507"
		date = "2020-11-25"
		date = "2020-11-25"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/PGF/production/yara/APT_Loader_MSIL_PGF_2.yar#L4-L20"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "7c2a06ceb29cdb25f24c06f2a8892fba"
		logic_hash = "b962ea30c063009c0383e25edda3a65202bea4496d0d6228549dcea82bba0d03"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$sb1 = { 2? 00 10 00 00 0A 1? 40 0? 72 [4] 0? 0? 28 [2] 00 0A 0? 03 28 [2] 00 0A 74 [2] 00 01 6F [2] 00 0A 03 1? 0? 74 [2] 00 01 28 [2] 00 0A 6? 0? 0? 28 [2] 00 06 D0 [2] 00 01 28 [2] 00 0A 1? 28 [2] 00 0A 79 [2] 00 01 71 [2] 00 01 13 ?? 0? 1? 11 ?? 0? 74 [2] 00 01 28 [2] 00 0A 28 [2] 00 0A 7E [2] 00 0A 13 ?? 1? 13 ?? 7E [2] 00 0A 13 ?? 03 28 [2] 00 0A 74 [2] 00 01 6F [2] 00 0A 03 1? 1? 11 ?? 11 ?? 1? 11 ?? 28 [2] 00 06 }
		$ss1 = "\x00CreateThread\x00"
		$ss2 = "\x00ScriptObjectStackTop\x00"
		$ss3 = "\x00Microsoft.JScript\x00"

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule FIREEYE_RT_APT_Loader_Win32_PGF_5 : FILE
{
	meta:
		description = "PGF payload, generated rule based on symfunc/a86b004b5005c0bcdbd48177b5bac7b8"
		author = "FireEye"
		id = "376875f3-00f2-58d0-ae22-7f52ea566da2"
		date = "2020-12-08"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/PGF/production/yara/APT_Loader_Win32_PGF_5.yar#L4-L18"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "8c91a27bbdbe9fb0877daccd28bd7bb5"
		logic_hash = "dfff615a1d329cf181294f7b0a32c11a21d66ff8a6aa6b9fcd183c9738369623"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 3

	strings:
		$cond1 = { 8B FF 55 8B EC 81 EC 30 01 00 00 A1 00 30 00 10 33 C5 89 45 E0 56 C7 45 F8 00 00 00 00 C6 85 D8 FE FF FF 00 68 03 01 00 00 6A 00 8D 85 D9 FE FF FF 50 E8 F9 07 00 00 83 C4 0C C7 45 F4 00 00 00 00 C6 45 E7 00 C7 45 E8 00 00 00 00 C7 45 EC 00 00 00 00 C7 45 FC 00 00 00 00 C7 45 F0 00 00 00 00 6A 01 6A 00 8D 8D D8 FE FF FF 51 6A 00 68 9C 10 00 10 8B 15 10 30 00 10 52 E8 31 01 00 00 89 45 F8 6A 14 FF 15 5C 10 00 10 83 C4 04 89 45 E8 8B 45 F8 8A 48 04 88 4D E7 8B 55 F8 83 C2 0C 8B 45 E8 8B 0A 89 08 8B 4A 04 89 48 04 8B 4A 08 89 48 08 8B 4A 0C 89 48 0C 8B 52 10 89 50 10 C7 85 D4 FE FF FF 00 00 00 00 EB 0F 8B 85 D4 FE FF FF 83 C0 01 89 85 D4 FE FF FF 83 BD D4 FE FF FF 14 7D 1F 8B 4D E8 03 8D D4 FE FF FF 0F B6 11 0F B6 45 E7 33 D0 8B 4D E8 03 8D D4 FE FF FF 88 11 EB C9 8B 55 F8 8B 42 08 89 45 FC 6A 40 68 00 30 00 00 8B 4D FC 51 6A 00 FF 15 00 10 00 10 89 45 EC 8B 55 FC 52 8B 45 F8 83 C0 20 50 8B 4D EC 51 E8 F0 06 00 00 83 C4 0C C7 85 D0 FE FF FF 00 00 00 00 EB 0F 8B 95 D0 FE FF FF 83 C2 01 89 95 D0 FE FF FF 8B 85 D0 FE FF FF 3B 45 FC 73 30 8B 4D EC 03 8D D0 FE FF FF 0F B6 09 8B 85 D0 FE FF FF 99 BE 14 00 00 00 F7 FE 8B 45 E8 0F B6 14 10 33 CA 8B 45 EC 03 85 D0 FE FF FF 88 08 EB B6 8B 4D EC 89 4D F0 FF 55 F0 5E 8B 4D E0 33 CD E8 6D 06 00 00 8B E5 5D C3 }
		$cond2 = { 8B FF 55 8B EC 81 EC 30 01 00 00 A1 00 30 00 10 33 C5 89 45 E0 56 C7 45 F8 00 00 00 00 C6 85 D8 FE FF FF 00 68 03 01 00 00 6A 00 8D 85 D9 FE FF FF 50 E8 F9 07 00 00 83 C4 0C C7 45 F4 00 00 00 00 C6 45 E7 00 C7 45 E8 00 00 00 00 C7 45 EC 00 00 00 00 C7 45 FC 00 00 00 00 C7 45 F0 00 00 00 00 6A 01 6A 00 8D 8D D8 FE FF FF 51 6A 00 68 9C 10 00 10 8B 15 20 33 00 10 52 E8 31 01 00 00 89 45 F8 6A 14 FF 15 58 10 00 10 83 C4 04 89 45 E8 8B 45 F8 8A 48 04 88 4D E7 8B 55 F8 83 C2 0C 8B 45 E8 8B 0A 89 08 8B 4A 04 89 48 04 8B 4A 08 89 48 08 8B 4A 0C 89 48 0C 8B 52 10 89 50 10 C7 85 D4 FE FF FF 00 00 00 00 EB 0F 8B 85 D4 FE FF FF 83 C0 01 89 85 D4 FE FF FF 83 BD D4 FE FF FF 14 7D 1F 8B 4D E8 03 8D D4 FE FF FF 0F B6 11 0F B6 45 E7 33 D0 8B 4D E8 03 8D D4 FE FF FF 88 11 EB C9 8B 55 F8 8B 42 08 89 45 FC 6A 40 68 00 30 00 00 8B 4D FC 51 6A 00 FF 15 2C 10 00 10 89 45 EC 8B 55 FC 52 8B 45 F8 83 C0 20 50 8B 4D EC 51 E8 F0 06 00 00 83 C4 0C C7 85 D0 FE FF FF 00 00 00 00 EB 0F 8B 95 D0 FE FF FF 83 C2 01 89 95 D0 FE FF FF 8B 85 D0 FE FF FF 3B 45 FC 73 30 8B 4D EC 03 8D D0 FE FF FF 0F B6 09 8B 85 D0 FE FF FF 99 BE 14 00 00 00 F7 FE 8B 45 E8 0F B6 14 10 33 CA 8B 45 EC 03 85 D0 FE FF FF 88 08 EB B6 8B 4D EC 89 4D F0 FF 55 F0 5E 8B 4D E0 33 CD E8 6D 06 00 00 8B E5 5D C3 }
		$cond3 = { 8B FF 55 8B EC 81 EC 30 01 00 00 A1 ?? ?? ?? ?? 33 C5 89 45 ?? 56 C7 45 ?? 00 00 00 00 C6 85 ?? ?? ?? ?? 00 68 03 01 00 00 6A 00 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 0C C7 45 ?? 00 00 00 00 C6 45 ?? 00 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 6A 01 6A 00 8D 8D ?? ?? ?? ?? 51 6A 00 68 9C 10 00 10 8B 15 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 89 45 ?? 6A 14 FF 15 ?? ?? ?? ?? 83 C4 04 89 45 ?? 8B 45 ?? 8A 48 ?? 88 4D ?? 8B 55 ?? 83 C2 0C 8B 45 ?? 8B 0A 89 08 8B 4A ?? 89 48 ?? 8B 4A ?? 89 48 ?? 8B 4A ?? 89 48 ?? 8B 52 ?? 89 50 ?? C7 85 ?? ?? ?? ?? 00 00 00 00 EB ?? 8B 85 ?? ?? ?? ?? 83 C0 01 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 14 7D ?? 8B 4D ?? 03 8D ?? ?? ?? ?? 0F B6 11 0F B6 45 ?? 33 D0 8B 4D ?? 03 8D ?? ?? ?? ?? 88 11 EB ?? 8B 55 ?? 8B 42 ?? 89 45 ?? 6A 40 68 00 30 00 00 8B 4D ?? 51 6A 00 FF 15 ?? ?? ?? ?? 89 45 ?? 8B 55 ?? 52 8B 45 ?? 83 C0 20 50 8B 4D ?? 51 E8 ?? ?? ?? ?? 83 C4 0C C7 85 ?? ?? ?? ?? 00 00 00 00 EB ?? 8B 95 ?? ?? ?? ?? 83 C2 01 89 95 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 3B 45 ?? 73 ?? 8B 4D ?? 03 8D ?? ?? ?? ?? 0F B6 09 8B 85 ?? ?? ?? ?? 99 BE 14 00 00 00 F7 FE 8B 45 ?? 0F B6 14 10 33 CA 8B 45 ?? 03 85 ?? ?? ?? ?? 88 08 EB ?? 8B 4D ?? 89 4D ?? FF 55 ?? 5E 8B 4D ?? 33 CD E8 ?? ?? ?? ?? 8B E5 5D C3 }
		$cond4 = { 8B FF 55 8B EC 81 EC 3? ?1 ?? ?? A1 ?? ?? ?? ?? 33 C5 89 45 E0 56 C7 45 F8 ?? ?? ?? ?? C6 85 D8 FE FF FF ?? 68 ?? ?? ?? ?? 6A ?? 8D 85 D9 FE FF FF 50 E8 ?? ?? ?? ?? 83 C4 0C C7 45 F4 ?? ?? ?? ?? C6 45 E7 ?? C7 45 E8 ?? ?? ?? ?? C7 45 EC ?? ?? ?? ?? C7 45 FC ?? ?? ?? ?? C7 45 F? ?? ?? ?? ?0 6A ?? 6A ?? 8D 8D D8 FE FF FF 51 6A ?? 68 ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 89 45 F8 6A ?? FF ?? ?? ?? ?? ?? 83 C4 04 89 45 E8 8B 45 F8 8A 48 04 88 4D E7 8B 55 F8 83 ?? ?? 8B 45 E8 8B 0A 89 08 8B 4A 04 89 48 04 8B 4A 08 89 48 08 8B 4A 0C 89 48 0C 8B 52 10 89 50 10 C7 85 D4 FE FF FF ?? ?? ?? ?? EB ?? 8B 85 D4 FE FF FF 83 C? ?1 89 85 D4 FE FF FF 83 BD D4 FE FF FF 14 7D ?? 8B 4D E8 03 8D D4 FE FF FF 0F B6 11 0F B6 45 E7 33 D0 8B 4D E8 03 8D D4 FE FF FF 88 11 EB ?? 8B 55 F8 8B 42 08 89 45 FC 6A ?? 68 ?? ?? ?? ?? 8B 4D FC 51 6A ?? FF ?? ?? ?? ?? ?? 89 45 EC 8B 55 FC 52 8B 45 F8 83 ?? ?? 50 8B 4D EC 51 E8 ?? ?? ?? ?? 83 C4 0C C7 85 D0 FE FF FF ?? ?? ?? ?? EB ?? 8B 95 D0 FE FF FF 83 C2 01 89 95 D0 FE FF FF 8B 85 D0 FE FF FF 3B 45 FC 73 ?? 8B 4D EC 03 8D D0 FE FF FF 0F B6 09 8B 85 D0 FE FF FF 99 BE ?? ?? ?? ?? F7 FE 8B 45 E8 0F B6 14 10 33 CA 8B 45 EC 03 85 D0 FE FF FF 88 08 EB ?? 8B 4D EC 89 4D F0 FF ?? ?? 5E 8B 4D E0 33 CD E8 ?? ?? ?? ?? 8B E5 5D C3 }

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x010B ) and any of them
}

rule FIREEYE_RT_APT_Hacktool_MSIL_DTRIM_1 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'dtrim' project, which is a modified version of SharpSploit."
		author = "FireEye"
		id = "9be695a1-6d18-5952-974c-96a30f035e7a"
		date = "2020-12-08"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/DTRIM/production/yara/APT_HackTool_MSIL_DTRIM_1.yar#L4-L15"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "dd8805d0e470e59b829d98397507d8c2"
		logic_hash = "357c1f76631ec9ee342995cd12369fd9ff18c541bffe6f5464b1e8db45057196"
		score = 75
		quality = 73
		tags = "FILE"
		rev = 2

	strings:
		$typelibguid0 = "7760248f-9247-4206-be42-a6952aa46da2" ascii nocase wide

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule FIREEYE_RT_APT_Hacktool_MSIL_SHARPSTOMP_2 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "d1a3477d-55c6-5c33-bd65-5b1e0d65f24b"
		date = "2020-12-02"
		date = "2020-12-02"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/SHARPSTOMP/production/yara/APT_HackTool_MSIL_SHARPSTOMP_2.yar#L4-L22"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "83ed748cd94576700268d35666bf3e01"
		logic_hash = "4ed1553f12c607792d7d4e7026ecb36231cd417a06eba8b2925c2c643436b5fe"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 3

	strings:
		$f0 = "mscoree.dll" fullword nocase
		$s0 = { 06 72 [4] 6F [4] 2C ?? 06 72 [4] 6F [4] 2D ?? 72 [4] 28 [4] 28 [4] 2A }
		$s1 = { 02 28 [4] 0A 02 28 [4] 0B 02 28 [4] 0C 72 [4] 28 [4] 72 }
		$s2 = { 28 [4] 02 28 [4] 0D 12 ?? 03 6C 28 [4] 28 [4] 02 28 [4] 0D 12 ?? 03 6C 28 [4] 28 [4] 02 28 [4] 0D 12 ?? 03 6C 28 [4] 28 [4] 72 }
		$s3 = "SetCreationTime" fullword
		$s4 = "GetLastAccessTime" fullword
		$s5 = "SetLastAccessTime" fullword

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule FIREEYE_RT_APT_Hacktool_MSIL_SHARPSTOMP_1 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "4b4a54c8-9717-5fbb-8130-a49162bc6b07"
		date = "2020-12-02"
		date = "2020-12-02"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/SHARPSTOMP/production/yara/APT_HackTool_MSIL_SHARPSTOMP_1.yar#L4-L24"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "83ed748cd94576700268d35666bf3e01"
		logic_hash = "af8aa0e87d8b6623a908fde5014f3849cd0ca20d5926c798be82ce4eab2668bb"
		score = 75
		quality = 71
		tags = "FILE"
		rev = 3

	strings:
		$s0 = "mscoree.dll" fullword nocase
		$s1 = "timestompfile" fullword nocase
		$s2 = "sharpstomp" fullword nocase
		$s3 = "GetLastWriteTime" fullword
		$s4 = "SetLastWriteTime" fullword
		$s5 = "GetCreationTime" fullword
		$s6 = "SetCreationTime" fullword
		$s7 = "GetLastAccessTime" fullword
		$s8 = "SetLastAccessTime" fullword

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule FIREEYE_RT_APT_Loader_Win64_MATRYOSHKA_2 : FILE
{
	meta:
		description = "matryoshka.rs"
		author = "FireEye"
		id = "25f916bc-6ee1-5175-903c-4266b0a086e1"
		date = "2020-12-02"
		date = "2020-12-02"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/MATRYOSHKA/production/yara/APT_Loader_Win64_MATRYOSHKA_2.yar#L4-L20"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "7f8102b789303b7861a03290c79feba0"
		logic_hash = "daa6f6d526bf959c268b2c5a4cae33307cfec5e9ca51283131bbfa66a582b505"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$sb1 = { 4D [2] 00 49 [2] 08 B? 02 00 00 00 31 ?? E8 [4] 48 89 ?? 48 89 ?? 4C 89 ?? 49 89 ?? E8 [4] 4C 89 ?? 48 89 ?? E8 [4] 83 [2] 01 0F 84 [4] 48 89 ?? 48 8B [2] 48 8B [2] 48 89 [5] 48 89 [5] 48 89 [5] 41 B? [4] 4C 89 ?? 31 ?? E8 [4] C7 45 [5] 48 89 ?? 4C 89 ?? E8 [4] 85 C0 }
		$sb2 = { 4C [2] 0F 83 [4] 41 0F [3] 01 41 32 [2] 00 48 8B [5] 48 3B [5] 75 ?? 41 B? 01 00 00 00 4C 89 ?? E8 [4] E9 }
		$si1 = "CreateToolhelp32Snapshot" fullword
		$si2 = "Process32Next" fullword

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x020B ) and all of them
}

rule FIREEYE_RT_APT_Dropper_Win64_MATRYOSHKA_1 : FILE
{
	meta:
		description = "matryoshka_dropper.rs"
		author = "FireEye"
		id = "1406aafd-6217-51ef-b3af-107ee88f9c99"
		date = "2020-12-02"
		date = "2020-12-02"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/MATRYOSHKA/production/yara/APT_Dropper_Win64_MATRYOSHKA_1.yar#L4-L18"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "edcd58ba5b1b87705e95089002312281"
		logic_hash = "23f811f8e9387ca6a1257a31af66de9739733e4728adba0a3e3f74b5e5c0a556"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$sb1 = { 8D 8D [4] E8 [4] 49 89 D0 C6 [2-6] 01 C6 [2-6] 01 [0-8] C7 44 24 ?? 0E 00 00 00 4C 8D 0D [4] 48 8D 8D [4] 48 89 C2 E8 [4] C6 [2-6] 01 C6 [2-6] 01 48 89 E9 48 8D 95 [4] E8 [4] 83 [2] 01 0F 8? [4] 48 01 F3 48 29 F7 48 [2] 08 48 89 85 [4] C6 [2-6] 01 C6 [2-6] 01 C6 [2-6] 01 48 8D 8D [4] 48 89 DA 49 89 F8 E8 }
		$sb2 = { 0F 29 45 ?? 48 C7 45 ?? 00 00 00 00 0F 29 45 ?? 0F 29 45 ?? 0F 29 45 ?? 0F 29 45 ?? 0F 29 45 ?? 0F 29 45 ?? 48 C7 45 ?? 00 00 00 00 C7 45 ?? 68 00 00 00 48 8B [2] 48 8D [2] 48 89 [3] 48 89 [3] 0F 11 44 24 ?? C7 44 24 ?? 08 00 00 0C C7 44 24 ?? 00 00 00 00 31 ?? 48 89 ?? 31 ?? 45 31 ?? 45 31 ?? E8 [4] 83 F8 01 }

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x020B ) and all of them
}

rule FIREEYE_RT_APT_Dropper_Win_MATRYOSHKA_1 : FILE
{
	meta:
		description = "matryoshka_dropper.rs"
		author = "FireEye"
		id = "7fd305c7-0b1b-5d91-b968-7f1fb0a8ae47"
		date = "2020-12-02"
		date = "2020-12-02"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/MATRYOSHKA/production/yara/APT_Dropper_Win_MATRYOSHKA_1.yar#L4-L20"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "edcd58ba5b1b87705e95089002312281"
		logic_hash = "a7bf7599ec9b4b1d09a8c90b70ae565a9396fb31d449da3c1492d6fa336d9c5e"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$s1 = "\x00matryoshka.exe\x00"
		$s2 = "\x00Unable to write data\x00"
		$s3 = "\x00Error while spawning process. NTStatus: \x0a\x00"
		$s4 = "\x00.execmdstart/Cfailed to execute process\x00"

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule FIREEYE_RT_APT_Loader_Win_MATRYOSHKA_1 : FILE
{
	meta:
		description = "matryoshka_process_hollow.rs"
		author = "FireEye"
		id = "c07fb67e-ded5-593d-b5dc-d0e2c3b5a352"
		date = "2020-12-02"
		date = "2020-12-02"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/MATRYOSHKA/production/yara/APT_Loader_Win_MATRYOSHKA_1.yar#L4-L24"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "44887551a47ae272d7873a354d24042d"
		logic_hash = "8f762684ffd3984630bf41ededa78b8993b53b22591a59912cabfe635775de53"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$s1 = "ZwQueryInformationProcess" fullword
		$s2 = "WriteProcessMemory" fullword
		$s3 = "CreateProcessW" fullword
		$s4 = "WriteProcessMemory" fullword
		$s5 = "\x00Invalid NT Signature!\x00"
		$s6 = "\x00Error while creating and mapping section. NTStatus: "
		$s7 = "\x00Error no process information - NTSTATUS:"
		$s8 = "\x00Error while erasing pe header. NTStatus: "

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x020B ) and all of them
}

rule FIREEYE_RT_APT_Builder_Win64_MATRYOSHKA_1 : FILE
{
	meta:
		description = "matryoshka_pe_to_shellcode.rs"
		author = "FireEye"
		id = "0afcf13e-5cd3-5c1c-897e-b6d0c283ab0f"
		date = "2020-12-02"
		date = "2020-12-02"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/MATRYOSHKA/production/yara/APT_Builder_Win64_MATRYOSHKA_1.yar#L4-L20"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "8d949c34def898f0f32544e43117c057"
		logic_hash = "b370d7dea44bccc92fc8dbd4ea0ee9bec523820108bf8bc67acb17ebf9835f74"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$sb1 = { 4D 5A 45 52 [0-32] E8 [0-32] 00 00 00 00 [0-32] 5B 48 83 EB 09 53 48 81 [0-32] C3 [0-32] FF D3 [0-32] C3 }
		$ss1 = "\x00Stub Size: "
		$ss2 = "\x00Executable Size: "
		$ss3 = "\x00[+] Writing out to file"

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x020B ) and all of them
}

rule FIREEYE_RT_APT_Loader_Win64_MATRYOSHKA_1 : FILE
{
	meta:
		description = "matryoshka_process_hollow.rs"
		author = "FireEye"
		id = "69919a80-8ed1-5b8c-911a-ceb75570f11f"
		date = "2020-12-02"
		date = "2020-12-02"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/MATRYOSHKA/production/yara/APT_Loader_Win64_MATRYOSHKA_1.yar#L4-L19"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "44887551a47ae272d7873a354d24042d"
		logic_hash = "46e5480dc95ce8b9d8385c2e44a50b21629301535b93833c13cc3db319ac15dd"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$sb1 = { 48 8B 45 ?? 48 89 85 [0-64] C7 45 ?? 00 00 00 00 31 ?? E8 [4-64] BA 00 10 00 00 [0-32] 41 B8 04 00 00 00 E8 [4] 83 F8 01 [2-32] BA [4] E8 }
		$sb2 = { E8 [4] 83 F8 01 [2-64] 41 B9 00 10 00 00 [0-32] E8 [4] 83 F8 01 [2-32] 3D 4D 5A 00 00 [0-32] 48 63 ?? 3C [0-32] 50 45 00 00 [4-64] 0F B7 [2] 18 81 ?? 0B 01 00 00 [2-32] 81 ?? 0B 02 00 00 [2-32] 8B [2] 28 }
		$sb3 = { 66 C7 45 ?? 48 B8 48 C7 45 ?? 00 00 00 00 66 C7 45 ?? FF E0 [0-64] 41 B9 40 00 00 00 [0-32] E8 [4] 83 F8 01 }

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x020B ) and all of them
}

rule FIREEYE_RT_APT_Loader_Win32_Dshell_3 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "6b6fccef-ac93-5f1b-b9b6-c2d3ee4d8da7"
		date = "2020-11-27"
		date = "2020-11-27"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/DSHELL/production/yara/APT_Loader_Win32_DShell_3.yar#L4-L19"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "12c3566761495b8353f67298f15b882c"
		logic_hash = "ec2a8b0abc6cb6d1861199b892fbe84782b42babb08e3ea203d10ab17ff7a20a"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$sb1 = { 6A 40 68 00 30 00 00 [4-32] E8 [4-8] 50 [0-16] E8 [4-150] 6A FF [1-32] 6A 00 6A 00 5? 6A 00 6A 00 [0-32] E8 [4] 50 }
		$ss1 = "\x00CreateThread\x00"
		$ss2 = "base64.d" fullword
		$ss3 = "core.sys.windows" fullword

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x010B ) and all of them
}

rule FIREEYE_RT_APT_Loader_Win32_Dshell_1 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "dad763bd-0e4a-542a-9920-ece11d23ce24"
		date = "2020-11-27"
		date = "2020-11-27"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/DSHELL/production/yara/APT_Loader_Win32_DShell_1.yar#L4-L20"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "12c3566761495b8353f67298f15b882c"
		logic_hash = "79643f9c252765647d80f6fe1ee7bb698fbc6a6c3a0ff1fd819a09bff031907c"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$sb1 = { 6A 40 68 00 30 00 00 [4-32] E8 [4-8] 50 [0-16] E8 [4-150] 6A FF [1-32] 6A 00 6A 00 5? 6A 00 6A 00 [0-32] E8 [4] 50 }
		$sb2 = { FF 7? 0C B? [4-16] FF 7? 08 5? [0-12] E8 [4] 84 C0 74 05 B? 01 00 00 00 [0-16] 80 F2 01 0F 84 }
		$ss1 = "\x00CreateThread\x00"
		$ss2 = "base64.d" fullword
		$ss3 = "core.sys.windows" fullword

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x010B ) and all of them
}

rule FIREEYE_RT_APT_Loader_Win32_Dshell_2 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "ae34d547-d979-5ce2-bcf8-a5b4e4567de3"
		date = "2020-11-27"
		date = "2020-11-27"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/DSHELL/production/yara/APT_Loader_Win32_DShell_2.yar#L4-L21"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "590d98bb74879b52b97d8a158af912af"
		logic_hash = "958ff45add46c0a43e839e8007c1d9296ee89ddd8c045b8ec6b031b225207a6c"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 2

	strings:
		$sb1 = { 6A 40 68 00 30 00 00 [4-32] E8 [4-8] 50 [0-16] E8 [4-150] 6A FF [1-32] 6A 00 6A 00 5? 6A 00 6A 00 [0-32] E8 [4] 50 }
		$ss1 = "\x00CreateThread\x00"
		$ss2 = "base64.d" fullword
		$ss3 = "core.sys.windows" fullword
		$ss4 = "C:\\Users\\config.ini" fullword
		$ss5 = "Invalid config file" fullword

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x010B ) and all of them
}

rule FIREEYE_RT_APT_Hacktool_MSIL_TITOSPECIAL_1 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "b12490ba-41f6-5469-bcbb-0d2e0055c193"
		date = "2020-11-25"
		date = "2020-11-25"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/TITOSPECIAL/production/yara/APT_HackTool_MSIL_TITOSPECIAL_1.yar#L4-L20"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "4bf96a7040a683bd34c618431e571e26"
		logic_hash = "6def0c667d38c1bad9233628e509bdcaed322e75be4ff3823b0f788c391e090c"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 5

	strings:
		$ind_dump = { 1F 10 16 28 [2] 00 0A 6F [2] 00 0A [50-200] 18 19 18 73 [2] 00 0A 13 [1-4] 06 07 11 ?? 6F [2] 00 0A 18 7E [2] 00 0A 7E [2] 00 0A 7E [2] 00 0A 28 [2] 00 06 }
		$ind_s1 = "NtReadVirtualMemory" fullword wide
		$ind_s2 = "WriteProcessMemory" fullword
		$shellcode_x64 = { 4C 8B D1 B8 3C 00 00 00 0F 05 C3 }
		$shellcode_x86 = { B8 3C 00 00 00 33 C9 8D 54 24 04 64 FF 15 C0 00 00 00 83 C4 04 C2 14 00 }

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of ( $ind* ) and any of ( $shellcode* )
}

rule FIREEYE_RT_APT_Hacktool_MSIL_SHARPSACK_1 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharpsack' project."
		author = "FireEye"
		id = "8e344acb-73c4-5509-be9d-85cf6fe94445"
		date = "2020-12-08"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/SHARPSACK/production/yara/APT_HackTool_MSIL_SHARPSACK_1.yar#L4-L15"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "dd8805d0e470e59b829d98397507d8c2"
		logic_hash = "ecc3250e65e34595b4b827add3eb3062edad6a3373930048bfd6225d4a229e93"
		score = 75
		quality = 73
		tags = "FILE"
		rev = 2

	strings:
		$typelibguid0 = "1946808a-1a01-40c5-947b-8b4c3377f742" ascii nocase wide

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule FIREEYE_RT_APT_Hacktool_MSIL_FLUFFY_1 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "6593202d-9b30-59ed-98c0-3e730fb5ceb7"
		date = "2020-12-04"
		date = "2020-12-04"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/FLUFFY/production/yara/APT_HackTool_MSIL_FLUFFY_1.yar#L4-L18"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "11b5aceb428c3e8c61ed24a8ca50553e"
		logic_hash = "4d91c96ab7b628e88f79ee193612acc959448fe2220ef54371f5f5c6e7305d86"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$sb1 = { 0E ?? 1? 72 [4] 28 [2] 00 06 [0-16] 28 [2] 00 0A [2-80] 1F 58 0? [0-32] 28 [2] 00 06 [2-32] 1? 28 [2] 00 06 0? 0? 6F [2] 00 06 [2-4] 1F 0B }
		$sb2 = { 73 [2] 00 06 13 ?? 11 ?? 11 ?? 7D [2] 00 04 11 ?? 73 [2] 00 0A 7D [2] 00 04 0E ?? 2D ?? 11 ?? 7B [2] 00 04 72 [4] 28 [2] 00 0A [2-32] 0? 28 [2] 00 0A [2-16] 11 ?? 7B [2] 00 04 0? 28 [2] 00 0A 1? 28 [2] 00 0A [2-32] 7E [2] 00 0A [0-32] FE 15 [2] 00 02 [0-16] 7D [2] 00 04 28 [2] 00 06 [2-32] 7B [2] 00 04 7D [2] 00 04 [2-32] 7C [2] 00 04 FE 15 [2] 00 02 [0-16] 11 ?? 8C [2] 00 02 28 [2] 00 0A 28 [2] 00 0A [2-80] 8C [2] 00 02 28 [2] 00 0A 12 ?? 12 ?? 12 ?? 28 [2] 00 06 }
		$ss1 = "\x00Fluffy\x00"

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule FIREEYE_RT_APT_Hacktool_MSIL_FLUFFY_2 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "ce39710e-7649-5f7d-bbbe-65dc30f678e8"
		date = "2020-12-04"
		date = "2020-12-04"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/FLUFFY/production/yara/APT_HackTool_MSIL_FLUFFY_2.yar#L4-L21"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "11b5aceb428c3e8c61ed24a8ca50553e"
		logic_hash = "872ab717668375a49d6c7b1927a680747b405c0198fe4fc6f43ccc562870eb37"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$s1 = "\x00Asktgt\x00"
		$s2 = "\x00Kerberoast\x00"
		$s3 = "\x00HarvestCommand\x00"
		$s4 = "\x00EnumerateTickets\x00"
		$s5 = "[*] Action: " wide
		$s6 = "\x00Fluffy.Commands\x00"

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule FIREEYE_RT_APT_Hacktool_MSIL_LUALOADER_1 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'lualoader' project."
		author = "FireEye"
		id = "e8480cf8-1852-5572-8e92-c0ae676b7507"
		date = "2020-12-08"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/LUALOADER/production/yara/APT_HackTool_MSIL_LUALOADER_1.yar#L4-L15"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "dd8805d0e470e59b829d98397507d8c2"
		logic_hash = "7e9f9836ec91aa66c8779588cfceff718487f0cb5048d17538c947aba687a4cf"
		score = 75
		quality = 73
		tags = "FILE"
		rev = 3

	strings:
		$typelibguid0 = "8b546b49-2b2c-4577-a323-76dc713fe2ea" ascii nocase wide

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule FIREEYE_RT_APT_Hacktool_MSIL_REVOLVER_1 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'revolver' project."
		author = "FireEye"
		id = "8fa5adb7-dc66-51bc-9f60-2308515f33a8"
		date = "2020-12-08"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/REVOLVER/production/yara/APT_HackTool_MSIL_REVOLVER_1.yar#L4-L16"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "dd8805d0e470e59b829d98397507d8c2"
		logic_hash = "8df8a56ed55b7857adb95daa643d544a49eb5f1952b4ad3ef757c34dad2ce317"
		score = 75
		quality = 71
		tags = "FILE"
		rev = 2

	strings:
		$typelibguid0 = "a8bdbba4-7291-49d1-9a1b-372de45a9d88" ascii nocase wide
		$typelibguid1 = "b214d962-7595-440b-abef-f83ecdb999d2" ascii nocase wide

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule FIREEYE_RT_APT_Hacktool_MSIL_NOAMCI_1 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'noamci' project."
		author = "FireEye"
		id = "48066258-528f-5a70-81e1-15d6dfd9ff4f"
		date = "2020-12-08"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/NOAMCI/production/yara/APT_HackTool_MSIL_NOAMCI_1.yar#L4-L16"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "dd8805d0e470e59b829d98397507d8c2"
		logic_hash = "6278cfb4e9af20bbe943f4b99227c7fba276315a9f0059575b3ed4ef96a848c4"
		score = 75
		quality = 71
		tags = "FILE"
		rev = 4

	strings:
		$typelibguid0 = "7bcccf21-7ecd-4fd4-8f77-06d461fd4d51" ascii nocase wide
		$typelibguid1 = "ef86214e-54de-41c3-b27f-efc61d0accc3" ascii nocase wide

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule FIREEYE_RT_APT_Hacktool_MSIL_JUSTASK_1 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'justask' project."
		author = "FireEye"
		id = "06a03d82-db69-5b5a-a578-a8053814e917"
		date = "2020-12-08"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/JUSTASK/production/yara/APT_HackTool_MSIL_JUSTASK_1.yar#L4-L15"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "dd8805d0e470e59b829d98397507d8c2"
		logic_hash = "24d2f8e3838c4f02cd80644a396ce7cf105761d2feba54e39973564ca5e97571"
		score = 75
		quality = 73
		tags = "FILE"
		rev = 2

	strings:
		$typelibguid0 = "aa59be52-7845-4fed-9ea5-1ea49085d67a" ascii nocase wide

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule FIREEYE_RT_APT_Hacktool_MSIL_WMISPY_2 : FILE
{
	meta:
		description = "wql searches"
		author = "FireEye"
		id = "474af878-a657-54bc-a063-04532df928d4"
		date = "2020-12-08"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/WMISPY/production/yara/APT_HackTool_MSIL_WMISPY_2.yar#L4-L24"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "3651f252d53d2f46040652788499d65a"
		logic_hash = "553fc1e536482a56b3228a5c9ebac843af9083e8ac864bf65c81b36a39ca5e5e"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 4

	strings:
		$MSIL = "_CorExeMain"
		$str1 = "root\\cimv2" wide
		$str2 = "root\\standardcimv2" wide
		$str3 = "from MSFT_NetNeighbor" wide
		$str4 = "from Win32_NetworkLoginProfile" wide
		$str5 = "from Win32_IP4RouteTable" wide
		$str6 = "from Win32_DCOMApplication" wide
		$str7 = "from Win32_SystemDriver" wide
		$str8 = "from Win32_Share" wide
		$str9 = "from Win32_Process" wide

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and $MSIL and all of ( $str* )
}

rule FIREEYE_RT_APT_Hacktool_MSIL_SHARPDACL_1 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharpdacl' project."
		author = "FireEye"
		id = "13f4e3ea-1e36-5fad-9197-66511d6f026a"
		date = "2020-12-08"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/UNCATEGORIZED/production/yara/APT_HackTool_MSIL_SHARPDACL_1.yar#L4-L15"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "dd8805d0e470e59b829d98397507d8c2"
		logic_hash = "5f44ec5ddded18fb3a9132b469b2fe7ccbffb3f907325485f0f72fe3d6bbfa23"
		score = 75
		quality = 73
		tags = "FILE"
		rev = 3

	strings:
		$typelibguid0 = "b3c17fb5-5d5a-4b14-af3c-87a9aa941457" ascii nocase wide

	condition:
		filesize < 10MB and ( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule FIREEYE_RT_APT_Hacktool_MSIL_SHARPNFS_1 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharpnfs' project."
		author = "FireEye"
		id = "b9d1b4e8-644a-5611-85e8-a124f915b443"
		date = "2020-12-08"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/UNCATEGORIZED/production/yara/APT_HackTool_MSIL_SHARPNFS_1.yar#L4-L15"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "dd8805d0e470e59b829d98397507d8c2"
		logic_hash = "e7f9883376b153849970599d9ecc308882eb86a67834cfd8ab06b44539346125"
		score = 75
		quality = 73
		tags = "FILE"
		rev = 3

	strings:
		$typelibguid0 = "9f67ebe3-fc9b-40f2-8a18-5940cfed44cf" ascii nocase wide

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule FIREEYE_RT_APT_Hacktool_MSIL_SHARPPATCHCHECK_1 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharppatchcheck' project."
		author = "FireEye"
		id = "dedc12b9-b9e7-5c13-ad6d-2e286aba2302"
		date = "2020-12-08"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/UNCATEGORIZED/production/yara/APT_HackTool_MSIL_SHARPPATCHCHECK_1.yar#L4-L15"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "dd8805d0e470e59b829d98397507d8c2"
		logic_hash = "dec6231b656eed1526d4f70fe1b9a476bfb06246f0a7c25f2687d8c68886d400"
		score = 75
		quality = 73
		tags = "FILE"
		rev = 2

	strings:
		$typelibguid0 = "528b8df5-6e5e-4f3b-b617-ac35ed2f8975" ascii nocase wide

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule FIREEYE_RT_APT_Hacktool_MSIL_SHARPNATIVEZIPPER_1 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharpnativezipper' project."
		author = "FireEye"
		id = "c48835a7-06fe-5b30-be4d-086d98dc7a21"
		date = "2020-12-08"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/UNCATEGORIZED/production/yara/APT_HackTool_MSIL_SHARPNATIVEZIPPER_1.yar#L4-L15"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "dd8805d0e470e59b829d98397507d8c2"
		logic_hash = "fa54375b21abbb613e695f70a15233575fbe6e0536716544bb3b527f5e3ed8c6"
		score = 75
		quality = 73
		tags = "FILE"
		rev = 3

	strings:
		$typelibguid0 = "de5536db-9a35-4e06-bc75-128713ea6d27" ascii nocase wide

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule FIREEYE_RT_APT_Hacktool_MSIL_SHARPWEBCRAWLER_1 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharpwebcrawler' project."
		author = "FireEye"
		id = "29b2a410-bcc4-58df-b192-7a413b3db1c0"
		date = "2020-12-08"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/UNCATEGORIZED/production/yara/APT_HackTool_MSIL_SHARPWEBCRAWLER_1.yar#L4-L15"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "dd8805d0e470e59b829d98397507d8c2"
		logic_hash = "8df328663a813ca0a6864ae0503cbc1b03cfdf839215b9b4f2bb7962adf09bf8"
		score = 75
		quality = 73
		tags = "FILE"
		rev = 2

	strings:
		$typelibguid0 = "cf27abf4-ef35-46cd-8d0c-756630c686f1" ascii nocase wide

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule FIREEYE_RT_APT_Hacktool_MSIL_SHARPZIPLIBZIPPER_1 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharpziplibzipper' project."
		author = "FireEye"
		id = "392a52be-29ae-58e1-b517-1ab34a1e1fb8"
		date = "2020-12-08"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/UNCATEGORIZED/production/yara/APT_HackTool_MSIL_SHARPZIPLIBZIPPER_1.yar#L4-L15"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "dd8805d0e470e59b829d98397507d8c2"
		logic_hash = "19354edb91a0d79fdf79437f7247bcf155514db40340af91a3320b556dc2e4c2"
		score = 75
		quality = 73
		tags = "FILE"
		rev = 3

	strings:
		$typelibguid0 = "485ba350-59c4-4932-a4c1-c96ffec511ef" ascii nocase wide

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule FIREEYE_RT_APT_Hacktool_MSIL_DNSOVERHTTPS_C2_1 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the public 'DoHC2' External C2 project."
		author = "FireEye"
		id = "ee71be6c-e3c8-5365-9f32-157f00066c49"
		date = "2020-12-08"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/UNCATEGORIZED/production/yara/APT_HackTool_MSIL_DNSOVERHTTPS_C2_1.yar#L4-L16"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "dd8805d0e470e59b829d98397507d8c2"
		logic_hash = "a482161bbd8e249977f28466ff1381d4693495f8b8ccd9183ae4fde1ec1471eb"
		score = 75
		quality = 71
		tags = "FILE"
		rev = 2

	strings:
		$typelibguid0 = "5d9515d0-df67-40ed-a6b2-6619620ef0ef" ascii nocase wide
		$typelibguid1 = "7266acbb-b10d-4873-9b99-12d2043b1d4e" ascii nocase wide

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule FIREEYE_RT_APT_Hacktool_MSIL_MODIFIEDSHARPVIEW_1 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'modifiedsharpview' project."
		author = "FireEye"
		id = "e07d3d4b-fba3-5df7-85f4-927bb8cec2d1"
		date = "2020-12-08"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/UNCATEGORIZED/production/yara/APT_HackTool_MSIL_MODIFIEDSHARPVIEW_1.yar#L4-L15"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "db0eaad52465d5a2b86fdd6a6aa869a5"
		logic_hash = "a47c48da998243fab92665649fb9d6ecc6ac32e1fd884c2c0d5ccecb05290c10"
		score = 75
		quality = 73
		tags = "FILE"
		rev = 3

	strings:
		$typelibguid0 = "22a156ea-2623-45c7-8e50-e864d9fc44d3" ascii nocase wide

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule FIREEYE_RT_APT_Hacktool_MSIL_SHARPTEMPLATE_1 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharptemplate' project."
		author = "FireEye"
		id = "0ca9a13c-e0a0-588b-be13-5954b17d95b1"
		date = "2020-12-08"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/UNCATEGORIZED/production/yara/APT_HackTool_MSIL_SHARPTEMPLATE_1.yar#L4-L15"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "dd8805d0e470e59b829d98397507d8c2"
		logic_hash = "9746c1ab7b945d311c53fbdf95993d255369e06b23a3279c9f2e8a4df73ab63c"
		score = 75
		quality = 73
		tags = "FILE"
		rev = 2

	strings:
		$typelibguid0 = "e9e452d4-9e58-44ff-ba2d-01b158dda9bb" ascii nocase wide

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule FIREEYE_RT_APT_Hacktool_MSIL_REDTEAMMATERIALS_1 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'red_team_materials' project."
		author = "FireEye"
		id = "272cd3e9-884a-566b-ae90-4a79ee726a8d"
		date = "2020-12-08"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/UNCATEGORIZED/production/yara/APT_HackTool_MSIL_REDTEAMMATERIALS_1.yar#L4-L16"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "dd8805d0e470e59b829d98397507d8c2"
		logic_hash = "ca54a1e8335c4256295fc643f5d31eae2e89f020dc7a9b571c4772edaad08022"
		score = 75
		quality = 71
		tags = "FILE"
		rev = 3

	strings:
		$typelibguid0 = "86c95a99-a2d6-4ebe-ad5f-9885b06eab12" ascii nocase wide
		$typelibguid1 = "e06f1411-c7f8-4538-bbb9-46c928732245" ascii nocase wide

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule FIREEYE_RT_APT_Hacktool_MSIL_SHARPSQLCLIENT_1 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharpsqlclient' project."
		author = "FireEye"
		id = "4d526c36-f56f-53cf-9bdf-b7a15619eb41"
		date = "2020-12-08"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/UNCATEGORIZED/production/yara/APT_HackTool_MSIL_SHARPSQLCLIENT_1.yar#L4-L15"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "dd8805d0e470e59b829d98397507d8c2"
		logic_hash = "bc79f80582f4fadecf54d926abdcf61694224654ba5075203f0d1123cf11afc1"
		score = 75
		quality = 73
		tags = "FILE"
		rev = 2

	strings:
		$typelibguid0 = "13ed03cd-7430-410d-a069-cf377165fbfd" ascii nocase wide

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule FIREEYE_RT_APT_Hacktool_MSIL_SHARPGOPHER_1 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharpgopher' project."
		author = "FireEye"
		id = "cc8eb9cd-9a51-5fab-b0a4-247baaa69dd7"
		date = "2020-12-08"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/UNCATEGORIZED/production/yara/APT_HackTool_MSIL_SHARPGOPHER_1.yar#L4-L15"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "dd8805d0e470e59b829d98397507d8c2"
		logic_hash = "ac37f77440cb76d7dafa4c9b4130471ca6ca760f6d72691db9ebb8cbaaad0c58"
		score = 75
		quality = 73
		tags = "FILE"
		rev = 2

	strings:
		$typelibguid0 = "83413a89-7f5f-4c3f-805d-f4692bc60173" ascii nocase wide

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule FIREEYE_RT_APT_Hacktool_MSIL_SHARPDNS_1 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharpdns' project."
		author = "FireEye"
		id = "db6b45be-f42f-5d0f-b50a-32e7a2cbfce6"
		date = "2020-12-08"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/UNCATEGORIZED/production/yara/APT_HackTool_MSIL_SHARPDNS_1.yar#L4-L15"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "dd8805d0e470e59b829d98397507d8c2"
		logic_hash = "bab36f9b1532c3b24c2aea2907006820ed7cf1c90dae7a8138962e14ac9eff55"
		score = 75
		quality = 73
		tags = "FILE"
		rev = 2

	strings:
		$typelibguid0 = "d888cec8-7562-40e9-9c76-2bb9e43bb634" ascii nocase wide

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule FIREEYE_RT_APT_Loader_MSIL_WILDCHILD_1 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "b9e0707e-98eb-55da-ad1d-6a84bd113747"
		date = "2020-12-01"
		date = "2020-12-01"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/WILDCHILD/production/yara/APT_Loader_MSIL_WILDCHILD_1.yar#L4-L18"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "6f04a93753ae3ae043203437832363c4"
		logic_hash = "a600c3d127f77dc1f99160e4a242e005970de0abd1798296b6a351b968ca1350"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$s1 = "\x00QueueUserAPC\x00"
		$s2 = "\x00WriteProcessMemory\x00"
		$sb1 = { 6F [2] 00 0A 28 [2] 00 0A 6F [2] 00 0A 13 ?? 28 [2] 00 0A 28 [2] 00 0A 13 ?? 11 ?? 11 ?? 28 [2] 00 0A [0-16] 7B [2] 00 04 1? 20 [4] 28 [2] 00 0A 11 ?? 28 [2] 00 0A 28 [2] 00 0A 7E [2] 00 0A 7E [2] 00 0A 28 [2] 00 06 [0-16] 14 7E [2] 00 0A 7E [2] 00 0A 1? 20 04 00 08 08 7E [2] 00 0A 14 12 ?? 12 ?? 28 [2] 00 06 [0-16] 7B [2] 00 04 7E [2] 00 0A [0-16] 8E ?? 7E [2] 00 04 7E [2] 00 04 28 [2] 00 06 [4-120] 28 [2] 00 06 [0-80] 6F [2] 00 0A 6F [2] 00 0A 28 [2] 00 06 13 ?? 11 ?? 11 ?? 7E [2] 00 0A 28 [2] 00 06 }

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule FIREEYE_RT_APT_Loader_MSIL_TRIMBISHOP_2 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "90ee2569-2e68-517b-b2d7-8c4015d92683"
		date = "2020-12-03"
		date = "2020-12-03"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/TRIMBISHOP/production/yara/APT_Loader_MSIL_TRIMBISHOP_2.yar#L4-L22"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "c0598321d4ad4cf1219cc4f84bad4094"
		logic_hash = "4cccfca0c06954105f762066741b6c35599a6c28df8b7c255a2659059169578f"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$ss1 = "\x00NtMapViewOfSection\x00"
		$ss2 = "\x00NtOpenProcess\x00"
		$ss3 = "\x00NtAlertResumeThread\x00"
		$ss4 = "\x00LdrGetProcedureAddress\x00"
		$ss5 = "\x2f(\x00?\x00i\x00)\x00(\x00-\x00|\x00-\x00-\x00|\x00/\x00)\x00(\x00i\x00|\x00I\x00n\x00j\x00e\x00c\x00t\x00)\x00$\x00"
		$ss6 = "\x2d(\x00?\x00i\x00)\x00(\x00-\x00|\x00-\x00-\x00|\x00/\x00)\x00(\x00c\x00|\x00C\x00l\x00e\x00a\x00n\x00)\x00$\x00"
		$tb1 = "\x00DTrim.Execution.DynamicInvoke\x00"

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule FIREEYE_RT_APT_Loader_MSIL_TRIMBISHOP_1 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "1a3f4247-25f4-51ca-b881-209c0753b915"
		date = "2020-12-03"
		date = "2020-12-03"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/TRIMBISHOP/production/yara/APT_Loader_MSIL_TRIMBISHOP_1.yar#L4-L22"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "e91670423930cbbd3dbf5eac1f1a7cb6"
		logic_hash = "f020efff58c8b7761d700c662c422a9e1ffdf8fe5f6648e421b7c257e3b8d078"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$sb1 = { 28 [2] 00 06 0A 06 7B [2] 00 04 [12-64] 06 7B [2] 00 04 6E 28 [2] 00 06 0B 07 7B [2] 00 04 [12-64] 0? 7B [2] 00 04 0? 7B [2] 00 04 0? 7B [2] 00 04 6E 28 [2] 00 06 0? 0? 7B [2] 00 04 [12-80] 0? 7B [2] 00 04 1? 0? 7B [2] 00 04 }
		$sb2 = { 0F ?? 7C [2] 00 04 28 [2] 00 0A 8C [2] 00 01 [20-80] 28 [2] 00 06 0? 0? 7E [2] 00 0A 28 [2] 00 0A [12-80] 7E [2] 00 0A 13 ?? 0? 7B [2] 00 04 28 [2] 00 0A 0? 28 [2] 00 0A 58 28 [2] 00 0A 13 [1-32] 28 [2] 00 0A [0-32] D0 [2] 00 02 28 [2] 00 0A 28 [2] 00 0A 74 [2] 00 02 }
		$ss1 = "\x00NtMapViewOfSection\x00"
		$ss2 = "\x00NtOpenProcess\x00"
		$ss3 = "\x00NtAlertResumeThread\x00"
		$ss4 = "\x00LdrGetProcedureAddress\x00"
		$tb1 = "\x00DTrim.Execution.DynamicInvoke\x00"

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( @sb1 [ 1 ] < @sb2 [ 1 ] ) and ( all of ( $ss* ) ) and ( all of ( $tb* ) )
}

rule MALPEDIA_Win_Keylogger_Apt3_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "96f37009-369b-5f17-a68b-4eb5c0d4026d"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.keylogger_apt3"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.keylogger_apt3_auto.yar#L1-L131"
		license_url = "N/A"
		logic_hash = "023590d599979615d817aedf4414560e8504e62badef12c9dd3c7d358dc03318"
		score = 75
		quality = 75
		tags = "FILE"
		version = "1"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_rule_date = "20260105"
		malpedia_hash = "19b79e7cab4eaf532122e5b45a77dd8f6bb5cc79"
		malpedia_version = "20251219"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"

	strings:
		$sequence_0 = { 50 ffd7 8b4e08 6a08 51 ffd7 }
		$sequence_1 = { 8b9c2430040000 55 8bac2430040000 56 57 8bbc2434040000 6800010000 }
		$sequence_2 = { 52 ffd7 8b0d???????? 8d442424 50 51 }
		$sequence_3 = { 8d45f0 50 e8???????? cc e8???????? 8b4004 c3 }
		$sequence_4 = { e8???????? 55 e8???????? 68???????? e8???????? 8b8c2440020000 83c40c }
		$sequence_5 = { 52 ffd7 a1???????? 896844 8b9eac010000 85db 742e }
		$sequence_6 = { 52 e8???????? 8d862c020000 50 8d4c242c 68???????? 51 }
		$sequence_7 = { 8d7c00ff 3bc7 89442418 0f8dc6000000 8b542414 8bd8 69db14010000 }
		$sequence_8 = { 68???????? 52 ffd7 8b0d???????? 8d442438 50 }
		$sequence_9 = { e8???????? 83c404 8b442414 6a00 6a00 6a10 8d54244c }

	condition:
		7 of them and filesize < 761856
}

rule MALPEDIA_Win_Postnaptea_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "51c689b3-106f-5456-8a81-c39f4d1222d0"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.postnaptea"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.postnaptea_auto.yar#L1-L134"
		license_url = "N/A"
		logic_hash = "cbc31a40430b61bd28460ce500d3e6052f8e6a6f9e1d2c25674ed00c58ea2b2d"
		score = 75
		quality = 75
		tags = "FILE"
		version = "1"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_rule_date = "20260105"
		malpedia_hash = "19b79e7cab4eaf532122e5b45a77dd8f6bb5cc79"
		malpedia_version = "20251219"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"

	strings:
		$sequence_0 = { e8???????? ffd0 448bc0 488d542430 488bb590000000 488bce e8???????? }
		$sequence_1 = { c745c8d4f6ccf6 41bf60090000 c745cc95f695f6 c745d086f6cdf6 c745d4c6f6c7f6 660f1f840000000000 4863c2 }
		$sequence_2 = { c785060800000af50cf5 c7850a08000012f50ef5 c7850e08000009f505f5 c7851208000003f511f5 c7851608000009f54df5 c7851a0800001af507f5 c7851e08000015f551f5 }
		$sequence_3 = { c7459418f513f5 c7459819f51bf5 c7459c5ff5baf5 c745a0a1f50000 4533c0 418bd0 660f1f840000000000 }
		$sequence_4 = { e8???????? 0fb64b08 0fb7430a 663b4509 7416 84c9 750c }
		$sequence_5 = { c744247c01f516f5 c7458018f515f5 c7458453f517f5 c745881af518f5 c7458c03f51df5 c7459017f50ef5 c7459408f55cf5 }
		$sequence_6 = { c7451830f51bf5 c7451c0bf5e8f5 c74520eef5e6f5 c74524a3f5e1f5 c74528fdf5e3f5 c7452ce4f5fdf5 c74530fdf5e3f5 }
		$sequence_7 = { ff15???????? 85c0 7498 83f857 7493 4533c0 418bc8 }
		$sequence_8 = { ffc3 41b401 488b0f 4885c9 7441 488b4138 4c3928 }
		$sequence_9 = { ff15???????? 4c8bf0 4885ff 0f84a90a0000 4885c0 0f84a00a0000 c74424400af532f5 }

	condition:
		7 of them and filesize < 2457600
}

rule MALPEDIA_Win_Credraptor_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "38da88b1-241e-5356-be41-ccd7d9b62617"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.credraptor"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.credraptor_auto.yar#L1-L134"
		license_url = "N/A"
		logic_hash = "0cde833c9a51e3ab99821592757d4fd144febcb8863fef5eac3bf6a67840a9e9"
		score = 75
		quality = 75
		tags = "FILE"
		version = "1"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_rule_date = "20260105"
		malpedia_hash = "19b79e7cab4eaf532122e5b45a77dd8f6bb5cc79"
		malpedia_version = "20251219"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"

	strings:
		$sequence_0 = { 8b4720 83c40c 837e4000 89558c 8945c0 894db8 0f85c9120000 }
		$sequence_1 = { e8???????? 83c40c e9???????? 837f3000 7415 8b5508 52 }
		$sequence_2 = { e8???????? 83c404 8b5dfc 5e 8b4d0c 51 8bc3 }
		$sequence_3 = { e9???????? a802 7508 83c8ff e9???????? 8b45f0 85c0 }
		$sequence_4 = { c6043b25 03da ddd9 ddd8 8b4d94 41 803900 }
		$sequence_5 = { c745dc377f0682 c745e0002de218 884de9 8855ea 8845eb 3bc7 750e }
		$sequence_6 = { c70353000000 b802000000 5b 5d c3 83f83e 7510 }
		$sequence_7 = { be???????? 8d4ddc 8a01 3a06 751a 84c0 7412 }
		$sequence_8 = { c1f812 0cf0 0fb6c8 51 8bce e8???????? 8bd3 }
		$sequence_9 = { e8???????? ff45e4 83c404 83c318 8945f0 85c0 74e0 }

	condition:
		7 of them and filesize < 1728512
}

rule TRELLIX_ARC_APT_Acidbox_Kernelmode_Module : KERNELDRIVER FILE
{
	meta:
		description = "Rule to detect the kernel mode component of AcidBox"
		author = "Marc Rivero | McAfee ATR Team"
		id = "80b60307-5431-5f21-9e6f-06adaab0519d"
		date = "2020-07-24"
		modified = "2020-08-14"
		reference = "https://github.com/advanced-threat-research/Yara-Rules/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/APT/APT_acidbox.yar#L1-L32"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/LICENSE"
		logic_hash = "e39da89d0da22115ac7889bc73ff183973a6c5334e304df955362bde76694d42"
		score = 75
		quality = 70
		tags = "KERNELDRIVER, FILE"
		rule_version = "v1"
		malware_type = "kerneldriver"
		malware_family = "Rootkit:W32/Acidbox"
		actor_type = "APT"
		actor_group = "Turla"
		hash1 = "3ef071e0327e7014dd374d96bed023e6c434df6f98cce88a1e7335a667f6749d"

	strings:
		$pattern_0 = { 897c2434 8978b8 8d5f28 448bc3 33d2 }
		$pattern_1 = { 4c8d842470010000 488d942418010000 498bcf e8???????? 8bd8 89442460 }
		$pattern_2 = { 4c8bf1 49d1eb 4585c9 0f88a2000000 440fb717 498bd0 }
		$pattern_3 = { ff15???????? 4c8d9c2480000000 498b5b10 498b7318 498b7b20 4d8b7328 498be3 }
		$pattern_4 = { 33d2 41b8???????? 895c2420 e8???????? }
		$pattern_5 = { 895c2420 4885ff 0f8424010000 440f20c0 84c0 0f8518010000 }
		$pattern_6 = { 85f6 0f8469fdffff 488d8424c8010000 41b9???????? }
		$pattern_7 = { 894c2404 750a ffc7 893c24 41ffc3 ebcb 85c9 }
		$pattern_8 = { 488b5c2450 488b742458 488b7c2460 4883c430 }
		$pattern_9 = { 33d2 488b4c2428 e8???????? 448b842450040000 4503c0 4c8d8c2450040000 488bd7 }

	condition:
		7 of them and filesize < 78848
}

rule ARKBIRD_SOLG_APT_Chimera_Sept_2020_1 : FILE
{
	meta:
		description = "Detect Cobalt Strike agent used by Chimera"
		author = "Arkbird_SOLG"
		id = "7a7c3952-fa6e-5643-a40f-d2e466b8c2a2"
		date = "2020-10-03"
		modified = "2020-10-04"
		reference = "Internal Research"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2020-10-03/Chimera/APT_Chimera_Sept_2020_1.yar#L1-L23"
		license_url = "N/A"
		logic_hash = "8fdb34c793534f8632fd2c35b89462d4a736a31f2347e7bab3e8bcebff04c21f"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "f6d89ff139f4169e8a67332a0fd55b6c9beda0b619b1332ddc07d9a860558bab"

	strings:
		$header = { 4D 5A 41 52 55 48 89 E5 48 83 EC 20 48 83 E4 F0 E8 00 00 00 00 5B 48 81 C3 EB 18 00 00 FF D3 48 81 C3 00 09 03 00 49 89 D8 6A 04 5A FF D0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 E8 }
		$s1 = "\\\\%s\\pipe\\%s" fullword ascii
		$s2 = "%04x-%04x:%s" fullword wide
		$core1 = "core_pivot_session_new" fullword ascii
		$core2 = "core_pivot_session_died" fullword ascii
		$core3 = "core_pivot_remove" fullword ascii
		$core4 = "core_pivot_add" fullword ascii
		$lib1 = "CreateNamedPipeA" fullword ascii
		$lib2 = "ConnectNamedPipe" fullword ascii
		$lib3 = "WinHttpGetIEProxyConfigForCurrentUser" fullword ascii
		$export = "ReflectiveLoader" fullword ascii

	condition:
		uint16( 0 ) == 0x4a5d and filesize > 30KB and $header and 1 of ( $s* ) and 2 of ( $core* ) and 2 of ( $lib* ) and $export
}

rule ARKBIRD_SOLG_APT_NK_Lazarus_Stealer_Screencapture_June_2020_1 : FILE
{
	meta:
		description = "Detect ScreenCapture malware used by Lazarus APT"
		author = "Arkbird_SOLG, James_inthe_box"
		id = "bb0463ac-6219-5a12-b3d2-fc82800bda69"
		date = "2020-06-23"
		modified = "2021-07-13"
		reference = "https://twitter.com/GR_CTI/status/1275164880992186371"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2020-06-23/APT_Lazarus_Stealer_June_2020_1.yar#L3-L31"
		license_url = "N/A"
		logic_hash = "66f8d3da0f70f6c4ed6f853ab4040d7f96c043e9e194f1720999b48910b3e756"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "6caa98870efd1097ee13ae9c21c6f6c9202a19ad049a9e65c60fce5c889dc4c8"

	strings:
		$s1 = "E:\\workspace\\VS\\crat_2\\client\\Build\\Win32\\DllRelease\\ScreenCapture_Win32_DllRelease.pdb" fullword ascii
		$s2 = "CloseHandle ScreenCaptureMutex failure! %d" fullword ascii
		$s3 = "ScreenCapture_Win32_DllRelease.dll" fullword ascii
		$s4 = "ScreenCaptureMutex already created! %s\n" fullword ascii
		$s5 = "Capturing screen...\n" fullword ascii
		$s6 = "%s\\P%02d%lu.tmp" fullword ascii
		$s7 = "ScreenCaptureThread finished!" fullword ascii
		$s8 = "ScreenCaptureThread started!" fullword ascii
		$s9 = "ScreenCapture start time set to %llu" fullword ascii
		$s10 = "ScreenCaptureMutex already created! %s\n" fullword ascii
		$s11 = "Major=%d, Minor=%d, Build=%d, Arch=%d" fullword ascii
		$s12 = "Can't create file %s, errno = %d, nCreateRetryCount = %d" fullword ascii
		$s13 = "ExploreDirectory, csDirectoryPath = %s, dwError=%d" fullword ascii
		$s14 = "[END] ScreenCaptureThread terminated!" fullword ascii
		$s15 = { 25 00 2d 00 32 00 30 00 73 00 20 00 20 00 20 00 25 00 31 00 30 00 6c 00 6c 00 75 00 20 00 62 00 79 00 74 00 65 00 73 }
		$s16 = { 57 00 72 00 6f 00 74 00 65 00 20 00 25 00 64 00 20 00 62 00 79 00 74 00 65 00 73 00 20 00 74 00 6f 00 20 00 66 00 69 00 6c 00 65 00 20 00 25 00 73 }
		$s17 = "Entered Windows direcotry, skipping..." fullword ascii
		$s18 = "Found %d entries." fullword ascii

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 80KB and 14 of them
}

rule ARKBIRD_SOLG_APT_NK_Lazarus_Stealer_Keylog_June_2020_1 : FILE
{
	meta:
		description = "Detect keylog malware used by Lazarus APT"
		author = "Arkbird_SOLG, James_inthe_box"
		id = "dd6aae8c-76d1-514d-905e-21472eb9b9b2"
		date = "2020-06-23"
		modified = "2021-07-13"
		reference = "https://twitter.com/GR_CTI/status/1275164880992186371"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2020-06-23/APT_Lazarus_Stealer_June_2020_1.yar#L33-L58"
		license_url = "N/A"
		logic_hash = "9a4e17903ad2a7c80651aa8f3d57876d1621be06ba7a683135b11929b232b2fa"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "6d461bf3e3ca68b2d6d850322b79d5e3e647b0d515cb10449935bf6d77d7d5f2"

	strings:
		$s1 = "E:\\workspace\\VS\\crat_2\\client\\Build\\Win32\\DllRelease\\KeyLog_Win32_DllRelease.pdb" fullword ascii
		$s2 = "CloseHandle KeyLogMutex failure! %d" fullword ascii
		$s3 = "KeyLog_Win32_DllRelease.dll" fullword ascii
		$s4 = "Key Log Mutex already created! %s\n" fullword ascii
		$s5 = "Unable to GetProcAddress of GetAsyncKeyState" fullword ascii
		$s6 = "KeyLogThread finished!" fullword ascii
		$s7 = "KeyLogThread started!" fullword ascii
		$s8 = "Major=%d, Minor=%d, Build=%d, Arch=%d" fullword ascii
		$s9 = "Can't create file %s, errno = %d, nCreateRetryCount = %d" fullword ascii
		$s10 = "ExploreDirectory, csDirectoryPath = %s, dwError=%d" fullword ascii
		$s11 = "[END] KeyLogThread terminated!" fullword ascii
		$s12 = { 25 00 2d 00 32 00 30 00 73 00 20 00 20 00 20 00 25 00 31 00 30 00 6c 00 6c 00 75 00 20 00 62 00 79 00 74 00 65 00 73 }
		$s13 = { 57 00 72 00 6f 00 74 00 65 00 20 00 25 00 64 00 20 00 62 00 79 00 74 00 65 00 73 00 20 00 74 00 6f 00 20 00 66 00 69 00 6c 00 65 00 20 00 25 00 73 }
		$s14 = "Entered Windows direcotry, skipping..." fullword ascii
		$s15 = "Found %d entries." fullword ascii

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 80KB and 11 of them
}

rule ARKBIRD_SOLG_APT_NK_Lazarus_Stealer_Generic_June_2020_1 : FILE
{
	meta:
		description = "Detect stealers used by Lazarus APT by common strings"
		author = "Arkbird_SOLG, James_inthe_box"
		id = "11a7c531-91a4-524e-aa5d-c11538f7db58"
		date = "2020-06-23"
		modified = "2021-07-13"
		reference = "https://twitter.com/GR_CTI/status/1275164880992186371"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2020-06-23/APT_Lazarus_Stealer_June_2020_1.yar#L60-L85"
		license_url = "N/A"
		logic_hash = "878e4a128b7de45f4940e7adccfeb376ce46e87b35b25e162f668303e9fd7852"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "6d461bf3e3ca68b2d6d850322b79d5e3e647b0d515cb10449935bf6d77d7d5f2"
		hash2 = "6caa98870efd1097ee13ae9c21c6f6c9202a19ad049a9e65c60fce5c889dc4c8"

	strings:
		$s1 = "E:\\workspace\\VS\\crat_2\\client\\Build\\Win32\\DllRelease" fullword ascii
		$s2 = "Mutex failure! %d" fullword ascii
		$s3 = "Win32_DllRelease.dll" fullword ascii
		$s4 = "Mutex already created! %s\n" fullword ascii
		$s5 = "[END]" fullword ascii
		$s6 = "Thread finished!" fullword ascii
		$s7 = "Thread started!" fullword ascii
		$s8 = "Major=%d, Minor=%d, Build=%d, Arch=%d" fullword ascii
		$s9 = "Can't create file %s, errno = %d, nCreateRetryCount = %d" fullword ascii
		$s10 = "ExploreDirectory, csDirectoryPath = %s, dwError=%d" fullword ascii
		$s11 = "Thread terminated!" fullword ascii
		$s12 = { 25 00 2d 00 32 00 30 00 73 00 20 00 20 00 20 00 25 00 31 00 30 00 6c 00 6c 00 75 00 20 00 62 00 79 00 74 00 65 00 73 }
		$s13 = { 57 00 72 00 6f 00 74 00 65 00 20 00 25 00 64 00 20 00 62 00 79 00 74 00 65 00 73 00 20 00 74 00 6f 00 20 00 66 00 69 00 6c 00 65 00 20 00 25 00 73 }
		$s14 = "Entered Windows direcotry, skipping..." fullword ascii

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 80KB and 11 of them
}

rule ARKBIRD_SOLG_APT_Molerats_Feb_2021_1 : FILE
{
	meta:
		description = "Detect Molerats implants"
		author = "Arkbird_SOLG"
		id = "8ede3aa9-9788-52a5-91a7-bb160daad5ba"
		date = "2021-02-27"
		modified = "2021-03-01"
		reference = "Internal Research"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-02-28/Molerats/APT_Molerats_Feb_2021_1.yar#L1-L23"
		license_url = "N/A"
		logic_hash = "fbd98f088019434f736107dfe62a307e2c57d0288d68f3133a13de59bf318aea"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "0a55551ade55705d4be6e946ab58a26d7cf8087558894af8799931b09d38f3bc"
		hash2 = "c9d7b5d06cd8ab1a01bf0c5bf41ef2a388e41b4c66b1728494f86ed255a95d48"

	strings:
		$seq1 = { 55 8b ec 81 c4 60 fc ff ff 53 33 d2 89 95 60 fc ff ff 89 45 fc 33 c0 55 68 [1-3] 00 64 ff 30 64 89 20 8b 45 fc 83 78 44 00 0f 85 5d 01 00 00 b2 01 a1 [2] 44 00 e8 [3] ff 8b 55 fc 89 42 44 8b 45 fc 83 c0 48 e8 [3] ff 8d 85 ec fe ff ff 50 6a 40 e8 [3] ff 48 85 c0 0f 8c 18 01 00 00 40 89 45 f0 8d 85 ec fe ff ff 89 45 ec 8b 45 ec 8b 00 e8 35 ?? f5 ff 84 c0 0f 84 ec 00 00 00 8d 45 f4 50 68 19 00 02 00 6a 00 6a 00 8b 45 ec 0f b7 00 89 85 64 fc ff ff c6 85 68 fc ff ff 00 8d 8d 64 fc ff ff ba [3] 00 8d 85 6c fc ff ff e8 [3] ff 50 68 02 00 00 80 e8 [3] ff 85 c0 0f 85 a3 00 00 00 33 c0 55 68 [3] 00 64 ff 30 64 89 20 c7 45 f8 00 02 00 00 8d 45 f8 50 8d 85 ec fc ff ff 50 6a 00 6a 00 68 [3] 00 8b 45 f4 50 e8 [3] ff 85 c0 75 4f 8d 85 60 fc ff ff 8d 95 ec fc ff ff b9 00 01 00 00 e8 [3] ff 8b 95 60 fc ff ff 8b 45 ec 8b 08 8b 45 fc 8b 40 44 8b 18 ff 53 40 8b 45 ec 8b 00 8b 55 fc 3b 42 4c 75 16 8b 45 fc 83 c0 48 8d 95 ec fc ff ff b9 00 01 00 00 e8 [3] ff 33 c0 5a 59 59 64 89 10 68 [3] 00 8b 45 f4 50 e8 [3] ff }
		$seq2 = { 55 8b ec 81 c4 e4 fd ff ff 53 8b da 89 45 fc 8b 45 fc e8 [2] ff ff 33 c0 55 68 [2] 40 00 64 ff 30 64 89 20 83 7d fc 00 75 15 68 05 01 00 00 8d 85 e6 fd ff ff 50 6a 00 e8 [2] ff ff eb 1a 8b 45 fc e8 [2] ff ff 8b c8 8d 85 e6 fd ff ff ba 05 01 00 00 e8 da f7 ff ff 66 83 bd e6 fd ff ff 00 0f 84 a7 01 00 00 33 c0 89 45 f8 8d 45 f4 50 68 19 00 0f 00 6a 00 68 [2] 40 00 68 01 00 00 80 e8 [2] ff ff 85 c0 0f 84 9a 00 00 00 8d 45 f4 50 68 19 00 0f 00 6a 00 68 [2] 40 00 68 02 00 00 80 e8 2b 5e ff ff 85 c0 74 7c 8d 45 f4 50 68 19 00 0f 00 6a 00 68 70 f6 40 00 68 01 00 00 80 e8 0d 5e ff ff 85 c0 74 5e 8d 45 f4 50 68 19 00 0f 00 6a 00 68 70 f6 40 00 68 02 00 00 80 e8 [2] ff ff 85 c0 74 40 8d 45 f4 50 68 19 00 0f 00 6a 00 68 [2] 40 00 68 01 00 00 80 e8 [2] ff ff 85 c0 74 22 8d 45 f4 50 68 19 00 0f 00 6a 00 68 [2] 40 00 68 01 00 00 80 e8 [2] ff ff 85 c0 0f 85 e6 00 00 00 33 c0 55 68 [2] 40 00 64 ff 30 64 89 20 8d 85 e6 fd ff ff ba 05 01 00 00 e8 c9 fc ff ff 8d 45 f0 50 6a 00 6a 00 6a 00 8d 85 e6 fd ff ff 50 8b 45 f4 50 e8 [2] ff ff 85 c0 75 33 8b 45 f0 e8 [2] ff ff 89 45 f8 8d 45 f0 50 8b 45 f8 50 6a 00 6a 00 8d 85 e6 fd ff ff 50 8b 45 f4 50 e8 [2] ff ff 8b c3 8b 55 f8 e8 [2] ff ff eb 4b 8d 45 f0 50 6a 00 6a 00 6a 00 68 [2] 40 00 8b 45 f4 50 e8 [2] ff ff 85 c0 75 2f 8b 45 f0 e8 [2] ff ff 89 45 f8 8d 45 f0 50 8b 45 f8 50 6a 00 6a 00 68 [2] 40 00 8b 45 f4 50 e8 [2] ff ff 8b c3 8b 55 f8 e8 [2] ff ff 33 c0 5a 59 59 64 89 10 68 [2] 40 00 83 7d f8 00 74 08 8b 45 f8 e8 [2] ff ff 8b 45 f4 50 e8 [2] ff ff }
		$seq3 = { d1 f8 79 03 83 d0 00 03 45 80 89 45 d0 8b 45 a4 8b 80 e4 02 00 00 8b 40 10 01 45 d0 8b 45 a4 8b 80 e4 02 00 00 8b 40 04 29 45 d0 8b 75 8c 2b 75 d4 83 ee 02 8b 45 a4 8b 80 e4 02 00 00 2b 70 08 8b 45 a4 8b 80 e4 02 00 00 2b 70 0c 89 75 8c 6a 00 56 8b 45 d0 50 8b 45 ec e8 [2] fb ff 50 57 8b 85 68 ff ff ff 50 e8 [2] fc ff 84 db 0f 84 0d 03 00 00 a1 [3] 00 8b 00 e8 [2] 09 00 50 8b 45 b4 50 6a 23 e8 [3] ff 89 45 d8 8b 45 d8 01 45 90 83 45 94 0f 83 45 90 05 8b 45 f0 8b 40 08 8b 50 74 }
		$s1 = "System\\CurrentControlSet\\Control\\Keyboard Layouts\\%.8x" fullword wide
		$s2 = { 45 00 72 00 72 00 6f 00 72 00 20 00 63 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 69 00 6e 00 67 00 20 00 74 00 6f 00 20 00 73 00 65 00 72 00 76 00 65 00 72 00 3a 00 20 00 25 00 73 }
		$s3 = { 45 00 72 00 72 00 6f 00 72 00 20 00 6f 00 70 00 65 00 6e 00 69 00 6e 00 67 00 20 00 72 00 65 00 71 00 75 00 65 00 73 00 74 00 3a 00 20 00 28 00 25 00 64 00 29 00 20 00 25 00 73 }
		$s4 = { 43 00 61 00 6e 00 6e 00 6f 00 74 00 20 00 6f 00 70 00 65 00 6e 00 20 00 66 00 69 00 6c 00 65 00 20 00 22 00 25 00 73 00 22 00 2e 00 20 00 25 00 73 }
		$s5 = { 43 00 61 00 6e 00 6e 00 6f 00 74 00 20 00 6f 00 70 00 65 00 6e 00 20 00 63 00 6c 00 69 00 70 00 62 00 6f 00 61 00 72 00 64 00 3a 00 20 00 25 00 73 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize > 500KB and 2 of ( $seq* ) and 3 of ( $s* )
}

rule ARKBIRD_SOLG_APT_Unknown_Middle_East_Feb_2020_1 : FILE
{
	meta:
		description = "Dectect unknown Middle East implants (retrohunt June 2020)"
		author = "Arkbird_SOLG"
		id = "e45675e6-29d5-587b-943e-19450772a092"
		date = "2021-03-05"
		modified = "2021-03-06"
		reference = "internal Research"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-03-06/Unknown/APT_Unknown_Middle_East_Feb_2020_1.yar#L1-L24"
		license_url = "N/A"
		logic_hash = "64cdac73bc3e29e8716cb24ae6577f853b2cf31303d129a0ec38ba89b7ff5351"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "274beb57ae19cbc5c2027e08cb2b718dea7ed1acb21bd329d5aba33231fb699d"
		hash2 = "3a4ef9b7bd7f61c75501262e8b9e31f9e9bc3a841d5de33dcdeb8aaa65e95f76"

	strings:
		$seq1 = { 55 8b ec 83 e4 f8 81 ec 08 04 00 00 a1 34 45 49 00 33 c4 89 84 24 04 04 00 00 83 ec 08 ba [2] 48 00 b9 ?? 82 48 00 68 [2] 48 00 e8 af 9f ff ff 83 c4 04 ba [2] 48 00 b9 ?? 82 48 00 68 [2] 48 00 e8 98 9f ff ff 83 c4 04 ba [2] 48 00 b9 ?? 82 48 00 68 [2] 48 00 e8 81 9f ff ff 83 c4 0c 8d 04 24 68 00 04 00 00 6a 00 50 e8 [2] 01 00 83 c4 0c 8d 04 24 [4] 00 68 00 02 00 00 50 e8 [2] 02 00 83 c4 0c 8d 04 24 68 ?? ab 49 00 68 00 02 00 00 50 e8 [2] 02 00 83 c4 0c 8d 04 24 68 ?? 6c 48 00 68 00 02 00 00 50 e8 [2] 02 00 83 c4 0c 8d 04 24 68 ?? a9 49 00 68 00 02 00 00 50 e8 [2] 02 00 83 c4 0c 8d 04 24 68 ?? 83 48 00 68 00 02 00 00 50 e8 [2] 02 00 83 c4 0c 33 c0 66 89 84 24 fe 03 00 00 8d 04 24 68 [2] 48 00 68 00 02 00 00 50 e8 [2] 02 00 83 c4 0c 8d 04 24 68 ?? a6 49 00 68 00 02 00 00 50 e8 [2] 02 00 83 c4 0c 8d 04 24 68 ?? 83 48 00 68 00 02 00 00 50 e8 [2] 02 00 8d 4c 24 0c e8 6b a1 ff ff 83 c4 04 ba [2] 48 00 b9 ?? 83 48 00 68 [2] 48 00 e8 94 9e ff ff 8b 8c 24 10 04 00 00 83 c4 0c 33 cc e8 [2] 01 00 8b e5 5d }
		$seq2 = { 55 8b ec 6a ff 68 [2] 47 00 64 a1 00 00 00 00 50 81 ec d8 00 00 00 a1 34 45 49 00 33 c5 89 45 f0 56 57 50 8d 45 f4 64 a3 00 00 00 00 8b 45 08 8b 75 14 c7 45 fc 00 00 00 00 89 85 34 ff ff ff 89 85 40 ff ff ff 33 c0 50 50 50 50 c7 85 3c ff ff ff 00 00 00 00 68 ?? 70 48 00 89 b5 6c ff ff ff c7 85 48 ff ff ff 00 00 00 00 c7 85 44 ff ff ff 00 00 00 00 89 85 50 ff ff ff ff 15 78 55 47 00 89 85 38 ff ff ff 85 c0 74 3f 6a 00 68 bb 01 00 00 68 ?? 6d 48 00 50 ff 15 8c 55 47 00 89 85 44 ff ff ff 85 c0 74 22 68 00 00 80 00 6a 00 6a 00 6a 00 68 ?? 71 48 00 68 ?? 6d 48 00 50 ff 15 90 55 47 00 89 85 50 ff ff ff 8b 3d 44 53 47 00 6a 00 6a 00 6a 00 6a 00 6a ff 56 6a 00 68 e9 fd 00 00 ff d7 8b f0 56 e8 ?? 35 01 00 83 c4 04 89 85 4c ff ff ff 6a 00 6a 00 56 50 6a ff ff b5 6c ff ff ff 6a 00 68 e9 fd 00 00 ff d7 68 80 00 00 00 8b f8 8d 85 70 ff ff ff 6a 00 50 e8 [2] 02 00 57 8d 85 70 ff ff ff 68 ?? 79 48 00 50 e8 ?? a3 00 00 83 c4 18 c7 85 64 ff ff ff 00 00 00 00 33 c0 c7 85 68 ff ff ff 07 00 00 00 8d 8d 54 ff ff ff 66 89 85 54 ff ff ff 6a 10 68 [2] 48 00 e8 ?? 84 00 00 8d 8d 70 ff ff ff c7 45 fc 01 00 00 00 8d 51 02 66 8b 01 83 c1 02 66 85 c0 75 f5 2b ca 8d 85 70 ff ff ff d1 f9 51 50 8d 8d 54 ff ff ff e8 89 63 00 00 6a 33 68 ?? 71 48 00 8d 8d 54 ff ff ff e8 77 63 00 00 8b b5 50 ff ff ff 85 f6 }
		$s1 = "taskkill /im svehost.exe /t /f" fullword ascii
		$s2 = "\\AppData\\Windows\\svehost.exe" fullword ascii
		$s3 = "svehost.exe" fullword wide
		$s4 = "bdagent.exe" fullword wide
		$s5 = "taskkill /im keepass.exe /t /f" fullword ascii
		$s6 = "%s\\AppData\\Windows\\svehost" fullword ascii
		$s7 = "\\AppData\\Roaming\\ViberPc" fullword wide
		$s8 = "\\AppData\\Roaming\\Skype" fullword wide

	condition:
		uint16( 0 ) == 0x5a4d and filesize > 200KB and 1 of ( $seq* ) and 4 of ( $s* )
}

rule ARKBIRD_SOLG_APT_Puzzlemaker_Implant_Jun_2021_1 : FILE
{
	meta:
		description = "Detect the implant of the PuzzleMaker group"
		author = "Arkbird_SOLG"
		id = "9387130c-4474-55bf-9736-09494a5e81b8"
		date = "2021-06-10"
		modified = "2021-11-01"
		reference = "https://securelist.com/puzzlemaker-chrome-zero-day-exploit-chain/102771/"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-06-09/PuzzleMaker/APT_PuzzleMaker_Implant_Jun_2021_1.yara#L1-L21"
		license_url = "N/A"
		logic_hash = "e54eaaa76b2d370a27a232dee2299266f8b3b82d53da36e35c2a6fcdd7d5b1f7"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "8a17279ba26c8fbe6966ea3300fdefb1adae1b3ed68f76a7fc81413bd8c1a5f6"
		hash2 = "1ee9bb4e8bcabe197399b654dbf940438b120af1c376719ff9bdccf2bb1dc606"
		hash3 = "f2ce2a00de8673f52d37911f3e0752b8dfab751b2a17e719a565b4083455528e"
		tlp = "White"
		adversary = "PuzzleMaker"

	strings:
		$s1 = { 4c 8d 4c 24 5c 49 8b ce 48 8d 95 c0 00 00 00 ff 15 21 01 04 00 85 c0 74 28 4c 8d 4c 24 58 4c 89 64 24 20 41 b8 00 04 00 00 48 8d 95 c0 04 00 00 49 8b cf ff 15 b5 fe 03 00 85 c0 0f 85 25 ff ff ff ff 15 77 fe 03 00 8b }
		$s2 = { 40 55 53 56 41 55 41 57 48 8d ac 24 a0 fe ff ff 48 81 ec 60 02 00 00 48 8b 05 5a 1c 03 00 48 33 c4 48 89 85 30 01 00 00 48 8b 85 b0 01 00 00 4c 8b f9 48 8b b1 b8 00 00 00 4c 8b ad c8 01 00 00 48 83 c6 07 48 89 44 24 60 48 8b 85 d0 01 00 00 48 89 45 98 8b 85 c0 01 00 00 83 c0 fd 48 c1 ee 03 4c 89 4d 80 4c 89 45 88 48 89 55 90 83 f8 06 0f 87 84 03 00 00 48 8d 15 f3 6b fd ff 48 98 8b 8c 82 b0 97 02 00 48 }
		$s3 = { 48 8d 1d 98 3d 02 00 0f 57 c0 48 89 bc 24 58 02 00 00 33 c0 c7 44 24 68 01 00 00 00 0f 11 85 80 00 00 00 4c 8b c6 c7 85 8c 00 00 00 10 27 00 00 48 8d 95 a0 00 00 00 48 89 44 24 70 49 8b c9 48 89 44 24 78 0f 11 45 20 0f 11 45 30 0f 11 45 40 0f 11 45 50 0f 11 45 60 0f 11 45 70 0f 11 85 90 00 00 00 e8 57 58 fe ff 8b f8 85 c0 0f 85 62 02 00 00 49 8b 87 b8 00 00 00 48 8d 4c 24 68 48 8b 54 24 60 48 83 c0 07 48 c1 e8 03 4c 89 a4 24 50 02 00 00 4c 8b a5 b8 01 00 00 4c 3b e0 4c 89 b4 24 48 02 00 00 4d 8b f4 4c 0f 47 f0 4d 8b c6 e8 1b 57 fe ff 8b f8 85 c0 75 54 49 8b 87 b8 00 00 00 4a 8d 14 f5 00 00 00 00 48 }
		$s4 = { 85 ff 0f 85 cd 01 00 00 48 8b 4d 90 48 8d 45 a0 48 89 44 24 50 45 33 c9 48 8d 45 d0 4d 8b c7 48 89 44 24 48 33 d2 4c 89 64 24 40 4c 89 64 24 38 c7 44 24 30 00 00 00 08 c7 44 24 28 01 00 00 00 4c 89 64 24 20 ff 15 62 1c 04 00 85 c0 75 3a ff 15 38 1d 04 00 44 8b c3 48 8b ce 8b d0 8b f8 e8 d1 09 00 00 48 8b 4d 80 ff 15 07 1d 04 00 48 8b 4d 88 ff 15 fd 1c 04 00 48 8b 4d 90 ff 15 f3 1c 04 00 }
		$s5 = { 40 53 55 56 57 41 54 41 55 41 56 41 57 48 81 ec 28 02 00 00 48 8b 05 5d 0a 04 00 48 33 c4 48 89 84 24 10 02 00 00 48 8b ac 24 90 02 00 00 0f 57 c0 4c 8b ac 24 98 02 00 00 33 db 45 32 e4 4c 89 4c 24 58 4c 89 44 24 70 49 8b f9 48 89 6c 24 68 4d 8b c8 4c 89 6c 24 60 4c 8b fa 48 8b f1 44 8b f3 0f 11 84 24 e0 00 00 00 c7 84 24 ec 00 00 00 10 27 00 00 0f 11 84 24 80 00 00 00 0f 11 84 24 90 00 00 00 0f 11 84 24 a0 00 00 00 0f 11 84 24 b0 00 00 00 0f 11 84 24 c0 00 00 00 0f 11 84 24 d0 00 00 00 0f 11 84 24 f0 00 00 00 48 85 ed 75 47 4c 8b 81 b8 00 00 00 48 8d 05 a1 c2 ff ff 48 89 44 24 68 48 8d 8c 24 80 00 00 00 49 83 c0 07 48 8d 84 24 80 00 00 00 49 c1 e8 03 49 8b d1 48 89 44 24 60 e8 87 c2 ff ff 8b f8 85 c0 0f 85 ee 01 00 00 48 8b 7c 24 58 48 8d 56 68 48 8d 4f 18 e8 7b 4a ff ff 85 c0 75 15 48 8d 56 50 48 8b cf e8 6b 4a ff ff 85 c0 75 05 40 b5 }
		$s6 = { 41 b9 01 00 00 00 c7 44 24 20 00 00 00 f0 45 33 c0 48 8d 4c 24 60 33 d2 ff 15 11 06 04 00 85 c0 74 28 48 8b 4c 24 60 4c 8d 85 b0 00 00 00 ba 20 00 00 00 ff 15 ee 05 04 00 48 8b 4c 24 60 33 d2 85 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize > 80KB and 5 of ( $s* )
}

rule ARKBIRD_SOLG_APT_Puzzlemaker_Launcher_Jun_2021_1 : FILE
{
	meta:
		description = "Detect the launcher of the PuzzleMaker group"
		author = "Arkbird_SOLG"
		id = "ae31d9de-8e6c-5c1b-bc45-bc4e50cea00f"
		date = "2021-06-10"
		modified = "2021-11-01"
		reference = "https://securelist.com/puzzlemaker-chrome-zero-day-exploit-chain/102771/"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-06-09/PuzzleMaker/APT_PuzzleMaker_Launcher_Jun_2021_1.yara#L1-L19"
		license_url = "N/A"
		logic_hash = "5c717ca5c57a86e1b5db45b3d581a45be248d45820c00c40c57a001ac07ce1b2"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "982f7c4700c75b81833d5d59ad29147c392b20c760fe36b200b541a0f841c8a9"
		tlp = "White"
		adversary = "PuzzleMaker"

	strings:
		$s1 = { 4c 89 6d bf 48 8d 45 bf 48 89 44 24 20 4c 8d 0d f9 45 01 00 33 d2 44 8d 42 01 48 8d 0d dc 45 01 00 ff 15 56 44 01 00 8b d8 85 c0 78 c6 4c 89 6d c7 48 8b 45 bf 48 8b 08 4c 8b 79 18 b9 18 00 00 00 e8 9b 04 00 00 48 8b d8 48 89 45 a7 48 85 c0 74 32 0f 57 c0 33 c0 0f 11 03 48 89 43 10 4c 89 6b 08 c7 43 10 01 00 00 00 48 8d 0d 15 fb 01 00 ff 15 cf 43 01 00 48 89 03 48 85 }
		$s2 = { 44 89 6c 24 38 4c 89 6c 24 30 c7 44 24 28 03 00 00 00 c7 44 24 20 03 00 00 00 45 33 c9 45 33 c0 41 8d 51 0a 48 8b 4d c7 ff 15 f6 42 01 00 85 c0 0f 88 bb 01 00 00 48 8d 0d 1d fa 01 00 ff 15 c1 42 01 00 4c 8b f8 48 8d 0d 1b fa 01 00 ff 15 b1 42 01 00 4c 8b e0 4c 89 6d df 48 8b 4d c7 48 8b 11 4c 8b 52 30 4c 89 6c 24 28 48 8d 45 df 48 89 44 24 20 45 33 c9 45 33 c0 49 8b d4 41 ff d2 4c 89 6d e7 48 8b 4d df 48 8b 01 4c 89 6c 24 20 4c 8d 4d e7 45 33 c0 49 8b d7 ff 90 98 00 00 00 4c 89 6d cf 48 8b 4d e7 48 8b 01 4c 8d 45 cf 33 d2 ff 50 78 b8 08 00 00 00 66 89 45 ef 8d 48 10 e8 dc 02 00 00 48 8b d8 48 89 45 a7 48 85 c0 74 33 0f 57 c0 33 c0 0f 11 03 48 89 43 10 4c 89 6b 08 c7 43 10 01 00 00 00 48 8b ce ff 15 14 42 01 00 48 89 03 48 85 c0 75 0e 48 85 }
		$s3 = { 4c 8d 05 75 0e 02 00 0f 1f 40 00 66 0f 1f 84 00 00 00 00 00 0f b6 d0 42 0f b6 0c 12 66 41 31 08 74 12 ff c0 49 83 c0 02 83 f8 20 72 e7 0f 1f 80 00 00 00 00 0f b7 05 49 09 02 00 48 8d 0d 76 09 02 00 66 d1 e8 66 83 e0 7f 66 0f 6f 15 f3 d4 01 00 66 89 05 2c 09 02 00 0f b7 05 27 09 02 00 66 d1 e8 66 83 e0 7f 66 89 05 19 09 02 00 0f b7 05 14 09 02 00 66 d1 e8 66 83 e0 7f 66 89 05 06 09 02 00 0f b7 05 01 09 02 00 66 d1 e8 66 83 e0 7f 66 89 05 f3 08 02 00 0f b7 05 ee 08 02 00 66 d1 e8 66 83 e0 7f 66 89 05 e0 08 02 00 0f b7 05 db 08 02 00 66 d1 e8 66 83 e0 7f 66 89 05 cd 08 02 00 0f b7 05 c8 08 02 00 66 d1 e8 66 83 e0 7f 66 89 05 ba 08 02 00 0f b7 05 b5 08 02 00 66 d1 e8 66 83 e0 7f f3 0f 6f 05 bc 08 02 00 66 89 05 9f 08 02 00 0f b7 05 9a 08 02 00 66 d1 e8 66 83 e0 7f 66 89 05 8c 08 02 00 0f b7 05 87 08 02 00 66 d1 e8 66 83 e0 7f 66 89 05 79 08 02 00 0f b7 05 74 08 02 00 66 d1 e8 66 83 e0 7f 66 89 05 66 08 02 00 0f b7 05 61 08 02 00 66 d1 e8 66 83 e0 7f 66 89 05 53 08 02 00 0f b7 05 4e 08 02 00 66 d1 e8 66 83 e0 7f 66 89 05 40 08 02 00 0f b7 05 3b 08 02 00 66 d1 e8 66 83 e0 7f 66 89 05 2d 08 02 00 0f b7 05 28 08 02 00 66 d1 e8 66 83 e0 7f 66 89 05 1a 08 02 00 0f b7 05 15 08 02 00 66 d1 e8 66 83 e0 7f 66 89 05 07 08 02 00 0f b7 05 02 08 02 00 66 d1 e8 66 83 e0 7f 66 89 05 f4 07 02 00 0f b7 05 ef 07 02 00 66 d1 e8 66 83 e0 7f 66 89 05 e1 07 02 00 b8 01 00 00 00 66 0f 6e c8 8d 50 05 66 0f d1 c1 66 0f db c2 f3 0f 7f 05 c7 07 02 00 0f }
		$s4 = { 48 89 9c 24 60 06 00 00 48 89 b4 24 68 06 00 00 48 89 bc 24 70 06 00 00 4c 89 b4 24 30 06 00 00 c7 05 2e 1a 02 00 04 00 00 00 48 c7 05 27 1a 02 00 01 00 00 00 4c 89 2d 2c 1a 02 00 ff 15 22 48 01 00 48 8d 35 8b 04 02 00 66 66 66 0f 1f 84 00 00 00 00 00 33 d2 44 89 6c 24 70 41 b8 08 03 00 00 48 8d 8d 10 02 00 00 45 8b f5 e8 e4 28 00 00 4c 8d 0d 5d 03 02 00 48 89 74 24 20 ba 84 01 00 00 48 8d 8d 10 02 00 00 49 c7 c0 ff ff ff ff e8 a0 fb ff ff 48 8d 54 24 70 48 8d 8d 10 02 00 00 e8 9f 05 00 00 8b d0 85 }
		$s5 = { 4c 89 6c 24 60 4c 8d 05 25 cc 01 00 4c 89 6c 24 58 48 8d 15 e1 04 02 00 4c 89 6c 24 50 41 b9 ff 01 0f 00 4c 89 6c 24 48 48 8b cf 4c 89 6c 24 40 48 89 74 24 38 44 89 6c 24 30 c7 44 24 28 02 00 00 00 c7 44 24 20 10 00 00 00 ff 15 19 46 01 00 48 8b d8 ff 15 a8 46 01 00 8b f0 48 85 db 74 22 48 8b cb ff 15 20 46 01 00 48 8b cb ff 15 ff 45 01 00 48 8b cf ff 15 f6 45 01 00 bf 01 00 00 }
		$s6 = { 33 d2 33 c9 41 b8 3f 00 0f 00 ff 15 f4 46 01 00 48 8b f8 48 85 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize > 80KB and 5 of ( $s* )
}

rule ARKBIRD_SOLG_APT_Gelsemium_Gelsenicine_June_2021_2 : FILE
{
	meta:
		description = "Detect Gelsenicine malware (Loader - Variant 2)"
		author = "Arkbird_SOLG"
		id = "c6e28da2-622b-57ba-9381-9f8f6b8879bf"
		date = "2021-06-12"
		modified = "2021-06-14"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2021/06/eset_gelsemium.pdf"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-06-13/Gelsemium/APT_Gelsemium_Gelsenicine_June_2021_2.yara#L1-L19"
		license_url = "N/A"
		logic_hash = "e1d6402c743af697c8d1b34087b6fe9db80237834d73967b0a0638023d4e4a40"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "6eaeca0cf28e74de6cfd82d29a3c3cc30c2bc153ac811692cc41ee290d766474"
		hash1 = "d986207bc108e55f4b110ae208656b415d2c5fcc8f99f98b4b3985e82b9d5e5b"
		hash1 = "ec491de0e2247f64b753c4ef0c7227ea3548c2f222b547528dae0cf138eca53a"
		tlp = "white"
		adversary = "Gelsemium"

	strings:
		$s1 = { 48 53 48 83 ec 30 48 c7 44 24 20 fe ff ff ff 48 8b d9 c7 44 24 40 00 00 00 00 8b 05 [3] 00 a8 01 0f 85 96 00 00 00 83 c8 01 89 05 [3] 00 33 c0 88 44 24 40 4c 8d 44 24 40 48 8d 15 [3] 00 48 8d 0d [3] 00 ff 15 [2] 00 00 90 33 c0 88 44 24 48 4c 8d 44 24 48 48 8d 15 [3] 00 48 8d 0d [3] 00 ff 15 [2] 00 00 90 33 c0 88 44 24 40 4c 8d 44 24 40 48 8d 15 [3] 00 48 8d 0d [3] 00 ff 15 [2] 00 00 90 33 c0 88 44 24 48 4c 8d 44 24 48 48 8d 15 [3] 00 48 8d 0d [3] 00 ff 15 [2] 00 00 90 48 8d 0d [2] 00 00 e8 [2] 00 00 90 48 c7 43 08 00 00 00 00 48 c7 43 10 00 00 00 00 48 c7 43 18 00 00 00 00 4c 8d 0d [3] 00 4c 8d 05 [3] 00 33 d2 48 8b cb e8 86 f9 ff ff 48 8b c3 48 83 c4 30 }
		$s2 = { 54 00 65 00 6d 00 70 00 2f 00 00 00 00 00 00 00 43 00 6f 00 6d 00 6d 00 6f 00 6e 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 2f 00 00 00 00 00 53 00 79 00 73 00 74 00 65 00 6d 00 2f 00 00 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 2f }
		$s3 = { 48 8b ca e8 [3] 00 48 39 5e 08 75 05 48 8b c3 eb 08 48 8b 46 10 48 2b 46 08 3b c3 0f 4c c3 48 63 c8 e8 [3] 00 48 89 47 08 48 8b 56 10 48 8b 4e 08 4c 8b d8 eb 10 4c 3b db 74 05 8a 01 41 88 03 49 ff c3 48 ff c1 48 3b ca 75 eb 4c 89 5f 10 4c 89 5f 18 48 8b c7 48 83 c4 20 5f 5e }
		$s4 = { 45 33 c9 45 33 c0 ba 80 00 00 00 48 8b ce e8 16 f2 ff ff 84 c0 74 71 48 8d 53 18 41 b8 20 00 00 00 48 8b ce e8 e4 f4 ff ff 84 c0 74 5b 48 8d 53 38 41 b8 20 00 00 00 48 8b ce e8 56 f9 ff ff 84 c0 74 45 48 8b 43 10 48 8b 0d [3] 00 48 3b c1 74 0d 48 8b d8 48 8b 00 48 3b c1 75 f5 eb 1b 48 8b 43 08 eb 07 48 8b d8 48 8b 40 08 48 3b 58 10 74 f3 48 39 43 10 48 0f }

	condition:
		uint16( 0 ) == 0x5a4d and filesize > 30KB and 3 of ( $s* )
}

rule ARKBIRD_SOLG_APT_Gelsemium_Gelsenicine_June_2021_1 : FILE
{
	meta:
		description = "Detect Gelsenicine malware (Loader - Variant 1)"
		author = "Arkbird_SOLG"
		id = "36276150-a5dd-5385-9e50-958a6fa54de5"
		date = "2021-06-12"
		modified = "2021-06-14"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2021/06/eset_gelsemium.pdf"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-06-13/Gelsemium/APT_Gelsemium_Gelsenicine_June_2021_1.yara#L1-L19"
		license_url = "N/A"
		logic_hash = "66d9fad7105b46a55db11c5224b1a395793f2dee89f779d59c80b2f7cda5a115"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "97982e098a4538d05e78c172c9bbc5b412754df86dc73e760004f0038ec928fb"
		hash2 = "46338cae732ee1664aac77d9dce57c4ff8666460c1a51bee49cae44c86e42df9"
		hash3 = "f0d23aa026ae6ba96051401dc2b390ba5c968d55c2a4b31a36e45fb67dfc2e3c"
		tlp = "white"
		adversary = "Gelsemium"

	strings:
		$s1 = { b8 [3] 74 e8 [2] 00 00 81 ec bc 03 00 00 53 56 57 be [3] 74 8d bd 38 fc ff ff 6a 1b a5 a5 a5 a5 66 a5 59 33 c0 8d bd 4a fc ff ff be [3] 74 f3 ab 66 ab 8d bd b8 fc ff ff 6a 1c a5 a5 a5 a5 59 33 c0 8d bd c8 fc ff ff 6a 07 f3 ab 59 be [3] 74 8d bd 38 fd ff ff 6a 18 f3 a5 66 a5 8b 5d 0c 59 8d bd 56 fd ff ff 83 65 cc 00 f3 ab 66 ab 8a 03 6a 00 8d 4d e0 c7 45 c0 24 00 00 00 c7 45 c4 25 00 00 00 c7 45 c8 23 00 00 00 88 45 e0 ff 15 [3] 74 a1 [3] 74 8d 4d e0 ff 30 6a 00 53 ff 15 [3] 74 8a 45 0f 6a 00 8d 4d d0 c7 45 fc 01 00 00 00 88 45 d0 ff 15 [3] 74 8b 35 [3] 74 bf [3] 74 57 ff d6 59 50 57 8d 4d d0 ff 15 [3] 74 8b 55 d4 8b 0d [3] 74 85 d2 c6 45 fc 02 75 02 8b d1 8b 43 04 85 c0 75 02 8b c1 ff 75 d8 52 50 ff 15 [3] 74 83 c4 0c 85 c0 0f 85 d9 00 00 00 8d 85 b8 fd ff ff 50 68 04 01 00 00 ff 15 [3] 74 8d 85 b8 fd ff ff 50 ff d6 85 c0 59 0f 84 b5 00 00 00 8d 85 b8 fd ff ff 50 ff d6 66 83 bc 45 b6 fd ff ff 2f 59 74 56 8d 85 b8 fd ff ff 50 ff d6 66 83 bc 45 b6 fd ff ff 5c 59 74 41 8d 4d e0 ff 15 [3] 74 8b 7d e4 8b 5d d8 8d 4d e0 ff 15 [3] 74 8b 45 e4 89 45 f0 8d 85 b8 fd ff ff 50 ff d6 59 8d 84 45 b8 fd ff ff 50 8d 85 b8 fd ff ff 50 8d 44 5f fe 50 ff }
		$s2 = { ff 75 0c 89 45 f0 ff d6 50 ff 75 0c ff 75 f0 ff 15 [3] 74 83 c4 10 85 c0 }
		$s3 = "pluginkey" fullword wide
		$s4 = { 55 8b ec 51 33 c0 56 f6 05 [3] 74 01 89 45 fc 0f 85 c6 00 00 00 8a 4d 0b 80 0d [3] 74 01 53 bb [3] 74 57 88 0d [3] 74 50 8b cb ff 15 [3] 74 8b 35 [3] 74 bf [3] 74 57 ff d6 59 50 57 8b cb ff 15 [3] 74 8a 45 0b bb [3] 74 6a 00 8b cb a2 [3] 74 ff 15 [3] 74 bf [3] 74 57 ff d6 59 50 57 8b cb ff 15 [3] 74 8a 45 0b bb [3] 74 6a 00 8b cb a2 [3] 74 ff 15 [3] 74 bf [3] 74 57 ff d6 59 50 57 8b cb ff 15 [3] 74 8a 45 0b bb [3] 74 6a 00 8b cb a2 [3] 74 ff 15 [3] 74 bf [3] 74 57 ff d6 59 50 57 8b cb ff 15 [3] 74 68 [2] e2 74 e8 [2] 00 00 59 5f 33 c0 5b 8b 75 08 8a 4d 0b 68 [3] 74 68 [3] 74 88 0e 50 8b ce 89 46 04 89 46 08 89 46 0c e8 [2] 00 00 8b c6 5e }

	condition:
		uint16( 0 ) == 0x5a4d and filesize > 15KB and 3 of ( $s* )
}

rule ARKBIRD_SOLG_APT_Gelsemium_Gelsemine_June_2021_1 : FILE
{
	meta:
		description = "Detect Gelsemine malware (Dropper - Variant 1)"
		author = "Arkbird_SOLG"
		id = "cfe932fd-ff50-5e54-824c-e11afe8e8575"
		date = "2021-06-12"
		modified = "2021-06-14"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2021/06/eset_gelsemium.pdf"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-06-13/Gelsemium/APT_Gelsemium_Gelsemine_June_2021_1.yara#L1-L19"
		license_url = "N/A"
		logic_hash = "2b5031412de163ad92dfe00c7da331eb36c4ce7b590df48dfa84df0104e93b15"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "00b701e3ef29912c1fcd8c2154c4ae372cfe542cfa54ffcce9fb449883097cec"
		hash2 = "109d4b8878b8c8f3b7015f6b3ae573a6799296becce0f32ca3bd216bee0ab473"
		hash3 = "fe71b66d65d5ff9d03a47197c99081d9ec8d5f6e95143bdc33f5ea2ac0ae5762"
		hash3 = "29e78ca3cb49dd2985a29e74cafb1a0a15515670da0f4881f6095fb2926bfefd"
		tlp = "white"
		adversary = "Gelsemium"

	strings:
		$s1 = { 8b 44 24 04 83 ec 40 85 c0 53 55 56 57 0f 84 ec 15 00 00 8b 58 1c 85 db 0f 84 e1 15 00 00 8b 48 0c 85 c9 0f 84 d6 15 00 00 83 38 00 75 0b 8b 48 04 85 c9 0f 85 c6 15 00 00 83 3b 0b 75 06 c7 03 0c 00 00 00 8b 48 0c 8b 30 8b 78 04 8b 53 38 8b 6b 3c 89 4c 24 28 8b 48 10 8b 03 83 f8 1e 89 4c 24 20 89 74 24 14 89 7c 24 18 89 54 24 10 89 7c 24 38 89 4c 24 2c c7 44 24 34 00 00 00 }
		$s2 = { 33 c0 33 d2 8a 06 8a 56 01 03 c8 33 c0 8a 46 02 03 f9 03 ca 33 d2 8a 56 03 03 f9 03 c8 33 c0 8a 46 04 03 f9 03 ca 33 d2 8a 56 05 03 f9 03 c8 33 c0 8a 46 06 03 f9 03 ca 33 d2 8a 56 07 03 f9 03 c8 33 c0 8a 46 08 03 f9 03 ca 33 d2 8a 56 09 03 f9 03 c8 33 c0 8a 46 0a 03 f9 03 ca 33 d2 8a 56 0b 03 f9 03 c8 33 c0 8a 46 0c 03 f9 03 ca 33 d2 8a 56 0d 03 f9 03 c8 33 c0 8a 46 0e 03 f9 03 ca 33 d2 8a 56 0f 03 f9 03 c8 83 c6 10 03 f9 03 ca 03 f9 4d 0f 85 67 ff ff ff 8b c1 33 d2 b9 f1 ff 00 00 f7 f1 8b c7 bf f1 ff 00 00 8b ca 33 d2 f7 f7 ff 4c 24 18 8b fa 0f 85 38 ff ff ff 85 db 0f 84 da 00 00 00 83 fb 10 0f 82 a1 00 00 00 8b eb c1 ed 04 33 d2 33 c0 8a 16 8a 46 01 03 ca 33 d2 8a 56 02 03 f9 03 c8 33 c0 8a 46 03 03 f9 03 ca 33 d2 8a 56 04 03 f9 03 c8 33 c0 8a 46 05 03 f9 03 ca 33 d2 8a 56 06 03 f9 03 c8 33 c0 8a 46 07 03 f9 03 ca 33 d2 8a 56 08 03 f9 03 c8 33 c0 8a 46 09 03 f9 03 ca 33 d2 8a 56 0a 03 f9 03 c8 33 c0 8a 46 0b 03 f9 03 ca 33 d2 8a 56 0c 03 f9 03 c8 33 c0 8a 46 0d 03 f9 03 ca 33 d2 8a 56 0e 03 f9 03 c8 33 c0 8a 46 0f 03 f9 03 ca 83 eb 10 03 f9 03 c8 03 f9 83 c6 10 }
		$s3 = { 55 8b ec 6a ff 68 [2] 40 00 68 [2] 40 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 68 53 56 57 89 65 e8 33 db 89 5d fc 6a 02 5f 57 ff 15 [2] 40 00 59 83 0d [2] 41 00 ff 83 0d [2] 41 00 ff ff 15 [2] 40 00 8b 0d [2] 41 00 89 08 ff 15 [2] 40 00 8b 0d [2] 41 00 89 08 a1 [2] 40 00 8b 00 a3 [2] 41 00 e8 ?? 01 00 00 39 1d [3] 00 75 0c 68 [2] 40 00 ff 15 [2] 40 00 59 e8 ?? 01 00 00 68 [3] 00 68 [3] 00 e8 ?? 01 00 00 a1 [2] 41 00 89 45 94 8d 45 94 50 ff 35 [2] 41 00 8d 45 9c 50 8d 45 90 50 8d 45 a0 50 ff 15 [2] 40 00 68 [3] 00 68 00 [2] 00 e8 ?? 01 00 00 83 c4 24 a1 [2] 40 00 8b 30 3b }

	condition:
		uint16( 0 ) == 0x5a4d and filesize > 150KB and all of ( $s* )
}

rule ARKBIRD_SOLG_APT_Gelsemium_Gelsevirine_June_2021_1 : FILE
{
	meta:
		description = "Detect Gelsevirine malware (Main Plug-in)"
		author = "Arkbird_SOLG"
		id = "31900186-2531-5558-aafb-67707040ddaf"
		date = "2021-06-12"
		modified = "2021-06-14"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2021/06/eset_gelsemium.pdf"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-06-13/Gelsemium/APT_Gelsemium_Gelsevirine_June_2021_1.yara#L1-L18"
		license_url = "N/A"
		logic_hash = "06e7ee49092621c8469eeb1cd9e5cc1420a1879084e0d0a39181dc046bfa00cf"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "1a9d78e5c255de239fb18b2cf47c4c2298f047073299c27fb54a0edf08a1d5a1"
		hash1 = "51b9296ff1f562350cd63abd22c6032ef26d5ae6a3e2e5e0f851d8b1a5d0ee35"
		tlp = "white"
		adversary = "Gelsemium"

	strings:
		$s1 = { 48 8b c4 55 41 56 41 57 48 8d a8 38 fa ff ff 48 81 ec b0 06 00 00 48 c7 85 a0 02 00 00 fe ff ff ff 48 89 58 08 48 89 70 10 48 89 78 18 4c 89 60 20 48 8b 05 68 bf 0b 00 48 33 c4 48 89 85 a0 05 00 00 45 33 e4 4c 89 65 08 4c 89 65 10 44 89 64 24 20 48 8d 54 24 20 48 8d 4d 08 e8 30 96 01 00 90 48 c7 85 f8 00 00 00 07 00 00 00 4c 89 a5 f0 00 00 00 66 44 89 a5 e0 00 00 00 45 8d 44 24 04 48 8d 15 79 d8 08 00 48 8d 8d e0 00 00 00 e8 dd b0 00 00 90 48 8d 8d e0 00 00 00 e8 50 30 ff ff 90 48 83 bd f8 00 00 00 08 72 0d 48 8b 8d e0 00 00 00 ff 15 b0 32 06 00 48 c7 85 b8 01 00 00 07 00 00 00 4c 89 a5 b0 01 00 00 66 44 89 a5 a0 01 00 00 41 b8 10 00 00 00 48 8d 15 61 d6 08 00 48 8d 8d a0 01 00 00 e8 85 b0 00 00 90 48 8d 95 a0 01 00 00 48 8d 8d 80 05 00 00 e8 41 96 01 00 90 48 83 bd b8 01 00 00 08 72 0d 48 8b 8d a0 01 00 00 ff 15 51 32 06 00 48 c7 85 68 04 00 00 07 00 00 00 4c 89 a5 60 04 00 00 66 44 89 a5 50 04 00 00 48 c7 85 78 01 00 00 07 00 00 00 4c 89 a5 70 01 00 00 66 44 89 a5 60 01 00 00 49 83 ce ff 4d 8b ce 45 33 c0 48 8d 95 80 05 00 00 48 8d 8d 60 01 00 00 e8 c8 ae 00 00 90 48 8d 95 60 01 00 00 48 8d 8d e0 01 00 00 e8 e4 5b ff ff 90 48 8d 8d 50 04 00 00 48 3b c8 74 15 4d 8b ce 45 33 c0 48 8b d0 48 8d 8d 50 04 00 00 e8 92 ae 00 00 48 8d 8d 50 04 00 00 e8 b6 11 ff ff 90 48 83 bd f8 01 00 00 08 72 0d 48 8b 8d e0 01 00 00 ff 15 a6 31 06 00 48 c7 85 f8 01 00 00 07 00 00 00 4c 89 a5 f0 01 00 00 66 44 89 a5 e0 01 00 00 48 83 bd 78 01 00 00 08 72 0d 48 8b 8d 60 01 00 00 ff 15 75 31 06 00 33 d2 48 8d 8d 50 04 00 00 e8 5f 2b 04 00 48 c7 85 58 01 00 00 07 00 00 00 4c 89 a5 50 01 00 00 66 44 89 a5 40 01 00 00 41 b8 0d 00 00 00 48 8d 15 b8 e2 08 00 48 8d 8d 40 01 00 00 e8 3c af 00 00 90 e8 96 2d ff ff 48 8d 48 30 48 8d 95 40 01 00 00 e8 b6 77 00 00 48 8b c8 e8 fe dc 02 00 48 8b c8 e8 16 d5 ff ff 90 48 83 bd 58 01 00 00 08 72 0d 48 8b 8d 40 01 00 00 ff 15 f6 30 06 00 48 c7 85 18 01 00 00 07 00 00 00 4c 89 a5 10 01 00 00 66 44 89 a5 00 01 00 00 41 b8 24 00 00 00 48 8d 15 d7 e3 08 00 48 8d 8d 00 01 00 00 e8 cb ae 00 00 90 48 8d 8d 00 01 00 00 e8 ce 6b 00 00 84 c0 0f 94 c3 48 83 bd 18 01 00 00 08 72 0d 48 8b 8d 00 01 00 00 ff 15 9a 30 06 00 84 db 0f 84 36 08 00 00 4c 89 a5 88 04 00 00 4c 89 a5 90 04 00 00 e8 f7 3b 01 00 48 89 85 88 04 00 00 48 c7 45 50 07 00 00 00 4c 89 65 48 66 44 89 65 38 41 b8 0b 00 00 00 48 8d 15 2a d6 08 00 48 8d 4d 38 e8 59 ae 00 00 90 e8 b3 2c ff ff 48 8d 48 30 48 8d 55 38 e8 96 75 00 00 48 c7 85 b0 04 00 00 07 00 00 00 4c 89 a5 a8 04 00 00 66 44 89 a5 98 04 00 00 4d 8b ce 45 33 c0 48 8b d0 48 8d 8d 98 04 00 00 e8 d7 ac 00 00 90 48 83 7d 50 08 72 0a 48 8b 4d 38 ff 15 fd 2f 06 00 48 c7 45 50 07 00 00 00 4c 89 65 48 66 44 89 65 38 4c 89 a5 b8 04 00 00 4c 89 a5 c0 04 00 00 4c 89 a5 c8 04 00 00 48 c7 45 00 07 00 00 00 4c 89 65 f8 66 44 89 65 e8 41 b8 01 00 00 00 48 8d 15 0d e3 08 00 48 8d 4d e8 e8 b8 ad 00 00 90 48 c7 45 c0 07 00 00 00 4c 89 65 b8 66 44 89 65 a8 41 b8 0d 00 00 00 48 8d 15 e9 e2 08 00 48 8d 4d a8 e8 90 ad 00 00 90 e8 ea 2b ff ff 48 8d 48 30 48 8d 55 a8 e8 cd 74 00 00 48 8b d0 4c 8d 45 e8 48 8d 8d b8 04 00 00 e8 1a 55 01 00 90 48 83 7d c0 08 72 0a 48 8b 4d a8 ff 15 50 2f 06 00 48 c7 45 c0 07 00 00 00 4c 89 65 b8 66 44 89 65 a8 48 83 7d 00 08 72 0a 48 8b 4d e8 ff 15 2e 2f 06 00 48 c7 45 00 07 00 00 00 4c 89 65 f8 66 44 89 65 e8 48 8d 85 98 04 00 00 48 89 85 c0 00 00 00 48 8d 85 88 04 00 00 48 89 85 c8 00 00 00 48 8b 9d b8 04 00 00 48 8b bd c0 04 00 00 48 3b df 0f 84 8b 02 00 00 66 90 4c 89 a5 48 05 00 00 4c 89 a5 50 05 00 00 48 c7 45 30 07 00 00 00 4c 89 65 28 66 44 89 65 18 4c 8d 85 50 04 00 00 48 83 bd 68 04 00 00 08 4c 0f 43 85 50 04 00 00 48 8d 95 50 04 00 00 48 0f 43 95 50 04 00 00 48 8b 85 60 04 00 00 4d 8d 04 40 48 8d 4d 18 e8 37 b4 01 00 90 48 8d 55 18 48 8d 8d 48 05 00 00 e8 36 9a 00 00 90 48 83 7d 30 }
		$s2 = { 48 c7 85 b0 04 00 00 07 00 00 00 4c 89 a5 a8 04 00 00 66 44 89 a5 98 04 00 00 4c 8b 85 88 04 00 00 4d 8b c8 4d 8b 00 48 8d 95 28 02 00 00 48 8d 8d 88 04 00 00 e8 d1 fe 00 00 48 8b 8d 88 04 00 00 ff 15 5c 28 06 00 48 c7 45 e0 0f 00 00 00 4c 89 65 d8 c6 45 c8 00 41 b8 0e 00 00 00 48 8d 15 b7 db 08 00 48 8d 4d c8 e8 ee d0 00 00 90 48 8d 4d c8 e8 54 8c 01 00 48 8b d8 48 83 7d e0 10 72 0a 48 8b 4d c8 ff 15 18 28 06 00 48 c7 45 e0 0f 00 00 00 4c 89 65 d8 c6 45 c8 00 48 }
		$s3 = { 48 8d 8d a8 02 00 00 e8 88 64 01 00 90 48 8b 08 48 89 4c 24 38 48 8b 48 08 48 89 4c 24 40 4c 89 20 4c 89 60 08 48 8d 54 24 38 48 8d 4c 24 48 e8 a0 8e 01 00 90 48 c7 45 a0 07 00 00 00 4c 89 65 98 66 44 89 65 88 41 b8 0b 00 00 00 48 8d 15 d9 d3 08 00 48 8d 4d 88 e8 a8 a5 00 00 90 48 8d 54 24 48 48 8d 4d 88 e8 d9 60 00 00 90 48 83 7d a0 08 72 0a 48 8b 4d 88 ff 15 7f 27 06 00 48 c7 45 a0 07 00 00 00 4c 89 65 98 66 44 89 65 88 48 8b 4c 24 48 48 85 c9 74 0b 48 8b 01 ba 01 00 00 00 ff 10 90 48 8b 4c 24 40 }
		$s4 = { 48 83 7c 24 58 08 72 0b 48 8b 4c 24 40 ff 15 85 df 06 00 49 8b ce e8 05 dd ff ff e8 e0 db ff ff 48 8d 78 30 e8 27 fc ff ff 33 f6 84 c0 0f 85 ae 01 00 00 48 c7 44 24 38 07 00 00 00 48 89 74 24 30 66 89 74 24 20 44 8d 46 07 48 8d 15 cf 84 09 00 48 8d 4c 24 20 e8 45 5d 01 00 90 48 c7 44 24 58 07 00 00 00 48 89 74 24 50 66 89 74 24 40 44 8d 46 07 48 8d 15 a6 84 09 00 48 8d 4c 24 40 e8 1c 5d 01 00 90 48 8d 54 24 20 48 8b cf e8 5e 24 01 00 48 8b d8 48 8d 54 24 40 48 8d 4d 18 e8 4d 24 01 00 48 8b c8 48 8b d3 e8 72 c1 ff ff 85 c0 0f 9e c3 48 83 7c 24 58 08 72 0b 48 8b 4c 24 40 ff 15 d2 de 06 00 48 c7 44 24 58 07 00 00 00 48 89 74 24 50 66 89 74 24 40 48 83 7c 24 38 08 72 0b 48 8b 4c 24 20 ff 15 ac de 06 00 84 db 0f 84 ed 00 00 00 48 c7 44 24 38 07 00 00 00 48 89 74 24 30 66 89 74 24 20 41 b8 20 00 00 00 48 8d 15 ec 84 09 00 48 8d 4c 24 20 e8 82 5c 01 00 90 48 8d 05 3a aa 09 00 48 89 44 24 40 48 c7 44 24 60 07 00 00 00 48 89 74 24 58 66 89 74 24 48 49 83 c9 ff 45 33 c0 48 8d 54 24 20 48 8d 4c 24 48 e8 0c 5b 01 00 90 48 8d 05 e4 a8 09 00 48 89 45 80 48 8d 4d 88 ff 15 76 de 06 00 48 8d 05 ff e7 06 00 48 89 45 a0 48 89 75 a8 48 89 75 b0 48 89 75 b8 c7 45 c0 ff ff ff ff 48 8b 45 80 48 63 48 04 48 8d 05 71 9a 09 00 48 89 44 0d 80 48 8b 45 80 48 63 48 08 48 8d 05 bd ac 09 00 48 89 44 0d 80 48 8d 54 24 40 48 8d 4d 80 e8 a2 e0 02 00 48 8b d0 41 b8 01 00 00 00 48 8d 4d d0 e8 e0 05 00 00 48 8d 15 81 f8 0b 00 48 8d 4d d0 e8 a2 46 06 00 90 48 c7 44 24 38 07 00 00 00 48 89 74 24 30 66 89 74 24 20 41 b8 0b 00 00 00 48 8d 15 67 83 09 00 48 8d 4c 24 20 e8 95 5b 01 00 90 48 8d 54 24 20 49 8b cd e8 d7 22 01 00 49 3b c4 74 13 49 83 c9 ff 45 33 c0 49 8b d4 48 8b c8 e8 30 5a 01 00 90 48 83 7c 24 38 08 72 0b 48 8b 4c 24 20 ff 15 54 dd 06 00 48 c7 44 24 38 07 00 00 00 48 89 74 24 30 66 89 74 24 20 41 b8 07 00 00 00 48 8d 15 bc 82 09 00 48 8d 4c 24 20 e8 32 5b 01 00 90 48 c7 44 24 58 07 00 00 00 48 89 74 24 50 66 89 74 24 40 41 b8 07 00 00 00 48 8d 15 91 82 09 00 48 8d 4c 24 40 e8 07 5b 01 00 90 48 8d 54 24 20 48 8d 4d 18 e8 48 22 01 00 48 8b d8 48 8d 54 24 40 48 8b cf e8 38 22 01 00 48 3b c3 74 13 49 83 c9 ff 45 33 c0 48 8b d3 48 8b c8 e8 91 59 01 00 90 48 83 7c 24 58 08 72 0b 48 8b 4c 24 40 ff 15 b5 dc 06 00 48 c7 44 24 58 07 00 00 00 48 89 74 24 50 66 89 74 24 40 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize > 300KB and 3 of ( $s* )
}

rule ARKBIRD_SOLG_APT_Turla_Comrat_Chinch_V4_Jan_2021_1 : FILE
{
	meta:
		description = "Detect ComRAT V4 (Chinch) used by APT Turla group"
		author = "Arkbird_SOLG"
		id = "7d4daf3d-eed9-59fb-a4b9-fbc1c72adfcd"
		date = "2021-01-23"
		modified = "2021-01-26"
		reference = "Internal Research"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-01-23/Turla/APT_Turla_ComRAT_Chinch_V4_Jan_2021_1.yar#L1-L28"
		license_url = "N/A"
		logic_hash = "0d92207c4716f8d2fbf1d4f0cf3a33c38417fdd1565c87c251f7ff290135c435"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "a62e1a866bc248398b6abe48fdb44f482f91d19ccd52d9447cda9bc074617d56"

	strings:
		$com1 = "state->_reprocess_current_token || token.type != GUMBO_TOKEN_START_TAG || token.v.start_tag.attributes.data == NULL" fullword wide
		$com2 = "fragment_ctx != GUMBO_TAG_LAST" fullword wide
		$com3 = "has_matching_a == 1" fullword wide
		$com4 = "ODFA: %u %d %u" fullword ascii
		$com5 = "Custom browser path is empty." fullword ascii
		$com6 = "Default browser path is:" fullword ascii
		$com7 = "Search for browser path." fullword ascii
		$com8 = "Cant retrieve any path." fullword ascii
		$com9 = "Custom browser path is:" fullword ascii
		$jmp1 = { 2e 64 6c 6c 00 55 4d 45 50 00 56 46 45 50 }
		$jmp2 = { 33 c9 e9 ?? ?? ff ff cc cc cc cc cc cc cc cc cc }
		$seq1 = { 40 55 48 8d ac 24 00 fd ff ff 48 81 ec 00 04 00 00 48 8b 05 80 46 1b 00 48 33 c4 48 89 85 d0 02 00 00 b9 d8 02 00 00 e8 f4 8b 07 00 4c 8b 0d c5 a5 1c 00 48 8d 95 00 01 00 00 4c 8b 05 af a5 1c 00 48 8d 0d c8 9d 1c 00 4d 2b c8 48 89 05 ae 8a 1d 00 e8 a9 7e fc ff 48 83 bd 18 01 00 00 10 48 8d 8d 00 01 00 00 48 0f 43 8d 00 01 00 00 ff 15 24 f3 0c 00 48 8b 15 25 f3 0c 00 48 8b c8 e8 6d 59 fb ff 48 8b 95 18 01 00 00 48 83 fa 10 }
		$seq2 = { 41 8b 41 08 83 e8 09 83 f8 08 }
		$seq3 = { 48 8b 03 48 8b cb ff 50 08 48 8b 95 f8 01 00 00 48 83 fa 08 72 39 48 8b 8d e0 }
		$seq4 = { b8 09 00 00 00 44 88 a5 60 01 00 00 48 8d 8d 60 01 00 00 f3 0f 7f 85 70 01 00 00 e8 c1 19 fc ff ba df 5e ca 76 48 8d 4d 50 e8 63 ea fc ff 48 8b c8 48 8d 95 60 01 00 00 e8 c4 cb ff ff 0f b6 15 dd 8b 1c 00 48 8b c8 e8 35 cd ff ff 48 8b 95 78 01 00 00 48 83 fa 10 72 34 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize > 1000KB and 6 of ( $com* ) and all of ( $jmp* ) and 3 of ( $seq* )
}

rule ARKBIRD_SOLG_APT_APT34_Dustman_Apr_2021_1 : FILE
{
	meta:
		description = "Detect the Installer of Dustman wiper used by APT34"
		author = "Arkbird_SOLG"
		id = "071063f5-d2a4-5666-a8c4-283c02061f6d"
		date = "2021-04-28"
		modified = "2021-04-30"
		reference = "Internal Research"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-04-29/APT34/APT_APT34_Dustman_Apr_2021_1.yara#L1-L19"
		license_url = "N/A"
		logic_hash = "44e68fa21c1d6258bc9c0dcdc9cc531a15081122c90b23607bcfda716471aeb6"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "a9397eb9e95087db7e03239c689776d56c1450d685568564acd90e1532c78882"
		tlp = "white"
		adversary = "APT34"

	strings:
		$s1 = { 43 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 63 6d 64 2e 65 78 65 00 00 00 00 00 2f 63 20 61 67 65 6e 74 2e 65 78 65 20 41 00 00 44 00 6f 00 77 00 6e 00 20 00 57 00 69 00 74 00 68 00 20 00 42 00 69 00 6e 00 20 00 53 00 61 00 6c 00 6d 00 61 00 6e 00 00 00 00 00 5c 00 }
		$s2 = "\\assistant.sys" fullword wide
		$s3 = { 61 00 67 00 65 00 6e 00 74 00 2e 00 65 00 78 00 65 00 00 00 00 00 00 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4f 00 72 00 61 00 63 00 6c 00 65 00 5c 00 56 00 69 00 72 00 74 00 75 00 61 00 6c 00 42 00 6f 00 78 00 00 00 00 00 54 68 65 20 4d 61 67 69 63 20 57 6f 72 64 21 00 56 00 42 00 6f 00 78 00 44 00 72 00 76 00 00 00 5c 00 44 00 65 00 76 00 69 00 63 00 65 00 00 00 56 00 42 00 6f 00 78 00 55 00 53 00 42 00 4d 00 6f 00 6e 00 00 00 00 00 56 00 42 00 6f 00 78 00 4e 00 65 00 74 00 41 00 64 00 70 00 00 00 00 00 56 00 42 00 6f 00 78 00 4e 00 65 00 74 00 4c 00 77 00 66 }
		$s4 = { 5c 00 5c 00 2e 00 5c 00 25 00 73 }
		$s5 = { 68 54 00 00 00 68 00 00 00 00 68 80 69 40 00 e8 f4 0f 00 00 83 c4 0c 68 00 00 00 00 e8 ed 0f 00 00 a3 84 69 40 00 68 00 00 00 00 68 00 10 00 00 68 00 00 00 00 e8 da 0f 00 00 a3 80 69 40 00 e8 fc 2f 00 00 e8 7d 2c 00 00 e8 7a 18 00 00 e8 1d 12 00 00 e8 40 2d 00 00 68 00 00 00 00 e8 78 2f 00 00 a3 8c 69 40 00 68 00 00 00 00 e8 8d 2f 00 00 a3 90 69 40 00 c7 05 94 69 40 00 5a 00 00 00 c7 05 98 69 40 00 14 00 00 00 8b 1d 8c 69 40 00 2b 1d 94 69 40 00 83 c3 ea 89 1d 9c 69 40 00 8b 1d 90 69 40 00 2b 1d 98 69 40 00 83 c3 cc 89 1d a0 69 40 00 68 00 00 c8 00 68 18 60 40 00 ff 35 98 69 40 00 ff 35 94 69 40 00 ff 35 a0 69 40 00 ff 35 9c 69 40 00 68 00 00 00 }
		$s6 = "Release\\Dustman.pdb" fullword ascii

	condition:
		uint16( 0 ) == 0x5a4d and filesize > 50KB and 4 of them
}

rule ARKBIRD_SOLG_APT_Evilnum_LNK_Jul_2021_1 : FILE
{
	meta:
		description = "Detect LNK file used by EvilNum group"
		author = "Arkbird_SOLG"
		id = "9d570c02-606a-5bff-af7a-9b5ef1e6df90"
		date = "2020-07-13"
		modified = "2021-07-14"
		reference = "Internal Research"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-07-13/EvilNum/APT_EvilNum_LNK_Jul_2021_1.yara#L1-L22"
		license_url = "N/A"
		logic_hash = "d20aadfce6a0246f415f94a62edbf7fd48dcdcd9756a5a8d898a5459633b9350"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "b60ae30ba90f852f886bb4e9aaabe910add2b70278e3a88a3b7968f644e10554"
		hash2 = "bc203f44b48c9136786891be153311c37ce74ceb7eb540d515032c152f5eb2fb"
		hash3 = "fefc9dbb46bc02a2bdccbf3c581d270f6341562e050e5357484ecae7e1e702f3"
		tlp = "white"
		adversary = "EvilNum"

	strings:
		$s1 = "1-5-21-669817101-1001941732-3035937113-1000" fullword wide
		$s2 = "*..\\..\\..\\..\\..\\..\\Windows\\System32\\cmd.exe" fullword wide
		$s3 = "C:\\Windows\\System32\\cmd.exe" fullword wide
		$s4 = "System32 (C:\\Windows)" fullword wide
		$s5 = { 3d 00 25 00 74 00 6d 00 70 00 25 00 5c 00 74 00 65 00 73 00 74 00 2e 00 63 00 26 }
		$s6 = { 3c 00 22 00 25 [5] 25 00 6d 00 64 00 22 00 26 00 6e 00 65 00 74 00 73 00 74 00 61 00 74 00 20 00 2d }
		$s7 = { 43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 46 00 69 00 6c 00 65 00 73 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4e 00 54 00 5c 00 41 00 63 00 63 00 65 00 73 00 73 00 6f 00 72 00 69 00 65 00 73 00 5c 00 77 00 6f 00 72 00 64 00 70 00 61 00 64 00 2e 00 65 00 78 00 65 }

	condition:
		filesize > 60KB and 6 of ( $s* )
}

rule ARKBIRD_SOLG_APT_APT34_RDAT_July_2021_1 : FILE
{
	meta:
		description = "Detect RDAT used by APT34"
		author = "Arkbird_SOLG"
		id = "136f8a9e-e680-5fab-8113-b4d33a47bc34"
		date = "2021-07-15"
		modified = "2021-07-16"
		reference = "https://twitter.com/ShadowChasing1/status/1415206437806960647"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-07-15/APT34/APT_APT34_RDAT_July_2021_1.yara#L1-L22"
		license_url = "N/A"
		logic_hash = "269788430ca8faff4b0ea5ec7c2a62f99f5f48ef3bc4ea3f7a27f1d735e64819"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "b59dea96ef94e8d32ee1a1805174318643569bbdca0d7569ede19467ff09dcdc"
		hash2 = "65a6afc027ff851bd325d8a4f2ab4f326dd8f2c230bfd49a213c5afc00df8e2c"
		hash3 = "f9f6dbb09773f708b125a4cca509047eb33c8c53d9e15a8c41ae3d7a8c3e5c7c"
		tlp = "White"
		adversary = "APT34"

	strings:
		$s1 = { 0a 6f 70 74 20 25 6c 75 28 25 6c 75 29 20 73 74 61 74 20 25 6c 75 28 25 6c 75 29 20 73 74 6f 72 65 64 20 25 6c 75 20 6c 69 74 20 25 75 20 64 69 73 74 20 25 75 }
		$s2 = { 0a 6c 61 73 74 5f 6c 69 74 20 25 75 2c 20 6c 61 73 74 5f 64 69 73 74 20 25 75 2c 20 69 6e 20 25 6c 64 2c 20 6f 75 74 20 7e 25 6c 64 28 25 6c 64 25 25 29 }
		$s3 = { 70 65 6e 53 43 4d 61 6e 61 67 65 72 20 66 61 69 6c 65 64 20 28 25 64 29 0a }
		$s4 = { 43 72 65 61 74 65 53 65 72 76 69 63 65 20 66 61 69 6c 65 64 20 28 25 64 29 0a 00 00 00 00 00 00 53 65 72 76 69 63 65 20 69 6e 73 74 61 6c 6c 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 0a }
		$s5 = { 49 8b cd ff 15 56 22 07 00 c6 05 87 7b 0a 00 00 c7 05 81 7b 0a 00 60 ea 00 00 49 83 c9 ff 45 33 c0 48 8d 55 20 48 8d 0d f3 7b 0a 00 e8 26 a4 ff ff 49 83 c9 ff 45 33 c0 48 8d 55 00 48 8d 0d bc 7b 0a 00 e8 0f a4 ff ff 41 b8 07 00 00 00 48 8d 15 92 b8 08 00 48 8d 0d 03 7c 0a 00 e8 16 a3 ff ff 49 83 c9 ff 45 33 c0 48 8d 55 40 48 8d 0d 6c 7b 0a 00 e8 df a3 ff ff 41 b8 ?? 00 00 00 48 8d 15 6a b8 08 00 48 8d 0d 13 7c 0a 00 e8 e6 a2 ff ff 48 8d 1d 0f 7d 0a 00 48 8b c3 48 83 3d 1c 7d 0a 00 08 48 0f 43 05 fc 7c 0a 00 48 89 44 24 58 48 8d 05 a0 03 00 00 48 89 44 24 60 48 89 7c 24 68 48 89 7c 24 70 48 8d 4c 24 58 ff 15 4e 21 07 00 85 c0 75 29 48 83 3d e2 7c 0a 00 08 48 0f 43 1d c2 7c 0a 00 48 8b d3 33 c9 ff 15 37 21 07 00 48 85 c0 74 09 48 8b c8 ff 15 f1 20 07 00 83 7c 24 30 02 7f 5d 48 8d 44 24 48 48 89 44 24 28 89 7c 24 20 45 33 c9 4c 8d 05 0a 71 ff ff 33 d2 33 c9 ff 15 60 22 07 00 48 8d 44 24 50 48 89 44 24 28 89 7c 24 20 45 33 c9 4c 8d 05 a8 95 ff ff 33 d2 33 c9 ff 15 3e 22 07 00 83 ca ff 48 8b c8 ff 15 f2 20 07 00 b9 64 00 00 00 ff 15 47 22 07 }
		$s6 = { 48 89 7d f0 48 89 7d f8 45 33 c0 33 d2 48 8d 4d e0 e8 43 a7 ff ff 41 b8 2c 00 00 00 48 8d 15 be bc 08 00 48 8d 4d e0 e8 ad a7 ff ff 48 89 7d 70 48 89 7d 78 45 33 c0 33 d2 48 8d 4d 60 e8 17 a7 ff ff 45 33 c0 48 8d 15 77 94 08 00 48 8d 4d 60 e8 84 a7 ff ff 83 7c 24 30 02 75 6e 48 8d 85 a8 00 00 00 48 89 85 a0 00 00 00 41 b8 03 00 00 00 49 8b 55 08 48 8d 8d a0 00 00 00 e8 c9 0a 00 00 48 8b 95 a0 00 00 00 48 8d 4d a0 e8 89 a5 ff ff 48 8d 85 a8 00 00 00 48 8b 8d a0 00 00 48 89 85 b0 10 00 00 48 8b da 48 8b f9 33 f6 89 74 24 78 c7 45 80 18 00 00 00 c7 45 90 01 00 00 00 48 89 75 88 45 33 c9 4c 8d 45 80 48 8d 54 24 68 48 8d 4c 24 60 ff 15 81 fe 06 00 45 33 c0 8d 56 01 48 8b 4c 24 60 ff 15 68 fe 06 00 45 33 c9 4c 8d 45 80 48 8d 54 24 70 48 8d 4c 24 58 ff 15 59 fe 06 00 45 33 c0 8d 56 01 48 8b 4c 24 58 ff 15 40 fe 06 00 33 c0 48 89 45 98 48 89 45 a0 48 89 45 a8 33 d2 44 8d 46 68 48 8d 4d c0 e8 ab 89 04 00 c7 45 c0 68 00 00 00 48 8b 44 24 68 48 89 45 20 48 8b 44 24 70 48 89 45 18 81 4d fc 00 01 00 00 48 8b d3 48 8d 4d 30 e8 bf fe ff ff 90 4c 8b c0 48 8d 8d 90 00 00 00 e8 9f 0d 00 00 90 45 33 c0 b2 01 48 8d 4d 30 e8 d0 7d ff ff 48 8d 95 90 00 00 00 48 83 bd a8 00 00 00 08 48 0f 43 95 90 00 00 00 48 8d 45 98 48 89 44 24 48 48 8d 45 c0 48 89 44 24 40 48 89 74 24 38 48 89 74 24 30 c7 44 24 28 00 00 00 08 c7 44 24 20 01 00 00 00 45 33 c9 45 33 c0 33 c9 ff 15 a7 fd 06 00 48 8b 4c 24 68 ff 15 94 fd 06 00 48 8b 4c 24 70 ff 15 89 fd 06 00 48 89 b5 80 00 00 00 48 89 b5 88 00 00 00 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize > 80KB and 5 of ( $s* )
}

rule ARKBIRD_SOLG_APT_MAL_Donot_Loader_June_2020_1 : FILE
{
	meta:
		description = "Detect loader malware used by APT Donot for drops the final stage"
		author = "Arkbird_SOLG"
		id = "ec4cac12-529f-56d2-bbc0-5fe30424b10b"
		date = "2020-06-22"
		modified = "2020-06-22"
		reference = "https://twitter.com/ccxsaber/status/1274978583463649281"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2020-06-22/APT_MAL_Donot_Loader_June_2020_1.yar#L3-L22"
		license_url = "N/A"
		logic_hash = "986deffd48c1fb707948b00e1e200fa6538d4c73a32ab89f5119403f9bf0d734"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "1ff33d1c630db0a0b8b27423f32d15cc9ef867349ac71840aed47c90c526bb6b"

	strings:
		$s1 = "C:\\Users\\spartan\\Documents\\Visual Studio 2010\\new projects\\frontend\\Release\\test.pdb" fullword ascii
		$s2 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36 Edg/81.0.416.68" fullword ascii
		$s3 = "bbLorkybbYngxkjbb]khbbmgvjgz4k~k" fullword ascii
		$s4 = "8&8-8X8.959?9Q9h9v9|9" fullword ascii
		$s5 = "0$0h4h5l5p5t5x5|5" fullword ascii
		$s6 = "?&?+?1?7?M?T?g?z?" fullword ascii
		$s7 = "12.02.1245" fullword ascii
		$s8 = ">>?C?L?[?~?" fullword ascii
		$s9 = "6*6=6P6b6" fullword ascii

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 30KB and 7 of them
}

rule ARKBIRD_SOLG_APT_APT29_Polyglotduke_Mar_2021_1 : FILE
{
	meta:
		description = "Detect PolyglotDuke implant used by APT29 group"
		author = "Arkbird_SOLG"
		id = "751e4f57-2c31-5cad-a794-e124b40c537b"
		date = "2021-03-08"
		modified = "2021-03-10"
		reference = "Internal Research"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-03-09/APT29/APT_APT29_PolyglotDuke_Mar_2021_1.yar#L1-L19"
		license_url = "N/A"
		logic_hash = "3a6d54fb266fe054886569c200f122b1e4459e0d561fe5246b623a19ec526224"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "9b33ec7f5e615a6556f147b611425d3ca4a8879ce746d4a8cb62adf4c7f76029"
		hash2 = "0c39fce5bd32b4f91a1df4f6321c2f01c017195659c7e95a235ef71ca2865aa9"

	strings:
		$seq1 = { 48 83 ec 28 48 8b 05 [2] 02 00 48 33 05 [2] 02 00 74 02 ff d0 48 83 c4 28 c3 cc 48 83 ec 28 48 8b 05 [2] 02 00 48 33 05 [2] 02 00 74 02 ff d0 48 83 c4 28 c3 cc 4c 8b 15 [2] 02 00 41 8b c0 4c 33 15 [2] 02 00 74 03 49 ff e2 83 e0 01 4c 8b ca 41 83 e0 02 8b d0 48 ff 25 [2] 01 00 cc cc cc 4c 8b 15 [2] 02 00 4c 33 15 [2] 02 00 74 03 49 ff e2 48 ff 25 [2] 01 00 cc cc 48 83 ec 28 48 8b 05 [2] 02 00 48 33 05 [2] 02 00 74 07 48 83 c4 28 48 ff e0 b9 78 00 00 00 ff 15 [2] 01 00 32 c0 48 83 c4 28 c3 cc cc cc 48 8b 05 [2] 02 00 48 33 05 [2] 02 00 74 03 48 ff e0 33 c0 c3 cc cc 48 8b 05 [2] 02 00 48 33 05 [2] 02 00 74 03 48 ff e0 }
		$seq2 = { 48 8b c4 48 89 58 08 48 89 68 10 48 89 70 18 48 89 78 20 41 57 48 83 ec 30 33 ff 48 8b da 48 8b f1 48 85 c9 75 18 e8 69 0c 00 00 bb 16 00 00 00 89 18 e8 b1 38 00 00 8b c3 e9 a7 00 00 00 48 85 d2 74 e3 e8 a8 3f 00 00 41 bf 01 00 00 00 85 c0 75 0c ff 15 [2] 01 00 85 c0 41 0f 44 ff 83 64 24 28 00 48 83 23 00 48 83 64 24 20 00 41 83 c9 ff 4c 8b c6 33 d2 8b cf ff 15 [2] 01 00 48 63 e8 85 c0 75 11 ff 15 [2] 01 00 8b c8 e8 b2 0b 00 00 33 c0 eb 4f 48 8b cd 48 03 c9 e8 e3 07 00 00 48 89 03 48 85 c0 74 e9 41 83 c9 ff 4c 8b c6 33 d2 8b cf 89 6c 24 28 48 89 44 24 20 ff 15 [2] 01 00 85 c0 75 1b ff 15 [2] 01 00 8b c8 e8 70 0b 00 00 48 8b 0b e8 ?? f3 ff ff 48 83 23 00 eb b0 41 8b c7 48 8b 5c 24 40 48 8b 6c 24 48 48 8b 74 24 50 48 8b 7c 24 58 48 83 c4 30 41 5f c3 48 8b c4 48 89 58 08 48 89 68 10 48 89 70 18 48 89 78 20 41 57 48 83 ec 40 33 ff 48 8b da 48 8b f1 }
		$seq3 = { ff 25 00 00 00 00 00 00 00 00 00 00 00 00 cc }
		$seq4 = "InitSvc" fullword ascii

	condition:
		uint16( 0 ) == 0x5a4d and filesize > 100KB and 3 of them
}

rule ARKBIRD_SOLG_APT_APT28_Downdelph_Feb_2021_1 : FILE
{
	meta:
		description = "Detect Downdelph used by APT28 group"
		author = "Arkbird_SOLG"
		id = "0376c026-93eb-526a-8ab3-26bdd365e608"
		date = "2021-02-18"
		modified = "2021-02-19"
		reference = "https://twitter.com/RedDrip7/status/1362343352759250946"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-02-18/APT28/APT_APT28_Downdelph_Feb_2021_1.yar#L1-L18"
		license_url = "N/A"
		logic_hash = "15e38ceeb0410645938ce2f90becf9a344711efd6e539f304de7b413f6f3b420"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "ee7cfc55a49b2e9825a393a94b0baad18ef5bfced67531382e572ef8a9ecda4b"

	strings:
		$s1 = { 53 [1-3] 81 c4 [2] ff ff 8b f2 8b ?? 54 8d 44 24 08 50 68 04 01 00 00 8b ?? e8 [12-22] 8d 54 24 04 8b c6 [73-133] 33 d2 52 50 8b 45 e8 8b 55 ec e8 [3] ff 8b 4d 0c 89 01 89 51 04 8b 45 f0 33 d2 52 50 8b 45 e8 8b 55 ec e8 [3] ff 8b 4d 10 89 01 89 51 04 8b c3 5b 8b e5 5d }
		$s2 = "cmd.exe /c " fullword ascii
		$s3 = "Failed to Save Stream %s is already associated with %s=This control requires version 4.70 or greater of COMCTL32.DLL" fullword wide
		$s4 = { 53 00 79 00 73 00 74 00 65 00 6d 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 5c 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 5c 00 4b 00 65 00 79 00 62 00 6f 00 61 00 72 00 64 00 20 00 4c 00 61 00 79 00 6f 00 75 00 74 00 73 00 5c 00 25 00 2e 00 38 00 78 }
		$s5 = { 4a 00 50 00 45 00 47 00 20 00 65 00 72 00 72 00 6f 00 72 00 20 00 23 00 25 00 64 }
		$s6 = { 45 00 72 00 72 00 6f 00 72 00 20 00 63 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 69 00 6e 00 67 00 20 00 74 00 6f 00 20 00 73 00 65 00 72 00 76 00 65 00 72 00 3a 00 20 00 25 00 73 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize > 100KB and 5 of them
}

rule ARKBIRD_SOLG_APT_APT_34_Maildrop_Mar_2021_1 : FILE
{
	meta:
		description = "Detect MailDrop malware used by APT34"
		author = "Arkbird_SOLG"
		id = "a17c4e0b-9bbb-594d-8551-5c146e6a601e"
		date = "2021-04-03"
		modified = "2021-04-09"
		reference = "Internal Research"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-04-03/APT34/APT_APT_34_MailDrop_Mar_2021_1.yar#L1-L24"
		license_url = "N/A"
		logic_hash = "f55192044bf8e190dfdc18aeaac543a5022643ea242e75ff2492939ae6e1814c"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "d6b876d72dba94fc0bacbe1cb45aba493e4b71572a7713a1a0ae844609a72504"
		hash2 = "ebae23be2e24139245cc32ceda4b05c77ba393442482109cc69a6cecc6ad1393"

	strings:
		$EWSInitCom = { 7e ?? 00 00 04 28 ?? 00 00 06 ?? 4f [0-3] 02 7b ?? 00 00 04 28 ?? 00 00 06 28 ?? 00 00 06 02 7b ?? 00 00 04 6f ?? 00 00 06 02 7b ?? 00 00 04 28 ?? 00 00 06 72 ?? 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 06 02 7b ?? 00 00 04 6f ?? 00 00 06 7e ?? 00 00 04 72 ?? 00 00 70 28 ?? 00 00 06 7e 06 00 00 04 28 ?? 00 00 06 [2-4] 00 00 [3-4] 00 00 [3] 00 00 [3] 00 00 [3] 00 00 }
		$EWSCom = { 13 30 ?? 00 ?? 00 00 00 00 00 00 00 02 28 ?? 00 00 ?? 02 03 05 0e 04 0e 05 0e 06 [0-4] 73 ?? 00 00 06 7d ?? 00 00 04 04 [2-6] 00 00 ?? 02 ?? 7d ?? 00 00 04 [0-2] 02 ?? 7d ?? 00 00 04 [2-4] 00 00 [0-18] 04 02 28 ?? 00 00 06 2a }
		$EWSDecrypt = { 13 30 03 00 27 00 00 00 ?? 00 00 11 0f 00 20 00 01 00 00 16 28 ?? 00 00 06 28 ?? 00 00 06 0a 0f 00 1f 10 16 28 ?? 00 00 06 0b 02 06 07 28 ?? 00 00 06 2a }
		$EWSRandomData = { 1b 30 ?? 00 ?? 00 00 00 ?? 00 00 11 02 19 28 ?? 00 00 0a 0a 16 0b ?? 35 [0-3] 06 16 6a 16 6f ?? 00 00 0a 26 06 6f ?? 00 00 0a d4 8d ?? 00 00 01 0c 7e ?? 00 00 04 08 6f ?? 00 00 0a 06 08 16 06 6f ?? 00 00 0a b7 6f ?? 00 00 0a 07 17 d6 0b 07 1f 32 32 c6 [5-11] 06 6f ?? 00 00 0a dc 2a [0-1] 01 10 00 00 02 00 08 00 }
		$s1 = "HMicrosoft Office/15.0 (Windows NT {0}; Microsoft Outlook 15.0.4675; Pro)" fullword ascii
		$s2 = "https://{0}/ews/exchange.asmx" fullword wide
		$s3 = "Send_Log" fullword ascii
		$s4 = "CheckEWSConnection" fullword ascii
		$s5 = "Done:D" fullword wide
		$s6 = "ExecAllCmds" fullword ascii
		$s7 = "ExchangeUri" fullword ascii
		$s8 = "get_cmdSubject" fullword ascii

	condition:
		uint16( 0 ) == 0x5a4d and filesize > 20KB and 2 of ( $EWS* ) and 5 of ( $s* )
}

rule ARKBIRD_SOLG_APT_Sidewinder_NET_Loader_Aug_2020_1 : FILE
{
	meta:
		description = "Detected the NET loader used by SideWinder group (August 2020)"
		author = "Arkbird_SOLG"
		id = "7334a3b8-cd56-5820-a073-5bd22076644f"
		date = "2020-08-24"
		modified = "2020-08-24"
		reference = "https://twitter.com/ShadowChasing1/status/1297902086747598852"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2020-08-24/SideWinder/APT_SideWinder_NET_Loader_Aug_2020_1.yar#L3-L21"
		license_url = "N/A"
		logic_hash = "b40127cd845d75ef81eb230c12635da00dd77fc53e5886c253a2466627aa8534"
		score = 75
		quality = 73
		tags = "FILE"
		hash1 = "4a0947dd9148b3d5922651a6221afc510afcb0dfa69d08ee69429c4c75d4c8b4"

	strings:
		$s1 = "DUSER.dll" fullword wide
		$s2 = "UHJvZ3JhbQ==" fullword wide
		$s3 = ".tmp           " fullword wide
		$s4 = "U3RhcnQ=" fullword wide
		$s5 = "Gadgets" fullword ascii
		$s6 = "AdapterInterfaceTemplateObject" fullword ascii
		$s7 = "FileRipper" fullword ascii
		$s8 = "copytight @" fullword wide

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 4KB and ( ( pe.exports ( "FileRipper" ) and pe.exports ( "Gadgets" ) ) and 5 of them )
}

rule ARKBIRD_SOLG_APT_Turla_Bigboss_Apr_2021_1 : FILE
{
	meta:
		description = "Detects new BigBoss implants (SilentMoon/GoldenSky)"
		author = "Arkbird_SOLG"
		id = "6f6c8d1e-f2c7-5f08-b1dc-ce726c6d89be"
		date = "2021-04-06"
		modified = "2021-07-17"
		reference = "https://twitter.com/DrunkBinary/status/1304086230540390400"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-07-17/BigBoss/APT_Turla_BigBoss_Apr_2021_1.yara#L1-L21"
		license_url = "N/A"
		logic_hash = "ce0ffdad9eecb79128b6c08c87914f356c86ac631655c76905a06d953add3998"
		score = 75
		quality = 71
		tags = "FILE"
		hash1 = "94421ccb97b784c43d92c4b1438481eee9c907db6b13f6cfc4b86a6bb057ddcd"
		hash2 = "67bfa585ace8df20deb1d8a05bd4acf2c84c6fa0966276b3ea7607056abe25bb"
		hash3 = "6ca0b4efe077fe05b2ae871bf50133c706c7090a54d2c3536a6c86ff454caa9a"

	strings:
		$s1 = { 55 8b ec a1 [2] 40 00 83 ec 3c 50 6a 3c 8d 4d c4 51 68 [2] 40 00 68 [2] 40 00 68 [2] 40 00 ff 15 78 ?? 40 00 8d 45 c4 8d 50 02 8d 49 00 66 8b 08 83 c0 02 66 85 c9 75 f5 2b c2 d1 f8 75 1c 8b 15 [2] 40 00 52 68 [2] 40 00 68 [2] 40 00 68 [2] 40 00 ff 15 [2] 40 00 8b e5 }
		$s2 = { 5c 00 5c 00 2e 00 5c 00 47 00 6c 00 6f 00 62 00 61 00 6c 00 5c 00 50 00 49 00 50 00 45 00 5c }
		$s3 = { 5c 5c 25 73 5c 70 69 70 65 5c 25 73 }
		$s4 = { 5c 00 69 00 6e 00 66 00 5c 00 00 00 [4-16] 2e 00 69 00 6e 00 66 }
		$s5 = "%d blocks, %d sorted, %d scanned" ascii fullword
		$s6 = "REMOTE_NS:ERROR:%d" ascii fullword
		$s7 = { 5c 5c 25 73 5c 69 70 63 24 }
		$s8 = { 53 00 59 00 53 00 54 00 45 00 4d 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 5c 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 5c 00 6c 00 61 00 6e 00 6d 00 61 00 6e 00 73 00 65 00 72 00 76 00 65 00 72 00 5c 00 70 00 61 00 72 00 61 00 6d 00 65 00 74 00 65 00 72 00 73 00 00 00 4e 00 75 00 6c 00 6c 00 53 00 65 00 73 00 73 00 69 00 6f 00 6e 00 50 00 69 00 70 00 65 00 73 00 00 00 00 00 53 00 59 00 53 00 54 00 45 00 4d 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 5c 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 5c 00 4c 00 53 00 41 00 00 00 00 00 52 00 65 00 73 00 74 00 72 00 69 00 63 00 74 00 41 00 6e 00 6f 00 6e 00 79 00 6d 00 6f 00 75 00 73 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize > 20KB and 7 of ( $s* )
}

rule ARKBIRD_SOLG_APT_Sidewinder_Nov_2020_1 : FILE
{
	meta:
		description = "Detect Sidewinder DLL decoder algorithm"
		author = "Arkbird_SOLG"
		id = "9e948949-f38d-5a76-a34c-965ec9be070d"
		date = "2020-11-14"
		modified = "2020-11-15"
		reference = "https://twitter.com/hexfati/status/1325397305051148292"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2020-11-15/APT_SideWinder_Nov_2020_1.yar#L1-L12"
		license_url = "N/A"
		logic_hash = "661eb5510ff0aa59b38b2c023653f0a23867a2813d854fbd0a7a6b657d9ba671"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "8d7ad2c603211a67bb7abf2a9fe65aefc993987dc804bf19bafbefaaca066eaa"

	strings:
		$s = { 13 30 05 00 ?? 00 00 00 01 00 00 11 ?? ?? 00 00 ?? ?? ?? 00 00 [30-80] 2B 16 07 08 8F 1? }

	condition:
		uint16( 0 ) == 0x5a4d and filesize > 3KB and $s
}

rule ARKBIRD_SOLG_APT_Donot_Downloader_May_2021_1 : FILE
{
	meta:
		description = "Detect the trojan downloader used by Donot group"
		author = "Arkbird_SOLG"
		id = "251a809e-9e36-5c46-955f-006531bd9619"
		date = "2020-05-09"
		modified = "2021-05-09"
		reference = "Internal Research"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-05-09/Donot/APT_Donot_Downloader_May_2021_1.yara#L1-L20"
		license_url = "N/A"
		logic_hash = "df64ab97b74935ce8b73c3854eb81fa1dbd4e59b1e27c43ae9c85b90aaaef6f7"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "28aa296bda12f0184564c5f6b46e679f07255aa8df58b861ea17910cdcaa674a"
		hash2 = "03730cdc23a3d10c8752ad1464ff2e68a64c69f8310b0ceea4d52b1db0215dfc"
		hash3 = "edd590c343570f7576aca83da58967e058585c6ba861682dca2fc987c713ee3a"
		tlp = "White"
		adversary = "Donot"

	strings:
		$seq1 = { 65 63 68 6f 20 6f 66 66 0a 20 6d 64 20 25 73 20 0a 20 6d 64 20 25 73 20 0a 20 6d 64 20 25 73 20 0a 20 6d 64 20 25 73 20 0a 20 6d 64 20 25 73 20 0a 20 20 61 74 74 72 69 62 20 2b 61 20 2b 68 20 2b 73 20 25 73 20 0a 20 61 74 74 72 69 62 20 2b 61 20 2b 68 20 2b 73 20 25 73 20 0a 20 61 74 74 72 69 62 20 2b 61 20 2b 68 20 2b 73 20 25 73 20 0a 20 61 74 74 72 69 62 20 2b 61 20 2b 68 20 2b 73 20 25 73 20 0a 20 64 65 6c 20 2f 66 20 25 73 20 0a 20 53 45 54 20 2f 41 20 25 25 43 4f 4d 50 55 54 45 52 4e 41 4d 45 25 25 20 0a 20 53 45 54 20 2f 41 20 52 41 4e 44 3d 25 25 52 41 4e 44 4f 4d 25 25 20 31 30 30 30 30 20 2b 20 32 20 0a 20 65 63 68 6f 20 25 25 43 4f 4d 50 55 54 45 52 4e 41 4d 45 25 25 2d 25 25 52 41 4e 44 25 25 20 3e 3e 20 25 73 20 0a 20 73 63 68 74 61 73 6b 73 20 2f 64 65 6c 65 74 65 20 2f 74 6e 20 4d 6f 62 55 70 64 61 74 65 20 2f 66 20 20 0a 20 73 63 68 74 61 73 6b 73 20 2f 64 65 6c 65 74 65 20 2f 74 6e 20 54 61 73 6b 55 70 64 61 74 65 20 2f 66 20 0a 20 73 63 68 74 61 73 6b 73 20 2f 64 65 6c 65 74 65 20 2f 74 6e 20 4d 61 63 68 69 6e 65 43 6f 72 65 20 2f 66 20 0a 20 73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 73 63 20 6d 69 6e 75 74 65 20 2f 6d 6f 20 32 30 20 2f 66 20 2f 74 6e 20 54 61 73 6b 55 70 64 61 74 65 20 2f 74 72 20 25 73 20 20 0a 20 73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 73 63 20 6d 69 6e 75 74 65 20 2f 6d 6f 20 31 30 20 2f 66 20 2f 74 6e 20 4d 61 63 68 69 6e 65 43 6f 72 65 20 2f 74 72 20 25 73 20 0a 20 6d 6f 76 65 20 25 25 41 50 50 44 41 54 41 25 }
		$seq2 = { c7 44 24 10 00 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 08 00 00 00 00 c7 44 24 04 00 00 00 00 c7 04 24 ?? 42 [2] e8 ?? 01 00 00 83 ec 14 [0-3] c7 44 24 14 00 00 00 00 c7 44 24 10 00 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 08 00 00 00 00 [2-5] 24 04 [0-3] 89 04 24 e8 ?? 01 00 00 83 ec 18 89 [1-9] c7 44 24 04 ?? 43 [2] c7 04 24 ?? 61 [2] e8 ?? 08 00 00 }
		$s1 = "VirtualQuery failed for %d bytes at address %p" fullword ascii
		$s2 = { 25 73 5c [1-14] 2e 62 61 74 }
		$s3 = { 25 73 5c [1-14] 25 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize > 10KB and all of ( $seq* ) and 2 of ( $s* )
}

rule ARKBIRD_SOLG_APT_Lazarus_Jun_2021_1 : FILE
{
	meta:
		description = "Detect a variant of NukeSped malware"
		author = "Arkbird_SOLG"
		id = "0f5d42c0-d6dc-573b-9227-787ccbcaa83d"
		date = "2021-06-19"
		modified = "2021-06-21"
		reference = "Internal Research"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-06-19/Lazarus/APT_Lazarus_Jun_2021_1.yara#L1-L20"
		license_url = "N/A"
		logic_hash = "ea4ce93d54b9b8e5d1d5bb64d37ac26839e2fa3200da3057597d83c4be6d129f"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "5c2f339362d0cd8e5a8e3105c9c56971087bea2701ea3b7324771b0ea2c26c6c"
		hash2 = "2dff6d721af21db7d37fc1bd8b673ec07b7114737f4df2fa8b2ecfffbe608a00"
		hash3 = "1177105e51fa02f9977bd435f9066123ace32b991ed54912ece8f3d4fbeeade4"
		tlp = "White"
		adversary = "Lazarus"

	strings:
		$seq1 = { 48 8b ce e8 8a 2c 00 00 48 8b d8 48 85 c0 0f 84 28 06 00 00 4c 8b c6 33 d2 48 8b c8 e8 11 56 00 00 8d 4e fc 48 8d 57 04 4c 63 c1 48 8b cb e8 af 3a 00 00 33 c0 48 8d 4c 24 30 48 89 4c 24 28 45 33 c9 4c 8b c3 33 d2 33 c9 89 44 24 30 89 44 24 20 ff 15 4b 49 01 00 48 85 c0 0f 84 d4 05 00 00 ba 88 13 00 00 48 8b c8 ff 15 9c 2c 02 00 48 8d 8d 91 00 00 00 33 d2 41 b8 ff 03 00 00 c6 85 90 00 00 00 00 e8 a9 55 00 00 48 8d 15 02 c1 01 00 48 8d 8d 90 00 00 00 e8 16 2b 00 00 48 8d 85 90 00 00 00 48 83 cb ff 48 ff c3 80 3c 18 00 75 f7 41 b2 84 ba 43 90 21 57 41 b8 c2 a2 a9 09 85 db 0f 8e 4b 05 00 00 4c 8d 8d 90 00 00 00 44 8b db 66 90 41 0f b6 01 41 0f b6 c8 4d 8d 49 01 32 ca 41 32 c2 44 22 d1 41 32 c0 42 8d 0c c5 00 00 00 00 32 c2 41 33 c8 41 88 41 ff 81 e1 f8 07 00 00 41 0f b6 c0 22 c2 c1 e1 14 44 32 d0 41 8b c0 44 8b c1 c1 e8 08 8d 0c 12 33 ca 44 0b c0 8b c2 c1 e1 04 c1 e0 07 33 ca 83 e1 80 33 c8 8b c2 c1 e1 11 c1 e8 08 8b d1 0b d0 49 ff }
		$seq2 = { 48 8d ac 24 50 ff ff ff 48 81 ec b0 01 00 00 48 8b 05 82 09 02 00 48 33 c4 48 89 85 a0 00 00 00 44 8b 25 d5 38 02 00 4c 8b f9 48 8d 4d 91 33 d2 41 b8 03 01 00 00 c6 45 90 00 e8 59 66 00 00 b9 3c 00 00 00 ff 15 f6 3c 02 00 ff 15 88 59 01 00 8b c8 e8 51 42 00 00 e8 20 42 00 00 b9 3c 00 00 00 8b d8 83 e3 03 83 c3 08 ff 15 d1 3c 02 00 ff 15 63 59 01 00 8b c8 e8 2c 42 00 00 e8 fb 41 00 00 b9 3c 00 00 00 8b f8 83 e7 01 83 c7 05 ff 15 ac 3c 02 00 ff 15 3e 59 01 00 8b c8 e8 07 42 00 00 e8 d6 41 00 00 8b f0 b8 ab aa aa aa f7 e6 d1 ea 8d 0c 52 2b f1 83 eb 08 0f 84 30 03 00 00 ff cb 0f 84 68 02 00 00 ff cb 0f 84 9a 01 00 00 ff cb 0f 85 ef 04 00 00 8d 4b 3c ff 15 60 3c 02 00 ff 15 f2 58 01 00 8b c8 e8 bb 41 00 00 e8 8a 41 00 00 8b d8 b8 1f 85 eb 51 f7 e3 c1 ea 03 6b ca 19 2b d9 b9 3c 00 00 00 83 c3 0a ff 15 2f 3c 02 00 ff 15 c1 58 01 00 8b c8 e8 8a 41 00 00 e8 59 41 00 00 44 8b f0 b8 ab aa aa aa 41 f7 e6 c1 ea 02 8d 0c 52 03 c9 44 2b f1 b9 3c 00 00 00 41 81 c6 d7 07 00 00 ff 15 f5 3b 02 00 ff 15 87 58 01 00 8b c8 e8 50 41 00 00 e8 1f 41 00 00 44 8b e8 b8 ab aa aa aa 41 f7 e5 c1 ea 03 8d 0c 52 c1 e1 02 44 2b e9 b9 3c 00 00 00 41 ff c5 ff 15 be 3b 02 00 ff 15 50 58 01 00 8b c8 e8 19 41 00 00 e8 e8 40 00 00 44 8b c0 b8 09 cb 3d 8d 41 f7 e0 c1 ea 04 6b ca 1d 44 2b c1 b9 7d 00 00 00 41 ff c0 44 89 44 24 74 e8 3e 3b 00 00 33 d2 44 8d 42 7d 48 8b c8 e8 d0 64 00 00 4c 8d 44 24 70 48 8d 0d d4 ce 01 00 ba 7c 00 00 00 c7 44 24 70 00 00 00 00 e8 c2 27 00 00 44 8b 44 24 70 48 8b d0 48 8b c8 48 89 44 24 78 e8 3d 25 00 00 48 8b 44 24 78 4c 8d 45 90 48 8b d0 4c 2b c0 0f 1f 40 00 66 66 0f 1f 84 00 00 00 00 00 0f b6 0a 48 8d 52 01 41 88 4c 10 ff 84 c9 75 f0 48 8b c8 e8 88 3a 00 00 8b 44 24 74 44 89 64 24 48 89 5c 24 40 89 44 24 38 44 89 6c 24 30 48 8d 55 90 44 8b cf 41 b8 04 00 00 00 49 8b cf 44 89 74 24 28 89 74 24 20 e8 b4 39 00 00 e9 5d 03 00 00 b9 3c 00 00 00 ff 15 cc 3a 02 00 ff 15 5e 57 01 00 8b c8 e8 27 40 00 00 e8 f6 3f 00 00 b9 79 00 00 00 8b d8 83 e3 03 e8 63 3a 00 00 33 d2 44 8d 42 79 48 8b c8 e8 f5 63 00 00 4c 8d 44 24 70 48 8d 0d 79 cd 01 00 ba 78 00 00 00 c7 44 24 70 00 00 00 00 e8 e7 26 00 00 44 8b 44 24 70 48 8b d0 48 8b c8 4c 8b f0 e8 64 24 00 00 4c 8d 45 90 49 8b d6 4d 2b c6 66 66 0f 1f 84 00 00 00 00 00 0f b6 0a 48 8d 52 01 41 88 4c 10 ff 84 c9 75 f0 49 8b ce e8 b8 39 00 00 44 89 64 24 38 8d 43 04 89 44 24 30 44 8d 4b 08 48 8d 55 90 41 b8 04 00 00 00 49 8b cf 89 74 24 28 89 }
		$seq3 = { 48 89 5c 24 18 55 56 57 48 83 ec 70 48 8b 05 9d fe 01 00 48 33 c4 48 89 44 24 60 33 c0 48 8b d9 8b fa 8d 48 20 c6 44 24 48 00 48 89 44 24 49 48 89 44 24 51 e8 d7 31 00 00 48 8d 15 44 c6 01 00 48 8b f0 33 c0 48 8d 4c 24 48 48 89 06 48 89 46 08 48 89 46 10 4c 8b c3 48 89 46 18 e8 3f 13 00 00 48 8d 4c 24 48 ff 15 ac 50 01 00 bd 02 00 00 00 0f b7 cf 89 44 24 3c 66 89 6c 24 38 ff 15 a5 2e 02 00 8d 55 ff 44 8d 45 04 8b cd 66 89 44 24 3a ff 15 01 32 02 00 48 8b f8 48 83 f8 ff 75 20 48 8d 15 e1 c5 01 00 48 8b ce e8 81 30 00 00 48 0b df 48 ff c3 80 3c 1e 00 75 f7 e9 c9 00 00 00 48 8d 54 24 38 41 b8 10 00 00 00 48 8b c8 ff 15 f4 31 02 00 83 f8 ff 75 6b 48 8d 15 a8 c5 01 00 48 8b ce e8 48 30 00 00 48 83 cb }
		$seq4 = { 40 55 48 8d ac 24 e0 fb ff ff 48 81 ec 20 05 00 00 48 8b 05 b8 fc 01 00 48 33 c4 48 89 85 10 04 00 00 48 8d 8d f1 00 00 00 33 d2 41 b8 03 01 00 00 c6 85 f0 00 00 00 00 e8 93 59 00 00 48 8d 8d 01 02 00 00 33 d2 41 b8 07 02 00 00 c6 85 00 02 00 00 00 e8 78 59 00 00 48 8d 4d e1 33 d2 41 b8 03 01 00 00 c6 45 e0 00 e8 63 59 00 00 48 8d 95 f0 00 00 00 41 b8 f4 01 00 00 33 c9 ff 15 2e 30 02 00 85 c0 0f 84 5e 01 00 00 48 8d 55 e0 b9 f4 01 00 00 48 89 9c 24 30 05 00 00 48 89 bc 24 38 05 00 00 ff 15 17 30 02 00 4c 8d 05 20 15 02 00 48 8d 4d e0 ba 04 01 00 00 e8 5a 37 00 00 48 8d 45 e0 4c 8d 0d f7 14 02 00 48 89 44 24 28 48 8d 85 f0 00 00 00 4c 8d 85 f0 00 00 00 48 8d 15 dd c3 01 00 48 8d 8d 00 02 00 00 48 89 44 24 20 e8 fc 10 00 00 33 ff 48 8d 4d e0 48 89 7c 24 30 44 8d 47 03 45 33 c9 ba 00 00 00 40 c7 44 24 28 80 00 00 00 c7 44 24 20 02 00 00 00 ff 15 6f 2f 02 00 48 8b d8 }
		$seq5 = { 48 89 5c 24 10 48 89 74 24 18 48 89 7c 24 20 55 48 8d ac 24 70 f2 ff ff 48 81 ec 90 0e 00 00 48 8b 05 da ed 01 00 48 33 c4 48 89 85 80 0d 00 00 48 8b f1 48 8d 8d 81 05 00 00 33 d2 41 b8 ff 07 00 00 c6 85 80 05 00 00 00 e8 b2 4a 00 00 48 8d 4d 71 33 d2 41 b8 03 01 00 00 c6 45 70 00 e8 9d 4a 00 00 33 c0 c6 44 24 50 00 39 05 f4 1c 02 00 89 44 24 51 75 0b e8 b5 dd ff ff 89 05 e3 1c 02 00 48 8d 4d 70 e8 c6 e3 ff ff 8b 05 e8 b5 01 00 48 8d 8d 81 01 00 00 89 44 24 50 0f b6 05 da b5 01 00 33 d2 41 b8 ff 03 00 00 c6 85 80 01 00 00 00 88 44 24 54 e8 46 4a 00 00 48 8d 15 3f b6 01 00 48 8d 8d 80 01 00 00 e8 b3 1f 00 00 48 8d 4d 90 33 d2 0f 10 05 b6 b6 01 00 0f 10 0d bf b6 01 00 41 b8 d4 00 00 00 0f 29 44 24 60 0f 29 4c 24 70 0f 10 05 b8 b6 01 00 0f 29 45 80 e8 ff 49 00 00 48 83 cb ff 48 8b c3 0f 1f 84 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize > 60KB and 4 of ( $seq* )
}

rule ARKBIRD_SOLG_APT_Kimsuky_Aug_2020_1 : FILE
{
	meta:
		description = "Detect Gold Dragon used by Kimsuky APT group"
		author = "Arkbird_SOLG"
		id = "dd79aa3b-0bbc-5fdd-808e-c2dee6d89804"
		date = "2020-08-31"
		modified = "2020-09-14"
		reference = "Internal Research"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2020-09-14/Kimsuky/APT_Kimsuky_Aug_2020_1.yar#L1-L23"
		license_url = "N/A"
		logic_hash = "4644ea81535c867a36a882bb270cea784ae135e7acc7078823be0579b1746932"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "4ff2a67b094bcc56df1aec016191465be4e7de348360fd307d1929dc9cbab39f"
		hash2 = "97935fb0b5545a44e136ee07df38e9ad4f151c81f5753de4b59a92265ac14448"

	strings:
		$s1 = "/c systeminfo >> %s" fullword ascii
		$s2 = "/c dir %s\\ >> %s" fullword ascii
		$s3 = ".?AVGen3@@" fullword ascii
		$s4 = { 48 6f 73 74 3a 20 25 73 0d 0a 52 65 66 65 72 65 72 3a 20 68 74 74 70 3a 2f 2f 25 73 25 73 0d 0a 25 73 0d 0a 25 73 }
		$s5 = "%s?filename=%s" fullword ascii
		$s6 = "Content-Disposition: form-data; name=\"userfile\"; filename=\"" fullword ascii
		$s7 = "Content-Type: multipart/form-data; boundary=----WebKitFormBoundarywhpFxMBe19cSjFnG" fullword ascii
		$s8 = "Content-Disposition: form-data; name=\"MAX_FILE_SIZE\"" fullword ascii
		$s9 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; .NET CLR 1.1.4322)" fullword ascii
		$s10 = "\\Microsoft\\HNC" fullword ascii
		$s11 = "Mozilla/5.0" fullword ascii

	condition:
		uint16( 0 ) == 0x5a4d and filesize > 150KB and 8 of them
}

rule ARKBIRD_SOLG_APT_MAL_NK_Lazarus_Nukesped_June_2020_1 : FILE
{
	meta:
		description = "Detect NukeSped malware used by APT Lazarus"
		author = "Arkbird_SOLG"
		id = "7a5b27df-43bd-544d-8d0f-72e58ce3064c"
		date = "2020-06-11"
		modified = "2020-06-12"
		reference = "https://twitter.com/batrix20/status/1270924079826997248"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2020-06-12/Lazarus/Lazarus_June_2020_1.yar#L28-L54"
		license_url = "N/A"
		logic_hash = "b1332eb255f8ae9ae6a68ef8ef86d9f5472584cae8161c27186e341990df7eae"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "90ea1c7806e2d638f4a942b36a533a1da61adedd05a6d80ea1e09527cf2d839b"

	strings:
		$s1 = "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X" fullword wide
		$s2 = "<htr<jtb<lt6<tt&<wt" fullword ascii
		$s3 = "Content-Disposition: form-data; name=\"file\"; filename=\"%s\"" fullword ascii
		$s4 = "Content-Type: multipart/form-data; boundary=" fullword wide
		$s5 = "POST" fullword ascii
		$s6 = "Content-Type: octet-stream" fullword ascii
		$s7 = "CONOUT$" fullword ascii
		$s8 = "cmd.exe /c" fullword ascii
		$s9 = "2>&1" fullword ascii
		$s10 = "WINHTTP.dll" fullword ascii
		$s11 = "WinHttpSendRequest" fullword wide
		$s12 = "ObtainUserAgentString" fullword ascii
		$s13 = "WS2_32.dll" fullword ascii
		$s14 = "WinHttpReceiveResponse" fullword ascii
		$s15 = "GetLogicalDrives" fullword ascii

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 100KB and ( pe.imphash ( ) == "c8379f0eeeb3a522f1dd75aa5f1500b0" or 12 of them )
}

rule ARKBIRD_SOLG_APT_Tardigrade_Nov_2021_1 : FILE
{
	meta:
		description = "Detect Tardigrade loader"
		author = "Arkbird_SOLG"
		id = "f6c8014a-21dd-5ebd-9edd-7a9f649a43a0"
		date = "2021-11-22"
		modified = "2021-11-23"
		reference = "https://www.isac.bio/post/tardigrade"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-11-22/APT_Tardigrade_Nov_2021_1.yara#L1-L19"
		license_url = "N/A"
		logic_hash = "98358d9dbf62e653b136268d8694ed4d7f48c80125dd12ccea5f36ff5c6b4a3c"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "1c7c1a28921d81f672320e81ad58642ef3b8e27abf8a8e51400b98b40f49568be"
		hash2 = "c0976a1fbc3dd938f1d2996a888d0b3a516b432a2c38d788831553d81e2f5858"
		hash3 = "cf88926b7d5a5ebbd563d0241aaf83718b77cec56da66bdf234295cc5a91c5fe"
		tlp = "white"
		adversary = "Tardigrade"

	strings:
		$s1 = { 63 6d 64 2e 65 78 65 20 2f 63 20 65 63 68 6f 20 [10-40] 3e 22 25 73 22 26 65 78 69 74 }
		$s2 = { 4c 89 44 24 38 89 54 24 34 48 89 4c 24 28 e8 [2] 01 00 e8 [2] 01 00 4c 8b 44 24 38 8b 54 24 34 48 8b 4c 24 28 48 83 c4 48 e9 71 fe ff ff 90 48 89 ca 48 8d 0d 76 ?? 02 00 }
		$s3 = { 41 57 41 56 41 55 41 54 55 57 56 53 48 ?? ec [1-4] 48 8b 84 24 ?? 00 00 00 48 89 44 24 60 48 8b 05 [2] 01 00 48 89 4c 24 40 ?? 38 }
		$s4 = { 45 31 c0 48 8d 8c 24 ?? 02 00 00 4c 8d 8c 24 ?? 01 00 00 48 8d 15 [2] 01 00 ff 15 [2] 02 00 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize > 50KB and all of them
}

rule ARKBIRD_SOLG_APT_NK_Lazarus_Implant_June_2020_1 : FILE
{
	meta:
		description = "Detect Lazarus implant June 2020"
		author = "Arkbird_SOLG"
		id = "602c33f2-1e34-5267-9154-ada2d6edc64b"
		date = "2020-06-28"
		modified = "2020-06-28"
		reference = "https://twitter.com/ccxsaber/status/1277064824434745345"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2020-06-28/APT_NK_Lazarus_Implant_June_2020_1.yar#L3-L23"
		license_url = "N/A"
		logic_hash = "29b6b8d3bdd47707854ed0dc00808d6352934950a8e7244450df78422ff3cb15"
		score = 75
		quality = 73
		tags = "FILE"
		hash1 = "21afaceee5fab15948a5a724222c948ad17cad181bf514a680267abcce186831"

	strings:
		$s1 = "Upgrade.exe" fullword ascii
		$s2 = "ver=%d&timestamp=%lu" fullword ascii
		$s3 = "_update.php" fullword ascii
		$s4 = "Dorusio Wallet 2.1.0 (Check Update Windows)" fullword wide
		$s5 = "Content-Type: application/x-www-form-urlencoded" fullword ascii
		$s6 = "CONOUT$" fullword ascii
		$s7 = "D$8fD;i" fullword ascii
		$s8 = "WinHttpOpenRequest" fullword ascii
		$s9 = "HTTP/1.0" fullword ascii
		$s10 = "POST" fullword ascii

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 30KB and ( pe.imphash ( ) == "565005404f00b7def4499142ade5e3dd" or 6 of them )
}

rule ARKBIRD_SOLG_Tool_Screencapture_Jul_2021_1 : FILE
{
	meta:
		description = "Detect Screen Capture utility"
		author = "Arkbird_SOLG"
		id = "09e4295e-454a-519a-964e-c5295e603aef"
		date = "2021-07-09"
		modified = "2021-07-12"
		reference = "https://securelist.com/iamtheking-and-the-slothfulmedia-malware-family/99000/"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-07-11/IAmTheKing/Tool_ScreenCapture_Jul_2021_1.yara#L1-L19"
		license_url = "N/A"
		logic_hash = "dff6c722ec001f5e3b5c53b41f8d457ab69ae46316f5dc7bbf1d00eb3d1ed3c8"
		score = 75
		quality = 73
		tags = "FILE"
		hash1 = "f441e6239b592ac15538a8ba8903e5874283b066050a5a7e514ce33e84237f4e"
		tlp = "White"
		adversary = "IAmTheKing"

	strings:
		$s1 = "@MyScreen.jpg" fullword wide
		$s2 = "DISPLAY" fullword wide
		$s3 = "_invoke_watson" fullword ascii
		$s4 = "GdipSaveImageToStream" fullword ascii
		$s5 = { 8b 57 04 89 4d e8 8d 4d e8 51 52 e8 16 0c 00 00 85 c0 74 03 89 47 08 8b 75 e8 81 fe 00 04 00 00 77 18 56 e8 ac f9 ff ff 83 c4 04 84 c0 74 0b 8b c6 e8 9e 15 00 00 8b f4 eb 35 83 c8 ff 2b c6 83 f8 08 72 15 8d 46 08 50 ff 15 f4 30 40 00 83 c4 04 85 }

	condition:
		uint16( 0 ) == 0x5a4d and ( filesize > 8KB and filesize < 60KB ) and 4 of ( $s* )
}

rule VOLEXITY_Apt_Malware_Win_Flipflop_Ldr : COZYLARCH FILE MEMORY
{
	meta:
		description = "A loader for the CobaltStrike malware family, which ultimately takes the first and second bytes of an embedded file, and flips them prior to executing the resulting payload."
		author = "threatintel@volexity.com"
		id = "58696a6f-55a9-5212-9372-a539cc327e6b"
		date = "2021-05-25"
		modified = "2025-05-21"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2021/2021-05-27 - Suspected APT29 Operation Launches Election Fraud Themed Phishing Campaigns/indicators/yara.yar#L3-L26"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		hash = "ee42ddacbd202008bcc1312e548e1d9ac670dd3d86c999606a3a01d464a2a330"
		logic_hash = "a79d2b0700ae14f7a2af23c8f7df3df3564402b1137478008ccabefea0f543ad"
		score = 75
		quality = 80
		tags = "COZYLARCH, FILE, MEMORY"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 5443
		version = 6

	strings:
		$s1 = "irnjadle"
		$s2 = "BADCFEHGJILKNMPORQTSVUXWZY"
		$s3 = "iMrcsofo taBesC yrtpgoarhpciP orived r1v0."

	condition:
		all of ( $s* )
}

rule VOLEXITY_Apt_Malware_Win_Freshfire : COZYLARCH FILE
{
	meta:
		description = "The FRESHFIRE malware family. The malware acts as a downloader, pulling down an encrypted snippet of code from a remote source, executing it, and deleting it from the remote server."
		author = "threatintel@volexity.com"
		id = "050b8e61-139a-5ff5-998a-7de67c9975bf"
		date = "2021-05-27"
		modified = "2025-05-21"
		reference = "https://www.volexity.com/blog/2021/05/27/suspected-apt29-operation-launches-election-fraud-themed-phishing-campaigns/"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2021/2021-05-27 - Suspected APT29 Operation Launches Election Fraud Themed Phishing Campaigns/indicators/yara.yar#L55-L87"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		hash = "ad67aaa50fd60d02f1378b4155f69cffa9591eaeb80523489a2355512cc30e8c"
		logic_hash = "69cd73f5812ba955c1352fb1552774d5cf49019d6b65a304fd1e33f852e678ba"
		score = 75
		quality = 80
		tags = "COZYLARCH, FILE"
		os = "win"
		os_arch = "all"
		scan_context = "file"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 5459
		version = 9

	strings:
		$uniq1 = "UlswcXJJWhtHIHrVqWJJ"
		$uniq2 = "gyibvmt\x00"
		$path1 = "root/time/%d/%s.json"
		$path2 = "C:\\dell.sdr"
		$path3 = "root/data/%d/%s.json"

	condition:
		(pe.number_of_exports == 1 and pe.exports ( "WaitPrompt" ) ) or any of ( $uniq* ) or 2 of ( $path* )
}

rule VOLEXITY_Apt_Malware_Win_Bluelight : INKYPINE FILE MEMORY
{
	meta:
		description = "The BLUELIGHT malware family. Leverages Microsoft OneDrive for network communications."
		author = "threatintel@volexity.com"
		id = "5bfdc74b-592e-5f3d-9fb8-bbbbd0f6f0f6"
		date = "2021-04-23"
		modified = "2025-02-18"
		reference = "https://www.volexity.com/blog/2021/08/24/north-korean-bluelight-special-inkysquid-deploys-rokrat/"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2021/2021-08-17 - InkySquid Part 1/indicators/yara.yar#L78-L120"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		logic_hash = "45490dfc793bb95f153c0194989b25e0b2641fa9b9f6763d5733eab6483ffead"
		score = 75
		quality = 80
		tags = "INKYPINE, FILE, MEMORY"
		hash1 = "7c40019c1d4cef2ffdd1dd8f388aaba537440b1bffee41789c900122d075a86d"
		hash2 = "94b71ee0861cc7cfbbae53ad2e411a76f296fd5684edf6b25ebe79bf6a2a600a"
		hash3 = "485246b411ef5ea9e903397a5490d106946a8323aaf79e6041bdf94763a0c028"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 5284
		version = 12

	strings:
		$pdb1 = "\\Development\\BACKDOOR\\ncov\\"
		$pdb2 = "Release\\bluelight.pdb" nocase ascii
		$pdb3 = "D:\\Development\\GOLD-BACKDOOR\\Release\\FirstBackdoor.pdb"
		$pdb4 = "GOLD-BACKDOOR\\Release\\"
		$msg0 = "https://ipinfo.io" fullword
		$msg1 = "country" fullword
		$msg5 = "\"UserName\":\"" fullword
		$msg7 = "\"ComName\":\"" fullword
		$msg8 = "\"OS\":\"" fullword
		$msg9 = "\"OnlineIP\":\"" fullword
		$msg10 = "\"LocalIP\":\"" fullword
		$msg11 = "\"Time\":\"" fullword
		$msg12 = "\"Compiled\":\"" fullword
		$msg13 = "\"Process Level\":\"" fullword
		$msg14 = "\"AntiVirus\":\"" fullword
		$msg15 = "\"VM\":\"" fullword

	condition:
		any of ( $pdb* ) or all of ( $msg* )
}

rule VOLEXITY_Apt_Malware_Py_Bluelight_Ldr : INKYPINE FILE
{
	meta:
		description = "Python Loader used to execute the BLUELIGHT malware family."
		author = "threatintel@volexity.com"
		id = "db32b752-eba4-52a6-80b6-d1d394660453"
		date = "2021-06-22"
		modified = "2025-02-18"
		reference = "https://www.volexity.com/blog/2021/08/24/north-korean-bluelight-special-inkysquid-deploys-rokrat/"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2021/2021-08-24 - InkySquid Part 2/indicators/yara.yar#L33-L61"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		logic_hash = "6987f5903561da8d4fa32c8d824593f601a49e13edfa2d617952d57ba3444f76"
		score = 75
		quality = 80
		tags = "INKYPINE, FILE"
		hash1 = "80269413be6ad51b8b19631b2f5559c9572842e789bbce031babe6e879d2e120"
		os = "win"
		os_arch = "all"
		scan_context = "file"
		severity = "high"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 5600
		version = 6

	strings:
		$s1 = "\"\".join(chr(ord(" ascii
		$s2 = "import ctypes" ascii
		$s3 = "ctypes.CFUNCTYPE(ctypes.c_int)" ascii
		$s4 = "ctypes.memmove" ascii
		$magic = "writelines(\"python ended\")" ascii

	condition:
		all of ( $s* ) or $magic
}

rule VOLEXITY_Apt_Malware_Win_Decrok : INKYPINE FILE MEMORY
{
	meta:
		description = "The DECROK malware family, which uses the victim's hostname to decrypt and execute an embedded payload."
		author = "threatintel@volexity.com"
		id = "46be1793-6419-54fe-a78b-5d087e02626e"
		date = "2021-06-23"
		modified = "2023-09-28"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2021/2021-08-24 - InkySquid Part 2/indicators/yara.yar#L62-L90"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		hash = "6a452d088d60113f623b852f33f8f9acf0d4197af29781f889613fed38f57855"
		logic_hash = "a551700943d5abc95af00fc4fefd416ace8d59037852c6bc5caf1d6bd09afd63"
		score = 75
		quality = 80
		tags = "INKYPINE, FILE, MEMORY"
		os = "win"
		os_arch = "x86"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 5606
		version = 4

	strings:
		$v1 = {C7 ?? ?? ?? 01 23 45 67 [2-20] C7 ?? ?? ?? 89 AB CD EF C7 ?? ?? ?? FE DC BA 98}
		$av1 = "Select * From AntiVirusProduct" wide
		$av2 = "root\\SecurityCenter2" wide
		$func1 = "CreateThread"
		$format = "%02x"

	condition:
		all of them and $func1 in ( @format .. @format + 10 )
}

rule VOLEXITY_Apt_Malware_Win_Rokload : INKYPINE FILE
{
	meta:
		description = "A shellcode loader used to decrypt and run an embedded executable."
		author = "threatintel@volexity.com"
		id = "229dbf3c-1538-5ecd-b5f8-8c9a9c81c515"
		date = "2021-06-23"
		modified = "2025-05-21"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2021/2021-08-24 - InkySquid Part 2/indicators/yara.yar#L91-L112"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		hash = "85cd5c3bb028fe6931130ccd5d0b0c535c01ce2bcda660a3b72581a1a5382904"
		logic_hash = "8d65d32fd5bc055ca0e3831d3db88299e7c99f8547a170d3c53ec2c4001496a3"
		score = 75
		quality = 80
		tags = "INKYPINE, FILE"
		os = "win"
		os_arch = "x64"
		scan_context = "file"
		severity = "high"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 5603
		version = 4

	strings:
		$bytes00 = { 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 57 41 54 41 55 41 56 41 57 48 ?? ?? ?? b9 ?? ?? ?? ?? 33 ff e8 ?? ?? ?? ?? b9 ?? ?? ?? ?? 4c 8b e8 e8 ?? ?? ?? ?? 4c 8b f0 41 ff d6 b9 ?? ?? ?? ?? 44 8b f8 e8 ?? ?? ?? ?? 4c 8b e0 e8 ?? ?? ?? ?? 48 }

	condition:
		$bytes00 at 0
}

rule VOLEXITY_Apt_Malware_Apk_Badbazaar_Common_Certificate : EVILBAMBOO FILE
{
	meta:
		description = "Detection of the common.cer file used for a large BADBAZAAR malware cluster for its certificate pinning for the C2 communication."
		author = "threatintel@volexity.com"
		id = "5a033770-7ad3-5c79-90ac-b1e3fff6b5f0"
		date = "2023-06-01"
		modified = "2023-06-13"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2023/2023-09-22 EvilBamboo/indicators/rules.yar#L230-L255"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		logic_hash = "861d4e1c40847c6ade04eddb047370d645afea6d5c16d55155fa58a16111c39e"
		score = 75
		quality = 80
		tags = "EVILBAMBOO, FILE"
		hash1 = "6aefc2b33e23f6e3c96de51d07f7123bd23ff951d67849a9bd32d446e76fb405"
		scan_context = "file"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$b1 = {30 82 03 61 30 82 02 49 a0 03 02 01 02 02 04 2b 6e df 67 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b}
		$s1 = "california1"
		$s2 = "los1"
		$s3 = "tech1"
		$s4 = "common1"
		$s5 = "common0"
		$s6 = "220401234506Z"
		$s7 = "470326234506Z0a1"

	condition:
		$b1 at 0 or all of ( $s* )
}

rule VOLEXITY_Apt_Malware_Apk_Badbazaar_Stage2_Implant_May23 : EVILBAMBOO FILE
{
	meta:
		description = "Detection of the second stage capability of the BadBazaar android malware that has the main malicious capabilities. Will gather various info about the user/phone and routinely send this to the C2."
		author = "threatintel@volexity.com"
		id = "1f97c610-773f-5385-935a-445cb9192157"
		date = "2023-05-25"
		modified = "2023-08-30"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2023/2023-09-22 EvilBamboo/indicators/rules.yar#L257-L285"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		logic_hash = "2186369298ebfa0b892ecb14ebacc93c6d14c9c35012e8e6cdff077634cf3773"
		score = 75
		quality = 80
		tags = "EVILBAMBOO, FILE"
		hash1 = "bf5f7fbf42236e89bcf663d2822d54bee89abaf3f247a54f371bf156e0e03629"
		scan_context = "file"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$c1 = "%{\"command\":\"%s\",\"path\":\"%s\",\"files\":["
		$c2 = "{\"name\":\"%s\",\"dirs\":\"%d\",\"files\":\"%d\",\"isfolder\":\"%d\",\"path\":\"%s\"},"
		$s1 = "Timezon id:"
		$s2 = "China Telecom"
		$s3 = "China Unicom"
		$s4 = "ConfigPipe"
		$s5 = "ForwordTo"
		$s6 = "can't get camera content"
		$s7 = "cat /sys/class/net/wlan0/address"
		$s8 = "_preferences_light"
		$s9 = "registration_jid"

	condition:
		1 of ( $c* ) or 5 of ( $s* )
}

rule VOLEXITY_Apt_Delivery_Web_Js_Jmask_Str_Array_Variant : EVILBAMBOO FILE
{
	meta:
		description = "Detects the JMASK profiling script in an obfuscated format using a string array and an offset."
		author = "threatintel@volexity.com"
		id = "d5d32c8b-53fb-5103-ac73-05f320e71c97"
		date = "2023-06-27"
		modified = "2023-09-21"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2023/2023-09-22 EvilBamboo/indicators/rules.yar#L408-L444"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		logic_hash = "0ae7c96e0f866f21d66d7a23bf937d6ce48c9dd1ea19142dbb13487208780146"
		score = 75
		quality = 80
		tags = "EVILBAMBOO, FILE"
		hash1 = "7995c382263f8dbbfc37a9d62392aef8b4f89357d436b3dd94dea842f9574ecf"
		scan_context = "file"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$array_1 = "http://eular.github.io"
		$array_2 = "stun:stun.services.mozilla.com"
		$array_3 = "\xE6\x9C\xAA\xE5\xAE\x89\xE8\xA3\x85MetaMask"
		$array_4 = "/jquery/jquery.min.js"
		$array_5 = "onicecandidate"
		$ios_1 = "['a7', '640x1136', [_0x"
		$ios_2 = "['a7', _0x"
		$ios_3 = "['a8', _0x"
		$ios_4 = "['a8', '750x1334', ['iPhone\\x206']]"
		$ios_5 = "['a8', '1242x2208', ['iPhone\\x206\\x20Plus']]"
		$ios_6 = "['a8', _0x"
		$ios_7 = "['a9', _0x"
		$ios_8 = "['a9', '750x1334', [_0x"
		$ios_9 = "['a9', '1242x2208', ['iPhone\\x206s\\x20Plus']]"
		$ios_10 = "['a9x', '2048x2732', ['iPad\\x20Pro\\x20(1st\\x20gen\\x2012.9-inch)']]"
		$ios_11 = "['a10x', '1668x2224', [_0x"
		$header = "info = {}, finished = 0x0;"

	condition:
		3 of ( $array_* ) or 5 of ( $ios_* ) or $header
}

rule VOLEXITY_Apt_Delivery_Web_Js_Jmask : EVILBAMBOO FILE
{
	meta:
		description = "Detects the JMASK profiling script in its minified // obfuscated format."
		author = "threatintel@volexity.com"
		id = "a7b653e1-f7c6-56cc-ab99-3de91d29ef3b"
		date = "2023-06-15"
		modified = "2023-09-21"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2023/2023-09-22 EvilBamboo/indicators/rules.yar#L446-L472"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		logic_hash = "64315ac05049954d36297a616a25ffdd7ce81c6313c0878d5ba4082da24c21bb"
		score = 75
		quality = 80
		tags = "EVILBAMBOO, FILE"
		hash1 = "efea95720853e0cd2d9d4e93a64a726cfe17efea7b17af7c4ae6d3a6acae5b30"
		scan_context = "file"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$rev0 = "oi.buhtig.ralue//:ptth" ascii
		$rev1 = "lairA' xp41" ascii
		$rev2 = "dnuof ton ksaMateM" ascii
		$unicode1 = "document[\"\\u0063\\u0075\\u0072\\u0072\\u0065\\u006e\\u0074\\u0053\\u0063\\u0072\\u0069\\u0070\\u0074\"]" ascii
		$unicode2 = "\\u0061\\u0070\\u0070\\u006c\\u0069\\u0063\\u0061\\u0074\\u0069\\u006f\\u006e\\u002f\\u006a\\u0073\\u006f\\u006e" ascii
		$unicode3 = "\\u0063\\u006c\\u0069\\u0065\\u006e\\u0074\\u0057\\u0069\\u0064\\u0074\\u0068" ascii
		$unicode4 = "=window[\"\\u0073\\u0063\\u0072\\u0065\\u0065\\u006e\"]" ascii
		$header = "(function(){info={};finished=" ascii

	condition:
		all of ( $rev* ) or all of ( $unicode* ) or $header
}

rule VOLEXITY_Apt_Win_Powerstar_Persistence_Batch : CHARMINGKITTEN
{
	meta:
		description = "Detects the batch script used to persist PowerStar via Startup."
		author = "threatintel@volexity.com"
		id = "f3ed7b46-d80d-55b1-b6c7-6ea6569f199c"
		date = "2023-05-16"
		modified = "2023-09-20"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2023/2023-06-28 POWERSTAR/indicators/rules.yar#L1-L19"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		logic_hash = "9c3a45b759516959eae1cdf8e73bf540b682c90359a6232aa4782a8d1fe15b7d"
		score = 75
		quality = 80
		tags = "CHARMINGKITTEN"
		hash1 = "9777f106ac62829cd3cfdbc156100fe892cfc4038f4c29a076e623dc40a60872"
		memory_suitable = 1
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$s_1 = "e^c^h^o o^f^f"
		$s_2 = "powershertxdll.ertxdxe"
		$s_3 = "Get-Conrtxdtent -Prtxdath"
		$s_4 = "%appdata%\\Microsrtxdoft\\Windortxdws\\"
		$s_5 = "&(gcm i*x)$"

	condition:
		3 of them
}

rule VOLEXITY_Apt_Win_Powerstar_Memonly : CHARMINGKITTEN
{
	meta:
		description = "Detects the initial stage of the memory only variant of PowerStar."
		author = "threatintel@volexity.com"
		id = "469fc433-da9e-55ed-99fb-9560ec86a179"
		date = "2023-05-16"
		modified = "2023-09-20"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2023/2023-06-28 POWERSTAR/indicators/rules.yar#L20-L65"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		logic_hash = "d790ff204e4e8adeb3e887d9ebce743e958b523c48317d017487b1b0c6aebc11"
		score = 75
		quality = 78
		tags = "CHARMINGKITTEN"
		hash1 = "977cf5cc1d0c61b7364edcf397e5c67d910fac628c6c9a41cf9c73b3720ce67f"
		memory_suitable = 1
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$s_1 = "[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($in.substring(3)))"
		$s_2 = "[Convert]::ToByte(([Convert]::ToString(-bnot ($text_bytes[$i])"
		$s_3 = "$Exec=[System.Text.Encoding]::UTF8.GetString($text_bytes)"
		$s_4 = "((65..90) + (97..122) | Get-Random -Count 16 | % {[char]$_})"
		$f_1 = "function Gorjol{"
		$f_2 = "Borjol \"$"
		$f_3 = "Gorjol -text"
		$f_4 = "function Borjoly{"
		$f_6 = "$filename = $env:APPDATA+\"\\Microsoft\\Windows\\DocumentPreview.pdf\";"
		$f_7 = "$env:APPDATA+\"\\Microsoft\\Windows\\npv.txt\""
		$f_8 = "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\brt8ts74e.bat"
		$f_9 = "\\Microsoft\\Windows\\s7qe52.txt"
		$f_10 = "$yeolsoe2 = $yeolsoe"
		$f_11 = "setRequestHeader(\"Content-DPR\""
		$f_12 = "getResponseHeader(\"Content-DPR\")"
		$f_13 = {24 43 6f 6d 6d 61 6e 64 50 61 72 74 73 20 3d 24 53 65 73 73 69 6f 6e 52 65 73 70 6f 6e 73 65 2e 53 70 6c 69 74 28 22 b6 22 29}
		$f_14 = "$language -like \"*shar*\""
		$f_15 = "$language -like \"*owers*\""
		$alias_1 = "(gcm *v????E?P?e*)"
		$alias_2 = "&(gcm *ke-e*) $Command"
		$key = "T2r0y1M1e1n1o0w1"
		$args_1 = "$sem.Close()"
		$args_2 = "$cem.Close()"
		$args_3 = "$mem.Close()"
		$command_1 = "_____numone_____"
		$command_2 = "_____mac2_____"
		$command_3 = "_____yeolsoe_____"

	condition:
		2 of ( $s_* ) or any of ( $f_* ) or 2 of ( $alias_* ) or $key or all of ( $args_* ) or any of ( $command_* )
}

rule VOLEXITY_Apt_Win_Powerstar_Logmessage : CHARMINGKITTEN
{
	meta:
		description = "Detects interesting log message embedded in memory only version of PowerStar."
		author = "threatintel@volexity.com"
		id = "5979c776-5138-50e2-adab-0793ad86ba76"
		date = "2023-05-16"
		modified = "2023-09-20"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2023/2023-06-28 POWERSTAR/indicators/rules.yar#L66-L79"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		logic_hash = "539c9a8b3de24f2c8058d204900344756a8031822ebebc312612b8fb8422e341"
		score = 75
		quality = 80
		tags = "CHARMINGKITTEN"
		memory_suitable = 1
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$s_1 = "wau, ije ulineun mueos-eul halkkayo?"

	condition:
		all of them
}

rule VOLEXITY_Apt_Win_Powerstar_Lnk : CHARMINGKITTEN
{
	meta:
		description = "Detects LNK command line used to install PowerStar."
		author = "threatintel@volexity.com"
		id = "33f16283-69b9-5109-b723-3ddc8abb8c41"
		date = "2023-05-16"
		modified = "2023-09-20"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2023/2023-06-28 POWERSTAR/indicators/rules.yar#L80-L97"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		logic_hash = "da53aeaf69e80f697068779f4741b8c23cff82dd1bfb0640916a1bcc98c4892f"
		score = 75
		quality = 80
		tags = "CHARMINGKITTEN"
		memory_suitable = 1
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$p_1 = "-UseBasicParsing).Content; &(gcm i*x)$"
		$c_1 = "powershecde43ell.ecde43exe"
		$c_2 = "wgcde43eet -Ucde43eri"
		$c_3 = "-UseBasicde43ecParsing).Contcde43eent; &(gcm i*x)$"

	condition:
		any of them
}

rule VOLEXITY_Apt_Win_Powerstar_Decrypt_Function : CHARMINGKITTEN
{
	meta:
		description = "Detects PowerStar decrypt function, potentially downloaded standalone and then injected."
		author = "threatintel@volexity.com"
		id = "1fbc2689-8169-53b1-b581-c41ab2b3a16f"
		date = "2023-05-16"
		modified = "2023-09-20"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2023/2023-06-28 POWERSTAR/indicators/rules.yar#L98-L121"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		logic_hash = "d022e363464488836a1c161f2b9c7463ac91ae6f60f14dfd574189233201c9aa"
		score = 75
		quality = 80
		tags = "CHARMINGKITTEN"
		hash1 = "b79d28fe5e3c988bb5aadb12ce442d53291dbb9ede0c7d9d64eec078beba5585"
		memory_suitable = 1
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$f_1 = "function Borjol{"
		$s_1 = "$global:Domain = \""
		$s_2 = "$global:IP = \""
		$s_3 = "$global:yeolsoe"
		$s_4 = "$semii.Close()"
		$s_5 = "$cemii.Close()"
		$s_6 = "$memii.Close()"

	condition:
		any of ( $f_* ) or 2 of ( $s_* )
}

rule VOLEXITY_Apt_Win_Powerstar : CHARMINGKITTEN
{
	meta:
		description = "Custom PowerShell backdoor used by Charming Kitten."
		author = "threatintel@volexity.com"
		id = "febcd23b-6545-571b-905d-18dffe8e913f"
		date = "2021-10-13"
		modified = "2023-09-20"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2023/2023-06-28 POWERSTAR/indicators/rules.yar#L122-L150"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		logic_hash = "2cbf59eaee60a8f84b1ac35cec3b01592a2a0f56c92a2db218bb26a15be24bf3"
		score = 75
		quality = 80
		tags = "CHARMINGKITTEN"
		hash1 = "de99c4fa14d99af791826a170b57a70b8265fee61c6b6278d3fe0aad98e85460"
		memory_suitable = 1
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$appname = "[AppProject.Program]::Main()" ascii wide
		$langfilters1 = "*shar*" ascii wide
		$langfilters2 = "*owers*" ascii wide
		$definitions1 = "[string]$language" ascii wide
		$definitions2 = "[string]$Command" ascii wide
		$definitions3 = "[string]$ThreadName" ascii wide
		$definitions4 = "[string]$StartStop" ascii wide
		$sess = "$session = $v + \";;\" + $env:COMPUTERNAME + $mac;" ascii wide

	condition:
		$appname or all of ( $langfilters* ) or all of ( $definitions* ) or $sess
}

rule VOLEXITY_Apt_Ico_Uta0040_B64_C2 : UTA0040 FILE
{
	meta:
		description = "Detection of malicious ICO files used in 3CX compromise."
		author = "threatintel@volexity.com"
		id = "1efb6376-a362-5f03-b4d3-08cd7d634de6"
		date = "2023-03-30"
		modified = "2023-03-30"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2023/2023-03-30 3CX/indicators/rules.yar#L1-L31"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		logic_hash = "2667a36ce151c6e964f9ce9a6f587eedbffdd6ec76e451a23c5cfdd08248d15e"
		score = 75
		quality = 80
		tags = "UTA0040, FILE"
		hash1 = "a541e5fc421c358e0a2b07bf4771e897fb5a617998aa4876e0e1baa5fbb8e25c"
		memory_suitable = 0
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$IEND_dollar = {49 45 4e 44 ae 42 60 82 24}
		$IEND_nodollar = {49 45 4e 44 ae 42 60 82 }

	condition:
		uint16be( 0 ) == 0x0000 and filesize < 120KB and ( $IEND_dollar in ( filesize -500 .. filesize ) and not $IEND_nodollar in ( filesize -20 .. filesize ) and for any k in ( 1 .. #IEND_dollar ) : ( for all i in ( 1 .. 4 ) : ( uint8( @IEND_dollar [ k ] + !IEND_dollar [ k ] + i ) < 123 and uint8( @IEND_dollar [ k ] + !IEND_dollar [ k ] + i ) > 47 ) ) )
}

rule VOLEXITY_Apt_Mac_Iconic : UTA0040
{
	meta:
		description = "Detects the MACOS version of the ICONIC loader."
		author = "threatintel@volexity.com"
		id = "6d702ed3-e5b9-5324-a06b-507c9231cc00"
		date = "2023-03-30"
		modified = "2023-03-30"
		reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2023/2023-03-30 3CX/indicators/rules.yar#L32-L50"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		logic_hash = "7b689c3931632b01869ac2f21a1edca0a5ca9007299fe7cd16962d6866c27558"
		score = 75
		quality = 80
		tags = "UTA0040"
		hash1 = "a64fa9f1c76457ecc58402142a8728ce34ccba378c17318b3340083eeb7acc67"
		memory_suitable = 1
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$str1 = "3CX Desktop App" xor(0x01-0xff)
		$str2 = "__tutma=" xor(0x01-0xff)
		$str3 = "Mozilla/5.0" xor(0x01-0xff)

	condition:
		all of them
}

rule VOLEXITY_Apt_Win_Iconicstealer : UTA0040
{
	meta:
		description = "Detect the ICONICSTEALER malware family."
		author = "threatintel@volexity.com"
		id = "d7896506-6ce5-59b1-b24a-87ffdb2a5174"
		date = "2023-03-30"
		modified = "2023-03-30"
		reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2023/2023-03-30 3CX/indicators/rules.yar#L51-L69"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		logic_hash = "ed7731d2361e7d96a6a35f8359b61a2af049b16bc457cf870db8831e142aebe2"
		score = 75
		quality = 80
		tags = "UTA0040"
		hash1 = "8ab3a5eaaf8c296080fadf56b265194681d7da5da7c02562953a4cb60e147423"
		memory_suitable = 1
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$str1 = "\\3CXDesktopApp\\config.json" wide
		$str2 = "url, title FROM urls" wide
		$str3 = "url, title FROM moz_places" wide

	condition:
		all of them
}

rule VOLEXITY_Apt_Malware_Win_Avburner : DEVIOUSBAMBOO FILE MEMORY
{
	meta:
		description = "Detects AVBurner based on a combination of API calls used, hard-coded strings and bytecode patterns."
		author = "threatintel@volexity.com"
		id = "1bde0861-4820-5bb1-98a3-516092c91be0"
		date = "2023-01-02"
		modified = "2024-08-16"
		reference = "https://www.trendmicro.com/en_us/research/22/k/hack-the-real-box-apt41-new-subgroup-earth-longzhi.html"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2023/2023-03-07 AVBurner/yara.yar#L1-L40"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		hash = "4b1b1a1293ccd2c0fd51075de9376ebb55ab64972da785153fcb0a4eb523a5eb"
		logic_hash = "56ff6c8a4b737959a1219699a0457de1f0c34fead4299033840fb23c56a0caad"
		score = 75
		quality = 80
		tags = "DEVIOUSBAMBOO, FILE, MEMORY"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 8780
		version = 4

	strings:
		$api1 = "PspCreateProcessNotifyRoutineAddress" wide
		$api2 = "PspCreateThreadNotifyRoutineAddress" wide
		$api3 = "PspLoadImageNotifyRoutineAddress" wide
		$str1 = "\\\\.\\RTCORE64" wide
		$str2 = "\\\\%ws/pipe/%ws" wide
		$str3 = "CreateServerW Failed %u" wide
		$str4 = "OpenSCManager Failed %u" wide
		$str5 = "Get patternAddress" wide
		$pattern1 = { 4C 8B F9 48 8D 0C C1 E8 }
		$pattern2 = { 48 8D 0C DD 00 00 00 00  45 33 C0 49 03 CD 48 8B }
		$pattern3 = { 48 8D 04 C1 48 89 45 70 48 8B C8 E8 }
		$pattern4 = { 49 8D 0C FC 45 33 C0 48 8B D6 E8 00 00 00 00 00}
		$pattern5 = { 45 33 C0 48 8D 0C D9 48 8B D7 E8 00 00 00 00 00 00 00 00 00 00 00 00 00 }
		$pattern6 = { 41 0F BA 6D 00 0A BB 01 00 00 00 4C 8B F2 4C 8B F9 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

	condition:
		all of ( $api* ) or all of ( $str* ) or all of ( $pattern* )
}

rule VOLEXITY_Apt_Malware_Golang_Govershell_Strings_UTA0388 : UTA0388 FILE MEMORY
{
	meta:
		description = "This rule detects multiple variants of the GOVERSHELL malware family employed by UTA0388 via unique strings. The implant is side-loaded by a legitimate executable and uses various network protocol to communicate with the C2 server."
		author = "threatintel@volexity.com"
		id = "1fe9b2b8-5c74-5d3c-954b-37f625911f75"
		date = "2025-06-30"
		modified = "2025-10-08"
		reference = "TIB-20250708B"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2025/2025-10-08 UTA0388/rules.yar#L74-L134"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		logic_hash = "74fa940002e0af9095790b1cf7260778661c97db4e3d316183eecde0e2b580a8"
		score = 75
		quality = 78
		tags = "UTA0388, FILE, MEMORY"
		hash1 = "a5ee55a78d420dbba6dec0b87ffd7ad6252628fd4130ed4b1531ede960706d2d"
		hash2 = "fbade9d8a040ed643b68e25e19cba9562d2bd3c51d38693fe4be72e01da39861"
		os = "win"
		os_arch = "all"
		report2 = "MAR-20250930"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 11993
		version = 10

	strings:
		$a1 = "/lib/te64/"
		$a2 = "te64/payload."
		$a3 = "payload.sendAuthRequest.Println.func1"
		$a4 = "sendAuthRequest.deferwrap"
		$a5 = ".ensureSingleInstance.Printf."
		$a6 = "httpslike.NewHttpsLikeConn"
		$a7 = "main.Execute.Println."
		$a8 = "C:/Users/Dev/Desktop/20250608"
		$a9 = "/lib/te64/httpslike/httpslike.go"
		$a10 = "/lib/te64/payload/payload.go"
		$a11 = "/lib/te64/main.go"
		$a12 = "'rootFolderObj"
		$a13 = "'triggersObj"
		$a14 = "'repetitionObj"
		$a15 = "httpslike"
		$a16 = "main.CopySelf.copyDir."
		$s1 = "C:/Users/Make/Downloads/te250608/lib/te64/payload"
		$s2 = "te64/payload."
		$s3 = "C:/Users/Make/Desktop/lib/"
		$s4 = "CreateUserTask.deferwrap"
		$s5 = "main.generateRandomDir"
		$s6 = "te64.dll"
		$s7 = "payload.NewHttpClient.ProxyURL."
		$s8 = "payload.normalizeProxyURL"
		$b1 = {27 70 72 6f 67 72 61 6d 44 61 74 61 00}
		$b2 = {27 72 61 6e 64 6f 6d 44 69 72 00}
		$b3 = {27 74 61 72 67 65 74 44 69 72 00}
		$b4 = {27 65 78 65 50 61 74 68 00}
		$b5 = {27 63 75 72 72 65 6e 74 44 69 72 00}
		$b6 = {27 65 78 65 4e 61 6d 65 00}
		$b7 = {27 74 61 72 67 65 74 45 78 65 00}
		$b8 = {27 72 65 6c 50 61 74 68 00}

	condition:
		4 of ( $a* ) or 5 of ( $s* ) or 3 of ( $b* )
}

rule VOLEXITY_Apt_Malware_Macos_Gimmick : STORMBAMBOO FILE MEMORY
{
	meta:
		description = "Detects the macOS port of the GIMMICK malware."
		author = "threatintel@volexity.com"
		id = "3d485788-4aab-511b-a49e-5dc09d1950a9"
		date = "2021-10-18"
		modified = "2024-08-02"
		reference = "https://www.volexity.com/blog/2022/03/22/storm-cloud-on-the-horizon-gimmick-malware-strikes-at-macos/"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2022/2022-03-22 GIMMICK/indicators/yara.yar#L1-L59"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		logic_hash = "00fba9df2212874a45d44b3d098a7b76c97fcd53ff083c76b784d2b510a4a467"
		score = 75
		quality = 78
		tags = "STORMBAMBOO, FILE, MEMORY"
		hash1 = "2a9296ac999e78f6c0bee8aca8bfa4d4638aa30d9c8ccc65124b1cbfc9caab5f"
		os = "darwin"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 6022
		version = 8

	strings:
		$s1 = "http://cgi1.apnic.net/cgi-bin/my-ip.php --connect-timeout 10 -m 20" wide ascii
		$json1 = "base_json" ascii wide
		$json2 = "down_json" ascii wide
		$json3 = "upload_json" ascii wide
		$json4 = "termin_json" ascii wide
		$json5 = "request_json" ascii wide
		$json6 = "online_json" ascii wide
		$json7 = "work_json" ascii wide
		$msg1 = "bash_pid: %d, FDS_CHILD: %d, FDS_PARENT: %d" ascii wide
		$msg2 = "pid %d is dead" ascii wide
		$msg3 = "exit with code %d" ascii wide
		$msg4 = "recv signal %d" ascii wide
		$cmd1 = "ReadCmdQueue" ascii wide
		$cmd2 = "read_cmd_server_timer" ascii wide
		$cmd3 = "enableProxys" ascii wide
		$cmd4 = "result_block" ascii wide
		$cmd5 = "createDirLock" ascii wide
		$cmd6 = "proxyLock" ascii wide
		$cmd7 = "createDirTmpItem" ascii wide
		$cmd8 = "dowfileLock" ascii wide
		$cmd9 = "downFileTmpItem" ascii wide
		$cmd10 = "filePathTmpItem" ascii wide
		$cmd11 = "uploadItems" ascii wide
		$cmd12 = "downItems" ascii wide
		$cmd13 = "failUploadItems" ascii wide
		$cmd14 = "failDownItems" ascii wide
		$cmd15 = "downloadCmds" ascii wide
		$cmd16 = "uploadFiles" ascii wide
		$cmd17 = "bash callback...." ascii wide

	condition:
		$s1 or 5 of ( $json* ) or 3 of ( $msg* ) or 9 of ( $cmd* )
}

rule VOLEXITY_Apt_Malware_Win_Gimmick_Dotnet_Base : STORMBAMBOO FILE MEMORY
{
	meta:
		description = "Detects the base version of GIMMICK written in .NET."
		author = "threatintel@volexity.com"
		id = "be42d85f-3143-51d3-b148-95d0ae666771"
		date = "2020-03-16"
		modified = "2024-08-19"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2022/2022-03-22 GIMMICK/indicators/yara.yar#L60-L86"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		logic_hash = "39a38ea189d5e840f9334cb7ec8f390444139b39c6f426906a8845f9a1ada9f7"
		score = 75
		quality = 80
		tags = "STORMBAMBOO, FILE, MEMORY"
		hash1 = "b554bfe4c2da7d0ac42d1b4f28f4aae854331fd6d2b3af22af961f6919740234"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 6628
		version = 3

	strings:
		$other1 = "srcStr is null" wide
		$other2 = "srcBs is null " wide
		$other3 = "Key cannot be null" wide
		$other4 = "Faild to get target constructor, targetType=" wide
		$other5 = "hexMoudule(public key) cannot be null or empty." wide
		$other6 = "https://oauth2.googleapis.com/token" wide

	condition:
		5 of ( $other* )
}

rule VOLEXITY_Apt_Malware_Js_Sharpext : SHARPPINE FILE MEMORY
{
	meta:
		description = "A malicious Chrome browser extension used by the SharpPine threat actor to steal Gmail data from a victim."
		author = "threatintel@volexity.com"
		id = "61b5176a-ff73-5fce-bc70-c9e09bb5afed"
		date = "2021-09-14"
		modified = "2025-05-21"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2022/2022-07-28 SharpTongue SharpTongue Deploys Clever Mail-Stealing Browser Extension SHARPEXT/yara.yar#L1-L52"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		logic_hash = "0ed58c8646582ee36aeac650fac02d1e4962d45c0f6a24783c021d9267bed192"
		score = 75
		quality = 80
		tags = "SHARPPINE, FILE, MEMORY"
		hash1 = "1c9664513fe226beb53268b58b11dacc35b80a12c50c22b76382304badf4eb00"
		hash2 = "6025c66c2eaae30c0349731beb8a95f8a5ba1180c5481e9a49d474f4e1bb76a4"
		hash3 = "6594b75939bcdab4253172f0fa9066c8aee2fa4911bd5a03421aeb7edcd9c90c"
		os = "all"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 5916
		version = 5

	strings:
		$s1 = "\"mode=attach&name=\"" ascii
		$s2 = "\"mode=new&mid=\"" ascii
		$s3 = "\"mode=attlist\"" ascii
		$s4 = "\"mode=list\"" ascii
		$s5 = "\"mode=domain\"" ascii
		$s6 = "\"mode=black\"" ascii
		$s7 = "\"mode=newD&d=\"" ascii
		$mark1 = "chrome.runtime.onMessage.addListener" ascii
		$mark2 = "chrome.webNavigation.onCompleted.addListener" ascii
		$enc1 = "function BSue(string){" ascii
		$enc2 = "function BSE(input){" ascii
		$enc3 = "function bin2hex(byteArray)" ascii
		$xhr1 = ".send(\"mode=cd1" ascii
		$xhr2 = ".send(\"mode=black" ascii
		$xhr3 = ".send(\"mode=domain" ascii
		$xhr4 = ".send(\"mode=list" ascii
		$manifest1 = "\"description\":\"advanced font\"," ascii
		$manifest2 = "\"scripts\":[\"bg.js\"]" ascii
		$manifest3 = "\"devtools_page\":\"dev.html\"" ascii

	condition:
		(5 of ( $s* ) and all of ( $mark* ) ) or all of ( $enc* ) or 3 of ( $xhr* ) or 2 of ( $manifest* )
}

rule VOLEXITY_Apt_Malware_Win_Applejeus_Oct22 : LAZYPINE FILE MEMORY
{
	meta:
		description = "Detects AppleJeus DLL samples."
		author = "threatintel@volexity.com"
		id = "f88e2253-e296-57d8-a627-6cb4ccff7a92"
		date = "2022-11-03"
		modified = "2025-05-21"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2022/2022-12-01 Buyer Beware - Fake Cryptocurrency Applications Serving as Front for AppleJeus Malware/yara.yar#L1-L22"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		logic_hash = "46f3325a7e8e33896862b1971f561f4871670842aecd46bcc7a5a1af869ecdc4"
		score = 75
		quality = 80
		tags = "LAZYPINE, FILE, MEMORY"
		hash1 = "82e67114d632795edf29ce1d50a4c1c444846d9e16cd121ce26e63c8dc4a1629"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 8495
		version = 3

	strings:
		$s1 = "HijackingLib.dll" ascii

	condition:
		$s1
}

rule VOLEXITY_Apt_Malware_Win_Applejeus_B_Oct22 : LAZYPINE FILE MEMORY
{
	meta:
		description = "Detects unpacked AppleJeus samples."
		author = "threatintel@volexity.com"
		id = "8586dc64-225b-5f28-a6d6-b9b6e8f1c815"
		date = "2022-11-03"
		modified = "2025-05-21"
		reference = "https://www.volexity.com/blog/2022/12/01/buyer-beware-fake-cryptocurrency-applications-serving-as-front-for-applejeus-malware/"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2022/2022-12-01 Buyer Beware - Fake Cryptocurrency Applications Serving as Front for AppleJeus Malware/yara.yar#L24-L54"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		logic_hash = "76f3c9692ea96d3cadbbcad03477ab6c53445935352cb215152b9b5483666d43"
		score = 75
		quality = 80
		tags = "LAZYPINE, FILE, MEMORY"
		hash1 = "9352625b3e6a3c998e328e11ad43efb5602fe669aed9c9388af5f55fadfedc78"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 8497
		version = 5

	strings:
		$key1 = "AppX7y4nbzq37zn4ks9k7amqjywdat7d"
		$key2 = "Gd2n5frvG2eZ1KOe"
		$str1 = "Windows %d(%d)-%s"
		$str2 = "&act=check"

	condition:
		( any of ( $key* ) and 1 of ( $str* ) ) or all of ( $str* )
}

rule VOLEXITY_Apt_Malware_Win_Applejeus_C_Oct22 : LAZYPINE MEMORY
{
	meta:
		description = "Detects unpacked AppleJeus samples."
		author = "threatintel@volexity.com"
		id = "c9cbddde-220c-5e26-8760-85c29b98bfeb"
		date = "2022-11-03"
		modified = "2023-09-28"
		reference = "https://www.volexity.com/blog/2022/12/01/buyer-beware-fake-cryptocurrency-applications-serving-as-front-for-applejeus-malware/"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2022/2022-12-01 Buyer Beware - Fake Cryptocurrency Applications Serving as Front for AppleJeus Malware/yara.yar#L57-L84"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		logic_hash = "a9e635d9353c8e5c4992beba79299fb889a7a3d5bc3eaf191f8bb7f51258a6c6"
		score = 75
		quality = 80
		tags = "LAZYPINE, MEMORY"
		hash1 = "a0db8f8f13a27df1eacbc01505f311f6b14cf9b84fbc7e84cb764a13f001dbbb"
		os = "win"
		os_arch = "all"
		scan_context = "memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 8519
		version = 3

	strings:
		$str1 = "%sd.e%sc \"%s > %s 2>&1\"" wide
		$str2 = "tuid"
		$str4 = "payload"
		$str5 = "fconn"
		$str6 = "Mozilla_%lu"

	condition:
		5 of ( $str* )
}

rule VOLEXITY_Apt_Malware_Win_Applejeus_D_Oct22 : LAZYPINE FILE MEMORY
{
	meta:
		description = "Detected AppleJeus unpacked samples."
		author = "threatintel@volexity.com"
		id = "80d2821b-a437-573e-9e9d-bf79f9422cc9"
		date = "2022-11-10"
		modified = "2025-05-21"
		reference = "https://www.volexity.com/blog/2022/12/01/buyer-beware-fake-cryptocurrency-applications-serving-as-front-for-applejeus-malware/"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2022/2022-12-01 Buyer Beware - Fake Cryptocurrency Applications Serving as Front for AppleJeus Malware/yara.yar#L87-L112"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		logic_hash = "23c0642e5be15a75a39d089cd52f2f14d633f7af6889140b9ec6e53c5c023974"
		score = 75
		quality = 80
		tags = "LAZYPINE, FILE, MEMORY"
		hash1 = "a241b6611afba8bb1de69044115483adb74f66ab4a80f7423e13c652422cb379"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 8534
		version = 3

	strings:
		$reg = "Software\\Bitcoin\\Bitcoin-Qt"
		$pattern = "%s=%d&%s=%s&%s=%s&%s=%d"
		$exec = " \"%s\", RaitingSetupUI "
		$http = "Accept: */*" wide

	condition:
		all of them
}

rule VOLEXITY_Apt_Delivery_Macro_Lazypine_Jeus_B : LAZYPINE FILE
{
	meta:
		description = "Detects macros used by the LazyPine threat actor to distribute AppleJeus."
		author = "threatintel@volexity.com"
		id = "ac4d4e82-e29f-5134-999d-b8dcef59d285"
		date = "2022-11-03"
		modified = "2025-05-21"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2022/2022-12-01 Buyer Beware - Fake Cryptocurrency Applications Serving as Front for AppleJeus Malware/yara.yar#L114-L139"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		logic_hash = "e55199e6ad26894f98e930cd4716127ee868872d08ada1c44675e4db1ec27894"
		score = 75
		quality = 80
		tags = "LAZYPINE, FILE"
		hash1 = "17e6189c19dedea678969e042c64de2a51dd9fba69ff521571d63fd92e48601b"
		os = "win"
		os_arch = "all"
		scan_context = "file"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 8493
		version = 3

	strings:
		$a1 = ", vbDirectory) = \"\" Then" ascii
		$a2 = ".Caption & " ascii
		$a3 = ".nodeTypedValue" ascii
		$a4 = ".Application.Visible = False" ascii
		$a5 = " MkDir (" ascii

	condition:
		all of ( $a* )
}

rule VOLEXITY_Apt_Delivery_Office_Macro_Lazypine_Jeus : LAZYPINE FILE
{
	meta:
		description = "Detects malicious documents used by LazyPine in a campaign dropping the AppleJeus malware."
		author = "threatintel@volexity.com"
		id = "f9a92f47-aa1d-56ea-ac59-47cc559f379f"
		date = "2022-11-02"
		modified = "2025-05-21"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2022/2022-12-01 Buyer Beware - Fake Cryptocurrency Applications Serving as Front for AppleJeus Malware/yara.yar#L141-L165"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		logic_hash = "54d5396b889a45d81122301eadf77f73135937fbe9647ad60491ac7856faf5ad"
		score = 75
		quality = 80
		tags = "LAZYPINE, FILE"
		hash1 = "17e6189c19dedea678969e042c64de2a51dd9fba69ff521571d63fd92e48601b"
		os = "all"
		os_arch = "all"
		scan_context = "file"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 8490
		version = 7

	strings:
		$s1 = "0M8R4K" ascii
		$s2 = "bin.base64" ascii
		$s3 = "dragon" ascii
		$s4 = "Workbook_Open" ascii

	condition:
		all of ( $s* )
}

rule VOLEXITY_Apt_Malware_Linux_Disgomoji_Modules : TRANSPARENTJASMINE FILE MEMORY
{
	meta:
		description = "Detects DISGOMOJI modules using strings in the ELF."
		author = "threatintel@volexity.com"
		id = "b9e4ecdc-9b02-546f-9b79-947cb6b1f99a"
		date = "2024-02-22"
		modified = "2024-07-05"
		reference = "TIB-20240229"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2024/2024-06-13 DISGOMOJI/indicators/rules.yar#L1-L24"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		logic_hash = "7880288e3230b688b780bdfbac2b0761fd7831b7df233672c2242c21a86e1297"
		score = 75
		quality = 80
		tags = "TRANSPARENTJASMINE, FILE, MEMORY"
		hash1 = "2abaae4f6794131108adf5b42e09ee5ce24769431a0e154feabe6052cfe70bf3"
		os = "linux"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10270
		version = 6

	strings:
		$s1 = "discord-c2/test/main/finalizing/Deliveries/ob_Delivery.go" wide ascii
		$s2 = "discord-c2/test/main/finalizing/WAN_Conf.go" wide ascii

	condition:
		any of them
}

rule VOLEXITY_Apt_Malware_Linux_Disgomoji_Loader : TRANSPARENTJASMINE FILE MEMORY
{
	meta:
		description = "Detects DISGOMOJI loader using strings in the ELF."
		author = "threatintel@volexity.com"
		id = "6d7848db-f1a5-5ccc-977a-7597b966a31c"
		date = "2024-02-22"
		modified = "2024-07-05"
		reference = "TIB-20240229"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2024/2024-06-13 DISGOMOJI/indicators/rules.yar#L25-L47"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		logic_hash = "d9be4846bab5fffcfd60eaec377443819404f30ec088905c2ee26bd3b7525832"
		score = 75
		quality = 80
		tags = "TRANSPARENTJASMINE, FILE, MEMORY"
		hash1 = "51a372fee89f885741515fa6fdf0ebce860f98145c9883f2e3e35c0fe4432885"
		os = "linux"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10269
		version = 7

	strings:
		$s1 = "discord-c2/test/main/delievery.go" wide ascii

	condition:
		$s1
}

rule VOLEXITY_Apt_Malware_Linux_Disgomoji_Debug_String : TRANSPARENTJASMINE FILE MEMORY
{
	meta:
		description = "Detects DISGOMOJI using strings in the ELF."
		author = "threatintel@volexity.com"
		id = "eed2468f-7e50-5f3e-946a-277c10984823"
		date = "2024-02-22"
		modified = "2024-11-27"
		reference = "TIB-20240229"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2024/2024-06-13 DISGOMOJI/indicators/rules.yar#L48-L71"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		logic_hash = "6bb130eead39bd8128983e0f2e76cfeff8865ce8ed3cb73b132ed32d68fc0db0"
		score = 75
		quality = 80
		tags = "TRANSPARENTJASMINE, FILE, MEMORY"
		hash1 = "d9f29a626857fa251393f056e454dfc02de53288ebe89a282bad38d03f614529"
		os = "linux"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10268
		version = 9

	strings:
		$s1 = "discord-c2/test/main/payload.go" wide ascii
		$s2 = "Desktop/Golang_Dev/Discord"

	condition:
		any of them
}

rule VOLEXITY_Apt_Malware_Linux_Disgomoji_2 : TRANSPARENTJASMINE FILE MEMORY
{
	meta:
		description = "Detects DISGOMOJI malware using strings in the ELF."
		author = "threatintel@volexity.com"
		id = "609beb47-5e93-5f69-b89d-2cf62f20851a"
		date = "2024-02-22"
		modified = "2024-07-05"
		reference = "TIB-20240229"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2024/2024-06-13 DISGOMOJI/indicators/rules.yar#L72-L103"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		logic_hash = "e03a774cca2946c1becdbd775ef465033dae089d578ea18a4f43fd7bdae9168e"
		score = 75
		quality = 80
		tags = "TRANSPARENTJASMINE, FILE, MEMORY"
		hash1 = "d9f29a626857fa251393f056e454dfc02de53288ebe89a282bad38d03f614529"
		os = "linux"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10266
		version = 9

	strings:
		$s1 = "downloadFileFromURL" wide ascii
		$s2 = "createCronJob" wide ascii
		$s3 = "findAndSendFiles" wide ascii
		$s4 = "updateLogFile" wide ascii
		$s5 = "handleZipFile" wide ascii
		$s6 = "takeScreenshot" wide ascii
		$s7 = "zipFirefoxProfile" wide ascii
		$s8 = "zipDirectoryWithParts" wide ascii
		$s9 = "uploadAndSendToOshi" wide ascii
		$s10 = "uploadAndSendToLeft" wide ascii

	condition:
		7 of them
}

rule VOLEXITY_Apt_Malware_Linux_Disgomoji_1 : TRANSPARENTJASMINE FILE MEMORY
{
	meta:
		description = "Detects GOMOJI malware using strings in the ELF."
		author = "threatintel@volexity.com"
		id = "f6643e9a-ca41-57e0-9fce-571d340f1cfe"
		date = "2024-02-22"
		modified = "2024-07-05"
		reference = "TIB-20240229"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2024/2024-06-13 DISGOMOJI/indicators/rules.yar#L104-L131"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		logic_hash = "dd3535079881ae9cfe25c129803668cb595be89b7f62eb82af19cc3839f92b6d"
		score = 75
		quality = 80
		tags = "TRANSPARENTJASMINE, FILE, MEMORY"
		hash1 = "d9f29a626857fa251393f056e454dfc02de53288ebe89a282bad38d03f614529"
		os = "linux"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10265
		version = 7

	strings:
		$s1 = "Session *%s* opened!" wide ascii
		$s2 = "uevent_seqnum.sh" wide ascii
		$s3 = "Error downloading shell script: %v" wide ascii
		$s4 = "Error setting execute permissions: %v" wide ascii
		$s5 = "Error executing shell script: %v" wide ascii
		$s6 = "Error creating Discord session" wide ascii

	condition:
		4 of them
}

rule VOLEXITY_Apt_Malware_Linux_Disgomoji_Bogus_Strings : TRANSPARENTJASMINE FILE
{
	meta:
		description = "Detects the DISGOMOJI malware using bogus strings introduced in the newer version."
		author = "threatintel@volexity.com"
		id = "ecff8d3c-d4fe-5b6d-a227-6ff531cf8e2b"
		date = "2024-03-14"
		modified = "2024-07-05"
		reference = "TIB-20240318"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2024/2024-06-13 DISGOMOJI/indicators/rules.yar#L132-L159"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		logic_hash = "0d8a2b371ffb182e60a8cc0cc500d1a9f906718a55f23f35f6c12f7faabbe971"
		score = 75
		quality = 80
		tags = "TRANSPARENTJASMINE, FILE"
		hash1 = "8c8ef2d850bd9c987604e82571706e11612946122c6ab089bd54440c0113968e"
		os = "linux"
		os_arch = "all"
		scan_context = "file"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10341
		version = 5

	strings:
		$s1 = "Graphics Display Rendering" wide ascii
		$s2 = "Error fetching Repository Key: %v" wide ascii
		$s3 = "Error reading Repository Key: %v" wide ascii
		$s4 = "Error fetching dpkg: %v" wide ascii
		$s5 = "GNU Drivers Latest version v1.4.2" wide ascii
		$s6 = "ps_output.txt" wide ascii

	condition:
		all of them
}

rule VOLEXITY_Apt_Malware_Linux_Disgomoji_Script_Uevent_Seqnum : TRANSPARENTJASMINE FILE
{
	meta:
		description = "Detects a script deployed as part of DISGOMOJI malware chain."
		author = "threatintel@volexity.com"
		id = "9df61164-6a92-5042-ba4f-64dc7e998283"
		date = "2024-03-07"
		modified = "2024-07-05"
		reference = "TIB-20240318"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2024/2024-06-13 DISGOMOJI/indicators/rules.yar#L160-L187"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		logic_hash = "e390e83d9fc15499c9f32ad47d1c526273105602bda7b3532720b0a3f6abc835"
		score = 75
		quality = 80
		tags = "TRANSPARENTJASMINE, FILE"
		hash1 = "98b24fb7aaaece7556aea2269b4e908dd79ff332ddaa5111caec49123840f364"
		os = "linux"
		os_arch = "all"
		scan_context = "file"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10314
		version = 6

	strings:
		$s1 = "USB_DIR=\"/media/$USER\"" wide ascii
		$s2 = "RECORD_FILE=\"record.txt\"" wide ascii
		$s3 = "copy_files()" wide ascii
		$s4 = "Check for connected USB drives" wide ascii
		$s5 = "Check if filename already exists in record.txt" wide ascii
		$s6 = "Function to copy files from USB drive to destination folder" wide ascii

	condition:
		3 of them
}

rule VOLEXITY_Apt_Malware_Linux_Disgomoji_Script_Lan_Conf : TRANSPARENTJASMINE FILE
{
	meta:
		description = "Detects a script deployed as part of DISGOMOJI malware chain."
		author = "threatintel@volexity.com"
		id = "b338b3cf-22ce-5767-bdea-503e883bc84b"
		date = "2024-03-07"
		modified = "2024-07-05"
		reference = "TIB-20240318"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2024/2024-06-13 DISGOMOJI/indicators/rules.yar#L188-L215"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		logic_hash = "2a19d5cff7adc9b1b92538a5df4e3cadea694f925f65080f5093fc5425e840f4"
		score = 75
		quality = 80
		tags = "TRANSPARENTJASMINE, FILE"
		hash1 = "0b5cf9bd917f0af03dd694ff4ce39b0b34a97c9f41b87feac1dc884a684f60ef"
		os = "linux"
		os_arch = "all"
		scan_context = "file"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10312
		version = 7

	strings:
		$s1 = "add_lan_conf_cron_if_not_exists" wide ascii
		$s2 = "download_if_not_exists" wide ascii
		$s3 = "add_cron_if_not_exists" wide ascii
		$s4 = "uevent_seqnum.sh" wide ascii
		$s5 = "$HOME/.x86_64-linux-gnu" wide ascii
		$s6 = "lanConfScriptPath" wide ascii

	condition:
		4 of them
}

rule VOLEXITY_Apt_Malware_Win_Deepdata_Module : BRAZENBAMBOO FILE MEMORY
{
	meta:
		description = "Detects modules used by DEEPDATA based on the required export names used by those modules."
		author = "threatintel@volexity.com"
		id = "1287f5dd-9229-57ce-a91a-73d61041df80"
		date = "2024-07-30"
		modified = "2024-11-14"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2024/2024-11-15 BrazenBamboo/rules.yar#L1-L25"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		logic_hash = "d36f34343826daf7f7368118c7127c7181a54c99a01803016c9a6965abb309cb"
		score = 75
		quality = 80
		tags = "BRAZENBAMBOO, FILE, MEMORY"
		hash1 = "c782346bf9e5c08a0c43a85d4991f26b0b3c99c054fa83beb4a9e406906f011e"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10868
		version = 2

	strings:
		$str1 = "ExecuteCommand"
		$str2 = "GetPluginCommandID"
		$str3 = "GetPluginName"
		$str4 = "GetPluginVersion"

	condition:
		all of them
}

rule VOLEXITY_Apt_Malware_Win_Lightspy_Orchestrator_Decoded_Core : BRAZENBAMBOO FILE MEMORY
{
	meta:
		description = "Detects the decoded orchestrator for the Windows variant of the LightSpy malware family. This file is normally stored in an encoded state on the C2 server and is used as the core component of this malware family, loading additional plugins from the C2 whilst managing all the C2 communication etc."
		author = "threatintel@volexity.com"
		id = "44f8d7a4-7f48-5960-91a7-baf475f7d291"
		date = "2024-02-15"
		modified = "2024-07-03"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2024/2024-11-15 BrazenBamboo/rules.yar#L244-L287"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		logic_hash = "f0189c0a84c53e365130e9683f2f2b2f73c14412d8e4d0251a4780d0e80162d8"
		score = 75
		quality = 78
		tags = "BRAZENBAMBOO, FILE, MEMORY"
		hash1 = "80c0cdb1db961c76de7e4efb6aced8a52cd0e34178660ef34c128be5f0d587df"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10246
		version = 2

	strings:
		$s1 = "Enter RunWork......."
		$s2 = "it's running......."
		$s3 = "select ret = socket_error."
		$s4 = "%s\\\\account.bin"
		$s5 = "[CtrlLink]: get machine sn err:%d"
		$s6 = "wmic path Win32_VideoController get CurrentHorizontalResolution,CurrentVerticalResolution /format:list | findstr /v \\\"^$\\\""
		$s7 = "wmic csproduct get vendor,version /format:list | findstr /v \\\"^$\\\""
		$s8 = "local ip get sockname error=%d"
		$s9 = "connect goole dns error=%d"
		$s10 = "%s/api/terminal/upsert/"
		$s11 = "/963852741/windows/plugin/manifest"
		$s12 = "Hello deepdata."
		$s13 = "Start Light."
		$s14 = "InitialPluginManager Error."
		$s15 = "InitialCommandExe Error."
		$s16 = "ws open, and send logon info."
		$s17 = "plugin_replay_handler"
		$s18 = "light_x86.dll"
		$pdb1 = "\\light\\bin\\light_x86.pdb"
		$pdb2 = "\\light\\bin\\plugin"
		$pdb3 = "D:\\tmpWork\\"

	condition:
		1 of ( $pdb* ) or 5 of ( $s* )
}

rule VOLEXITY_Apt_Malware_Win_Lightspy_Orchestrator_Decoded_C2_Strings : BRAZENBAMBOO FILE MEMORY
{
	meta:
		description = "Detects the decoded orchestrator for the Windows variant of the LightSpy malware family. This file is normally stored in an encoded state on the C2 server and is used as the core component of this malware family, loading additional plugins from the C2 whilst managing all the C2 communication etc."
		author = "threatintel@volexity.com"
		id = "a0af8fb7-13a3-54e8-8569-e8622fa80d89"
		date = "2024-02-15"
		modified = "2024-11-14"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2024/2024-11-15 BrazenBamboo/rules.yar#L288-L337"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		logic_hash = "eeaaf6e16d4854a2279bd62596f75cb8b8ec1b05f3b050f5dac97254704b9005"
		score = 75
		quality = 78
		tags = "BRAZENBAMBOO, FILE, MEMORY"
		hash1 = "80c0cdb1db961c76de7e4efb6aced8a52cd0e34178660ef34c128be5f0d587df"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10245
		version = 4

	strings:
		$s1 = "[WsClient][Error]:"
		$s2 = "[WsClient][Info]:"
		$s3 = "[WsClient]:WsClient"
		$s4 = "[WsClient][Info]:Ws"
		$s5 = "WsClient Worker Thread ID=%d"
		$s6 = "[LightWebClient]:"
		$s7 = "LightHttpGet err:%s"
		$s8 = "User-Agent: Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.145 Safari/537.36"
		$s9 = "KvList Err:%s"
		$s10 = "dataMultiPart malloc err:%d"
		$ctrl1 = "CTRL_HEART_BEAT"
		$ctrl2 = "CTRL_NET_CONFIG"
		$ctrl3 = "CTRL_COMMAND_PLAN"
		$ctrl4 = "CTRL_MODIFY_NET_CONFIG"
		$ctrl5 = "CTRL_UPLOAD_PLUGIN_STATUS"
		$ctrl6 = "CTRL_PLUGIN_EXECUTE_COMMAND"
		$ctrl7 = "CTRL_PLUGIN_COMMAND_STATUS"
		$ctrl8 = "CTRL_PLUGIN_STOP_COMMAND"
		$ctrl9 = "CTRL_GET_SLEEP_CONFIG"
		$ctrl10 = "CTRL_MODIFY_SLEEP_CONFIG"
		$ctrl11 = "CTRL_SLEEP_STATUS"
		$ctrl12 = "CTRL_UPDATE_PLUGIN"
		$ctrl13 = "CTRL_DESTROY"
		$ctrl14 = "CTRL_RECONFIG_REBOUNT_ADDRESS"
		$ctrl15 = "CTRL_AUTO_UPLOUD_FILE_CONFIG"
		$ctrl16 = "CTRL_UPLOUD_DEVICE_INFO"
		$ctrl17 = "CTRL_TEST_VPDN_ACCOUNT"

	condition:
		3 of ( $s* ) or 5 of ( $ctrl* )
}

rule VOLEXITY_Apt_Malware_Any_Reloadext_Plugin : STORMBAMBOO FILE MEMORY
{
	meta:
		description = "Detection for RELOADEXT, a Google Chrome extension malware."
		author = "threatintel@volexity.com"
		id = "6c6c8bee-2a13-5645-89ef-779f00264fd9"
		date = "2024-02-23"
		modified = "2024-08-02"
		reference = "TIB-20240227"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2024/2024-08-02 StormBamboo/rules.yar#L4-L36"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		logic_hash = "2b11f8fc5b6260ebf00bde83585cd7469709a4979ca579cdf065724bc15052fc"
		score = 75
		quality = 80
		tags = "STORMBAMBOO, FILE, MEMORY"
		hash1 = "9d0928b3cc21ee5e1f2868f692421165f46b5014a901636c2a2b32a4c500f761"
		os = "all"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10282
		version = 4

	strings:
		$man1 = "Reload page with Internet Explorer compatible mode."
		$man2 = "\"http://*/*\""
		$code1 = ";chrome["
		$code2 = "XMLHttpRequest(),_"
		$code3 = "0x400*0x400"

	condition:
		all of ( $man* ) or ( #code1 > 8 and #code2 >= 2 and #code3 >= 2 )
}

rule VOLEXITY_Apt_Malware_Macos_Reloadext_Installer : STORMBAMBOO FILE MEMORY
{
	meta:
		description = "Detect the RELOADEXT installer."
		author = "threatintel@volexity.com"
		id = "c65ea2b5-ab98-5693-92ea-05c0f1ea1e5b"
		date = "2024-02-23"
		modified = "2024-08-02"
		reference = "TIB-20240227"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2024/2024-08-02 StormBamboo/rules.yar#L37-L62"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		logic_hash = "8688796839202d95ded15e10262a7a7c7cbbae4a332b60305402e5984005d452"
		score = 75
		quality = 80
		tags = "STORMBAMBOO, FILE, MEMORY"
		hash1 = "07e3b067dc5e5de377ce4a5eff3ccd4e6a2f1d7a47c23fe06b1ededa7aed1ab3"
		os = "darwin"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10281
		version = 2

	strings:
		$str1 = "/CustomPlug1n/"
		$str2 = "Chrome NOT installed."
		$str3 = "-f force kill Chrome"
		$str4 = "/*} &&cp -rf ${"

	condition:
		3 of them
}

rule VOLEXITY_Apt_Malware_Win_Dustpan_Apihashes : STORMBAMBOO FILE
{
	meta:
		description = "Detects DUSTPAN malware using API hashes used to resolve functions at runtime."
		author = "threatintel@volexity.com"
		id = "ed275da4-cd95-5fa3-a568-e610fb405bb3"
		date = "2023-08-17"
		modified = "2024-08-02"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2024/2024-08-02 StormBamboo/rules.yar#L171-L205"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		logic_hash = "3edb66ade428c451c18aa152244f869f9f8c10e62ed942bf722b4d1cf1893e93"
		score = 75
		quality = 80
		tags = "STORMBAMBOO, FILE"
		hash1 = "b77bcfb036f5a6a3973fdd68f40c0bd0b19af1246688ca4b1f9db02f2055ef9d"
		os = "win"
		os_arch = "all"
		report1 = "MAR-20230818"
		report2 = "TIB-20231221"
		scan_context = "file"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 9591
		version = 3

	strings:
		$h1 = {9c 5b 9f 0b}
		$h2 = {4c 8f 3e 08}
		$h3 = {b4 aa f2 06}
		$h4 = {dc cb ca 09}
		$h5 = {d4 33 07 0e}
		$h6 = {27 89 d6 0a}
		$h7 = {b5 7d ae 09}
		$h8 = {4e 64 eb 0b}
		$h9 = {be 17 d9 08}
		$magic = "SMHM"

	condition:
		6 of ( $h* ) and $magic
}

rule VOLEXITY_Apt_Malware_Win_Pocostick_Jul23 : STORMBAMBOO FILE MEMORY
{
	meta:
		description = "Detects the July 2023 POCOSTICK variant. These strings are only visible in memory after several rounds of shellcode decryption."
		author = "threatintel@volexity.com"
		id = "9632a7fc-06da-58b4-b95c-b46aeb9dd41d"
		date = "2023-07-24"
		modified = "2024-08-02"
		reference = "TIB-20231221"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2024/2024-08-02 StormBamboo/rules.yar#L206-L235"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		logic_hash = "19487db733c7f793be2a1287df32a165e46f6af0e940b13b389f4d675b5100c4"
		score = 75
		quality = 80
		tags = "STORMBAMBOO, FILE, MEMORY"
		hash1 = "ec3e787c369ac4b28447e7cacc44d70a595e39d47f842bacb07d19b12cab6aad"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 9542
		version = 3

	strings:
		$str1 = "Folder PATH listing form volume" wide
		$str2 = "Volume serial number is 0000-1111" wide
		$str3 = "Type:Error" wide
		$str4 = "Type:Desktop" wide
		$str5 = "Type:Laptop" wide
		$str6 = "Type:Vitual" wide
		$str7 = ".unicode.tmp" wide
		$str8 = "EveryOne" wide

	condition:
		6 of them
}

rule VOLEXITY_Apt_Malware_Py_Dustpan_Pyloader : STORMBAMBOO FILE MEMORY
{
	meta:
		description = "Detects Python script used by KPlayer to update, modified by attackers to download a malicious payload."
		author = "threatintel@volexity.com"
		id = "446d2eef-c60a-50ed-9ff1-df86b6210dff"
		date = "2023-07-21"
		modified = "2024-08-02"
		reference = "TIB-20231221"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2024/2024-08-02 StormBamboo/rules.yar#L236-L270"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		logic_hash = "bb3a70dad28181534e27abbbd618165652c137264bfd3726ae4480c642493a3b"
		score = 75
		quality = 80
		tags = "STORMBAMBOO, FILE, MEMORY"
		os = "all"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 9530
		version = 4

	strings:
		$s_1 = "def count_md5(src)"
		$s_2 = "urllib.request.urlretrieve(image_url,main)"
		$s_3 = "m1 != '4c8a326899272d2fe30e818181f6f67f'"
		$s_4 = "os.path.split(os.path.realpath(__file__))[0]"
		$s_5 = "r_v = os.system('curl '+ini_url+cc)"
		$s_6 = "b41ef5f591226a0d5adce99cb2e629d8"
		$s_7 = "1df495e7c85e59ad0de1b9e50912f8d0"
		$s_8 = "tasklist | findstr mediainfo.exe"
		$url_1 = "http://dl1.5kplayer.com/youtube/youtube_dl.png"
		$url_2 = "http://dl1.5kplayer.com/youtube/youtube.ini?fire="
		$path_1 = "C:\\\\ProgramData\\\\Digiarty\\\\mediainfo.exe"

	condition:
		3 of ( $s_* ) or any of ( $url_* ) or $path_1
}

rule VOLEXITY_Apt_Malware_Py_Upstyle : UTA0218 FILE MEMORY
{
	meta:
		description = "Detect the UPSTYLE webshell."
		author = "threatintel@volexity.com"
		id = "45726f35-8b3e-5095-b145-9e7f6da6838b"
		date = "2024-04-11"
		modified = "2024-04-12"
		reference = "TIB-20240412"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2024/2024-04-12 Palo Alto Networks GlobalProtect/indicators/rules.yar#L1-L34"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		logic_hash = "51923600b23d23f4ce29eac7f5ab9f7e1ddb45bed5f6727ddec4dcb75872e473"
		score = 75
		quality = 80
		tags = "UTA0218, FILE, MEMORY"
		hash1 = "3de2a4392b8715bad070b2ae12243f166ead37830f7c6d24e778985927f9caac"
		hash2 = "0d59d7bddac6c22230187ef6cf7fa22bca93759edc6f9127c41dc28a2cea19d8"
		hash3 = "4dd4bd027f060f325bf6a90d01bfcf4e7751a3775ad0246beacc6eb2bad5ec6f"
		os = "linux"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10429
		version = 2

	strings:
		$stage1_str1 = "/opt/pancfg/mgmt/licenses/PA_VM"
		$stage1_str2 = "exec(base64."
		$stage2_str1 = "signal.signal(signal.SIGTERM,stop)"
		$stage2_str2 = "exec(base64."
		$stage3_str1 = "write(\"/*\"+output+\"*/\")"
		$stage3_str2 = "SHELL_PATTERN"

	condition:
		all of ( $stage1* ) or all of ( $stage2* ) or all of ( $stage3* )
}

rule VOLEXITY_Apt_Malware_Vbs_Basicstar_A : CHARMINGCYPRESS FILE MEMORY
{
	meta:
		description = "VBS backdoor which bares architectural similarity to the POWERSTAR malware family."
		author = "threatintel@volexity.com"
		id = "e790defe-2bd5-5629-8420-ce8091483589"
		date = "2024-01-04"
		modified = "2025-05-21"
		reference = "TIB-20240111"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2024/2024-02-13 CharmingCypress/rules.yar#L69-L99"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		logic_hash = "977bb42553bb6585c8d0e1e89675644720ca9abf294eccd797e20d4bca516810"
		score = 75
		quality = 80
		tags = "CHARMINGCYPRESS, FILE, MEMORY"
		hash1 = "c6f91e5585c2cbbb8d06b7f239e30b271f04393df4fb81815f6556fa4c793bb0"
		os = "win"
		os_arch = "all"
		report2 = "TIB-20240126"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10037
		version = 8

	strings:
		$s1 = "Base64Encode(EncSess)" ascii wide
		$s2 = "StrReverse(PlainSess)" ascii wide
		$s3 = "ComDecode, \"Module\"" ascii wide
		$s4 = "ComDecode, \"SetNewConfig\"" ascii wide
		$s5 = "ComDecode, \"kill\"" ascii wide
		$magic = "cmd /C start /MIN curl --ssl-no-revoke -s -d " ascii wide

	condition:
		3 of ( $s* ) or $magic
}

rule VOLEXITY_Apt_Malware_Ps1_Powerless_B : CHARMINGCYPRESS FILE MEMORY
{
	meta:
		description = "Detects POWERLESS malware."
		author = "threatintel@volexity.com"
		id = "e62703b5-32fb-5ceb-9f21-f52a4871f3d9"
		date = "2023-10-25"
		modified = "2024-01-29"
		reference = "TIB-20231027"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2024/2024-02-13 CharmingCypress/rules.yar#L100-L157"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		logic_hash = "eb9d199c1f7c2a42d711c1a44ab13526787169c18a77ce988568525baca043ef"
		score = 75
		quality = 78
		tags = "CHARMINGCYPRESS, FILE, MEMORY"
		hash1 = "62de7abb39cf4c47ff120c7d765749696a03f4fa4e3e84c08712bb0484306ae1"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 9794
		version = 5

	strings:
		$fun_1 = "function verifyClickStorke"
		$fun_2 = "function ConvertTo-SHA256"
		$fun_3 = "function Convert-Tobase" fullword
		$fun_4 = "function Convert-Frombase" fullword
		$fun_5 = "function Send-Httppacket"
		$fun_6 = "function Generat-FetchCommand"
		$fun_7 = "function Create-Fetchkey"
		$fun_8 = "function Run-Uploader"
		$fun_9 = "function Run-Shot" fullword
		$fun_10 = "function ShotThis("
		$fun_11 = "function File-Manager"
		$fun_12 = "function zip-files"
		$fun_13 = "function Run-Stealer"
		$fun_14 = "function Run-Downloader"
		$fun_15 = "function Run-Stro" fullword
		$fun_16 = "function Run-Tele" fullword
		$fun_17 = "function Run-Voice"
		$s_1 = "if($commandtype -eq \"klg\")"
		$s_2 = "$desrilizedrecievedcommand"
		$s_3 = "$getAsyncKeyProto = @"
		$s_4 = "$Global:BotId ="
		$s_5 = "$targetCLSID = (Get-ScheduledTask | Where-Object TaskName -eq"
		$s_6 = "$burl = \"$Global:HostAddress/"
		$s_7 = "$hashString = [System.BitConverter]::ToString($hash).Replace('-','').ToLower()"
		$s_8 = "$Global:UID = ((gwmi win32_computersystemproduct).uuid -replace '[^0-9a-z]').substring("
		$s_9 = "$rawpacket = \"{`\"MId`\":`\"$Global:MachineID`\",`\"BotId`\":`\"$basebotid`\"}\""
		$s_12 = "Runned Without any Error"
		$s_13 = "$commandresponse = (Invoke-Expression $instruction -ErrorAction Stop) | Out-String"
		$s_14 = "Operation started successfuly"
		$s_15 = "$t_path = (Get-WmiObject Win32_Process -Filter \"name = '$process'\" | Select-Object CommandLine).CommandLine"
		$s_16 = "?{ $_.DisplayName -match \"Telegram Desktop\" } | %{$app_path += $_.InstallLocation }"
		$s_17 = "$chlids = get-ChildItem $t -Recurse -Exclude \"$t\\tdata\\user_data\""
		$s_18 = "if($FirsttimeFlag -eq $True)"
		$s_19 = "Update-Conf -interval $inter -url $url -next_url $next -conf_path $conf_path -key $config_key"

	condition:
		3 of ( $fun_* ) or any of ( $s_* )
}

rule VOLEXITY_Apt_Malware_Macos_Vpnclient_Cc_Oct23 : CHARMINGCYPRESS FILE MEMORY
{
	meta:
		description = "Detection for fake macOS VPN client used by CharmingCypress."
		author = "threatintel@volexity.com"
		id = "e0957936-dc6e-5de6-bb23-d0ef61655029"
		date = "2023-10-17"
		modified = "2023-10-27"
		reference = "TIB-20231027"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2024/2024-02-13 CharmingCypress/rules.yar#L246-L272"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		logic_hash = "da5e9be752648b072a9aaeed884b8e1729a14841e33ed6633a0aaae1f11bd139"
		score = 75
		quality = 80
		tags = "CHARMINGCYPRESS, FILE, MEMORY"
		hash1 = "11f0e38d9cf6e78f32fb2d3376badd47189b5c4456937cf382b8a574dc0d262d"
		os = "darwin,linux"
		os_arch = "all"
		parent_hash = "31ca565dcbf77fec474b6dea07101f4dd6e70c1f58398eff65e2decab53a6f33"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 9770
		version = 3

	strings:
		$s1 = "networksetup -setsocksfirewallproxystate wi-fi off" ascii
		$s2 = "networksetup -setsocksfirewallproxy wi-fi ___serverAdd___ ___portNum___; networksetup -setsocksfirewallproxystate wi-fi on" ascii
		$s3 = "New file imported successfully." ascii
		$s4 = "Error in importing the File." ascii

	condition:
		2 of ( $s* )
}

rule VOLEXITY_Apt_Malware_Charmingcypress_Openvpn_Configuration : CHARMINGCYPRESS FILE
{
	meta:
		description = "Detection for a .ovpn file used in a malicious VPN client on victim machines by CharmingCypress."
		author = "threatintel@volexity.com"
		id = "f39b2d7c-f0c5-5623-a114-02ba32469e59"
		date = "2023-10-17"
		modified = "2023-10-27"
		reference = "TIB-20231027"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2024/2024-02-13 CharmingCypress/rules.yar#L273-L298"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		logic_hash = "f4c5f13ac75504b14def9c37d3a41c6eea4c45845d4b54c50030b1f00691e4bf"
		score = 75
		quality = 80
		tags = "CHARMINGCYPRESS, FILE"
		hash1 = "d6d043973d8843a82033368c785c362f51395b1a1d475fa4705aff3526e15268"
		parent_hash = "31ca565dcbf77fec474b6dea07101f4dd6e70c1f58398eff65e2decab53a6f33"
		os = "all"
		os_arch = "all"
		scan_context = "file"
		severity = "high"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 9769
		version = 3

	strings:
		$remote = "remote-cert-tls server" ascii
		$ip = "Ip: "
		$tls = "<tls_auth>"

	condition:
		all of them
}

rule VOLEXITY_Apt_Delivery_Win_Charming_Openvpn_Client : CHARMINGCYPRESS FILE
{
	meta:
		description = "Detects a fake OpenVPN client developed by CharmingCypress."
		author = "threatintel@volexity.com"
		id = "b69fdd72-4a55-5e83-b754-401fe9339007"
		date = "2023-10-17"
		modified = "2023-10-27"
		reference = "TIB-20231027"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2024/2024-02-13 CharmingCypress/rules.yar#L299-L323"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		logic_hash = "02596a62cb1ba17ecabef0ae93f434e4774b00422a6da2106a2bc4c59d2f8077"
		score = 75
		quality = 80
		tags = "CHARMINGCYPRESS, FILE"
		hash1 = "2d99755d5cd25f857d6d3aa15631b69f570d20f95c6743574f3d3e3e8765f33c"
		os = "win"
		os_arch = "all"
		scan_context = "file"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 9768
		version = 2

	strings:
		$s1 = "DONE!"
		$s2 = "AppCore.dll"
		$s3 = "ultralight@@"

	condition:
		all of ( $s* )
}

rule VOLEXITY_Apt_Malware_Ps1_Powerstar_Generic : CHARMINGCYPRESS FILE MEMORY
{
	meta:
		description = "Detects POWERSTAR modules based on common HTTP functions used across modules."
		author = "threatintel@volexity.com"
		id = "71a3e99d-e1c8-5ac1-abbc-2ba5cba80799"
		date = "2023-06-02"
		modified = "2024-01-26"
		reference = "TIB-20240126"
		source_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/2024/2024-02-13 CharmingCypress/rules.yar#L324-L352"
		license_url = "https://github.com/volexity/threat-intel/blob/92353b1ccc638f5ed0e7db43a26cb40fad7f03df/LICENSE.txt"
		logic_hash = "4da02190ffd16304eccbc0d12dfcc5637a6b785af0e3dc3dfcafcfe114597eb2"
		score = 75
		quality = 80
		tags = "CHARMINGCYPRESS, FILE, MEMORY"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 9356
		version = 3

	strings:
		$http1 = "Send_Upload" ascii wide
		$http2 = "Send_Post_Data" ascii wide
		$json1 = "{\"OS\":\"" ascii wide
		$json2 = "{\"ComputerName\":\"' + $env:COMPUTERNAME + '\"}" ascii wide
		$json3 = "{\"Token\"" ascii wide
		$json4 = "{\"num\":\"" ascii wide

	condition:
		all of ( $http* ) or all of ( $json* )
}
/*
 * YARA Rule Set
 * Repository Name: SecuInfra
 * Repository: https://github.com/SIFalcon/Detection
 * Retrieval Date: 2026-05-03
 * Git Commit: 2d7c66d7d16c7541bf2a9a83a7a6d334364a26fd
 * Number of Rules: 32
 * Skipped: 0 (age), 24 (quality), 0 (score), 0 (importance)
 *
 * 
 * LICENSE
 * 
 * NO LICENSE SET
 */

rule SECUINFRA_APT_Bitter_Maldoc_Verify : CVE_2018_0798
{
	meta:
		description = "Detects Bitter (T-APT-17) shellcode in oleObject (CVE-2018-0798)"
		author = "SECUINFRA Falcon Team (@SI_FalconTeam)"
		id = "8e0e32d3-f00e-5145-9386-f42ddca703ae"
		date = "2022-06-01"
		modified = "2022-07-05"
		reference = "https://www.secuinfra.com/en/techtalk/whatever-floats-your-boat-bitter-apt-continues-to-target-bangladesh"
		source_url = "https://github.com/SIFalcon/Detection/blob/2d7c66d7d16c7541bf2a9a83a7a6d334364a26fd/Yara/APT/APT_Bitter_T-APT-17.yar#L11-L40"
		license_url = "N/A"
		logic_hash = "1d30e2ad0d99d274a4e3dd029ff41ec05e8ba4160bea37762bce1bb5286493d8"
		score = 75
		quality = 70
		tags = "CVE-2018-0798"
		tlp = "WHITE"
		hash0 = "0c7158f9fc2093caf5ea1e34d8b8fffce0780ffd25191fac9c9b52c3208bc450"
		hash1 = "bd0d25194634b2c74188cfa3be6668590e564e6fe26a6fe3335f95cbc943ce1d"
		hash2 = "3992d5a725126952f61b27d43bd4e03afa5fa4a694dca7cf8bbf555448795cd6"

	strings:
		$xor_string0 = "LoadLibraryA" xor
		$xor_string1 = "urlmon.dll" xor
		$xor_string2 = "Shell32.dll" xor
		$xor_string3 = "ShellExecuteA" xor
		$xor_string4 = "MoveFileA" xor
		$xor_string5 = "CreateDirectoryA" xor
		$xor_string6 = "C:\\Windows\\explorer" xor
		$padding = {000001128341000001128341000001128342000001128342}

	condition:
		3 of ( $xor_string* ) and $padding
}


rule SECUINFRA_APT_Bitter_Almond_RAT : FILE
{
	meta:
		description = "Detects Bitter (T-APT-17) Almond RAT (.NET)"
		author = "SECUINFRA Falcon Team (@SI_FalconTeam)"
		id = "191fadf9-4f64-56c9-bc2a-a7b4e27ab0fc"
		date = "2022-06-01"
		modified = "2022-07-05"
		reference = " https://www.secuinfra.com/en/techtalk/whatever-floats-your-boat-bitter-apt-continues-to-target-bangladesh"
		source_url = "https://github.com/SIFalcon/Detection/blob/2d7c66d7d16c7541bf2a9a83a7a6d334364a26fd/Yara/APT/APT_Bitter_T-APT-17.yar#L82-L108"
		license_url = "N/A"
		hash = "55901c2d5489d6ac5a0671971d29a31f4cdfa2e03d56e18c1585d78547a26396"
		logic_hash = "b8d6b95987fe434fc16c87a7bc144f1fe69301a32bb93588df7c2abbfef62d75"
		score = 75
		quality = 70
		tags = "FILE"
		tlp = "WHITE"

	strings:
		$function0 = "GetMacid" ascii
		$function1 = "StartCommWithServer" ascii
		$function2 = "sendingSysInfo" ascii
		$dbg0 = "*|END|*" wide
		$dbg1 = "FILE>" wide
		$dbg2 = "[Command Executed Successfully]" wide

	condition:
		uint16( 0 ) == 0x5a4d and dotnet.version == "v4.0.30319" and filesize > 12KB and filesize < 68KB and any of ( $function* ) and any of ( $dbg* )
}

rule SECUINFRA_APT_Bitter_PDB_Paths : FILE
{
	meta:
		description = "Detects Bitter (T-APT-17) PDB Paths"
		author = "SECUINFRA Falcon Team (@SI_FalconTeam)"
		id = "e2ad4ac3-45fe-5087-b0d6-a5de16774229"
		date = "2022-06-22"
		modified = "2022-07-05"
		reference = "https://www.secuinfra.com/en/techtalk/whatever-floats-your-boat-bitter-apt-continues-to-target-bangladesh"
		source_url = "https://github.com/SIFalcon/Detection/blob/2d7c66d7d16c7541bf2a9a83a7a6d334364a26fd/Yara/APT/APT_Bitter_T-APT-17.yar#L110-L133"
		license_url = "N/A"
		logic_hash = "7eb9e4c1b4e0cca070596f3702045756eb32716481bb59f2f8322221804291f5"
		score = 75
		quality = 70
		tags = "FILE"
		tlp = "WHITE"
		hash0 = "55901c2d5489d6ac5a0671971d29a31f4cdfa2e03d56e18c1585d78547a26396"

	strings:
		$pdbPath0 = "C:\\Users\\Window 10 C\\Desktop\\COMPLETED WORK\\" ascii
		$pdbPath1 = "stdrcl\\stdrcl\\obj\\Release\\stdrcl.pdb"
		$pdbPath2 = "g:\\Projects\\cn_stinker_34318\\"
		$pdbPath3 = "renewedstink\\renewedstink\\obj\\Release\\stimulies.pdb"

	condition:
		uint16( 0 ) == 0x5a4d and any of ( $pdbPath* )
}

rule CHECK_POINT_Apt_Nazar_Component_Guids
{
	meta:
		description = "Detect Nazar Components by COM Objects' GUID"
		author = "Itay Cohen"
		id = "1bdc0b54-4903-559d-9037-450470fc7ef7"
		date = "2020-04-27"
		modified = "2023-04-10"
		reference = "https://research.checkpoint.com/2020/nazar-spirits-of-the-past/"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Checkpoint/apt_nazar_component_guids.yar#L1-L32"
		license_url = "N/A"
		hash = "1110c3e34b6bbaadc5082fabbdd69f492f3b1480724b879a3df0035ff487fd6f"
		hash = "1afe00b54856628d760b711534779da16c69f542ddc1bb835816aa92ed556390"
		hash = "2caedd0b2ea45761332a530327f74ca5b1a71301270d1e2e670b7fa34b6f338e"
		hash = "2fe9b76496a9480273357b6d35c012809bfa3ae8976813a7f5f4959402e3fbb6"
		hash = "460eba344823766fe7c8f13b647b4d5d979ce4041dd5cb4a6d538783d96b2ef8"
		hash = "4d0ab3951df93589a874192569cac88f7107f595600e274f52e2b75f68593bca"
		hash = "75e4d73252c753cd8e177820eb261cd72fecd7360cc8ec3feeab7bd129c01ff6"
		hash = "8fb9a22b20a338d90c7ceb9424d079a61ca7ccb7f78ffb7d74d2f403ae9fbeec"
		hash = "967ac245e8429e3b725463a5c4c42fbdf98385ee6f25254e48b9492df21f2d0b"
		hash = "be624acab7dfe6282bbb32b41b10a98b6189ab3a8d9520e7447214a7e5c27728"
		hash = "d34a996826ea5a028f5b4713c797247913f036ca0063cc4c18d8b04736fa0b65"
		hash = "d9801b4da1dbc5264e83029abb93e800d3c9971c650ecc2df5f85bcc10c7bd61"
		hash = "eb705459c2b37fba5747c73ce4870497aa1d4de22c97aaea4af38cdc899b51d3"
		logic_hash = "9fb69a0ea7272f1b1cbb290ae81e08f7e2b2f6c5409bbca12d9b0b781cb4c267"
		score = 75
		quality = 85
		tags = ""

	strings:
		$guid1_godown = { 98 B3 E5 F6 DF E3 6B 49 A2 AD C2 0F EA 30 DB FE }
		$guid2_godown = { 31 4B CB DB B8 21 0F 4A BC 69 0C 3C E3 B6 6D 00 }
		$guid3_godown = { AF 94 4E B6 6B D5 B4 48 B1 78 AF 07 23 E7 2A B5 }
		$guid4_filesystem = { 79 27 AB 37 34 F2 9D 4D B3 FB 59 A3 FA CB 8D 60 }
		$guid6_filesystem = { 2D A1 2B 77 62 8A D3 4D B3 E8 92 DA 70 2E 6F 3D }
		$guid5_filesystem = { AB D3 13 CF 1C 6A E8 4A A3 74 DE D5 15 5D 6A 88 }

	condition:
		any of them
}
/*
 * YARA Rule Set
 * Repository Name: BlackBerry
 * Repository: https://github.com/mikesxrs/Open-Source-YARA-rules
 * Retrieval Date: 2026-05-03
 * Git Commit: ec0056f767db98bf6d5fd63877ad51fb54d350e9
 * Number of Rules: 19
 * Skipped: 0 (age), 4 (quality), 0 (score), 0 (importance)
 *
 * 
 * LICENSE
 * 
 * NO LICENSE SET
 */

rule CLUSTER25_APT28_Skinnyboy_Launcher : RUSSIAN THREAT ACTOR FILE
{
	meta:
		description = "No description has been set in the source file - Cluster25"
		author = "Cluster25"
		id = "eaf4e8e5-cbec-5000-a2ff-31d1dac4c30f"
		date = "2023-04-10"
		modified = "2023-04-10"
		reference = "https://21649046.fs1.hubspotusercontent-na1.net/hubfs/21649046/2021-05_FancyBear.pdf"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Cluster 25/APT28_SkinnyBoy_Launcher.yar#L1-L19"
		license_url = "N/A"
		logic_hash = "cbb7a6e0114a9556a99ab3f5601664f430b650b2de0b44fe0178a99f21082e8d"
		score = 75
		quality = 75
		tags = "RUSSIAN, THREAT, ACTOR, FILE"
		hash1 = "2a652721243f29e82bdf57b565208c59937bbb6af4ab51e7b6ba7ed270ea6bce"

	strings:
		$sha = {F4 EB 56 52 AF 4B 48 EE 08 FF 9D 44 89 4B D5 66 24 61 2A 15 1D 58 14 F9 6D 97
13 2C 6D 07 6F 86}
		$l1 = "CryptGetHashParam" ascii
		$l2 = "CryptCreateHash" ascii
		$l3 = "FindNextFile" ascii
		$l4 = "PathAddBackslashW" ascii
		$l5 = "PathRemoveFileSpecW" ascii
		$h1 = {50 6A 00 6A 00 68 0C 80 00 00 FF ?? ?? ?? FF 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 6A 00
56 ?? ?? ?? ?? 50 FF ?? ?? ?? FF 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ??}
		$h2 = {8B 01 3B 02 75 10 83 C1 04 83 C2 04 83 EE 04 73 EF}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 100KB and ( $sha or ( all of ( $l* ) and all of ( $h* ) ) )
}

rule CLUSTER25_Sidewinder_Apt_Rtf_Cve_2017_0199 : FILE
{
	meta:
		description = "No description has been set in the source file - Cluster25"
		author = "Cluster25"
		id = "0c44f22e-6b21-5dfb-9812-7d8d14e08c1a"
		date = "2021-09-09"
		modified = "2023-04-10"
		reference = "https://21649046.fs1.hubspotusercontent-na1.net/hubfs/21649046/a_rattlesnake_in_the_navy.pdf"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Cluster 25/sidewinder_apt_rtf_cve_2017_0199.yar#L2-L18"
		license_url = "N/A"
		logic_hash = "63c7b8c251a906ea9ea81a7ea838506cd2c0304b4d197eaff8cd3bac99f860ac"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "282367417cdc711fbad33eb6988c172c61a9a57d9f926addaefabc36cac3c004"
		hash2 = "6d021166bdde0eab22fd4a9f398fdd8ccf8b977ff33a77c518f8d16e56d3eeee"

	strings:
		$head = "{\\rtf1" ascii
		$obj = "objdata 0105000002000000" ascii
		$expl = "6D007300680074006D006C000000FFD7E8130000006E756E48544D4C4170706C69636174696F6E" ascii
		$s1 = "416374697665584F626A656374" ascii nocase
		$s2 = "5176524d384b4e4734504332565a55753765497764426f72686974366761416259796d356c4563306a4453576e585431334a7173467870484f666b7a4c392b2f3d" ascii nocase
		$s3 = "62203e3e2031362026203235352c2062203e3e20382026203235352c2062202620323535" ascii nocase

	condition:
		$head at 0 and $obj and $expl and 2 of ( $s* )
}


rule CLUSTER25_APT29_Loader_87221_00001 : FILE
{
	meta:
		description = "Detects DLL loader variants used in Nobelium kill-chain"
		author = "Cluster25"
		id = "cbee0268-d346-5246-9c2c-97a01ec2e0b3"
		date = "2023-04-10"
		modified = "2023-04-10"
		reference = "https://blog.cluster25.duskrise.com/2022/05/13/cozy-smuggled-into-the-box"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Cluster 25/APT29_Loader_87221_00001.yar#L2-L28"
		license_url = "N/A"
		logic_hash = "7de041baa35b6b07c11c5f08d456a717007ae356e35e296ec4288cf0293a1d7e"
		score = 75
		quality = 75
		tags = "FILE"
		tlp = "white"
		hash1 = "6fc54151607a82d5f4fae661ef0b7b0767d325f5935ed6139f8932bc27309202"
		hash2 = "23a09b74498aea166470ea2b569d42fd661c440f3f3014636879bd012600ed68"

	strings:
		$s1 = "%s\\blank.pdf" fullword ascii
		$s2 = "%s\\AcroSup" fullword ascii
		$s3 = "vcruntime140.dll" fullword ascii
		$s4 = "ME3.99.5UUUUUUUUUUU" fullword ascii
		$c1 = "Rock" fullword ascii
		$c2 = ".mp3" fullword ascii
		$c3 = "%s.backup" fullword ascii
		$sequence1 = { C7 45 ?? 0B 00 10 00 48 8B CF FF 15 ?? ?? ?? 00 85 C0 74 ?? 48 8D 55 ?? 48 89 75 ?? 48 8B CF FF 15 ?? ?? ?? 00 85 C0 74 ?? 48 8B CF FF 15 ?? ?? ?? 00 }
		$sequence2 = { 0F B6 0B 4C 8D 05 ?? ?? ?? 00 89 4C 24 ?? 4D 8B CD 49 8B CD BA 04 01 00 00 E8 ?? ?? ?? ?? 48 8D 5B 01 48 83 EF 01 75 ?? }
		$sequence3 = { 4C 8D 8C 24 ?? 00 00 00 8B 53 ?? 44 8D 40 ?? 48 03 CD 44 89 A4 24 ?? 00 00 00 FF 15 ?? ?? ?? 00 8B 43 ?? 44 8B 43 ?? 4A 8D 14 38 48 8D 0C 28 E8 ?? ?? 00 00 8B 4B ?? 4C 8D 8C 24 ?? 00 00 00 8B 53 ?? 48 03 CD 44 8B 84 24 ?? 00 00 00 FF 15 ?? ?? ?? 00 }
		$sequence4 = { 42 0F B6 8C 32 ?? ?? ?? 00 48 83 C2 03 88 0F 48 8D 7F 01 48 83 FA 2D 7C E7 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 200KB and pe.imports ( "kernel32.dll" , "SetThreadContext" ) and pe.imports ( "kernel32.dll" , "ResumeThread" ) and pe.imports ( "kernel32.dll" , "K32GetModuleFileNameExA" ) and 3 of ( $s* ) and all of ( $c* ) and 3 of ( $sequence* )
}

rule CLUSTER25_APT29_Htmlsmuggling_ZIP_82733_00001 : FILE
{
	meta:
		description = "Rule to detect the EnvyScout HTML smuggling with ZIP payload used in the APT29/Nobelium APT29 chain"
		author = "Cluster25"
		id = "edc2fc67-482f-594e-9b10-f738b9e34c4a"
		date = "2022-05-12"
		modified = "2023-04-10"
		reference = "https://blog.cluster25.duskrise.com/2022/05/13/cozy-smuggled-into-the-box"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Cluster 25/APT29_HTMLSmuggling_ZIP_82733_00001.yar#L1-L16"
		license_url = "N/A"
		hash = "d5c84cbd7dc70e71f3eb24434a58b2f149d0c39faa7e4157552b60c7dbb53d11"
		logic_hash = "ec51d08551af64100f0f22ef61470ea930be7a457c5aba84e8e00cd9b423616d"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "new Blob("
		$s2 = "new Uint8Array("
		$s3 = "application/octet-stream"
		$t1 = "saveAs("
		$t2 = "download("
		$r1 = { 66 6F 72 28 76 61 72 20 69 20 3D 20 30 78 30 3B 20 69 20 3C 20 64 5B 27 6C 65 6E 67 74 68 27 5D 3B 20 69 2B 2B 29 20 7B 0A 20 20 20 20 64 5B 69 5D 20 3D 20 64 5B 69 5D }

	condition:
		( filesize > 500KB and all of ( $s* ) and ( $t1 or $t2 ) and $r1 )
}


rule CLUSTER25_APT28_Skinnyboy_Implanter : RUSSIAN THREAT ACTOR FILE
{
	meta:
		description = "No description has been set in the source file - Cluster25"
		author = "Cluster25"
		id = "c44faf95-a64c-58f4-97d4-2fe17aefc813"
		date = "2021-05-24"
		modified = "2023-04-10"
		reference = "https://21649046.fs1.hubspotusercontent-na1.net/hubfs/21649046/2021-05_FancyBear.pdf"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Cluster 25/APT28_SkinnyBoy_Implanter.yar#L2-L16"
		license_url = "N/A"
		hash = "ae0bc3358fef0ca2a103e694aa556f55a3fed4e98ba57d16f5ae7ad4ad583698"
		logic_hash = "f5b8944910297988ecf5aecf23d20c384cf141a3a0972baadfacc4969dc46e7c"
		score = 75
		quality = 75
		tags = "RUSSIAN, THREAT, ACTOR, FILE"

	strings:
		$enc_string = {F3 0F 7E 05 ?? ?? ?? ?? 6? [5] 6A ?? 66 [6] 66 [7] F3 0F 7E 05 ?? ?? ?? ?? 8D
85 [4] 6A ?? 50 66 [7] E8}
		$heap_ops = {8B [1-5] 03 ?? 5? 5? 6A 08 FF [1-6] FF ?? ?? ?? ?? ?? [0-6] 8B ?? [0-6] 8?}
		$xor_cycle = { 8A 8C ?? ?? ?? ?? ?? 30 8C ?? ?? ?? ?? ?? 42 3B D0 72 }

	condition:
		uint16( 0 ) == 0x5a4d and pe.is_dll ( ) and filesize < 100KB and $xor_cycle and $heap_ops and $enc_string
}

rule SBOUSSEADEN_APT_Xdsspy_Xdupload : FILE
{
	meta:
		description = "No description has been set in the source file - SBousseaden"
		author = "SBousseaden"
		id = "ae38d017-6420-596c-af29-62f15cfe56b8"
		date = "2020-05-10"
		modified = "2020-10-05"
		reference = "https://www.welivesecurity.com/2020/10/02/xdspy-stealing-government-secrets-since-2011/"
		source_url = "https://github.com/sbousseaden/YaraHunts//blob/71b27a2a7c57c2aa1877a11d8933167794e2b4fb/apt_xdspy_xdupload.yara#L1-L11"
		license_url = "N/A"
		logic_hash = "648ea81d1b44d8514439683cf2f86a8027f9e1eb64abf76d42347fc2ce9c4e68"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "cmd.exe /u /c cd /d \"%s\" & dir /a /-c" wide
		$s2 = "commandC_dll.dll"
		$s3 = "cmd.exe /u /c del" wide

	condition:
		uint16( 0 ) == 0x5a4d and 2 of ( $s* )
}

rule CRAIU_Apt_ZZ_Orangeworm_Kwampirs_Shamoon_Code : FILE
{
	meta:
		description = "Kwampirs and Shamoon common code"
		author = "FBI / cywatch@fbi.gov"
		id = "0d403b3b-a5a8-5ac6-a12d-7181a1ad11b3"
		date = "2020-01-14"
		modified = "2020-03-31"
		reference = "https://assets.documentcloud.org/documents/6821582/FLASH-CP-000118-MW-Downgraded-Version.pdf"
		source_url = "https://github.com/craiu/yararules/blob/23cf0ca22021fa3684e180a18416b9ae1b695243/files/apt_zz_orangeworm.yara#L85-L105"
		license_url = "https://github.com/craiu/yararules/blob/23cf0ca22021fa3684e180a18416b9ae1b695243/LICENSE"
		logic_hash = "5ab949280be87d242ad2843dee001eee5a338e266ef52da55883f7c77e66cf5b"
		score = 75
		quality = 85
		tags = "FILE"
		yara_version = "3.7.0"

	strings:
		$memcpy = { 56 8B F0 85 FF 74 19 85 D2 74 15 8B CF 85 F6 74 0B 2B D7 8A 04 0A 88 01 41 4E 75 F7 8B C7 5E C3 33 C0 5E C3 }
		$strlenW = { 33 C0 85 C9 74 17 80 3C 41 00 75 07 80 7C 41 01 00 74 0A 3D 00 94 35 77 73 03 40 EB E9 C3 }
		$strcmp = { 85 C0 75 07 85 D2 75 40 B0 01 C3 85 D2 74 39 66 83 38 00 56 74 24 0F B7 0A 66 85 C9 74 16
		66 8B 30 83 C2 02 83 C0 02 66 3B F1 75 18 66 83 38 00 75 E4 EB 06 66 83 38 00 75 0A 66 83 3A 00 75 04 B0
		01 5E C3 32 C0 5E C3 32 C0 C3 }

	condition:
		( uint16( 0 ) == 0x5a4d ) and ( 1 of them )
}

rule CRAIU_Apt_ZZ_Orangeworm_Kwampirs_Installer : FILE
{
	meta:
		description = "Kwampirs installer xor keys and Unicode string length routine"
		author = "FBI / cywatch@fbi.gov"
		id = "8c80d0d5-8c65-5cef-ad86-b38f4d671bec"
		date = "2020-01-14"
		modified = "2020-03-31"
		reference = "https://assets.documentcloud.org/documents/6821582/FLASH-CP-000118-MW-Downgraded-Version.pdf"
		source_url = "https://github.com/craiu/yararules/blob/23cf0ca22021fa3684e180a18416b9ae1b695243/files/apt_zz_orangeworm.yara#L109-L127"
		license_url = "https://github.com/craiu/yararules/blob/23cf0ca22021fa3684e180a18416b9ae1b695243/LICENSE"
		logic_hash = "ac9c3ba7188cbbe736ff81b41086fdc874ac24ae83d3cec390907f8edd0a0ce5"
		score = 75
		quality = 85
		tags = "FILE"
		yara_version = "3.7.0"

	strings:
		$string_key = { 6C 35 E3 31 1B 23 F9 C9 65 EB F3 07 93 33 F2 A3 }
		$resource_key = { 28 99 B6 17 63 33 EE 22 97 97 55 B5 7A C4 E1 A4 }
		$strlenW = { 33 C0 85 C9 74 17 80 3C 41 00 75 07 80 7C 41 01 00 74 0A 3D 00 94 35 77 73 03 40 EB E9 C3}

	condition:
		(( uint16( 0 ) == 0x5a4d ) and ( 2 of them ) )
}

rule CRAIU_Apt_ZZ_Orangeworm_Kwampirs_Implant : FILE
{
	meta:
		description = "Kwampirs implant xor and rsa keys"
		author = "FBI / cywatch@fbi.gov"
		id = "d1c1ab0e-e07d-5f0e-97e8-5aee53ab620e"
		date = "2020-01-14"
		modified = "2020-03-31"
		reference = "https://assets.documentcloud.org/documents/6821582/FLASH-CP-000118-MW-Downgraded-Version.pdf"
		source_url = "https://github.com/craiu/yararules/blob/23cf0ca22021fa3684e180a18416b9ae1b695243/files/apt_zz_orangeworm.yara#L130-L177"
		license_url = "https://github.com/craiu/yararules/blob/23cf0ca22021fa3684e180a18416b9ae1b695243/LICENSE"
		logic_hash = "a9559c17c802c6060799d0a1ee96d68bd521475dd12ff6040a74874cabe3a9a9"
		score = 75
		quality = 85
		tags = "FILE"
		yara_version = "3.7.0"

	strings:
		$string_key = { 6C 35 E3 31 1B 23 F9 C9 65 EB F3 07 93 33 F2 A3 }
		$beacon_key = { 28 30 A4 3F 6D 28 04 23 36 2A 32 DC AD 0B A0 4B E8 20 1F 64 84 0A F4 C4 C7 8A 8D C0
                        A2 C4 40 19 A1 43 82 38 14 FD 6C 90 E0 7E 2A 40 DF D3 F2 3E 72 38 C4 96 4D 98 7C 16 3B 3C E7 27 B7 D0 EF
                        7B 3C 45 06 9A 69 0D 6A 41 18 95 95 46 88 CC 19 6F EB 6B 5B F8 51 E4 2E E1 E6 8F 44 CF 20 2F 2B DE 7A 28
                        5D DB 55 5A 1A 35 AF D8 5F 57 B8 0F A5 F7 08 4A D0 AB E5 95 31 A1 25 31 00 65 3C 70 73 99 42 0A 02 1A 69
                        D9 A6 DF 14 B2 05 DD A8 DF F5 D9 71 6D 6E 96 5F 1B D1 0F 8E 0A 35 D4 65 FA 90 58 CC 75 02 92 B7 2C 46 ED
                        66 33 44 75 FC A4 E0 FD B8 C8 B5 0C 3A 84 D9 23 16 A4 AF 3B 57 C6 D2 5C B3 AB 9C CD F0 B2 A4 51 43 D3 F0
                        30 21 B5 ED 25 E3 64 B7 0C 1C A8 50 3A FF 6B 2C 32 06 B2 D1 54 3D 86 B9 1A BF 59 D7 92 59 EC 40 4A 8D B0
                        E7 9A 9A 0D 94 19 27 D8 6D AD 5C 3E BE 14 67 DC F0 92 }
		$download_key = { B7 E9 F9 2D F8 3E 18 57 B9 18 2B 1F 5F D9 A5 38 C8 E7 67 E9 C6 62 9C 50 4E 8D 00
                        A6 59 F8 72 E0 91 42 FF 18 A6 D1 81 F2 2B C8 29 EB B9 87 6F 58 C2 C9 8E 75 3F 71 ED 07 D0 AC CE 28 A1 E7
                        B5 68 CD CF F1 D8 2B 26 5C 31 1E BC 52 7C 23 6C 3E 6B 8A 24 61 0A 17 6C E2 BB 1D 11 3B 79 E0 29 75 02 D9
                        25 31 5F 95 E7 28 28 26 2B 31 EC 4D B3 49 D9 62 F0 3E D4 89 E4 CC F8 02 41 CC 25 15 6E 63 1B 10 3B 60 32
                        1C 0D 5B FA 52 DA 39 DF D1 42 1E 3E BD BC 17 A5 96 D9 43 73 3C 09 7F D2 C6 D4 29 83 3E 44 44 6C 97 85 9E
                        7B F0 EE 32 C3 11 41 A3 6B A9 27 F4 A3 FB 2B 27 2B B6 A6 AF 6B 39 63 2D 91 75 AE 83 2E 1E F8 5F B5 65 ED
                        B3 40 EA 2A 36 2C A6 CF 8E 4A 4A 3E 10 6C 9D 28 49 66 35 83 30 E7 45 0E 05 ED 69 8D CF C5 40 50 B1 AA 13
                        74 33 0F DF 41 82 3B 1A 79 DC 3B 9D C3 BD EA B1 3E 04 33 }
		$hashfile_key = { FE FE F5 5C 37 54 A1 6C 28 84 ED BF 84 70 25 41 56 24 37 32 98 9F A0 35 48 F3 1C 33
                        2E F9 D0 A3 7D 36 BA 66 ED FB 52 E3 8B 07 32 5A 1A DD 19 0A F0 73 A8 C6 61 3F 3F 31 8A 93 AB F4 19 AA D8
                        42 3B 3E 6E FC 0A 2A 41 1B 28 33 7F 79 27 41 81 14 D0 0B 24 06 4C 35 B3 23 5C F2 E4 06 7D 73 93 1C 7A 30
                        8E 87 74 0F 53 F9 92 A3 CA 20 E3 A1 12 E1 6B 86 62 B6 CC C1 45 C9 43 43 15 59 BE 5A 77 31 D8 36 5F BD F6
                        D7 09 65 42 3C CD 2C B1 C1 28 55 6E F9 91 3C 55 3B DF EB ED BF 84 70 25 41 56 24 37 32 98 9F A0 35 48 F3
                        1C 33 2E F9 D0 A3 7D 36 BA 66 ED FB 52 E3 8B 07 32 5A 1A DD 19 0A F0 73 A8 C6 61 3F 3F 31 8A 93 AB F4 19
                        AA D8 42 3B 3E 6E FC 0A 2A 41 1B 28 33 7F 79 27 41 81 14 D0 0B 24 06 4C 35 B3 23 5C F2 E4 06 7D 73 93 1C
                        7A 30 8E 87 74 0F 53 F9 92 A3 CA 20 E3 A1 12 E1 6B 86 }
		$rsa_key = { CD 74 15 BC 47 7E 0A 5E E4 35 22 A5 97 0C 65 BE E0 33 22 F2 94 9D F5 40 97 3C 53 F9 E4 7E
                        DD 67 CF 5F 0A 5E F4 AD C9 CF 27 D3 E6 31 48 B8 00 32 1D BE 87 10 89 DA 8B 2F 21 B4 5D 0A CD 43 D7 B4
                        75 C9 19 FE CC 88 4A 7B E9 1D 8C 11 56 A6 A7 21 D8 C6 82 94 C1 66 11 08 E6 99 2C 33 02 E2 3A 50 EA 58 D2
                        A7 36 EE 5A D6 8F 5D 5D D2 9E 04 24 4A CE 4C B6 91 C0 7A C9 5C E7 5F 51 28 4C 72 E1 60 AB 76 73 30 66 18
                        BE EC F3 99 5E 4B 4F 59 F5 56 AD 65 75 2B 8F 14 0C 0D 27 97 12 71 6B 49 08 84 61 1D 03 BA A5 42 92 F9 13
                        33 57 D9 59 B3 E4 05 F9 12 23 08 B3 50 9A DA 6E 79 02 36 EE CE 6D F3 7F 8B C9 BE 6A 7E BE 8F 85 B8 AA 82
                        C6 1E 14 C6 1A 28 29 59 C2 22 71 44 52 05 E5 E6 FE 58 80 6E D4 95 2D 57 CB 99 34 61 E9 E9 B3 3D 90 DC 6C
                        26 5D 70 B4 78 F9 5E C9 7D 59 10 61 DF F7 E4 0C B3 }

	condition:
		(( uint16( 0 ) == 0x5a4d ) and ( 2 of them ) )
}

rule DITEKSHEN_INDICATOR_RMM_Dwagent_Screencapture : FILE
{
	meta:
		description = "Detect DWAgent Remote Administration Tool Screen Capture Module"
		author = "ditekSHen"
		id = "79586e5e-b7e5-5adc-97f3-0d29ad695079"
		date = "2023-08-22"
		modified = "2024-10-04"
		reference = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/indicator_rmm.yar#L503-L528"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "d3160fd4cce445aa6d2bc6c083893c7610ea5e72824fe9824ad853700f4d3874"
		score = 75
		quality = 75
		tags = "FILE"
		clamav1 = "INDICATOR.Win.RMM.DWAgent-ScreenCapture"

	strings:
		$s1 = "DWAgentLib" fullword wide
		$s2 = "PYTHONHOME" wide
		$s3 = "VirtualBox" wide
		$s4 = "VMware" wide
		$s5 = "ScreenCapture::prepareCursor#" ascii
		$s6 = "ScreenCapture::getMonitorCount#" ascii
		$s7 = "ScreenCapture::token" ascii
		$s8 = "dwascreencapture" ascii
		$s9 = "inputKeyboard CTRLALTCANC" ascii
		$s10 = "_Z34ScreenCaptureNativeMonitorEnumProc" ascii
		$s11 = "_Z41ScreenCaptureNativeCreateWindowThreadProc" ascii
		$s12 = "_ZN13ScreenCapture" ascii
		$s13 = "isUserInAdminGroup" ascii

	condition:
		uint16( 0 ) == 0x5a4d and 7 of them
}


rule DITEKSHEN_MALWARE_Win_Fakecaptcha_Downloader : FILE
{
	meta:
		description = "Detects downloader executables dropped by fake captcha"
		author = "ditekshen"
		id = "d577e8ef-11df-565c-9925-63b8768a7115"
		date = "2020-11-06"
		modified = "2024-11-01"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/malware.yar#L11793-L11803"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "57c39ce93f74d03767e7fde53281983a8462e4f3705d1bb9084bc169a08a0f83"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "</script>MZ" ascii
		$s2 = "window.close();" ascii
		$s3 = "eval(" ascii

	condition:
		uint16( 0 ) == 0x5a4d and all of them
}

rule HARFANGLAB_Apt31_Rawdoor_Dropper : FILE
{
	meta:
		description = "Matches the RawDoor dropper"
		author = "HarfangLab"
		id = "b278a157-20e2-5271-aca0-0692929b881d"
		date = "2024-04-12"
		modified = "2026-01-29"
		reference = "TRR240401"
		source_url = "https://github.com/HarfangLab/iocs/blob/278c38e11e99d35af836cb9140e0857fd9226574/hl_public_reports_master.yar#L917-L938"
		license_url = "N/A"
		hash = "c3056e39f894ff73bba528faac04a1fc86deeec57641ad882000d7d40e5874be"
		logic_hash = "d0cbe02c4fafb4895bd0126d2496802a3fee6a0362e55bfa91cfd1c75043d94a"
		score = 75
		quality = 80
		tags = "FILE"
		context = "file"

	strings:
		$service_target = "%SystemRoot%\\system32\\svchost.exe -k netsvcs" ascii
		$service_dispname = "Microsoft .NET Framework NGEN" ascii
		$drop_name = "~DF313.msi" ascii
		$msg1 = "RegOpenKeyEx %s  error:%d\x0D\x0A" ascii
		$msg2 = "RegDeleteValue Wow64 . %d\x0D\x0A" ascii
		$msg3 = "CreateService %s success! but Start Faile.. %d\x0D\x0A" ascii
		$msg4 = "OutResFile to %s%s False!" ascii
		$msg5 = "Can't GetNetSvcs Buffer!" ascii

	condition:
		uint16( 0 ) == 0x5A4D and filesize > 350KB and filesize < 600KB and ( ( $service_target and $service_dispname and $drop_name ) or 3 of ( $msg* ) )
}

rule LOLDRIVERS_MAL_Driver_Legalcorp_Pciexpressvideocapture_FD22
{
	meta:
		description = "Detects malicious driver mentioned in LOLDrivers project using VersionInfo values from the PE header - PcieCubed.sys"
		author = "Florian Roth"
		id = "c9b28922-d4c7-5c09-9df8-b7b8d8ffc2e8"
		date = "2025-09-18"
		modified = "2025-09-18"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		source_url = "https://github.com/magicsword-io/LOLDrivers//blob/1746cc6486b247e898cf025d255130ea8ca44bbc/detections/yara/yara-rules_mal_drivers.yar#L350-L368"
		license_url = "https://github.com/magicsword-io/LOLDrivers//blob/1746cc6486b247e898cf025d255130ea8ca44bbc/LICENSE"
		hash = "fd223833abffa9cd6cc1848d77599673643585925a7ee51259d67c44d361cce8"
		logic_hash = "4c47a159595f420c520e6924238bd260f49ccf163208713c72c62638b13756d9"
		score = 70
		quality = 80
		tags = ""

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]005000430049006500200056006900640065006f00200043006100700074007500720065 }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]004c006500670061006c00200043006f00720070002e }
		$ = { 00460069006c006500560065007200730069006f006e[1-8]0031002e0030002e0030002e00310035 }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0031002e0030002e0030002e00310035 }
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]0050004300490020004500780070007200650073007300200056006900640065006f00200043006100700074007500720065 }
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]005000630069006500430075006200650064002e007300790073 }
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]00320030003100360020004c006500670061006c }

	condition:
		all of them
}

rule SEKOIA_Apt_Apt_K_47_Walkershell : FILE
{
	meta:
		description = "Detects WalkerShell used by APT-K-47"
		author = "Sekoia.io"
		id = "201f8415-32d4-4af1-ba80-734554ced728"
		date = "2024-02-14"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_apt_k_47_walkershell.yar#L1-L20"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "0dffd8e4d6c244a4faea0f8b8cda1e544a732ad9982e7963b21d5f71080f8f5d"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = "\\n kuskure" ascii wide
		$s2 = "col.log.txt" ascii wide
		$s3 = "polor" ascii wide
		$s4 = "emit" ascii wide
		$s5 = "delta" ascii wide
		$s6 = "under process" ascii wide

	condition:
		uint16be( 0 ) == 0x4d5a and filesize < 4MB and all of them
}

rule SEKOIA_Apt_Suspected_Sandworm_Sdelete_Wiper : FILE
{
	meta:
		description = "Detects Sdelete wiper"
		author = "Sekoia.io"
		id = "c1419b11-33e5-4280-b92a-039719cb17d3"
		date = "2023-10-25"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_suspected_sandworm_sdelete_wiper.yar#L1-L19"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "094b946b89cfb475b8692f88af73fa8768a933139e0df9d6e7d7aa8614d3ab14"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = ".exe -accepteula -r -s -q" wide
		$s2 = "sdelete [-p passes] [-r]" wide
		$s3 = "!This program cannot be run in DOS mode."

	condition:
		uint16be( 0 ) == 0x4d5a and $s1 and $s2 and #s3 == 2 and filesize < 500KB
}

rule SEKOIA_Apt_Uac0099_Lonepage : FILE
{
	meta:
		description = "Detects LonePage vbs malware"
		author = "Sekoia.io"
		id = "007f62f5-da5c-4df7-8b5c-5ed815ce6993"
		date = "2024-01-08"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_uac0099_lonepage.yar#L1-L30"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "479f438acb63c76e09722640b973e76d1f1924bf24db477ca6898d123091d5f8"
		score = 75
		quality = 76
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s0 = "dim r, c" ascii fullword
		$s1 = "= createobject(\"WScript.Shell\")" ascii fullword
		$s2 = "r.Run c, 0, false" ascii fullword
		$t1 = "GetHostAddresses" ascii fullword nocase
		$t2 = "upgrade.txt" ascii fullword nocase
		$t3 = "net.webclient" ascii fullword nocase
		$t4 = "downloaddata" ascii fullword nocase
		$t5 = "[System.Environment]::NewLine" ascii fullword nocase
		$t6 = ".uploaddata('" ascii nocase

	condition:
		true and filesize < 10KB and ( ( $s1 at 0x10 and $s0 at 0 and $s2 and 2 of ( $t* ) ) or ( all of ( $t* ) and any of ( $s* ) ) )
}

rule SEKOIA_Apt_Kimsuky_Sharptongue_Strings : FILE
{
	meta:
		description = "Detects SharpTongue variants."
		author = "Sekoia.io"
		id = "56027edb-4e6e-40ec-a1b9-36c52b0dd3ec"
		date = "2022-07-29"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_kimsuky_sharptongue_strings.yar#L1-L18"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "a7a9045485f6e713a8ae1bc87cd1296d64905b18e5d13d6e2b9a95328181af54"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = "Post0.Open" ascii wide
		$s2 = ".php?op=" ascii wide
		$s3 = "s=s&Mid(c,ix*d+jx+1,1)" ascii wide
		$s4 = "curl -o " ascii wide

	condition:
		$s2 in ( @s1 .. @s1 + 200 ) or $s2 in ( @s4 .. @s4 + 200 ) or $s3 and filesize < 500KB
}

rule SEKOIA_Apt_Kimsuky_Vbs : FILE
{
	meta:
		description = "VBS files used by Kimsuky"
		author = "Sekoia.io"
		id = "3f92dbda-2ddb-4fa3-a587-743f65ced9e4"
		date = "2024-09-23"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_kimsuky_vbs.yar#L1-L23"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		hash = "12386be22ca82fce98a83a5a19e632bc"
		hash = "7b5783d42240651af78ebf7e01b31fe8"
		hash = "ff7d68e5fb253664ce64c85457b28041"
		hash = "622358469e5e24114dd0eb03da815576"
		hash = "edbb2aa40408e2a7936067ace38b445b"
		hash = "73ed9b012785dc3b3ee33aa52700cfe4"
		logic_hash = "b4a05a50c8223198082f6f6aa7309cc19b019738fb99e37c6f2140b8ef7cecc9"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = ")):Next:Execute " ascii
		$ = "=\"\":" ascii
		$ = "\":for "

	condition:
		all of them and filesize < 10KB
}

rule SEKOIA_Apt_Andariel_Dorarat_Strings : FILE
{
	meta:
		description = "Detects Dora RAT based on strings"
		author = "Sekoia.io"
		id = "30388291-a287-489f-a060-c90a16cda217"
		date = "2024-06-17"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_andariel_dorarat_strings.yar#L1-L19"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "21e1c77d486cbf6ddaa2eca673275c7c21cc59fa9551c2eb02c526518ed5b217"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$x1 = "/encryption.go" ascii fullword
		$x2 = "/handshake.go" ascii fullword
		$x3 = "/trans_module.go" ascii fullword
		$enc_rsc = { 14 02 72 14 D3 4C 4A 49 55 36 14 DF 8D 6F 2D CF }

	condition:
		uint16be( 0 ) == 0x4d5a and ( all of ( $x* ) or $enc_rsc )
}

rule SEKOIA_Apt_Reaper_Malicious_Lnk : FILE
{
	meta:
		description = "No description has been set in the source file - SEKOIA"
		author = "Sekoia.io"
		id = "8f055d1b-5727-4d77-9671-cdbb1ea69d5f"
		date = "2023-09-12"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_reaper_malicious_lnk.yar#L1-L15"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "8cec5819dd7b01b3993acae056f5640fa28ffe76b05d2d9e59779a73eb00bd6e"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "*rshell.exe" wide
		$ = "/od') do call" wide

	condition:
		uint32be( 0 ) == 0x4c000000 and all of them
}

rule SEKOIA_Apt_Implant_Xdealer_Strings : FILE
{
	meta:
		description = "Detects XDealer based on strings"
		author = "Sekoia.io"
		id = "06ef72ca-b4e3-493b-8e01-d34b98259c6d"
		date = "2024-03-22"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_implant_xdealer_strings.yar#L1-L20"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "13c0bbc933f68164b0fe1c2768148bb649b1755bed0cfbc6ed90188fab6876d5"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "unknow_PC"
		$ = "rdp-tcp#"
		$ = "Din_%s_%s_%u_"
		$ = "nslookup %s %s"
		$ = "XFByb2dyYW1EYXRhXA=="

	condition:
		uint16be( 0 ) == 0x4d5a and 3 of them and filesize < 1MB
}

rule SEKOIA_Apt_Kimsuky_Toddlershark_Obfuscated : FILE
{
	meta:
		description = "Detects obfuscated version of Kimsuky TODDLERSHARK vbs malware"
		author = "Sekoia.io"
		id = "9ab82466-4f38-4597-b75b-13252e180c70"
		date = "2024-03-06"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_kimsuky_toddlershark_obfuscated.yar#L1-L18"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "5f067ce32e7fee5cf481d82bb98f4ae10bd7187078bc111b08fc58d043954152"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = { 3a 20 [3-10] 20 3d 20 22 [3-30] 22 3a }
		$s2 = { 45 78 65 63 75 74 65 28  [3-15] 28 22 }
		$s3 = { 50 72 69 76 61 74 65 20 46 75 6e 63 74 69 6f 6e 20 [3-15] 28 42 79 56 61 6c 20 [3-15] 29 3a }
		$s4 = "& Chr(\"&H\" & Mid("

	condition:
		#s4== 1 and #s3 == 1 and #s2 == 1 and #s1 > 20 and filesize < 1MB
}

rule SEKOIA_Apt_Kimsuky_Malicious_Gotopwsh_Lnk : FILE
{
	meta:
		description = "Detects malicious LNK used by Kimsuky"
		author = "Sekoia.io"
		id = "cfe9adf5-2c06-4d04-8006-c4eea0dab549"
		date = "2023-09-11"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_kimsuky_malicious_gotopwsh_lnk.yar#L1-L15"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "1537ea232e745b1ed9e4b7f6b9ba779a3498f5edf0c46bdccfdc511137b2bb3a"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = {67 00 6f 00 74 00 6f 00 26 00 70 00 5e 00 6f 00 77 00 5e 00 65 00 5e 00 72 00 73 00 5e 00 68 00 65 00 5e 00 6c 00 5e 00 6c}

	condition:
		uint32be( 0 ) == 0x4c000000 and all of them
}

rule SEKOIA_Apt_Kimsuky_Toddlershark_Strings : FILE
{
	meta:
		description = "Detects Kimsuky TODDLERSHARK vbs malware"
		author = "Sekoia.io"
		id = "2db1a424-9e83-4168-8ebf-d3b415b6a576"
		date = "2024-03-06"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_kimsuky_toddlershark_strings.yar#L1-L20"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "dee9d03f498437dd6d8399975cd91ec44307067ac4642b9ff31df1a6d6b10468"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "On Error Resume Next"
		$ = ".open \"POST\", \"http"
		$ = ".setRequestHeader"
		$ = ".send"
		$ = "Execute("
		$ = ".responseText)"

	condition:
		all of them and filesize < 450
}

rule SEKOIA_Apt_Lazarus_Dll_C2_Comms : FILE
{
	meta:
		description = "Detects DLL communicating with the C2"
		author = "Sekoia.io"
		id = "9b379aa8-77ce-4c76-ab13-05e35ebfbdfe"
		date = "2023-04-04"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_lazarus_dll_c2_comms.yar#L1-L33"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "b5ba5ae25822cf54d530d1a18c8196194d44e4fd76be1a0bf98c193772286282"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"
		hash1 = "fe948451df90df80c8028b969bf89ecbf501401e7879805667c134080976ce2e"
		hash2 = "bb1066c1ca53139dc5a2c1743339f4e6360d6fe4f2f3261d24fc28a12f3e2ab9"
		hash3 = "dca33d6dacac0859ec2f3104485720fe2451e21eb06e676f4860ecc73a41e6f9"
		hash4 = "69dd140f45c3fa3aaa64c69f860cd3c74379dec37c46319d7805a29b637d4dbf"

	strings:
		$x1 = "vG2eZ1KOeGd2n5fr" ascii fullword
		$s1 = "Windows %d(%d)-%s" ascii fullword
		$s2 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36" wide fullword
		$op1 = {B8 C8 00 00 00 83 FB 01 44 0F 47 E8 41 8B C5 48 8B B4 24 E0 18 00 00 4C 8B A4 24 E8 18 00 00 48 8B 8D A0 17 00 00 48 33 CC}
		$op2 = {33 D2 46 8D 04 B5 00 00 00 00 66 0F 1F 44 00 00 49 63 C0 41 FF C0 8B 4C 84 70 31 4C 94 40 48 FF C2}
		$op3 = {89 5C 24 50 0F 57 C0 C7 44 24 4C 04 00 00 00 C7 44 24 48 40 00 00 00 0F 11 44 24 60 0F 11 44 24 70 0F 11 45 80 0F 11 45 90}

	condition:
		( uint32be( 0 ) == 0x7f454c46 or uint16be( 0 ) == 0x4d5a ) and ( filesize < 500KB and ( 1 of ( $x* ) or 2 of them ) or ( $x1 and 1 of ( $s* ) or 3 of them ) )
}

rule SEKOIA_Apt_Cottonsandstorm_Win_Implant : FILE
{
	meta:
		description = "Detects a simple win implant used by Cotton Sandstorm"
		author = "Sekoia.io"
		id = "04a5255c-f9bb-4612-b0e2-ed0326867055"
		date = "2024-11-05"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_cottonsandstorm_win_implant.yar#L1-L24"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		hash = "f797d71ed07d6e05556300e4ce0f2927"
		logic_hash = "dcb25ee236ca52f23cc6bfdbcedcbc6d407e88f06341e684f202a59954733ade"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "DIR =>" wide
		$ = "type=machines&md5=" wide
		$ = "File =>" wide
		$ = "&ip=" wide fullword
		$ = "&un=" wide fullword
		$ = "&cp=" wide fullword
		$ = "myFile\";filename=" ascii
		$ = "ifB75BcjsRBhy2et" ascii

	condition:
		uint16be( 0 ) == 0x4d5a and 4 of them and filesize < 500KB
}

rule SEKOIA_Apt_Andariel_Nestdoor_Variants_Strings : FILE
{
	meta:
		description = "Detects Nestdoor based on (weak) strings"
		author = "Sekoia.io"
		id = "dcfc48ad-f17b-4224-912b-b01740080fea"
		date = "2024-06-17"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_andariel_nestdoor_variants_strings.yar#L1-L21"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "bc01138d1fc079c2b778175742e121f10cb47f29cc4eb04d38b4f0f5740f05a4"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$v_11 = "Error occurs while reading" wide
		$v_12 = "{DECIMAL}" wide
		$v_13 = "lnk_" wide
		$v_21 = "Cannot connect with your ip and your operating system." wide
		$v_22 = "del /q /f %1" ascii
		$v_23 = "/f /tn %2" ascii

	condition:
		( uint32be( 0 ) == 0x7f454c46 or uint16be( 0 ) == 0x4d5a ) and ( all of ( $v_1* ) or all of ( $v_2* ) )
}

rule SEKOIA_Apt_Mustangpanda_Xoreddll : FILE
{
	meta:
		description = "Detects xored DLL from MustangPanda embedding a document"
		author = "Sekoia.io"
		id = "73d13624-01df-41ab-b449-86db43dc6c55"
		date = "2022-07-19"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_mustangpanda_xoreddll.yar#L1-L20"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "685be191cf187c0d5bfd00354400c47a961c9d047aa7e65e4cfc2201ec5eb1bc"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$clear = "This program cannot be run in DOS mode"
		$stub = "This program cannot be run in DOS mode" xor
		$res1 = "5w>w9wR'31Z" xor
		$res2 = "r0y0~0KlBD" xor
		$res3 = "d&o&h&öé7Æ" xor
		$res4 = "9{2{5{+0" xor

	condition:
		$stub and any of ( $res* ) and not $clear and filesize < 3MB
}

rule SEKOIA_Apt_Boldmove_Strings : FILE
{
	meta:
		description = "Detects BOLDMOVE via strings"
		author = "Sekoia.io"
		id = "0458e282-f92f-4600-964a-de6b66b4a82d"
		date = "2023-01-16"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_boldmove_strings.yar#L1-L20"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "71649451b88629da1779c0856b2f1f60f87501962c69556f7943b049688a2d96"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = "cwd=%s" ascii wide
		$s2 = "executable=%s" ascii wide
		$s3 = "curl/6.12.34" ascii wide
		$s4 = "www.example.com" ascii wide
		$s5 = "GET /ws HTTP/1.1" ascii wide

	condition:
		( uint32be( 0 ) == 0x7f454c46 or uint16be( 0 ) == 0x4d5a ) and filesize < 4MB and 4 of them
}


rule SEKOIA_Apt_Mustangpanda_Downloader : FILE
{
	meta:
		description = "Detects the MustangPanda Downloader"
		author = "Sekoia.io"
		id = "54850ffd-f93b-4082-b3ca-8e1d60b35422"
		date = "2022-03-02"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_mustangpanda_downloader.yar#L1-L19"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "0bff0ee2960ecfa29939720e7efacaa35359f4fe555ae160c674efebf29bf61e"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "Windows Api" wide nocase
		$ = "200 OK" wide
		$ = "200 ok" wide
		$ = "mscoree.dll" wide

	condition:
		uint16be( 0 ) == 0x4d5a and all of them
}

rule SEKOIA_Apt_Rusticweb_Stealer : FILE
{
	meta:
		description = "Detects stealer used by RusticWeb"
		author = "Sekoia.io"
		id = "813072e0-28de-4cb7-b2cc-71d77a1e8508"
		date = "2024-01-09"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_rusticweb_stealer.yar#L1-L19"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "68f802ef442e68cbcca789eae2bb8a4395af86699320e5a8101c07469e7555fb"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = "-FTT=@"
		$s2 = "https://oshi.at"
		$s3 = "curl-T"
		$s4 = "upload/upload.php"
		$s5 = "cargo"

	condition:
		uint16be( 0 ) == 0x4d5a and filesize < 4MB and 3 of them
}

rule SEKOIA_Apt_Aridviper_Rustsysjoker : FILE
{
	meta:
		description = "Detects Rust Sysjoker variant via PDB path or key and Rust string"
		author = "Sekoia.io"
		id = "14ff3f76-0371-4b45-9864-bf69c74e60aa"
		date = "2023-11-27"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_aridviper_rustsysjoker.yar#L1-L18"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "cb3c5d37095c27aa169a6aa61fa12972ff71877c615eaa254c3906ef10c662a9"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$Rust = "called `Option::unwrap()` on a `None` value"
		$Key = "QQL8VJUJMABL8H5YNRC9QNEOHA"
		$PDB = "C:\\Code\\Rust\\RustDown-Belal\\target\\release\\deps\\RustDown.pdb"

	condition:
		uint16be( 0 ) == 0x4d5a and filesize < 1MB and ( $PDB or ( $Rust and $Key ) )
}


rule SEKOIA_Apt_Cloudatlas_Stagescalldllmainafterexec
{
	meta:
		description = "Detects call to dllmain after execution of exported function"
		author = "Sekoia.io"
		id = "a24b7887-87f6-44e3-80c5-cd117e694595"
		date = "2023-10-31"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_cloudatlas_stagescalldllmainafterexec.yar#L1-L46"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "6d1c1717b4012e72b0069068158265dfd215cd7685a5489aba3de4a9024bfa28"
		score = 75
		quality = 80
		tags = ""
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$chunk_1 = {
        55
        8B EC
        83 EC 10
        C7 45 ?? 00 00 00 00
        83 7D ?? 00
        74 ??
        8B 45 ??
        89 45 ??
        8B 4D ??
        8B 51 ??
        03 55 ??
        89 55 ??
        8B 45 ??
        8B 48 ??
        03 4D ??
        89 4D ??
        6A 00
        6A 00
        FF 75 ??
        FF 55 ??
        68 00 80 00 00
        6A 00
        8B 55 ??
        52
        FF 15 ?? ?? ?? ??
        C7 45 ?? 01 00 00 00
        8B 45 ??
        8B E5
        5D
        C2 04 00
        }

	condition:
		any of them
}

rule SEKOIA_Apt_Aptc60_Downloader_Strings : FILE
{
	meta:
		description = "Detects a simple downloader abusing wlrmdr.exe and used by APT-C-60"
		author = "Sekoia.io"
		id = "02fd6d5b-7211-46cc-bcff-ab5d78e459c0"
		date = "2024-09-05"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_aptc60_downloader_strings.yar#L1-L20"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		hash = "b14ef85a60ac71c669cc960bdf580144"
		logic_hash = "f05480834e6d91a852a190a2ecec05aaea1affa8a605a56c80962a9fbfc8f0c0"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "mydllmain" fullword
		$ = "-s 3600 -f 0 -t _ -m _ -a 11 -u" wide
		$ = "WlrMakeService" wide
		$ = "Trigger1" wide

	condition:
		uint16be( 0 ) == 0x4d5a and all of them and filesize < 500KB
}

rule SEKOIA_Apt_Spynote_Android_Dex_Strings : FILE
{
	meta:
		description = "Detects Android SpyNote DEX file"
		author = "Sekoia.io"
		id = "87fb8b7a-bfac-4003-b618-50b4a7863928"
		date = "2022-08-22"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_spynote_android_dex_strings.yar#L1-L20"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "474617628afe110d9e7ea2acef57c5e560139b57aa7e497bf9e111af239e9588"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "is not file found"
		$ = "Can not access"
		$ = "PANG !!"
		$ = "On Start!!"

	condition:
		uint32be( 0 ) == 0x6465780A and filesize < 1MB and all of them
}

rule SEKOIA_Apt_Tealkurma_Snappytcp_Reverse_Shell_Strings : FILE
{
	meta:
		description = "Detects TealKurma SnappyTCP reverse shell"
		author = "Sekoia.io"
		id = "e842825c-546c-475a-bc94-7e97aea4e9e0"
		date = "2023-12-08"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_tealkurma_snappytcp_reverse_shell_strings.yar#L1-L21"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "feb24cafcf5b080c91dab42bf8d78fbdb0b7fae9395c7513f02aa90a25663d2c"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "2>&1>/dev/null&" ascii
		$ = ".php HTTP/1.1" ascii
		$ = "GET /" ascii
		$ = "Hostname: %s" ascii
		$ = "bash -c \"./" ascii

	condition:
		uint32be( 0 ) == 0x7f454c46 and filesize < 3MB and 3 of them
}

rule SEKOIA_Apt_Aptk47_Asyncshell : FILE
{
	meta:
		description = "Detects APT-K-47's Asyncshell"
		author = "Sekoia.io"
		id = "2d009cf4-e30e-406d-8860-03b37a396ffa"
		date = "2024-11-22"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_aptk47_asyncshell.yar#L1-L24"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		hash = "ce6a589d5e3604112e5595a1f8d53e1e"
		hash = "751f427da8e11d8ab394574260735220"
		logic_hash = "ac202f7dc317d17118badf71c32776c5666eea4a47e1b439a287b6b8766e9da6"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "Error executing command:" wide
		$ = "Error occurred:" wide
		$ = "Attempting to reconnect in {0} seconds..." wide
		$ = "Exiting the application." wide
		$ = "Server disconnected." wide
		$ = "_CorExeMain"

	condition:
		uint16be( 0 ) == 0x4d5a and filesize < 1MB and 4 of them
}

rule SEKOIA_Apt_Cloudatlas_Powershower_Module : FILE
{
	meta:
		description = "Detects CloudAtlas PowerShower module"
		author = "Sekoia.io"
		id = "dd688058-3d5d-46a7-8380-fe961c3327cd"
		date = "2022-11-30"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_cloudatlas_powershower_module.yar#L1-L18"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "7542eb882ee44203d806ad936126be2476b6e3a85ad8c93b6fd6c8226fe82617"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "$env:temp" ascii wide
		$ = "foreach($item in $zip.items" ascii wide
		$ = "echo $result" ascii wide
		$ = "pass.txt" ascii wide

	condition:
		all of them and filesize < 10000
}


rule SEKOIA_Apt_Blackwood_Nspx30_Plugin : FILE
{
	meta:
		description = "Detects plugins of NSPX30 backdoor based on RTTI and rundll32 string"
		author = "Sekoia.io"
		id = "ef8e0d51-c78c-426b-8008-910e27546f23"
		date = "2024-01-29"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_blackwood_nspx30_plugin.yar#L1-L17"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "cf7c232a5a817ff5c0da04744abf99ed2fcea587e3e6f6e8bf3aef7ca8f2b51b"
		score = 75
		quality = 76
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = {2E 3F 41 56 43 43 61 62 69 6E 65 74 40 40}
		$s2 = {2E 3F 41 56 43 45 6E 63 6F 64 65 72 40 40}
		$s3 = "rundll32.exe \"%hs\",#1" wide

	condition:
		uint16be( 0 ) == 0x4d5a and filesize < 1MB and all of them
}


rule SEKOIA_Apt_Mustang_Panda_Toneshell : FILE
{
	meta:
		description = "Detect the TONESHELL implant used by Mustang Panda from specific functions"
		author = "Sekoia.io"
		id = "bf7c68a9-dddc-494a-a603-c2311ed712a4"
		date = "2022-11-28"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_mustang_panda_toneshell.yar#L4-L160"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "192fb01817cc6361062999cf539c51616d1755a5cd8e9d6e37bee6f6d04b0721"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$func1 = {
        55
        89 E5
        64 A1 18 00 00 00
        A3 ?? ?? ?? ??
        5D
        C3
        }
		$func2 = {
        55
        89 E5
        50
        8B 45 ??
        8B 45 ??
        8B 45 ??
        8B 45 ??
        89 45 ??
        8B 45 ??
        89 C1
        83 C1 FF
        89 4D ??
        83 F8 00
        0F 84 ?? ?? ?? ??
        8B 45 ??
        8A 08
        8B 45 ??
        88 08
        8B 45 ??
        83 C0 01
        89 45 ??
        8B 45 ??
        83 C0 01
        89 45 ??
        E9 ?? ?? ?? ??
        8B 45 ??
        83 C4 04
        5D
        C3
        }
		$decryption_routine1 = {
        8B 45 ??
        C7 45 ?? 00 00 00 00
        83 7D ?? 20
        0F 8D ?? ?? ?? ??
        8B 45 ??
        8B 4D ??
        0F BE 04 08
        83 F0 ??
        88 C2
        8B 45 ??
        8B 4D ??
        88 14 08
        8B 45 ??
        83 C0 01
        89 45 ??
        E9 ?? ?? ?? ??
        83 C4 04
        }
		$decryption_routine2 = {
        55
        89 E5
        83 EC 08
        8B 45 ??
        8B 45 ??
        8B 45 ??
        8B 45 ??
        C7 45 ?? 00 00 00 00
        C7 45 ?? 00 00 00 00
        8B 45 ??
        3B 45 ??
        0F 8D ?? ?? ?? ??
        8B 45 ??
        8B 4D ??
        0F BE 04 08
        8B 4D ??
        8B 55 ??
        0F BE 0C 11
        31 C8
        88 C2
        8B 45 ??
        8B 4D ??
        88 14 08
        8B 45 ??
        8B 4D ??
        83 E9 01
        39 C8
        0F 85 ?? ?? ?? ??
        C7 45 ?? 00 00 00 00
        E9 ?? ?? ?? ??
        8B 45 ??
        83 C0 01
        89 45 ??
        8B 45 ??
        83 C0 01
        89 45 ??
        E9 ?? ?? ?? ??
        83 C4 08
        5D
        C3
        }

	condition:
		uint16be( 0 ) == 0x4d5a and filesize < 8MB and for all i in ( 0 .. pe.number_of_sections -1 ) : ( hash.md5 ( pe.sections [ i ] . raw_data_offset , pe.sections [ i ] . raw_data_size ) != "69f400d3ff4679294e63fb8a8ca97dbb" ) and 3 of them and true
}


rule SEKOIA_Apt_Gamaredon_Powerrevshell : FILE
{
	meta:
		description = "Detects Powershell reverse shell"
		author = "Sekoia.io"
		id = "b5161c23-c607-4096-9f4a-1be516a0a614"
		date = "2023-02-08"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_gamaredon_powerrevshell.yar#L1-L19"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "fc5abcdf47641c1e7978cf076550f38987305bb2171b3e65f7865102a065af43"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "iex $enc.GetString("
		$ = "$stream.Write"
		$ = ".).FullName"
		$ = "Sockets.TcpClient"
		$ = "\">\";"

	condition:
		all of them and filesize < 3000
}

rule SEKOIA_Apt_Apt37_Chinotto_Powershell_Variant
{
	meta:
		description = "Detects APT37 Chinotto Powershell Variant"
		author = "Sekoia.io"
		id = "fa42b225-58fe-4e00-b84b-df37491d8fdd"
		date = "2023-03-06"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_apt37_chinotto_powershell_variant.yar#L1-L20"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "b4d17467f15d52bd615e335fa8bc31381ec273b67dabb74655f47179f04f631f"
		score = 75
		quality = 80
		tags = ""
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "$env:COMPUTERNAME + '-' + $env:USERNAME;" ascii wide
		$ = "while($true -eq $true)" ascii wide
		$ = "Start-Sleep -Seconds" ascii wide
		$ = " -ne 'null' -and $" ascii wide
		$ = "= 'R=' + [System.Convert]::" ascii wide
		$ = "[string]$([char]0x0D) + [string]$([char]0x0A);" ascii wide

	condition:
		4 of them
}


rule SEKOIA_Apt_Sidecopy_Actionrat_Packer_Strings : FILE
{
	meta:
		description = "Detects SideCopy's ActionRAT (packer?)"
		author = "Sekoia.io"
		id = "b9370bd5-12e1-448e-a5b1-2acc72adc4a7"
		date = "2023-05-11"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_sidecopy_actionrat_packer_strings.yar#L1-L19"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "1bb6896ac3efa0e43cc27f56d7324ab9bdd2c401941eeefc4e7be62b407657af"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "(HTTP/1\\.[01]) (\\d{3})(?: (.*?))?"
		$ = "cpp-httplib/0.7"
		$ = "\\HTTP Arsanel\\"

	condition:
		uint16be( 0 ) == 0x4d5a and filesize < 1MB and all of them
}

rule SEKOIA_Apt_Gelsemium_Wolfsbane_Launcher : FILE
{
	meta:
		description = "Detects Gelsemium's WolfsBane launcher"
		author = "Sekoia.io"
		id = "26fbf4df-aa08-47b6-a73c-e8f80a408454"
		date = "2024-11-22"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_gelsemium_wolfsbane_launcher.yar#L1-L21"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		hash = "87e437cf74ce4b1330b8af9ff71edae2"
		logic_hash = "9ecc3a8cb82f6183c263dde03a14f721d2e3aeb2338afc28e0368c323e5d51a9"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "rm -f /dev/shm/sem*%s"
		$ = "/etc/ld.so.preload"
		$ = "kill -9 %d 2>/dev/null"
		$ = "/,1d' %s 2>/dev/null"

	condition:
		uint32be( 0 ) == 0x7F454C46 and filesize < 500KB and all of them
}


rule SEKOIA_Apt_Badmagic_Commonmagic_Usbstealer : FILE
{
	meta:
		description = "Detects CommonMagic related implants"
		author = "Sekoia.io"
		id = "37d5becc-f1c3-4400-bc10-cd6036d4dbb1"
		date = "2023-05-15"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_badmagic_commonmagic_usbstealer.yar#L1-L20"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "a600f17bce9159b581c234cc101d1a0d093954fc9c79052dbca5451714fd7502"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "\\\\.\\pipe\\PipeDtMd" ascii wide fullword
		$ = "State USB" ascii wide
		$ = "DefaultNameDevice" ascii wide
		$ = "SerialNumber" ascii wide

	condition:
		uint16be( 0 ) == 0x4d5a and filesize < 1MB and all of them
}


rule SEKOIA_Apt_Cloudmensis_Downloader_Strings : FILE
{
	meta:
		description = "Detects CloudMensis downloader"
		author = "Sekoia.io"
		id = "450cfa42-7b56-4d93-afe2-9cf5c1049217"
		date = "2022-07-26"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_cloudmensis_downloader_strings.yar#L1-L20"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "9532530f9b6c39d64611354f5d3c95e7c8b9ebf917ab797c162c3b51945db1fc"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "https://api.pcloud.com/getfilelink?path=%@&forcedownload=1"
		$ = "python -c 'import os; print(os.confstr(65538))'"
		$ = "getCmdResult:"
		$ = "[pCloud DownloadFile:]"

	condition:
		uint32be( 0 ) == 0xcafebabe and filesize < 1MB and all of them
}

rule SEKOIA_Apt_Susp_Apt28_Uac0063_Hta_Loader
{
	meta:
		description = "Detects some suspected APT28 HTA loader"
		author = "Sekoia.io"
		id = "8e1889c1-c6ac-4048-9d3a-99ccbbd5435f"
		date = "2024-07-25"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_susp_apt28_uac0063_hta_loader.yar#L1-L18"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		hash = "332d9db35daa83c5ad226b9bf50e992713bc6a69c9ecd52a1223b81e992bc725"
		logic_hash = "494331a8088d350e4e49e67fe64041d451886e501775413f908bd9b3faa98aeb"
		score = 65
		quality = 80
		tags = ""
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "<HEAD><HTA:APPLICATION ID" ascii fullword
		$ = "id=service>null</span" ascii fullword
		$ = "script Language=\"VBScript.Encode" ascii fullword

	condition:
		2 of them
}

rule SEKOIA_Apt_Luckymouse_Compromised_Electronapp : FILE
{
	meta:
		description = "Detects compromised ElectronApp"
		author = "Sekoia.io"
		id = "7702217d-771f-47af-8eaa-d5acf1e14f4d"
		date = "2022-08-05"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_luckymouse_compromised_electronapp.yar#L1-L15"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "939546b75d5f7161bb8eb1fd838a9a7c0c88cb58a0f01f67e687523e5b31b0aa"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s = "module.exports=function(t){eval(function(p,a,c,k,e,r)"

	condition:
		$s at 0 and filesize < 100KB
}

rule SEKOIA_Apt_Uac0154_Malicious_Html_Smuggling : FILE
{
	meta:
		description = "UAC-0154 Infection chain"
		author = "Sekoia.io"
		id = "923d11e5-6332-456d-8aff-ae7fb76193a8"
		date = "2023-10-02"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_uac0154_malicious_html_smuggling.yar#L1-L17"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "ba37b076ac29edcb9af7792420b527b0d64e7838e0237b39afe98a817eafdf7e"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "Microsoft&reg; HTML Help Workshop 4.1"
		$ = "var a=['"
		$ = ")+b('0x"

	condition:
		all of them and filesize < 100KB
}

rule SEKOIA_Apt_Win_Disabledefender
{
	meta:
		description = "detects strings and imphash"
		author = "Sekoia.io"
		id = "a7b124ab-4c9d-47c0-a59e-211cc713b9b3"
		date = "2022-09-23"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_win_disabledefender.yar#L3-L20"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "3b8c8d9144d9f97ee053c7cefc30d3920940bc33efcd1d7f5c61666217ef7896"
		score = 75
		quality = 80
		tags = ""
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "Restarting with privileges"
		$ = "Windows defender is currently ACTIVE"
		$ = "Windows defender is currently OFF"
		$ = "Disabled windows defender"
		$ = "Failed to disable defender..."

	condition:
		4 of them or pe.imphash ( ) == "74a6ef9e7b49c71341e439022f643c8e"
}

rule SEKOIA_Apt_Cloudmensis_Spyagent_Strings : FILE
{
	meta:
		description = "Detects CloudMensis SpyAgent"
		author = "Sekoia.io"
		id = "c2df8373-6698-4b23-9d77-8e7968bd69f0"
		date = "2022-07-26"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_cloudmensis_spyagent_strings.yar#L1-L21"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "ad858b1b78fb4ac6efee093b11fde14956d63bc6b300ef37bf1f2a3356cf4402"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "[control_thread loop_DirStructure:]"
		$ = "[screen_keylog getScreenShotData]"
		$ = "[screen_keylog loop_usb]"
		$ = "[Management UploadFilebyPath:destination:]"
		$ = "[control_thread loop_pwd:]"

	condition:
		uint32be( 0 ) == 0xcafebabe and filesize < 2MB and all of them
}


rule SEKOIA_Apt_Apt28_Susp_Graphite_Downloader : FILE
{
	meta:
		description = "Matches the routine which decrypts the RSA key blob in the Graphite downloader"
		author = "Sekoia.io"
		id = "9c9da5fe-ffd6-4c45-8ce1-9a6cf4fa2fda"
		date = "2022-01-26"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_apt28_susp_graphite_downloader.yar#L3-L26"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "ca5aa7ea995aca9003fd98da2fba7bbec1e049d979a6b05e07b80876bab5a1c9"
		score = 65
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$gen = { 33 D2
        8B C1
        6A ??
        5E
        F7 F6
        8A 82 ?? ?? ?? ??
        30 81 ?? ?? ?? ??
        41
        81 F9 94 04 00 00
        72 E2 }

	condition:
		uint16be( 0 ) == 0x4d5a and $gen and pe.number_of_exports == 1
}

rule SEKOIA_Apt_Apt28_Powershell_Ntlm_Stealer : FILE
{
	meta:
		description = "Detects the NTLM Stealer used by APT28 against UA energy sector"
		author = "Sekoia.io"
		id = "3fb5c472-6b1c-490e-b38f-4d4f1c472f43"
		date = "2023-09-07"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_apt28_powershell_ntlm_stealer.yar#L1-L19"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "29d039bf7d7018ebbae187ae0f057161c3f9256076324f06167872adc0accfa7"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "'NTLM ' = [Convert]::ToBase64String"
		$ = ".Prefixes.Add('http://localhost:8080/')"
		$ = ".AddHeader('WWW-Authenticate', 'NTLM')"
		$ = "GetValues('Authorization');"
		$ = "[0] -split '\\s+';"

	condition:
		3 of them and filesize < 4000
}

rule SEKOIA_Apt_Scanbox_Obfuscated_Versions : FILE
{
	meta:
		description = "Detects obfuscated versions of the scanbox framework"
		author = "Sekoia.io"
		id = "2866cead-7f16-4895-80ef-aad6fb66e864"
		date = "2022-09-01"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_scanbox_obfuscated_versions.yar#L1-L20"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "0395d1ac9a593aa8249f6d16c485e431349cecf2f379d2b5bac466541f71968c"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "$_$_$_$__$_____$__$_$_$_$__$"
		$ = "NztCm_NcDkh"
		$ = "____$_$__$__$_______w____$_$__$__$_____i____$_$__$__$_____"
		$ = "391,379,398,381,386"
		$ = "plguinurl"
		$ = "plugin_timeout*1000"

	condition:
		2 of them and filesize < 500KB
}

rule SEKOIA_Apt_Gamaredon_Subtle_Paws : FILE
{
	meta:
		description = "SUBTLE-PAWS powershell backdoor used by Gamaredon"
		author = "Sekoia.io"
		id = "1950f886-97d2-4aa1-8f13-2947eba706e4"
		date = "2024-02-09"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_gamaredon_subtle_paws.yar#L1-L18"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "2fcebcf3401912e06ca4a34bf4e8d5318c6b2e08b00c4939ab932f3fb94cbc89"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = "$splitter" ascii wide
		$s2 = "[System.Convert]::FromBase64String" ascii wide
		$s3 = "$_;$var2 =\"var1\";$var3" ascii wide
		$s4 = "foreach-object{$_|powershell -noprofile -}" ascii wide

	condition:
		$s1 and $s2 and ( $s3 or $s4 ) and filesize < 100KB
}

rule SEKOIA_Apt_Konni : FILE
{
	meta:
		description = "Rule based on structure offsets and file extension"
		author = "Sekoia.io"
		id = "6a20c492-e932-41bd-ac4a-01d35bfb0c49"
		date = "2022-09-12"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_konni.yar#L1-L25"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "8f178421fd0968f4ce809054022579c7fc8dede5f6514e89966d13acb83d75d9"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ext_1 = ".zip" wide ascii fullword
		$ext_2 = ".cab" wide ascii fullword
		$ext_3 = ".rar" wide ascii fullword
		$ext_4 = ".ini" wide ascii fullword
		$ext_5 = ".dat" wide ascii fullword
		$offset_structure_1 = { 8d ?? 08 02 00 00 }
		$offset_structure_2 = { 8d ?? 10 04 00 00 }
		$offset_structure_3 = { 8d ?? 18 06 00 00 }
		$url = "%s/dn.php?name=%s&prefix=%s" wide

	condition:
		uint16be( 0 ) == 0x4d5a and filesize < 3MB and 3 of ( $ext_* ) and all of ( $offset_structure_* ) and $url
}

rule SEKOIA_Apt_Mustangpanda_Maliciousdll_Loading_Plugx_Strings
{
	meta:
		description = "Detects MustangPanda malicious DLL"
		author = "Sekoia.io"
		id = "2296ac6e-63f5-4cff-aeb7-2c5205e6f559"
		date = "2023-12-18"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_mustangpanda_maliciousdll_loading_plugx_strings.yar#L3-L23"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		hash = "651c096cf7043a01d939dff9ba58e4d69f15b2244c71b43bedb4ada8c37e8859"
		logic_hash = "667901d36585248a891b90ff8ed7006030151fbbbe0d4a85570944a94edba7f8"
		score = 75
		quality = 80
		tags = ""
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "VirtualAlloc"
		$ = "VirtualFree"
		$ = "VirtualProtect"
		$ = "VirtualQuery"
		$ = "GCC: (MinGW-W64"

	condition:
		pe.exports( "MsiProvideQualifiedComponentW" ) and all of them
}

rule SEKOIA_Apt_Sandworm_Awfulshred_Obfuscation_Apr2022 : FILE
{
	meta:
		description = "Detects the AWFULSHRED wiper used by Sandworm"
		author = "Sekoia.io"
		id = "52317e6b-7f2c-4c2a-bcfc-ebb4ab4c728e"
		date = "2022-04-12"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_sandworm_awfulshred_obfuscation_apr2022.yar#L1-L16"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "3e1eed3a4b638893828289f928a75b855bc9e1e29444ffa81c0461fdc1277cad"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$h = "#!/bin/bash"
		$s = { 64 65 63 6c 61 72 65 20 2d 72 20 [8] 3d }

	condition:
		$h at 0 and #s > 15
}

rule SEKOIA_Apt_Lazarus_Dangerouspassword_Lnk : FILE
{
	meta:
		description = "Detects Lazarus DangerousPassword LNKs"
		author = "Sekoia.io"
		id = "32533880-7f75-4682-a7ae-9868d0b5174b"
		date = "2022-07-26"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_lazarus_dangerouspassword_lnk.yar#L1-L21"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "79731450c4623f614c55d8c08d879579e21fd38c85d2a288724b6e9470de6e29"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = {6D 00 73 00 68 00 2A}
		$s2 = {25 00 70 00 75 00 62 00 6C 00 69 00 63 00 25}
		$s3 = {44 00 4F 00 20 00 73 00 74 00 61 00 72 00 74}
		$b1 = {2F 00 63 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 2F 00 62 00 20 00 6D 00 73 00 68 00 74 00 61}
		$c1 = {68 00 74 00 74 00 70 00 73 00 3A 00 2F 00 2F 00 62 00 69 00 74 00 2E 00 6C 00 79 00 2F}

	condition:
		uint32be( 0 ) == 0x4C000000 and filesize > 1KB and filesize < 40MB and ( all of ( $s* ) or $b1 or ( $s1 and $c1 ) )
}

rule SEKOIA_Apt_Malware_Pocoproxy : FILE
{
	meta:
		description = "Detects strings in PocoProxy"
		author = "Sekoia.io"
		id = "8b37e37f-339e-4f8b-b792-435096f56af0"
		date = "2024-08-13"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_malware_pocoproxy.yar#L1-L25"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		hash = "2b89f15012512002c656ff821bbbeca0"
		hash = "8d850fed6bb1f3b60365ed656c6791c5"
		logic_hash = "217f4eabb5ff4534878b6dd192ae446e651d8510f03ceb501eb33e91199c15a8"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "-listen" ascii fullword
		$ = "-connect" ascii fullword
		$ = "-proxy" ascii fullword
		$ = "%d-%d-%d %d:%d:%d" ascii fullword
		$ = "%S://%S:%u%S" wide
		$ = "\\r\\n[%u(%u/%u/%u/%u)]==> %S  %S>> %S:%d connect ok." wide
		$ = "\\r\\nnconnect to %S:%d faild." wide
		$ = "\\r\\nI'm listen %S:%d,welcome..." wide

	condition:
		uint16be( 0 ) == 0x4d5a and 5 of them
}

rule SEKOIA_Apt_Konni_Dropper : FILE
{
	meta:
		description = "Detects Konni dropper used when distributed via malicious document"
		author = "Sekoia.io"
		id = "0783a55e-1d1e-40ca-a661-2c5dec6d78d6"
		date = "2023-11-27"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_konni_dropper.yar#L1-L19"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "6d1b1f5ccbdc20908891e5f40ceb85c251b1ca2a395fa4b106e63718c6393a22"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "UnzipAFile"
		$ = "check.bat"
		$ = "FOF_SILENT"
		$ = "fLieObj"

	condition:
		filesize < 1MB and 3 of them
}

rule SEKOIA_Apt_Cloudatlas_Powertunnel : FILE
{
	meta:
		description = "Detects PowerTunnel DLL of CloudAtlas"
		author = "Sekoia.io"
		id = "04981493-de8b-4662-ae81-8866c182f8b2"
		date = "2022-11-29"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_cloudatlas_powertunnel.yar#L1-L21"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "aadb2739957d17c7e82e3abf7a178ab7b6e4a598fbbdb1a06d0c0531656d4ef6"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "BeginGetHostEntry"
		$ = "get_AddressList"
		$ = "time_stop_delay_seconds"
		$ = "<connect><result>{0}</result></connect>"
		$ = "_CorDllMain"

	condition:
		uint16be( 0 ) == 0x4d5a and filesize < 1MB and all of them
}


rule SEKOIA_Apt_Granitetyphoon_Pingpulllinux_Strings : FILE
{
	meta:
		description = "Detects PingPull Linux variant"
		author = "Sekoia.io"
		id = "ee213206-d9ad-47fa-bea1-61a9d2cfba58"
		date = "2023-05-25"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_granitetyphoon_pingpulllinux_strings.yar#L1-L25"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "89c89bb24d1996c04fba0e6ebfd2aaf1544d8a9e6333b896c1855747fb979308"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "chkconfig --add %s"
		$ = "chkconfig %s on"
		$ = "update-rc.d %s enable"
		$ = "service %s start"
		$ = "respawn limit 10 10"
		$ = "POST /%s HTTP/1.1"
		$ = "PROJECT_%s_%s_%08X"
		$ = "Description=The HTTP(S) Client"
		$ = "exec %s -f"

	condition:
		uint32be( 0 ) == 0x7f454c46 and filesize < 11MB and 7 of them
}


rule SEKOIA_Apt_Mustang_Panda_Toneins : FILE
{
	meta:
		description = "Detect the TONEINS implant used by Mustang Panda"
		author = "Sekoia.io"
		id = "f178217a-ff28-4dd7-9395-f19f3e2e934c"
		date = "2022-11-28"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_mustang_panda_toneins.yar#L4-L44"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "b71932f16ffb1d8d1780b6f9b4db2f0c98d1c770829a4d2284e78c19d37e54bb"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$rtti1 = ".?AVDNameNode@@"
		$rtti2 = ".?AVcharNode@@"
		$rtti3 = ".?AVpcharNode@@"
		$rtti4 = ".?AVpDNameNode@@"
		$rtti5 = ".?AVDNameStatusNode@@"
		$rtti6 = ".?AVpairNode@@"
		$s1 = "DefWindowProcW1222_test" wide ascii
		$s2 = "schtasks /create /sc minute /mo 2 /tn" wide ascii
		$fnv_CreateFile = {CE C9 CA BD}
		$fnv_GetFileSize = {18 81 ED 44}
		$fnv_ReadFile = {43 C9 FC 54}
		$fnv_CloseHandle = {65 00 BA FA}
		$fnv_WriteFile = {4A C4 07 7F}
		$fnv_CreateEventA = {E2 DD D2 F9}
		$fnv_TerminateProcess = {59 EE 4E F8}
		$fnv_GetCurrentProcess = {45 A8 D8 6D}
		$fnv_CreateProcessA = { 09 0A 7C 4A}

	condition:
		uint16be( 0 ) == 0x4d5a and 4 of ( $rtti* ) and filesize < 8MB and ( for any i in ( 0 .. pe.number_of_sections -1 ) : ( hash.md5 ( pe.sections [ i ] . raw_data_offset , pe.sections [ i ] . raw_data_size ) == "69f400d3ff4679294e63fb8a8ca97dbb" ) or ( all of ( $s* ) and 5 of ( $fnv* ) ) )
}


rule SEKOIA_Apt_Turla_Comlook : FILE
{
	meta:
		description = "Detects Class and Method names used inside ComLook"
		author = "Sekoia.io"
		id = "c3bf886b-f952-47f9-aff6-3cd74c27077d"
		date = "2023-10-30"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_turla_comlook.yar#L1-L31"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "882a2efda4c3888c34a2802797c9eac4ab8b96774f2eea19e586ff9c8adb9292"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ClassName1 = "AgentConfig"
		$ClassName2 = "CommandPerforming"
		$MethodName1 = "CmdCommand"
		$MethodName2 = "GetConfigCommand"
		$MethodName3 = "GetFileCommand"
		$MethodName4 = "PutFileCommand"
		$MethodName5 = "SetConfigCommand"
		$MethodName6 = "AgentProtocol"
		$Log1 = "CONFIG_SERVERS_LIST_PARSING_ERROR" ascii wide
		$Log2 = "GET_UIDS_TO_CHECK_PARSING_ERROR" ascii wide
		$Log3 = "PAYLOAD_PARSING_FILEPATH_AND_FILE_ERROR" ascii wide
		$Log4 = "COMMAND_EMPTY_ERROR" ascii wide
		$Log5 = "IMAP_USERNAME_FORMAT_INCORRECT" ascii wide
		$Log6 = "NO_MESSAGES_TO_RETRIEVE" ascii wide

	condition:
		uint16be( 0 ) == 0x4d5a and filesize < 10MB and any of ( $ClassName* ) and any of ( $MethodName* ) and any of ( $Log* )
}

rule SEKOIA_Apt_Mustangpanda_Decrypt_Payload : FILE
{
	meta:
		description = "Detects the decryption routine of DAT file"
		author = "Sekoia.io"
		id = "7b954007-0929-454d-8a10-05279a337f1b"
		date = "2022-12-08"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_mustangpanda_decrypt_payload.yar#L1-L27"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "dcc32580e351e605d21dc29558764c6fd85f8a9506de8e78f301459a5a2610b7"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$chunk_1 = {
        85 ??
        74 ??
        8B ??
        D1 EA
        A1 ?? ?? ?? ??
        03 C2
        A3 ?? ?? ?? ??
        30 04 29
        41
        3B ??
        72 EC
        }

	condition:
		filesize < 8MB and all of them
}

rule SEKOIA_Apt_Apt28_Htmlsmuggling_Disclosing_Ip : FILE
{
	meta:
		description = "Detects some kind of HTMLSmuggling used by APT28"
		author = "Sekoia.io"
		id = "57adc227-2b72-457e-a786-97ca1a7300d8"
		date = "2023-09-11"
		modified = "2024-12-19"
		reference = "https://www.zscaler.com/blogs/security-research/steal-it-campaign"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_apt28_htmlsmuggling_disclosing_ip.yar#L1-L18"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "047d2d5f8d04576b6d57bc599f82406804845a3acb7628e7ad9b56e71e4dfe92"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = "ipapi.co/json"
		$s2 = "a.download("
		$s3 = "a.click("

	condition:
		$s1 and $s2 and $s3 and filesize < 5000
}

rule SEKOIA_Apt_Uac0154_Powershell_Infection_Chain_2 : FILE
{
	meta:
		description = "UAC-0154 Infection chain"
		author = "Sekoia.io"
		id = "6fe37d52-9bd3-4aa8-83ba-15399bd1b66c"
		date = "2023-10-02"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_uac0154_powershell_infection_chain_2.yar#L1-L19"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "029d88971030a377b3c93ba4c986668e53b01ee03ba94a0a4ceb54b20b72ff2d"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "files.catbox.moe"
		$ = "$pse = $pse.Replace"
		$ = "start -WindowStyle Hidden -FilePath $p"
		$ = "-bxor $xorMask"
		$ = "SysctlHost"

	condition:
		4 of them and filesize < 100KB
}

rule SEKOIA_Apt_Ta428_Tmanger_Strings : FILE
{
	meta:
		description = "Detects Tmanger malware"
		author = "Sekoia.io"
		id = "f600404d-3f93-4e3f-bba7-9f519f67c6cb"
		date = "2022-09-06"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_ta428_tmanger_strings.yar#L1-L26"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "e045f38367fa7f3cdcc908e60de4386889c7878c95b1a40f63fd70683699b0f1"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "sock_hmutex" wide ascii
		$ = "cmd_hmutex" wide ascii
		$ = "%s_%d.bmp" wide ascii
		$ = "WSAStartup Error!" wide ascii
		$ = "4551-8f84-08e738aec" wide ascii
		$ = "Init failed!" wide ascii
		$ = "GetLanIP error!" wide ascii
		$ = "chcp & exit" wide ascii
		$ = "GetHostname error!" wide ascii
		$ = "[Num Lock]" wide ascii

	condition:
		uint16be( 0 ) == 0x4d5a and filesize < 200KB and 4 of them
}

rule SEKOIA_Apt_Kimsuky_Malicious_Vba : FILE
{
	meta:
		description = "Detects malicious VBA used by Kimsuky"
		author = "Sekoia.io"
		id = "2dbe2431-3592-4395-8164-49abae4a5a3d"
		date = "2022-08-30"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_kimsuky_malicious_vba.yar#L1-L18"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "68d7b757f660907fcea3ea03c4027b429f8acdef6569d63cdb744e9d77637080"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "Certutil -decode %TMP%"
		$ = "%LOCALAPPDATA%\\Microsoft\\Office"

	condition:
		uint32be( 0 ) == 0xD0CF11E0 and filesize < 1MB and all of them
}

rule SEKOIA_Apt_Badmagic_Installpzz_Pshscript : FILE
{
	meta:
		description = "Detects BadMagic InstallPZZ powershell script"
		author = "Sekoia.io"
		id = "d01bc217-9e14-498b-a92a-17f6aedec269"
		date = "2023-05-15"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_badmagic_installpzz_pshscript.yar#L1-L18"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "58256cffd1d5060769f304393c22b6488abe9515eb7df2a967ba2fed85a9ec9a"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "start-job -ScriptBlock $script;"
		$ = "Start-Sleep -Second 1;"
		$ = "Write-Output \"$url$j"
		$ = "Start-Sleep -Second 2;"

	condition:
		all of them and filesize < 1KB
}

rule SEKOIA_Apt_Muddywater_Muddyc2Go_Dll_Launcher_Strings : FILE
{
	meta:
		description = "Detects MuddyC2Go DLL launcher"
		author = "Sekoia.io"
		id = "59756195-d842-4038-8fbf-43d26f4353bc"
		date = "2024-03-07"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_muddywater_muddyc2go_dll_launcher_strings.yar#L1-L20"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		hash = "1a0827082d4b517b643c86ee678eaa53f85f1b33ad409a23c50164c3909fdaca"
		logic_hash = "b91653e313258ebd2073a398d0467800056ac94adab02c3a83aa8a379710e4e6"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "-Method GET -ErrorAction Stop;Write-Output $response.Content;iex $response.Content;"
		$ = "GetCurrentProcess"
		$ = "TerminateProcess"

	condition:
		uint16be( 0 ) == 0x4d5a and filesize < 50KB and all of them
}

rule SEKOIA_Apt_Luckymouse_Sysupdate_Removing_Tool : FILE
{
	meta:
		description = "Detects the SysUpdate removing tool"
		author = "Sekoia.io"
		id = "711d059c-6229-49ef-aa20-a04d505838dc"
		date = "2022-08-03"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_luckymouse_sysupdate_removing_tool.yar#L1-L18"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "6a23fac99f26f4b0f9099e435ad53d9e83bf1322d190c565abf0c06dceeeaf34"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "KsWAYYYXXsFUCK" wide
		$ = "remove Services:%s %d" wide
		$ = "remove dir:%s %d" wide
		$ = "remove reg %d" wide

	condition:
		uint16be( 0 ) == 0x4d5a and filesize < 11MB and 2 of them
}

rule SEKOIA_Apt_Susp_Apt28_Uac0063_Malicious_Doc_Vba : FILE
{
	meta:
		description = "Detects some suspected APT28 document vba"
		author = "Sekoia.io"
		id = "58040dbd-09ae-4f9e-940d-3a522e7ccfbb"
		date = "2024-07-25"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_susp_apt28_uac0063_malicious_doc_vba.yar#L1-L17"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		hash = "fceffb8ae94cef3af21b2943131e94db9e0e67073de48d9d32601a245448d067"
		logic_hash = "c57676b765364c5c51d2bf231b5fe858129b45ba837ec6554b353177bb16bd8a"
		score = 65
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = { 2f 31 2e 31 20 32 30 30 20 4f 4b 0d 0a 43 6f 6e 74 65 6e 74 2d 4c 65 6e 67 74 68 3a 20 33 31 30 }
		$ = "ThisDocument" wide

	condition:
		uint32be( 0 ) == 0xd0cf11e0 and all of them
}

rule SEKOIA_Apt_Oilrig_Powerexchange : FILE
{
	meta:
		description = "Detects OilRig's PowerExchange backdoor"
		author = "Sekoia.io"
		id = "cb6b370f-7b05-480b-865e-ac81ded4a2a4"
		date = "2023-10-24"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_oilrig_powerexchange.yar#L1-L19"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "5e505e9bbb17500f7e9a316b66bccb62089172582478230e0bda736bbefa1fd6"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "($h.value).PadRight((($h.value).Length+($h.value).Length%4),'='" ascii wide
		$ = "(($h.value).Length%4 -ne 0)" ascii wide
		$ = "-match \"@@(.*)@@\"" ascii wide
		$ = "[Environment]::NewLine+$_.Exception.Message | Out-File -FilePath" ascii wide
		$ = "ContainsSubjectStrings.Add(\"@@\")" ascii wide

	condition:
		2 of them and filesize < 50KB
}

rule SEKOIA_Apt_Sandworm_Caddywiper_Stacked_Strings : FILE
{
	meta:
		description = "Detects stacked strings used in the wiper."
		author = "Sekoia.io"
		id = "7750c4b6-5781-4b1c-8200-cbce9f18aa56"
		date = "2022-04-06"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_sandworm_caddywiper_stacked_strings.yar#L1-L74"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "e8c94e8611a50080368785d2b341a95d5359d1d814e1d665553324118700ed10"
		score = 75
		quality = 80
		tags = "FILE"
		version = "2.0"
		classification = "TLP:CLEAR"

	strings:
		$ = { C6 45 ?? 6E
        C6 45 ?? 65
        C6 45 ?? 74
        C6 45 ?? 61
        C6 45 ?? 70
        C6 45 ?? 69
        C6 45 ?? 33
        C6 45 ?? 32
        C6 45 ?? 2E
        C6 45 ?? 64
        C6 45 ?? 6C
        C6 45 ?? 6C }
		$ = {  C6 45 ?? 44
        C6 45 ?? 65
        C6 45 ?? 76
        C6 45 ?? 69
        C6 45 ?? 63
        C6 45 ?? 65
        C6 45 ?? 49
        C6 45 ?? 6F
        C6 45 ?? 43
        C6 45 ?? 6F
        C6 45 ?? 6E
        C6 45 ?? 74
        C6 45 ?? 72
        C6 45 ?? 6F
        C6 45 ?? 6C }
		$ = { C6 45 ?? 5C
        C6 45 ?? 00
        C6 45 ?? 5C
        C6 45 ?? 00
        C6 45 ?? 2E
        C6 45 ?? 00
        C6 45 ?? 5C
        C6 45 ?? 00
        C6 45 ?? 50
        C6 45 ?? 00
        C6 45 ?? 48
        C6 45 ?? 00
        C6 45 ?? 59
        C6 45 ?? 00
        C6 45 ?? 53
        C6 45 ?? 00
        C6 45 ?? 49
        C6 45 ?? 00
        C6 45 ?? 43
        C6 45 ?? 00
        C6 45 ?? 41
        C6 45 ?? 00
        C6 45 ?? 4C
        C6 45 ?? 00
        C6 45 ?? 44
        C6 45 ?? 00
        C6 45 ?? 52
        C6 45 ?? 00
        C6 45 ?? 49
        C6 45 ?? 00
        C6 45 ?? 56
        C6 45 ?? 00
        C6 45 ?? 45 }

	condition:
		uint16be( 0 ) == 0x4d5a and 2 of them
}

rule SEKOIA_Apt_Badmagic_Commonmagic_Generic_2 : FILE
{
	meta:
		description = "Detects CommonMagic related implants"
		author = "Sekoia.io"
		id = "c6a16ecc-e00a-4756-b603-f6c85e4f4220"
		date = "2023-05-15"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_badmagic_commonmagic_generic_2.yar#L1-L20"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "d3916ab749ae5b6e0a8abdc9641de13e0328809a6e20c6ce04ada5dbfb742689"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "\\CommonCommand\\" ascii wide
		$ = "\\\\.\\pipe\\PipeMd" ascii wide fullword
		$ = "\\\\.\\pipe\\PipeDtMd" ascii wide fullword
		$ = "\\\\.\\pipe\\PipeCrDtMd" ascii wide fullword

	condition:
		uint16be( 0 ) == 0x4d5a and filesize < 1MB and 2 of them
}

rule SEKOIA_Apt_Apt33_Tickler : FILE
{
	meta:
		description = "Detects APT33 Tickler malware"
		author = "Sekoia.io"
		id = "e9ecf678-350c-47d2-ab4c-522974c70a45"
		date = "2024-08-29"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_apt33_tickler.yar#L4-L19"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		hash = "8bd712b0a49f4fecd39d30ebd121832c"
		hash = "3f29429fce0168748d7cc75e1478aedc"
		logic_hash = "97b858819a1920e6dcdd1a9489754a948de8e6e39b4282e7fe4f6431617a9849"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	condition:
		uint16be( 0 ) == 0x4d5a and ( hash.md5 ( pe.rich_signature.clear_data ) == "2fe65623e6b22577516a4cd051ec3baa" or pe.imphash ( ) == "a5accd1a0d3eaf2c131bc662dd7ff8ea" )
}

rule SEKOIA_Apt_Kimsuky_Fpspy : FILE
{
	meta:
		description = "Detects FPSpy, a backdoor used by Kimsuky"
		author = "Sekoia.io"
		id = "75d41851-a7a6-4068-8ea5-6a3e6e62a965"
		date = "2024-09-27"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_kimsuky_fpspy.yar#L1-L22"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		hash = "6d6c1b175e435f5564341cc1f2c33ddf"
		hash = "54c58b72f98cb63c44e7694add551e9d"
		logic_hash = "65904b77a30b2e2a25f8d80ab32742f0ad931f07c034ae576a4fbde7e1fd999c"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "Chrome/31.0." wide
		$ = "%srundll32.exe %s, %s %%1" wide
		$ = "MazeFunc" wide
		$ = "sys.dll" wide
		$ = "KLog" wide

	condition:
		uint16be( 0 ) == 0x4d5a and 4 of them
}

rule SEKOIA_Apt_3Cx_Payload_Stealer : FILE
{
	meta:
		description = "Detects stealer used in 3CX campaign"
		author = "Sekoia.io"
		id = "1ca0605d-101f-4d1d-a476-9dfd93e74b4c"
		date = "2023-03-31"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_3cx_payload_stealer.yar#L1-L20"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "17630ab86a3da3408e29765c0c30f14c76b870b88fea634b998392fe5d46cfa2"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = "******************************** %s ******************************" wide
		$s2 = "\\3CXDesktopApp\\config.json" wide
		$s3 = "{\"HostName\": \"%s\", \"DomainName\": \"%s\", \"OsVersion\":" wide
		$s4 = "%s.old" wide

	condition:
		( uint32be( 0 ) == 0x7f454c46 or uint16be( 0 ) == 0x4d5a ) and filesize < 8MB and all of them
}

rule SEKOIA_Apt_Badmagic_Commonmagic_Screenshot_Module : FILE
{
	meta:
		description = "Detects CommonMagic related implants"
		author = "Sekoia.io"
		id = "d1ef0bd1-37dc-405f-b82b-288b1798455c"
		date = "2023-05-15"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_badmagic_commonmagic_screenshot_module.yar#L1-L19"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "caab57534a00620974f7d49c7b38a3f191aca596b69b3e4c499e3099023c2f9c"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "%s_%02d.%02d.%04d_%02d.%02d.%02d.%03d.%s" wide
		$ = "Screenshot" wide
		$ = "\\\\.\\pipe\\PipeDtMd" wide

	condition:
		uint16be( 0 ) == 0x4d5a and filesize < 1MB and all of them
}

rule SEKOIA_Apt_Apt41_Keyplug_Dropper : FILE
{
	meta:
		description = "Detects a dropper used by keyplug"
		author = "Sekoia.io"
		id = "b6740371-c4c3-437e-8235-0bd4f7b9c3f5"
		date = "2024-06-12"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_apt41_keyplug_dropper.yar#L1-L20"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "a61f57302d8fe58ed8b77542c94159acbc36a3bd52c204171e76e668d10a74e7"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "C:\\ProgramData\\pfm.ico" wide
		$ = "C:\\\\ProgramData\\\\pfm.ico" wide
		$ = "67f8de349abc5ghi" wide
		$ = "3abc64597f8diegh" wide

	condition:
		uint16be( 0 ) == 0x4d5a and filesize < 2MB and any of them
}

rule SEKOIA_Apt_Shadowpad_First_Called_Function : FILE
{
	meta:
		description = "Detects entrypoint of shadowpad"
		author = "Sekoia.io"
		id = "3ce1ffd3-5c30-4b36-b7cc-c9fa873ebc25"
		date = "2023-01-30"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_shadowpad_first_called_function.yar#L1-L36"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "a40db3fad01f4177973fd50bd489e5c4ff6d3592dfff063c2c31694007c31e0b"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$chunk_1 = {
        48 83 EC 28
        33 C9
        FF 15 ?? ?? ?? ??
        8B 80 ?? ?? ?? ??
        3B 05 ?? ?? ?? ??
        74 ??
        E8 ?? ?? ?? ??
        E8 ?? ?? ?? ??
        EB ??
        48 8B 0D ?? ?? ?? ??
        E8 ?? ?? ?? ??
        8B C8
        FF 15 ?? ?? ?? ??
        90
        B9 28 04 00 00
        FF 15 ?? ?? ?? ??
        90
        48 83 C4 28
        C3
        }

	condition:
		uint16be( 0 ) == 0x4d5a and all of them
}

rule SEKOIA_Apt_Aptk47_Maliciouslnk : FILE
{
	meta:
		description = "Detects APT-K-47 malicious LNK"
		author = "Sekoia.io"
		id = "2ccc8777-26fe-4018-9646-4ea91394fe78"
		date = "2024-11-22"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_aptk47_maliciouslnk.yar#L1-L18"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		hash = "6a405d4e88b4acb9706e19a83aad9cf6"
		logic_hash = "865bb08f57affb3795853aa3c9f49577efb74df9b32e7760263b9fb08246a3ab"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "[/c for /f" wide
		$ = "2^>nul') do copy" wide
		$ = "%F in ('where /r %Temp%" wide

	condition:
		uint32be( 0 ) == 0x4c000000 and all of them
}

rule SEKOIA_Apt_Menupass_Maliciouslibvlc_Dll
{
	meta:
		description = "Detects the malicious LibVLC variants used by MenuPass"
		author = "Sekoia.io"
		id = "8b6b56f3-33b5-41cf-8bcb-e653c98718bd"
		date = "2022-04-06"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_menupass_maliciouslibvlc_dll.yar#L3-L17"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "de56e112a477d3a77146f1b84c8aa3e66a382a87f1492dd50aa1de9458b33717"
		score = 75
		quality = 80
		tags = ""
		version = "1.0"
		classification = "TLP:CLEAR"

	condition:
		pe.DLL and pe.number_of_exports < 15 and for all i in ( 0 .. pe.number_of_exports - 1 ) : ( pe.export_details [ i ] . name contains "libvlc_" )
}

rule SEKOIA_Apt_Emissarypanda_Web_Auto_Attack_Tool : FILE
{
	meta:
		description = "Detect LuckyMouse's Web auto attack tool"
		author = "Sekoia.io"
		id = "c93eb792-a443-4c9a-8fcb-6015cc69f9b3"
		date = "2022-08-03"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_emissarypanda_web_auto_attack_tool.yar#L1-L21"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "bc55758367ba0a6b5cf963bcb51b7770b2c7b1cf43b0b79e663b4110f6a7bba8"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "[192.168.1.1/24|192.168.1.1|192.168.1|@host.txt]" ascii
		$ = "80,s443,8080,s8443,8000-8010" ascii
		$ = "exploit When find module vul" ascii
		$ = "<title>\\s*(.*?)\\s*</title>" ascii
		$ = "<meta.+?charset=[^\\w]?([-\\w]+)" ascii
		$ = "%s is not existed" ascii
		$ = "%-15s %4d Open" wide

	condition:
		uint16be( 0 ) == 0x4d5a and 4 of them and filesize < 500KB
}

rule SEKOIA_Apt_Granitetyphoon_Sword2023_Strings : FILE
{
	meta:
		description = "Detects Sword2023 malware based on strings"
		author = "Sekoia.io"
		id = "417b355f-9eb8-40ae-bc3b-f7f23b5ca63e"
		date = "2023-05-25"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_granitetyphoon_sword2023_strings.yar#L1-L21"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "8644547f093295eeac30c9040796329a3e2222c06a942d14899545726c8bed78"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "TERM=linux"
		$ = ";echo"
		$ = "sh:time out"
		$ = "sh:read stdout error"
		$ = "/proc/sys/kernel/random/uuid"

	condition:
		( uint32be( 0 ) == 0x7f454c46 ) and filesize < 100KB and all of them
}

rule SEKOIA_Apt_Evasive_Panda_Rphost_Dll : FILE
{
	meta:
		description = "Detects DLL used by Evasive Panda"
		author = "Sekoia.io"
		id = "8d70639d-b736-4823-86ad-37f0e383b5f7"
		date = "2024-03-15"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_evasive_panda_rphost_dll.yar#L1-L20"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		hash = "fa44028115912c95b5efb43218f3c7237d5c349f"
		logic_hash = "2132f1c69db8fd5793c858ada2443fdfa1f941e68d24cc337766df99f8b3a895"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = "htks.ini" ascii fullword
		$s2 = "MyDemo" wide fullword

	condition:
		uint16be( 0 ) == 0x4d5a and all of them and filesize < 1MB
}

rule SEKOIA_Apt_Cloudatlas_Powershower_Clean : FILE
{
	meta:
		description = "Detects clean version of PowerShower"
		author = "Sekoia.io"
		id = "4a7c37df-3f53-4190-a86f-94bba3df628e"
		date = "2022-12-05"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_cloudatlas_powershower_clean.yar#L1-L19"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "24ea6ec0cd8dbcebdf7e42dbd48319562d8682fefd5d0d464a3a5c4b90be40f3"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "[io.file]::WriteAllBytes($zipfile" ascii wide
		$ = "System.IO.File]::Exists($p_t" ascii wide
		$ = "HttpRequestP" ascii wide
		$ = "$http_request.getOption(2)" ascii wide
		$ = "HttpRequestP($url)" ascii wide

	condition:
		uint8( 0 ) == 0x24 and filesize < 4000 and 4 of them
}

rule SEKOIA_Apt_Gamaredon_Lnk_Spreader : FILE
{
	meta:
		description = "Detects LNK generated by Gamaredon LNK spreader"
		author = "Sekoia.io"
		id = "2866ca1d-c094-49ba-b1de-ff9a60680e28"
		date = "2023-06-19"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_gamaredon_lnk_spreader.yar#L1-L19"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		hash = "7d6264ce74e298c6d58803f9ebdb4a40b4ce909d02fd62f54a1f8d682d73519a"
		logic_hash = "e8a82fd4cdce7bc888184ccf8d182ab5bb53e30de04b02b7c63379bae5d21b1f"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "windoWSTYLE hiDdEn -NOlOgo iEX" wide nocase
		$ = "(IeX (geT-coNtEnT" wide nocase

	condition:
		uint32be( 0 ) == 0x4C000000 and filesize < 3KB and all of them
}


rule SEKOIA_Apt_Sugardump_Credentials_Stealer_Smtp : FILE
{
	meta:
		description = "Detects SUGARDUMP SMTP version"
		author = "Sekoia.io"
		id = "bf028ebc-bfaa-45b3-9a3f-8949a5efbb73"
		date = "2022-08-23"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_sugardump_credentials_stealer_smtp.yar#L1-L20"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "1f423f38ff323e67667e35af5603e608cba6eaf8d98633467b0292c5f81c8d1c"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "<<<<<<<< ------ Passwords Total: {0} --------- >>>>>>>>" wide
		$ = "Url = {0} , Count = {1}" wide
		$ = "smtp." wide
		$ = "encrypted_key\":\"(.*?)\"" wide

	condition:
		uint16be( 0 ) == 0x4d5a and filesize < 1MB and all of them
}

rule SEKOIA_Apt_Apt29_Quarterrig
{
	meta:
		description = "Detects QUARTERRIG"
		author = "Sekoia.io"
		id = "e370ed7e-5e12-4add-95f3-3773ea8e2d03"
		date = "2023-04-19"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_apt29_quarterrig.yar#L1-L18"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "9628418789a9bc24c7e44dbc9106ffa6316aefebe33b91c749b54cb5462b1309"
		score = 75
		quality = 80
		tags = ""
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$str_dll_name = "hijacker.dll"
		$str_import_name = "VCRUNTIME140.dll"
		$op_resolve_and_call_openthread = { 48 [6] 48 [6] 8B D8 E8 [4] [3] 33 D2 B9 FF FF 1F 00 FF D0 }
		$op_resolve_and_call_suspendthread = { E8 [4] 48 8B CB FF D0 83 F8 FF }

	condition:
		all of them
}

rule SEKOIA_Apt_Mustangpanda_Coolclient : FILE
{
	meta:
		description = "Detect COOLCLIENT via obfuscation & specific string"
		author = "Sekoia.io"
		id = "2f8fdb66-03a2-400f-808b-56ae1b276d2f"
		date = "2023-03-27"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_mustangpanda_coolclient.yar#L1-L19"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "9fd552604299ecb8fa28042ee26e72bbe4fb9804ad087bf4a373b2c2e17d43b0"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = {eb 14 ea 50 eb 0b ea 8b c4 a8 01 74 06 eb 0b}
		$s2 = {66 0f d6 44 24 eb eb}
		$s3 = "c:\\windows\\syste" fullword

	condition:
		( uint32be( 0 ) == 0x7f454c46 or uint16be( 0 ) == 0x4d5a ) and filesize < 1MB and all of them
}

rule SEKOIA_Apt_Susp_Apt28_Uac0063_Malicious_Doc : FILE
{
	meta:
		description = "Detects some suspected APT28 document"
		author = "Sekoia.io"
		id = "2b9d597a-a6cd-49df-8938-7103342a1d06"
		date = "2024-07-25"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_susp_apt28_uac0063_malicious_doc.yar#L1-L18"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		hash = "93322be0785556e627d2b09832c18e39c115e6a6fbff64b1e590e1ddcf8f6a43"
		logic_hash = "27aeadbb76dd4e670a85e8fcd1e885b69845537dd937aacc1808902e75008848"
		score = 65
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "Sub pop() : : End Sub" ascii fullword
		$ = "%localappdata%\\Temp" ascii fullword
		$ = "rthedbv" ascii fullword

	condition:
		2 of them and filesize < 1MB
}

rule SEKOIA_Apt_Gamaredon_Htmlsmuggling_2024 : FILE
{
	meta:
		description = "Detects HTML Smuggling webpages of Gamaredon used in 2024"
		author = "Sekoia.io"
		id = "8fa1f80b-2261-4d63-92d8-7c360be73fe2"
		date = "2024-09-09"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_gamaredon_htmlsmuggling_2024.yar#L1-L23"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		hash = "ab2807824e68d5efb4c896e1af82e693"
		hash = "926b7e65d0d61cd6ba9e085193ae8b1d"
		logic_hash = "9cd82f497fd7b82f02fec4ce1d131cd2685861c7c02aaae992e07a7d8bd30595"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "').innerHTML;window['" ascii fullword
		$ = "='at'+'ob';"
		$ = "]('*','');"
		$ = "display:none"
		$ = "0px;\" onerror=\""
		$ = "'ev'+'"
		$ = "<!DOCTYPE html PUBLIC"

	condition:
		5 of them and filesize < 1MB
}

rule SEKOIA_Apt_Lazarus_Blindingcan_Rtti
{
	meta:
		description = "Detects BLINDINGCAN with RTTI"
		author = "Sekoia.io"
		id = "9a16c189-ffc1-4aa6-8582-298abaecd0ef"
		date = "2022-10-04"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_lazarus_blindingcan_rtti.yar#L1-L16"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "fbec1f9a180782bf330d86facbada9af018741897c58f4ab6e0b52a1b38ae966"
		score = 75
		quality = 80
		tags = ""
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = ".?AVCHTTP_Protocol@@" ascii wide fullword
		$s2 = ".?AVCFileRW@@" ascii wide fullword

	condition:
		all of them
}

rule SEKOIA_Apt_Apt37_Malicious_Hta_File : FILE
{
	meta:
		description = "Detects malicious APT37 files"
		author = "Sekoia.io"
		id = "22a98c27-8ff4-4760-b505-f8eacf4dabda"
		date = "2023-03-06"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_apt37_malicious_hta_file.yar#L1-L20"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "85289bea86641ea9c359c361d075783449d453017485170abc87c47872792210"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = "<HTML>" nocase
		$s2 = " UwB0AGEAcgB0AC0AUwBs" ascii
		$s3 = "= new ActiveXObject(" ascii
		$s4 = "\", \"\", \"open\", 0);" ascii
		$s5 = ".moveTo(" ascii
		$s6 = "self.close();"

	condition:
		$s1 at 0 and all of them and filesize < 1MB
}

rule SEKOIA_Apt_Unknown_Sessionmanageriis_Strings : FILE
{
	meta:
		description = "Detects the IIS SessionManager backdoor"
		author = "Sekoia.io"
		id = "7d55dd82-509f-444d-a1ba-6417b51f392f"
		date = "2022-07-04"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_unknown_sessionmanageriis_strings.yar#L1-L23"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "b1058b07c8e40431f8f3841b5ad49b4d6ead21a91d014f24c083f37eeacc5ac5"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "Wokring OK"
		$ = "Delete File Success :"
		$ = "Delete File Error :"
		$ = "SM_SESSION="
		$ = "SM_SESSIONID"
		$ = "attachment; filename ="
		$ = "CHttpModule::"

	condition:
		uint16be( 0 ) == 0x4d5a and filesize > 100KB and filesize < 400KB and 4 of them
}

rule SEKOIA_Apt_Windows_Wip19_Screencap : FILE
{
	meta:
		description = "Detects ScreenCap resource"
		author = "Sekoia.io"
		id = "ebf5d2c5-81c9-45c3-aa61-05870f800f6b"
		date = "2022-10-18"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_windows_wip19_screencap.yar#L4-L18"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "02479f0c8199b31f089608da0f44f1487b75790cb31c77bb65ca1fb0fd57ac0d"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	condition:
		( uint32be( 0 ) == 0x7f454c46 or uint16be( 0 ) == 0x4d5a ) and for any i in ( 0 .. pe.number_of_resources -1 ) : ( hash.sha256 ( pe.resources [ i ] . offset , pe.resources [ i ] . length ) == "89f4d0e3f7f3318270aa9c8345c1402202b1a02ffefc03c7a86636e297aa0ffc" ) and filesize < 2MB
}

rule SEKOIA_Apt_Evasive_Panda_Downloader_Certificate_Exe : FILE
{
	meta:
		description = "Detects downloader used by Evasive Panda (certificate.exe)"
		author = "Sekoia.io"
		id = "1b40fca9-04b1-46b3-b48c-5a148a1b36b9"
		date = "2024-03-15"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_evasive_panda_downloader_certificate_exe.yar#L1-L15"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "38115b463378f58035a0ef0536a6af4adbec7c275164758d312e95300670b695"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = {C6 45 D4 44 C6 45 D5 74 C6 45 D6 7C C6 45 D7 74 C6 45 D8 79}

	condition:
		uint16be( 0 ) == 0x4d5a and all of them
}

rule SEKOIA_Apt_Kimsuky_Sharptongue_C2_Source
{
	meta:
		description = "Detects the PHP code of the SharpTongue C2"
		author = "Sekoia.io"
		id = "a2ccf773-511c-4088-8bcf-b923291d024b"
		date = "2022-07-29"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_kimsuky_sharptongue_c2_source.yar#L1-L18"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "c301a99876cfe2863546c990654aa922f9327e0eb010968eaea43f1d8ced76da"
		score = 75
		quality = 80
		tags = ""
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "<?php"
		$ = "foreach($_GET as $variable => $value)"
		$ = "$chk=$value"
		$ = "base64_encode($ip)"

	condition:
		all of them
}

rule SEKOIA_Apt_Kimsuky_Powershell : FILE
{
	meta:
		description = "Powershell scripts used by Kimsuky. If size < 3KB ok. If between 3 and 15, a check is needed"
		author = "Sekoia.io"
		id = "b7f812e0-d08b-40fe-908a-dc5765d6bc66"
		date = "2024-09-23"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_kimsuky_powershell.yar#L1-L21"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		hash = "6babb53d881448dc58dd7c32fcd4208a"
		hash = "29ec7a4495ea512d44d33c9847893200"
		hash = "fde68771cebd7ecd81721b0dff5b7869"
		hash = "0c3fd7f45688d5ddb9f0107877ce2fbd"
		hash = "1a1723be720c1d9cd57cf4a6a112df79"
		logic_hash = "7436d8cba8a8caaf95786c38c4ceee4426dc7e36ae3eeed5d3162310cd76091d"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = ".ToCharArray();[array]::Reverse(" ascii
		$ = ");$res = -join ($bytes -as [char[]]);Invoke-Expression $res;" ascii

	condition:
		all of them and filesize < 15KB
}

rule SEKOIA_Apt_Apt10_Hui_Loader : FILE
{
	meta:
		description = "Specific string for HUI Loader"
		author = "Sekoia.io"
		id = "97d17052-80d0-4f8e-8b3a-2e0d622522a9"
		date = "2022-07-04"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_apt10_hui_loader.yar#L1-L17"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "33df202599c6bceff2cf76acdc0096f7167acb69c541b3cfe4cdc34edc174005"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = "HUIHWASDIHWEIUDHDSFSFEFWEFEWFDSGEFERWGWEEFWFWEWD" wide fullword

	condition:
		( uint16be( 0 ) == 0x4d5a ) and filesize > 30KB and filesize < 100KB and 1 of them
}


rule SEKOIA_Apt_Nobelium_Nativezone_Gen : FILE
{
	meta:
		description = "Detects NativeZone used in 2022"
		author = "Sekoia.io"
		id = "e16cac97-38dd-4145-95f5-cf641940a19b"
		date = "2022-02-25"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_nobelium_nativezone_gen.yar#L3-L31"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "63ad9fc510541f98237fa5b254dc4a147539cbf485b2889d97bf3b619c3db3ae"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$rich = { 52 69 63 68 [4] 00 }
		$obs = { C7 85 [8] C7 85 }
		$nobs = { C7 85 [6] 00 00 C7 85 }

	condition:
		pe.DLL and filesize < 2500KB and pe.number_of_exports > 20 and pe.number_of_imports < 30 and ( pe.imports ( "kernel32.dll" , "VirtualAlloc" ) and pe.imports ( "kernel32.dll" , "VirtualProtect" ) ) and for any i in ( 0 .. pe.number_of_sections - 1 ) : ( pe.sections [ i ] . name == ".rdata" and pe.sections [ i ] . raw_data_size > 300000 ) and #obs > 300 and #nobs < 150 and not $rich
}

rule SEKOIA_Apt_Mustangpanda_Zpakage : FILE
{
	meta:
		description = "Detect obfuscation seen in ZPAKAGE"
		author = "Sekoia.io"
		id = "a4767d12-5058-4a26-be62-0cec685917bd"
		date = "2023-03-27"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_mustangpanda_zpakage.yar#L1-L31"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		hash = "711c0e83f4e626a7b54e3948b281a71915a056c5341c8f509ecba535bc199bee"
		logic_hash = "52ad51589ca154fbf6e5829a2c80a9b811809288bed6995820a0ca8aa218d8ef"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$chunk_1 = {
        88 94 1D ?? ?? ?? ??
        8A 84 1D ?? ?? ?? ??
        83 ?? ??
        88 84 1D ?? ?? ?? ??
        8A 84 1D ?? ?? ?? ??
        83 ?? ??
        88 84 1D ?? ?? ?? ??
        8A 84 1D ?? ?? ?? ??
        83 ?? ??
        88 84 1D ?? ?? ?? ??
        0F BE 8C 1D ?? ?? ?? ??
        0F BE 84 1D ?? ?? ?? ??
        }

	condition:
		( uint32be( 0 ) == 0x7f454c46 or uint16be( 0 ) == 0x4d5a ) and filesize < 1MB and filesize < 11MB and #chunk_1 > 20
}


rule SEKOIA_Apt_Gamaredon_Ddrdoh_Vbs_Downloader_Vbs : FILE
{
	meta:
		description = "Detects malicious VBScript executed by LNK/mshta"
		author = "Sekoia.io"
		id = "cc29d5d9-58bd-4f68-8673-daa41abfc7be"
		date = "2023-01-24"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_gamaredon_ddrdoh_vbs_downloader_vbs.yar#L1-L20"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "c91e1ce26c0735e8c68fe39f2fbeda8aed51cd4f9a0b967b5d184843728dcef4"
		score = 75
		quality = 78
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "b24gZXJyb3IgcmVzd" ascii
		$ = "BinaryStream.readtext" ascii nocase
		$ = "createobject(\"msxml2.domdocument.3.0\").createelement(" ascii nocase
		$ = "Dim cSecond, cMinute, CHour, cDay, cMonth, cYear" ascii nocase
		$ = "tDate & \"T\" & tTime"
		$ = "AutoOpen" ascii nocase

	condition:
		5 of them and filesize < 50KB
}

rule SEKOIA_Apt_Micdown_Encrypted_Configuration : FILE
{
	meta:
		description = "Encrypted C2 configuration of micDown"
		author = "Sekoia.io"
		id = "9567d68b-05d1-4d41-b87f-c8691ee689cd"
		date = "2023-08-24"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_micdown_encrypted_configuration.yar#L1-L15"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "9b80bd284f9aa9e4073bdead7bb0c5412ec1809c36a85dfd35d9ea7ac62da8a3"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = {?? [20] 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 37 84 36}

	condition:
		filesize == 66 and all of them
}

rule SEKOIA_Apt_Unc4990_Emptyspace_Pyc : FILE
{
	meta:
		description = "Detects Python Bytecode of EmptySpace"
		author = "Sekoia.io"
		id = "d970fd9c-1ce5-471c-96a1-146250f36b89"
		date = "2024-02-01"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_unc4990_emptyspace_pyc.yar#L1-L43"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "98e9c848f6b6276815b040681d7f36548b367257bb75d133309e89e8572a50b7"
		score = 75
		quality = 78
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "PYBOOTSTRAP"
		$ = "http://google.com/generate_204"
		$ = "from"
		$ = "pathZ"
		$ = "usernamez"
		$ = "timeZ"
		$ = "win32api"
		$ = "base64Z"
		$ = "json"
		$ = "marshalZ"
		$ = "BOOTSTRAP_VERSION"
		$ = "getZ"
		$ = "sleepZ    b64encode"
		$ = "dumps"
		$ = "executableZ"
		$ = "GetUserNameExZ"
		$ = "NameSamCompatible"
		$ = "encode"
		$ = "decodeZ"
		$ = "request_dataZ"
		$ = "server"
		$ = "post"
		$ = "raise_for_status"
		$ = "exec"
		$ = "loadsZ    b64decode"
		$ = "text"
		$ = "globals"
		$ = "bootstrap.py"
		$ = "<module>"

	condition:
		uint32be( 0 ) == 0x420d0d0a and all of them
}

rule SEKOIA_Apt_Gamaredon_Stealer_Obfuscation_2 : FILE
{
	meta:
		description = "Matches the Gamaredon Stealer obfuscation"
		author = "Sekoia.io"
		id = "fd278a90-537b-4c67-9421-01c9f2416b60"
		date = "2022-02-04"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_gamaredon_stealer_obfuscation_2.yar#L1-L17"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "6ffd8504ba8ca614d3941bd46b944d85e0ad4b9d8d2960d508f50550497d2852"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = { 3d 20 6e 65 77 20 73 74 72 69 6e 67 5b 5d 20 7b 20 [50-200] 20 7d 3b }

	condition:
		uint16be( 0 ) == 0x4d5a and filesize > 100MB and #s1 > 40
}

rule SEKOIA_Apt_Konni_Check_Bat : FILE
{
	meta:
		description = "Script used to performs check before executing Konni"
		author = "Sekoia.io"
		id = "f05e6ba2-c128-4c17-8f74-f7640103c859"
		date = "2023-11-27"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_konni_check_bat.yar#L1-L23"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "13a9dd6978985eb17960794c6de2ee2e6411e6afeb705ff95ced72bc0efb5d8c"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = ":64BIT"
		$ = ":32BIT"
		$ = ":INSTALL"
		$ = ":EXIT"
		$ = "netpp.dll"
		$ = "wpns.dll"
		$ = "netpp64.dll"
		$ = "wpns64.dll"
		$ = "rundll32"

	condition:
		filesize < 1MB and 7 of them
}

rule SEKOIA_Apt_Unc3524_Quietexit_Strings : FILE
{
	meta:
		description = "Detect the QUIETEXIT malware used by UNC3524"
		author = "Sekoia.io"
		id = "1bfa9baa-40a3-4ad7-83dc-f9340fbed180"
		date = "2022-05-04"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_unc3524_quietexit_strings.yar#L1-L23"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "9f8bc7516fdefd94c6bddaf77ea3ac1ba8a3a6380530118c4b28d74b42eaae54"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "Child connection from %s:%s" ascii
		$ = "Failed to run %s" ascii
		$ = "add %s %s %s" ascii
		$ = "/usr/bin/xauth -q" ascii
		$ = "/tmp/dropbear-%" ascii
		$ = "cron" ascii
		$ = { DD E5 D5 97 20 53 27 BF F0 A2 BA CD 96 35 9A AD 1C 75 EB 47 }

	condition:
		uint32be( 0 ) == 0x7f454c46 and filesize > 1MB and 5 of them
}

rule SEKOIA_Apt_Mustangpanda_Malicious_Lnk_Worm : FILE
{
	meta:
		description = "Detects MustangPanda infected ThumbDrive"
		author = "Sekoia.io"
		id = "e7cc5ecc-2369-49ff-9e35-c9faeb69acda"
		date = "2023-09-21"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_mustangpanda_malicious_lnk_worm.yar#L1-L16"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "ca19a925af695cbbb41fdfbb161dceafeb8aae6d42000cc09bb07e1dbdfdb9e5"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = "RECYCLER.BIN\\1\\CEFHelper.exe" wide

	condition:
		uint32be( 0 ) == 0x4C000000 and 1 of them
}

rule SEKOIA_Apt_Kimsuky_Sharpext_Devtoolmodule_Strings : FILE
{
	meta:
		description = "Detects the DevTool module used by SharpExt"
		author = "Sekoia.io"
		id = "6f589a9c-344a-4ddc-929e-f123a2c3c187"
		date = "2022-07-29"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_kimsuky_sharpext_devtoolmodule_strings.yar#L1-L17"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "61007801d28636c6d88b14225f34910d03e82337520257637a5017d58600b2bc"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "packetProc = function" ascii fullword
		$ = "var url = request.request.url" ascii fullword
		$ = "https://mail" ascii fullword

	condition:
		all of them and filesize < 50KB
}

rule SEKOIA_Apt_Gobrat_2 : FILE
{
	meta:
		description = "Detects GobRat related files"
		author = "Sekoia.io"
		id = "6b7e38f5-00bc-49c8-b34d-3e878bf426d8"
		date = "2024-09-10"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_gobrat_2.yar#L1-L16"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "9f2fdbe2cc39c91b2ac8904fb29a0142bf770859d17590017920203641860a13"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "thisisweird" ascii
		$ = "ZzZzZzZzZzZz"

	condition:
		all of them and uint32be( 0 ) == 0x7f454c46
}

rule SEKOIA_Apt_Sofacy_Graphitemalware_Generic : FILE
{
	meta:
		description = "Detects APT28 graphite malware based on strings"
		author = "Sekoia.io"
		id = "6b51cfa3-4a7d-4c2a-9fd9-f129b8a18466"
		date = "2022-09-27"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_sofacy_graphitemalware_generic.yar#L3-L25"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "f4c994c36768bae6d6e3b5aeefb634e485ab7b483a693781f29d5ff44c71996f"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "Microsoft Enhanced RSA and AES Cryptographic Provider" wide
		$ = "Microsoft Enhanced RSA and AES Cryptographic Provider (Prototype)" wide
		$ = "%s %04d sp%1d.%1d %s"
		$ = "%s%c%s%c%s"
		$ = "InternetReadFile"
		$ = "ObtainUserAgentString"
		$ = "CryptImportKey"

	condition:
		uint16be( 0 ) == 0x4d5a and filesize < 100KB and ( all of them or pe.imphash ( ) == "c56c322548250651361aef7dacf93eaf" )
}

rule SEKOIA_Apt_Apt28_Ukrnet_Phishing_Page : FILE
{
	meta:
		description = "Detects APT28 Phishing page"
		author = "Sekoia.io"
		id = "053158d8-aac0-486f-8432-834a06f41ed2"
		date = "2024-09-02"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_apt28_ukrnet_phishing_page.yar#L1-L24"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		hash = "20dc3a5beb8e3a7801e010b4113efef1"
		hash = "5f1462144d7704101cd71c679ea0322b"
		logic_hash = "3d077a7ce35094bcbda763c131d4564ffbcea0373f5cbd30406ada4e9db36529"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "baseurl+\"/captcha\""
		$ = "(\"sessionID\", sessionID"
		$ = ".responseJSON['origin"
		$ = "var baseurl="
		$ = "(req.responseText.includes("
		$ = "else if (req.responseText=='FAIL')"
		$ = "|| document.getElementById('confpwd"
		$ = "/master/dist/text-security-disc.woff"

	condition:
		4 of them and filesize < 500KB
}

rule SEKOIA_Apt_Badmagic_Reco_Pshscript : FILE
{
	meta:
		description = "Detects BadMagic Reco powershell script"
		author = "Sekoia.io"
		id = "7a1b2d31-03b7-4a43-8f4e-ed38ba8e118e"
		date = "2023-05-15"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_badmagic_reco_pshscript.yar#L1-L18"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "86369267545241f33c6fc7dab11eb06f71641d8e9cd0365ddcc676d4f4c9739b"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "$headers = @{};"
		$ = "==ARP Cache=="
		$ = "ipconfig.me"
		$ = "-ComputerName $env:computername;"

	condition:
		all of them and filesize < 1KB
}

rule SEKOIA_Apt_Apt29_Malicious_Rdp_File : FILE
{
	meta:
		description = "Detects malicious RDP files"
		author = "Sekoia.io"
		id = "a7b092b5-53a1-4638-a6c1-733d3f063139"
		date = "2024-10-25"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_apt29_malicious_rdp_file.yar#L1-L26"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		hash = "db326d934e386059cc56c4e61695128e"
		hash = "b38e7e8bba44bc5619b2689024ad9fca"
		hash = "f58cf55b944f5942f1d120d95140b800"
		hash = "40f957b756096fa6b80f95334ba92034"
		logic_hash = "da9d8dfbbf82f48c8b880cbde21f75ecd1e9f779e462da5ced32b6587c71eaf2"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "RedirectPrinters" wide
		$ = "RedirectCOMPorts" wide
		$ = "RedirectSmartCards" wide
		$ = "RedirectPOSDevices" wide
		$ = "RedirectClipboard" wide
		$ = "DrivesToRedirect" wide
		$ = "full address:s:" wide

	condition:
		uint16be( 0 ) == 0xFFFE and all of them and filesize < 20KB
}

rule SEKOIA_Apt_Kimsuky_Vbs_Powershell_Downloader : FILE
{
	meta:
		description = "Detects VBS/Powershell Downloader used by Kimsuky"
		author = "Sekoia.io"
		id = "4c9af11f-802b-4ffe-9783-90fc2ee53809"
		date = "2022-08-30"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_kimsuky_vbs_powershell_downloader.yar#L1-L18"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "dc24ca206a3122b34be978287f907b12c809f76058fe9355bbd00b3159b0a4d4"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "& WScript.ScriptFullName &" ascii fullword
		$ = "/c schtasks /create /sc minute /mo 5 /tn"
		$ = "pOwErsHeLl -ep bypass -encodedCommand"

	condition:
		filesize < 200KB and 2 of them
}

rule SEKOIA_Apt_Toddycat_Toddybox_Strings : FILE
{
	meta:
		description = "Detects ToddyCat's ToddyBox binary"
		author = "Sekoia.io"
		id = "fde3df24-ebd7-4327-998e-bddaa08835da"
		date = "2023-11-20"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_toddycat_toddybox_strings.yar#L1-L24"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "b71fad12d4485268cbeff98b8a8d6067ac8f62164be60cdb61f3f37ab471a247"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "Wait a while to upload the next file..."
		$ = "[-] Error Msg: %s"
		$ = "[-] Error Msg: Connect Errors or Proxy Errors"
		$ = "[-] arg missing!"
		$ = "[-] Get module dir failed!"
		$ = "[-] Dir error!"
		$ = "Auto Get Proxy %S"
		$ = "Dropbox-API-Arg"

	condition:
		uint16be( 0 ) == 0x4d5a and filesize < 1MB and all of them
}

rule SEKOIA_Apt_Badmagic_Malicious_Lnk : FILE
{
	meta:
		description = "Detect LNK used by BadMagic to execute MSI payloads."
		author = "Sekoia.io"
		id = "731bd51d-c4e4-4efb-9fa8-f981a8555ed3"
		date = "2023-05-15"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_badmagic_malicious_lnk.yar#L1-L19"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "b83749c71cefb485f8bbea1d465fc477de159e086efa04ebce4d0778a203ed89"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "/i http" wide
		$ = ".msi /quiet" wide
		$ = "%WINDIR%\\System32\\msiexec.exe"

	condition:
		uint32be( 0 ) == 0x4c000000 and filesize < 1KB and all of them
}

rule SEKOIA_Apt_Gamaredon_Lnk : FILE
{
	meta:
		description = "Detects lnk file used by Gamaredon"
		author = "Sekoia.io"
		id = "bfa69d84-433c-4f37-93b7-5b1b11677fbb"
		date = "2024-02-08"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_gamaredon_lnk.yar#L1-L16"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "be73ffca4b88f11e33532cf9a179743508bfa7a60c6f4de98c245b350b5fb910"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = "-windowstyle hidden $(gc " wide
		$s2 = "|out-string)|powershell -noprofile -" wide

	condition:
		uint32be( 0 ) == 0x4c000000 and any of them and filesize < 100KB
}


rule SEKOIA_Apt_Badmagic_Startngrok_Pshscript : FILE
{
	meta:
		description = "Detects BadMagic StartNgrok powershell script"
		author = "Sekoia.io"
		id = "94d64482-3033-4531-8530-58546364ac06"
		date = "2023-05-15"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_badmagic_startngrok_pshscript.yar#L1-L19"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "f15f9dc2c35f3f7cd816aa539c03b857254c3628c9b14eacca1110bb85b1a24c"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "$ExecutablePath http \"\"file:///$Disk"
		$ = "write \"$ExecutablePath not found"
		$ = "$ng_proxy_string ="
		$ = "$ng_auth_token ="
		$ = "$env:ALLUSERSPROFILE\\$NGrokFolderName"

	condition:
		all of them and filesize < 1KB
}

rule SEKOIA_Apt_Implant_Xdealer_Linux_Variant_Strings : FILE
{
	meta:
		description = "Detects XDealer linux variant"
		author = "Sekoia.io"
		id = "42690513-753f-4296-b641-4d3b59a5e5e1"
		date = "2024-03-22"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_implant_xdealer_linux_variant_strings.yar#L1-L21"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "400beb53d0f7b7727962175c7c4f8dfccdfed56bb3978d3e847147e8ad7644fb"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "ls -l /proc/%s/exe"
		$ = "Linux_%s_%s_%u"
		$ = "chkconfig --add"
		$ = "cmd over return [%s]"
		$ = "touch   -d"
		$ = "%s can't be opened/n"
		$ = "/proc/%s/status"

	condition:
		uint32be( 0 ) == 0x7f454c46 and 3 of them and filesize < 1MB
}


rule SEKOIA_Apt_Icepeony_Icecache : FILE
{
	meta:
		description = "Detects IceCache backdoor"
		author = "Sekoia.io"
		id = "3135c70e-c925-4d26-beed-09424fc0c153"
		date = "2024-10-21"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_icepeony_icecache.yar#L1-L46"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		hash = "38708c33dafb5625ddde1030a7efa7db"
		hash = "1e102c8909b2bf71c626b81f7526ee01"
		hash = "34bc3c586a48f836b00aff59fe891b30"
		hash = "cd906f4cef84dddeb644b06777474b2e"
		hash = "add23fedfbf238f51173796f3feb12af"
		hash = "25b8daaa5e9c5f8820261d7ebf79f3cd"
		hash = "7fd45cc1de1230c916d5f547a9fc725c"
		hash = "e6e4060e838d7af5f13ad64258d5db0c"
		hash = "87dfc911885420380bea0cf74c8160d3"
		hash = "bd15103b300cad635191972330913d17"
		hash = "a8119b7803a6e0b8aed6bc74d9062b7f"
		hash = "e1bc3efc33b57c9e1e6d37e5011228f2"
		hash = "e1233a5f613aafec2c28133e810f536d"
		hash = "fe88a5b91841b25b4bafa08d42faab22"
		logic_hash = "db82489e1a1eb55960b7a8fd3e6f52db526295ed4e5b90ddea826c5be5f9a1c4"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "Source Response Empty!"
		$ = "Source Response Len:"
		$ = "GetFromSource:"
		$ = "Failed add header!"
		$ = "Failed receive response:"
		$ = "Error: Status Code :"
		$ = "WinHttpAddRequestHeaders"
		$ = "X-FORWARDED-HOST:"
		$ = "PROXY_DEL_CONTENT"
		$ = "PROXY_CLEAR_CONTENT"
		$ = "PROXY_SET_JS"
		$ = "PROXY_GET_JS"
		$ = "PROXY_ALLOW_PC"
		$ = "Parse IP failed :"
		$ = "Clear Proxy Contents Success!"
		$ = "FILE_UPLOAD"
		$ = "FILE_DOWNLOAD"

	condition:
		uint16be( 0 ) == 0x4d5a and filesize < 1MB and 6 of them
}

rule SEKOIA_Apt_Apt28_Document_Phishing_Webpage : FILE
{
	meta:
		description = "Detects APT28 document phishing webpage"
		author = "Sekoia.io"
		id = "585a8e23-c302-41d3-938f-eda60c82ef28"
		date = "2024-04-08"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_apt28_document_phishing_webpage.yar#L1-L22"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "b64888c1d8568cf9d8f4dfcd2e18093db8635966d88abaa368dc46a1e4453782"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "webhook.site"
		$ = "document.createElement('img')"
		$ = "brightness(15%) blur(7.0px)"
		$ = "This document is not available from mobile devices."
		$ = "Capture2.PNG"
		$ = ">CLICK TO VIEW DOCUMENT<"
		$ = "window.location.href = 's"
		$ = ".oast."

	condition:
		4 of them and filesize < 20KB
}

rule SEKOIA_Apt_Sidecopy_Malicious_Macro : FILE
{
	meta:
		description = "Detects malicious macro used by SideCopy"
		author = "Sekoia.io"
		id = "4b90c33e-48d4-48b6-87a7-c35686e7e913"
		date = "2023-05-11"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_sidecopy_malicious_macro.yar#L1-L21"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "b1d9d7af8507b478b2a8d34a4a5ca3714b219a42d5b3f9d5026d98351294e1cf"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "htmlFile$"
		$ = "Gecko/20100101 Firefox/91.0"
		$ = "Start Menu\\Programs\\Startup\\"
		$ = "Document_Close"
		$ = "ThisDocument" wide
		$ = "ServerXMLHTTP.6.0"

	condition:
		uint32be( 0 ) == 0xD0CF11E0 and all of them
}

rule SEKOIA_Apt_Toddycat_Tomberbil_Strings : FILE
{
	meta:
		description = "Detects TomBerBil password stealer"
		author = "Sekoia.io"
		id = "b16f4d35-ea59-4439-8ddb-2c0415b97b9b"
		date = "2024-04-23"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_toddycat_tomberbil_strings.yar#L1-L22"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "92da6ba86cffec75a9af90a513840672b023c81baa9aedb2b706534cc39ecc09"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "[+] Begin" ascii wide
		$ = "[+] Delete File" ascii wide
		$ = "[+] Current user" ascii wide
		$ = "[+] Impersonate user" ascii wide
		$ = "[+] Local State File" ascii wide
		$ = "[>] Profile" ascii wide

	condition:
		uint16be( 0 ) == 0x4d5a and filesize < 1MB and 4 of them
}

rule SEKOIA_Apt_Sugargh0Stcampaign_Malicious_Lnk : FILE
{
	meta:
		description = "Detects malicious LNK used in SugarGh0st campaign"
		author = "Sekoia.io"
		id = "4297c150-d125-49b9-8850-fcedf5284ae9"
		date = "2023-12-01"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_sugargh0stcampaign_malicious_lnk.yar#L1-L18"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "9efa131fdb02f31812c8a3f2053e1b60d0970c748eb0f82aed92a1c0719e048c"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "dir /S/b *.lnk " wide
		$ = "%temp%\\*.lnk" wide

	condition:
		uint32be( 0 ) == 0x4c000000 and filesize < 1MB and all of them
}

rule SEKOIA_Apt_Oilrig_Oilbooster_Strings : FILE
{
	meta:
		description = "Detects OilBooster malware based on strings"
		author = "Sekoia.io"
		id = "001d12bc-1e7e-4a6c-9172-66687d08d827"
		date = "2023-12-20"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_oilrig_oilbooster_strings.yar#L1-L20"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "9562d373ba7602d250aec1eefa2d671da64e897e490da284ffa0e310074266cf"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "/rt.ovf" wide ascii
		$ = "User-Agent: " wide ascii
		$ = "/me/drive/items" wide ascii
		$ = "client_secret" wide ascii

	condition:
		uint16be( 0 ) == 0x4d5a and filesize < 5MB and all of them
}

rule SEKOIA_Apt_Tortoiseshell_Wateringhole_Script : FILE
{
	meta:
		description = "Detect's Tortoiseshell WH script"
		author = "Sekoia.io"
		id = "58c5ae66-fe09-497c-80bf-20feee4d95e7"
		date = "2023-05-24"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_tortoiseshell_wateringhole_script.yar#L1-L22"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "8ad886443b1bd17048054b57650d38cda1ffccc10fedfac86283a41daf956dc2"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "btoa(pluggin.toString())"
		$ = "btoa(document.referrer)"
		$ = "pluggin.push(navigator.plugins[i]"
		$ = "navigator.language"
		$ = "window.RTCPeerConnection"
		$ = "sha256(canvas.toDataURL("
		$ = "canvas.getContext('2d"
		$ = "noop = function() {},"

	condition:
		5 of them and filesize < 10000
}

rule SEKOIA_Apt_Muddywater_Powgoop_Decoded : FILE
{
	meta:
		description = "Detects decoded PowGoop malware"
		author = "Sekoia.io"
		id = "194cb9ef-da96-42b6-a3b5-b0aee7495f2c"
		date = "2022-01-13"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_muddywater_powgoop_decoded.yar#L1-L26"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "6654d8107bb2ad6344f1fa03c6525ed9a0b8e49627787355efe857e80a02eca4"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$h1 = "[System.Net.WebRequest]::Create(" ascii wide
		$h2 = "Headers.Add('Authorization'" ascii wide
		$h3 = "Headers.Add('Cookie',('value=' + $ec + ';')" ascii wide
		$h4 = ".GetResponse()" ascii wide
		$h5 = "GetResponseStream()" ascii wide
		$c1 = "return (65..90) + (97..122) | Get-Random -Count" ascii wide
		$c2 = "% {[char]$_}" ascii wide

	condition:
		filesize > 1KB and filesize < 1MB and ( $h2 in ( @h1 .. @h5 ) and $h3 in ( @h1 .. @h5 ) and $h4 in ( @h1 .. @h5 ) ) or ( $c2 in ( @c1 .. @c1 + 50 ) ) and true
}

rule SEKOIA_Apt_Sugardump_Credentials_Stealer_Http : FILE
{
	meta:
		description = "No description has been set in the source file - SEKOIA"
		author = "Sekoia.io"
		id = "47d01ba8-9fdd-42d5-9f10-115f982dc133"
		date = "2022-08-23"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_sugardump_credentials_stealer_http.yar#L1-L28"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "8d1725da41704fd534d3438021a98d0fb9b9b5bfdc63cc3144c4957954be1870"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "\\Google\\Chrome\\User Data" wide
		$ = "\\DebugLogWindowsDefender.txt" wide
		$ = "Opera Software\\Opera Stable" wide
		$ = "Microsoft\\Edge\\User Data" wide
		$ = "\"encrypted_key\":\"(.*?)\\" wide
		$ = "Url:" wide
		$ = "Username:" wide
		$ = "Password:" wide
		$ = "Application:" wide
		$ = "BCrypt.BCryptDecrypt" wide
		$ = "C:\\Users\\User\\" wide
		$ = "_CorExeMain"
		$ = "http://" wide

	condition:
		uint16be( 0 ) == 0x4d5a and filesize < 1MB and 10 of them
}

rule SEKOIA_Apt_Mustangpanda_Tonedrop : FILE
{
	meta:
		description = "TONEDROP strings"
		author = "Sekoia.io"
		id = "39df631c-5766-4804-838f-6c9b800c0cc9"
		date = "2023-06-19"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_mustangpanda_tonedrop.yar#L1-L43"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "97f9138810fbc56fa1cab671865b3234f63fcd0f9a15ba012dfe76e86c6dbd48"
		score = 75
		quality = 78
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$window1 = "PROCMON_WINDOW_CLASS" ascii wide
		$window2 = "OLLYDBG" ascii wide
		$window3 = "WinDbgFrameClass" ascii wide
		$window4 = "OllyDbg - [CPU]" ascii wide
		$window5 = "Immunity Debugger - [CPU]" ascii wide
		$errormsg1 = "Unable to open file %s for writing" ascii wide
		$proc_01 = "cheatengine-x86_64.exe" ascii wide
		$proc_02 = "ollydbg.exe" ascii wide
		$proc_03 = "ida.exe" ascii wide
		$proc_04 = "ida64.exe" ascii wide
		$proc_05 = "radare2.exe" ascii wide
		$proc_06 = "x64dbg.exe" ascii wide
		$proc_07 = "procmon.exe" ascii wide
		$proc_08 = "procmon64.exe" ascii wide
		$proc_09 = "procexp.exe" ascii wide
		$proc_10 = "processhacker.exe" ascii wide
		$proc_11 = "pestudio.exe" ascii wide
		$proc_12 = "systracerx32.exe" ascii wide
		$proc_13 = "fiddler.exe" ascii wide
		$proc_14 = "tcpview.exe" ascii wide
		$opcodes_check_PEsize = {C7 85 94 FD FF FF 2C 02}
		$opcodes_ShellExecute_1 = {C7 45 BC 53 68 65 6C}
		$opcodes_ShellExecute_2 = {C7 45 C0 6C 45 78 65}
		$opcodes_ShellExecute_3 = {C7 45 C4 63 75 74 65}
		$opcodes_ShellExecute_4 = {66 C7 45 C8 41 00}

	condition:
		( uint32be( 0 ) == 0x7f454c46 or uint16be( 0 ) == 0x4d5a ) and filesize < 8MB and 3 of ( $window* ) and $errormsg1 and 10 of ( $proc_* ) and 3 of ( $opcodes* )
}

rule SEKOIA_Apt_Icepeony_Iceevent : FILE
{
	meta:
		description = "Detects IceEvent Backdoor"
		author = "Sekoia.io"
		id = "7d1f8b90-fde4-4d5c-a8a3-375db8aa88a1"
		date = "2024-10-21"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_icepeony_iceevent.yar#L1-L24"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		hash = "07c291c9cea4430676c303128bbbb8e3"
		hash = "489b573b37ab8bc74cca3704e723b895"
		hash = "265f6cf778d26e62903fb295f89507e3"
		hash = "f5eb28dd29c91cc84818b74d7f138ff6"
		logic_hash = "8afe4a94513e9aa5d20849153c76cfe5c684c9a529710947930c76098a36540e"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "Created a process" ascii fullword
		$ = "CreateProcess failed: %d"
		$ = "bind error:"
		$ = "Error creating pip: %d"
		$ = "listen error:"

	condition:
		uint16be( 0 ) == 0x4d5a and 4 of them and filesize < 500KB
}

rule SEKOIA_Apt_Qnapworm_Loader_May2022 : FILE
{
	meta:
		description = "Detects the QNAPWorm loader"
		author = "Sekoia.io"
		id = "c6e87a55-73ea-4df4-ab61-b5d34968d741"
		date = "2022-05-23"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_qnapworm_loader_may2022.yar#L1-L28"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "d31fdaaacd417a4191e79e3a287e84c55109158eaacc789b2129e2ba94e443f6"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = {
        66 C1 C0 05
        0F B7 D8
        81 C3 85 D0 FF FF
        66 C1 C3 02
        0F B7 C3
        0F B6 9A ?? ?? ?? ??
        33 D8
        88 1C 11
        42
        0F B6 D2
        81 FA ?? 00 00 00
        }

	condition:
		uint16be( 0 ) == 0x4d5a and all of ( $s* )
}

rule SEKOIA_Apt_Muddywater_Moriagent : FILE
{
	meta:
		description = "Detects Muddy's Mori Agent implant"
		author = "Sekoia.io"
		id = "e7a83663-6a30-416a-8f29-87a6b9445ea4"
		date = "2022-01-14"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_muddywater_moriagent.yar#L3-L28"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "21389d4e71e9a19a9d263b8ced740c337ea88ed4ac97199897b0aa3f5914594a"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$mut = "0x50504060" ascii fullword
		$cmd1 = "TType" ascii fullword
		$cmd2 = "TPath" ascii fullword
		$cmd3 = "TFileid" ascii fullword
		$cmd4 = "TCommand" ascii fullword
		$cmd5 = "TTimeout" ascii fullword
		$cmd6 = "TFilter" ascii fullword

	condition:
		uint16be( 0 ) == 0x4d5a and ( ( pe.number_of_exports == 2 and pe.exports ( "DllRegisterServer" ) and pe.exports ( "DllUnregisterServer" ) ) and ( 5 of them ) )
}

rule SEKOIA_Apt_Cloudatlas_Powershower_Variant : FILE
{
	meta:
		description = "Detects PowerShower"
		author = "Sekoia.io"
		id = "416d0cb0-bc59-47ae-8a98-d7b39f8108ab"
		date = "2023-12-20"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_cloudatlas_powershower_variant.yar#L1-L17"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "7bcfafd5a52d685fe33715c8c3725d95947c65863902fde05cf85685a6bfeab8"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = "[System.Text.Encoding]::" ascii wide
		$s2 = "{8}{9}{10}{11}{12}{13}{14}{15}{16}{17}{18}{19}{20}" ascii wide

	condition:
		filesize < 10KB and all of them
}

rule SEKOIA_Apt_Oilrig_Sc5Kv3_Strings : FILE
{
	meta:
		description = "Detects SC5kv3 malware based on strings"
		author = "Sekoia.io"
		id = "885ea13b-47b0-4a6d-8136-9b31abc9064a"
		date = "2023-12-20"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_oilrig_sc5kv3_strings.yar#L1-L18"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "ace8e227abd97d0ec21815cc58c24d46e4944f2b0e1987672be53f81356a7a57"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "no-reply this email!" ascii wide
		$ = "The serial is " ascii wide

	condition:
		uint16be( 0 ) == 0x4d5a and filesize < 5MB and all of them
}

rule SEKOIA_Apt_Spikedwine_Malicious_Hta
{
	meta:
		description = "Detects malicious HTA used by SPIKEDWINE"
		author = "Sekoia.io"
		id = "e4526142-d98a-bf35-9d2c-ca2e83638c4b"
		date = "2024-02-29"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_spikedwine_malicious_hta.yar#L1-L17"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "305896cde5d95c29de511541a961063730709d40d67a8788f084c17f181e3baf"
		score = 75
		quality = 80
		tags = ""
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "<HTA:APPLICATION ID=" nocase
		$ = "return _0x"
		$ = "font-size: 18px;"

	condition:
		all of them
}

rule SEKOIA_Apt_Badmagic_Commonmagic_Main : FILE
{
	meta:
		description = "Detects CommonMagic related implants"
		author = "Sekoia.io"
		id = "99983df5-89d6-4fac-81e6-16e5ab20bde3"
		date = "2023-05-15"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_badmagic_commonmagic_main.yar#L1-L19"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "9bcfd6e9e150399c7f11abc41205119ddf24ea0fef5816ed905cd9b1e9ec5c1e"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "graph.microsoft.com" ascii wide
		$ = "children?select=name,size" ascii wide fullword
		$ = "\\\\.\\pipe\\PipeCrDtMd" ascii wide fullword

	condition:
		uint16be( 0 ) == 0x4d5a and filesize < 1MB and all of them
}

rule SEKOIA_Apt_Tortoiseshell_Imaploader : FILE
{
	meta:
		description = "Detects IMAPLoader malware"
		author = "Sekoia.io"
		id = "e1706b59-5c94-4fbf-8560-0022ca631d1d"
		date = "2023-11-13"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_tortoiseshell_imaploader.yar#L1-L19"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "93f57940ed69145064e5153cc9b099fb9456116cae808acfb4e6f7f14003dde7"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = "yandex.com"
		$s2 = "saveImapMessage.pdb"
		$s3 = "downloader"
		$s4 = "MailServer.Auth"

	condition:
		filesize < 1MB and 3 of them
}


rule SEKOIA_Apt_Lazarus_Pondrat : FILE
{
	meta:
		description = "Detects PondRAT via mangled command names"
		author = "Sekoia.io"
		id = "a957c158-a79a-4d7a-8473-b6960cf02d9b"
		date = "2024-09-23"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_lazarus_pondrat.yar#L1-L24"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		hash = "b62c912de846e743effdf7e5654a7605"
		hash = "61d7b2c7814971e5323ec67b3a3d7f45"
		hash = "ce35c935dcc9d55b2c79945bac77dc8e"
		hash = "f50c83a4147b86cdb20cc1fbae458865"
		hash = "05957d98a75c04597649295dc846682d"
		hash = "33c9a47debdb07824c6c51e13740bdfe"
		logic_hash = "49c5f635e3873a145479bb164838043921d012eef7dc8ad6373c43c8cf1f14e0"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$cmd_PondRAT1 = "_Z7MsgDownP11_TRANS_INFO" ascii
		$cmd_PondRAT2 = "_Z5MsgUpP11_TRANS_INFO" ascii
		$cmd_PondRAT3 = "_Z6MsgRunP11_TRANS_INFO" ascii
		$cmd_PondRAT4 = "_Z6MsgCmdP11_TRANS_INFO" ascii

	condition:
		3 of them and filesize < 4MB
}


rule SEKOIA_Apt_Lazarus_Lambload_Timecheck : FILE
{
	meta:
		description = "Detects timeCheck routine in LambLoad"
		author = "Sekoia.io"
		id = "8807c752-c34e-4c3b-9194-3a9bd2575a88"
		date = "2023-11-27"
		modified = "2024-12-19"
		reference = "https://www.microsoft.com/en-us/security/blog/2023/11/22/diamond-sleet-supply-chain-compromise-distributes-a-modified-cyberlink-installer/"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_lazarus_lambload_timecheck.yar#L1-L67"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "019e559f3596cf83f7e7ada05f6550b50b2d45d577600fa549470b98af93e23b"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$chunk_1 = {
        0F 85 ?? ?? ?? ??
        8D 85 ?? ?? ?? ??
        50
        E8 ?? ?? ?? ??
        83 C4 ??
        83 78 ?? ??
        0F 85 ?? ?? ?? ??
        8B 48 ??
        83 F9 ??
        0F 8C ?? ?? ?? ??
        83 F9 ??
        0F 8D ?? ?? ?? ??
        8B 40 ??
        83 F8 ??
        0F 8C ?? ?? ?? ??
        83 F8 ??
        0F 8D ?? ?? ?? ??
        53
        57
        68 ?? ?? ?? ??
        8D 85 ?? ?? ?? ??
        6A ??
        50
        C7 85 ?? ?? ?? ?? ?? ?? ?? ??
        }

	condition:
		uint16be( 0 ) == 0x4d5a and any of them
}

rule SEKOIA_Apt_Ta410_Flowcloud_Loader : FILE
{
	meta:
		description = "Detects FlowCloud Loader"
		author = "Sekoia.io"
		id = "0a11dfa0-5a59-477b-baf6-6a777d020860"
		date = "2024-05-27"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_ta410_flowcloud_loader.yar#L1-L23"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "450cfdfbd9a42b623fc1acb55f3ea309ae54282b480edcb9495f4d45874d3922"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$decryption_function = {8A C8 80 C1 26 32 D1 30 14 38}
		$derivation_key = {6B 04 00 00 F7 ?? 81 c2 a8 01 00 00}
		$new_pattern_1 = {50 33 c0 58 74 01 e8}
		$new_pattern_2 = {89 44 24 fc 58 8D 64
        24 fc 81 fc 00 10 00
        00 77 06 81 c4 ?? ??
        ?? ?? 8B 44 24 FC}
		$patch_bytes = {68 78 56 34 12 C3 90 90 90 90 90 00}

	condition:
		uint16be( 0 ) == 0x4d5a and filesize < 4MB and 2 of them
}

rule SEKOIA_Apt_Toneshell_Shellcode : FILE
{
	meta:
		description = "Detects first bytes of ToneShell used to call the shellcode or the code to check the MagicNumber (0x17 0x03 0x03)"
		author = "Sekoia.io"
		id = "5ac8d2e9-dbeb-42f9-8343-1281510d4411"
		date = "2024-10-02"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_toneshell_shellcode.yar#L1-L34"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "0e164677681dce2aa75d3621d9f3df1449c3e67a3551817693856d80ccc48eca"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$code = {55 8b ec 83 ec 0c e8 85 00 00 00 6a 00 6a 00 6a 02 6a 00 6a 00 68 00 00 00 10}
		$MagicNumberParser = {
        B8 01 00 00 00
        6B C8 00
        8B 55 ??
        0F BE 04 0A
        83 F8 17
        75 ??
        B9 01 00 00 00
        C1 E1 00
        8B 55 ??
        0F BE 04 0A
        83 F8 03
        75 ??
        B9 01 00 00 00
        D1 E1
        8B 55 ??
        0F BE 04 0A
        83 F8 03
        }

	condition:
		any of them and filesize < 1MB
}


rule SEKOIA_Apt_Gelsemium_Wolfsbane_Rootkit : FILE
{
	meta:
		description = "Detects Gelsemium's WolfsBane rootkit"
		author = "Sekoia.io"
		id = "e93f4515-62f5-4057-a464-aae11cbe0639"
		date = "2024-11-22"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_gelsemium_wolfsbane_rootkit.yar#L1-L24"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		hash = "ba08e63ad65a9bdcdb1655f25d32c808"
		logic_hash = "a7440e1b4c0bbff0d80d7152e3bfb0867abe9b0151b45f88aa656f3c9a55b303"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "__non_hooked_symbols"
		$ = "__hidden_literals"
		$ = "extract_type_2_socket_inode2"
		$ = "/proc/%s/fd"
		$ = "pluginkey" wide
		$ = "mainpath" wide
		$ = "hiderpath" wide

	condition:
		uint32be( 0 ) == 0x7f454c46 and filesize < 1MB and all of them
}

rule SEKOIA_Apt_Emberbear_Credpump_Strings : FILE
{
	meta:
		description = "Detects CredPump backdoor"
		author = "Sekoia.io"
		id = "c9898e34-4ab8-49d6-9c8a-3fce592449e2"
		date = "2023-02-28"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_emberbear_credpump_strings.yar#L1-L20"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "6f2c96fe3f314221626b4c053658af0e7231f151886f10eb1d69e07ea3e5c634"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "User=%s Pass=%s Host=%s"
		$ = "/etc/rc0.d/.rc0.d"
		$ = "pam_get_authtok"
		$ = "Password:"

	condition:
		uint32be( 0 ) == 0x7f454c46 and filesize < 200KB and all of them
}

rule SEKOIA_Apt_Gamaredon_Htmlsmuggling_Attachment_Stage2 : FILE
{
	meta:
		description = "Detects Gamaredon HTMLSmuggling attachment"
		author = "Sekoia.io"
		id = "e82335ea-48d5-409c-a270-cfd5a2197c44"
		date = "2023-01-20"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_gamaredon_htmlsmuggling_attachment_stage2.yar#L1-L19"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "42e637f628db6719342ae104c6c89bb80609c5f3f5c2586daccb31f7d688a2a1"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = ") == -1) die();" ascii
		$ = "'data:application/x-rar-compressed;base64, ' +" ascii
		$ = ".appendChild(img);" ascii
		$ = "['Win32', 'Win64', 'Windows', 'WinCE'].indexOf(" ascii
		$ = " = navigator[\"platform\"];" ascii

	condition:
		4 of them and filesize < 1MB
}

rule SEKOIA_Apt_Kimsuky_Validator_Strings : FILE
{
	meta:
		description = "Detects Kimsuky validator"
		author = "Sekoia.io"
		id = "e055f2d4-8318-4342-812e-0f621d7886b4"
		date = "2024-06-11"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_kimsuky_validator_strings.yar#L1-L17"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "a627dae8c12f0f6f8472bc12b8e1a85137f92f6e389f817ab9023c90720a42b0"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "%s%sc %s >%s 2>&1" wide
		$ = "%s%sc %s 2>%s" wide

	condition:
		uint16be( 0 ) == 0x4d5a and all of them
}

rule SEKOIA_Apt_Andariel_Keylogger_Strings : FILE
{
	meta:
		description = "Detects one of the Andariel keylogger"
		author = "Sekoia.io"
		id = "59e94bee-9bd4-4f72-9358-858956bb4787"
		date = "2024-06-17"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_andariel_keylogger_strings.yar#L1-L19"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "671698af4fbaed3d19f3d3498263183909db9422a5a0a8f12ba119409773c505"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "Username:%s [%d/%02d/%02d %02d:%02d]" ascii fullword
		$ = "-------[%d/%02d/%02d %02d:%02d]"
		$ = "{Insert}"

	condition:
		uint16be( 0 ) == 0x4d5a and filesize < 300KB and 2 of them
}

rule SEKOIA_Apt_Mustangpanda_Windows_Shellcode_Decryptionalgorithm : FILE
{
	meta:
		description = "Decryption routine for Shellcode of MustangPanda"
		author = "Sekoia.io"
		id = "c9873a5f-97a6-477f-a1a0-650441c73444"
		date = "2022-12-05"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_mustangpanda_windows_shellcode_decryptionalgorithm.yar#L1-L28"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "a2ad3bd4dcbee3e23762b674ee8b6717e7ece712b0128145518bfa5d2e4bd66a"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$chunk_1 = {
        7E ??
        8B 55 ??
        53
        56
        8B 75 ??
        57
        8B 7D ??
        4F
        8D A4 24 ?? ?? ?? ??
        8A 1C 11
        30 1C 30
        }

	condition:
		filesize < 8MB and all of them
}

rule SEKOIA_Implant_Win_Apt29_2022_10
{
	meta:
		description = "APT29 implants from October 2022"
		author = "Sekoia.io"
		id = "0f270e75-f687-4fdc-a980-fde81107a4d6"
		date = "2023-02-15"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/implant_win_apt29_2022_10.yar#L4-L20"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "b9300c2f06b54b16e1cab579d686d986caacf3b6eccec3a4e62d58e94b50bfb4"
		score = 75
		quality = 80
		tags = ""
		version = "1.0"
		classification = "TLP:CLEAR"
		hash1 = "1cffaf3be725d1514c87c328ca578d5df1a86ea3b488e9586f9db89d992da5c4"
		hash2 = "381a3c6c7e119f58dfde6f03a9890353a20badfa1bfa7c38ede62c6b0692103c"

	condition:
		pe.imphash( ) == "39b818e7bac0a276f509f8c47e467666" or for any i in ( 0 .. pe.number_of_sections -1 ) : ( hash.md5 ( pe.sections [ i ] . raw_data_offset , pe.sections [ i ] . raw_data_size ) == "6621113d9f212c71b8dd3ce85c62b251" )
}

rule SEKOIA_Apt_Toneshell_Loader : FILE
{
	meta:
		description = "Detects loader of ToneShell (exception based)"
		author = "Sekoia.io"
		id = "b4bf284b-cab6-455e-a1c1-ad341d43bfdd"
		date = "2024-10-02"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_toneshell_loader.yar#L1-L40"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		hash = "41e0d172d900344a3692b88fff7527d9"
		hash = "782cf7183735935f3f7aad041cec3184"
		hash = "97c1f436028c58b51d4c92ee9c9ce424"
		hash = "d6c771f2afd8ce35e8727f95f3a3c6c4"
		hash = "b8520c5bad88ade394086cb7b1b7b631"
		hash = "0b3e8571e70a32490da19f6b3283151c"
		hash = "f6784c65ee115a9ae4c0fb03e0045285"
		hash = "38888696e5223c77f5f8680922396123"
		hash = "b52d0707e4e5d5c0d5fd5f5a177ba712"
		hash = "fd54c6d17ff91640b377ff41353efdaa"
		hash = "a6efe263acc794a212647a96e52ddf1f"
		hash = "6e8c80c5f2f9a1da504618e984d2a56c"
		hash = "0839666697ccc562a9c1fe77d6755931"
		hash = "f367f2fe580e556176b60da202c742a5"
		hash = "e8b2fcc14494ada2f28d1f6ecd2521a2"
		hash = "c08589e10812cc7d636dcbe2a36d43b4"
		hash = "fa848a05cfecc0c25cd21364c9516584"
		hash = "be231f7879d8d2159b67b7f277527268"
		hash = "2acd8b48202dcc30d88a871370c4f37a"
		hash = "72963bfc2837695f038680471d4f061c"
		logic_hash = "40e1b918a4d83a4918260d8b1cc56e5097665a366f94bd5068e4ae519e3a681b"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$exception = {00 00 00 00 2e 44 00 00}
		$code = {02 00 00 00 66 89 96}
		$kernel32 = "Kernel32.dll" wide
		$outputdbgstr = "OutputDebugStringA"
		$content = "ResetEvent"

	condition:
		uint16be( 0 ) == 0x4d5a and all of them and filesize < 2MB
}

rule SEKOIA_Apt_Sidecopy_Reverserat_Strings : FILE
{
	meta:
		description = "Detects SideCopy's ReverseRAT"
		author = "Sekoia.io"
		id = "383397c9-fd4a-4255-a8f2-27683bdbb7f7"
		date = "2023-05-11"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_sidecopy_reverserat_strings.yar#L1-L23"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "be657405b5703dc402b53350aa7ef18529bda3dc44c759585c4cfa1bc1eb76ff"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "downloadexe" wide
		$ = "creatdir" wide
		$ = "regnewkey" wide
		$ = "reglist" wide
		$ = "regdelkey" wide
		$ = "clipboardset" wide
		$ = "shellexec" wide
		$ = "SELECT maxclockspeed,  datawidth, name, manufacturer FROM Win32_Processor" wide

	condition:
		uint16be( 0 ) == 0x4d5a and all of them
}

rule SEKOIA_Apt_Gamaredon_Gammaload_Maliciouslnk : FILE
{
	meta:
		description = "Detects Gamaredon's GammaLoad LNK"
		author = "Sekoia.io"
		id = "2612e6c6-0bda-4bfa-a840-aa0a0b4c945b"
		date = "2022-08-01"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_gamaredon_gammaload_maliciouslnk.yar#L1-L18"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "94ba156cd6697a9999b6a4f78c4356ea3382b7b3e7a1af79d488aa34df2c3b40"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$mshta = "System32\\mshta.exe"
		$trait = { 0D 0A ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0D 0A }

	condition:
		uint32be( 0 ) == 0x4c000000 and #trait > 100 and $mshta and filesize > 100KB and filesize < 300KB
}

rule SEKOIA_Apt_Sandworm_Olympicdestroyer : FILE
{
	meta:
		description = "Detects OlympicDestroyer malware"
		author = "Sekoia.io"
		id = "6820eb32-fea2-4a00-a5a2-672ba09f8206"
		date = "2022-04-15"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_sandworm_olympicdestroyer.yar#L1-L21"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "a68a96ab036e69a32e173b2d2fa6a81ab872032f89bfdfc3cd4446305a33921b"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "cmd.exe /c (ping 0.0.0.0 > nul)" wide
		$ = "if exist %programdata%\\evtchk.txt" wide
		$ = "\\\\.\\pipe\\%ls" wide
		$ = "%ProgramData%\\%COMPUTERNAME%.exe" wide
		$ = "(exit 5) else ( type nul >" wide
		$ = "Select * From Win32_ProcessStopTrace" nocase

	condition:
		uint16be( 0 ) == 0x4d5a and 3 of them
}

rule SEKOIA_Apt_Kimsuky_Sharptongue_Vbslauncher_Strings : FILE
{
	meta:
		description = "Detects VBS Launchers used by SharpTongue"
		author = "Sekoia.io"
		id = "82bd648c-2961-4945-950e-8fb1e4650338"
		date = "2022-07-29"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_kimsuky_sharptongue_vbslauncher_strings.yar#L1-L17"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "9e1383a71b4ab5ca1de5016061f0e9c83e6f3e1a41eef25dae15cd1aab8b581f"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "powershell" ascii wide
		$ = "On Error Resume Next" ascii wide
		$ = "oShell.run(tmp0,0" ascii wide

	condition:
		all of them and filesize < 10KB
}

rule SEKOIA_Apt_Gamaredon_Htmlsmuggling_Attachment : FILE
{
	meta:
		description = "Detects Gamaredon HTMLSmuggling attachment"
		author = "Sekoia.io"
		id = "a39b6e67-9327-4c5b-902a-b9853cfefc8e"
		date = "2023-01-20"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_gamaredon_htmlsmuggling_attachment.yar#L1-L19"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "e13da493404b27ef0c026ca32accbb30792981e810c099d633f5de225e241b4d"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "['at'+'ob'](" ascii
		$ = "['ev'+'al'](" ascii
		$ = "document.querySelectorAll('[" ascii
		$ = "[0].innerHTML.split(' ').join('')))" ascii

	condition:
		filesize < 1MB and 2 of them
}

rule SEKOIA_Apt_Sandworm_Notpetya_Strings : FILE
{
	meta:
		description = "Detects NotPetya worm"
		author = "Sekoia.io"
		id = "c6021638-1b59-4d20-a29d-95cabf256a28"
		date = "2022-04-15"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_sandworm_notpetya_strings.yar#L1-L21"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "5600071de4b4022a71c48fbcd4b5e47ff6dfa291cc5eac65720bbf763068a6e3"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "wevtutil cl Security &" wide
		$ = "wevtutil cl System &" wide
		$ = "u%s \\%s -accepteula -s" wide
		$ = "\\\\%ws\\admin$\\%ws" wide
		$ = "\\\\%s\\admin$" wide
		$ = "C:\\Windows\\System32\\rundll32.exe \"C:\\Windows\\%s\",#1" wide

	condition:
		uint16be( 0 ) == 0x4d5a and 3 of them
}

rule SEKOIA_Apt_Cloudatlas_Rtf_Shellcode_Cve_2018_0798 : FILE
{
	meta:
		description = "CloudAtlas Shellcode for CVE_2018_0798 "
		author = "Sekoia.io"
		id = "6c602c66-df40-4436-800f-e548dacc1e81"
		date = "2022-12-01"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_cloudatlas_rtf_shellcode_cve_2018_0798.yar#L1-L16"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "a8c320ca81ef196b84a8fb08d9e02ef8cfb338024fa7e6776ff6c8c049b8e63c"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = "6060606061616161616161616161616161616161FB0B00004bE8FFFFFFFFC35F83C71B33C966B908010f0d00ddd8d97424f4668137" ascii nocase

	condition:
		filesize < 8MB and all of them
}

rule SEKOIA_Apt_Apt31_Pakdoor : FILE
{
	meta:
		description = "Detects APT31 ORB implant - 2019/2021"
		author = "Sekoia.io"
		id = "463b8d0d-30f4-45ed-8f19-4b32436fbbf0"
		date = "2021-10-11"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_apt31_pakdoor.yar#L1-L25"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		hash = "1d60edb577641ce47dc2a8299f8b7f878e37120b192655aaf80d1cde5ee482d2"
		logic_hash = "ef001e31b34761688f32ec767082d9d7f9fc4e4368d567eb64b66583bcb7fc78"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"
		version = "1.0"

	strings:
		$s1 = "mv -f %s %s ;chmod 777 %s"
		$s2 = "GET /plain HTTP/1.1"
		$s3 = "exc_cmd time out"
		$s4 = "exc_cmd pipe err"
		$s5 = { 2e 2f [1-10] 20 20 64 65 6c }

	condition:
		int32be ( 0 ) == 0x7f454c46 and filesize < 800KB and filesize > 400KB and 4 of ( $s* )
}

rule SEKOIA_Apt_Unc4990_Explorer_Ps1_Reverse_B64 : FILE
{
	meta:
		description = "Detects reverse base64 files (explorer.ps1)"
		author = "Sekoia.io"
		id = "35c3ffb2-2ced-426c-ac3f-a8cd0c357672"
		date = "2024-02-01"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_unc4990_explorer_ps1_reverse_b64.yar#L1-L17"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "bf13fbf2dbe6a718510f3e435a9fe06517ed962f8e129d79a15e6a301e5713ca"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s0 = "Invoke-Expression ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(\""
		$s1 = "Wa1VHJ\"[-1..-"
		$s2 = "-join '')))"

	condition:
		all of them and $s0 at 0 and @s2 - @s2 < 20
}

rule SEKOIA_Apt_Toddycat_Waexp_Strings : FILE
{
	meta:
		description = "Detects WAExp based on strings"
		author = "Sekoia.io"
		id = "1bbb3e81-14a9-4bda-b647-b6f5255e9a16"
		date = "2024-04-23"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_toddycat_waexp_strings.yar#L1-L18"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "4377183b326329fb14ae3911fbb1e29cde220d7b247d048fba4bbbda9de8938d"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "[>] Profile:" wide ascii
		$ = "[+] All Done" wide ascii
		$ = "[+] Files:" wide ascii

	condition:
		( uint32be( 0 ) == 0x7f454c46 or uint16be( 0 ) == 0x4d5a ) and all of them and filesize < 1MB
}

rule SEKOIA_Apt_37_Chinotto : FILE
{
	meta:
		description = "Detects obfuscation and string of APT37 stealer"
		author = "Sekoia.io"
		id = "eff8fd11-dc7a-4011-b083-181d0cca8790"
		date = "2023-02-27"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_37_chinotto.yar#L1-L50"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "a721f102b4c9568379649f8004fa4eb460240145ab829d8ce3740dafb52d13c8"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"
		hash1 = "feab7940559392bbf38f29267509340569160e0a3b257fd86e5c65ae087ea014"
		hash2 = "c9d2c8b6011a53e68e4a6c6e51142cef3348951d0b379e49b1a65a1891538df5"
		hash3 = "2f5be3773e7e3a2f6806cdef154adfabc454c0e57a49e437c5889ce09b739302"
		hash4 = "5bf170c95ca0e2079653d694f783b5bcd38f274ea875f67f0b60db4ac552a66c"
		hash5 = "6fad04c836bc923f12ebaec8d8fb0c7091b044bf6f5c97e36d7bf46b8494f978"
		hash6 = "64fe964f342acca6d85d247c4f67503e4222a58dfc5c644dedc2006a4b356d39"
		hash7 = "6e216b265ea391f71f2a609df995f36b9ba8b17c8859f6d8e4ce4a076d351efd"
		hash8 = "70dcc03cde3dd5c5ec6a6a240190cfb51667aaba9c867e20281e8dfc43afa891"
		hash9 = "5053390bde150b771f8efe344b692c6c5718ba9203a4b23f5323af1ee9060ff2"
		hash10 = "089e4dfd8b25afe596eff05baae86156a4e3243c84faa15416cff31a5120e107"
		hash11 = "37e096338a78cb06d6236cb5a04cf125f191871ded3c9421f08a37890a095eb8"
		hash12 = "b90a2b0249407b271a5d849fe82cbf4e9a31c2c6259caf515c9be3897e327414"
		hash13 = "8f4751ed22619b04009c4b85ec45c8140b570835ca4c638c9e6019e7b7eb66c7"

	strings:
		$chunk_1 = {
        C7 85 ?? ?? ?? ?? ?? ?? ?? 00
        C7 85 ?? ?? ?? ?? ?? ?? ?? 00
        33 C0
        EB 03
        8D 49 00
        8B 8C 85 ?? ?? ?? ??
        3B 8C 85 ?? ?? ?? ??
        }
		$chunk_2 = {
        C7 84 24 ?? ?? ?? ?? ?? ?? 0? 00
        C7 84 24 ?? ?? ?? ?? ?? ?? 0? 00
        33 C0
        EB 0D
        8D A4 24 00 00 00 00
        8D 9B 00 00 00 00
        8B 8C 84 ?? ?? ?? ??
        3B 8C 84 ?? ?? ?? ??
        }
		$movs_zip_dir_start = { C7 45 ?? 5A 69 70 20 C7 45 ?? 44 69 72 20 C7 45 ?? 53 74 61 72  C7 45 ?? 74 20 2D 20}

	condition:
		( uint32be( 0 ) == 0x7f454c46 or uint16be( 0 ) == 0x4d5a ) and filesize < 1MB and ( $chunk_1 or $chunk_2 ) and $movs_zip_dir_start
}

rule SEKOIA_Apt_Oilrig_Odagent_Strings : FILE
{
	meta:
		description = "Detects ODAgent malware based on strings"
		author = "Sekoia.io"
		id = "1c5c0eb5-7c6f-4a34-b2e2-4a7c6d7030d6"
		date = "2023-12-20"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_oilrig_odagent_strings.yar#L1-L21"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "14a1399ff3519632e3bbb6eea0d44e9908cfc03728bd26f610ab75fff6a8d2c6"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "application/x-www-form-urlencoded" ascii wide
		$ = "dly>" ascii wide
		$ = "DELETE" ascii wide
		$ = "nok!" ascii wide
		$ = ".c:/content" ascii wide

	condition:
		uint16be( 0 ) == 0x4d5a and filesize < 5MB and all of them
}

rule SEKOIA_Apt_Apt41_Powershell_Exfiltration_Script : FILE
{
	meta:
		description = "Detects PowerShell exfiltration script"
		author = "Sekoia.io"
		id = "9a15f845-c0af-4f1c-a033-b4f40232dc0d"
		date = "2023-11-15"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_apt41_powershell_exfiltration_script.yar#L1-L18"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "0ba4118855d6bd54cbb3a35e3b5fc36484eeb1e742ed3480e6c967b078ec4881"
		score = 75
		quality = 72
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "$UPLOAD_PASSPORT" ascii wide nocase
		$ = "$fileName=$singleFile.Name" ascii wide nocase
		$ = "Upload-Passport" ascii wide nocase
		$ = "$singleFile in $files" ascii wide nocase

	condition:
		filesize < 10KB and all of them
}

rule SEKOIA_Apt_Dark_Pink_Pdb_Path : FILE
{
	meta:
		description = "Detects PDB path of some Dark Pink sample"
		author = "Sekoia.io"
		id = "695586dc-66de-4f9d-814a-2d81261a7357"
		date = "2023-01-16"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_dark_pink_pdb_path.yar#L1-L17"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "f67e0d50975697424313acc77a9c86e1c2b41fde1663e4f5d8f4765acb997775"
		score = 75
		quality = 76
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = "C:\\Users\\hoang\\source\\repos\\Cucky\\Cucky\\obj\\Release\\net46\\Cucky.pdb" wide ascii
		$s2 = "C:\\Users\\build\\source\\repos\\CtealWebCredential\\Release\\CtealWebCredential.pdb" wide ascii

	condition:
		( uint32be( 0 ) == 0x7f454c46 or uint16be( 0 ) == 0x4d5a ) and filesize < 5MB and any of them
}

rule SEKOIA_Apt_Ta410_Flowcloud_Rtti : FILE
{
	meta:
		description = "Detects FlowCloud via RTTI"
		author = "Sekoia.io"
		id = "c6a18c08-8b98-46d7-a6c3-dc171c7791ac"
		date = "2022-10-11"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_ta410_flowcloud_rtti.yar#L1-L17"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "97f052c409c9b5de025d34180979cd4c322e67bab9f894d3b56c928340a6859b"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$RTTI_1 = ".?AVdllloader@@" ascii fullword
		$RTTI_2 = ".?AVel_cryptowrapper@@" ascii fullword
		$RTTI_3 = ".?AVAntiVirusCheck@@" ascii fullword

	condition:
		uint16( 0 ) == 0x5A4D and filesize < 10MB and all of them
}


rule SEKOIA_Apt_Uac0154_Powershell_Infection_Chain_1 : FILE
{
	meta:
		description = "UAC-0154 Infection chain"
		author = "Sekoia.io"
		id = "428eb021-b37f-4db5-8cab-ca2f6dd2e202"
		date = "2023-10-02"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_uac0154_powershell_infection_chain_1.yar#L1-L18"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "a849c397e7f61e41ea7e67a265717d7d66f6af42f3d1e930020d1433dd3aab18"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "command $es ="
		$ = "function isV"
		$ = "doIn;"
		$ = "System.IO.Comp"

	condition:
		all of them and filesize < 100KB
}

rule SEKOIA_Apt_Luckymouse_Rshell_Strings : FILE
{
	meta:
		description = "Detects LuckyMouse RShell Mach-O implant"
		author = "Sekoia.io"
		id = "89f18013-ea3e-440f-821e-cef102a43b7b"
		date = "2022-08-05"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_luckymouse_rshell_strings.yar#L1-L26"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "ffca47856d4c4d83312220cff23c0a556be0e675d59ac009c2f74fc0e39cb816"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = { 64 69 72 00 70 61 74 68
        00 64 6F 77 6E 00 72 65
        61 64 00 75 70 6C 6F 61
        64 00 77 72 69 74 65 00
        64 65 6C }
		$ = { 6C 6F 67 69 6E 00 68 6F
        73 74 6E 61 6D 65 00 6C
        61 6E 00 75 73 65 72 6E
        61 6D 65 00 76 65 72 73
        69 6F 6E }

	condition:
		( uint32be( 0 ) == 0xCFFAEDFE or uint16be( 0 ) == 0x4d5a ) and filesize < 300KB and all of them
}


rule SEKOIA_Apt_Badmagic_Commonmagic_Generic_1 : FILE
{
	meta:
		description = "Detects CommonMagic related implants"
		author = "Sekoia.io"
		id = "0b328771-f674-4606-bb30-d20d07c67832"
		date = "2023-05-15"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_badmagic_commonmagic_generic_1.yar#L1-L20"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "513226d050945af1a8bbc51f9a48936c815bfc6cd43b0766e34ac000d3c90625"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "\\CommonCommand\\Clean\\"
		$ = "\\CommonCommand\\Overall\\"
		$ = "\\CommonCommand\\Other\\"
		$ = "\\CommonCommand\\Other\\*"

	condition:
		uint16be( 0 ) == 0x4d5a and filesize < 1MB and all of them
}

rule SEKOIA_Apt_Buhtrap_Maldocx
{
	meta:
		description = "Detect the malicious DOCX used by Buhtrap"
		author = "Sekoia.io"
		id = "4aaba2f1-fafd-4e3f-8b18-7beda11464d1"
		date = "2022-02-25"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_buhtrap_maldocx.yar#L1-L25"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "69968fa6836a71cd835f40c5168d197d3b5fc13b62791279f48a6bdeb4709bd5"
		score = 75
		quality = 80
		tags = ""
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "<xm:macrosheet xmlns=" ascii fullword
		$ = "CALL(\"kernel32\",\"VirtualFree"
		$ = "CALL(\"kernel32\",\"CreateFileA"
		$ = "CALL(\"kernel32\",\"WriteFile"
		$ = "CALL(\"kernel32\",\"VirtualAlloc"
		$ = "CALL(\"kernel32\",\"WinExec"
		$ = "CALL(\"kernel32\",\"lstrcatA"
		$ = "CALL(\"kernel32\",\"CreateFileA"
		$ = "CALL(\"kernel32\",\"VirtualFree"
		$ = "CALL(\"kernel32\",\"ExpandEnvironmentStringsA"
		$ = "CALL(\"kernel32\",\"CloseHandle"

	condition:
		all of them
}

rule SEKOIA_Apt_Muddywater_Powgoop_Loader : FILE
{
	meta:
		description = "Detects the loader of PowGoop malware"
		author = "Sekoia.io"
		id = "716b45e1-9f17-4546-a003-a7c78340d623"
		date = "2022-01-13"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_muddywater_powgoop_loader.yar#L1-L19"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "70f20928d2bbe081f0595ecdbb6dbe58a2f0807032598d88d829513e6d75287f"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = "$d.Add($in[$i]);" ascii wide
		$s2 = "[System.Text.Encoding]::UTF8.GetString($o);" ascii wide
		$s3 = "$i+=(1+1)" ascii wide
		$t = { 24 ?? 3d [1-15] 20 24 ?? 3b ?? ?? ?? 20 24 ?? 3b }

	condition:
		filesize < 50KB and ( 3 of ( $s* ) or $t in ( filesize -50 .. filesize ) )
}

rule SEKOIA_Apt_Uta0178_Javascript_Inclusion_Strings
{
	meta:
		description = "Detects UTA0178 malicious inclusion strings"
		author = "Sekoia.io"
		id = "af816c35-1f00-47ea-86ee-c034607c625e"
		date = "2024-01-12"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_uta0178_javascript_inclusion_strings.yar#L1-L23"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "d3fedf49417178df374d6ae20e57ffcfa00cb68a647769964c049d9a8e0f4958"
		score = 75
		quality = 80
		tags = ""
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s0 = ".value"
		$s1 = "btoa("
		$s2 = "https://"
		$s3 = "new XMLHttpRequest();"
		$s4 = ".send(null);"

	condition:
		@s0< @s1 and @s1 < @s2 and @s2 < @s3 and @s3 < @s4 and @s4- @s0 < 350
}

rule SEKOIA_Apt_Gamaredon_Stealer_Obfuscation_1 : FILE
{
	meta:
		description = "Matches the Gamaredon Stealer obfuscation"
		author = "Sekoia.io"
		id = "a6197d16-8ed1-410b-8814-d7eff9a8096c"
		date = "2022-02-04"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_gamaredon_stealer_obfuscation_1.yar#L1-L18"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "7f6a5f8af73c4eb7debbadfd22232ad4e3f44e3aae36c3d624ce7a1a050e8782"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = { 76 61 72 20 [5-30] 3d 20 6e 65 77 20 6f 62 6a 65 63 74 5b 5d 20 7b 20 [2-10] 2c 20 [2-10] 2c 20 [2-10] 2c 20 [2-10] 2c 20 [2-10] 2c 20 [2-10] 20 7d 3b }
		$s2 = { 66 6f 72 28 69 6e 74 20 [5-30] 20 3d 20 30 3b 20 [5-30] 20 3c 20 31 30 3b 20 [5-30] 2b 2b 29 }

	condition:
		uint16be( 0 ) == 0x4d5a and filesize > 100MB and ( #s1 > 100 or #s2 > 100 )
}

rule SEKOIA_Apt_Sidecopy_Cheex : FILE
{
	meta:
		description = "Detects PDB path of Cheex"
		author = "Sekoia.io"
		id = "e9b57f15-e703-4367-b501-fa8a873e4455"
		date = "2024-08-14"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_sidecopy_cheex.yar#L1-L16"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		hash = "825c7a1603f800ff247c8f3e9a1420af"
		logic_hash = "e5561466b616c746b33c0c4a46e8bdb0859e55aef8896bc1b14e54838c1661ee"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "C:\\Users\\Dead Snake\\source\\repos\\cheex" ascii fullword

	condition:
		uint16be( 0 ) == 0x4d5a and all of them
}

rule SEKOIA_Apt_Andariel_Siennablue : FILE
{
	meta:
		description = "Detects SiennaBlue based routine names"
		author = "Sekoia.io"
		id = "ab3f8b49-0851-47a8-ac77-98d4e26f448e"
		date = "2023-11-16"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_andariel_siennablue.yar#L1-L20"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "0876deb2e76098ac8d304737243d3a76e9741b2ca1570034bec51fea5a40818d"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "main_cryptAVPass"
		$ = "main_DecryptString"
		$ = "main_DisableNetworkDevice"
		$ = "main_DeleteSchTask"

	condition:
		( uint32be( 0 ) == 0x7f454c46 or uint16be( 0 ) == 0x4d5a ) and filesize > 4MB and filesize < 15MB and all of them
}

rule SEKOIA_Apt_Apt28_Htmlsmuggling
{
	meta:
		description = "Detects some kind of HTMLSmuggling used by APT28"
		author = "Sekoia.io"
		id = "2e20c992-d971-4c0f-99b3-a7d528c7055a"
		date = "2023-09-11"
		modified = "2024-12-19"
		reference = "https://www.zscaler.com/blogs/security-research/steal-it-campaign"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_apt28_htmlsmuggling.yar#L1-L17"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "47cca1d0a0843c8df43661ee8188dae86cce06e1f3982973871863728d328e89"
		score = 75
		quality = 80
		tags = ""
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = "click();" ascii
		$s2 = "window.location.replace("

	condition:
		$s1 in ( @s2 .. @s2-100 )
}

rule SEKOIA_Apt_Cerana_Keeper_Yk0130 : FILE
{
	meta:
		description = "Detects YK0130 reverse shell"
		author = "Sekoia.io"
		id = "3da898a9-68e7-472f-8478-a0243840ec0a"
		date = "2024-10-04"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_cerana_keeper_yk0130.yar#L1-L17"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		hash = "2554e4864294dc96a5b4548dd42c7189"
		logic_hash = "4462c6b7f46520207f49275292a3be873540becb593176d771d3489fba6f4cb0"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$pdb = "C:\\Users\\admin\\source\\repos\\YK0130" ascii fullword

	condition:
		uint16be( 0 ) == 0x4d5a and all of them and filesize < 300KB
}

rule SEKOIA_Apt_Polonium_Deepcreep_Strings : FILE
{
	meta:
		description = "Tries to detect POLONIUM's DeepCreep implant"
		author = "Sekoia.io"
		id = "b04af229-2bea-4ee8-9e17-8e4befa06e3a"
		date = "2022-10-12"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_polonium_deepcreep_strings.yar#L1-L20"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "60724d2eb964e2c3681b72bdb732ca640b603af7dc94b4eb6608c77cddb94011"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = ";Invoke-Expression -Command '$shortcut =" ascii wide
		$ = "CreateShortcut($c1" ascii wide
		$ = "svchostdp.exe" ascii wide
		$ = "HNlIC91IA==" ascii wide

	condition:
		uint16be( 0 ) == 0x4d5a and filesize < 3MB and 3 of them
}

rule SEKOIA_Apt_Gamaredon_Doc_External_Template : FILE
{
	meta:
		description = "Detects malicious templates used by Gamaredon"
		author = "Sekoia.io"
		id = "5f6bbf92-2fdf-428d-af49-2d3e754c29d7"
		date = "2023-01-23"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_gamaredon_doc_external_template.yar#L1-L17"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "51412081fa7e62fa342b0ed6da18009b39e3952286f2bd319fbe10e0b1761e02"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "USERPROFILE" ascii
		$ = "msxml2" ascii
		$ = "T24gRXJyb3IgUmVzdW1lIE5leHQ" ascii

	condition:
		uint32be( 0 ) == 0xd0cf11e0 and filesize < 100KB and all of them
}

rule SEKOIA_Apt_Unk_Malicious_Lnk : FILE
{
	meta:
		description = "Detects a malicious LNK used by an APT"
		author = "Sekoia.io"
		id = "d2248803-7ddf-4cde-ab6a-78b20e760919"
		date = "2024-09-06"
		modified = "2024-12-19"
		reference = "https://www.seqrite.com/blog/operation-oxidovy-sophisticated-malware-campaign-targets-czech-officials-using-nato-themed-decoys/"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_unk_malicious_lnk.yar#L1-L21"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		hash = "a8d7e56eb01a8cf576533db9af2e92ec"
		logic_hash = "993411ceba45d1212a4840e6a35b72b52e64e78cbb2599ebc5c70c2fd3b8e552"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = ".pdf.lnkPK"
		$ = ".jfifPK"
		$ = ".batPK"
		$ = ".pdfPK"

	condition:
		uint32be( 0 ) == 0x504b0304 and all of them
}

rule SEKOIA_Apt_Cerana_Keeper_Dropboxflop : FILE
{
	meta:
		description = "Detects DropboxFlop malware"
		author = "Sekoia.io"
		id = "e077901f-3847-45f3-82cb-d52724cd3fb5"
		date = "2024-10-04"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_cerana_keeper_dropboxflop.yar#L1-L17"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		hash = "2b65b74e52fbf25cb400dbdfcd1a06a7"
		logic_hash = "5b2dfdf0c35f574e7006bb3e6eafa10d0e7fc7d980d443b31d4d6d6b7cec2fce"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "<assemblyIdentity type=\"win32\" name=\"dropboxflop\""

	condition:
		uint16be( 0 ) == 0x4d5a and all of them
}

rule SEKOIA_Apt_Oilrig_Clipog_Strings : FILE
{
	meta:
		description = "Detects OilRig's Clipog stealer"
		author = "Sekoia.io"
		id = "0ac40fd9-f67d-41fa-a774-77a3a1b7cac3"
		date = "2023-10-24"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_oilrig_clipog_strings.yar#L1-L20"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "16f3fef59db9c58025a4a977de944b628e9dc850f87c1bb22e2f2f97601e5107"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "[ClipBoard=" wide
		$ = "[NUMPAD .]" wide
		$ = "[SPACE]" wide
		$ = "GetClipboardData"

	condition:
		uint16be( 0 ) == 0x4d5a and filesize < 350KB and all of them
}

rule SEKOIA_Apt_Badmagic_Generic_Pshscript : FILE
{
	meta:
		description = "Detects BadMagic generic powershell script (Possible FPs)"
		author = "Sekoia.io"
		id = "82cda554-3c2b-4c04-b9f9-b5ba50c53271"
		date = "2023-05-15"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_badmagic_generic_pshscript.yar#L1-L16"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "f442e1ba815cc7eae0c627db5ad1917021d69b8ce37155923a0f19776aeba95d"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "$ExecutablePath"
		$ = "Start-Sleep -Second 2"

	condition:
		all of them and filesize < 1KB
}


rule SEKOIA_Apt_Darkpink_Kamikakabot_Strings
{
	meta:
		description = "Detects KamiKakaBot strings (.NET sample of Dark Pink)"
		author = "Sekoia.io"
		id = "0f5a7d72-81c8-4fdd-aefd-136bc6d48aa5"
		date = "2023-02-22"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_darkpink_kamikakabot_strings.yar#L1-L30"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "0bc37c96b591d8edb1fd288ef874b3cc31879ce166b8734a3dd0e29644cbea55"
		score = 75
		quality = 80
		tags = ""
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "Execute"
		$ = "f4869"
		$ = "getIndentifyName"
		$ = "getMessageAsync"
		$ = "requestMessageID"
		$ = "run_command"
		$ = "sendFile"
		$ = "sendMessage"
		$ = "send_brw_data"
		$ = "updateMessageID"
		$ = "update_new_token"
		$ = "update_new_xml"
		$ = {53 00 74 00 61 00 72 00 74 00 65 00 64 00 20 00 75 00 70 00 20 00 72 00 75 00 6e}
		$ = {20 00 72 00 65 00 63 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 65 00 64 00 21}
		$ = {6e 00 65 00 77 00 20 00 63 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 65 00 64 00 21}
		$ = {74 00 6f 00 6b 00 65 00 6e 00 20 00 75 00 70 00 64 00 61 00 74 00 65 00 20 00 73 00 75 00 63 00 63 00 65 00 73 00 73 00 21 00 21 00 21}

	condition:
		6 of them
}

rule SEKOIA_Apt_Unk_Batcopier_Strings : FILE
{
	meta:
		description = "Detects BatCopier variant"
		author = "Sekoia.io"
		id = "eb76bbd0-a722-4fec-a4a7-c48c70a1880b"
		date = "2024-09-06"
		modified = "2024-12-19"
		reference = "https://www.seqrite.com/blog/operation-oxidovy-sophisticated-malware-campaign-targets-czech-officials-using-nato-themed-decoys/"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_unk_batcopier_strings.yar#L1-L18"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "0007d6d00d5b8db048456bb566ef9ed4516c4e1b392cc73c40396785ba885f55"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "@echo off"
		$ = "echo F|xcopy"
		$ = "attrib +r +s +h"

	condition:
		all of them and filesize < 1KB
}

rule SEKOIA_Apt_Flightnight_Malicious_Lnk : FILE
{
	meta:
		description = "Detects malicious LNK used by FlightNight"
		author = "Sekoia.io"
		id = "06f33ece-ac9f-4dd3-98fb-cd69305ee995"
		date = "2024-04-02"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_flightnight_malicious_lnk.yar#L1-L21"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "3446852709fe425b2c053ffdb9c078cf20e442ef50fe20402d3b4c9e9d8b543a"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s0 = "/c start /B " wide
		$s1 = ".exe &" wide
		$s2 = ".pdf" wide
		$s3 = "%CD%" wide

	condition:
		uint32be( 0 ) == 0x4c000000 and $s1 in ( @s0 .. @s2 ) and $s1 in ( @s0 .. @s0 + 100 ) and $s3
}

rule SEKOIA_Apt_Implant_Xdealer_Vbs_Launcher_Strings : FILE
{
	meta:
		description = "Detects XDealer VBS Launcher"
		author = "Sekoia.io"
		id = "ebfc8a33-70dc-44d5-bc4a-07afc56f8254"
		date = "2024-03-22"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_implant_xdealer_vbs_launcher_strings.yar#L1-L17"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "e206189fd21ed7b3bf48a51d955df9055b7f7aa502b7fac52b274cc414adea0d"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = "Dim objws"
		$s2 = "Set objws="
		$s3 = "objws.Run \"\"\"C:\\ProgramData\\"

	condition:
		$s1 at 0 and all of them and filesize < 200
}

rule SEKOIA_Apt_Gamaredon_Lnks_Farl139_Hostname : FILE
{
	meta:
		description = "Detects some hostname used in Gamaredon LNKs"
		author = "Sekoia.io"
		id = "f8bb2e6b-e544-46b0-b61b-048fe84e1100"
		date = "2023-01-20"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_gamaredon_lnks_farl139_hostname.yar#L1-L17"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "8be31a4fed363f0e2791efb96a229f6cdec5bfaeaf3e9cd880f8d25c9ae0435e"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "desktop-farl139"

	condition:
		uint32be( 0 ) == 0x4c000000 and all of them and filesize < 10KB
}

rule SEKOIA_Apt_Turla_Kazuar_Variant_2023 : FILE
{
	meta:
		description = "New variant of Kazuar observed in 2023"
		author = "Sekoia.io"
		id = "51e9de6a-5d8a-4627-8063-b70f78e78726"
		date = "2023-11-03"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_turla_kazuar_variant_2023.yar#L1-L17"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "98207fef906c922ff09f72b0dea7103c0fb86c5ec4712a23ecba6840b79b0ad5"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = "Started from file '" ascii wide
		$s2 = "Zombifying user's" ascii wide
		$s3 = "Result #{0:X16} already exists in {1}" ascii wide

	condition:
		uint16( 0 ) == 0x5a4d and 2 of them
}

rule SEKOIA_Apt_Apt41_Powershell_Collection_Script : FILE
{
	meta:
		description = "Detects PowerShell collection script"
		author = "Sekoia.io"
		id = "55b6cc3e-24b2-4faa-a7fb-b4203a8e6d83"
		date = "2023-11-15"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_apt41_powershell_collection_script.yar#L1-L19"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "8b0462636c9f6270baff2bf09638e94db6d5a0472b8216ddd1919a77b6a63aca"
		score = 75
		quality = 70
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "$yestoday.ToString(" ascii wide nocase
		$ = "$m.LastAccessTime -" ascii wide nocase
		$ = "$fmat=" ascii wide nocase
		$ = "$computername" ascii wide nocase
		$ = "Rar.exe" ascii wide nocase

	condition:
		filesize < 10KB and all of them
}


rule SEKOIA_Apt_Darkpink_Loader_Decryptionroutine : FILE
{
	meta:
		description = "Detects decryption routine of dark pink loader"
		author = "Sekoia.io"
		id = "fefc7b2f-eecc-49dc-84bc-24c45e9ea8f0"
		date = "2023-01-17"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_darkpink_loader_decryptionroutine.yar#L4-L49"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "fe2726b77c293fc2aa19216025cfa2b4cd0c5194730cbc57a1fcceb6f6198977"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"
		hashs = "3f38860d0f6f0ff1b65219379f8793383cba85b11de1c853192fb2d2ba99e481"
		hashs = "b3f1d6366ebc184f634a240c838b39d729c28b8718b0b9ca6be988a7e446ec42"

	strings:
		$chunk_1 = {
        8A 08
        40
        84 C9
        75 ??
        6A 00
        2B C2
        50
        53
        56
        E8 ?? ?? ?? ??
        8A 88 ?? ?? ?? ??
        30 0C 3E
        83 C6 01
        83 D3 00
        78 ??
        7F ??
        81 FE ?? ?? ?? ??
        72 ??
        55
        }

	condition:
		( uint32be( 0 ) == 0x7f454c46 or uint16be( 0 ) == 0x4d5a ) and filesize < 3MB and ( all of them or hash.md5 ( pe.rich_signature.clear_data ) == "950c0710dc4cbf6e2cd6b857d25da523" or for any i in ( 0 .. pe.number_of_sections -1 ) : ( hash.md5 ( pe.sections [ i ] . raw_data_offset , pe.sections [ i ] . raw_data_size ) == "547e43dd8560fa8b0ca0be9f633bf62d" ) )
}

rule SEKOIA_Apt_Apt35_Iisraid_Strings : FILE
{
	meta:
		description = "Detects APT35s ISSRaid implant"
		author = "Sekoia.io"
		id = "ee42f406-0c7e-4385-9098-409611dbe0a5"
		date = "2023-05-11"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_apt35_iisraid_strings.yar#L1-L19"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "de2ebef5ab46136aa54b146dbd4198f69801f3414d1d239fc7983c5b3c0115c4"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "CHttpModule::"
		$ = "X-Forward-Verify"
		$ = "X-Beserver-Verify"

	condition:
		uint16be( 0 ) == 0x4d5a and filesize < 500KB and all of them
}


rule SEKOIA_Apt_Spikedwine_Wineloader : FILE
{
	meta:
		description = "Detects vineloader"
		author = "Sekoia.io"
		id = "7a599076-cd9d-42c4-a83a-9a991ede19fb"
		date = "2024-02-29"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_spikedwine_wineloader.yar#L3-L26"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "c71d7ef8cb89d8fcd42e3178a729d912d5fe8e9eb396e46d7a0f5176a9398d75"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$c = { E8 ?? ?? ?? ?? 48 8D 0D
        ?? ?? ?? ?? 48 8D 05 ??
        ?? ?? ?? 48 89 05 ?? ??
        ?? ?? 48 C7 05 ?? ?? ??
        ?? ?? ?? 00 00 48 C7 05
        ?? ?? ?? ?? ?? ?? 00 00 }

	condition:
		pe.is_dll( ) and filesize < 100KB and for any export in pe.export_details : ( $c in ( export.offset..export.offset + 100 ) )
}

rule SEKOIA_Apt_Mustangpanda_Windows_Remoteshell : FILE
{
	meta:
		description = "Detects Remote Shell of Mustang Panda by detecting internal structure intialization"
		author = "Sekoia.io"
		id = "cffdd11e-9700-462e-a965-f9f51db63f0b"
		date = "2022-12-06"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_mustangpanda_windows_remoteshell.yar#L1-L121"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "4a72ae1574022d6454e29a6b05a0279f2e774f8218d24a3a866721d958c52e1a"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$chunk_1 = {
        C7 45 ?? 0C 00 00 00
        8D 4E ??
        C6 01 03
        8B 87 ?? ?? ?? ??
        89 41 ??
        66 8B 87 ?? ?? ?? ??
        66 89 41 ??
        }
		$chunk_2 = {
        C7 45 ?? 0C 00 00 00
        8D 4E ??
        C6 01 02
        8B 87 ?? ?? ?? ??
        89 41 ??
        66 8B 87 ?? ?? ?? ??
        66 89 41 ??
        8B 45 ??
        83 E8 05
        50
        51
        E8 ?? ?? ?? ??
        }
		$chunk_3 = {
        C7 87 ?? ?? ?? ?? 01 00 00 00
        8D 4E ??
        C7 45 ?? 0C 00 00 00
        C6 01 04
        8B 87 ?? ?? ?? ??
        89 41 ??
        66 8B 87 ?? ?? ?? ??
        66 89 41 ??
        8B 45 ??
        83 E8 05
        50
        51
        E8 ?? ?? ?? ??
        }
		$chunk_4 = {
        83 65 ?? ??
        EB ??
        8B 45 ??
        40
        89 45 ??
        8B 45 ??
        3B 45 ??
        7D ??
        8B 45 ??
        03 45 ??
        0F B6 08
        8B 45 ??
        33 D2
        6A ??
        5E
        F7 F6
        0F B6 84 15 ?? ?? ?? ??
        33 C8
        8B 45 ??
        03 45 ??
        88 08
        EB ??
        83 65 ?? ??
        EB ??
        8B 45 ??
        40
        89 45 ??
        8B 45 ??
        }

	condition:
		filesize < 8MB and 3 of them
}

rule SEKOIA_Apt_Stripedfly : FILE
{
	meta:
		description = "Detects string relative to Stripedfly malware"
		author = "Sekoia.io"
		id = "81968d34-3247-4965-ba44-55747370c90e"
		date = "2023-11-30"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_stripedfly.yar#L1-L17"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "ded64ae30cf994162d4af649a34eadd4b8619cbced4392a6684129f8cf906136"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = "{\"id\":%d,\"jsonrpc\":\"2.0\",\"method\":\"%s\",\"params\":%s}"
		$s2 = "{\"login\":\"%s\",\"pass\":\"%s\",\"agent\":\"\"}"
		$s3 = "(tcp|ssl)://([A-Za-z0-9\\.\\-]+):([0-9]+)"

	condition:
		filesize < 3MB and 2 of them
}

rule SEKOIA_Apt_Badmagic_Ld_Dll_Loader_Pshscript : FILE
{
	meta:
		description = "Detects BadMagic DLL Loader powershell script"
		author = "Sekoia.io"
		id = "d4a23afc-693f-4fab-b2c4-15eecba047f7"
		date = "2023-05-15"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_badmagic_ld_dll_loader_pshscript.yar#L1-L18"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "8482521fe1f90c008948e551df35448b870145cf8b58f3c5019cafb66bb0ae36"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "$ModulePath = \"$folder_path\\$name"
		$ = "$ModuleExport ="
		$ = "start-job -ScriptBlock $ScriptBlock"
		$ = "Invoke-WebRequest -Uri"

	condition:
		all of them and filesize < 1KB
}

rule SEKOIA_Apt_Susp_Lazarus_Dangerous_Password : FILE
{
	meta:
		description = "No description has been set in the source file - SEKOIA"
		author = "Sekoia.io"
		id = "726c8b92-7fbe-40f8-917a-cabd206028da"
		date = "2023-09-12"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_susp_lazarus_dangerous_password.yar#L1-L15"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "2b159266bd6bba20ffaa627dac840840eaaad98e7962f48bbae428e687155b3d"
		score = 65
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = ".jpeg" wide
		$ = "mshta"

	condition:
		uint32be( 0 ) == 0x4c000000 and all of them and filesize < 5KB
}

rule SEKOIA_Apt_Implant_Xdealer_Stealer_Strings : FILE
{
	meta:
		description = "Detects stealer module of XDealer"
		author = "Sekoia.io"
		id = "6314cf6c-2c3b-4e9a-87a1-b56ee148474c"
		date = "2024-03-22"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_implant_xdealer_stealer_strings.yar#L1-L20"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "79ba2fd14cd2eb73848026f79ce6115df813e0fda3a071ab26659874e04e2201"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "%sbmp.tmp"
		$ = "%sjgp.tmp"
		$ = "%sma_%s_%05u_%u."
		$ = "%s%s_%05u_%u."

	condition:
		uint16be( 0 ) == 0x4d5a and filesize < 500KB and all of them
}

rule SEKOIA_Apt_Polonium_Powershell_Creepydrive_Strings
{
	meta:
		description = "Detects POLONIUM CreepyDrive Powershell implant"
		author = "Sekoia.io"
		id = "0ba196bd-9cd6-4553-b7bf-69989cdb8be4"
		date = "2022-06-03"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_polonium_powershell_creepydrive_strings.yar#L1-L24"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "28b8f10a36d13e97e606b082f20c50c3d48241409e7f1aca621e2af9d756dbe5"
		score = 75
		quality = 80
		tags = ""
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "function Exec($comm)" base64 ascii wide
		$ = "$comm = $comm + \"| outstring" base64 ascii wide
		$ = "Invoke-Expression -Command:$comm" base64 ascii wide
		$ = "microsoft.com" base64 ascii wide
		$ = "$req = Invoke-WebRequest" base64 ascii wide
		$ = "$j += $data" base64 ascii wide
		$ = "$res = Exec($arr[$i])" base64 ascii wide
		$ = "$arr = @(iex \"$req\")" base64 ascii wide
		$ = "elseif ($req -cmatch" base64 ascii wide
		$ = "graph.microsoft.com" base64 ascii wide

	condition:
		3 of them
}

rule SEKOIA_Apt_Ir_Sugarush_Implant : FILE
{
	meta:
		description = "Detects the SUGARUSH implant"
		author = "Sekoia.io"
		id = "bcf057cc-272c-4cb6-bb76-928788675282"
		date = "2022-08-23"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_ir_sugarush_implant.yar#L1-L21"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "0d249552013c29ce1eb66dca2d93e5cde0a1b0fb80aae55469bec3bda224be91"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "You are offline at " wide
		$ = "\\Logs\\ServiceLog_" wide
		$ = "Service is recall at" wide
		$ = "add_OutputDataReceived" ascii
		$ = "get_CurrentDomain" ascii

	condition:
		uint16be( 0 ) == 0x4d5a and filesize < 100KB and all of them
}

rule SEKOIA_Apt_Sandworm_Orcshred_Apr2022 : FILE
{
	meta:
		description = "Detects the ORCSHRED script"
		author = "Sekoia.io"
		id = "1a88800c-29e1-4e2c-8374-f5a93dd9fd91"
		date = "2022-04-12"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_sandworm_orcshred_apr2022.yar#L1-L18"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "de38cf43fa5cc756c26ae241f2e60636c2aabbe4254fdeca2340c62873498de7"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "find /etc -name os-release >"
		$ = "/bin/bash /var/"
		$ = "crontab -l >"
		$ = ".sh & disown"

	condition:
		3 of them and filesize < 2KB
}

rule SEKOIA_Apt_Redhotel_Maliciouslnk_Strings : FILE
{
	meta:
		description = "Detects RedHotel's malicious LNKs"
		author = "Sekoia.io"
		id = "df2f0002-7921-4378-a936-ea0de5fbfa5a"
		date = "2024-09-06"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_redhotel_maliciouslnk_strings.yar#L1-L25"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		hash = "8e2c17040ec78cbcdc07bb2cf9dd7e01"
		hash = "dc613a519e515ca817fdfb88f81fc9d7"
		hash = "6f7d85c196c277a6a619f6d94b8f69b9"
		hash = "b04d484d1e1d793b04af2a5fb88a8a57"
		logic_hash = "c1d64b3eca5961d7eaab82a6934299642a70301ef791493a371ae5a29376225f"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "desktop-" ascii
		$ = ".\\1.docx" wide
		$ = ".\\1.pdf" wide
		$ = ".\\1.doc" wide
		$ = ".\\1.ppt" wide
		$ = ".\\1.pptx" wide
		$ = "MACOS" wide

	condition:
		uint32be( 0 ) == 0x4c000000 and 3 of them
}

rule SEKOIA_Apt_Nobelium_Acrobox_Downloader_Apr2022 : FILE
{
	meta:
		description = "Detects AcroBox downloader"
		author = "Sekoia.io"
		id = "77f7f01d-72a2-4b13-b23f-d938a415dd40"
		date = "2022-05-11"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_nobelium_acrobox_downloader_apr2022.yar#L1-L24"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "ebcbdf13908971eea3e5b291719527e2e454a9ee3b98b5dc66149b2bb3b8fe67"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = { 80 ?? 7B
        0F 84 ?? ?? 00 00
        80 ?? ?? 0F
        0F 84 ?? ?? 00 00
        80 ?? ?? 0F
        0F 84 ?? ?? 00 00
        80 ?? ?? 0F
        0F 84 ?? ?? 00 00 }

	condition:
		uint16be( 0 ) == 0x4d5a and filesize < 200KB and all of ( $s* )
}

rule SEKOIA_Apt_Tealkurma_Snappytcp_Strings : FILE
{
	meta:
		description = "Detects TealKurma SnappyTCP shell script"
		author = "Sekoia.io"
		id = "6bbee6d6-f490-4550-bd61-a643f93a8788"
		date = "2023-12-08"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_tealkurma_snappytcp_strings.yar#L1-L18"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "b91adef3332850d952cace104fc05e1b09e6175a27ae991905defc46de608e88"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = "#!/bin/bash" ascii
		$s2 = "2>&1>/dev/null&" ascii
		$s3 = "PATH=$PATH:$PWD;" ascii

	condition:
		$s1 at 0 and $s2 at filesize -16 and $s3 and filesize < 300
}

rule SEKOIA_Apt_Apt29_Wineloader_Malicious_Pdf : FILE
{
	meta:
		description = "Detects malicious PDF used by APT29 to drop Wineloader"
		author = "Sekoia.io"
		id = "b1db731e-471e-493a-b76c-38d2808ccac9"
		date = "2024-03-25"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_apt29_wineloader_malicious_pdf.yar#L1-L21"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		hash = "9712217ff3597468b48cdf45da588005de3a725ba554789bb7e5ae1b0f7c02a7"
		hash = "3739b2eae11c8367b576869b68d502b97676fb68d18cc0045f661fbe354afcb9"
		logic_hash = "784f5ab2602e2185e8253b5b8d9a084ede0604457b0a0674fceffbcb226e3ba1"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = "<</Type/Annot/Subtype/Link/Border[0 0 0]/Rect["
		$s2 = "/A<</Type/Action/S/URI/URI("
		$s3 = { 2f [2-10] 2e 70 68 70 29 3e 3e }
		$s4 = "JamrulNormal"

	condition:
		uint32be( 0 ) == 0x25504446 and $s2 in ( @s1 .. @s3 ) and $s4
}

rule SEKOIA_Apt_Scanbox_Framework_Not_Obfuscated : FILE
{
	meta:
		description = "Detects the non obfuscated version of ScanBox"
		author = "Sekoia.io"
		id = "4790f122-89de-4f7b-a25f-9ac7b1af8333"
		date = "2022-09-01"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_scanbox_framework_not_obfuscated.yar#L1-L23"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "52779571eb4e68442542a1c4cff58d5b00a264bb567396126cd93dc4ec4eda45"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "php?m=a&data="
		$ = "php?m=p&data="
		$ = ".fun.split_data = function"
		$ = ".php?data="
		$ = ".php?m=b"
		$ = "basic.apipath"
		$ = ".info.seed ="
		$ = "loadjs ="
		$ = "info.color = screen.colorDepth"

	condition:
		5 of them and filesize < 500KB
}

rule SEKOIA_Apt_Gamaredon_Gammaload_Malicioushta : FILE
{
	meta:
		description = "Detects Gamaredon's GammaLoad HTA"
		author = "Sekoia.io"
		id = "e5e502db-7f37-40f2-9ba3-81e158e767db"
		date = "2022-08-01"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_gamaredon_gammaload_malicioushta.yar#L1-L21"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "e41ce63e7c6df2edb548ddc57d51af914dab9200e37eb12463169d587205aa7a"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = "platform = window.navigator?.userAgentData?.platform" ascii fullword
		$s2 = "'Win32', 'Win64', 'Windows', 'WinCE'" ascii
		$s3 = "dcreate.download ="
		$s4 = "dcreate.href = 'data:application/x-rar-compressed;base64"
		$s5 = "= \"UmFyI"

	condition:
		uint32be( 0 ) == 0x3c68746d and filesize < 400KB and filesize > 50KB and 4 of them
}

rule SEKOIA_Apt_Unk_Dex_China_Freedom_Trap_Spyware : FILE
{
	meta:
		description = "Detects China Freedom Trap spyware dex file"
		author = "Sekoia.io"
		id = "3d66b6b8-8397-441a-a337-4a282df39591"
		date = "2022-09-07"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_unk_dex_china_freedom_trap_spyware.yar#L1-L31"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		hash = "ceb70fce74898ea64ded6880a978441c"
		logic_hash = "f85f78a1a58fa8b2698637f8c540877ea1c5141ff7f74e8c2f2755f5aba5a599"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "INSTALL" base64
		$ = "FAILED" base64
		$ = "TEST" base64
		$ = "ONLY" base64
		$ = "INSTALL" base64
		$ = "INCONSISTENT" base64
		$ = "CERTIFICATES" base64
		$ = "Network country iso:" base64
		$ = "Network operator name:" base64
		$ = "SIM operator name:" base64
		$ = "SIM country iso:" base64
		$ = "SIM state:" base64
		$ = "PIN REQUIRED" base64
		$ = "PUK REQUIRED" base64

	condition:
		uint32be( 0 ) == 0x6465780A and filesize < 100KB and 4 of them
}

rule SEKOIA_Apt_Muddywater_Powgoop_Decode_Loop : FILE
{
	meta:
		description = "Detects the loop used in PowGoop and its loader"
		author = "Sekoia.io"
		id = "644ed1c4-e0e1-496e-9efc-7d9e15565f7b"
		date = "2022-01-13"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_muddywater_powgoop_decode_loop.yar#L1-L19"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "1d60f53014fb1934a85a573856244431c8f565c2f024511991817e6235566815"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = "System.Collections.Generic.List[System.Object]" ascii wide
		$s2 = "$d.Add($in[$i]);" ascii wide
		$s3 = "[System.Convert]::FromBase64String(" ascii wide

	condition:
		filesize < 1MB and $s2 in ( @s1 .. @s1 + 400 ) and $s3 in ( @s1 .. @s1 + 400 )
}

rule SEKOIA_Apt_Apt41_Javascript_Dropper : FILE
{
	meta:
		description = "Detects Earth Lusca JS dropper"
		author = "Sekoia.io"
		id = "fde70806-af50-4706-9daf-d39ad0564fc7"
		date = "2024-02-26"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_apt41_javascript_dropper.yar#L1-L21"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "3e34af7141e41044c3d3e099e8b8deafc7441ea47ccbd8af7ffe686f10bb18a2"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = "eval(function(p, a, c, k, e, r) {"
		$s2 = "|4d53"
		$s3 = "ActiveXObject"
		$x1 = " -F:* %1%"
		$x2 = "&I /r c:\\"
		$x3 = "ActiveXObject"

	condition:
		filesize < 2MB and ( all of ( $s* ) or all of ( $x* ) )
}

rule SEKOIA_Apt_Agent_Racoon_Strings : FILE
{
	meta:
		description = "Detects Agent Racoon used by CL-STA-0002"
		author = "Sekoia.io"
		id = "ec89f1db-0ba8-48c8-8c1a-c38c410f3e39"
		date = "2023-12-05"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_agent_racoon_strings.yar#L1-L24"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "4e32606edffab0907e343ab2fef8642c0064d83c2933531619f9dee8957d2fe4"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "Command failed:" wide
		$ = "Not uploaded:" wide
		$ = "Not downloaded:" wide
		$ = "xn--cc" wide
		$ = "xn--ac" wide
		$ = "xn--bc" wide
		$ = "cmd.exe" wide
		$ = ".xn--" wide

	condition:
		uint16be( 0 ) == 0x4d5a and filesize < 1MB and all of them
}

rule SEKOIA_Apt_Kimsuky_Klogexe : FILE
{
	meta:
		description = "Detects KLogExe, a keylogger used by Kimsuky"
		author = "Sekoia.io"
		id = "f6e3b1a5-43b6-4dac-83c2-a365c41de38d"
		date = "2024-09-27"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_kimsuky_klogexe.yar#L1-L32"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		hash = "e1d683ee1746c08c5fff1c4c2b3b02f0"
		hash = "90946c6358eacd119fe1eb36ec7a0a18"
		hash = "9760f489a390665b5e7854429b550c83"
		logic_hash = "4b616908ceacd85c5d8b527cd1a718082c709071dc1fa9c9ccc96e71dc4e7449"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$event = "Norton_BreakHelper" ascii wide
		$log = "------ %d/%d/%d : %d/%d ------" ascii wide
		$keylog_1 = "[RM+]"
		$keylog_2 = "[Tab+]"
		$keylog_3 = "[Home+]"
		$keylog_4 = "[End+]"
		$keylog_5 = "[clip_s]: %s "
		$keylog_6 = "%s[Too many clip_tail]"
		$keylog_7 = "%s[F%d]"
		$user_agent = "Chrome/31.0." wide

	condition:
		uint16be( 0 ) == 0x4d5a and filesize < 600KB and 8 of them
}

rule SEKOIA_Apt_Cloudatlas_Powershower_Obfuscated : FILE
{
	meta:
		description = "Detects obfuscated version of PowerShower"
		author = "Sekoia.io"
		id = "f76ab9d8-7753-4a17-aedd-fc9c3b8cd322"
		date = "2022-11-29"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_cloudatlas_powershower_obfuscated.yar#L1-L18"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "fdb1edb3982eb5356cdf5fd1fa9fcc41d5048848b2a05589e87836ac0b05ec7a"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = "{0}{1}{2}{3}{4}{5}{6}{7}{8}" ascii wide
		$s2 = "{000}{001}{002}{003}{004}{005}{006}{007}{008}" ascii wide
		$s3 = "::Unicode.GetString([System.Convert]::FromBase64String(" ascii wide

	condition:
		($s1 in ( 0 .. 100 ) or $s2 in ( 0 .. 100 ) ) and $s3 in ( filesize -200 .. filesize )
}

rule SEKOIA_Apt_Coathanger_Beacon : FILE
{
	meta:
		description = "Detects COATHANGER beacon"
		author = "Sekoia.io"
		id = "cc201479-016a-46d2-a9e2-41b4914ce618"
		date = "2024-02-07"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_coathanger_beacon.yar#L1-L21"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "e44496e62de8c885d5bd941819a97f4c0dd90ce2d0cfe9d042ab9590cc354ddb"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = {
        48 B8 47 45 54 20 2F 20 48 54
        48 89 45 B0 48 B8 54 50 2F 32 0A 48 6F 73
        48 89 45 B8 48 B8 74 3A 20 77 77 77 2E 67
        48 89 45 C0 48 B8 6F 6F 67 6C 65 2E 63 6F
        }

	condition:
		uint32( 0 ) == 0x464c457f and filesize < 5MB and any of them
}

rule SEKOIA_Apt_Kimsuky_Powershell_Dropper_Strings : FILE
{
	meta:
		description = "Detects a PowerShell dropper used by Kimsuky"
		author = "Sekoia.io"
		id = "8b346e05-215b-46c0-82bf-fce3a65440f3"
		date = "2024-06-11"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_kimsuky_powershell_dropper_strings.yar#L1-L21"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "e98f23ddf02049126786e9300e7b6661b2a74817b36e2f3a661b07b24ef4402d"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = "try { " ascii wide
		$s2 = "); } catch(e){} } if ("
		$s3 = "WScript.Sleep("
		$s4 = " } catch(e) { }"

	condition:
		filesize > 500KB and $s1 at 0 and $s2 in ( filesize -1000 .. filesize ) and $s3 in ( filesize -1000 .. filesize ) and $s4 in ( filesize -1000 .. filesize )
}

rule SEKOIA_Apt_Unk_Hrserv_Memory_Commands_Strings
{
	meta:
		description = "Detects HrServ web shell memory commands"
		author = "Sekoia.io"
		id = "1b5f442a-e758-4bd5-a612-8b504a542d29"
		date = "2023-11-23"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_unk_hrserv_memory_commands_strings.yar#L1-L19"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "a87c35658ded301c098f9ee8ee5886a54e89537eabd145cf82b0286c703a77d2"
		score = 75
		quality = 80
		tags = ""
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "list all the process" ascii wide
		$ = "equal with cmd /c tasklist" ascii wide
		$ = "start target service by name" ascii wide
		$ = "query local process information by wmi." ascii wide
		$ = "upload local shellcode to" ascii wide

	condition:
		all of them
}

rule SEKOIA_Apt_Polonium_Technocreep_Strings : FILE
{
	meta:
		description = "Tries to detect TechnoCreep implant"
		author = "Sekoia.io"
		id = "dad79df3-b081-458e-9c14-1d5e2b43ba91"
		date = "2022-10-12"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_polonium_technocreep_strings.yar#L1-L27"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "6fbd14d39f215b835c0fe7709041ca982774be42d389397d19a41fda6f7a00d1"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.1"
		classification = "TLP:CLEAR"

	strings:
		$ = "file name : " ascii wide
		$ = "copy to : " ascii wide
		$ = "download" ascii wide
		$ = "persistence" ascii wide
		$ = "/cmdResult created!" ascii wide
		$ = "/downloadsResulat created!" ascii wide
		$ = "Downloading will take minets..." ascii wide
		$ = "powershell -Command \"$c1 = " ascii wide
		$ = "Missing Parameter.. Format of command:" ascii wide
		$ = "File Fath On Target Device Not Exists>" ascii wide
		$ = "/MissingDownloadParameter.txt" ascii wide

	condition:
		uint16be( 0 ) == 0x4d5a and filesize < 1MB and 4 of them
}

rule SEKOIA_Apt_Badmagic_Listfiles_Pshscript : FILE
{
	meta:
		description = "Detects BadMagic ListFiles powershell script"
		author = "Sekoia.io"
		id = "55f1c409-234e-4feb-91a3-9bf5c41ec2b8"
		date = "2023-05-15"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_badmagic_listfiles_pshscript.yar#L1-L16"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "4401d31e4b0484776aab51c161a301fc4ee3e944a1669df763bd274014178368"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "$env:USERPROFILE"
		$ = "-Include *.jpg, *.odt, *.doc, *.docx"

	condition:
		all of them and filesize < 1KB
}

rule SEKOIA_Apt_Oilrig_Maliciousdocument_May2022 : FILE
{
	meta:
		description = "Detects OilRig Malicious Document"
		author = "Sekoia.io"
		id = "cb4ab310-e24c-4edc-8804-0c49c30124fb"
		date = "2022-05-13"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_oilrig_maliciousdocument_may2022.yar#L1-L22"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "d4aa960d4471ddf66ec6f98a5c883177763771ba9960b749509311a05384d9a7"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = "<LogonType>InteractiveToken</LogonType>"
		$s2 = "Select * From Win32_PingStatus Where Address"
		$s3 = "She@et1"
		$s4 = "_VBA_PROJECT" wide
		$s5 = "This program cannot be run in DOS mode." base64
		$s6 = ".Agent.pdb" base64
		$s7 = "GetAgentID" base64

	condition:
		uint32be( 0 ) == 0xD0CF11E0 and 3 of them
}

rule SEKOIA_Apt_Cloudatlas_Init_Module_Virtualalloc : FILE
{
	meta:
		description = "Find init module of CloudAtlas with params passed to VirtualAlloc"
		author = "Sekoia.io"
		id = "299ed681-9d1f-4b47-8389-ff5a608f49d4"
		date = "2023-09-19"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_cloudatlas_init_module_virtualalloc.yar#L1-L25"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "31ffaeccc0b8fe36eea3b3a8200eff6a420b1a3937fd439dc84121654fcea502"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"
		hash1 = "02a1a9582f5ccf421b08c41c35049416b9cdefc9228daf6b38d95e9b0930cc5a"
		hash2 = "c7f19c7c295c86867ea7fa4597ba0cebe12f751753866e7298fd5d84676facc3"

	strings:
		$chunk_1 = {
        6A 40
        68 00 30 10 00
        8B 8D ?? ?? ?? ??
        8B 51 50
        52
        6A 00
        FF 15 ?? ?? ?? ??
        }

	condition:
		( uint32be( 0 ) == 0x7f454c46 or uint16be( 0 ) == 0x4d5a ) and $chunk_1 and filesize < 3MB
}

rule SEKOIA_Apt_Apt29_Wineloader_Malicious_Hta
{
	meta:
		description = "Detects malicious HTA used by APT29 to drop Wineloader"
		author = "Sekoia.io"
		id = "5a17d854-0564-4830-a0e5-7867b99716c2"
		date = "2024-03-25"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_apt29_wineloader_malicious_hta.yar#L1-L18"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		hash = "efafcd00b9157b4146506bd381326f39"
		logic_hash = "0cc4692e5ff3f258c287f28030147f725d6a534c4f2f7a2a4ff49a305b7fd13d"
		score = 75
		quality = 80
		tags = ""
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "<HTA:APPLICATION ID="
		$ = "var _0x"
		$ = "Date['\\x6e\\x6f\\x77']"

	condition:
		all of them
}


rule SEKOIA_Apt_Unc4990_Explorer_Ps1
{
	meta:
		description = "Detects powershell script (explorer.ps1)"
		author = "Sekoia.io"
		id = "2e1abbbf-f9b7-4147-b7da-3544cbc4a5f1"
		date = "2024-02-01"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_unc4990_explorer_ps1.yar#L1-L19"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "5085f738e23b801c7e36408d189755086d91c0bb266af6738c80510eb85e598f"
		score = 75
		quality = 80
		tags = ""
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s0 = "$(get-location).Path"
		$s1 = "+ \"\\Runtime Broker.exe"
		$s2 = "Start-Process -FilePath"
		$s3 = "-Wait;"
		$s4 = "Start-Sleep -s"

	condition:
		all of them and @s3- @s2 < 35
}

rule SEKOIA_Apt_Muddywater_Powershell_Reverse_Secure_Proxy
{
	meta:
		description = "Detects PowerShell Reverse Secure Proxy"
		author = "Sekoia.io"
		id = "b255f327-cb56-41b7-82f7-83ee23f791a5"
		date = "2023-11-14"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_muddywater_powershell_reverse_secure_proxy.yar#L1-L17"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "6507bc030d60af5559492bbb02bc619646306ab06c9bd9d3f78ae6ce55307bda"
		score = 75
		quality = 80
		tags = ""
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "$CS.Read($buff,4,2) | Out-Null" ascii wide
		$ = "$DP = $buff[2]*256 + $buff[3]" ascii wide
		$ = "$PS3.BeginInvoke() | Out-Null" ascii wide

	condition:
		all of them
}

rule SEKOIA_Apt_Gamaredon_Flash_Infostealer : FILE
{
	meta:
		description = "Detects the Gamaredon's Flash InfoStealer"
		author = "Sekoia.io"
		id = "f060fe4b-74fd-4ef3-ac86-916e2113ff24"
		date = "2023-01-24"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_gamaredon_flash_infostealer.yar#L1-L21"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "5a3ee8c2c3c377bea7de1993e5ef744796130643575bcce1b6181d68190aafb7"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$a1 = "Content-Type: multipart/form-data; boundary=----%s" ascii
		$a2 = "Content-Disposition: form-data; name=\"p\"" ascii
		$a3 = "Content-Type: application/octet-stream"
		$w1 = "%s||%s||%s||%s" wide
		$w2 = "Pragma: no-cache" wide
		$w3 = { 64 00 6F 00 63 00 00 00 00 00 2E 00 64 00 6F 00 63 00 78 00 }

	condition:
		uint16be( 0 ) == 0x4d5a and filesize < 500KB and 2 of ( $a* ) and 2 of ( $w* )
}

rule SEKOIA_Apt_Mustangpanda_Tinynote : FILE
{
	meta:
		description = "Detects strings in TinyNote backdoor"
		author = "Sekoia.io"
		id = "a2b9bea4-a211-456f-8a3f-0f31733e8b29"
		date = "2023-06-07"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_mustangpanda_tinynote.yar#L1-L21"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "20723b449d057ddf09fa34aa7511275939f98c6c84593af64d99f980c679b2c1"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = "bypassSMADAV" ascii fullword
		$s2 = "excuteCmdLine" ascii fullword
		$s3 = "/Create1953125" ascii
		$s4 = "MINUTEMonday" ascii
		$s5 = "WndProc" ascii

	condition:
		( uint32be( 0 ) == 0x7f454c46 or uint16be( 0 ) == 0x4d5a ) and filesize < 8MB and all of them
}

rule SEKOIA_Apt_Kimsuky_Sharpext_Compromised_Securepreferences
{
	meta:
		description = "Detects compromised Chrome SecurePreferences file"
		author = "Sekoia.io"
		id = "aeda5d15-82e1-4ffc-8252-1eb4fc78d024"
		date = "2022-07-29"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_kimsuky_sharpext_compromised_securepreferences.yar#L1-L17"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "662358fdb4c4cfa9984d06e391ade52e1c7a3d7b78724aea4fb0d6035fe2e7b2"
		score = 75
		quality = 80
		tags = ""
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "\"devtools\", \"tabs\", \"webNavigation\", \"webRequest\", \"webRequestBlocking\""
		$ = "AppData\\\\Roaming"
		$ = "https://*/*"

	condition:
		all of them
}

rule SEKOIA_Apt_Badmagic_Startrevsocks_Pshscript : FILE
{
	meta:
		description = "Detects BadMagic DLL Loader powershell script"
		author = "Sekoia.io"
		id = "a6c96aee-9e78-47d2-afe3-f3c5246a9370"
		date = "2023-05-15"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_badmagic_startrevsocks_pshscript.yar#L1-L17"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "6a4615afb836330634cde9559dacfff50daef44a370f6191c6771a2066074a31"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "$ExecutablePath"
		$ = "Start-Sleep -Second 2"
		$ = "recn -15 -rect 15"

	condition:
		all of them and filesize < 1KB
}

rule SEKOIA_Apt_Muddywater_Rotrot_Strings : FILE
{
	meta:
		description = "Detects RotRot backdoor based on strings"
		author = "Sekoia.io"
		id = "f7bc195a-0e60-4495-b78a-78f101543700"
		date = "2024-06-10"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_muddywater_rotrot_strings.yar#L1-L36"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "425168003d0f14d791e7f46bf47c18652a1f6b66b9329155d2bca72cf0d8126b"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = "qsphsbnebub"
		$s2 = "rtqitcofcvc"
		$s3 = "surjudpgdwd"
		$s4 = "tvskveqhexe"
		$s5 = "uwtlwfrifyf"
		$s6 = "vxumxgsjgzg"
		$t1 = "MpbeMjcsbs"
		$t2 = "NqcfNkdtct"
		$t3 = "OrdgOleudu"
		$t4 = "PsehPmfvev"
		$t5 = "QtfiQngwfw"
		$t6 = "RugjRohxgx"
		$u1 = "UfsnjobufKpcPckfdu"
		$u2 = "VgtokpcvgLqdQdlgev"
		$u3 = "WhuplqdwhMreRemhfw"
		$u4 = "XivqmrexiNsfSfnigx"
		$u5 = "YjwrnsfyjOtgTgojhy"
		$u6 = "ZkxsotgzkPuhUhpkiz"

	condition:
		uint16be( 0 ) == 0x4d5a and filesize > 100KB and filesize < 300KB and any of ( $s* ) and any of ( $t* ) and any of ( $u* )
}

rule SEKOIA_Apt_Luckymouse_Rshell_Strings_All_Platform : FILE
{
	meta:
		description = "Detects LuckyMouse RShell Mach-O implant"
		author = "Sekoia.io"
		id = "e79a5ee1-96b3-4643-ab11-0b1095e96488"
		date = "2022-08-05"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_luckymouse_rshell_strings_all_platform.yar#L1-L20"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "ef923b6633a2b7dfa645a31c7c2d0e00872ebad6ec7748568c2b306c29b6b29b"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = { 6C 6F 67 69 6E 00 68 6F
        73 74 6E 61 6D 65 00 6C
        61 6E 00 75 73 65 72 6E
        61 6D 65 00 76 65 72 73
        69 6F 6E }

	condition:
		filesize < 1MB and all of them
}


rule SEKOIA_Apt_Gamaredon_Ddrdoh_Vbs_Downloader : FILE
{
	meta:
		description = "Detects the core of the VBS Gamaredon's Telegram Downloader"
		author = "Sekoia.io"
		id = "c934b95d-d81d-4f58-a752-1bb31ba8593d"
		date = "2023-01-25"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_gamaredon_ddrdoh_vbs_downloader.yar#L1-L26"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "940635313b23e29ac98310fc0f20352405c96190d56cd36ef028bf4d6e77fa6b"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$a1 = "==([0-9\\@]+)==" ascii
		$a2 = "data\"\":\"\"(.*?)" ascii
		$a3 = ", vbcr ,\"\")" ascii
		$a4 = ", vblf ,\"\")" ascii
		$a5 = ", \"&&\" ,\"\")" ascii
		$a6 = "ru-RU,ru;q=0.8,en-US;q=0.6,en;q=0.4" ascii
		$b1 = "==([0-9\\@]+)==" base64
		$b2 = "data\"\":\"\"(.*?)" base64
		$b3 = ", vbcr ,\"\")" base64
		$b4 = ", vblf ,\"\")" base64
		$b5 = ", \"&&\" ,\"\")" base64
		$b6 = "ru-RU,ru;q=0.8,en-US;q=0.6,en;q=0.4" base64

	condition:
		(4 of ( $a* ) or 4 of ( $b* ) ) and filesize < 50KB
}

rule SEKOIA_Apt_Gamaredon_Gamaredon_Lnk_Usb_Spreader_Encoded : FILE
{
	meta:
		description = "Detects encoded version of Gamaredon LNK USB Spreader"
		author = "Sekoia.io"
		id = "e42bb654-d1aa-4219-b3da-dd4053d59a83"
		date = "2023-06-19"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_gamaredon_gamaredon_lnk_usb_spreader_encoded.yar#L1-L19"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		hash = "28358a4a6acdcdfc6d41ea642220ef98c63b9c3ef2268449bb02d2e2e71e7c01"
		logic_hash = "81ab55330b3003cb698ade7e14eaea5fb03e5d2d3dd310b7db682aeef9b51f6e"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = "[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(" ascii
		$s2 = " 1000000){" base64
		$s3 = "+\"\\$" base64
		$s4 = ",3\";" base64

	condition:
		$s1 at 0 and 3 of them and filesize < 4000
}

rule SEKOIA_Apt_Polonium_Megacreep_Strings : FILE
{
	meta:
		description = "Tries to detect POLONIUM's MegaCreep implant"
		author = "Sekoia.io"
		id = "4d62d5bc-2ec9-58ef-bfe7-c0b04fa73b6f"
		date = "2022-10-12"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_polonium_megacreep_strings.yar#L1-L28"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "f4881e15854b082d8e6b8a28a7eb1518c559577b1b3ce76e404d67b1fe723fde"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"
		orig_id = "927c5fd6-0574-43bf-8db9-6ecc328estrin56c7"

	strings:
		$ = "[#!#]" ascii wide
		$ = "[$$%$$]" ascii wide
		$ = ".e##x##e" ascii wide
		$ = "WHLib.dll" ascii wide
		$ = "TestService.txt" ascii wide
		$ = "X = Stop" ascii wide
		$ = "Sess.dll" ascii wide
		$ = "filepathOnTarget" ascii wide
		$ = "FileNameOnMega" ascii wide
		$ = "Missing Parameter.. Format of command:" ascii wide
		$ = "Your Old K##E##Y is Wronge" ascii wide
		$ = "Your Upgrage Is Success" ascii wide

	condition:
		uint16be( 0 ) == 0x4d5a and filesize < 2MB and 3 of them
}

rule SEKOIA_Apt_Kimsuky_Sharpext_Jsexfil_Strings : FILE
{
	meta:
		description = "Detects the exfiltration JS code of SharpExt"
		author = "Sekoia.io"
		id = "c9ebd123-6450-4424-93d1-60322bd97bf6"
		date = "2022-07-29"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_kimsuky_sharpext_jsexfil_strings.yar#L1-L18"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "37ea72b369baaced89f30f655901cc4a9d6a70d00cfca3b92a1015aca64d4e2c"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "var req_url" ascii fullword
		$ = "var newReqId" ascii fullword
		$ = "chrome.tabs.query" ascii fullword
		$ = "payload.message.flags = new Object();" ascii fullword

	condition:
		all of them and filesize < 50KB
}

rule SEKOIA_Apt_Ta410_Driver_Keylogger : FILE
{
	meta:
		description = "Keylogger TA410"
		author = "Sekoia.io"
		id = "0cba1b3b-b93e-41e3-a7df-afd306e6b519"
		date = "2022-10-11"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_ta410_driver_keylogger.yar#L1-L23"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "5ed152cc068f194cb7bf8c34744f0f1ebd4f621e6ae47f14bab64b18d94af4c5"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "namedpipe_keymousespy" ascii wide
		$ = "[`LCTRL]" ascii wide
		$ = "[`RCTRL]" ascii wide
		$ = "[`BREAK]" ascii wide
		$ = "[`NUMLOCK]" ascii wide
		$ = "[`L]" ascii wide
		$ = "[`R]" ascii wide
		$ = "[`M]" ascii wide

	condition:
		uint16be( 0 ) == 0x4d5a and filesize < 1MB and 3 of them
}

rule SEKOIA_Apt_Coathanger_Files : FILE
{
	meta:
		description = "Detects COATHANGER files"
		author = "Sekoia.io"
		id = "615f5ac1-14bc-4f5b-a02e-7b13cd179917"
		date = "2024-02-07"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_coathanger_files.yar#L1-L24"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "5406d8a99e16f08f1ffca548ea1dd1e27e7707506e796e0fc263bcdbb681632d"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "/data2/"
		$ = "/httpsd"
		$ = "/preload.so"
		$ = "/authd"
		$ = "/tmp/packfile"
		$ = "/smartctl"
		$ = "/etc/ld.so.preload"
		$ = "/newcli"
		$ = "/bin/busybox"

	condition:
		( uint32( 0 ) == 0x464c457f or uint32( 4 ) == 0x464c457f ) and filesize < 5MB and 4 of them
}


rule SEKOIA_Downloader_Win_Apt33_Tickler : FILE
{
	meta:
		description = "Detect the downloader used by APT33 to diwnload Tickler"
		author = "Sekoia.io"
		id = "e1f704d6-d527-479a-8311-d286c06768ac"
		date = "2024-08-29"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/downloader_win_apt33_tickler.yar#L4-L29"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "e6fff291b73812e5a999fbc566e8f7181dcdf01b849a9664ba05fe0a2bc982fe"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	condition:
		uint16be( 0 ) == 0x4d5a and pe.imphash ( ) == "e43c58659b5b3082387307603478881a" or hash.md5 ( pe.rich_signature.clear_data ) == "d30bd7875b225709ecf95bf68dbd435f" or for any i in ( 0 .. pe.number_of_sections -1 ) : ( hash.md5 ( pe.sections [ i ] . raw_data_offset , pe.sections [ i ] . raw_data_size ) == "d7d2079d0a656c06a03f2c277bb08bda" or hash.md5 ( pe.sections [ i ] . raw_data_offset , pe.sections [ i ] . raw_data_size ) == "61a1425e6a0d28e29c6fd3d451ac3717" or hash.md5 ( pe.sections [ i ] . raw_data_offset , pe.sections [ i ] . raw_data_size ) == "916bf96ed3274ce8322d9f370432844f" or hash.md5 ( pe.sections [ i ] . raw_data_offset , pe.sections [ i ] . raw_data_size ) == "3fab9d4ae989d53cecb2f443b8ce88d0" or hash.md5 ( pe.sections [ i ] . raw_data_offset , pe.sections [ i ] . raw_data_size ) == "e0967483e074da72ceff4dea3bc17530" or hash.md5 ( pe.sections [ i ] . raw_data_offset , pe.sections [ i ] . raw_data_size ) == "b4a571736b6646765155ffbd57c27c83" or hash.md5 ( pe.sections [ i ] . raw_data_offset , pe.sections [ i ] . raw_data_size ) == "35c88ba521887f8fe1b2501f8cd8bd98" ) or for any i in ( 0 .. pe.number_of_resources -1 ) : ( hash.sha256 ( pe.resources [ i ] . offset , pe.resources [ i ] . length ) == "636dc666c7496cb3382b029fed53473f181cdc24405886c468e51a103d78b4d4" )
}

rule SEKOIA_Apt_Darkpink_Sample : FILE
{
	meta:
		description = "Detects two parts of cmd.exe /c "
		author = "Sekoia.io"
		id = "91b4c64a-7622-4f03-bd3f-9fe56f01dfbe"
		date = "2023-06-05"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_darkpink_sample.yar#L1-L19"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		hash = "8dc3f6179120f03fd6cb2299dbc94425451d84d6852b801a313a39e9df5d9b1a"
		logic_hash = "c9d3952036bffe2d924ea553fd53f8b6f0b3f16f1060fbde69496c800d4d5ad9"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$cmd_xor_part_1 = {DF 00 A1 00 E4 00 F0 00 4B 00 3A 00 D1 00 C4 00}
		$cmd_xor_part_2 = {bc 00 cc 00 80 00 d0 00 64 00 59 00 F1 00 E6 00 FD 00 83 00 C6}

	condition:
		( uint32be( 0 ) == 0x7f454c46 or uint16be( 0 ) == 0x4d5a ) and filesize < 1MB and all of them
}

rule SEKOIA_Apt_Apt28_Wayzgoose_Exploit_String : FILE
{
	meta:
		description = "Detects APT28's Wayzgoose exploit strings"
		author = "Sekoia.io"
		id = "23d9e09e-202c-47f5-abf7-6b5085e44400"
		date = "2024-04-29"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_apt28_wayzgoose_exploit_string.yar#L1-L20"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "804de275f7e8c43fe5690c0bd9338b134c0c47f845f1c3b3a747c3765815084c"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "wayzgoose.dll"
		$ = "wayzgoose_get_version"
		$ = "NtSetInformationFile"
		$ = "ZwDuplicateObject"
		$ = "ZwClose"

	condition:
		uint16be( 0 ) == 0x4d5a and 4 of them and filesize < 500KB
}

rule SEKOIA_Apt_Reaper_2Fa_Phishing_Webpage
{
	meta:
		description = "Detects Reaper 2FA phishing webpage"
		author = "Sekoia.io"
		id = "348ca2ad-c8f9-4aed-8a27-95caa3a34f4b"
		date = "2023-03-09"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_reaper_2fa_phishing_webpage.yar#L1-L23"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "3f0ae0b35ea181b4712feeb34e866519921917179297148982e5298df9f133a9"
		score = 75
		quality = 80
		tags = ""
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "setTimeout(checkUpload,"
		$ = "commChannel.addListener("
		$ = "else if(commType =="
		$ = "?dir=DOWN&method=READ&id="
		$ = "Content : base64_encode(upload_data)"
		$ = "$.post(upHttpRelayer"
		$ = "var ablyUpData = {"
		$ = "initComm();"
		$ = "function Next(arg) {"

	condition:
		3 of them
}

rule SEKOIA_Apt_Mustangpanda_Payload : FILE
{
	meta:
		description = "Decryption routine of mustang panda payload"
		author = "Sekoia.io"
		id = "ce7ddf20-e13f-4b5f-8fff-4b1387b29568"
		date = "2022-12-08"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_mustangpanda_payload.yar#L1-L42"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "734d42aed4574de620773f1f2d08c6b1fc206efd1b576f0f3679edcc0b2ce91d"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$chunk_1 = {
        89 74 24 ??
        B9 ?? ?? ?? ??
        8B 44 24 ??
        3D ?? ?? ?? ??
        B8 ?? ?? ?? ??
        0F 4C C1
        E9 ?? ?? ?? ??
        B8 ?? ?? ?? ??
        31 DB
        31 ED
        31 FF
        E9 ?? ?? ?? ??
        8B 44 24 ??
        B9 ?? ?? ?? ??
        3B 44 24 ??
        B8 ?? ?? ?? ??
        0F 42 C1
        E9 ?? ?? ?? ??
        88 5C 24 ??
        89 6C 24 ??
        89 7C 24 ??
        B9 ?? ?? ?? ??
        8B 44 24 ??
        3D ?? ?? ?? ??
        B8 ?? ?? ?? ??
        0F 4C C1
        }

	condition:
		filesize < 8MB and all of them
}

rule SEKOIA_Apt_Queueseed : FILE
{
	meta:
		description = "Detects strings of Queueseed/Kapeka malware"
		author = "Sekoia.io"
		id = "35f7ffd5-4f6f-4b31-8d60-c713a15d14e8"
		date = "2024-04-22"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_queueseed.yar#L1-L28"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "80d1135d63a351cabf45d2266c0ffc770e11669103107cd40caf00eb62c836ed"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = {2D 00 6F 00 00 00}
		$ = {2D 00 62 00 63 00 00 00}
		$ = {20 00 00 00 00 00 00 00}
		$ = {20 00 2D 00 77 00 00 00}
		$ = {35 00 3A 00 20 00 00 00}
		$ = {34 00 3A 00 20 00 00 00}
		$ = {33 00 3A 00 20 00 00 00}
		$ = {32 00 3A 00 20 00 00 00}
		$ = {31 00 3A 00 20 00 00 00}
		$ = {50 00 49 00 44 00 20 00 3A 00 20 00 00 00 00 00}
		$ = "ExitCode : " wide

	condition:
		uint16be( 0 ) == 0x4d5a and all of them and filesize < 200KB
}

rule SEKOIA_Apt_Yemen_Apk_Guardzoo : FILE
{
	meta:
		description = "Detects Dex files containing GuardZoo strings."
		author = "Sekoia.io"
		id = "f4004e7c-2904-46ea-a3e6-2bdd3e704fea"
		date = "2024-08-09"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/apt_yemen_apk_guardzoo.yar#L1-L40"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		hash = "3afad114c68489e2d294720339baf570"
		hash = "c59d0f5c8d00485199f147b96c5abca0"
		hash = "75c58948725133160085dc1cfdf602ec"
		hash = "d76a39ee85263900f7e6eaacb804f5e2"
		hash = "51356c95dfe1221c0f4ca2475bc787f8"
		hash = "1d0dd8201c051d9c8d2c945c8b31a48c"
		hash = "b7b6be5e8eec44dd13e1df1f3908fcf0"
		hash = "229984f004578a8fa643afb881d81e8c"
		hash = "f3f1ccb3912c49a0a6ea710a0bd856de"
		hash = "a3f8365bfa5f8185e8c7eba8efc63165"
		hash = "7392deaf81ddf50b8a6f2179538f7e81"
		hash = "c40d56e1586f9fa382c688d624d25525"
		hash = "629fb04b91c4db4ea282440e20317dab"
		hash = "bcebc41628196f8bd119f72e1e8eb47c"
		hash = "f1cfdc9e91c3a20563246cf366b94f10"
		hash = "a75ffb11adbace40a7c59128adba43ad"
		logic_hash = "7d98aefa4c2ee7316e0ff47a67d9f19913852d1a451ef38ccb77709394e4ba73"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$classes_1 = "GuardZoo.java"
		$classes_2 = "com/animals"
		$path_1 = "&Password="
		$path_2 = "&Coordinates="
		$path_3 = "&Data="
		$path_4 = "&Device="
		$path_5 = "&ISPICTURE="
		$path_6 = "&Phone_Number="
		$path_7 = "&Provider="

	condition:
		uint32be( 0 ) == 0x6465780a and filesize < 10MB and ( ( any of ( $classes_* ) ) and ( 3 of ( $path_* ) ) )
}

rule SIGNATURE_BASE_APT_Builder_PY_REDFLARE_2_1
{
	meta:
		description = "No description has been set in the source file - Signature Base"
		author = "FireEye"
		id = "74c56ee1-734e-5fdb-beee-6345a5993f68"
		date = "2020-12-01"
		modified = "2020-12-01"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/gen_fireeye_redteam_tools.yar#L1376-L1391"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		hash = "4410e95de247d7f1ab649aa640ee86fb"
		logic_hash = "0f28fb23c0c1d589466c7c541c8dc588b038d02dded0c66c4a448d1f768c95c5"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s1 = "<510sxxII"
		$s2 = "0x43,0x00,0x3a,0x00,0x5c,0x00,0x57,0x00,0x69,0x00,0x6e,0x00,0x64,0x00,0x6f,0x00,"
		$s3 = "parsePluginOutput"

	condition:
		all of them and #s2 == 2
}


rule SIGNATURE_BASE_EXT_APT_UNC2891_SLAPSTICK : FILE
{
	meta:
		description = "Detects SLAPSTICK malware used by UNC2891"
		author = "Mandiant"
		id = "788b259e-02cf-5265-9c13-2b5a4b937c32"
		date = "2022-03-17"
		modified = "2026-01-30"
		reference = "https://www.mandiant.com/resources/blog/unc2891-overview"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_unc2891_tinyshell_slapstick.yar#L44-L57"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "b046a949dab2f38b8181782cc6ea0782d2e102c0c30bc782de74112a77c23d6e"
		score = 80
		quality = 85
		tags = "FILE"

	strings:
		$ss1 = { 25 59 20 25 62 20 25 64 20 25 48 3a 25 4d 3a 25 53 20 20 20 20 00 }
		$ss2 = { 25 2d 32 33 73 20 25 2d 32 33 73 20 25 2d 32 33 73 00 }
		$ss3 = { 25 2d 32 33 73 20 25 2d 32 33 73 20 25 2d 32 33 73 20 25 2d 32 33 73 20 25 2d 32 33 73 20 25 73 0a 00 }

	condition:
		( uint32( 0 ) == 0x464c457f ) and all of them
}

rule SIGNATURE_BASE_APT_MAL_Win_Bluelight : INKYSQUID
{
	meta:
		description = "The BLUELIGHT malware family. Leverages Microsoft OneDrive for network communications."
		author = "threatintel@volexity.com"
		id = "3ec2d44c-4c08-514d-a839-acef3f53f7dc"
		date = "2021-04-23"
		modified = "2023-12-05"
		reference = "https://www.volexity.com/blog/2021/08/17/north-korean-apt-inkysquid-infects-victims-using-browser-exploits/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_apt37_bluelight.yar#L114-L144"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "52589348f42aadbe453ad8a40ac36b58fcc9e07cd298486f09b6f793823d8cc7"
		score = 75
		quality = 85
		tags = "INKYSQUID"
		hash1 = "7c40019c1d4cef2ffdd1dd8f388aaba537440b1bffee41789c900122d075a86d"
		hash2 = "94b71ee0861cc7cfbbae53ad2e411a76f296fd5684edf6b25ebe79bf6a2a600a"
		license = "See license at https://github.com/volexity/threat-intel/LICENSE.txt"

	strings:
		$pdb1 = "\\Development\\BACKDOOR\\ncov\\"
		$pdb2 = "Release\\bluelight.pdb"
		$msg0 = "https://ipinfo.io" fullword
		$msg1 = "country" fullword
		$msg5 = "\"UserName\":\"" fullword
		$msg7 = "\"ComName\":\"" fullword
		$msg8 = "\"OS\":\"" fullword
		$msg9 = "\"OnlineIP\":\"" fullword
		$msg10 = "\"LocalIP\":\"" fullword
		$msg11 = "\"Time\":\"" fullword
		$msg12 = "\"Compiled\":\"" fullword
		$msg13 = "\"Process Level\":\"" fullword
		$msg14 = "\"AntiVirus\":\"" fullword
		$msg15 = "\"VM\":\"" fullword

	condition:
		any of ( $pdb* ) or all of ( $msg* )
}

rule SIGNATURE_BASE_APT_Sandworm_Cyclopsblink_Notable_Strings : FILE
{
	meta:
		description = "Detects notable strings identified within the Cyclops Blink executable"
		author = "NCSC"
		id = "81ccf582-41f5-5fe5-8afc-e008e01289ff"
		date = "2022-02-23"
		modified = "2023-12-05"
		reference = "https://www.ncsc.gov.uk/news/joint-advisory-shows-new-sandworm-malware-cyclops-blink-replaces-vpnfilter"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_sandworm_cyclops_blink.yar#L6-L37"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "fdd3a1de9d178370fcc66dbca4628d7bedfbc002bca9e463e11cb444302900ea"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "3adf9a59743bc5d8399f67cab5eb2daf28b9b863"
		hash2 = "c59bc17659daca1b1ce65b6af077f86a648ad8a8"

	strings:
		$proc_name1 = "[kworker/0:1]"
		$proc_name2 = "[kworker/1:1]"
		$dns_query = "POST /dns-query HTTP/1.1\x0d\x0aHost: dns.google\x0d\x0a"
		$iptables1 = "iptables -I %s -p tcp --dport %d -j ACCEPT &>/dev/null"
		$iptables2 = "iptables -D %s -p tcp --dport %d -j ACCEPT &>/dev/null"
		$sys_recon1 = "{\"ver\":\"%x\",\"mods\";["
		$sys_recon2 = "uptime: %lu mem_size: %lu mem_free: %lu"
		$sys_recon3 = "disk_size: %lu disk_free: %lu"
		$sys_recon4 = "hw: %02x:%02x:%02x:%02x:%02x:%02x"
		$testpath = "%s/214688dsf46"
		$confpath = "%s/rootfs_cfg"
		$downpath = "/var/tmp/a.tmp"

	condition:
		( uint32( 0 ) == 0x464c457f ) and ( 8 of them )
}

rule SIGNATURE_BASE_APT_Sandworm_Cyclopsblink_Module_Initialisation : FILE
{
	meta:
		description = "Detects the code bytes used to initialise the modules built into Cyclops Blink"
		author = "NCSC"
		id = "c81b92c4-3f70-5bbd-acfa-ed1e1d33461d"
		date = "2022-02-23"
		modified = "2023-12-05"
		reference = "https://www.ncsc.gov.uk/news/joint-advisory-shows-new-sandworm-malware-cyclops-blink-replaces-vpnfilter"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_sandworm_cyclops_blink.yar#L39-L55"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "8bde37f642cf07e323beabaacd5c62f8422b451777fc1fc4a6bdf474db49de12"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "3adf9a59743bc5d8399f67cab5eb2daf28b9b863"
		hash2 = "c59bc17659daca1b1ce65b6af077f86a648ad8a8"

	strings:
		$ = {94 21 FF F0 93 E1 00 08 7C 3F 0B 78 38 00 00 ?? 7C 03
      03 78 81 61 00 00 8E EB FF F8 7D 61 5B 78 4E 80 00 20}

	condition:
		( uint32( 0 ) == 0x464c457f ) and ( any of them )
}

rule SIGNATURE_BASE_APT_Sandworm_Cyclopsblink_Modified_Install_Upgrade : FILE
{
	meta:
		description = "Detects notable strings identified within the modified install_upgrade executable, embedded within Cyclops Blink"
		author = "NCSC"
		id = "4c4f7262-df74-5f6a-afc0-df1fcae4741c"
		date = "2022-02-23"
		modified = "2023-12-05"
		reference = "https://www.ncsc.gov.uk/news/joint-advisory-shows-new-sandworm-malware-cyclops-blink-replaces-vpnfilter"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_sandworm_cyclops_blink.yar#L57-L88"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "69b89dbaf3e2661f376ff1be7c19e96c82bf84fd572fea422c109f8afdd1e5aa"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "3adf9a59743bc5d8399f67cab5eb2daf28b9b863"
		hash2 = "c59bc17659daca1b1ce65b6af077f86a648ad8a8"
		hash3 = "7d61c0dd0cd901221a9dff9df09bb90810754f10"
		hash4 = "438cd40caca70cafe5ca436b36ef7d3a6321e858"

	strings:
		$ = "/pending/%010lu_%06d_%03d_p1"
		$ = "/pending/sysa_code_dir/test_%d_%d_%d_%d_%d_%d"
		$ = "etaonrishdlcupfm"
		$ = "/pending/WGUpgrade-dl.new"
		$ = "/pending/bin/install_upgraded"
		$ = {38 80 4C 00}
		$ = {38 80 4C 05}
		$ = {38 80 4C 04}
		$ = {3C 00 48 4D 60 00 41 43 90 09 00 00}

	condition:
		( uint32( 0 ) == 0x464c457f ) and ( 6 of them )
}

rule SIGNATURE_BASE_APT_Sandworm_Cyclopsblink_Config_Identifiers : FILE
{
	meta:
		description = "Detects the initial characters used to identify Cyclops Blink configuration data"
		author = "NCSC"
		id = "db5b3a4a-82c2-500a-88f6-340b3392eac8"
		date = "2022-02-23"
		modified = "2023-12-05"
		reference = "https://www.ncsc.gov.uk/news/joint-advisory-shows-new-sandworm-malware-cyclops-blink-replaces-vpnfilter"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_sandworm_cyclops_blink.yar#L106-L126"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "6fa39442d717a69dd6f31a4bb2e5865c3f16156ce24a2b419d95ed751bb0d8ee"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "3adf9a59743bc5d8399f67cab5eb2daf28b9b863"
		hash2 = "c59bc17659daca1b1ce65b6af077f86a648ad8a8"

	strings:
		$ = {3C 00 3C 6B 60 00 3A 20 90 09 00 00}
		$ = {3C 00 3C 63 60 00 3A 20 90 09 00 00}
		$ = {3C 00 3C 73 60 00 3A 20 90 09 00 00}

	condition:
		( uint32( 0 ) == 0x464c457f ) and ( all of them )
}

rule SIGNATURE_BASE_APT_Sandworm_Cyclopsblink_Handle_Mod_0Xf_Command : FILE
{
	meta:
		description = "Detects the code bytes used to check module ID 0xf control flags and a format string used for file content upload"
		author = "NCSC"
		id = "36646b7a-389d-5fd9-88a1-e43e7224763a"
		date = "2022-02-23"
		modified = "2023-12-05"
		reference = "https://www.ncsc.gov.uk/news/joint-advisory-shows-new-sandworm-malware-cyclops-blink-replaces-vpnfilter"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_sandworm_cyclops_blink.yar#L128-L150"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "6e3eebe404c8cd24e1e16eb3c881b1eda78ba6b365bf89c2557329e6f89396ac"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "3adf9a59743bc5d8399f67cab5eb2daf28b9b863"
		hash2 = "c59bc17659daca1b1ce65b6af077f86a648ad8a8"

	strings:
		$ = {54 00 06 3E 54 00 07 FE 54 00 06 3E 2F 80 00 00}
		$ = {54 00 06 3E 54 00 07 BC 2F 80 00 00}
		$ = {54 00 06 3E 54 00 07 7A 2F 80 00 00}
		$ = {54 00 06 3E 54 00 06 F6 2F 80 00 00}
		$ = "file:%s\n" fullword

	condition:
		( uint32( 0 ) == 0x464c457f ) and ( all of them )
}

rule SIGNATURE_BASE_APT_Sandworm_Cyclopsblink_Default_Config_Values : FILE
{
	meta:
		description = "Detects the code bytes used to set default Cyclops Blink configuration values"
		author = "NCSC"
		id = "04067609-1173-51f2-907f-2a236aae6c7c"
		date = "2022-02-23"
		modified = "2023-12-05"
		reference = "https://www.ncsc.gov.uk/news/joint-advisory-shows-new-sandworm-malware-cyclops-blink-replaces-vpnfilter"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_sandworm_cyclops_blink.yar#L152-L174"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "180993057c110c0c0327b673c6d6e251534012de51cf6475838691e0942a1aa8"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "3adf9a59743bc5d8399f67cab5eb2daf28b9b863"
		hash2 = "c59bc17659daca1b1ce65b6af077f86a648ad8a8"

	strings:
		$ = {38 00 00 19 90 09 01 A4}
		$ = {3C 00 00 01 60 00 80 00 90 09 01 A8}
		$ = {38 00 40 00 90 09 01 AC}
		$ = {38 00 01 0B 90 09 01 B0}
		$ = {38 00 27 11 90 09 01 C0}

	condition:
		( uint32( 0 ) == 0x464c457f ) and ( 3 of them )
}

rule SIGNATURE_BASE_APT_Sandworm_Cyclopsblink_Handle_Mod_0X51_Command : FILE
{
	meta:
		description = "Detects the code bytes used to check commands sent to module ID 0x51 and notable strings relating to the Cyclops Blink update process"
		author = "NCSC"
		id = "a6800aed-27dc-5d01-b005-1eb4a62344a3"
		date = "2022-02-23"
		modified = "2023-12-05"
		reference = "https://www.ncsc.gov.uk/news/joint-advisory-shows-new-sandworm-malware-cyclops-blink-replaces-vpnfilter"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_sandworm_cyclops_blink.yar#L176-L200"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "8a68f4a5f5b7a45819e9a198881aa41b75a65181b63788c8b824b339bfd6fc67"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "3adf9a59743bc5d8399f67cab5eb2daf28b9b863"
		hash2 = "c59bc17659daca1b1ce65b6af077f86a648ad8a8"

	strings:
		$cmd_check = {88 1F [2] 54 00 06 3E 2F 80 00 (01|02|03) }
		$path1 = "/etc/wg/configd-hash.xml"
		$path2 = "/etc/wg/config.xml"
		$mnt_arg1 = "ext2"
		$mnt_arg2 = "errors=continue"
		$mnt_arg3 = {38 C0 0C 20}
		$mnt_arg4 = {38 C0 0C 21}

	condition:
		( uint32( 0 ) == 0x464c457f ) and ( #cmd_check == 3 ) and ( ( @cmd_check [ 3 ] - @cmd_check [ 1 ] ) < 0x200 ) and ( all of ( $path* ) ) and ( all of ( $mnt_arg* ) )
}

rule SIGNATURE_BASE_APT_MAL_DTRACK_Oct19_1 : FILE
{
	meta:
		description = "Detects DTRACK malware"
		author = "Florian Roth (Nextron Systems)"
		id = "802135bd-234d-574d-b111-fcc9eaa000f8"
		date = "2019-10-28"
		modified = "2023-12-05"
		reference = "https://twitter.com/a_tweeter_user/status/1188811977851887616?s=21"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_dtrack.yar#L2-L44"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "b99bc8ec4df7185da306365dc2a24a0849ff0d5d92269daaa1efbb20f5e5bf83"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "c5c1ca4382f397481174914b1931e851a9c61f029e6b3eb8a65c9e92ddf7aa4c"
		hash2 = "a0664ac662802905329ec6ab3b3ae843f191e6555b707f305f8f5a0599ca3f68"
		hash3 = "93a01fbbdd63943c151679d037d32b1d82a55d66c6cb93c40ff63f2b770e5ca9"
		hash4 = "3cc9d9a12f3b884582e5c4daf7d83c4a510172a836de90b87439388e3cde3682"
		hash5 = "bfb39f486372a509f307cde3361795a2f9f759cbeb4cac07562dcbaebc070364"
		hash6 = "58fef66f346fe3ed320e22640ab997055e54c8704fc272392d71e367e2d1c2bb"
		hash7 = "9d9571b93218f9a635cfeb67b3b31e211be062fd0593c0756eb06a1f58e187fd"

	strings:
		$xc1 = { 25 73 2A 2E 2A 00 00 00 5C 00 00 00 25 73 7E 00
               5C 00 00 00 77 62 00 00 64 61 74 00 64 6B 77 65
               72 6F 33 38 6F 65 72 41 5E 74 40 23 00 00 00 00
               63 3A 5C 00 25 73 5C 25 63 2E 74 6D 70 }
		$sx1 = "%02d.%02d.%04d - %02d:%02d:%02d:%03d : " fullword ascii
		$sx2 = "%s\\%c.tmp" fullword ascii
		$sx3 = "dkwero38oerA" fullword ascii
		$sx4 = "awz2qr21yfbj" fullword ascii
		$s1 = "Execute_%s.log" ascii
		$s2 = "%s\\%s\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles" fullword ascii
		$s3 = "CCS_Mozilla/5.0" fullword ascii
		$s4 = "\\C$\\Windows\\Temp\\MpLogs\\" ascii
		$s5 = "127.0.0.1 >NUL & echo EEEE > \"%s\"" fullword ascii
		$s6 = "[+] DownloadCommand" fullword ascii
		$s7 = "DC-Error: Too long cmd length" fullword ascii
		$s8 = "%s\\~%d.tmp" fullword ascii
		$s9 = "%02X:%02X:%02X:%02X:%02X:%02X" ascii fullword
		$op1 = { 0f b6 8d a3 fc ff ff 85 c9 74 09 8b 55 f4 83 c2 }
		$op2 = { 6a 00 8d 85 28 fc ff ff 50 6a 04 8d 4d f8 51 8b }
		$op3 = { 8b 85 c8 fd ff ff 03 85 a4 fc ff ff 89 85 b4 fc }

	condition:
		$xc1 or 2 of ( $sx* ) or 4 of them or ( uint16( 0 ) == 0x5a4d and filesize <= 3000KB and 2 of them )
}


rule SIGNATURE_BASE_APT_Turlamosquito_MAL_Oct22_1 : FILE
{
	meta:
		description = "Detects Turla Mosquito malware"
		author = "Florian Roth (Nextron Systems)"
		id = "f5ad0c0f-81ca-5157-aefb-ead049ada30d"
		date = "2022-10-25"
		modified = "2023-12-05"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_turla_mosquito.yar#L129-L156"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "fbaca774d6398aac7c171a5d87aa456a1921c1b80449d06f392b088db33ee845"
		score = 80
		quality = 85
		tags = "FILE"
		hash1 = "6b9e48e3f4873cfb95639d9944fe60e3b056daaa2ea914add14c982e3e11128b"
		hash2 = "b868b674476418bbdffbe0f3d617d1cce4c2b9dae0eaf3414e538376523e8405"
		hash3 = "e7fd14ca45818044690ca67f201cc8cfb916ccc941a105927fc4c932c72b425d"

	strings:
		$s1 = "Logger32.dll" ascii fullword
		$s4 = " executing %u command on drive %martCommand : CWin32ApiErrorExce" wide
		$s5 = "Unsupported drive!!!" ascii fullword
		$s7 = "D:\\Build_SVN\\PC_MAGICIAN_4." ascii fullword
		$op1 = { 40 cc 8b 8b 06 cc 55 00 70 8b 10 10 33 51 04 46 04 64 }
		$op2 = { c3 10 e8 50 04 00 cc ff 8d 00 69 8d 75 ff 68 ec 6a 4d }
		$op3 = { e8 64 a1 6e 00 64 a1 c2 04 08 75 40 73 1d 8b ff cc 10 89 cc 8b c3 cc af }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 2000KB and ( pe.imphash ( ) == "073235ae6dfbb1bf5db68a039a7b7726" or all of them )
}

rule SIGNATURE_BASE_APT_MAL_CN_Wocao_Agent_Csharp
{
	meta:
		description = "Strings from CSharp version of Agent"
		author = "Fox-IT SRT"
		id = "e5212226-a82d-558d-abb4-43ad7848764e"
		date = "2019-12-20"
		modified = "2023-12-05"
		reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_op_wocao.yar#L2-L22"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "e77fcd2ac0c21db54563b15466962a775a5e8ef73cedb3af5cd00d5b0d615e4c"
		score = 75
		quality = 85
		tags = ""

	strings:
		$a = "mysend(client_sock, new byte[] { 0x16, 0x00 }, 2);" ascii wide
		$b = "Dns.GetHostAddresses(sip.Remove(sip.Length - 1));" ascii wide
		$c = "Port = 256 * buf[4] + buf[5];" ascii wide
		$d = "Port = 256 * buf[AddrLen] + buf[AddrLen + 1];" ascii wide
		$e = "StartTransData(CliSock" ascii wide
		$f = "static void ForwardTransmit(object ft_data)" ascii wide
		$key = "0x4c, 0x1b, 0x68, 0x0b, 0x6a, 0x18, 0x09, 0x41, 0x5a, 0x36, 0x1f, 0x56, 0x26, 0x2a, 0x03, 0x44, 0x7d, 0x5f, 0x03, 0x7b, 0x07, 0x6e, 0x03, 0x77, 0x30, 0x70, 0x52, 0x42, 0x53, 0x67, 0x0a, 0x2a" ascii wide
		$key_raw = { 4c1b680b6a1809415a361f56262a03447d5f037b076e03773070524253670a2a }

	condition:
		1 of them
}

rule SIGNATURE_BASE_APT_MAL_CN_Wocao_Agent_Powershell_Dropper
{
	meta:
		description = "Strings from PowerShell dropper of CSharp version of Agent"
		author = "Fox-IT SRT"
		id = "833ce607-56a9-5580-bbd1-e72392945fec"
		date = "2019-12-20"
		modified = "2023-12-05"
		reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_op_wocao.yar#L24-L38"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "19f56e69685ae8c13b9dd884f8322915835c16e2c6313f01f9fa447218419108"
		score = 75
		quality = 85
		tags = ""

	strings:
		$a = "function format([string]$source)"
		$b = "foreach($c in $bb){$tt = $tt + [char]($c -bxor"
		$c = "[agent]::Main($args);"

	condition:
		1 of them
}

rule SIGNATURE_BASE_APT_MAL_CN_Wocao_Agent_Powershell_B64Encoded
{
	meta:
		description = "Piece of Base64 encoded data from Agent CSharp version"
		author = "Fox-IT SRT"
		id = "14e1702d-6229-5989-8bb7-cc9c0c321676"
		date = "2019-12-20"
		modified = "2023-12-05"
		reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_op_wocao.yar#L40-L52"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "bcf9a75dbbf90044db76c56ffd07971d4252b0e75d73abf402ca4fadbfb59767"
		score = 75
		quality = 85
		tags = ""

	strings:
		$header = "LFNVT0hBBnVfVVJDSx0sU1VPSEEGdV9VUkNLCG9pHSxTVU9IQQZ1X1VSQ0sIZUlK"

	condition:
		all of them
}

rule SIGNATURE_BASE_APT_MAL_CN_Wocao_Agent_Py_B64Encoded
{
	meta:
		description = "Piece of Base64 encoded data from Agent Python version"
		author = "Fox-IT SRT"
		id = "eb2701e9-4358-5d24-bfcd-b4dde24f13bf"
		date = "2019-12-20"
		modified = "2023-12-05"
		reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_op_wocao.yar#L77-L89"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "279fb27637d9b62b484283f778215d042de9fb83110a233e048452e921c540ee"
		score = 75
		quality = 85
		tags = ""

	strings:
		$header = "QlpoOTFBWSZTWWDdHjgABDTfgHwQe////z/v/9+////6YA4cGPsAl2e8M9LSU128"

	condition:
		all of them
}

rule SIGNATURE_BASE_APT_MAL_CN_Wocao_Keylogger_Py
{
	meta:
		description = "Strings from Python keylogger"
		author = "Fox-IT SRT"
		id = "f7b5ec1b-669e-5e7d-a9d3-011d212eb363"
		date = "2019-12-20"
		modified = "2023-12-05"
		reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_op_wocao.yar#L91-L107"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "2dc2ce153d559d795f302f5ca4a9ef9e6e5c54762472e38e6f4a26ef8a28a184"
		score = 75
		quality = 85
		tags = ""

	strings:
		$a = "c:\\windows\\temp\\tap.tmp"
		$b = "c:\\windows\\temp\\mrteeh.tmp"
		$c = "GenFileName"
		$d = "outfile"
		$e = "[PASTE:%d]"

	condition:
		3 of them
}

rule SIGNATURE_BASE_APT_MAL_CN_Wocao_Keylogger_File
{
	meta:
		description = "Rule for finding keylogger output files"
		author = "Fox-IT SRT"
		id = "22e866b3-4b02-593a-b9a6-aa86870b6509"
		date = "2019-12-20"
		modified = "2023-12-05"
		reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_op_wocao.yar#L109-L121"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "6d2d677b69eaf31843e8352bfe040c9e5a8d423d17900e022b769d28789f2d98"
		score = 75
		quality = 85
		tags = ""

	strings:
		$a = { 0d 0a 20 [3-10] 53 74 61 72 74 75 70 3a 20 [3] 20 [3] 20 [2] 20 [2] 3a [2] 3a [2] 20 }

	condition:
		all of them
}

rule SIGNATURE_BASE_APT_MAL_CN_Wocao_Xserver_Csharp
{
	meta:
		description = "Strings from the CSharp version of XServer"
		author = "Fox-IT SRT"
		id = "48f4c88d-fb56-54ca-84e2-38f88804a50f"
		date = "2019-12-20"
		modified = "2023-12-05"
		reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_op_wocao.yar#L123-L141"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "1201ee45df78cf3aec4b4bbb59cb7e4a70af6928895bb7c968ef02075a963405"
		score = 75
		quality = 85
		tags = ""

	strings:
		$a = "static void ServerX(int ListenPort)" ascii wide
		$b = "public class xserver" ascii wide
		$c = "[xserver]::Main($args);" ascii wide
		$d = "add rule name=powershell dir=in localport=47000 action=allow" ascii wide
		$e = "string TempFile = file_path + \".CT\";" ascii wide
		$f = "Port = 256 * RecvBuf[AddrLen + 5] + RecvBuf[AddrLen + 6];"
		$g = "CliSock.Send(new byte[] { 0x05, 0x00 });"

	condition:
		1 of them
}

rule SIGNATURE_BASE_APT_MAL_CN_Wocao_Xserver_Powershell_B64Encoded
{
	meta:
		description = "Piece of Base64 encoded data from the XServer PowerShell dropper"
		author = "Fox-IT SRT"
		id = "01e38cfb-b245-5398-b037-6d1d2fb726ee"
		date = "2019-12-20"
		modified = "2023-12-05"
		reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_op_wocao.yar#L143-L155"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "77315f0fc8387fa87892fc8fcea1f6e8a95560049aaa9a87519859020d0a7a3e"
		score = 75
		quality = 85
		tags = ""

	strings:
		$header_47000 = "5T39c9u2kr/nr2A0Ny2VKIzkfLRJntuJHafPN/nwWG777rUZDy3BNq8UqSEpx26b"
		$header_25667 = "5T1rc9u2st/zKxjNmZZKFEZyErdJ6nZsx+nxnTjxWGp77mkzHlqCbd5SpIak/Gjr"

	condition:
		any of them
}

rule SIGNATURE_BASE_APT_MAL_CN_Wocao_Xserver_Powershell_Dropper
{
	meta:
		description = "Strings from the PowerShell dropper of XServer"
		author = "Fox-IT SRT"
		id = "97169ab4-d68d-5137-83de-d9cac975747e"
		date = "2019-12-20"
		modified = "2023-12-05"
		reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_op_wocao.yar#L157-L168"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "640c9e52f3cf3df4e954177624e6fba4bab80a2c9442b718fe90e8577dafbbd6"
		score = 75
		quality = 85
		tags = ""

	strings:
		$encfile = "New-Object IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String($encfile)"

	condition:
		all of them
}

rule SIGNATURE_BASE_APT_MAL_CN_Wocao_Injector_Bin
{
	meta:
		description = "Process injector/launcher"
		author = "Fox-IT SRT"
		id = "389279f1-6531-594f-97b6-5adbc8fa4d3d"
		date = "2019-12-20"
		modified = "2023-12-05"
		reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_op_wocao.yar#L170-L193"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "c8cd4e3c87c6d80b39069f7a94e512e3f7b739c21f6fd70c2a79829c5a04f32f"
		score = 75
		quality = 85
		tags = ""

	strings:
		$a = "%s{%04d-%02d%02d-%02d%02d-%d%ld}.tmp"
		$b = "s% > s% c/ exe.d"
		$c = {
            48 89 5C 24 08 48 89 74  24 10 57 48 83 EC 50 48
            8B 71 08 48 8D 59 10 48  8B F9 48 8B CB FF 17 33
            C9 48 8D 47 78 48 89 44  24 48 4C 8D 87 9C 03 00
            00 48 89 5C 24 40 48 8D  97 90 00 00 00 4C 89 44
            24 38 45 33 C9 48 89 4C  24 30 45 33 C0 89 4C 24
            28 C7 44 24 20 01 00 00  00 66 89 4B 40 FF D6 48
            8B 5C 24 60 33 C0 48 8B  74 24 68 48 83 C4 50 5F
            C3
        }

	condition:
		1 of them
}

rule SIGNATURE_BASE_APT_MAL_CN_Wocao_Timeliner_Bin
{
	meta:
		description = "Timeliner utility"
		author = "Fox-IT SRT"
		id = "3d81a4ae-0ce0-5867-ac93-a706556481b6"
		date = "2019-12-20"
		modified = "2023-12-05"
		reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_op_wocao.yar#L195-L213"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "c3a8cddc34134faaab93ee0df0086604e4a7b031530dd65e2e8dab705483305b"
		score = 75
		quality = 85
		tags = ""

	strings:
		$a = "[+] Work completed." ascii wide
		$b = "[-] Create a new file failed." ascii wide
		$c = "[-] This is not a correct path." ascii wide
		$d = "%s [TargetPath] <Num> <SavePath>" ascii wide
		$e = "D\t%ld\t%ld\t%ld\t%d\t%d\t%s\t" ascii wide
		$f = "D\t%ld\t%ld\t%ld\t-1\t%d\t%s\t" ascii wide
		$g = "%s\t%ld\t%ld\t%ld\t%I64d\t%d\t%s\t%s" ascii wide

	condition:
		1 of them
}

rule SIGNATURE_BASE_APT_MAL_CN_Wocao_Checkadmin_Bin
{
	meta:
		description = "Checkadmin utility"
		author = "Fox-IT SRT"
		id = "2f819213-ade1-525b-af18-d77b7fc96093"
		date = "2019-12-20"
		modified = "2023-12-05"
		reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_op_wocao.yar#L215-L232"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "784ec960ce2733aebc404ee5c09bb852eb45553ad167db292d05b82feedbd5a6"
		score = 75
		quality = 85
		tags = ""

	strings:
		$a = "[-] %s * A system error has occurred: %d" ascii wide
		$b = {
            0D 00 0A 00 25 00 6C 00 64 00 20 00 72 00 65 00
            73 00 75 00 6C 00 74 00 73 00 2E 00 0D 00 0A 00
        }
		$c = "%s\t<Access denied>" ascii wide

	condition:
		1 of them
}

rule SIGNATURE_BASE_APT_MAL_CN_Wocao_Getos_Py
{
	meta:
		description = "Python getos utility"
		author = "Fox-IT SRT"
		id = "4a731dde-87e4-566a-b559-d23e0bef5841"
		date = "2019-12-20"
		modified = "2023-12-05"
		reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_op_wocao.yar#L234-L295"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "2535c01b703c0fcba43e771832db8cd969e4a4b112ef28e4ddfeac6491ba604c"
		score = 75
		quality = 85
		tags = ""

	strings:
		$smb_1 = {
            00 00 00 85 ff 53 4d 42 72 00 00 00 00 18 53 c8
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 ff fe
            00 00 ff b4 00 62 00 02 50 43 20 4e 45 54 57 4f
            52 4b 20 50 52 4f 47 52 41 4d 20 31 2e 30 00 02
            4c 41 4e 4d 41 4e 31 2e 30 00 02 57 69 6e 64 6f
            77 73 20 66 6f 72 20 57 6f 72 6b 67 72 6f 75 70
            73 20 33 2e 31 61 00 02 4c 4d 31 2e 32 58 30 30
            32 00 02 4c 41 4e 4d 41 4e 32 2e 31 00 02 4e 54
            20 4c 4d 20 30 2e 31 32 00
        }
		$smb_2 = {
            00 00 00 c8 ff 53 4d 42 73 00 00 00 00 18 03 c8
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 ff fe
            00 00 3f b5 0c ff 00 c8 00 04 11 32 00 00 00 00
            00 00 00 28 00 00 00 00 00 d4 00 00 a0 8d 00 4e
            54 4c 4d 53 53 50 00 01 00 00 00 07 82 88 a2 00
            00 00 00 28 00 00 00 00 00 00 00 28 00 00 00 05
            01 28 0a 00 00 00 0f 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00
        }
		$smbstr_1 = "\\x00\\x00\\x00\\x85\\xffSMBr\\x00\\x00\\x00\\x00\\x18S\\xc8\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\xff\\xfe\\x00\\x00\\xff\\xb4\\x00b\\x00\\x02PC NETWORK PROGRAM 1.0\\x00\\x02LANMAN1.0\\x00\\x02Windows for Workgroups 3.1a\\x00\\x02LM1.2X002\\x00\\x02LANMAN2.1\\x00\\x02NT LM 0.12\\x00"
		$smbstr_2 = "\\x00\\x00\\x00\\xc8\\xffSMBs\\x00\\x00\\x00\\x00\\x18\\x03\\xc8\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\xff\\xfe\\x00\\x00?\\xb5\\x0c\\xff\\x00\\xc8\\x00\\x04\\x112\\x00\\x00\\x00\\x00\\x00\\x00\\x00(\\x00\\x00\\x00\\x00\\x00\\xd4\\x00\\x00\\xa0\\x8d\\x00NTLMSSP\\x00\\x01\\x00\\x00\\x00\\x07\\x82\\x88\\xa2\\x00\\x00\\x00\\x00(\\x00\\x00\\x00\\x00\\x00\\x00\\x00(\\x00\\x00\\x00\\x05\\x01(\\n\\x00\\x00\\x00\\x0f\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00"
		$code_1 = "return 'Other error.'" ascii wide
		$code_2 = "sblob = buf[47:47 + sbl]" ascii wide
		$code_3 = "re.split('[\\x00-,]+', y[-4])" ascii wide
		$code_4 = "('').join(sblob[off:off + hlen].split('\\x00'))" ascii wide
		$code_5 = "banner = '%s    %s' % (hostname, native)" ascii wide
		$code_6 = "banner = '%s\\\\%s    %s' % (dm, hostname, native)" ascii wide
		$tsk_1 = "PushTask" ascii wide
		$tsk_2 = "parse_task" ascii wide
		$tsk_3 = "commit_task" ascii wide
		$str_1 = "Usage: getos.py <ip-range|ip-file>" ascii wide
		$str_2 = "The path '%s' write fails." ascii wide
		$str_3 = "Receive a signal %d," ascii wide
		$str_4 = "Scan Complete!" ascii wide
		$str_5 = "line: %d, %s: %s" ascii wide
		$str_6 = "Other error." ascii wide

	condition:
		( all of ( $smb_* ) ) or ( all of ( $smbstr_* ) ) or ( 3 of ( $code_* ) ) or ( all of ( $tsk_* ) ) or ( 3 of ( $str_* ) )
}

rule SIGNATURE_BASE_APT_MAL_CN_Wocao_Info_Vbs
{
	meta:
		description = "Strings from the information grabber VBS"
		author = "Fox-IT SRT"
		id = "b719fb31-2836-5faf-a7c8-c361a14df2be"
		date = "2019-12-20"
		modified = "2023-12-05"
		reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_op_wocao.yar#L297-L316"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "e37f8768c7920b8c3d9fdd6bb3a4e748c47a6c06a8aaed01655355ef3d8c3457"
		score = 75
		quality = 85
		tags = ""

	strings:
		$ = "Logger PingConnect"
		$ = "Logger GetAdmins"
		$ = "Logger InstallPro"
		$ = "Logger Exec"
		$ = "retstr = adminsName & \" Members\" & vbCrLf & _"
		$ = "Logger VolumeName & \" (\" & objDrive.DriveLetter & \":)\" _"
		$ = "txtRes = txtRes & machine & \" can"
		$ = "retstr = \"PID   SID Image Name\" & vbCrLf & \"===="

	condition:
		4 of them
}

rule SIGNATURE_BASE_APT_APT28_Drovorub_Library_And_Unique_Strings : FILE
{
	meta:
		description = "Rule to detect Drovorub-server, Drovorub-agent, and Drovorub-client"
		author = "NSA / FBI"
		id = "8e010356-09c7-5897-9cbe-051cd0800502"
		date = "2020-08-13"
		modified = "2023-12-05"
		reference = "https://www.nsa.gov/news-features/press-room/Article/2311407/nsa-and-fbi-expose-russian-previously-undisclosed-malware-drovorub-in-cybersecu/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_apt28_drovorub.yar#L23-L42"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "adb0d4cb6d589213e6a125d3cc20fcea8164b697bdd24d897ce75e7c7f06120a"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "Poco" ascii wide
		$s2 = "Json" ascii wide
		$s3 = "OpenSSL" ascii wide
		$a1 = "clientid" ascii wide
		$a2 = "-----BEGIN" ascii wide
		$a3 = "-----END" ascii wide
		$a4 = "tunnel" ascii wide

	condition:
		( filesize > 1MB and filesize < 10MB and ( uint32( 0 ) == 0x464c457f ) ) and ( #s1 > 20 and #s2 > 15 and #s3 > 15 and all of ( $a* ) )
}

rule SIGNATURE_BASE_APT_APT28_Drovorub_Unique_Network_Comms_Strings
{
	meta:
		description = "Rule to detect Drovorub-server, Drovorub-agent, or Drovorub-client based"
		author = "NSA / FBI"
		id = "c6a930e8-c1c0-5d96-9051-7516df848b45"
		date = "2020-08-13"
		modified = "2023-12-05"
		reference = "https://www.nsa.gov/news-features/press-room/Article/2311407/nsa-and-fbi-expose-russian-previously-undisclosed-malware-drovorub-in-cybersecu/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_apt28_drovorub.yar#L44-L72"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "8c82766b76c36fe64c6aa99577e1997d7181dbd36a4c27329845ae8a413f5327"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s_01 = "action" wide ascii
		$s_02 = "auth.commit" wide ascii
		$s_03 = "auth.hello" wide ascii
		$s_04 = "auth.login" wide ascii
		$s_05 = "auth.pending" wide ascii
		$s_06 = "client_id" wide ascii
		$s_07 = "client_login" wide ascii
		$s_08 = "client_pass" wide ascii
		$s_09 = "clientid" wide ascii
		$s_10 = "clientkey_base64" wide ascii
		$s_11 = "file_list_request" wide ascii
		$s_12 = "module_list_request" wide ascii
		$s_13 = "monitor" wide ascii
		$s_14 = "net_list_request" wide ascii
		$s_15 = "server finished" wide ascii
		$s_16 = "serverid" wide ascii
		$s_17 = "tunnel" wide ascii

	condition:
		all of them
}

rule SIGNATURE_BASE_APT_NK_Lazarus_RC4_Loop : FILE
{
	meta:
		description = "Detects RC4 loop in Lazarus Group implant"
		author = "f-secure "
		id = "a9503795-b4b8-505e-a1bf-df64ec8c1c32"
		date = "2020-06-10"
		modified = "2023-12-05"
		reference = "https://labs.f-secure.com/publications/ti-report-lazarus-group-cryptocurrency-vertical"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_lazarus_aug20.yar#L2-L15"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "b0e96bfff924a0c9b39e1ab03097ae0790743417d9da70917d64bc238905971e"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$str_rc4_loop = { 41 FE 8? 00 01 00 00 45 0F B6 ?? 00 01 00 00 48 
                        FF C? 43 0F B6 0? ?? 41 00 8? 01 01 00 00 41 0F 
                        B6 ?? 01 01 00 00 }

	condition:
		int16 ( 0 ) == 0x5a4d and filesize < 3000KB and $str_rc4_loop
}

rule SIGNATURE_BASE_APT_NK_MAL_DLL_Apr23_1 : FILE
{
	meta:
		description = "Detects DLLs loaded by shellcode loader (6ce5b6b4cdd6290d396465a1624d489c7afd2259a4d69b73c6b0ba0e5ad4e4ad) (relation to Lazarus group)"
		author = "Florian Roth (Nextron Systems)"
		id = "c2abe266-0c21-51aa-9426-46a4f59df937"
		date = "2023-04-03"
		modified = "2023-12-05"
		reference = "https://securelist.com/gopuram-backdoor-deployed-through-3cx-supply-chain-attack/109344/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_mal_gopuram_apr23.yar#L43-L75"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "e0a8f3896c0119ce399e83fe3e565c66144693e84996aa3d01ca1b6315521782"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "69dd140f45c3fa3aaa64c69f860cd3c74379dec37c46319d7805a29b637d4dbf"
		hash3 = "bb1066c1ca53139dc5a2c1743339f4e6360d6fe4f2f3261d24fc28a12f3e2ab9"
		hash4 = "dca33d6dacac0859ec2f3104485720fe2451e21eb06e676f4860ecc73a41e6f9"
		hash5 = "fe948451df90df80c8028b969bf89ecbf501401e7879805667c134080976ce2e"

	strings:
		$x1 = "vG2eZ1KOeGd2n5fr" ascii fullword
		$s1 = "Windows %d(%d)-%s" ascii fullword
		$s2 = "auth_timestamp: " ascii fullword
		$s3 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36" wide fullword
		$op1 = { b8 c8 00 00 00 83 fb 01 44 0f 47 e8 41 8b c5 48 8b b4 24 e0 18 00 00 4c 8b a4 24 e8 18 00 00 48 8b 8d a0 17 00 00 48 33 cc }
		$op2 = { 33 d2 46 8d 04 b5 00 00 00 00 66 0f 1f 44 00 00 49 63 c0 41 ff c0 8b 4c 84 70 31 4c 94 40 48 ff c2 }
		$op3 = { 89 5c 24 50 0f 57 c0 c7 44 24 4c 04 00 00 00 c7 44 24 48 40 00 00 00 0f 11 44 24 60 0f 11 44 24 70 0f 11 45 80 0f 11 45 90 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 500KB and ( 1 of ( $x* ) or 2 of them ) or ( $x1 and 1 of ( $s* ) or 3 of them )
}

rule SIGNATURE_BASE_APT_UNC4736_NK_MAL_TAXHAUL_3CX_Apr23_1 : FILE
{
	meta:
		description = "Detects TAXHAUL (AKA TxRLoader) malware used in the 3CX compromise by UNC4736"
		author = "Mandiant"
		id = "25a80f98-03d6-59e6-84e6-6d847a6c591e"
		date = "2023-03-04"
		modified = "2023-12-05"
		reference = "https://www.3cx.com/blog/news/mandiant-initial-results/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_mal_gopuram_apr23.yar#L77-L90"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "f67af611d0b3d96e4aaf7b3b5e49c1fb536e61a430b79ac0a0560ef3773ba140"
		score = 80
		quality = 85
		tags = "FILE"

	strings:
		$p00_0 = {410f45fe4c8d3d[4]eb??4533f64c8d3d[4]eb??4533f64c8d3d[4]eb}
		$p00_1 = {4d3926488b01400f94c6ff90[4]41b9[4]eb??8bde4885c074}

	condition:
		uint16( 0 ) == 0x5A4D and any of them
}

rule SIGNATURE_BASE_MAL_APT_NK_Andariel_Scheduledtask_Loader : FILE
{
	meta:
		description = "Detects a scheduled task loader used by Andariel"
		author = "CISA.gov"
		id = "0c32758b-480c-5784-b28f-cee85d038850"
		date = "2024-07-25"
		modified = "2026-01-29"
		reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_nk_andariel_jul24.yar#L3-L18"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "2d32ee777cb40c6fa58787e92c0de074ea5b81d629a17ccb4f9432d62436f03c"
		score = 80
		quality = 85
		tags = "FILE"

	strings:
		$obfuscation1 = { B8 02 00 00 00 48 6B C0 00 B9 CD FF 00 00 66 89 8C 04 60 01 00 00 B8 02 00 00 00 48 6B C0 01 B9 CC FF 00 00 66 89 8C 04 60 01 00 00 B8 02 00 00 00 48 6B C0 02 B9 8D FF 00 00 66 89 8C 04 60 01 00 00 B8 02 00 00 00 48 6B C0 03 B9 9A FF 00 00 66 89 8C 04 60 01 00 00 B8 02 00 00 00 48 6B C0 04 B9 8C FF 00 00 66 89 8C 04 60 01 00 00 B8 02 00 00 00 48 6B C0 05 B9 8A FF 00 00 66 89 8C 04 60 01 00 00 B8 02 00 00 00 48 6B C0 06 33 C9 66 89 8C 04 60 01 00 00 }
		$obfuscation2 = { 48 6B C0 02 C6 44 04 20 BA B8 01 00 00 00 48 6B C0 03 C6 44 04 20 9A B8 01 00 00 00 48 6B C0 04 C6 44 04 20 8B B8 01 00 00 00 48 6B C0 05 C6 44 04 20 8A B8 01 00 00 00 48 6B C0 06 C6 44 04 20 9C B8 01 00 00 00 }
		$obfuscation3 = { 48 6B C0 00 C6 44 04 20 A8 B8 01 00 00 00 48 6B C0 01 C6 44 04 20 9A B8 01 00 00 00 48 6B C0 02 C6 44 04 20 93 B8 01 00 00 00 48 6B C0 03 C6 44 04 20 96 B8 01 00 00 00 48 6B C0 04 C6 44 04 20 B9 B8 01 00 00 00 48 6B C0 05 C6 44 04 20 9A B8 01 00 00 00 48 6B C0 06 C6 44 04 20 8B B8 01 00 00 00 48 6B C0 07 C6 44 04 20 9E B8 01 00 00 00 48 6B C0 08 C6 44 04 20 9A B8 01 00 00 00 48 6B C0 09 C6 44 04 20 8D B8 01 00 00 00 48 6B C0 0A C6 44 04 20 BC B8 01 00 00 00 }

	condition:
		uint16( 0 ) == 0x5A4D and $obfuscation1 and $obfuscation2 and $obfuscation3
}

rule SIGNATURE_BASE_MAL_APT_NK_Andariel_Kaosrat_Yamabot
{
	meta:
		description = "Detects the KaosRAT variant"
		author = "CISA.gov"
		id = "cdde69cd-1b38-52f5-8552-cef2cf4ad69c"
		date = "2024-07-25"
		modified = "2026-01-29"
		reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_nk_andariel_jul24.yar#L20-L42"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "92182aac2e56041292102b0486b7de1ee6eb3d54a9fc6786c567acd92073cd84"
		score = 70
		quality = 85
		tags = ""

	strings:
		$str1 = "/kaos/"
		$str2 = "Abstand ["
		$str3 = "] anwenden"
		$str4 = "cmVjYXB0Y2hh"
		$str5 = "/bin/sh"
		$str6 = "utilities.CIpaddress"
		$str7 = "engine.NewEgg"
		$str8 = "%s%04x%s%s%s"
		$str9 = "Y2FwdGNoYV9zZXNzaW9u"
		$str10 = "utilities.EierKochen"
		$str11 = "kandidatKaufhaus"

	condition:
		3 of them
}

rule SIGNATURE_BASE_MAL_APT_NK_Trifaux_Easyrat_JUPITER : FILE
{
	meta:
		description = "Detects a variant of the EasyRAT malware family"
		author = "CISA.gov"
		id = "8bd72287-59da-53cf-9015-66149303e59f"
		date = "2024-07-25"
		modified = "2026-01-29"
		reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_nk_andariel_jul24.yar#L44-L59"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "6108035dbebd34fe994fc1f8b4123321321f6ed5c022be6e84a88f905ea6fb73"
		score = 80
		quality = 85
		tags = "FILE"

	strings:
		$InitOnce = "InitOnceExecuteOnce"
		$BREAK = { 0D 00 0A 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 0D 00 0A }
		$Bytes = "4C,$00,$00,$00,$01,$14,$02,$00,$00,$00,$00,$00,$C0,$00,$00,$00,$00,$00,$00," wide

	condition:
		uint16( 0 ) == 0x5a4d and all of them
}

rule SIGNATURE_BASE_MAL_APT_NK_Andariel_Cutiedrop_Magicrat : FILE
{
	meta:
		description = "Detects the MagicRAT variant used by Andariel"
		author = "CISA.gov (modified by Florian Roth, Nextron Systems)"
		id = "104244de-83fb-5112-a2b6-e20d38a6ced6"
		date = "2024-07-25"
		modified = "2026-01-29"
		reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_nk_andariel_jul24.yar#L61-L85"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "f289bbd71bdeaf2c42063642454679ec26de5ed24c020af40db694a0ced54884"
		score = 80
		quality = 85
		tags = "FILE"

	strings:
		$config_os_w = "os/windows" ascii
		$config_os_l = "os/linux" ascii
		$config_os_m = "os/mac" ascii
		$config_comp_msft = "company/microsoft" ascii
		$config_comp_orcl = "company/oracle" ascii
		$POST_field_1 = "session=" ascii
		$POST_field_2 = "type=" ascii
		$command_misspelled = "renmae" ascii

	condition:
		uint16( 0 ) == 0x5a4d and 7 of them
}

rule SIGNATURE_BASE_MAL_APT_NK_Andariel_HHSD_Filetransfertool : FILE
{
	meta:
		description = "Detects a variant of the HHSD File Transfer Tool"
		author = "CISA.gov"
		id = "46b6dbaf-1272-5bbd-a586-5e48ba6c5022"
		date = "2024-07-25"
		modified = "2025-07-09"
		reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_nk_andariel_jul24.yar#L87-L125"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "665c1b27d64d5377be98aa4e629b077e56f3a44273d98653a338439b3dc05b65"
		score = 70
		quality = 85
		tags = "FILE"

	strings:
		$handshake = { 30 ?? ?? 81 7? ?? 22 C0 78 00 4? 88 }
		$err_xor_str = { 14 C7 [2] 14 00 41 00 C7 [2] 7A 00 7F 00 C7 [2] 7B 00 63 00 C7 [2] 7A 00 34 00 }
		$hash_call_loadlib = { B? 8D 10 B7 F8 E8 }
		$hash_call_unk = { B? 91 B8 F6 88 E8 }

	condition:
		uint16( 0 ) == 0x5a4d and 1 of ( $handshake , $err_xor_str ) and 1 of ( $hash_call_* ) or 2 of ( $handshake , $err_xor_str )
}

rule SIGNATURE_BASE_MAL_APT_NK_Andariel_Atharvan_3RAT : FILE
{
	meta:
		description = "Detects a variant of the Atharvan 3RAT malware family"
		author = "CISA.gov"
		id = "9ff6998a-a2dd-5671-bd3f-ee69561f71ef"
		date = "2024-07-25"
		modified = "2026-01-29"
		reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_nk_andariel_jul24.yar#L127-L141"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "741318234e245a35accc0b102a7891559ce5ef868ccdc3e6e4c8e59d8dea8b24"
		score = 80
		quality = 85
		tags = "FILE"

	strings:
		$3RAT = "D:\\rang\\TOOL\\3RAT"
		$atharvan = "Atharvan_dll.pdb"

	condition:
		uint16( 0 ) == 0x5a4d and 1 of them
}

rule SIGNATURE_BASE_MAL_APT_NK_Andariel_Lilithrat_Variant : FILE
{
	meta:
		description = "Detects a variant of the Lilith RAT malware family"
		author = "CISA.gov (modified by Florian Roth, Nextron Systems)"
		id = "916a289b-db7b-5f09-9d3e-589c3f09101d"
		date = "2024-07-25"
		modified = "2024-07-26"
		reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_nk_andariel_jul24.yar#L143-L178"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "3ce68908468ff85683b081842fa4faa579fbf6f7dc1a7fab5dcf7eac63d90aea"
		score = 80
		quality = 85
		tags = "FILE"

	strings:
		$lilith_1 = "Initiate a CMD session first." ascii
		$lilith_2 = "CMD is not open" ascii
		$lilith_3 = "Couldn't write command" ascii
		$lilith_4 = "Couldn't write to CMD: CMD not open" ascii
		$unique_1 = "Upload Error!" ascii
		$unique_2 = "ERROR: Downloading is already running!" ascii
		$unique_3 = "ERROR: Unable to open file:" ascii
		$unique_4 = "General error" ascii
		$unique_5 = "CMD error" ascii
		$unique_6 = "killing self" ascii

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 150KB and ( all of ( $lilith_* ) or 4 of ( $unique_* ) or 1 of ( $lilith_4 , $unique_2 ) )
}

rule SIGNATURE_BASE_MAL_APT_NK_Andariel_Sockstroy_Strings_Opcodes : FILE
{
	meta:
		description = "Detects a variant of the SocksTroy malware family"
		author = "CISA.gov"
		id = "9e7fb6ba-771e-5cae-a0d5-c0b95ee6d4e9"
		date = "2024-07-25"
		modified = "2026-01-29"
		reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_nk_andariel_jul24.yar#L180-L199"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "6ab31b285d0dba1745a2d8b172bd02931c6138e2b8e541203b88f111d179549b"
		score = 80
		quality = 85
		tags = "FILE"

	strings:
		$strHost = "-host" wide
		$strAuth = "-auth" wide
		$SocksTroy = "SocksTroy"
		$cOpCodeCheck = { 81 E? A0 00 00 00 0F 84 ?? ?? ?? ?? 83 E? 03 74 ?? 83 E? 02 74 ?? 83 F? 0B }

	condition:
		uint16( 0 ) == 0x5a4d and ( 1 of ( $str* ) and all of ( $c* ) or all of ( $Socks* ) )
}

rule SIGNATURE_BASE_MAL_APT_NK_Andariel_Agni : FILE
{
	meta:
		description = "Detects samples of the Agni malware family"
		author = "CISA.gov"
		id = "ffe3f427-c10a-5ad4-ab29-c0d9b576c30f"
		date = "2024-07-25"
		modified = "2026-01-29"
		reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_nk_andariel_jul24.yar#L201-L216"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "302899b65e5a3a6beabbb46e80e3f0ff246c209206cc3a7f871011d68871d0b9"
		score = 80
		quality = 85
		tags = "FILE"

	strings:
		$xor = { 34 ?? 88 01 48 8D 49 01 0F B6 01 84 C0 75 F1 }
		$stackstrings = { C7 44 24 [5-10] C7 44 24 [5] C7 44 24 [5-10] C7 44 24 [5-10] C7 44 24 }

	condition:
		uint16( 0 ) == 0x5a4d and #xor > 100 and #stackstrings > 5
}

rule SIGNATURE_BASE_MAL_APT_NK_Andariel_Golang_Validalpha_Handshake
{
	meta:
		description = "Detects a variant of the GoLang Validalpha malware"
		author = "CISA.gov"
		id = "51dafa43-9da0-569a-9123-7e9800284046"
		date = "2024-07-25"
		modified = "2026-01-29"
		reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_nk_andariel_jul24.yar#L218-L230"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "1978210d07d3298c0051c9faca16685636e3fb45131b4c2fcb7053a0b3ef84d1"
		score = 75
		quality = 85
		tags = ""

	strings:
		$ = { 66 C7 00 AB CD C6 40 02 EF ?? 03 00 00 00 48 89 C1 ?? 03 00 00 00 }

	condition:
		all of them
}

rule SIGNATURE_BASE_MAL_APT_NK_Andariel_Golang_Validalpha_Tasks
{
	meta:
		description = "Detects a variant of the GoLang Validalpha malware"
		author = "CISA.gov"
		id = "caa67a79-3ea6-5910-971c-f311722570ff"
		date = "2024-07-25"
		modified = "2026-01-29"
		reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_nk_andariel_jul24.yar#L232-L247"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "0d3fb944888b289d345ffc8dfcc988abd04b8cabd1729a66e8236f95ee6147ee"
		score = 80
		quality = 85
		tags = ""

	strings:
		$ = "main.ScreenMonitThread"
		$ = "main.CmdShell"
		$ = "main.GetAllFoldersAndFiles"
		$ = "main.SelfDelete"

	condition:
		all of them
}

rule SIGNATURE_BASE_MAL_APT_NK_Andariel_Golang_Validalpha_Blackstring : FILE
{
	meta:
		description = "Detects a variant of the GoLang Validalpha malware based on a file path found in the samples"
		author = "CISA.gov"
		id = "36f46a1d-69b6-5c99-9a54-6a14d62d2721"
		date = "2024-07-25"
		modified = "2026-01-29"
		reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_nk_andariel_jul24.yar#L249-L261"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "07ea38890e99dd53437a23b7c4002851604b69a83bd7fb8971609226249e5954"
		score = 90
		quality = 85
		tags = "FILE"

	strings:
		$ = "I:/01___Tools/02__RAT/Black"

	condition:
		uint16( 0 ) == 0x5A4D and all of them
}

rule SIGNATURE_BASE_MAL_APT_NK_Andariel_Grease2 : FILE
{
	meta:
		description = "Detects the Grease2 malware family used by Andariel"
		author = "CISA.gov (modified by Florian Roth, Nextron Systems)"
		id = "4defbe08-b3c6-5ab9-9a57-cec57ff42d9a"
		date = "2024-07-25"
		modified = "2024-07-26"
		reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_nk_andariel_jul24.yar#L330-L351"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "138fc915206e0c2834090ebc0a808913488121d51c17de3dbfadcb4099fbfa2f"
		score = 80
		quality = 85
		tags = "FILE"

	strings:
		$str_rdpconf = "emp\\RDPConf.exe"
		$str_rdpwinst = "emp\\RDPWInst.exe"
		$str_net_user = "net user"
		$str_admins_add = "net localgroup administrators"

	condition:
		uint16( 0 ) == 0x5A4D and all of them
}

rule SIGNATURE_BASE_MAL_APT_NK_Andariel_Nopineapple_Dtrack_Unpacked : FILE
{
	meta:
		description = "Detects the Dtrack variant used by Andariel"
		author = "CISA.gov"
		id = "6ccaf24b-c110-5788-a792-fa7f39fb18f7"
		date = "2024-07-25"
		modified = "2026-01-29"
		reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_nk_andariel_jul24.yar#L353-L368"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "cf5f92a66ba3ff4db61102dcc50b781e8dd14ca7cb1eb70dae8eba2ed0910b66"
		score = 80
		quality = 85
		tags = "FILE"

	strings:
		$str_nopineapple = "< No Pineapple! >"
		$str_qt_library = "Qt 5.12.10"
		$str_xor = { 8B 10 83 F6 ?? 83 FA 01 77 }

	condition:
		uint16( 0 ) == 0x5A4D and all of them
}

rule SIGNATURE_BASE_MAL_APT_NK_Andariel_Dtrack_Unpacked : FILE
{
	meta:
		description = "Detects DTrack variant used by Andariel"
		author = "CISA.gov (modified by Florian Roth, Nextron Systems)"
		id = "0c161275-2b2e-51a4-9e08-c118fb4c8671"
		date = "2024-07-25"
		modified = "2024-07-26"
		reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_nk_andariel_jul24.yar#L370-L393"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "d8de583fc0de01e6784305d28dbf7cea859a24cf4df1dc59356601bc830e4770"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$x_str_cmd_4 = "/c systeminfo > \"%s\" & tasklist > \"%s\" & netstat -naop tcp > \"%s\"" wide
		$x_str_cmd_2 = "/c ping -n 3 127.0.01 > NUL % echo EEE > \"%s\"" wide
		$str_mutex = "MTX_Global"
		$str_cmd_1 = "/c net use \\\\" wide
		$str_cmd_3 = "/c move /y %s \\\\" wide

	condition:
		uint16( 0 ) == 0x5A4D and ( 1 of ( $x* ) or 3 of them )
}

rule SIGNATURE_BASE_MAL_APT_NK_Andariel_Tigerrat_Crowdsourced_Rule : FILE
{
	meta:
		description = "Detects the Tiger RAT variant used by Andariel"
		author = "CISA.gov (modified by Florian Roth, Nextron Systems)"
		id = "6be65222-7d3c-5ff5-a9c7-d91dcf1deaa6"
		date = "2024-07-25"
		modified = "2024-07-26"
		reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_nk_andariel_jul24.yar#L395-L424"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "5d203d8c7e624796571f4597f70be0b8303f21c096640f25018cad29d4abc05b"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$m1 = ".?AVModuleKeyLogger@@" fullword ascii
		$m2 = ".?AVModulePortForwarder@@" fullword ascii
		$m3 = ".?AVModuleScreenCapture@@" fullword ascii
		$m4 = ".?AVModuleShell@@" fullword ascii
		$s1 = "\\x9891-009942-xnopcopie.dat" fullword wide
		$s2 = "(%02d : %02d-%02d %02d:%02d:%02d)--- %s[Clipboard]" fullword ascii
		$s3 = "[%02d : %02d-%02d %02d:%02d:%02d]--- %s[Title]" fullword ascii
		$s4 = "del \"%s\"%s \"%s\" goto " ascii

	condition:
		uint16( 0 ) == 0x5a4d and ( all of ( $s* ) or ( all of ( $m* ) and 1 of ( $s* ) ) or ( 2 of ( $m* ) and 2 of ( $s* ) ) )
}

rule SIGNATURE_BASE_MAL_APT_NK_WIN_Tiger_RAT_Auto : FILE
{
	meta:
		description = "Detects the Tiger RAT variant used by Andariel"
		author = "CISA.gov"
		id = "4579af62-52be-5f5f-a577-16ec50297c05"
		date = "2024-07-25"
		modified = "2026-01-29"
		reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_nk_andariel_jul24.yar#L426-L565"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "1deef66efb44c0d17f33508a8b6f0d6253f0308f309e81657f78eb0f87121bf5"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$sequence_0 = { 33 c0 89 44 24 38 89 44 24 30 44 8b cf 45 33 c0 }
		$sequence_1 = { 41 b9 01 00 00 00 48 8b d6 48 8b cb e8 ?? ?? ?? ?? }
		$sequence_2 = { 48 81 ec 90 05 00 00 8b 01 89 85 c8 04 00 00 8b 41 04 }
		$sequence_3 = { 48 8b 01 ff 10 48 8b 4f 08 4c 8d 4c 24 30 }
		$sequence_4 = { 48 8b 01 ff 10 48 8b 4e 18 48 8b 01 }
		$sequence_5 = { 48 81 ec a0 00 00 00 33 c0 48 8b d9 48 8d 4c 24 32 }
		$sequence_6 = { 48 8b 01 eb 03 48 8b c1 0f b6 00 }
		$sequence_7 = { 48 8b 01 8b 10 89 51 24 44 8b 41 24 45 85 c0 }
		$sequence_8 = { 4c 8d 0d 31 eb 00 00 c1 e9 18 c1 e8 08 41 bf 00 00 00 80 }
		$sequence_9 = { 48 8b d8 48 85 c0 75 2d ff 15 ?? ?? ?? ?? 83 f8 57 0f 85 e0 01 00 00 48 8d 0d a0 bd 00 00 }
		$sequence_10 = { 75 d4 48 8d 1d 7f 6c 01 00 48 8b 4b f8 48 85 c9 74 0b }
		$sequence_11 = { 0f 85 d9 00 00 00 48 8d 15 d0 c9 00 00 41 b8 10 20 01 00 48 8b cd e8 ?? ?? ?? ?? eb 6b b9 f4 ff ff ff }
		$sequence_12 = { 48 89 0d ?? ?? ?? ?? 48 89 05 ?? ?? ?? ?? 48 8d 05 ae 61 00 00 48 89 05 ?? ?? ?? ?? 48 8d 05 a0 55 00 00 48 89 05 ?? ?? ?? ?? }
		$sequence_13 = { 8b cf e8 ?? ?? ?? ?? 48 8b 7c 24 48 85 c0 0f 84 40 03 00 00 48 8d 05 60 25 01 00 }
		$sequence_14 = { ff 15 ?? ?? ?? ?? 8b 05 ?? ?? ?? ?? 23 05 ?? ?? ?? ?? ba 02 00 00 00 33 c9 89 05 ?? ?? ?? ?? 8b 05 ?? ?? ?? ?? }
		$sequence_15 = { 48 83 ec 30 49 8b d8 e8 ?? ?? ?? ?? 48 8b c8 48 85 c0 }

	condition:
		filesize < 600KB and 7 of them
}

rule SIGNATURE_BASE_MAL_APT_NK_WIN_Dtrack_Auto : FILE
{
	meta:
		description = "Detects DTrack variant used by Andariel"
		author = "CISA.gov"
		id = "1b40c685-beba-50fa-b484-c1526577cb23"
		date = "2024-07-25"
		modified = "2026-01-29"
		reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_nk_andariel_jul24.yar#L567-L706"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "2bd68ee6e5f35a9b80c07120beba3fe1f3ba9a9137ee15bb04bb2740381a9a44"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$sequence_0 = { 52 8b 45 08 50 e8 ?? ?? ?? ?? 83 c4 14 8b 4d 10 51 }
		$sequence_1 = { 3a 41 01 75 23 83 85 4c f6 ff ff 02 83 85 50 f6 ff ff 02 80 bd 4a f6 ff ff 00 75 ae c7 85 44 f6 ff ff 00 00 00 00 }
		$sequence_2 = { 50 ff 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 04 50 }
		$sequence_3 = { 8d 8d d4 fa ff ff 51 e8 ?? ?? ?? ?? 83 c4 08 8b 15 ?? ?? ?? ?? }
		$sequence_4 = { 88 55 f5 6a 5c 8b 45 0c 50 e8 ?? ?? ?? ?? }
		$sequence_5 = { 51 e8 ?? ?? ?? ?? 83 c4 10 8b 55 8c 52 }
		$sequence_6 = { 8b 4d 0c 51 68 ?? ?? ?? ?? 8d 95 60 ea ff ff 52 e8 ?? ?? ?? ?? }
		$sequence_7 = { 83 c0 01 89 45 f4 83 7d f4 20 7d 2c 8b 4d f8 }
		$sequence_8 = { 83 c0 01 89 85 6c f6 ff ff 8b 8d 70 f6 ff ff 8a 11 }
		$sequence_9 = { 03 55 f0 0f b6 02 0f b6 4d f7 33 c1 0f b6 55 fc 33 c2 }
		$sequence_10 = { d1 e9 89 4d f8 8b 55 18 89 55 fc c7 45 f0 00 00 00 00 }
		$sequence_11 = { 8b 4d f0 3b 4d 10 0f 8d 90 00 00 00 8b 55 08 03 55 f0 0f b6 02 }
		$sequence_12 = { 89 4d 14 8b 45 f8 c1 e0 18 8b 4d fc c1 e9 08 0b c1 }
		$sequence_13 = { 0b c1 89 45 18 8b 55 14 89 55 f8 }
		$sequence_14 = { 8b 55 14 89 55 f8 8b 45 18 89 45 fc e9 ?? ?? ?? ?? 8b e5 }

	condition:
		filesize < 1700KB and 7 of them
}

rule SIGNATURE_BASE_APT_UTA028_Forensicartefacts_Paloalto_CVE_2024_3400_Apr24_1 : SCRIPT CVE_2024_3400
{
	meta:
		description = "Detects forensic artefacts of APT UTA028 as found in a campaign exploiting the Palo Alto CVE-2024-3400 vulnerability"
		author = "Florian Roth"
		id = "32cf18ff-784d-5849-87f8-14ede7315188"
		date = "2024-04-15"
		modified = "2024-04-18"
		reference = "https://www.volexity.com/blog/2024/04/12/zero-day-exploitation-of-unauthenticated-remote-code-execution-vulnerability-in-globalprotect-cve-2024-3400/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/vuln_paloalto_cve_2024_3400_apr24.yar#L2-L25"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "1261eecca520daa0619859a45d2289d2c23c73be55e1a3849d2032a38e137f4d"
		score = 70
		quality = 85
		tags = "SCRIPT, CVE-2024-3400"

	strings:
		$x1 = "cmd = base64.b64decode(rst.group"
		$x2 = "f.write(\"/*\"+output+\"*/\")"
		$x3 = "* * * * * root wget -qO- http://"
		$x4 = "rm -f /var/appweb/sslvpndocs/global-protect/*.css"
		$x5a = "failed to unmarshal session(../"
		$x5b = "failed to unmarshal session(./../"
		$x6 = "rm -rf /opt/panlogs/tmp/device_telemetry/minute/*" base64
		$x7 = "$(uname -a) > /var/" base64

	condition:
		1 of them
}

rule SIGNATURE_BASE_APT_UNC2447_MAL_SOMBRAT_May21_1 : FILE
{
	meta:
		description = "Detects SombRAT samples from UNC2447 campaign"
		author = "Florian Roth (Nextron Systems)"
		id = "78b46bed-4fd4-596f-bba7-12243f467af3"
		date = "2021-05-01"
		modified = "2023-01-07"
		reference = "https://www.fireeye.com/blog/threat-research/2021/04/unc2447-sombrat-and-fivehands-ransomware-sophisticated-financial-threat.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_unc2447_sombrat.yar#L2-L36"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "6f2572745cbd68c5f2be5c64b160d2513938daba6da57523012491acc63cfee4"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "61e286c62e556ac79b01c17357176e58efb67d86c5d17407e128094c3151f7f9"
		hash2 = "99baffcd7a6b939b72c99af7c1e88523a50053ab966a079d9bf268aff884426e"

	strings:
		$x1 = "~arungvc" ascii fullword
		$s1 = "plugin64_" ascii
		$s2 = "0xUnknown" ascii fullword
		$s3 = "b%x.%s" ascii fullword
		$s4 = "/news" ascii
		$sc1 = { 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 73
               00 2E 00 65 00 78 00 65 00 00 00 00 00 00 00 00
               00 49 73 57 6F 77 36 34 50 72 6F 63 65 73 73 00
               00 6B 00 65 00 72 00 6E 00 65 00 6C 00 33 00 32
               00 00 00 00 00 00 00 00 00 47 00 6C 00 6F 00 62
               00 61 00 6C 00 5C 00 25 00 73 }
		$op1 = { 66 90 0f b6 45 80 32 44 0d 81 34 de 88 44 0d 81 48 ff c1 48 83 f9 19 72 e9 }
		$op2 = { 48 8b d0 66 0f 6f 05 ?1 ?? 0? 00 f3 0f 7f 44 24 68 66 89 7c 24 58 41 b8 10 00 00 00 4c 39 40 10 4c 0f 42 40 10 48 83 78 18 08 }
		$op3 = { 49 f7 b0 a0 00 00 00 42 0f b6 04 0a 41 30 44 33 fe 48 83 79 18 10 72 03 48 8b 09 33 d2 b8 05 00 00 00 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 3000KB and ( ( 1 of ( $x* ) and 1 of ( $s* ) ) or 3 of them ) or 5 of them
}

rule SIGNATURE_BASE_APT_UNC2447_PS1_WARPRISM_May21_1 : FILE
{
	meta:
		description = "Detects WARPRISM PowerShell samples from UNC2447 campaign"
		author = "Florian Roth (Nextron Systems)"
		id = "fa389a45-3b31-5a84-9882-49fd6ee8cac5"
		date = "2021-05-01"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2021/04/unc2447-sombrat-and-fivehands-ransomware-sophisticated-financial-threat.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_unc2447_sombrat.yar#L101-L119"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "09abac2be0f12d31dabfdae9e8a148a28887a2a5df003c7bcb56ba45f1c6a62c"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "3090bff3d16b0b150444c3bfb196229ba0ab0b6b826fa306803de0192beddb80"
		hash2 = "63ba6db8c81c60dd9f1a0c7c4a4c51e2e56883f063509ed7b543ad7651fd8806"
		hash3 = "b41a303a4caa71fa260dd601a796033d8bfebcaa6bd9dfd7ad956fac5229a735"

	strings:
		$x1 = "if ($MyInvocation.MyCommand.Path -match '\\S') {" ascii fullword
		$s1 = "[DllImport(\"kernel32.dll\")]public static extern IntPtr VirtualAlloc(IntPtr " ascii wide
		$s2 = "[Runtime.InteropServices.Marshal]::Copy($" ascii wide
		$s3 = "[System.Diagnostics.Process]::Start((-join(" ascii wide

	condition:
		filesize < 5000KB and 1 of ( $x* ) or 2 of them
}

rule SIGNATURE_BASE_APT_UNC2447_BAT_Runner_May21_1 : FILE
{
	meta:
		description = "Detects Batch script runners from UNC2447 campaign"
		author = "Florian Roth (Nextron Systems)"
		id = "0bacd4f7-421a-570f-9f74-5a19ab806dd0"
		date = "2021-05-01"
		modified = "2023-01-07"
		reference = "https://www.fireeye.com/blog/threat-research/2021/04/unc2447-sombrat-and-fivehands-ransomware-sophisticated-financial-threat.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_unc2447_sombrat.yar#L121-L135"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "f9872327f648e4421aa40ca3ce55df5d3eb5e8c5bc718ff62a3d4adac79217eb"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "ccacf4658ae778d02e4e55cd161b5a0772eb8b8eee62fed34e2d8f11db2cc4bc"

	strings:
		$x1 = "powershell.exe -c \"[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String([IO.File]::" ascii
		$x2 = "wwansvc.txt')))\" | powershell.exe -" ascii

	condition:
		filesize < 5000KB and 1 of them
}

rule SIGNATURE_BASE_APT_MAL_CISA_10365227_03_Clientuploader_Dec21 : FILE
{
	meta:
		description = "Detects ClientUploader onedrv"
		author = "CISA Code & Media Analysis"
		id = "4eeadb28-9312-5602-932a-36acb48772f4"
		date = "2021-12-23"
		modified = "2021-12-24"
		reference = "https://www.cisa.gov/uscert/ncas/analysis-reports/ar22-277a"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_stealer_cisa_ar22_277a.yar#L4-L23"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "76f552b2416ae2426b73a321485f34a611c2a3c1ca35791bc9f1834072dc28be"
		score = 80
		quality = 85
		tags = "FILE"
		hash1 = "84164e1e8074c2565d3cd178babd93694ce54811641a77ffdc8d1084dd468afb"

	strings:
		$s1 = "Decoder2"
		$s2 = "ClientUploader"
		$s3 = "AppDomain"
		$s4 = { 5F 49 73 52 65 70 47 ?? 44 65 63 6F 64 65 72 73 }
		$s5 = "LzmaDecoder"
		$s6 = "$ee1b3f3b-b13c-432e-a461-e52d273896a7"

	condition:
		uint16( 0 ) == 0x5a4d and all of them
}

rule SIGNATURE_BASE_APT_MAL_CISA_10365227_01_APPSTORAGE_Dec21 : APPSTORAGE FILE
{
	meta:
		description = "Detects AppStorage ntstatus msexch samples"
		author = "CISA Code & Media Analysis"
		id = "a44c5609-980f-5961-921c-6b1824cdd49c"
		date = "2021-12-23"
		modified = "2021-12-24"
		reference = "https://www.cisa.gov/uscert/ncas/analysis-reports/ar22-277a"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_stealer_cisa_ar22_277a.yar#L25-L46"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "6a46bc4efa1f22d9fc65d946dbaa7b94de6074e65c228373bb6001f152d5b603"
		score = 80
		quality = 85
		tags = "APPSTORAGE, FILE"
		family = "APPSTORAGE"
		hash1 = "157a0ffd18e05bfd90a4ec108e5458cbde01015e3407b3964732c9d4ceb71656"
		hash2 = "30191b3badf3cdbc65d0ffeb68e0f26cef10a41037351b0f562ab52fce7432cc"

	strings:
		$s1 = "026B924DD52F8BE4A3FEE8575DC"
		$s2 = "GetHDDId"
		$s3 = "AppStorage"
		$s4 = "AppDomain"
		$s5 = "$1e3e5580-d264-4c30-89c9-8933c948582c"
		$s6 = "hrjio2mfsdlf235d" wide

	condition:
		uint16( 0 ) == 0x5a4d and all of them
}

rule SIGNATURE_BASE_APT_MAL_CISA_10365227_02_Clientuploader_Dec21 : FILE
{
	meta:
		description = "Detects ClientUploader_mqsvn"
		author = "CISA Code & Media Analysis"
		id = "84351df9-e225-5c3f-9385-523246681a97"
		date = "2021-12-23"
		modified = "2021-12-24"
		reference = "https://www.cisa.gov/uscert/ncas/analysis-reports/ar22-277a"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_stealer_cisa_ar22_277a.yar#L48-L67"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "f9f82b4577568d0bd60bac0d3132ed7ffcb338f508a8689f3126f3d2440432ef"
		score = 80
		quality = 81
		tags = "FILE"
		hash1 = "3585c3136686d7d48e53c21be61bb2908d131cf81b826acf578b67bb9d8e9350"

	strings:
		$s1 = "UploadSmallFileWithStopWatch"
		$s2 = "UploadPartWithStopwatch"
		$s3 = "AppVClient"
		$s4 = "ClientUploader"
		$s5 = { 46 69 6C 65 43 6F 6E 74 61 69 6E 65 72 2E 46 69 6C 65 41 72 63 68 69 76 65 }
		$s6 = { 4F 6E 65 44 72 69 76 65 43 6C 69 65 6E 74 2E 4F 6E 65 44 72 69 76 65 }

	condition:
		uint16( 0 ) == 0x5a4d and all of them
}

rule SIGNATURE_BASE_APT_MAL_Maldoc_Cloudatlas_Oct20_1 : FILE
{
	meta:
		description = "Detects unknown maldoc dropper noticed in October 2020"
		author = "Florian Roth (Nextron Systems)"
		id = "e7caf2b2-caf2-5984-a792-8224f2641bda"
		date = "2020-10-13"
		modified = "2023-12-05"
		reference = "https://twitter.com/jfslowik/status/1316050637092651009"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_cloudatlas.yar#L2-L16"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "772bdd8ec89edf2054e675e9ecb321a7bfe0307a7086a4e5b65f8d8b8cf80ecc"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "7ba76b2311736dbcd4f2817c40dae78f223366f2404571cd16d6676c7a640d70"

	strings:
		$x1 = "https://msofficeupdate.org" wide

	condition:
		uint16( 0 ) == 0xcfd0 and filesize < 300KB and 1 of ( $x* )
}

rule SIGNATURE_BASE_APT_MAL_URL_Cloudatlas_Oct20_2 : FILE
{
	meta:
		description = "Detects unknown maldoc dropper noticed in October 2020 - file morgue6visible5bunny6culvert7ambo5nun1illuminate4.url"
		author = "Florian Roth (Nextron Systems)"
		id = "91f6362f-1793-58a3-a750-04ec9812b9df"
		date = "2020-10-13"
		modified = "2023-12-05"
		reference = "https://twitter.com/jfslowik/status/1316050637092651009"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_cloudatlas.yar#L18-L37"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "8bb60c262a34babbe8839f5d39d1c972eeb41ea77eaae02cc877d908c7033f13"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "a6a58b614a9f5ffa1d90b5d42e15521f52e2295f02c1c0e5cd9cbfe933303bee"

	strings:
		$hc1 = { 5B 49 6E 74 65 72 6E 65 74 53 68 6F 72 74 63 75
               74 5D 0D 0A 55 52 4C 3D 68 74 74 70 73 3A 2F 2F
               6D 73 6F 66 66 69 63 65 75 70 64 61 74 65 2E 6F
               72 67 }

	condition:
		uint16( 0 ) == 0x495b and filesize < 200 and $hc1 at 0
}

rule SIGNATURE_BASE_APT_MAL_LNX_Kobalos : FILE
{
	meta:
		description = "Kobalos malware"
		author = "Marc-Etienne M.Leveille"
		id = "dfa47e30-c093-57f6-af01-72a2534cc6f4"
		date = "2020-11-02"
		modified = "2023-12-05"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_lnx_kobalos.yar#L32-L57"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "48aec47b70633d4c8cb55d90a2e168f3c2027ef27cfe1cd5d30dcdc08a2ff717"
		score = 75
		quality = 85
		tags = "FILE"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$encrypted_strings_sizes = {
            05 00 00 00 09 00 00 00  04 00 00 00 06 00 00 00
            08 00 00 00 08 00 00 00  02 00 00 00 02 00 00 00
            01 00 00 00 01 00 00 00  05 00 00 00 07 00 00 00
            05 00 00 00 05 00 00 00  05 00 00 00 0A 00 00 00
        }
		$password_md5_digest = { 3ADD48192654BD558A4A4CED9C255C4C }
		$rsa_512_mod_header = { 10 11 02 00 09 02 00 }
		$strings_rc4_key = { AE0E05090F3AC2B50B1BC6E91D2FE3CE }

	condition:
		uint16( 0 ) == 0x457f and any of them
}

rule SIGNATURE_BASE_APT_MAL_LNX_Kobalos_SSH_Credential_Stealer : FILE
{
	meta:
		description = "Kobalos SSH credential stealer seen in OpenSSH client"
		author = "Marc-Etienne M.Leveille"
		id = "0f923f92-c5d8-500d-9a2e-634ca7945c5c"
		date = "2020-11-02"
		modified = "2023-12-05"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_lnx_kobalos.yar#L59-L76"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "fdabaea0c838e43b8716bcd102bdeebf2f08fc041b0b909333e3d9d6f94391fc"
		score = 75
		quality = 85
		tags = "FILE"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$ = "user: %.128s host: %.128s port %05d user: %.128s password: %.128s"

	condition:
		uint16( 0 ) == 0x457f and any of them
}

rule SIGNATURE_BASE_APT_APT29_NOBELIUM_JS_Envyscout_May21_1 : FILE
{
	meta:
		description = "Detects EnvyScout deobfuscator code as used by NOBELIUM group"
		author = "Florian Roth (Nextron Systems)"
		id = "42739aad-a88a-545b-8256-1f727c79c4f8"
		date = "2021-05-29"
		modified = "2025-03-21"
		reference = "https://www.microsoft.com/security/blog/2021/05/28/breaking-down-nobeliums-latest-early-stage-toolset/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_apt29_nobelium_may21.yar#L56-L67"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "ad8a7bb5a1d2065e3a573842fb37ee3c63b7695c18840f0c26d32e6ae3d99c6c"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$x1 = "[i].charCodeAt(0) ^ 2);}"

	condition:
		filesize < 5000KB and 1 of them
}

rule SIGNATURE_BASE_APT_APT29_NOBELIUM_JS_Envyscout_May21_2 : FILE
{
	meta:
		description = "Detects EnvyScout deobfuscator code as used by NOBELIUM group"
		author = "Florian Roth (Nextron Systems)"
		id = "d5cf3365-fe24-533a-a678-b5b6d4d99997"
		date = "2021-05-29"
		modified = "2025-03-21"
		reference = "https://www.microsoft.com/security/blog/2021/05/28/breaking-down-nobeliums-latest-early-stage-toolset/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_apt29_nobelium_may21.yar#L69-L83"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "6f5c50b340d628559799897a2ba79add7d126e3ecb2daeb365bc15d64796ccd2"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "saveAs(blob, " ascii
		$s2 = ".iso\");" ascii
		$s3 = "application/x-cd-image" ascii
		$s4 = ".indexOf(\"Win\")!=-1" ascii

	condition:
		filesize < 5000KB and all of them
}

rule SIGNATURE_BASE_APT_APT29_NOBELIUM_LNK_NV_Link_May21_2 : FILE
{
	meta:
		description = "Detects NV Link as used by NOBELIUM group"
		author = "Florian Roth (Nextron Systems)"
		id = "52c2caf9-13df-5614-9c9e-afcd76ec77f9"
		date = "2021-05-29"
		modified = "2025-03-21"
		reference = "https://www.microsoft.com/security/blog/2021/05/28/breaking-down-nobeliums-latest-early-stage-toolset/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_apt29_nobelium_may21.yar#L85-L97"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "5eee9df368da3fc98c00a0f8c65a7f3bd5b812342082be58054b272b5bb03455"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "RegisterOCX BOOM" ascii wide
		$s2 = "cmd.exe /c start BOOM.exe" ascii wide

	condition:
		filesize < 5000KB and 1 of them
}

rule SIGNATURE_BASE_APT_APT29_NOBELIUM_LNK_Samples_May21_1 : FILE
{
	meta:
		description = "Detects link file characteristics as described in APT29 NOBELIUM report"
		author = "Florian Roth (Nextron Systems)"
		id = "c807ab5a-f66a-5622-81b1-6e69b6df8446"
		date = "2021-05-27"
		modified = "2025-03-21"
		reference = "https://www.microsoft.com/security/blog/2021/05/27/new-sophisticated-email-based-attack-from-nobelium/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_apt29_nobelium_may21.yar#L99-L128"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "32d76bb1af76f0fc2afb76d9726bc8ec99c4be34c9d46cebab7356d8c68af11c"
		score = 85
		quality = 85
		tags = "FILE"
		hash1 = "24caf54e7c3fe308444093f7ac64d6d520c8f44ea4251e09e24931bdb72f5548"

	strings:
		$a1 = "rundll32.exe" wide
		$sa1 = "IMGMountingService.dll" wide
		$sa2 = "MountImgHelper" wide
		$sb1 = "diassvcs.dll" wide
		$sb2 = "InitializeComponent" wide
		$sc1 = "MsDiskMountService.dll" wide
		$sc2 = "DiskDriveIni" wide
		$sd1 = "GraphicalComponent.dll" wide
		$sd2 = "VisualServiceComponent" wide
		$se1 = "data/mstu.dll,MicrosoftUpdateService" wide

	condition:
		uint16( 0 ) == 0x004c and filesize < 4KB and $a1 and ( all of ( $sa* ) or all of ( $sb* ) or all of ( $sc* ) or all of ( $sd* ) or all of ( $se* ) )
}

rule SIGNATURE_BASE_APT_APT29_NOBELIUM_Boombox_May21_1 : FILE
{
	meta:
		description = "Detects BoomBox malware as described in APT29 NOBELIUM report"
		author = "Florian Roth"
		id = "1a14dcf7-81be-5a74-a530-caf6268d1976"
		date = "2021-05-27"
		modified = "2025-03-20"
		reference = "https://www.microsoft.com/security/blog/2021/05/27/new-sophisticated-email-based-attack-from-nobelium/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_apt29_nobelium_may21.yar#L130-L161"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		hash = "8199f309478e8ed3f03f75e7574a3e9bce09b4423bd7eb08bb5bff03af2b7c27"
		logic_hash = "034ea34eb34ea6de0c65b9a7fc9d16f108ef34cd75294b022371ac17789c3830"
		score = 85
		quality = 85
		tags = "FILE"

	strings:
		$a1 = "]::FromBase64String($" ascii wide
		$xa1 = "123do3y4r378o5t34onf7t3o573tfo73" ascii wide fullword
		$xa2 = "1233t04p7jn3n4rg" ascii wide fullword
		$s1 = "\\Release\\BOOM.pdb" ascii
		$s2 = "/files/upload" ascii
		$s3 = "/tmp/readme.pdf" ascii fullword
		$s4 = "/new/{0}" ascii fullword
		$s5 = "(&(objectClass=user)(objectCategory=person))"

	condition:
		( uint16( 0 ) == 0x5a4d or 1 of ( $a* ) ) and ( 1 of ( $x* ) or 3 of ( $s* ) )
}

rule SIGNATURE_BASE_APT_APT29_NOBELIUM_Nativezone_Loader_May21_1 : FILE
{
	meta:
		description = "Detects NativeZone loader as described in APT29 NOBELIUM report"
		author = "Florian Roth (Nextron Systems)"
		id = "02d9257d-f439-5071-96b0-a973b088e329"
		date = "2021-05-27"
		modified = "2025-03-21"
		reference = "https://www.microsoft.com/security/blog/2021/05/27/new-sophisticated-email-based-attack-from-nobelium/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_apt29_nobelium_may21.yar#L184-L204"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "a02fd6fcd7423781bbd2e4458bd61d28e16a5b1a73b1682e63db5c86d53c7da4"
		score = 85
		quality = 85
		tags = "FILE"
		hash1 = "136f4083b67bc8dc999eb15bb83042aeb01791fc0b20b5683af6b4ddcf0bbc7d"

	strings:
		$s1 = "\\SystemCertificates\\Lib\\CertPKIProvider.dll" ascii
		$s2 = "rundll32.exe %s %s" ascii fullword
		$s3 = "eglGetConfigs" ascii fullword
		$op1 = { 80 3d 74 8c 01 10 00 0f 85 96 00 00 00 33 c0 40 b9 6c 8c 01 10 87 01 33 db 89 5d fc }
		$op2 = { 8b 46 18 e9 30 ff ff ff 90 87 2f 00 10 90 2f 00 10 }
		$op3 = { e8 14 dd ff ff 8b f1 80 3d 74 8c 01 10 00 0f 85 96 00 00 00 33 c0 40 b9 6c 8c 01 10 87 01 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 3000KB and 3 of them or 4 of them
}

rule SIGNATURE_BASE_APT_APT29_NOBELIUM_Boombox_May21_2 : FILE
{
	meta:
		description = "Detects BoomBox malware used by APT29 / NOBELIUM"
		author = "Florian Roth (Nextron Systems)"
		id = "a4144c00-48b2-5520-b773-5d0a5de95fb1"
		date = "2021-05-29"
		modified = "2025-03-21"
		reference = "https://www.microsoft.com/security/blog/2021/05/28/breaking-down-nobeliums-latest-early-stage-toolset/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_apt29_nobelium_may21.yar#L206-L234"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "2a3829e704af2464639d07e8e7952669281e20cf2a7ac487d5d1eee021d08b35"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "0acb884f2f4cfa75b726cb8290b20328c8ddbcd49f95a1d761b7d131b95bafec"
		hash2 = "8199f309478e8ed3f03f75e7574a3e9bce09b4423bd7eb08bb5bff03af2b7c27"
		hash3 = "cf1d992f776421f72eabc31d5afc2f2067ae856f1c9c1d6dc643a67cb9349d8c"

	strings:
		$x1 = "\\Microsoft\\NativeCache\\NativeCacheSvc.dll" wide
		$x2 = "\\NativeCacheSvc.dll _configNativeCache" wide
		$a1 = "/content.dropboxapi.com" wide fullword
		$s1 = "rundll32.exe {0} {1}" wide fullword
		$s2 = "\\\\CertPKIProvider.dll" wide
		$s3 = "/tmp/readme.pdf" wide
		$s4 = "temp/[^\"]*)\"" wide fullword
		$op1 = { 00 78 00 2d 00 41 00 50 00 49 00 2d 00 41 00 72 00 67 00 01 2f 4f 00 72 00 }
		$op2 = { 25 72 98 01 00 70 6f 34 00 00 0a 25 6f 35 00 00 0a 72 71 02 00 70 72 }
		$op3 = { 4d 05 20 00 12 80 91 04 20 01 08 0e 04 20 00 12 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 40KB and 3 of them or 4 of them
}

rule SIGNATURE_BASE_APT_APT29_NOBELIUM_Malware_May21_2 : FILE
{
	meta:
		description = "Detects malware used by APT29 / NOBELIUM"
		author = "Florian Roth (Nextron Systems)"
		id = "b1462b4b-227f-5aeb-92ea-bda6a86831c7"
		date = "2021-05-29"
		modified = "2025-03-21"
		reference = "https://www.microsoft.com/security/blog/2021/05/28/breaking-down-nobeliums-latest-early-stage-toolset/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_apt29_nobelium_may21.yar#L236-L252"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "18a52f5fd71455b8564d4b485c233dd358a304bfddc5e6fb604b8e5a2a1949a3"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "292e5b0a12fea4ff3fc02e1f98b7a370f88152ce71fe62670dd2f5edfaab2ff8"
		hash2 = "776014a63bf3cc7034bd5b6a9c36c75a930b59182fe232535bb7a305e539967b"

	strings:
		$op1 = { 48 03 c8 42 0f b6 04 21 88 03 0f b6 43 01 8b c8 83 e0 0f 48 83 e1 f0 48 03 c8 }
		$op2 = { 48 03 c8 42 0f b6 04 21 88 43 01 41 0f b6 c7 8b c8 83 e0 0f 48 83 e1 f0 48 03 c8 }
		$op3 = { 45 0f b6 43 ff 41 8b c2 99 44 88 03 41 0f b6 2b 83 e2 03 03 c2 40 88 6b 01 }

	condition:
		filesize < 2200KB and all of them
}

rule SIGNATURE_BASE_APT_APT29_NOBELIUM_Stageless_Loader_May21_2 : FILE
{
	meta:
		description = "Detects stageless loader as used by APT29 / NOBELIUM"
		author = "Florian Roth (Nextron Systems)"
		id = "7b83d327-52fc-5401-ae35-00f6b825678a"
		date = "2021-05-29"
		modified = "2025-03-21"
		reference = "https://www.microsoft.com/security/blog/2021/05/28/breaking-down-nobeliums-latest-early-stage-toolset/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_apt29_nobelium_may21.yar#L254-L276"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "850f6a1ad342fd5e4bb29c7bf90a032ddd8ac9d2eac5ffcbedf43e4d04b178f5"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "a4f1f09a2b9bc87de90891da6c0fca28e2f88fd67034648060cef9862af9a3bf"
		hash2 = "c4ff632696ec6e406388e1d42421b3cd3b5f79dcb2df67e2022d961d5f5a9e78"

	strings:
		$x1 = "DLL_stageless.dll" ascii fullword
		$s1 = "c:\\users\\devuser\\documents" ascii fullword nocase
		$s2 = "VisualServiceComponent" ascii fullword
		$s3 = "CheckUpdteFrameJavaCurrentVersion" ascii fullword
		$op1 = { a3 d? 6? 04 10 ff d6 33 05 00 ?0 0? 10 68 d8 d4 00 10 57 a3 d? 6? 04 10 ff d6 33 05 00 ?0 0? 10 }
		$op2 = { ff d6 33 05 00 ?0 0? 10 68 d8 d4 00 10 57 a3 d? 6? 04 10 ff d6 33 05 00 ?0 0? 10 68 e8 d4 00 10 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 900KB and 2 of them or 3 of them
}

rule SIGNATURE_BASE_APT_APT29_NOBELIUM_Malware_May21_3 : FILE
{
	meta:
		description = "Detects malware used by APT29 / NOBELIUM"
		author = "Florian Roth (Nextron Systems)"
		id = "89cb6884-4242-5b5a-b0ac-b31041dd261c"
		date = "2021-05-29"
		modified = "2025-03-21"
		reference = "https://www.microsoft.com/security/blog/2021/05/28/breaking-down-nobeliums-latest-early-stage-toolset/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_apt29_nobelium_may21.yar#L278-L300"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "472acd1d6daf3480de59ecd3fa038d644e339dcc979cf7e56617eadc6cb32dc5"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "2a352380d61e89c89f03f4008044241a38751284995d000c73acf9cad38b989e"

	strings:
		$s1 = "Win32Project1.dll" ascii fullword
		$op1 = { 59 c3 6a 08 68 70 5e 01 10 e8 d2 8c ff ff 8b 7d 08 8b c7 c1 f8 05 }
		$op2 = { 8d 4d f0 e8 c4 12 00 00 68 64 5b 01 10 8d 45 f0 c7 45 f0 6c 01 01 10 50 e8 ea 13 00 00 cc }
		$op4 = { 40 c3 8b 65 e8 e8 a6 86 ff ff cc 6a 0c 68 88 60 01 10 e8 b0 4d ff ff }
		$xc1 = { 25 73 25 73 00 00 00 00 2F 65 2C 20 00 00 00 00
               43 00 3A 00 5C 00 77 00 69 00 6E 00 64 00 6F 00
               77 00 73 00 5C 00 65 00 78 00 70 00 6C 00 6F 00
               72 00 65 00 72 00 2E 00 65 00 78 00 65 }

	condition:
		filesize < 3000KB and ( $xc1 or 3 of them )
}

rule SIGNATURE_BASE_APT_APT29_NOBELIUM_Malware_May21_4 : FILE
{
	meta:
		description = "Detects malware used by APT29 / NOBELIUM"
		author = "Florian Roth (Nextron Systems)"
		id = "56193475-52b4-5720-abc5-72249e2a0c37"
		date = "2021-05-29"
		modified = "2025-03-21"
		reference = "https://www.microsoft.com/security/blog/2021/05/28/breaking-down-nobeliums-latest-early-stage-toolset/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_apt29_nobelium_may21.yar#L302-L323"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "7d5858cc6dab094d5dceab75a2002d9145537008241a08ac7bd399c9d6e6c270"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "3b94cc71c325f9068105b9e7d5c9667b1de2bde85b7abc5b29ff649fd54715c4"

	strings:
		$s1 = "KM.FileSystem.dll" ascii fullword
		$op1 = { 80 3d 50 6b 04 10 00 0f 85 96 00 00 00 33 c0 40 b9 48 6b 04 10 87 01 33 db 89 5d fc }
		$op2 = { c3 33 c0 b9 7c 6f 04 10 40 87 01 c3 8b ff 55 }
		$op3 = { 8d 4d f4 e8 53 ff ff ff 68 d0 22 01 10 8d 45 f4 50 e8 d8 05 00 00 cc 8b 41 04 }
		$xc1 = { 2E 64 6C 6C 00 00 00 00 41 53 4B 4F 44 00 00 00
               53 75 63 63 65 73 73 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 3000KB and ( $xc1 or 3 of them )
}

rule SIGNATURE_BASE_M_APT_VIRTUALPITA_2 : FILE
{
	meta:
		description = "Finds opcodes to decode and parse the recieved data in the socket buffer in fe34b7c071d96dac498b72a4a07cb246.  Opcodes from 401a36 to 401adc"
		author = "Mandiant"
		id = "6a59cc54-e1a0-594f-9efb-af63d5c05259"
		date = "2022-10-01"
		modified = "2025-12-19"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_unc3886_virtualpita.yar#L15-L25"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		hash = "fe34b7c071d96dac498b72a4a07cb246"
		logic_hash = "56a3e1b13f0955a780f882e62003f721e409a1fdf61120dd295941605dbf21a4"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$x = { 85 c0 74 ?? c7 05 ?? ?? ?? ?? fb ff ff ff c7 8? ?? ?? ?? ?? 00 00 00 00 e9 ?? ?? ?? ?? 4? 8b 05 ?? ?? ?? ?? 4? 83 c0 01 4? 89 05 ?? ?? ?? ?? c7 4? ?? 00 00 00 00 e9 ?? ?? ?? ?? 8b 4? ?? 4? 98 4? 8d 9? ?? ?? ?? ?? 4? 8d ?? e0 4? 8b 0? 4? 89 0? 4? 8b 4? ?? 4? 89 4? ?? 8b 4? ?? 4? 98 4? 8d b? ?? ?? ?? ?? b? ?? ?? ?? ?? e8 ?? ?? ?? ?? c7 4? ?? 00 00 00 00 eb ?? 8b 4? ?? 8b 4? ?? 01 c1 8b 4? ?? 03 4? ?? 4? 98 0f b6 9? ?? ?? ?? ?? 8b 4? ?? 4? 98 0f b6 8? ?? ?? ?? ?? 31 c2 4? 63 c1 88 9? ?? ?? ?? ?? 83 4? ?? 01 }

	condition:
		uint32( 0 ) == 0x464c457f and all of them
}

rule SIGNATURE_BASE_M_APT_VIRTUALPITA_3 : FILE
{
	meta:
		description = "Finds opcodes from 409dd8 to 409e46 in fe34b7c071d96dac498b72a4a07cb246 to set the HISTFILE environment variable to 'F' with a putenv() after loading each character individually."
		author = "Mandiant"
		id = "29ea2db0-4ab2-5e9c-8d42-7590ceabf99a"
		date = "2022-10-01"
		modified = "2025-12-19"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_unc3886_virtualpita.yar#L27-L37"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		hash = "fe34b7c071d96dac498b72a4a07cb246"
		logic_hash = "6f44d516b3cbe54542ae0991aad49274fc4728570e9498b319fc98840ceb7d7d"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$x = { 4? 8b 4? ?? c6 00 48 4? 8b 4? ?? 4? 83 c0 05 c6 00 49 4? 8b 4? ?? 4? 83 c0 01 c6 00 49 4? 8b 4? ?? 4? 83 c0 06 c6 00 4c 4? 8b 4? ?? 4? 83 c0 02 c6 00 53 4? 8b 4? ?? 4? 83 c0 07 c6 00 45 4? 8b 4? ?? 4? 83 c0 03 c6 00 54 4? 8b 4? ?? 4? 83 c0 08 c6 00 3d 4? 8b 4? ?? 4? 83 c0 04 c6 00 46 4? 8b 4? ?? 4? 83 c0 09 c6 00 00 4? 8b 7? ?? e8 }

	condition:
		uint32( 0 ) == 0x464c457f and all of them
}

rule SIGNATURE_BASE_M_APT_VIRTUALPITA_4 : FILE
{
	meta:
		description = "Finds opcodes from 401f1c to 401f4f in fe34b7c071d96dac498b72a4a07cb246 to decode text with multiple XORs"
		author = "Mandiant"
		id = "58d4db75-fcd5-50c2-93ba-a8a4718ac0f6"
		date = "2022-10-01"
		modified = "2025-12-19"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_unc3886_virtualpita.yar#L39-L50"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		hash = "fe34b7c071d96dac498b72a4a07cb246"
		logic_hash = "aaf2ff682c619d2a254fe069d477654a161658db6315239f1b956141b6a72c01"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$x = { 4? 8b 4? ?? 4? 83 c1 30 4? 8b 4? ?? 4? 8b 10 8b 4? ?? 4? 98 4? 8b 04 ?? ?? ?? ?? ?? 4? 31 c2 4? 8b 4? ?? 4? 83 c0 28 4? 8b 00 4? c1 e8 10 0f b6 c0 4? 98 4? 8b 04 }

	condition:
		uint32( 0 ) == 0x464c457f and all of them
}

rule SIGNATURE_BASE_APT_MAL_LNX_Turla_Apr20_1 : FILE
{
	meta:
		description = "Detects Turla Linux malware"
		author = "Florian Roth (Nextron Systems)"
		id = "f21e7793-a7dd-5195-805d-963827b35808"
		date = "2020-04-05"
		modified = "2023-12-05"
		reference = "https://twitter.com/Int2e_/status/1246115636331319309"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_turla.yar#L252-L272"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "d463f5a151bb0c3440d719b4c7c0d1ca34de1e0bed7fb9167ecf396607abd3ff"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "67d9556c695ef6c51abf6fbab17acb3466e3149cf4d20cb64d6d34dc969b6502"
		hash2 = "8ccc081d4940c5d8aa6b782c16ed82528c0885bbb08210a8d0a8c519c54215bc"

	strings:
		$s1 = "/root/.hsperfdata" ascii fullword
		$s2 = "Desc|     Filename     |  size  |state|" ascii fullword
		$s3 = "IPv6 address %s not supported" ascii fullword
		$s4 = "File already exist on remote filesystem !" ascii fullword
		$s5 = "/tmp/.sync.pid" ascii fullword
		$s6 = "'gateway' supported only on ethernet/FDDI/token ring/802.11/ATM LANE/Fibre Channel" ascii fullword

	condition:
		uint16( 0 ) == 0x457f and filesize < 5000KB and 4 of them
}

rule SIGNATURE_BASE_APT_MAL_Tinyturla_Sep21_1 : FILE
{
	meta:
		description = "Detects Tiny Turla backdoor DLL"
		author = "Cisco Talos"
		id = "19659ac7-310a-52dd-a94c-022c7add752b"
		date = "2021-09-21"
		modified = "2023-12-05"
		reference = "https://blog.talosintelligence.com/2021/09/tinyturla.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_turla.yar#L275-L295"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "ede598374bc4a8a870aa29498be4200b4a3d7b289dfcb680fb3f91108d212bca"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "030cbd1a51f8583ccfc3fa38a28a5550dc1c84c05d6c0f5eb887d13dedf1da01"

	strings:
		$a = "Title: " fullword wide
		$b = "Hosts" fullword wide
		$c = "Security" fullword wide
		$d = "TimeLong" fullword wide
		$e = "TimeShort" fullword wide
		$f = "MachineGuid" fullword wide
		$g = "POST" fullword wide
		$h = "WinHttpSetOption" fullword ascii
		$i = "WinHttpQueryDataAvailable" fullword ascii

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 25KB and all of them
}

rule SIGNATURE_BASE_APT_IIS_Config_Proxyshell_Artifacts : FILE
{
	meta:
		description = "Detects virtual directory configured in IIS pointing to a ProgramData folder (as found in attacks against Exchange servers in August 2021)"
		author = "Florian Roth (Nextron Systems)"
		id = "21888fc0-82c6-555a-9320-9cbb8332a843"
		date = "2021-08-25"
		modified = "2025-11-03"
		reference = "https://www.huntress.com/blog/rapid-response-microsoft-exchange-servers-still-vulnerable-to-proxyshell-exploit"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/expl_proxyshell.yar#L82-L105"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "a4557694629448d258b8b2fefc278e059217560e7a0ec3279863a16fb9b3989c"
		score = 90
		quality = 85
		tags = "FILE"

	strings:
		$a1 = "<site name=" ascii
		$a2 = "<sectionGroup name=\"system.webServer\">" ascii
		$sa1 = " physicalPath=\"C:\\ProgramData\\COM" ascii
		$sa2 = " physicalPath=\"C:\\ProgramData\\WHO" ascii
		$sa3 = " physicalPath=\"C:\\ProgramData\\ZING" ascii
		$sa4 = " physicalPath=\"C:\\ProgramData\\ZOO" ascii
		$sa5 = " physicalPath=\"C:\\ProgramData\\XYZ" ascii
		$sa6 = " physicalPath=\"C:\\ProgramData\\AUX" ascii
		$sa7 = " physicalPath=\"C:\\ProgramData\\CON\\" ascii
		$sb1 = " physicalPath=\"C:\\Users\\All Users\\" ascii

	condition:
		filesize < 500KB and all of ( $a* ) and 1 of ( $s* )
}

rule SIGNATURE_BASE_APT_NK_MAL_Keylogger_Unknown_Nov19_1 : FILE
{
	meta:
		description = "Detects unknown keylogger reported by CNMF in November 2019"
		author = "Florian Roth (Nextron Systems)"
		id = "5311d883-52e0-5503-9494-c583fabbedfe"
		date = "2019-11-06"
		modified = "2023-12-05"
		reference = "https://twitter.com/CNMF_VirusAlert/status/1192131508007505921"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_nk_gen.yar#L2-L35"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "a3b5c82cb8aa09e3c1b955bb175046e86f96da1f187eb46df83caaaf9e1370b2"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "04d70bb249206a006f83db39bbe49ff6e520ea329e5fbb9c758d426b1c8dec30"
		hash2 = "618a67048d0a9217317c1d1790ad5f6b044eaa58a433bd46ec2fb9f9ff563dc6"

	strings:
		$x1 = "CKeyLogDlg::Keylogger_WriteFile" ascii
		$x2 = "Keylog file is saved >>>>>> %s" fullword ascii
		$x3 = "MicCap file is saved >>>>>> %s" fullword ascii
		$x4 = "cr5cr33nc4p.dat" fullword ascii
		$xc1 = { 73 74 61 74 75 73 00 00 5C 4B 65 79 6C 6F 67 }
		$xc2 = { 5B 43 4D 69 63 43 61 70 44 6C 67 5D 2E 00 00 00
               25 30 34 64 25 30 32 64 25 30 32 64 25 30 32 64
               25 30 32 64 2E 77 61 76 }
		$xc3 = { 25 73 00 00 25 73 5C 2A 2E 2A 00 00 61 62 00 00
               5B 25 73 5D 20 75 70 6C 6F 61 64 20 66 61 69 6C
               65 64 2E 00 72 62 00 00 5B 25 73 5D 20 6F 70 65
               6E 20 66 61 69 6C 65 64 2E 00 00 00 2E 2E 00 00
               5B 25 73 20 2D 3E 20 25 73 5D 20 63 6F 70 79 20
               66 61 69 6C 65 64 }
		$s1 = "%s\\cmd.exe /c %s" fullword ascii
		$s2 = "File upload error occured in [CFSDlg::ProcessResultMessage]." fullword ascii
		$s3 = "\\SAM\\Domains\\Account\\Users\\Names" ascii
		$s4 = "%s_hist%d:%d:%s:%s:::" fullword ascii
		$s5 = "CARAT_Ws2_32.dll" fullword ascii
		$s6 = "PID [%s], open process failed." fullword ascii

	condition:
		uint16( 0 ) == 0x5a4d and filesize <= 40000KB and ( 1 of ( $x* ) or 4 of them )
}

rule SIGNATURE_BASE_APT_SH_Codecov_Hack_Apr21_1 : FILE
{
	meta:
		description = "Detects manipulated Codecov bash uploader tool that has been manipulated by an unknown actor during March / April 2021"
		author = "Florian Roth (Nextron Systems)"
		id = "b5fb74c4-073e-53af-a207-1672e63c9a64"
		date = "2021-04-16"
		modified = "2023-12-05"
		reference = "https://about.codecov.io/security-update/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/mal_codecov_hack.yar#L2-L17"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "1aa7723982a1b675ba6694f1af0eb28e5926b974874580bd727cf33a3f8d893a"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$a1 = "Global report uploading tool for Codecov"
		$s1 = "curl -sm 0.5 -d"

	condition:
		uint16( 0 ) == 0x2123 and filesize < 70KB and all of them
}

rule SIGNATURE_BASE_APT_CN_MAL_Reddelta_Shellcode_Loader_Oct20_1 : FILE
{
	meta:
		description = "Detects Red Delta samples"
		author = "Florian Roth (Nextron Systems)"
		id = "47417488-e843-5346-9baa-fcce30b884d1"
		date = "2020-10-14"
		modified = "2023-12-05"
		reference = "https://twitter.com/JAMESWT_MHT/status/1316387482708119556"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_cn_reddelta.yar#L2-L29"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "1f2406563b863b8ccd0fd8d8d33c576c4b82dabb55a1e4fa8291859323389834"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "30b2bbce0ca4cb066721c94a64e2c37b7825dd72fc19c20eb0ab156bea0f8efc"
		hash2 = "42ed73b1d5cc49e09136ec05befabe0860002c97eb94e9bad145e4ea5b8be2e2"
		hash3 = "480a8c883006232361c5812af85de9799b1182f1b52145ccfced4fa21b6daafa"
		hash4 = "7ea7c6406c5a80d3c15511c4d97ec1e45813e9c58431f386710d0486c4898b98"

	strings:
		$x1 = "InjectShellCode" ascii fullword
		$s1 = "DotNetLoader.exe" wide ascii fullword
		$s2 = "clipboardinject" ascii fullword
		$s3 = "download.php?raw=1" wide
		$s4 = "Windows NT\\CurrentVersion\\AppCompatFlags\\TelemetryController\\Levint" wide
		$s5 = "FlashUpdate.exe" wide
		$s6 = "raw_cc_url" ascii fullword
		$op1 = { 48 8b 4c 24 78 48 89 01 e9 1a ff ff ff 48 8b 44 }
		$op2 = { ff ff 00 00 77 2a 8b 44 24 38 8b 8c 24 98 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 200KB and $x1 or 3 of them
}

rule SIGNATURE_BASE_APT_CN_MAL_Reddelta_Shellcode_Loader_Oct20_2 : FILE
{
	meta:
		description = "Detects Red Delta samples"
		author = "Florian Roth (Nextron Systems)"
		id = "acb1024a-64af-51ac-84c8-7fe9a5bd4538"
		date = "2020-10-14"
		modified = "2023-12-05"
		reference = "https://twitter.com/JAMESWT_MHT/status/1316387482708119556"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_cn_reddelta.yar#L31-L57"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "179265c0b2175bc3d2d581a69e50e9b8b9cc918a6fdc7bcef42fb163c49b077a"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "260ebbf392498d00d767a5c5ba695e1a124057c1c01fff2ae76db7853fe4255b"
		hash2 = "9ccb4ed133be5c9c554027347ad8b722f0b4c3f14bfd947edfe75a015bf085e5"
		hash3 = "b3fd750484fca838813e814db7d6491fea36abe889787fb7cf3fb29d9d9f5429"

	strings:
		$x1 = "\\CLRLoader.exe" wide fullword
		$x2 = "/callback.php?token=%s&computername=%s&username=%s" ascii fullword
		$s1 = "DotNetLoader.Program" wide fullword
		$s2 = "/download.php?api=40" ascii fullword
		$s3 = "get %d URLDir" ascii fullword
		$s4 = "Read code failed" ascii fullword
		$s5 = "OpenFile fail!" wide fullword
		$s6 = "Writefile success" wide fullword
		$op1 = { 4c 8d 45 e0 49 8b cc 41 8d 51 c3 e8 34 77 02 00 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 3000KB and 1 of ( $x* ) or 4 of them
}

rule SIGNATURE_BASE_APT_CN_MAL_Reddelta_Shellcode_Loader_Oct20_3 : FILE
{
	meta:
		description = "Detects Red Delta samples"
		author = "Florian Roth (Nextron Systems)"
		id = "b52836bb-cdef-5416-a8e1-72d0b2298546"
		date = "2020-10-14"
		modified = "2022-12-21"
		reference = "https://twitter.com/JAMESWT_MHT/status/1316387482708119556"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_cn_reddelta.yar#L59-L78"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "64402f6265f23abf7d6a711aa888c89386c1a754f12286b0efe5fd5d81f15b01"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "740992d40b84b10aa9640214a4a490e989ea7b869cea27dbbdef544bb33b1048"

	strings:
		$s1 = "Taskschd.dll" ascii fullword
		$s2 = "AddTaskPlanDllVerson.dll" ascii fullword
		$s3 = "\\FlashUpdate.exe" ascii
		$s4 = "D:\\Project\\FBIRedTeam" ascii fullword
		$s5 = "Error %s:%d, ErrorCode: %x" ascii fullword

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 400KB and 4 of them
}

rule SIGNATURE_BASE_APT_MAL_LNX_Redmenshen_Bpfdoor_Controller_May22_1 : FILE
{
	meta:
		description = "Detects unknown Linux implants (uploads from KR and MO)"
		author = "Florian Roth (Nextron Systems)"
		id = "1438c3bf-3c42-59d5-9f3f-2d72bdaaac42"
		date = "2022-05-05"
		modified = "2023-12-05"
		reference = "https://doublepulsar.com/bpfdoor-an-active-chinese-global-surveillance-tool-54b078f1a896"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/mal_lnx_implant_may22.yar#L45-L76"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "8de10beea4ef2e059b16d38fb015d6f091cc517b6f0c06b6ef6868518349994d"
		score = 90
		quality = 85
		tags = "FILE"
		hash1 = "07ecb1f2d9ffbd20a46cd36cd06b022db3cc8e45b1ecab62cd11f9ca7a26ab6d"
		hash2 = "4c5cf8f977fc7c368a8e095700a44be36c8332462c0b1e41bff03238b2bf2a2d"
		hash3 = "599ae527f10ddb4625687748b7d3734ee51673b664f2e5d0346e64f85e185683"
		hash4 = "5b2a079690efb5f4e0944353dd883303ffd6bab4aad1f0c88b49a76ddcb28ee9"
		hash5 = "5faab159397964e630c4156f8852bcc6ee46df1cdd8be2a8d3f3d8e5980f3bb3"
		hash6 = "93f4262fce8c6b4f8e239c35a0679fbbbb722141b95a5f2af53a2bcafe4edd1c"
		hash7 = "97a546c7d08ad34dfab74c9c8a96986c54768c592a8dae521ddcf612a84fb8cc"
		hash8 = "c796fc66b655f6107eacbe78a37f0e8a2926f01fecebd9e68a66f0e261f91276"
		hash9 = "f8a5e735d6e79eb587954a371515a82a15883cf2eda9d7ddb8938b86e714ea27"
		hash10 = "fd1b20ee5bd429046d3c04e9c675c41e9095bea70e0329bd32d7edd17ebaf68a"

	strings:
		$s1 = "[-] Connect failed." ascii fullword
		$s2 = "export MYSQL_HISTFILE=" ascii fullword
		$s3 = "udpcmd" ascii fullword
		$s4 = "getshell" ascii fullword
		$op1 = { e8 ?? ff ff ff 80 45 ee 01 0f b6 45 ee 3b 45 d4 7c 04 c6 45 ee 00 80 45 ff 01 80 7d ff 00 }
		$op2 = { 55 48 89 e5 48 83 ec 30 89 7d ec 48 89 75 e0 89 55 dc 83 7d dc 00 75 0? }
		$op3 = { e8 a? fe ff ff 0f b6 45 f6 48 03 45 e8 0f b6 10 0f b6 45 f7 48 03 45 e8 0f b6 00 8d 04 02 }
		$op4 = { c6 80 01 01 00 00 00 48 8b 45 c8 0f b6 90 01 01 00 00 48 8b 45 c8 88 90 00 01 00 00 c6 45 ef 00 0f b6 45 ef 88 45 ee }

	condition:
		uint16( 0 ) == 0x457f and filesize < 80KB and 2 of them or 5 of them
}

rule SIGNATURE_BASE_APT_MAL_LNX_Redmenshen_Bpfdoor_Controller_May22_2 : FILE
{
	meta:
		description = "Detects BPFDoor implants used by Chinese actor Red Menshen"
		author = "Florian Roth (Nextron Systems)"
		id = "d5c3d530-ed6f-563e-a3b0-55d4c82e4899"
		date = "2022-05-07"
		modified = "2023-12-05"
		reference = "https://doublepulsar.com/bpfdoor-an-active-chinese-global-surveillance-tool-54b078f1a896"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/mal_lnx_implant_may22.yar#L78-L100"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "7525c675dbba6eb480f1d28fc6db05bd9907725c291e64ee6dc2453fd42892a0"
		score = 85
		quality = 85
		tags = "FILE"
		hash1 = "76bf736b25d5c9aaf6a84edd4e615796fffc338a893b49c120c0b4941ce37925"
		hash2 = "96e906128095dead57fdc9ce8688bb889166b67c9a1b8fdb93d7cff7f3836bb9"
		hash3 = "c80bd1c4a796b4d3944a097e96f384c85687daeedcdcf05cc885c8c9b279b09c"
		hash4 = "f47de978da1dbfc5e0f195745e3368d3ceef034e964817c66ba01396a1953d72"

	strings:
		$opx1 = { 48 83 c0 0c 48 8b 95 e8 fe ff ff 48 83 c2 0c 8b 0a 8b 55 f0 01 ca 89 10 c9 }
		$opx2 = { 48 01 45 e0 83 45 f4 01 8b 45 f4 3b 45 dc 7c cd c7 45 f4 00 00 00 00 eb 2? 48 8b 05 ?? ?? 20 00 }
		$op1 = { 48 8d 14 c5 00 00 00 00 48 8b 45 d0 48 01 d0 48 8b 00 48 89 c7 e8 ?? ?? ff ff 48 83 c0 01 48 01 45 e0 }
		$op2 = { 89 c2 8b 85 fc fe ff ff 01 c2 8b 45 f4 01 d0 2d 7b cf 10 2b 89 45 f4 c1 4d f4 10 }
		$op3 = { e8 ?? d? ff ff 8b 45 f0 eb 12 8b 85 3c ff ff ff 89 c7 e8 ?? d? ff ff b8 ff ff ff ff c9 }

	condition:
		uint16( 0 ) == 0x457f and filesize < 100KB and 2 of ( $opx* ) or 4 of them
}

rule SIGNATURE_BASE_APT_MAL_LNX_Redmenshen_Bpfdoor_Controller_May22_3 : FILE
{
	meta:
		description = "Detects BPFDoor implants used by Chinese actor Red Menshen"
		author = "Florian Roth (Nextron Systems)"
		id = "91c2153a-a6e0-529e-852c-61f799838798"
		date = "2022-05-08"
		modified = "2023-12-05"
		reference = "https://doublepulsar.com/bpfdoor-an-active-chinese-global-surveillance-tool-54b078f1a896"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/mal_lnx_implant_may22.yar#L102-L119"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "afec0bfeddf5c5c2abc1a3173f636c385437e5d7c0b68665f6274011113a6a9c"
		score = 85
		quality = 85
		tags = "FILE"
		hash1 = "144526d30ae747982079d5d340d1ff116a7963aba2e3ed589e7ebc297ba0c1b3"
		hash2 = "fa0defdabd9fd43fe2ef1ec33574ea1af1290bd3d763fdb2bed443f2bd996d73"

	strings:
		$s1 = "hald-addon-acpi: listening on acpi kernel interface /proc/acpi/event" ascii fullword
		$s2 = "/sbin/mingetty /dev" ascii fullword
		$s3 = "pickup -l -t fifo -u" ascii fullword

	condition:
		uint16( 0 ) == 0x457f and filesize < 200KB and 2 of them or all of them
}

rule SIGNATURE_BASE_APT_MAL_LNX_Redmenshen_Bpfdoor_Controller_Generic_May22_1 : FILE
{
	meta:
		description = "Detects BPFDoor malware"
		author = "Florian Roth (Nextron Systems)"
		id = "d30df2ae-7008-53c0-9a61-8346a9c9f465"
		date = "2022-05-09"
		modified = "2023-12-05"
		reference = "https://doublepulsar.com/bpfdoor-an-active-chinese-global-surveillance-tool-54b078f1a896"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/mal_lnx_implant_may22.yar#L121-L156"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "57ae5f7dc1d202fe66d6626ef2bf2278b92bec0310449ce049bdaeaec5657c77"
		score = 90
		quality = 85
		tags = "FILE"
		hash1 = "07ecb1f2d9ffbd20a46cd36cd06b022db3cc8e45b1ecab62cd11f9ca7a26ab6d"
		hash2 = "1925e3cd8a1b0bba0d297830636cdb9ebf002698c8fa71e0063581204f4e8345"
		hash3 = "4c5cf8f977fc7c368a8e095700a44be36c8332462c0b1e41bff03238b2bf2a2d"
		hash4 = "591198c234416c6ccbcea6967963ca2ca0f17050be7eed1602198308d9127c78"
		hash5 = "599ae527f10ddb4625687748b7d3734ee51673b664f2e5d0346e64f85e185683"
		hash6 = "5b2a079690efb5f4e0944353dd883303ffd6bab4aad1f0c88b49a76ddcb28ee9"
		hash7 = "5faab159397964e630c4156f8852bcc6ee46df1cdd8be2a8d3f3d8e5980f3bb3"
		hash8 = "76bf736b25d5c9aaf6a84edd4e615796fffc338a893b49c120c0b4941ce37925"
		hash9 = "93f4262fce8c6b4f8e239c35a0679fbbbb722141b95a5f2af53a2bcafe4edd1c"
		hash10 = "96e906128095dead57fdc9ce8688bb889166b67c9a1b8fdb93d7cff7f3836bb9"
		hash11 = "97a546c7d08ad34dfab74c9c8a96986c54768c592a8dae521ddcf612a84fb8cc"
		hash12 = "c796fc66b655f6107eacbe78a37f0e8a2926f01fecebd9e68a66f0e261f91276"
		hash13 = "c80bd1c4a796b4d3944a097e96f384c85687daeedcdcf05cc885c8c9b279b09c"
		hash14 = "f47de978da1dbfc5e0f195745e3368d3ceef034e964817c66ba01396a1953d72"
		hash15 = "f8a5e735d6e79eb587954a371515a82a15883cf2eda9d7ddb8938b86e714ea27"
		hash16 = "fa0defdabd9fd43fe2ef1ec33574ea1af1290bd3d763fdb2bed443f2bd996d73"
		hash17 = "fd1b20ee5bd429046d3c04e9c675c41e9095bea70e0329bd32d7edd17ebaf68a"

	strings:
		$op1 = { c6 80 01 01 00 00 00 48 8b 45 ?8 0f b6 90 01 01 00 00 48 8b 45 ?8 88 90 00 01 00 00 c6 45 ?? 00 0f b6 45 ?? 88 45 }
		$op2 = { 48 89 55 c8 48 8b 45 c8 48 89 45 ?? 48 8b 45 c8 0f b6 80 00 01 00 00 88 45 f? 48 8b 45 c8 0f b6 80 01 01 00 00 }
		$op3 = { 48 89 45 ?? 48 8b 45 c8 0f b6 80 00 01 00 00 88 45 f? 48 8b 45 c8 0f b6 80 01 01 00 00 88 45 f? c7 45 f8 00 00 00 00 }
		$op4 = { 48 89 7d d8 89 75 d4 48 89 55 c8 48 8b 45 c8 48 89 45 ?? 48 8b 45 c8 0f b6 80 00 01 00 00 88 45 f? }
		$op5 = { 48 8b 45 ?8 c6 80 01 01 00 00 00 48 8b 45 ?8 0f b6 90 01 01 00 00 48 8b 45 ?8 88 90 00 01 00 00 c6 45 ?? 00 0f b6 45 }
		$op6 = { 89 75 d4 48 89 55 c8 48 8b 45 c8 48 89 45 ?? 48 8b 45 c8 0f b6 80 00 01 00 00 88 45 f? 48 8b 45 c8 }

	condition:
		uint16( 0 ) == 0x457f and filesize < 200KB and 2 of them or 4 of them
}

rule SIGNATURE_BASE_APT_MAL_NK_3CX_Malicious_Samples_Mar23_1 : FILE
{
	meta:
		description = "Detects malicious DLLs related to 3CX compromise"
		author = "X__Junior, Florian Roth (Nextron Systems)"
		id = "a6ea3299-fde5-5206-b5db-eb3a3f5944d9"
		date = "2023-03-29"
		modified = "2023-04-20"
		reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/gen_mal_3cx_compromise_mar23.yar#L3-L30"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "68f4007791d365900c84e32e076aa3cac9f3a9ed46de297f1005306554ee13f5"
		score = 85
		quality = 85
		tags = "FILE"
		hash1 = "7986bbaee8940da11ce089383521ab420c443ab7b15ed42aed91fd31ce833896"
		hash2 = "c485674ee63ec8d4e8fde9800788175a8b02d3f9416d0e763360fff7f8eb4e02"
		hash3 = "cc4eedb7b1f77f02b962f4b05278fa7f8082708b5a12cacf928118520762b5e2"

	strings:
		$opa1 = { 4C 89 F1 4C 89 EA 41 B8 40 00 00 00 FF 15 ?? ?? ?? ?? 85 C0 74 ?? 4C 89 F0 FF 15 ?? ?? ?? ?? 4C 8D 4C 24 ?? 45 8B 01 4C 89 F1 4C 89 EA FF 15 }
		$opa2 = { 48 C7 44 24 ?? 00 00 00 00 4C 8D 7C 24 ?? 48 89 F9 48 89 C2 41 89 E8 4D 89 F9 FF 15 ?? ?? ?? ?? 41 83 3F 00 0F 84 ?? ?? ?? ?? 0F B7 03 3D 4D 5A 00 00}
		$opa3 = { 41 80 7C 00 ?? FE 75 ?? 41 80 7C 00 ?? ED 75 ?? 41 80 7C 00 ?? FA 75 ?? 41 80 3C 00 CE}
		$opa4 = { 44 0F B6 CD 46 8A 8C 0C ?? ?? ?? ?? 45 30 0C 0E 48 FF C1}
		$opb1 = { 41 B8 40 00 00 00 49 8B D5 49 8B CC FF 15 ?? ?? ?? ?? 85 C0 74 ?? 41 FF D4 44 8B 45 ?? 4C 8D 4D ?? 49 8B D5 49 8B CC FF 15 }
		$opb2 = { 44 8B C3 48 89 44 24 ?? 48 8B 5C 24 ?? 4C 8D 4D ?? 48 8B CB 48 89 74 24 ?? 48 8B D0 4C 8B F8 FF 15 }
		$opb3 = { 80 78 ?? FE 75 ?? 80 78 ?? ED 75 ?? 80 38 FA 75 ?? 80 78 ?? CE }
		$opb4 = { 49 63 C1 44 0F B6 44 05 ?? 44 88 5C 05 ?? 44 88 02 0F B6 54 05 ?? 49 03 D0 0F B6 C2 0F B6 54 05 ?? 41 30 12}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 5MB and pe.characteristics & pe.DLL and ( 2 of ( $opa* ) or 2 of ( $opb* ) )
}

rule SIGNATURE_BASE_APT_MAL_NK_3CX_Malicious_Samples_Mar23_3
{
	meta:
		description = "Detects malicious DLLs related to 3CX compromise (decrypted payload)"
		author = "Florian Roth , X__Junior (Nextron Systems)"
		id = "d2d361b6-8485-57eb-b6eb-88785f42e93e"
		date = "2023-03-29"
		modified = "2023-12-05"
		reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/gen_mal_3cx_compromise_mar23.yar#L56-L79"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "adfe04904d796690631e5841ee1ee10c767f9f4c340e5b9df78918e981359d4d"
		score = 80
		quality = 85
		tags = ""
		hash1 = "aa4e398b3bd8645016d8090ffc77d15f926a8e69258642191deb4e68688ff973"

	strings:
		$opa1 = { 41 81 C0 ?? ?? ?? ?? 02 C8 49 C1 E9 ?? 41 88 4B ?? 4D 03 D1 8B C8 45 8B CA C1 E1 ?? 33 C1 41 69 D0 ?? ?? ?? ?? 8B C8 C1 E9 ?? 33 C1 8B C8 C1 E1 ?? 81 C2 ?? ?? ?? ?? 33 C1 43 8D 0C 02 02 C8 49 C1 EA ?? 41 88 0B 8B C8 C1 E1 ?? 33 C1 44 69 C2 ?? ?? ?? ?? 8B C8 C1 E9 ?? 33 C1 8B C8 C1 E1 ?? 41 81 C0 }
		$opa2 = { 8B C8 41 69 D1 ?? ?? ?? ?? C1 E1 ?? 33 C1 45 8B CA 8B C8 C1 E9 ?? 33 C1 81 C2 ?? ?? ?? ?? 8B C8 C1 E1 ?? 33 C1 41 8B C8 4C 0F AF CF 44 69 C2 ?? ?? ?? ?? 4C 03 C9 45 8B D1 4C 0F AF D7}
		$opb1 = { 45 33 C9 48 89 6C 24 ?? 48 8D 44 24 ?? 48 89 6C 24 ?? 8B D3 48 89 B4 24 ?? ?? ?? ?? 48 89 44 24 ?? 45 8D 41 ?? FF 15 }
		$opb2 = { 44 8B 0F 45 8B C6 48 8B 4D ?? 49 8B D7 44 89 64 24 ?? 48 89 7C 24 ?? 44 89 4C 24 ?? 4C 8D 4D ?? 48 89 44 24 ?? 44 89 64 24 ?? 4C 89 64 24 ?? FF 15}
		$opb3 = { 48 FF C2 66 44 39 2C 56 75 ?? 4C 8D 4C 24 ?? 45 33 C0 48 8B CE FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 44 0F B7 44 24 ?? 33 F6 48 8B 54 24 ?? 45 33 C9 48 8B 0B 48 89 74 24 ?? 89 74 24 ?? C7 44 24 ?? ?? ?? ?? ?? 48 89 74 24 ?? FF 15 }
		$opb4 = { 33 C0 48 8D 6B ?? 4C 8D 4C 24 ?? 89 44 24 ?? BA ?? ?? ?? ?? 48 89 44 24 ?? 48 8B CD 89 44 24 ?? 44 8D 40 ?? 8B F8 FF 15}

	condition:
		( all of ( $opa* ) ) or ( 1 of ( $opa* ) and 1 of ( $opb* ) ) or ( 3 of ( $opb* ) )
}

rule SIGNATURE_BASE_SUSP_APT_MAL_NK_3CX_Malicious_Samples_Mar23_1
{
	meta:
		description = "Detects marker found in malicious DLLs related to 3CX compromise"
		author = "X__Junior, Florian Roth (Nextron Systems)"
		id = "9fc6eb94-d02f-5bcd-9f55-b6c6a8301b4f"
		date = "2023-03-29"
		modified = "2023-04-20"
		reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/gen_mal_3cx_compromise_mar23.yar#L81-L98"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "dcce1f5e769a2821d746a960cd333f8042fb71c8469aa41c29bbbd0dce79369c"
		score = 75
		quality = 85
		tags = ""
		hash1 = "7986bbaee8940da11ce089383521ab420c443ab7b15ed42aed91fd31ce833896"
		hash2 = "c485674ee63ec8d4e8fde9800788175a8b02d3f9416d0e763360fff7f8eb4e02"
		hash3 = "cc4eedb7b1f77f02b962f4b05278fa7f8082708b5a12cacf928118520762b5e2"

	strings:
		$opx1 = { 41 80 7C 00 FD FE 75 ?? 41 80 7C 00 FE ED 75 ?? 41 80 7C 00 FF FA 75 ?? 41 80 3C 00 CE }
		$opx2 = { 80 78 ?? FE 75 ?? 80 78 ?? ED 75 ?? 80 38 FA 75 ?? 80 78 ?? CE }

	condition:
		1 of them
}

rule SIGNATURE_BASE_APT_SUSP_NK_3CX_RC4_Key_Mar23_1 : FILE
{
	meta:
		description = "Detects RC4 key used in 3CX binaries known to be malicious"
		author = "Florian Roth (Nextron Systems)"
		id = "18ea2185-11a1-51ad-a51a-df9e6357bb58"
		date = "2023-03-29"
		modified = "2023-12-05"
		reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/gen_mal_3cx_compromise_mar23.yar#L100-L117"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "8324b537b149ad3816b12ae0f887f66a284a8e1ef4fe7cf51eb21d59c0f055b9"
		score = 70
		quality = 85
		tags = "FILE"
		hash1 = "7986bbaee8940da11ce089383521ab420c443ab7b15ed42aed91fd31ce833896"
		hash2 = "59e1edf4d82fae4978e97512b0331b7eb21dd4b838b850ba46794d9c7a2c0983"
		hash3 = "aa124a4b4df12b34e74ee7f6c683b2ebec4ce9a8edcf9be345823b4fdcf5d868"
		hash4 = "c485674ee63ec8d4e8fde9800788175a8b02d3f9416d0e763360fff7f8eb4e02"

	strings:
		$x1 = "3jB(2bsG#@c7"

	condition:
		( uint16( 0 ) == 0xcfd0 or uint16( 0 ) == 0x5a4d ) and $x1
}


rule SIGNATURE_BASE_APT_MAL_Macos_NK_3CX_Malicious_Samples_Mar23_1 : FILE
{
	meta:
		description = "Detects malicious macOS application related to 3CX compromise (decrypted payload)"
		author = "Florian Roth (Nextron Systems)"
		id = "ff39e577-7063-5025-bead-68394a86c87c"
		date = "2023-03-30"
		modified = "2023-12-05"
		reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/gen_mal_3cx_compromise_mar23.yar#L168-L184"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "c2733c2f7dcca82e5a0b2301777fb54853d04dfa893bcf88ecbec34d37e1a38a"
		score = 80
		quality = 85
		tags = "FILE"
		hash1 = "b86c695822013483fa4e2dfdf712c5ee777d7b99cbad8c2fa2274b133481eadb"
		hash2 = "ac99602999bf9823f221372378f95baa4fc68929bac3a10e8d9a107ec8074eca"
		hash3 = "51079c7e549cbad25429ff98b6d6ca02dc9234e466dd9b75a5e05b9d7b95af72"

	strings:
		$s1 = "20230313064152Z0"
		$s2 = "Developer ID Application: 3CX (33CF4654HL)"

	condition:
		( uint16( 0 ) == 0xfeca or uint16( 0 ) == 0xfacf or uint32( 0 ) == 0xbebafeca ) and all of them
}

rule SIGNATURE_BASE_APT_MAL_Macos_NK_3CX_DYLIB_Mar23_1
{
	meta:
		description = "Detects malicious DYLIB files related to 3CX compromise"
		author = "Florian Roth (Nextron Systems)"
		id = "a19904d3-9b2d-561f-b734-20bf09584fa7"
		date = "2023-03-30"
		modified = "2023-12-05"
		reference = "https://www.sentinelone.com/blog/smoothoperator-ongoing-campaign-trojanizes-3cx-software-in-software-supply-chain-attack/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/gen_mal_3cx_compromise_mar23.yar#L188-L214"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "e52c76de1e995cc7084ddb390b60f4bc66e5bdf89aaa28ef3fd70578ed3145a6"
		score = 80
		quality = 85
		tags = ""
		hash1 = "a64fa9f1c76457ecc58402142a8728ce34ccba378c17318b3340083eeb7acc67"
		hash2 = "fee4f9dabc094df24d83ec1a8c4e4ff573e5d9973caa676f58086c99561382d7"

	strings:
		$xc1 = { 37 15 00 13 16 16 1B 55 4F 54 4A 5A 52 2D 13 14 
               1E 15 0D 09 5A 34 2E 5A 4B 4A 54 4A 41 5A 2D 13
               14 4C 4E 41 5A 02 4C 4E 53 5A 3B 0A 0A 16 1F 2D
               1F 18 31 13 0E 55 4F 49 4D 54 49 4C 5A 52 31 32
               2E 37 36 56 5A 16 13 11 1F 5A 3D 1F 19 11 15 53
               5A 39 12 08 15 17 1F 55 4B 4A 42 54 4A 54 4F 49
               4F 43 54 4B 48 42 5A 29 1B 1C 1B 08 13 55 4F 49
               4D 54 49 4C 7A }
		$xc2 = { 41 49 19 02 25 1b 0f 0e 12 25 0e 15 11 1f 14 25 19 15 14 0e 1f 14 0e 47 5f 09 41 25 25 0e 0f 0e 17 1b 47 }
		$xc3 = { 55 29 03 09 0e 1f 17 55 36 13 18 08 1b 08 03 55 39 15 08 1f 29 1f 08 0c 13 19 1f 09 55 29 03 09 0e 1f 17 2c 1f 08 09 13 15 14 54 0a 16 13 09 0e }

	condition:
		1 of them
}

rule SIGNATURE_BASE_APT_SUSP_NK_3CX_Malicious_Samples_Mar23_1
{
	meta:
		description = "Detects indicator (event name) found in samples related to 3CX compromise"
		author = "Florian Roth (Nextron Systems)"
		id = "b233846a-19df-579b-a674-233d66824008"
		date = "2023-03-30"
		modified = "2023-12-05"
		reference = "https://www.sentinelone.com/blog/smoothoperator-ongoing-campaign-trojanizes-3cx-software-in-software-supply-chain-attack/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/gen_mal_3cx_compromise_mar23.yar#L216-L232"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "6ab8a4ac184eaba6eb56bfc49d6fa03f9b0877d75294aa9a242e9ac96482fab0"
		score = 70
		quality = 85
		tags = ""
		hash1 = "7986bbaee8940da11ce089383521ab420c443ab7b15ed42aed91fd31ce833896"
		hash2 = "59e1edf4d82fae4978e97512b0331b7eb21dd4b838b850ba46794d9c7a2c0983"
		hash3 = "aa124a4b4df12b34e74ee7f6c683b2ebec4ce9a8edcf9be345823b4fdcf5d868"
		hash4 = "c485674ee63ec8d4e8fde9800788175a8b02d3f9416d0e763360fff7f8eb4e02"

	strings:
		$a1 = "AVMonitorRefreshEvent" wide fullword

	condition:
		1 of them
}

rule SIGNATURE_BASE_APT_MAL_NK_3CX_Malicious_Samples_Mar23_4
{
	meta:
		description = "Detects decrypted payload loaded inside 3CXDesktopApp.exe which downloads info stealer"
		author = "MalGamy (Nextron Systems)"
		id = "d11170df-570c-510c-80ec-39048acd0fbd"
		date = "2023-03-29"
		modified = "2023-12-05"
		reference = "https://twitter.com/WhichbufferArda/status/1641404343323688964?s=20"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/gen_mal_3cx_compromise_mar23.yar#L234-L249"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		hash = "851c2c99ebafd4e5e9e140cfe3f2d03533846ca16f8151ae8ee0e83c692884b7"
		logic_hash = "2fd56527a094b1f155cf33af402328835d4fb8aee9a058742d3e3763acef9e46"
		score = 80
		quality = 85
		tags = ""

	strings:
		$op1 = {41 69 D0 [4] 8B C8 C1 E9 ?? 33 C1 8B C8 C1 E1 ?? 81 C2 [4] 33 C1 43 8D 0C 02 02 C8 49 C1 EA ?? 41 88 0B 8B C8 C1 E1 ?? 33 C1 44 69 C2 [4] 8B C8 C1 E9 ?? 33 C1 8B C8 C1 E1 ?? 41 81 C0 [4] 33 C1 4C 0F AF CF 4D 03 CA 45 8B D1 4C 0F AF D7 41 8D 0C 11 49 C1 E9 ?? 02 C8}
		$op2 = {4D 0F AF CC 44 69 C2 [4] 4C 03 C9 45 8B D1 4D 0F AF D4 41 8D 0C 11 41 81 C0 [4] 02 C8 49 C1 E9 ?? 41 88 4B ?? 4D 03 D1 8B C8 45 8B CA C1 E1 ?? 33 C1}
		$op3 = {33 C1 4C 0F AF C7 8B C8 C1 E1 ?? 4D 03 C2 33 C1}

	condition:
		2 of them
}

rule SIGNATURE_BASE_APT_MAL_NK_3CX_ICONIC_Stealer_Mar23_1 : FILE
{
	meta:
		description = "Detects ICONIC stealer payload used in the 3CX incident"
		author = "Florian Roth (Nextron Systems)"
		id = "e92b5b90-1146-5235-9711-a4d42689c49b"
		date = "2023-03-31"
		modified = "2023-12-05"
		reference = "https://github.com/volexity/threat-intel/blob/main/2023/2023-03-30%203CX/attachments/iconicstealer.7z"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/gen_mal_3cx_compromise_mar23.yar#L279-L304"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "1f57a2af4a5b9e71e2b72ddc3839400731d9d37eb4349c393b37b3f86c0c7f73"
		score = 80
		quality = 85
		tags = "FILE"
		hash1 = "8ab3a5eaaf8c296080fadf56b265194681d7da5da7c02562953a4cb60e147423"

	strings:
		$s1 = "{\"HostName\": \"%s\", \"DomainName\": \"%s\", \"OsVersion\": \"%d.%d.%d\"}" wide fullword
		$s2 = "******************************** %s ******************************" wide fullword
		$s3 = "AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data" wide fullword
		$s4 = "AppData\\Roaming\\Mozilla\\Firefox\\Profiles" wide fullword
		$s5 = "SELECT url, title FROM urls ORDER BY id DESC LIMIT 500" wide fullword
		$s6 = "TEXT value in %s.%s" ascii fullword
		$op1 = { 48 63 d1 48 63 ce 49 03 d1 49 03 cd 4c 63 c7 e8 87 1f 09 00 8b 45 d0 44 8d 04 37 }
		$op2 = { 48 8b c8 8b 56 f0 48 89 46 d8 e8 78 8f f8 ff e9 ec 13 00 00 c7 46 20 ff ff ff ff e9 e0 13 00 00 33 ff }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 4000KB and 4 of them or 6 of them
}

rule SIGNATURE_BASE_APT_MAL_NK_3CX_Macos_Elextron_App_Mar23_1 : FILE
{
	meta:
		description = "Detects macOS malware used in the 3CX incident"
		author = "Florian Roth (Nextron Systems)"
		id = "7a3755d4-37e5-5d3b-93aa-34edb557f2d5"
		date = "2023-03-31"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/gen_mal_3cx_compromise_mar23.yar#L306-L328"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "00dd28c3edd94e04e35ee9e3a43c30b5a0a1ad21ec8ecf2099bbeb9de2fca8d0"
		score = 80
		quality = 85
		tags = "FILE"
		hash1 = "51079c7e549cbad25429ff98b6d6ca02dc9234e466dd9b75a5e05b9d7b95af72"
		hash2 = "f7ba7f9bf608128894196cf7314f68b78d2a6df10718c8e0cd64dbe3b86bc730"

	strings:
		$a1 = "com.apple.security.cs.allow-unsigned-executable-memory" ascii
		$a2 = "com.electron.3cx-desktop-app" ascii fullword
		$s1 = "s8T/RXMlALbXfowom9qk15FgtdI=" ascii
		$s2 = "o8NQKPJE6voVZUIGtXihq7lp0cY=" ascii

	condition:
		uint16( 0 ) == 0xfacf and filesize < 400KB and ( all of ( $a* ) and 1 of ( $s* ) )
}

rule SIGNATURE_BASE_APT_UA_Hermetic_Wiper_Feb22_1 : FILE
{
	meta:
		description = "Detects Hermetic Wiper malware"
		author = "Florian Roth (Nextron Systems)"
		id = "2cbe4a69-e31a-5f5f-ab1a-9d71d16fb30f"
		date = "2022-02-24"
		modified = "2023-12-05"
		reference = "https://www.sentinelone.com/labs/hermetic-wiper-ukraine-under-attack/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_ua_hermetic_wiper.yar#L2-L38"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "1cf124f7533a060da8aff1a18f64a94b183502e58ffdfca012d72d99d30225ba"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "0385eeab00e946a302b24a91dea4187c1210597b8e17cd9e2230450f5ece21da"
		hash2 = "3c557727953a8f6b4788984464fb77741b821991acbf5e746aebdd02615b1767"
		hash3 = "2c10b2ec0b995b88c27d141d6f7b14d6b8177c52818687e4ff8e6ecf53adf5bf"
		hash4 = "1bc44eef75779e3ca1eefb8ff5a64807dbc942b1e4a2672d77b9f6928d292591"

	strings:
		$xc1 = { 00 5C 00 5C 00 2E 00 5C 00 50 00 68 00 79 00 73
               00 69 00 63 00 61 00 6C 00 44 00 72 00 69 00 76
               00 65 00 25 00 75 00 00 00 5C 00 5C 00 2E 00 5C
               00 45 00 50 00 4D 00 4E 00 54 00 44 00 52 00 56
               00 5C 00 25 00 75 00 00 00 5C 00 5C 00 2E 00 5C
               00 00 00 00 00 25 00 73 00 25 00 2E 00 32 00 73
               00 00 00 00 00 24 00 42 00 69 00 74 00 6D 00 61
               00 70 00 00 00 24 00 4C 00 6F 00 67 00 46 00 69
               00 6C 00 65 }
		$sc1 = { 00 44 00 72 00 69 00 76 00 65 00 72 00 73 00 00
               00 64 00 72 00 76 00 00 00 53 00 79 00 73 00 74
               00 65 00 6D 00 33 00 32 }
		$s1 = "\\\\?\\C:\\Windows\\System32\\winevt\\Logs" wide fullword
		$s2 = "\\\\.\\EPMNTDRV\\%u" wide fullword
		$s3 = "DRV_XP_X64" wide fullword
		$s4 = "%ws%.2ws" wide fullword
		$op1 = { 8b 7e 08 0f 57 c0 8b 46 0c 83 ef 01 66 0f 13 44 24 20 83 d8 00 89 44 24 18 0f 88 3b 01 00 00 }
		$op2 = { 13 fa 8b 55 f4 4e 3b f3 7f e6 8a 45 0f 01 4d f0 0f 57 c0 }

	condition:
		( uint16( 0 ) == 0x5a53 or uint16( 0 ) == 0x5a4d ) and filesize < 400KB and ( 1 of ( $x* ) or 3 of them )
}

rule SIGNATURE_BASE_APT_UA_Hermetic_Wiper_Artefacts_Feb22_1
{
	meta:
		description = "Detects artefacts found in Hermetic Wiper malware related intrusions"
		author = "Florian Roth (Nextron Systems)"
		id = "77f793c1-b02c-59c3-b3e4-75758f5b3b8d"
		date = "2022-02-25"
		modified = "2023-12-05"
		reference = "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/ukraine-wiper-malware-russia"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_ua_hermetic_wiper.yar#L40-L70"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "5e917618a5172c68b4b32ba9e63402c2a98ccb027276b317ec169a4fef219de1"
		score = 75
		quality = 85
		tags = ""

	strings:
		$sx1 = "/c powershell -c \"rundll32 C:\\windows\\system32\\comsvcs.dll MiniDump" ascii wide
		$sx2 = "appdata\\local\\microsoft\\windows\\winupd.log" ascii wide
		$sx3 = "AppData\\Local\\Microsoft\\Windows\\Winupd.log" ascii wide
		$sx4 = "CSIDL_SYSTEM_DRIVE\\temp\\sys.tmp1" ascii wide
		$sx5 = "\\policydefinitions\\postgresql.exe" ascii wide
		$sx6 = "powershell -v 2 -exec bypass -File text.ps1" ascii wide
		$sx7 = "powershell -exec bypass gp.ps1" ascii wide
		$sx8 = "powershell -exec bypass -File link.ps1" ascii wide
		$sx9 = " 1> \\\\127.0.0.1\\ADMIN$\\__16" ascii wide
		$sa1 = "(New-Object System.Net.WebClient).DownloadFile(" ascii wide
		$sa2 = "CSIDL_SYSTEM_DRIVE\\temp\\" ascii wide
		$sa3 = "1> \\\\127.0.0.1\\ADMIN$" ascii wide
		$fp1 = "<html" ascii

	condition:
		1 of ( $sx* ) or all of ( $sa* ) and not 1 of ( $fp* )
}

rule SIGNATURE_BASE_APT_UA_Hermetic_Wiper_Scheduled_Task_Feb22_1
{
	meta:
		description = "Detects scheduled task pattern found in Hermetic Wiper malware related intrusions"
		author = "Florian Roth (Nextron Systems)"
		id = "a628f773-9c71-5979-a4db-37b6b6bd6a56"
		date = "2022-02-25"
		modified = "2023-12-05"
		reference = "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/ukraine-wiper-malware-russia"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_ua_hermetic_wiper.yar#L72-L88"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "56368ba1c97fe3455312b6ee86dcd1a21677f7dfa3836e76ada4b236a5b2c171"
		score = 85
		quality = 85
		tags = ""

	strings:
		$a0 = "<Task version=" ascii wide
		$sa1 = "CSIDL_SYSTEM_DRIVE\\temp" ascii wide
		$sa2 = "postgresql.exe 1> \\\\127.0.0.1\\ADMIN$" ascii wide
		$sa3 = "cmd.exe /Q /c move CSIDL_SYSTEM_DRIVE" ascii wide

	condition:
		$a0 and 1 of ( $s* )
}

rule SIGNATURE_BASE_APT_PS1_Sysaid_EXPL_Forensicartifacts_Nov23_1 : SCRIPT CVE_2023_47246
{
	meta:
		description = "Detects forensic artifacts found in attacks on SysAid on-prem software exploiting CVE-2023-47246"
		author = "Florian Roth"
		id = "df7997d3-9309-58b3-8cd7-de9fea36d3c7"
		date = "2023-11-09"
		modified = "2023-12-05"
		reference = "https://www.sysaid.com/blog/service-desk/on-premise-software-security-vulnerability-notification"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/expl_sysaid_cve_2023_47246.yar#L2-L15"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "85efeea88961ca99b22004726d88efc46c748273b9a0b3be674f4cbb12cd3dd1"
		score = 85
		quality = 85
		tags = "SCRIPT, CVE-2023-47246"

	strings:
		$x1 = "if ($s -match '^(Sophos).*\\.exe\\s') {echo $s; $bp++;}" ascii wide
		$x2 = "$s=$env:SehCore;$env:SehCore=\"\";Invoke-Expression $s;" ascii wide

	condition:
		1 of them
}

rule SIGNATURE_BASE_APT_HKTL_Wiper_Whispergate_Jan22_1 : FILE
{
	meta:
		description = "Detects unknown wiper malware"
		author = "Florian Roth (Nextron Systems)"
		id = "f04b619e-1df2-5c51-9cab-4a0fffd1c042"
		date = "2022-01-16"
		modified = "2023-12-05"
		reference = "https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_ua_wiper_whispergate.yar#L2-L23"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "72eb50a70b3f2fbb232134ef4706dbb15bdb5893fe06d899bff3b7aacdfadd30"
		score = 85
		quality = 85
		tags = "FILE"
		hash1 = "a196c6b8ffcb97ffb276d04f354696e2391311db3841ae16c8c9f56f36a38e92"

	strings:
		$xc1 = { 41 41 41 41 41 00 59 6F 75 72 20 68 61 72 64 20
               64 72 69 76 65 20 68 61 73 20 62 65 65 6E 20 63
               6F 72 72 75 70 74 65 64 }
		$op1 = { 89 34 24 e8 3f ff ff ff 50 8d 65 f4 31 c0 59 5e 5f }
		$op2 = { 8d bd e8 df ff ff e8 04 de ff ff b9 00 08 00 00 f3 a5 c7 44 24 18 00 00 00 00 c7 44 24 14 00 00 00 00 c7 44 24 10 03 00 00 00 c7 44 24 0c 00 00 00 00 }
		$op3 = { c7 44 24 0c 00 00 00 00 c7 44 24 08 00 02 00 00 89 44 24 04 e8 aa fe ff ff 83 ec 14 89 34 24 e8 3f ff ff ff 50 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 100KB and ( 1 of ( $x* ) or 2 of them ) or all of them
}

rule SIGNATURE_BASE_APT_HKTL_Wiper_Whispergate_Jan22_2 : FILE
{
	meta:
		description = "Detects unknown wiper malware"
		author = "Florian Roth (Nextron Systems)"
		id = "822e5af5-9c51-5be3-94f1-7e0a714743e6"
		date = "2022-01-16"
		modified = "2023-12-05"
		reference = "https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_ua_wiper_whispergate.yar#L25-L57"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "87a03e95bc1c33d1b3343ec7369c516bb15791943fbb122de11867ad4bddd565"
		score = 90
		quality = 85
		tags = "FILE"
		hash1 = "dcbbae5a1c61dbbbb7dcd6dc5dd1eb1169f5329958d38b58c3fd9384081c9b78"

	strings:
		$sc1 = { 70 00 6F 00 77 00 65 00 72 00 73 00 68 00 65 00
               6C 00 6C 00 00 27 2D 00 65 00 6E 00 63 00 20 00
               55 00 77 00 42 00 30 00 41 00 47 00 45 00 41 00
               63 00 67 00 42 00 30 00 41 00 43 }
		$sc2 = { 59 00 6C 00 66 00 77 00 64 00 77 00 67 00 6D 00
               70 00 69 00 6C 00 7A 00 79 00 61 00 70 00 68 }
		$s1 = "xownxloxadDxatxxax" wide
		$s2 = "0AUwBsAGUAZQBwACAALQBzACAAMQAwAA==" wide
		$s3 = "https://cdn.discordapp.com/attachments/" wide
		$s4 = "fffxfff.fff" ascii fullword
		$op1 = { 20 6b 85 b9 03 20 14 19 91 52 61 65 20 e1 ae f1 }
		$op2 = { aa ae 74 20 d9 7c 71 04 59 20 71 cc 13 91 61 20 97 3c 2a c0 }
		$op3 = { 38 9c f3 ff ff 20 f2 96 4d e9 20 5d ae d9 ce 58 20 4f 45 27 }
		$op4 = { d4 67 d4 61 80 1c 00 00 04 38 35 02 00 00 20 27 c0 db 56 65 20 3d eb 24 de 61 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 1000KB and 5 of them or 7 of them
}

rule SIGNATURE_BASE_APT_HKTL_Wiper_Whispergate_Stage3_Jan22 : FILE
{
	meta:
		description = "Detects reversed stage3 related to Ukrainian wiper malware"
		author = "Florian Roth (Nextron Systems)"
		id = "d5d562cd-03ef-5450-8044-3f538cea32d0"
		date = "2022-01-16"
		modified = "2023-12-05"
		reference = "https://twitter.com/juanandres_gs/status/1482827018404257792"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_ua_wiper_whispergate.yar#L59-L74"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "b06536b6a6eebd5fb398ba2617bf68a5b2c4b0035766b3cd0fc03d95019891ec"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "9ef7dbd3da51332a78eff19146d21c82957821e464e8133e9594a07d716d892d"

	strings:
		$xc1 = { 65 31 63 70 00 31 79 72 61 72 62 69 4c 73 73 61 6c 43 00 6e 69 61 4d }
		$s1 = "lld." wide

	condition:
		uint16( filesize -2 ) == 0x4d5a and filesize < 5000KB and all of them
}

rule SIGNATURE_BASE_EXT_APT32_Goopdate_Installer
{
	meta:
		description = "Detects APT32 installer side-loaded with goopdate.dll"
		author = "Facebook"
		id = "08f3cbda-ccb7-517a-b205-5f71de26c735"
		date = "2021-02-25"
		modified = "2023-12-05"
		reference = "https://about.fb.com/news/2020/12/taking-action-against-hackers-in-bangladesh-and-vietnam/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_apt32.yar#L3-L20"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		hash = "69730f2c2bb9668a17f8dfa1f1523e0e1e997ba98f027ce98f5cbaa869347383"
		logic_hash = "1dcb3009c5c19ff4e54d82d3a4b99b3431e78664f1660522a781e815d96958c4"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = { 68 ?? ?? ?? ?? 57 A3 ?? ?? ?? ?? FF D6 33 05 ?? ?? ?? ?? }
		$s1 = "GetProcAddress"
		$s2 = { 8B 4D FC ?? ?? 0F B6 51 0C ?? ?? 8B 4D F0 0F B6 1C 01 33 DA }
		$s3 = "FindNextFileW"
		$s4 = "Process32NextW"

	condition:
		(pe.is_64bit ( ) or pe.is_32bit ( ) ) and all of them
}

rule SIGNATURE_BASE_APT_CN_Twistedpanda_Loader : FILE
{
	meta:
		description = "Detects loader used by TwistedPanda"
		author = "Check Point Research"
		id = "a10f6019-f069-579c-b112-18537a7d8fd8"
		date = "2022-04-14"
		modified = "2025-07-01"
		reference = "https://research.checkpoint.com/2022/twisted-panda-chinese-apt-espionage-operation-against-russians-state-owned-defense-institutes/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_cn_twisted_panda.yar#L1-L44"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "b7f4f31a26b5f968b1d5c82d9165b4d45d75336993b113dda54fd37f628639ee"
		score = 80
		quality = 85
		tags = "FILE"
		hash1 = "5b558c5fcbed8544cb100bd3db3c04a70dca02eec6fedffd5e3dcecb0b04fba0"
		hash2 = "efa754450f199caae204ca387976e197d95cdc7e83641444c1a5a91b58ba6198"

	strings:
		$seq1 = { 6A 40 68 00 30 00 00 }
		$seq2 = { 6A 00 50 6A 14 8D ?? ?? ?? ?? ?? 50 53 FF }
		$seq3 = { 6A 00 6A 00 6A 03 6A 00 6A 03 68 00 00 00 80 }
		$decryption = { 8B C? [2-3] F6 D? 1A C? [4-6] 30 0? ?? 4? }

	condition:
		uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 and filesize < 3000KB and all of ( $seq* ) and $decryption
}

rule SIGNATURE_BASE_APT_CN_Twistedpanda_SPINNER_1 : FILE
{
	meta:
		description = "Detects the obfuscated variant of SPINNER payload used by TwistedPanda"
		author = "Check Point Research"
		id = "0b44013d-0caa-5ea2-ab08-e2a6a5732c03"
		date = "2022-04-14"
		modified = "2025-07-01"
		reference = "https://research.checkpoint.com/2022/twisted-panda-chinese-apt-espionage-operation-against-russians-state-owned-defense-institutes/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_cn_twisted_panda.yar#L46-L80"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "e7abe4b3f4225596131882a9175f9ac2e45ba00557950772a8e4d1eaeab97d05"
		score = 80
		quality = 85
		tags = "FILE"
		hash1 = "a9fb7bb40de8508606a318866e0e5ff79b98f314e782f26c7044622939dfde81"

	strings:
		$config_init = { C7 ?? ?? ?? 00 00 00 C7 ?? ?? ?? 00 00 00 C6 }
		$c2_cmd_1 = { 01 00 03 10}
		$c2_cmd_2 = { 02 00 01 10}
		$c2_cmd_3 = { 01 00 01 10}
		$decryption = { 8D 83 [4] 80 B3 [5] 89 F1 6A 01 50 E8 [4] 80 B3 }

	condition:
		uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 and filesize < 3000KB and #config_init > 10 and 2 of ( $c2_cmd_* ) and $decryption
}

rule SIGNATURE_BASE_APT_CN_Twistedpanda_SPINNER_2 : FILE
{
	meta:
		description = "Detects an older variant of SPINNER payload used by TwistedPanda"
		author = "Check Point Research"
		id = "bbbf3af1-127f-5d32-967f-bdb94311d1d6"
		date = "2022-04-14"
		modified = "2025-07-01"
		reference = "https://research.checkpoint.com/2022/twisted-panda-chinese-apt-espionage-operation-against-russians-state-owned-defense-institutes/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_cn_twisted_panda.yar#L82-L118"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "d1e34903e58fb76671a076acbb9f26e10d511c8f00be90b4901d61b73b90a9a7"
		score = 80
		quality = 85
		tags = "FILE"
		hash1 = "28ecd1127bac08759d018787484b1bd16213809a2cc414514dc1ea87eb4c5ab8"

	strings:
		$config_init = { C7 [3] 00 00 00 C7 [3] 00 00 00 C6 }
		$c2_cmd_1 = { 01 00 03 10 }
		$c2_cmd_2 = { 02 00 01 10 }
		$c2_cmd_3 = { 01 00 01 10 }
		$c2_cmd_4 = { 01 00 00 10 }
		$c2_cmd_5 = { 02 00 00 10 }
		$decryption = { 80 B3 [5] 8D BB [4] 8B 56 14 8B C2 8B 4E 10 2B C1 83 F8 01 }

	condition:
		uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 and filesize < 3000KB and #config_init > 10 and 2 of ( $c2_cmd_* ) and $decryption
}

rule SIGNATURE_BASE_APT_CN_Twistedpanda_64Bit_Loader : FILE
{
	meta:
		description = "Detects the 64bit Loader DLL used by TwistedPanda"
		author = "Check Point Research"
		id = "2172dd33-204b-5a05-ad26-534a0c1d7a17"
		date = "2022-04-14"
		modified = "2025-07-01"
		reference = "https://research.checkpoint.com/2022/twisted-panda-chinese-apt-espionage-operation-against-russians-state-owned-defense-institutes/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_cn_twisted_panda.yar#L120-L155"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "644547f9fa6ca3f34ea32e06896f341e0c92f5c57dee3c478aed0cdf87b2f3de"
		score = 80
		quality = 85
		tags = "FILE"
		hash1 = "e0d4ef7190ff50e6ad2a2403c87cc37254498e8cc5a3b2b8798983b1b3cdc94f"

	strings:
		$path_check = { 48 8D [6] 48 8B ?? 48 81 [5] 72 }
		$shellcode_read = { 48 8B D0 41 B8 F0 16 00 00 48 8B CF 48 8B D8 FF}
		$shellcode_allocate = { BA F0 16 00 00 44 8D 4E 40 33 C9 41 B8 00 30 00 00 FF }

	condition:
		uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 and filesize < 3000KB and $path_check and $shellcode_allocate and $shellcode_read
}

rule SIGNATURE_BASE_APT_CN_Twistedpanda_Droppers : FILE
{
	meta:
		description = "Detects droppers used by TwistedPanda"
		author = "Check Point Research"
		id = "f61c8b97-5870-5837-942f-f1650870960a"
		date = "2022-04-14"
		modified = "2025-07-01"
		reference = "https://research.checkpoint.com/2022/twisted-panda-chinese-apt-espionage-operation-against-russians-state-owned-defense-institutes/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_cn_twisted_panda.yar#L157-L194"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "820b4796511dcf98cdc8017a39cc2c65e44d8d9a20f55803aa1ddd36f649c83a"
		score = 80
		quality = 85
		tags = "FILE"
		hash1 = "59dea38da6e515af45d6df68f8959601e2bbf0302e35b7989e741e9aba2f0291"
		hash2 = "8b04479fdf22892cdfebd6e6fbed180701e036806ed0ddbe79f0b29f73449248"
		hash3 = "f29a0cda6e56fc0e26efa3b6628c6bcaa0819a3275a10e9da2a8517778152d66"

	strings:
		$switch_control = { 81 FA [4] 75 ?? E8 [4] 48 89 05 [4] E? }
		$byte_manipulation = { 41 0F [2] 44 [2] 41 [2] 03 41 81 [5] 41 }
		$stack_strings_1 = { 25 00 70 00 }
		$stack_strings_2 = { 75 00 62 00 }
		$stack_strings_3 = { 6C 00 69 00 }
		$stack_strings_4 = { 63 00 25 00 }

	condition:
		uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 and filesize < 3000KB and #switch_control > 8 and all of ( $stack_strings_* ) and $byte_manipulation
}

rule SIGNATURE_BASE_APT_KE3CHANG_TMPFILE : APT KE3CHANG TMPFILE FILE
{
	meta:
		description = "Detects Strings left in TMP Files created by K3CHANG Backdoor Ketrican"
		author = "Markus Neis, Swisscom"
		id = "84d411af-ea3d-5862-8c2f-7caca60c1b66"
		date = "2020-06-18"
		modified = "2023-12-05"
		reference = "https://app.any.run/tasks/a96f4f9d-c27d-490b-b5d3-e3be0a1c93e9/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_ke3chang.yar#L1-L21"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "75c97fe2eeb82e09f52e98d76bd529824f171da4c802b5febc1036314d8145f0"
		score = 75
		quality = 85
		tags = "APT, KE3CHANG, TMPFILE, FILE"
		hash1 = "4ef11e84d5203c0c425d1a76d4bf579883d40577c2e781cdccc2cc4c8a8d346f"

	strings:
		$pps1 = "PSParentPath             : Microsoft.PowerShell.Core\\Registry::HKEY_CURRENT_USE" fullword ascii
		$pps2 = "PSPath                   : Microsoft.PowerShell.Core\\Registry::HKEY_CURRENT_USE" fullword ascii
		$psp1 = ": Microsoft.PowerShell.Core\\Registry" ascii
		$s4 = "PSChildName  : PhishingFilter" fullword ascii
		$s1 = "DisableFirstRunCustomize : 2" fullword ascii
		$s7 = "PSChildName  : 3" fullword ascii
		$s8 = "2500         : 3" fullword ascii

	condition:
		uint16( 0 ) == 0x5350 and filesize < 1KB and $psp1 and 1 of ( $pps* ) and 1 of ( $s* )
}

rule SIGNATURE_BASE_APT_MAL_Ke3Chang_Ketrican_Jun20_1 : FILE
{
	meta:
		description = "Detects Ketrican malware"
		author = "Florian Roth (Nextron Systems)"
		id = "ccd8322e-c822-512a-9ac5-eabc9d09640b"
		date = "2020-06-18"
		modified = "2023-12-05"
		reference = "BfV Cyber-Brief Nr. 01/2020"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_ke3chang.yar#L23-L42"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "a2806de18432dbab24f08c7c2863fd694c91192cf7df4388dfeb87b237f22257"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "02ea0bc17875ab403c05b50205389065283c59e01de55e68cee4cf340ecea046"
		hash2 = "f3efa600b2fa1c3c85f904a300fec56104d2caaabbb39a50a28f60e0fdb1df39"

	strings:
		$xc1 = { 00 59 89 85 D4 FB FF FF 8B 85 D4 FB FF FF 89 45
               FC 68 E0 58 40 00 8F 45 FC E9 }
		$op1 = { 6a 53 58 66 89 85 24 ff ff ff 6a 79 58 66 89 85 }
		$op2 = { 8d 45 bc 50 53 53 6a 1c 8d 85 10 ff ff ff 50 ff }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 300KB and 1 of ( $x* ) or 2 of them
}

rule SIGNATURE_BASE_APT_UNC1151_Windowsinstaller_Silent_Installproduct_Macromethod : FILE
{
	meta:
		description = "No description has been set in the source file - Signature Base"
		author = "Proofpoint Threat Research"
		id = "9ae80d54-33b9-55d7-957f-0738243e089f"
		date = "2021-07-28"
		modified = "2023-12-05"
		reference = "Thttps://www.proofpoint.com/us/blog/threat-insight/asylum-ambuscade-state-actor-uses-compromised-private-ukrainian-military-emails"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_unc1151_ua.yar#L1-L16"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "aec1bb992061fdf1abf5c1a61cf9ec9e54c1f13be36ceb84890b058ade273b70"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "1561ece482c78a2d587b66c8eaf211e806ff438e506fcef8f14ae367db82d9b3"
		hash2 = "a8fd0a5de66fa39056c0ddf2ec74ccd38b2ede147afa602aba00a3f0b55a88e0"

	strings:
		$doc_header = {D0 CF 11 E0 A1 B1 1A E1}
		$s1 = ".UILevel = 2"
		$s2 = "CreateObject(\"WindowsInstaller.Installer\")"
		$s3 = ".InstallProduct \"http"

	condition:
		$doc_header at 0 and all of ( $s* )
}

rule SIGNATURE_BASE_APT_MAL_HP_Ilo_Firmware_Dec21_1 : FILE
{
	meta:
		description = "Detects suspicios ELF files with sections as described in malicious iLO Board analysis by AmnPardaz in December 2021"
		author = "Florian Roth (Nextron Systems)"
		id = "7f5fa905-07a3-55da-b644-c5ab882b4a9d"
		date = "2021-12-28"
		modified = "2023-12-05"
		reference = "https://threats.amnpardaz.com/en/2021/12/28/implant-arm-ilobleed-a/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_mal_ilo_board_elf.yar#L2-L18"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "7e959d07d864a485b8cc7765f9e12869ff34747ab552e26244eb28f510d1051f"
		score = 80
		quality = 85
		tags = "FILE"

	strings:
		$s1 = ".newelf.elf.text" ascii
		$s2 = ".newelf.elf.libc.so.data" ascii
		$s3 = ".newelf.elf.Initial.stack" ascii
		$s4 = ".newelf.elf.libevlog.so.data" ascii

	condition:
		filesize < 5MB and 2 of them or all of them
}

rule SIGNATURE_BASE_M_APT_Downloader_BEATDROP : FILE
{
	meta:
		description = "Rule looking for BEATDROP malware"
		author = "Mandiant"
		id = "5720870e-8989-59f2-998b-019084d091ce"
		date = "2022-04-28"
		modified = "2023-12-05"
		reference = "https://www.mandiant.com/resources/tracking-apt29-phishing-campaigns"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_apt29_nobelium_apr22.yar#L1-L17"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "7a766682cc9a057798cc569111bfcb611648c4a052c0dd664d983b80d5891255"
		score = 90
		quality = 85
		tags = "FILE"

	strings:
		$ntdll1 = "ntdll" ascii fullword
		$ntdll2 = "C:\\Windows\\System32\\ntdll.dll" ascii fullword nocase
		$url1 = "api.trello.com" ascii
		$url2 = "/members/me/boards?key=" ascii
		$url3 = "/cards?key=" ascii

	condition:
		uint16( 0 ) == 0x5a4d and uint32( uint32( 0x3C ) ) == 0x00004550 and filesize < 1MB and all of them
}

rule SIGNATURE_BASE_M_APT_Downloader_BOOMMIC : FILE
{
	meta:
		description = "Rule looking for BOOMMIC malware"
		author = "Mandiant"
		id = "34ea08a6-5d6f-5cdd-a629-fa36313c98f7"
		date = "2022-04-28"
		modified = "2023-12-05"
		reference = "https://www.mandiant.com/resources/tracking-apt29-phishing-campaigns"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_apt29_nobelium_apr22.yar#L19-L38"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "c561b19464597f896d31307c0383fbc639cf4211600513e1251a3f59405bfed6"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$loc_10001000 = { 55 8B EC 8D 45 0C 50 8B 4D 08 51 6A 02 FF 15 [4] 85 C0 74 09 B8 01 00 00 00 EB 04 EB 02 33 C0 5D C3 }
		$loc_100012fd = {6A 00 8D 55 EC 52 8B 45 D4 50 6A 05 8B 4D E4 51 FF 15 }
		$func1 = "GetComputerNameExA" ascii
		$func2 = "HttpQueryInfoA" ascii

	condition:
		uint16( 0 ) == 0x5a4d and uint32( uint32( 0x3C ) ) == 0x00004550 and filesize < 1MB and ( ( $loc_10001000 and $func1 ) or ( $loc_100012fd and $func2 ) )
}


rule SIGNATURE_BASE_APT_PY_Bluelight_Loader : INKYSQUID
{
	meta:
		description = "Python Loader used to execute the BLUELIGHT malware family."
		author = "threatintel@volexity.com"
		id = "f8da3e40-c3b0-5b7f-8ece-81874993d8cd"
		date = "2021-06-22"
		modified = "2023-12-05"
		reference = "https://www.volexity.com/blog/2021/08/24/north-korean-bluelight-special-inkysquid-deploys-rokrat/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_nk_inkysquid.yar#L39-L58"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "e7e18a6d648b1383706439ba923335ac4396f6b5d2a3dc8f30f63ded7df29eda"
		score = 75
		quality = 85
		tags = "INKYSQUID"
		hash1 = "80269413be6ad51b8b19631b2f5559c9572842e789bbce031babe6e879d2e120"
		license = "See license at https://github.com/volexity/threat-intel/LICENSE.txt"

	strings:
		$s1 = "\"\".join(chr(ord(" ascii
		$s2 = "import ctypes " ascii
		$s3 = "ctypes.CFUNCTYPE(ctypes.c_int)" ascii
		$s4 = "ctypes.memmove" ascii
		$s5 = "python ended" ascii

	condition:
		all of them
}

rule SIGNATURE_BASE_APT_MAL_Win_Decrok : INKYSQUID
{
	meta:
		description = "The DECROK malware family, which uses the victim's hostname to decrypt and execute an embedded payload."
		author = "threatintel@volexity.com"
		id = "dc83843d-fd2a-52f1-82e8-8e36b135a0c5"
		date = "2021-06-23"
		modified = "2023-12-05"
		reference = "https://www.volexity.com/blog/2021/08/24/north-korean-bluelight-special-inkysquid-deploys-rokrat/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_nk_inkysquid.yar#L61-L82"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		hash = "6a452d088d60113f623b852f33f8f9acf0d4197af29781f889613fed38f57855"
		logic_hash = "47fa03e95ac17ba7195858cd63b1769e5d56ab8a5edf872b345989b767050b87"
		score = 75
		quality = 85
		tags = "INKYSQUID"
		license = "See license at https://github.com/volexity/threat-intel/LICENSE.txt"

	strings:
		$v1 = {C7 ?? ?? ?? 01 23 45 67 [2-20] C7 ?? ?? ?? 89 AB CD EF C7 ?? ?? ?? FE DC BA 98}
		$av1 = "Select * From AntiVirusProduct" wide
		$av2 = "root\\SecurityCenter2" wide
		$funcformat = { 25 30 32 78 [0-10] 43 72 65 61 74 65 54 68 72 65 61 64 }

	condition:
		all of them
}

rule SIGNATURE_BASE_APT_NK_Scarcruft_RUBY_Shellcode_XOR_Routine : APT
{
	meta:
		description = "Detects Ruby ShellCode XOR routine used by ScarCruft APT group"
		author = "S2WLAB_TALON_JACK2"
		id = "c393f2db-8ade-5083-9cec-f62f23056f8b"
		date = "2021-05-20"
		modified = "2023-12-05"
		reference = "https://medium.com/s2wlab/matryoshka-variant-of-rokrat-apt37-scarcruft-69774ea7bf48"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_nk_inkysquid.yar#L104-L133"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "a97041a06729d639c22a4ee272cc96555345b692fc0da8b62e898891d02b23ea"
		score = 75
		quality = 85
		tags = "APT"
		type = "APT"
		version = "0.1"

	strings:
		$hex1 = {C1 C7 0D 40 F6 C7 01 74 ?? 81 F7}
		$hex2 = {41 C1 C2 0D 41 8B C2 44 8B CA 41 8B CA 41 81 F2}

	condition:
		1 of them
}

rule SIGNATURE_BASE_APT_NK_Scarcruft_Evolved_ROKRAT : APT FILE
{
	meta:
		description = "Detects RokRAT malware used by ScarCruft APT group"
		author = "S2WLAB_TALON_JACK2"
		id = "53cabf41-0154-5372-b667-60d8a7cb9806"
		date = "2021-07-09"
		modified = "2023-12-05"
		reference = "https://medium.com/s2wlab/matryoshka-variant-of-rokrat-apt37-scarcruft-69774ea7bf48"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_nk_inkysquid.yar#L135-L179"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "01a2f410687c943d6c6e421ffacfe42f9e7b6afb82e43ba03a8d525e075a3a3c"
		score = 75
		quality = 85
		tags = "APT, FILE"
		type = "APT"
		version = "0.1"

	strings:
		$AES_IV_KEY = {
        C7 44 24 ?? 32 31 12 23
        C7 44 24 ?? 34 45 56 67
        C7 44 24 ?? 78 89 9A AB
        C7 44 24 ?? 0C BD CE DF
        C7 45 ?? 2B 7E A5 16
        C7 45 ?? 28 AE D2 A6
        C7 45 ?? AB F7 15 88
        C7 45 ?? 09 CF 4F 3C
        }
		$url_deocde = {
               80 E9 0F
               80 F1 C8
               88 48 ??
               48 83 EA 01  }

	condition:
		uint16( 0 ) == 0x5A4D and any of them
}

rule SIGNATURE_BASE_APT_Crywiper_Dec22
{
	meta:
		description = "Detects CryWiper malware samples"
		author = "Florian Roth (Nextron Systems)"
		id = "d56ccf4e-30ba-5308-ad68-ffc2ae5a1718"
		date = "2022-12-05"
		modified = "2023-12-05"
		reference = "https://securelist-ru.translate.goog/novyj-troyanec-crywiper/106114/?_x_tr_sl=auto&_x_tr_tl=en&_x_tr_hl=en"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_ru_crywiper.yar#L2-L19"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "7c22e02ed996cd820ed87a0c5d50e3264629cdd887aad4ea466cadeccaee2b2f"
		score = 75
		quality = 85
		tags = ""

	strings:
		$x1 = "Software\\Sysinternals\\BrowserUpdate"
		$sx1 = "taskkill.exe /f /im MSExchange*"
		$s1 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server" ascii
		$s2 = "fDenyTSConnections" ascii

	condition:
		1 of ( $x* ) or all of ( $s* )
}

rule SIGNATURE_BASE_APT_SAP_Netweaver_Exploitation_Activity_Apr25_1 : SCRIPT CVE_2025_31324 FILE
{
	meta:
		description = "Detects forensic artefacts related to exploitation activity of SAP NetWeaver CVE-2025-31324"
		author = "Florian Roth"
		id = "78863492-5c83-55a8-900b-057e99125414"
		date = "2025-04-25"
		modified = "2025-05-15"
		reference = "https://reliaquest.com/blog/threat-spotlight-reliaquest-uncovers-vulnerability-behind-sap-netweaver-compromise/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/expl_sap_netweaver_apr25.yar#L2-L14"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "ab6c5e17bba15a3f968bdbe88a8cf4a039c55b6035d91fd3c6b30092be89af5c"
		score = 70
		quality = 85
		tags = "SCRIPT, CVE-2025-31324, FILE"

	strings:
		$x01 = "/helper.jsp?cmd=" ascii wide
		$x02 = "/cache.jsp?cmd=" ascii wide

	condition:
		filesize < 20MB and 1 of them
}

rule SIGNATURE_BASE_APT_SAP_Netweaver_Exploitation_Activity_Apr25_2 : SCRIPT CVE_2025_31324 FILE
{
	meta:
		description = "Detects forensic artefacts related to exploitation activity of SAP NetWeaver CVE-2025-31324"
		author = "Florian Roth"
		id = "17fb236e-e78c-51e5-b0a8-14964e38dfc5"
		date = "2025-04-25"
		modified = "2025-05-15"
		reference = "https://reliaquest.com/blog/threat-spotlight-reliaquest-uncovers-vulnerability-behind-sap-netweaver-compromise/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/expl_sap_netweaver_apr25.yar#L16-L27"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "dfc24a4f359e2bc899ab3924bd342c2c6bd8c757b7c1d3859a47f61b9e4039a9"
		score = 70
		quality = 85
		tags = "SCRIPT, CVE-2025-31324, FILE"

	strings:
		$x03 = "MSBuild.exe c:\\programdata\\" ascii wide

	condition:
		filesize < 20MB and 1 of them
}

rule SIGNATURE_BASE_APT_MAL_Sandworm_Exaramel_Configuration_Key
{
	meta:
		description = "Detects the encryption key for the configuration file used by Exaramel malware as seen in sample e1ff72[...]"
		author = "FR/ANSSI/SDO"
		id = "8078de62-3dd2-5ee0-8bda-f508e4013144"
		date = "2021-02-15"
		modified = "2024-05-25"
		reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_sandworm_centreon.yar#L78-L90"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "056503a2c240a641cd2292a30ab1090e3a358cb4d57dca83b836ecb1bc62ed6b"
		score = 80
		quality = 85
		tags = ""

	strings:
		$ = "odhyrfjcnfkdtslt"

	condition:
		all of them
}

rule SIGNATURE_BASE_APT_MAL_Sandworm_Exaramel_Configuration_Name_Encrypted
{
	meta:
		description = "Detects the specific name of the configuration file in Exaramel malware as seen in sample e1ff72[...]"
		author = "FR/ANSSI/SDO"
		id = "1c06f5fc-3435-51cd-92fb-17a4ab6b63ad"
		date = "2021-02-15"
		modified = "2024-05-25"
		reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_sandworm_centreon.yar#L92-L104"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "f65d59381403534a2c2f39d66c7c62bf1540eafc9aad1ad73de1809e91c42446"
		score = 80
		quality = 85
		tags = ""

	strings:
		$ = "configtx.json"

	condition:
		all of them
}

rule SIGNATURE_BASE_APT_MAL_Sandworm_Exaramel_Configuration_File_Ciphertext
{
	meta:
		description = "Detects contents of the configuration file used by Exaramel (encrypted with key odhyrfjcnfkdtslt, sample e1ff72[...]"
		author = "FR/ANSSI/SDO"
		id = "763dbb17-2bad-5b40-8a7b-b71bc5849cd9"
		date = "2021-02-15"
		modified = "2024-05-25"
		reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_sandworm_centreon.yar#L120-L132"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "9dc7ee5b0a218a2b5be652e137fa090c944c3ddb0f699f521a72896668210813"
		score = 80
		quality = 85
		tags = ""

	strings:
		$ = { 6F B6 08 E9 A3 0C 8D 5E DD BE D4 }

	condition:
		all of them
}

rule SIGNATURE_BASE_APT_MAL_Sandworm_Exaramel_Socket_Path
{
	meta:
		description = "Detects path of the unix socket created to prevent concurrent executions in Exaramel malware"
		author = "FR/ANSSI/SDO"
		id = "3aab84c9-9748-5d11-9cd7-efa9151036cf"
		date = "2021-02-15"
		modified = "2024-05-25"
		reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_sandworm_centreon.yar#L134-L146"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "8c049b5a7b508ca0f160d166f3c726e4a23a2c5b3105d075d7bf7a301a1c58f6"
		score = 80
		quality = 85
		tags = ""

	strings:
		$ = "/tmp/.applocktx"

	condition:
		all of them
}

rule SIGNATURE_BASE_APT_MAL_Sandworm_Exaramel_Task_Names
{
	meta:
		description = "Detects names of the tasks received from the CC server in Exaramel malware"
		author = "FR/ANSSI/SDO"
		id = "185f2f3b-bf5c-54af-bca2-400d08bf9c91"
		date = "2021-02-15"
		modified = "2024-05-25"
		reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_sandworm_centreon.yar#L148-L167"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "193482da1e2b9509fa9c65d46edc56057f7b5d44b7408d918d4a9cbb60736dab"
		score = 80
		quality = 85
		tags = ""

	strings:
		$ = "App.Delete"
		$ = "App.SetServer"
		$ = "App.SetProxy"
		$ = "App.SetTimeout"
		$ = "App.Update"
		$ = "IO.ReadFile"
		$ = "IO.WriteFile"
		$ = "OS.ShellExecute"

	condition:
		all of them
}

rule SIGNATURE_BASE_APT_MAL_Sandworm_Exaramel_Struct
{
	meta:
		description = "Detects the beginning of type _type struct for some of the most important structs in Exaramel malware"
		author = "FR/ANSSI/SDO"
		id = "8282e485-966c-554d-8e41-70dc1657f5ea"
		date = "2021-02-15"
		modified = "2024-05-25"
		reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_sandworm_centreon.yar#L169-L185"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "312d0598fa85837f94023036468fcae50e8b2de532430a944befa8090afe79f6"
		score = 80
		quality = 85
		tags = ""

	strings:
		$struct_le_config = {70 00 00 00 00 00 00 00 58 00 00 00 00 00 00 00 47 2d 28 42 0? [2] 19}
		$struct_le_worker = {30 00 00 00 00 00 00 00 30 00 00 00 00 00 00 00 46 6a 13 e2 0? [2] 19}
		$struct_le_client = {20 00 00 00 00 00 00 00 10 00 00 00 00 00 00 00 7b 6a 49 84 0? [2] 19}
		$struct_le_report = {30 00 00 00 00 00 00 00 28 00 00 00 00 00 00 00 bf 35 0d f9 0? [2] 19}
		$struct_le_task = {50 00 00 00 00 00 00 00 20 00 00 00 00 00 00 00 88 60 a1 c5 0? [2] 19}

	condition:
		any of them
}

rule SIGNATURE_BASE_APT_MAL_Sandworm_Exaramel_Strings_Typo
{
	meta:
		description = "Detects misc strings in Exaramel malware with typos"
		author = "FR/ANSSI/SDO"
		id = "fdc79b87-eb9e-5751-9474-ff653b073165"
		date = "2021-02-15"
		modified = "2024-05-25"
		reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_sandworm_centreon.yar#L187-L202"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "65e6de743eb9fc742674c7e54eef8a376963a6fd4380bacd03fe6f92d4235920"
		score = 80
		quality = 85
		tags = ""

	strings:
		$typo1 = "/sbin/init | awk "
		$typo2 = "Syslog service for monitoring \n"
		$typo3 = "Error.Can't update app! Not enough update archive."
		$typo4 = ":\"metod\""

	condition:
		3 of ( $typo* )
}

rule SIGNATURE_BASE_APT_MAL_Sandworm_Exaramel_Strings
{
	meta:
		description = "Detects Strings used by Exaramel malware"
		author = "FR/ANSSI/SDO (composed from 4 saparate rules by Florian Roth)"
		id = "fdc79b87-eb9e-5751-9474-ff653b073165"
		date = "2021-02-15"
		modified = "2024-05-25"
		reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_sandworm_centreon.yar#L204-L232"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "9d2790e60184ed973b2735263d0a997f32af0beacc9ea8ef65926fe6507011d5"
		score = 80
		quality = 85
		tags = ""

	strings:
		$persistence1 = "systemd"
		$persistence2 = "upstart"
		$persistence3 = "systemV"
		$persistence4 = "freebsd rc"
		$report1 = "systemdupdate.rep"
		$report2 = "upstartupdate.rep"
		$report3 = "remove.rep"
		$url1 = "/tasks.get/"
		$url2 = "/time.get/"
		$url3 = "/time.set"
		$url4 = "/tasks.report"
		$url5 = "/attachment.get/"
		$url6 = "/auth/app"

	condition:
		(5 of ( $url* ) and all of ( $persistence* ) ) or ( all of ( $persistence* ) and all of ( $report* ) ) or ( 5 of ( $url* ) and all of ( $report* ) )
}

rule SIGNATURE_BASE_APT_APT41_POISONPLUG_3 : FILE
{
	meta:
		description = "Detects APT41 malware POISONPLUG"
		author = "Florian Roth (Nextron Systems)"
		id = "e150dd69-c611-53de-9c7d-de28d3a208dc"
		date = "2019-08-07"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_apt41.yar#L14-L31"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "b74b89ac382b2b839c169cd1388d86888172f133091afd079ec42c9380935fdc"
		score = 80
		quality = 85
		tags = "FILE"
		hash1 = "70c03ce5c80aca2d35a5555b0532eedede24d4cc6bdb32a2c8f7e630bba5f26e"

	strings:
		$s1 = "Rundll32.exe \"%s\", DisPlay 64" fullword ascii
		$s2 = "tcpview.exe" fullword ascii
		$s3 = "nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" fullword ascii
		$s4 = "AxEeulaVteSgeR" fullword ascii
		$s5 = "%04d-%02d-%02d_%02d-%02d-%02d.dmp" fullword ascii

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 900KB and 3 of them
}


rule SIGNATURE_BASE_APT_APT41_POISONPLUG_SHADOW : FILE
{
	meta:
		description = "Detects APT41 malware POISONPLUG SHADOW"
		author = "Florian Roth (Nextron Systems)"
		id = "e150dd69-c611-53de-9c7d-de28d3a208dc"
		date = "2019-08-07"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_apt41.yar#L33-L44"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "fc923c7e85f3870e08a077b344e575d3c349fa02f3d218a9a7ec31992f14866b"
		score = 85
		quality = 85
		tags = "FILE"
		hash1 = "462a02a8094e833fd456baf0a6d4e18bb7dab1a9f74d5f163a8334921a4ffde8"

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 500KB and pe.imphash ( ) == "c67de089f2009b21715744762fc484e8"
}

rule SIGNATURE_BASE_APT_APT41_CRACKSHOT : FILE
{
	meta:
		description = "Detects APT41 malware CRACKSHOT"
		author = "Florian Roth (Nextron Systems)"
		id = "4ec34a77-dc7f-5f27-9f0a-c98438389018"
		date = "2019-08-07"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_apt41.yar#L46-L64"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "70dd9edfc7f9ace7b00a35eb2ef664aa4fbaab8e2d268922d1593074897e769c"
		score = 85
		quality = 85
		tags = "FILE"
		hash1 = "993d14d00b1463519fea78ca65d8529663f487cd76b67b3fd35440bcdf7a8e31"

	strings:
		$x1 = ";procmon64.exe;netmon.exe;tcpview.exe;MiniSniffer.exe;smsniff.exe" ascii
		$s1 = "RunUrlBinInMem" fullword ascii
		$s2 = "DownRunUrlFile" fullword ascii
		$s3 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36" fullword ascii
		$s4 = "%s|%s|%s|%s|%s|%s|%s|%dx%d|%04x|%08X|%s|%s" fullword ascii

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 250KB and ( 1 of ( $x* ) or 2 of them )
}

rule SIGNATURE_BASE_APT_APT41_POISONPLUG_2 : FILE
{
	meta:
		description = "Detects APT41 malware POISONPLUG"
		author = "Florian Roth (Nextron Systems)"
		id = "e150dd69-c611-53de-9c7d-de28d3a208dc"
		date = "2019-08-07"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_apt41.yar#L66-L82"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "f2ec2e91edaaf976169b1fa6645aeae75135e5d5f522e0fda2438f84d674f383"
		score = 70
		quality = 85
		tags = "FILE"
		hash1 = "0055dfaccc952c99b1171ce431a02abfce5c6f8fb5dc39e4019b624a7d03bfcb"

	strings:
		$s1 = "ma_lockdown_service.dll" fullword wide
		$s2 = "acbde.dll" fullword ascii
		$s3 = "MA lockdown Service" fullword wide
		$s4 = "McAfee Agent" fullword wide

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 11000KB and all of them
}


rule SIGNATURE_BASE_APT_APT41_POISONPLUG : FILE
{
	meta:
		description = "Detects APT41 malware POISONPLUG"
		author = "Florian Roth (Nextron Systems)"
		id = "e150dd69-c611-53de-9c7d-de28d3a208dc"
		date = "2019-08-07"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_apt41.yar#L84-L106"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "34459c2a8a13b8084c93a640723a3e2b67d2f695ff84ab63f4e313cacc458f32"
		score = 80
		quality = 85
		tags = "FILE"
		hash1 = "2eea29d83f485897e2bac9501ef000cc266ffe10019d8c529555a3435ac4aabd"
		hash2 = "5d971ed3947597fbb7e51d806647b37d64d9fe915b35c7c9eaf79a37b82dab90"
		hash3 = "f4d57acde4bc546a10cd199c70cdad09f576fdfe66a36b08a00c19ff6ae19661"
		hash4 = "3e6c4e97cc09d0432fbbbf3f3e424d4aa967d3073b6002305cd6573c47f0341f"

	strings:
		$s1 = "TSMSISrv.DLL" fullword wide
		$s2 = "[-]write failed[%d]" fullword ascii
		$s3 = "[-]load failed" fullword ascii
		$s4 = "Remote Desktop Services" fullword wide

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 10000KB and ( pe.imphash ( ) == "1b074ef7a1c0888ef31337c8ad2f2e0a" or 2 of them )
}

rule SIGNATURE_BASE_APT_APT41_HIGHNOON : FILE
{
	meta:
		description = "Detects APT41 malware HIGHNOON"
		author = "Florian Roth (Nextron Systems)"
		id = "6611fb04-7237-52d1-b29f-941c3853aeca"
		date = "2019-08-07"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_apt41.yar#L108-L135"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "c8afa91f90157c3ac0f7954cd2d42022392c4e6f039d88d1dd4bace19028c2b1"
		score = 85
		quality = 85
		tags = "FILE"
		hash1 = "63e8ed9692810d562adb80f27bb1aeaf48849e468bf5fd157bc83ca83139b6d7"
		hash2 = "4aa6970cac04ace4a930de67d4c18106cf4004ba66670cfcdaa77a4c4821a213"

	strings:
		$x1 = "workdll64.dll" fullword ascii
		$s1 = "\\Fonts\\Error.log" ascii
		$s2 = "[%d/%d/%d/%d:%d:%d]" fullword ascii
		$s3 = "work_end" fullword ascii
		$s4 = "work_start" fullword ascii
		$s5 = "\\svchost.exe" ascii
		$s6 = "LoadAppInit_DLLs" fullword ascii
		$s7 = "netsvcs" fullword ascii
		$s8 = "HookAPIs ...PID %d " fullword ascii
		$s9 = "SOFTWARE\\Microsoft\\HTMLHelp" fullword ascii
		$s0 = "DllMain_mem" fullword ascii
		$s10 = "%s\\NtKlRes.dat" fullword ascii
		$s11 = "Global\\%s-%d" fullword ascii

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 2000KB and ( 1 of ( $x* ) or 4 of them )
}


rule SIGNATURE_BASE_APT_APT41_HIGHNOON_2 : FILE
{
	meta:
		description = "Detects APT41 malware HIGHNOON"
		author = "Florian Roth (Nextron Systems)"
		id = "1e48d859-2da9-583e-80e5-8d59054cfb85"
		date = "2019-08-07"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_apt41.yar#L137-L157"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "dc35b78df1631b1c9650de2bac625a7bc629225f36fe5e32fbff829cb77dc9ac"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "79190925bd1c3fae65b0d11db40ac8e61fb9326ccfed9b7e09084b891089602d"

	strings:
		$x1 = "H:\\RBDoor\\" ascii
		$s1 = "PlusDll.dll" fullword ascii
		$s2 = "ShutDownEvent.dll" fullword ascii
		$s3 = "\\svchost.exe" ascii

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 600KB and ( pe.imphash ( ) == "b70358b00dd0138566ac940d0da26a03" or pe.exports ( "DllMain_mem" ) or $x1 or 3 of them )
}


rule SIGNATURE_BASE_APT_APT41_HIGHNOON_BIN : FILE
{
	meta:
		description = "Detects APT41 malware HIGHNOON.BIN"
		author = "Florian Roth (Nextron Systems)"
		id = "c8bd62b4-b882-5c04-aace-76dd4a21a784"
		date = "2019-08-07"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_apt41.yar#L159-L180"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "c6557bff952454482271d1b52fb37b2dd0471abd237449fd9c94b293ea5218b3"
		score = 90
		quality = 85
		tags = "FILE"
		hash1 = "490c3e4af829e85751a44d21b25de1781cfe4961afdef6bb5759d9451f530994"
		hash2 = "79190925bd1c3fae65b0d11db40ac8e61fb9326ccfed9b7e09084b891089602d"

	strings:
		$s1 = "PlusDll.dll" fullword ascii
		$s2 = "\\Device\\PORTLESS_DeviceName" wide
		$s3 = "%s%s\\Security" fullword ascii
		$s4 = "%s\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" fullword ascii
		$s5 = "%s%s\\Enum" fullword ascii

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 600KB and ( pe.imphash ( ) == "b70358b00dd0138566ac940d0da26a03" or 3 of them )
}

rule SIGNATURE_BASE_APT_APT41_HIGHNOON_BIN_2 : FILE
{
	meta:
		description = "Detects APT41 malware HIGHNOON.BIN"
		author = "Florian Roth (Nextron Systems)"
		id = "37d6a44d-7811-5e87-84e2-b2a8b3da3124"
		date = "2019-08-07"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_apt41.yar#L182-L200"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "1e3d622b4719962f59d95dbf1374c526c22461dd1d9313504f28e8e5c9184272"
		score = 85
		quality = 85
		tags = "FILE"
		hash1 = "63e8ed9692810d562adb80f27bb1aeaf48849e468bf5fd157bc83ca83139b6d7"
		hash2 = "c51c5bbc6f59407286276ce07f0f7ea994e76216e0abe34cbf20f1b1cbd9446d"

	strings:
		$x1 = "\\Double\\Door_wh\\" ascii
		$x2 = "[Stone] Config --> 2k3 TCP Positive Logout." fullword ascii
		$x3 = "\\RbDoorX64.pdb" ascii
		$x4 = "RbDoor, Version 1.0" fullword wide
		$x5 = "About RbDoor" fullword wide

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 2000KB and 1 of them
}

rule SIGNATURE_BASE_APT_Equation_Group_Op_Triangulation_Triangledb_Implant_Jun23_1 : FILE
{
	meta:
		description = "Detects TriangleDB implant found being used in Operation Triangulation on iOS devices (maybe also used on macOS systems)"
		author = "Florian Roth"
		id = "d81a5103-41c8-5dba-a560-8fb5514f6c0a"
		date = "2023-06-21"
		modified = "2023-12-05"
		reference = "https://securelist.com/triangledb-triangulation-implant/110050/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_eqgrp_triangulation_jun23.yar#L2-L18"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "486b19ddb8b182dbba882359f7eb416735e76f9cda5aea1b290fb5c6b44960c5"
		score = 80
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "unmungeHexString" ascii fullword
		$s2 = "CRPwrInfo" ascii fullword
		$s3 = "CRConfig" ascii fullword
		$s4 = "CRXConfigureDBServer" ascii fullword

	condition:
		( uint16( 0 ) == 0xfacf and filesize < 30MB and $s1 and 2 of them ) or all of them
}

rule SIGNATURE_BASE_Apt_CN_Tetris_JS_Advanced_1 : FILE
{
	meta:
		description = "Unique code from Jetriz, Swid & Jeniva of the Tetris framework"
		author = "@imp0rtp3 (modified by Florian Roth)"
		id = "a56f69f5-3562-52ab-9686-411019c51055"
		date = "2020-09-06"
		modified = "2023-12-05"
		reference = "https://imp0rtp3.wordpress.com/2021/08/12/tetris"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_tetris.yar#L2-L31"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "ec4ba53fea05c5331ed900b8c7da4cddd4ab64e87dfc165ac18d72d22f754d87"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$a1 = "var a0_0x"
		$b1 = "a0_0x" ascii
		$cx1 = "))),function(){try{var _0x"
		$cx2 = "=window)||void 0x0===_0x"
		$cx3 = "){if(opener&&void 0x0!==opener["
		$cx4 = "String['fromCharCode'](0x"
		$e1 = "')](__p__)"

	condition:
		$a1 at 0 or ( filesize < 1000KB and ( #b1 > 300 or #e1 > 1 or 2 of ( $cx* ) ) )
}

rule SIGNATURE_BASE_APT_MAL_Revil_Kaseya_Jul21_1 : FILE
{
	meta:
		description = "Detects malware used in the Kaseya supply chain attack"
		author = "Florian Roth (Nextron Systems)"
		id = "7356f4ea-183f-52ec-a167-fc16b8bfb55a"
		date = "2021-07-02"
		modified = "2023-12-05"
		reference = "https://doublepulsar.com/kaseya-supply-chain-attack-delivers-mass-ransomware-event-to-us-companies-76e4ec6ec64b"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/crime_revil_general.yar#L3-L30"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "a7f9fa8f8e8a3a25728aa6a334924e0b4075f3422df6b92a2f544bb0ebb6bfad"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "1fe9b489c25bb23b04d9996e8107671edee69bd6f6def2fe7ece38a0fb35f98e"
		hash2 = "aae6e388e774180bc3eb96dad5d5bfefd63d0eb7124d68b6991701936801f1c7"
		hash3 = "dc6b0e8c1e9c113f0364e1c8370060dee3fcbe25b667ddeca7623a95cd21411f"
		hash4 = "df2d6ef0450660aaae62c429610b964949812df2da1c57646fc29aa51c3f031e"

	strings:
		$s1 = "Mpsvc.dll" wide fullword
		$s2 = ":0:4:8:<:@:D:H:L:P:T:X:\\:`:d:h:l:p:t:x:H<L<P<\\<`<" ascii fullword
		$op1 = { 40 87 01 c3 6a 08 68 f8 0e 41 00 e8 ae db ff ff be 80 25 41 00 39 35 ?? 32 41 00 }
		$op2 = { 8b 40 04 2b c2 c1 f8 02 3b c8 0f 84 56 ff ff ff 68 15 50 40 00 2b c1 6a 04 }
		$op3 = { 74 73 db e2 e8 ad 07 00 00 68 60 1a 40 00 e8 8f 04 00 00 e8 3a 05 00 00 50 e8 25 26 00 00 }
		$op4 = { 75 05 8b 45 fc eb 4c c7 45 f8 00 00 00 00 6a 00 8d 45 f0 50 8b 4d 0c }
		$op5 = { 83 7d 0c 00 75 05 8b 45 fc eb 76 6a 00 68 80 00 00 00 6a 01 6a 00 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 3000KB and ( pe.imphash ( ) == "c36dcd2277c4a707a1a645d0f727542a" or 2 of them )
}

rule SIGNATURE_BASE_APT_MAL_Revil_Kaseya_Jul21_2 : FILE
{
	meta:
		description = "Detects malware used in the Kaseya supply chain attack"
		author = "Florian Roth (Nextron Systems)"
		id = "38b168d4-e761-544e-9859-eb155bbfe54a"
		date = "2021-07-02"
		modified = "2023-12-05"
		reference = "https://doublepulsar.com/kaseya-supply-chain-attack-delivers-mass-ransomware-event-to-us-companies-76e4ec6ec64b"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/crime_revil_general.yar#L32-L57"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "44948d93c71370a9976f22bf78cd1af80359f2c9804ea7995791109785cfaf84"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "0496ca57e387b10dfdac809de8a4e039f68e8d66535d5d19ec76d39f7d0a4402"
		hash2 = "8dd620d9aeb35960bb766458c8890ede987c33d239cf730f93fe49d90ae759dd"
		hash3 = "cc0cdc6a3d843e22c98170713abf1d6ae06e8b5e34ed06ac3159adafe85e3bd6"
		hash4 = "d5ce6f36a06b0dc8ce8e7e2c9a53e66094c2adfc93cfac61dd09efe9ac45a75f"
		hash5 = "d8353cfc5e696d3ae402c7c70565c1e7f31e49bcf74a6e12e5ab044f306b4b20"
		hash6 = "e2a24ab94f865caeacdf2c3ad015f31f23008ac6db8312c2cbfb32e4a5466ea2"

	strings:
		$opa1 = { 8b 4d fc 83 c1 01 89 4d fc 81 7d f0 ff 00 00 00 77 1? ba 01 00 00 00 6b c2 00 8b 4d 08 }
		$opa2 = { 89 45 f0 8b 4d fc 83 c1 01 89 4d fc 81 7d f0 ff 00 00 00 77 1? ba 01 00 00 00 6b c2 00 }
		$opa3 = { 83 c1 01 89 4d fc 81 7d f0 ff 00 00 00 77 1? ba 01 00 00 00 6b c2 00 8b 4d 08 0f b6 14 01 }
		$opa4 = { 89 45 f4 8b 0d ?? ?0 07 10 89 4d f8 8b 15 ?? ?1 07 10 89 55 fc ff 75 fc ff 75 f8 ff 55 f4 }
		$opb1 = { 18 00 10 bd 18 00 10 bd 18 00 10 0e 19 00 10 cc cc cc }
		$opb2 = { 18 00 10 0e 19 00 10 cc cc cc cc 8b 44 24 04 }
		$opb3 = { 10 c4 18 00 10 bd 18 00 10 bd 18 00 10 0e 19 00 10 cc cc }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 3000KB and ( 2 of ( $opa* ) or 3 of them )
}

rule SIGNATURE_BASE_APT_Sidewinder_NET_Loader_Aug_2020_1_1 : FILE
{
	meta:
		description = "Detected the NET loader used by SideWinder group (August 2020)"
		author = "Arkbird_SOLG"
		id = "61d96e2a-3a43-586f-85bc-a2c53b1318e6"
		date = "2020-08-24"
		modified = "2023-12-05"
		reference = "https://twitter.com/ShadowChasing1/status/1297902086747598852"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_sidewinder.yar#L4-L22"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "5ee7029143c589f26e6c325e163bfac85507c950f09778bd51ec2bdf4d4263fa"
		score = 75
		quality = 83
		tags = "FILE"
		hash1 = "4a0947dd9148b3d5922651a6221afc510afcb0dfa69d08ee69429c4c75d4c8b4"

	strings:
		$a1 = "DUSER.dll" fullword wide
		$s1 = "UHJvZ3JhbQ==" fullword wide
		$s2 = "U3RhcnQ=" fullword wide
		$s3 = ".tmp           " fullword wide
		$s4 = "FileRipper" fullword ascii
		$s5 = "copytight @" fullword wide

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 4KB and $a1 and 3 of ( $s* )
}

rule SIGNATURE_BASE_APT_MAL_Sidewinder_Implant : FILE
{
	meta:
		description = "Detects SideWinder final payload"
		author = "AT&T Alien Labs"
		id = "3a420c9c-7821-5405-8d4d-6931d0f311ba"
		date = "2020-08-25"
		modified = "2023-12-05"
		reference = "https://cybersecurity.att.com/blogs/labs-research/a-global-perspective-of-the-sidewinder-apt"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_sidewinder.yar#L24-L50"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "bfad86dbdc04463e7e4cc126fd05fc9107617a7ea1bd3f283c0e0170862bd59b"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "c568238dcf1e30d55a398579a4704ddb8196b685"

	strings:
		$code = { 1B 30 05 00 C7 00 00 00 00 00 00 00 02 28 03 00
               00 06 7D 12 00 00 04 02 02 FE 06 23 00 00 06 73
               5B 00 00 0A 14 20 88 13 00 00 15 73 5C 00 00 0A
               7D 13 00 00 04 02 02 FE 06 24 00 00 06 73 5B 00
               00 0A 14 20 88 13 00 00 15 73 5C 00 00 0A 7D 15
               00 00 04 02 7B 12 00 00 04 6F 0E 00 00 06 2C 1D
               02 28 1F 00 00 06 02 7B 12 00 00 04 16 6F 0F 00
               00 06 02 7B 12 00 00 04 6F 06 00 00 06 02 7B 12
               00 00 04 6F 10 00 00 06 2C 23 02 28 20 00 00 06
               02 28 21 00 00 06 02 7B 12 00 00 04 16 }
		$strings = { 
         2E 00 73 00 69 00 66 00 00 09 2E 00 66 00 6C 00
         63 00 00 1B 73 00 65 00 6C 00 65 00 63 00 74 00
         65 00 64 00 46 00 69 00 6C 00 65 00 73
      }

	condition:
		uint16( 0 ) == 0x5A4D and all of them
}

rule SIGNATURE_BASE_APT_UNC5221_Ivanti_Forensicartifacts_Jan24_1 : FILE
{
	meta:
		description = "Detects forensic artifacts found in the Ivanti VPN exploitation campaign by APT UNC5221"
		author = "Florian Roth"
		id = "49ba2a96-379d-5a58-979d-45e83fa546e7"
		date = "2024-01-11"
		modified = "2024-04-24"
		reference = "https://www.mandiant.com/resources/blog/suspected-apt-targets-ivanti-zero-day"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_report_ivanti_mandiant_jan24.yar#L2-L16"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "7f485f41072f5584dc76e71564e13066d9fe41685f33bff9c2886fa7d2155f94"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$x1 = "system(\"chmod a+x /home/etc/sql/dsserver/sessionserver.sh\");"
		$x2 = "SSH-2.0-OpenSSH_0.3xx."
		$x3 = "sed -i '/retval=$(exec $installer $@)/d' /pkg/do-install"

	condition:
		filesize < 5MB and 1 of them
}

rule SIGNATURE_BASE_APT_NK_MAL_M_Hunting_VEILEDSIGNAL_1 : FILE
{
	meta:
		description = "Detects VEILEDSIGNAL malware"
		author = "Mandiant"
		id = "3e7c92fe-a7bd-5180-9935-4f98f2b64e2b"
		date = "2023-04-20"
		modified = "2023-12-05"
		reference = "https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_nk_tradingtech_apr23.yar#L37-L55"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "439a201e6a44a00a31fd13efc83a1acf858a52201e3ab48d5cf095bae1e48cf7"
		score = 75
		quality = 85
		tags = "FILE"
		disclaimer = "This rule is meant for hunting and is not tested to run in a production environment"
		hash1 = "404b09def6054a281b41d309d809a428"
		hash2 = "c6441c961dcad0fe127514a918eaabd4"

	strings:
		$rh1 = { 68 5D 7A D2 2C 3C 14 81 2C 3C 14 81 2C 3C 14 81 77 54 10 80 26 3C 14 81 77 54 17 80 29 3C 14 81 77 54 11 80 AB 3C 14 81 D4 4C 11 80 33 3C 14 81 D4 4C 10 80 22 3C 14 81 D4 4C 17 80 25 3C 14 81 77 54 15 80 27 3C 14 81 2C 3C 15 81 4B 3C 14 81 94 4D 1D 80 28 3C 14 81 94 4D 14 80 2D 3C 14 81 94 4D 16 80 2D 3C 14 81 }
		$rh2 = { 00 E5 A0 2B 44 84 CE 78 44 84 CE 78 44 84 CE 78 1F EC CA 79 49 84 CE 78 1F EC CD 79 41 84 CE 78 1F EC CB 79 C8 84 CE 78 BC F4 CA 79 4A 84 CE 78 BC F4 CD 79 4D 84 CE 78 BC F4 CB 79 65 84 CE 78 1F EC CF 79 43 84 CE 78 44 84 CF 78 22 84 CE 78 FC F5 C7 79 42 84 CE 78 FC F5 CE 79 45 84 CE 78 FC F5 CC 79 45 84 CE 78}
		$rh3 = { DA D2 21 22 9E B3 4F 71 9E B3 4F 71 9E B3 4F 71 C5 DB 4C 70 94 B3 4F 71 C5 DB 4A 70 15 B3 4F 71 C5 DB 4B 70 8C B3 4F 71 66 C3 4B 70 8C B3 4F 71 66 C3 4C 70 8F B3 4F 71 C5 DB 49 70 9F B3 4F 71 66 C3 4A 70 B0 B3 4F 71 C5 DB 4E 70 97 B3 4F 71 9E B3 4E 71 F9 B3 4F 71 26 C2 46 70 9F B3 4F 71 26 C2 B0 71 9F B3 4F 71 9E B3 D8 71 9F B3 4F 71 26 C2 4D 70 9F B3 4F 71 }
		$rh4 = { CB 8A 35 66 8F EB 5B 35 8F EB 5B 35 8F EB 5B 35 D4 83 5F 34 85 EB 5B 35 D4 83 58 34 8A EB 5B 35 D4 83 5E 34 09 EB 5B 35 77 9B 5E 34 92 EB 5B 35 77 9B 5F 34 81 EB 5B 35 77 9B 58 34 86 EB 5B 35 D4 83 5A 34 8C EB 5B 35 8F EB 5A 35 D3 EB 5B 35 37 9A 52 34 8C EB 5B 35 37 9A 58 34 8E EB 5B 35 37 9A 5B 34 8E EB 5B 35 37 9A 59 34 8E EB 5B 35 }

	condition:
		uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 and 1 of ( $rh* )
}

rule SIGNATURE_BASE_APT_NK_MAL_M_Hunting_VEILEDSIGNAL_2 : FILE
{
	meta:
		description = "Detects VEILEDSIGNAL malware"
		author = "Mandiant"
		id = "1b96c2f0-1c57-593e-9630-a72d43eb857e"
		date = "2023-04-20"
		modified = "2023-12-05"
		reference = "https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_nk_tradingtech_apr23.yar#L57-L76"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "62f74faa8f136f4dc63a4b703cffcb97b438cc4f180d5d127d1fc4b86d3cd1d1"
		score = 75
		quality = 85
		tags = "FILE"
		disclaimer = "This rule is meant for hunting and is not tested to run in a production environment"
		hash1 = "404b09def6054a281b41d309d809a428"

	strings:
		$sb1 = { C1 E0 05 4D 8? [2] 33 D0 45 69 C0 7D 50 BF 12 8B C2 41 FF C2 C1 E8 07 33 D0 8B C2 C1 E0 16 41 81 C0 87 D6 12 00 }
		$si1 = "CryptBinaryToStringA" fullword
		$si2 = "BCryptGenerateSymmetricKey" fullword
		$si3 = "CreateThread" fullword
		$ss1 = "ChainingModeGCM" wide
		$ss2 = "__tutma" fullword

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x020B ) and all of them
}

rule SIGNATURE_BASE_APT_NK_MAL_M_Hunting_VEILEDSIGNAL_3 : FILE
{
	meta:
		description = "Detects VEILEDSIGNAL malware"
		author = "Mandiant"
		id = "82790c65-1d93-509b-95df-841543943c30"
		date = "2023-04-20"
		modified = "2023-12-05"
		reference = "https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_nk_tradingtech_apr23.yar#L78-L96"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		hash = "c6441c961dcad0fe127514a918eaabd4"
		logic_hash = "2109340edfb1891baef5bd92ba3c9da77f891341de9e8094060a649de62fade2"
		score = 75
		quality = 85
		tags = "FILE"
		disclaimer = "This rule is meant for hunting and is not tested to run in a production environment"

	strings:
		$ss1 = { 61 70 70 6C 69 63 61 74 69 6F 6E 2F 6A 73 6F 6E 2C 20 74 65 78 74 2F 6A 61 76 61 73 63 72 69 70 74 2C 20 2A 2F 2A 3B 20 71 3D 30 2E 30 31 00 00 61 63 63 65 70 74 00 00 65 6E 2D 55 53 2C 65 6E 3B 71 3D 30 2E 39 00 00 61 63 63 65 70 74 2D 6C 61 6E 67 75 61 67 65 00 63 6F 6F 6B 69 65 00 00 }
		$si1 = "HttpSendRequestW" fullword
		$si2 = "CreateNamedPipeW" fullword
		$si3 = "CreateThread" fullword
		$se1 = "DllGetClassObject" fullword

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x020B ) and all of them
}

rule SIGNATURE_BASE_APT_NK_MAL_M_Hunting_VEILEDSIGNAL_4 : FILE
{
	meta:
		description = "Detects VEILEDSIGNAL malware"
		author = "Mandiant"
		id = "379e6471-3c4f-5c72-b8fd-17f481e89ac6"
		date = "2023-04-20"
		modified = "2023-12-05"
		reference = "https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_nk_tradingtech_apr23.yar#L98-L118"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "2a875c39a43ff054ed5a6cf2fa1f17c2adc189452582763db8ceddfa652abfbf"
		score = 75
		quality = 85
		tags = "FILE"
		disclaimer = "This rule is meant for hunting and is not tested to run in a production environment"
		hash1 = "404b09def6054a281b41d309d809a428"
		hash2 = "c6441c961dcad0fe127514a918eaabd4"

	strings:
		$sb1 = { FF 15 FC 76 01 00 8B F0 85 C0 74 ?? 8D 50 01 [6-16] FF 15 [4] 48 8B D8 48 85 C0 74 ?? 89 ?? 24 28 44 8B CD 4C 8B C? 48 89 44 24 20 }
		$sb2 = { 33 D2 33 C9 FF 15 [4] 4C 8B CB 4C 89 74 24 28 4C 8D 05 [2] FF FF 44 89 74 24 20 33 D2 33 C9 FF 15 }
		$si1 = "CreateThread" fullword
		$si2 = "MultiByteToWideChar" fullword
		$si3 = "LocalAlloc" fullword
		$se1 = "DllGetClassObject" fullword

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x020B ) and all of them
}

rule SIGNATURE_BASE_APT_NK_MAL_M_Hunting_VEILEDSIGNAL_5 : FILE
{
	meta:
		description = "Detects VEILEDSIGNAL malware"
		author = "Mandiant"
		id = "7d0718fc-4f1c-5293-8dc4-81a5783fbfb2"
		date = "2023-04-20"
		modified = "2023-12-05"
		reference = "https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_nk_tradingtech_apr23.yar#L120-L143"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "5d43b8198ad224bee8d290dd7031d73f76a7d957a2e3b44d89e7aaf5f2c94c65"
		score = 75
		quality = 85
		tags = "FILE"
		disclaimer = "This rule is meant for hunting and is not tested to run in a production environment"
		hash1 = "6727284586ecf528240be21bb6e97f88"

	strings:
		$sb1 = { 48 8D 15 [4] 48 8D 4C 24 4C E8 [4] 85 C0 74 ?? 48 8D 15 [4] 48 8D 4C 24 4C E8 [4] 85 C0 74 ?? 48 8D 15 [4] 48 8D 4C 24 4C E8 [4] 85 C0 74 ?? 48 8D [3] 48 8B CB FF 15 [4] EB }
		$ss1 = "chrome.exe" wide fullword
		$ss2 = "firefox.exe" wide fullword
		$ss3 = "msedge.exe" wide fullword
		$ss4 = "\\\\.\\pipe\\*" ascii fullword
		$ss5 = "FindFirstFileA" ascii fullword
		$ss6 = "Process32FirstW" ascii fullword
		$ss7 = "RtlAdjustPrivilege" ascii fullword
		$ss8 = "GetCurrentProcess" ascii fullword
		$ss9 = "NtWaitForSingleObject" ascii fullword

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x020B ) and all of them
}

rule SIGNATURE_BASE_APT_NK_MAL_M_Hunting_VEILEDSIGNAL_6 : FILE
{
	meta:
		description = "Detects VEILEDSIGNAL malware"
		author = "Mandiant"
		id = "2cbedbc0-d465-5674-bf9c-9362003eb8d2"
		date = "2023-04-20"
		modified = "2023-12-05"
		reference = "https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_nk_tradingtech_apr23.yar#L145-L164"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "d3b1e5f7a6b73fc4cdc5abe19a412130cde33c2d52c0ad78256b865e018e3794"
		score = 75
		quality = 85
		tags = "FILE"
		disclaimer = "This rule is meant for hunting and is not tested to run in a production environment"
		hash1 = "00a43d64f9b5187a1e1f922b99b09b77"

	strings:
		$ss1 = "C:\\Programdata\\" wide
		$ss2 = "devobj.dll" wide fullword
		$ss3 = "msvcr100.dll" wide fullword
		$ss4 = "TpmVscMgrSvr.exe" wide fullword
		$ss5 = "\\Microsoft\\Windows\\TPM" wide fullword
		$ss6 = "CreateFileW" ascii fullword

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x010B ) and all of them
}

rule SIGNATURE_BASE_SUSP_TH_APT_UNC4736_Tradingtech_Cert_Apr23_1
{
	meta:
		description = "Threat hunting rule that detects samples signed with the compromised Trading Technologies certificate after May 2022"
		author = "Florian Roth"
		id = "9a05fba9-9466-5b69-9207-27ad01d6eb8b"
		date = "2023-04-20"
		modified = "2023-12-05"
		reference = "https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_nk_tradingtech_apr23.yar#L227-L242"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "47941828b3c18ed39eddacbc73e147651a9bd48e1a0f7b9847ff1d4c6fea6afd"
		score = 65
		quality = 85
		tags = ""

	strings:
		$s1 = { 00 85 38 A6 C5 01 8F 50 FC }
		$s2 = "Go Daddy Secure Certificate Authority - G2"
		$s3 = "Trading Technologies International, Inc"

	condition:
		pe.timestamp> 1651363200 and all of them
}

rule SIGNATURE_BASE_Hvs_APT37_Smb_Scanner : FILE
{
	meta:
		description = "Unknown smb login scanner used by APT37"
		author = "Marc Stroebel"
		id = "89a5cc32-f151-583d-823d-692de2c2b084"
		date = "2020-12-15"
		modified = "2023-12-05"
		reference = "https://www.hybrid-analysis.com/sample/d16163526242508d6961f061aaffe3ae5321bd64d8ceb6b2788f1570757595fc?environmentId=2"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_lazarus_dec20.yar#L2-L29"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "0bea71db7052f1c22c01cfbf710d4ed24651cbbd8b0fd29f09dfd49c4e314028"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Scan.exe StartIP EndIP ThreadCount logfilePath [Username Password Deep]" fullword ascii
		$s2 = "%s - %s:(Username - %s / Password - %s" fullword ascii
		$s3 = "Load mpr.dll Error " fullword ascii
		$s4 = "Load Netapi32.dll Error " fullword ascii
		$s5 = "%s U/P not Correct! - %d" fullword ascii
		$s6 = "GetNetWorkInfo Version 1.0" fullword wide
		$s7 = "Hello World!" fullword wide
		$s8 = "%s Error: %ld" fullword ascii
		$s9 = "%s U/P Correct!" fullword ascii
		$s10 = "%s --------" fullword ascii
		$s11 = "%s%-30s%I64d" fullword ascii
		$s12 = "%s%-30s(DIR)" fullword ascii
		$s13 = "%04d-%02d-%02d %02d:%02d" fullword ascii
		$s14 = "Share:              Local Path:                   Uses:   Descriptor:" fullword ascii
		$s15 = "Share:              Type:                   Remark:" fullword ascii

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 200KB and ( 10 of them )
}

rule SIGNATURE_BASE_Hvs_APT37_Cred_Tool : FILE
{
	meta:
		description = "Unknown cred tool used by APT37"
		author = "Markus Poelloth"
		id = "e830025a-f2ac-55b1-aca3-ded9dba83a67"
		date = "2020-12-15"
		modified = "2023-12-05"
		reference = "https://www.hvs-consulting.de/media/downloads/ThreatReport-Lazarus.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_lazarus_dec20.yar#L31-L50"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "4fb7247b88f2d252e7c9d5034c209945bc9e17f49de3dcdb5bf50b5afb302987"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii
		$s2 = "Domain Login" fullword ascii
		$s3 = "IEShims_GetOriginatingThreadContext" fullword ascii
		$s4 = " Type Descriptor'" fullword ascii
		$s5 = "User: %s" fullword ascii
		$s6 = "Pass: %s" fullword ascii
		$s7 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
		$s8 = "E@c:\\u" fullword ascii

	condition:
		filesize < 500KB and 7 of them
}


rule SIGNATURE_BASE_Hvs_APT37_RAT_Loader
{
	meta:
		description = "BLINDINGCAN RAT loader named iconcash.db used by APT37"
		author = "Marc Stroebel"
		id = "6c3e8465-d607-59bf-85fc-5abbef71fb1c"
		date = "2020-12-15"
		modified = "2023-12-05"
		reference = "https://us-cert.cisa.gov/ncas/analysis-reports/ar20-232a"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_lazarus_dec20.yar#L52-L65"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		hash = "b70e66d387e42f5f04b69b9eb15306036702ab8a50b16f5403289b5388292db9"
		logic_hash = "241f2683adc29e8aca30ae24278f3703fef0fed6b276dae488fdb32c167af1c9"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	condition:
		(pe.version_info [ "OriginalFilename" ] contains "MFC_DLL.dll" ) and ( pe.exports ( "SMain" ) and pe.exports ( "SMainW" ) )
}

rule SIGNATURE_BASE_APT_Winnti_MAL_Dec19_1 : FILE
{
	meta:
		description = "Detects Winnti malware"
		author = "Unknown"
		id = "322e9362-bfb6-55e3-9a93-d54246311d11"
		date = "2019-12-06"
		modified = "2025-06-03"
		reference = "https://www.verfassungsschutz.de/download/broschuere-2019-12-bfv-cyber-brief-2019-01.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_winnti.yar#L160-L181"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "2ffeb40b096e5112adbb9c07b27b954424d6ef11a0a9bd736b43df9aa1e9af3e"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$e1 = "Global\\BFE_Notify_Event_{65a097fe-6102-446a-9f9c-55dfc3f411015}" ascii nocase
		$e2 = "Global\\BFE_Notify_Event_{65a097fe-6102-446a-9f9c-55dfc3f411014}" ascii nocase
		$e3 = "Global\\BFE_Notify_Event_{65a097fe-6102-446a-9f9c-55dfc3f411016}" ascii nocase
		$e4 = "\\BaseNamedObjects\\{B2B87CCA-66BC-4C24-89B2-C23C9EAC2A66}" wide
		$e5 = "BFE_Notify_Event_{7D00FA3C-FBDC-4A8D-AEEB-3F55A4890D2A}" nocase
		$fp1 = "also increase possible memory usage of THOR."

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 3000KB and 1 of ( $e* ) and not 1 of ( $fp* )
}

rule SIGNATURE_BASE_APT_Winnti_MAL_Dec19_2
{
	meta:
		description = "Detects Winnti malware"
		author = "Unknown"
		id = "77f2cb7d-90a6-5654-9d2e-6b525cd910a2"
		date = "2019-12-06"
		modified = "2025-08-11"
		reference = "https://www.verfassungsschutz.de/download/broschuere-2019-12-bfv-cyber-brief-2019-01.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_winnti.yar#L183-L206"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "216557999b7100f26556f9f7088b16ba125ac39b308cb77c997d620ce9591d24"
		score = 75
		quality = 85
		tags = ""

	strings:
		$a1 = "IPSecMiniPort" wide fullword
		$a2 = "ndis6fw" wide fullword
		$a3 = "TCPIP" wide fullword
		$a4 = "NDIS.SYS" ascii fullword
		$a5 = "ntoskrnl.exe" ascii fullword
		$a6 = "\\BaseNamedObjects\\{B2B87CCA-66BC-4C24-89B2-C23C9EAC2A66}" wide
		$a7 = "\\Device\\Null" wide
		$a8 = "\\Device" wide
		$a9 = "\\Driver" wide
		$b1 = { 66 81 7? ?? 70 17 }
		$b2 = { 81 7? ?? 07 E0 15 00 }
		$b3 = { 8B 46 18 3D 03 60 15 00 }

	condition:
		(6 of ( $a* ) ) and ( 2 of ( $b* ) )
}

rule SIGNATURE_BASE_APT_Winnti_MAL_Dec19_3
{
	meta:
		description = "Detects Winnti malware"
		author = "Unknown"
		id = "2e001c91-0794-5940-ad8c-8e58a01e100c"
		date = "2019-12-06"
		modified = "2025-08-11"
		reference = "https://www.verfassungsschutz.de/download/broschuere-2019-12-bfv-cyber-brief-2019-01.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_winnti.yar#L208-L224"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "601f8a3cba57fea46c16c36f8276631fcd22feef4ea1388a1ea35b00929b9fbb"
		score = 75
		quality = 85
		tags = ""

	strings:
		$b1 = { 0F B7 ?? 16 [0-1] (81 E? | 25) 00 20 [8-10] 8B ?? 50 41 B9 40 00 00 00 41 B8 00 10 00 00 }
		$b2 = { 8B 40 28 [5-8] 48 03 C8 48 8B C1 [5-8] 48 89 41 28 }
		$b3 = { 48 6B ?? 28 [5-8] 8B ?? ?? 10 [5-8] 48 6B ?? 28 [5-8] 8B ?? ?? 14 }
		$b4 = { 83 B? 90 00 00 00 00 0F 84 [9-12] 83 B? 94 00 00 00 00 0F 84 }
		$b5 = { (45 | 4D) (31 | 33) C0 BA 01 00 00 00 [10-16] FF 5? 28 [0-1] (84 | 85) C0 }

	condition:
		(4 of ( $b* ) )
}

rule SIGNATURE_BASE_APT_Winnti_MAL_Dec19_4
{
	meta:
		description = "Detects Winnti malware"
		author = "Unknown"
		id = "1f7ac215-d049-5b97-9797-9589a70cbf2b"
		date = "2019-12-06"
		modified = "2025-08-11"
		reference = "https://www.verfassungsschutz.de/download/broschuere-2019-12-bfv-cyber-brief-2019-01.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_winnti.yar#L226-L240"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "32909e915a6e602ad1e8698cf5c128c2e54670770b97f54b1414c5798c42cc00"
		score = 75
		quality = 85
		tags = ""

	strings:
		$b1 = { 4C 8D 41 24 33 D2 B9 03 00 1F 00 FF 9? F8 00 00 00 48 85 C0 74 }
		$b2 = { 4C 8B 4? 08 BA 01 00 00 00 49 8B C? FF D0 85 C0 [2-6] C7 4? 1C 01 00 00 00 B8 01 00 00 00 }
		$b3 = { 8B 4B E4 8B 53 EC 41 B8 00 40 00 00 4? 0B C? FF 9? B8 00 00 00 EB }

	condition:
		(2 of ( $b* ) )
}

rule SIGNATURE_BASE_APT_Winnti_MAL_Dec19_5
{
	meta:
		description = "Detects Winnti malware"
		author = "Unknown"
		id = "2a8f28e6-5a01-5a2f-b89b-9c34163afcda"
		date = "2019-12-06"
		modified = "2025-08-11"
		reference = "https://www.verfassungsschutz.de/download/broschuere-2019-12-bfv-cyber-brief-2019-01.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_winnti.yar#L242-L269"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "977d11fbb7cf4678d4da179c43d5566520ee97ac528e269a9b985e5bc75641b7"
		score = 75
		quality = 85
		tags = ""

	strings:
		$a1 = "-k netsvcs" ascii
		$a2 = "svchost.exe" ascii fullword
		$a3 = "%SystemRoot%\\System32\\ntoskrnl.exe" ascii
		$a4 = "Global\\BFE_Notify_Event_{65a097fe-6102-446a-9f9c-55dfc3f411015}" ascii
		$a5 = "Global\\BFE_Notify_Event_{65a097fe-6102-446a-9f9c-55dfc3f411014}" ascii
		$a6 = "Global\\BFE_Notify_Event_{65a097fe-6102-446a-9f9c-55dfc3f411016}" ascii
		$a7 = "cmd.exe" wide
		$a8 = ",XML" wide
		$a9 = "\\rundll32.exe" wide
		$a10 = "\\conhost.exe" wide
		$a11 = "\\cmd.exe" wide
		$a12 = "NtQueryInformationProcess" ascii
		$a13 = "Detours!" ascii fullword
		$a14 = "Loading modified build of detours library designed for MPC-HC player (http://sourceforge.net/projects/mpc-hc/)" ascii
		$a15 = "CONOUT$" wide fullword
		$a16 = { C6 0? E9 4? 8? 4? 05 [2] 89 4? 01 }

	condition:
		(12 of ( $a* ) )
}

rule SIGNATURE_BASE_APT_CN_Group_Loader_Jan20_1
{
	meta:
		description = "Detects loaders used by Chinese groups"
		author = "Vitali Kremez"
		id = "c85ae499-4f76-56ff-877d-887e1a7fc077"
		date = "2020-02-01"
		modified = "2025-08-11"
		reference = "https://twitter.com/VK_Intel/status/1223411369367785472?s=20"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_winnti.yar#L271-L283"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "30a180ada2390ca8df4bf7883624a5a176249622b4c34ce96931fe62b09ea8e3"
		score = 80
		quality = 85
		tags = ""

	strings:
		$xc1 = { 8B C3 C1 E3 10 C1 E8 10 03 D8 6B DB 77 83 C3 13 }

	condition:
		1 of them
}

rule SIGNATURE_BASE_Winnti_Dropper_X64_Libtomcrypt_Fns : TAU CN APT
{
	meta:
		description = "Designed to catch winnti 4.0 loader and hack tool x64"
		author = "CarbonBlack Threat Research"
		id = "080d837c-248f-5718-b4a2-290495cd3b38"
		date = "2019-08-26"
		modified = "2025-08-11"
		reference = "https://www.carbonblack.com/2019/09/04/cb-tau-threat-intelligence-notification-winnti-malware-4-0/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_winnti.yar#L285-L332"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "39d23f2a12a3b78182e52847e2fdb2d09386765138c37eb7f75edfc680505531"
		score = 75
		quality = 83
		tags = "TAU, CN, APT"
		rule_version = 1
		yara_version = "3.8.1"
		Confidence = "Prod"
		Priority = "High"
		TLP = "White"
		exemplar_hashes = "5ebf39d614c22e750bb8dbfa3bcb600756dd3b36929755db9b577d2b653cd2d1"
		sample_md5 = "794E127D627B3AF9015396810A35AF1C"

	strings:
		$0x140001820 = { 48 83 EC 28 83 3D ?? ?? ?? ?? 00 }
		$0x140001831 = { 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 F8 FF }
		$0x140001842 = { B8 0B 00 E0 0C 48 83 C4 28 C3 }
		$0x14000184c = { 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 F8 FF }
		$0x140001881 = { B8 0C 00 E0 0C 48 83 C4 28 C3 }
		$0x14000188b = { 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 F8 FF }
		$0x1400018e4 = { B8 0D 00 E0 0C 48 83 C4 28 C3 }
		$0x1400018ee = { 48 8D 0D ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 41 B8 A0 01 00 00 E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 01 00 00 00 }
		$0x140001911 = { 33 C0 48 83 C4 28 C3 }
		$0x140001670 = { 40 55 56 57 41 55 41 56 41 57 B8 38 12 00 00 E8 ?? ?? ?? ?? 48 2B E0 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 84 24 10 12 00 00 48 8B AC 24 90 12 00 00 4C 8B B4 24 A0 12 00 00 45 33 FF 44 39 3D ?? ?? ?? ?? 49 8B F1 41 0F B7 F8 4C 8B EA 44 8B D9 66 44 89 7C 24 40 }
		$0x1400016c8 = { B8 01 00 E0 0C }
		$0x1400016d2 = { 48 89 9C 24 30 12 00 00 4D 85 C9 }
		$0x1400016ec = { 8B 9C 24 98 12 00 00 83 FB 01 }
		$0x1400016fc = { 48 8D 54 24 40 }
		$0x140001701 = { 4C 89 A4 24 28 12 00 00 E8 ?? ?? ?? ?? 44 0F B7 64 24 40 66 44 3B E7 }
		$0x140001727 = { 48 8D 54 24 40 41 8B CB E8 ?? ?? ?? ?? 0F B7 94 24 A8 12 00 00 66 39 54 24 40 }
		$0x140001750 = { 41 8B CB E8 ?? ?? ?? ?? 8B F8 83 F8 FF }
		$0x14000175f = { B8 0F 00 E0 0C }
		$0x140001764 = { 4C 8B A4 24 28 12 00 00 }
		$0x14000176c = { 48 8B 9C 24 30 12 00 00 }
		$0x140001774 = { 48 8B 8C 24 10 12 00 00 48 33 CC E8 ?? ?? ?? ?? 48 81 C4 38 12 00 00 41 5F 41 5E 41 5D 5F 5E 5D C3 }
		$0x140001795 = { 48 8D 4C 24 54 33 D2 41 B8 B4 11 00 00 44 89 7C 24 50 E8 ?? ?? ?? ?? 48 8D 44 24 50 48 89 44 24 30 45 0F B7 CC 4D 8B C5 49 8B D6 8B CF 44 89 7C 24 28 44 89 7C 24 20 E8 ?? ?? ?? ?? 85 C0 }
		$0x1400017d5 = { 4C 8D 4C 24 50 44 8B C3 48 8B D5 48 8B CE E8 ?? ?? ?? ?? 48 8D 4C 24 50 8B D8 E8 ?? ?? ?? ?? 8B C3 }
		$0x1400017fb = { B8 04 00 E0 0C }
		$0x140001805 = { B8 03 00 E0 0C }
		$0x14000180f = { B8 02 00 E0 0C }

	condition:
		all of them
}

rule SIGNATURE_BASE_Winnti_Dropper_X86_Libtomcrypt_Fns : TAU CN APT
{
	meta:
		description = "Designed to catch winnti 4.0 loader and hack tool x86"
		author = "CarbonBlack Threat Research"
		id = "48e7a3b0-55c7-5db5-855f-1614bd00afb4"
		date = "2019-08-26"
		modified = "2025-08-11"
		reference = "https://www.carbonblack.com/2019/09/04/cb-tau-threat-intelligence-notification-winnti-malware-4-0/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_winnti.yar#L334-L375"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "84bfe001758677ff3a0d60d98e29c33ad1525a0afb27b73df750b2131e298879"
		score = 75
		quality = 85
		tags = "TAU, CN, APT"
		rule_version = 1
		yara_version = "3.8.1"
		confidence = "Prod"
		oriority = "High"
		TLP = "White"
		exemplar_hashes = "0fdcbd59d6ad41dda9ae8bab8fad9d49b1357282027e333f6894c9a92d0333b3"
		sample_md5 = "da3b64ec6468a4ec56f977afb89661b1"

	strings:
		$0x401d20 = { 8B 0D ?? ?? ?? ?? 33 C0 85 C9 }
		$0x401d30 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 04 83 F8 ?? }
		$0x401d46 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 83 F8 ?? }
		$0x401d76 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 1C 83 F8 ?? }
		$0x401dc4 = { 56 57 B9 ?? ?? ?? ?? BE ?? ?? ?? ?? BF ?? ?? ?? ?? 33 C0 F3 A5 5F C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 5E C3 }
		$0x401bd0 = { 55 8B EC B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 53 56 57 85 C0 C7 45 FC ?? ?? ?? ?? }
		$0x401bf4 = { 8B 45 14 85 C0 }
		$0x401bff = { 8B 45 18 85 C0 }
		$0x401c14 = { 8B 7D 08 8D 45 FC 50 57 E8 ?? ?? ?? ?? 8B 75 ?? 83 C4 08 66 }
		$0x401c31 = { 8B 45 0C 85 C0 }
		$0x401c3c = { 8D 4D FC 51 57 E8 ?? ?? ?? ?? 66 8B 55 FC 83 C4 08 66 3B 55 24 }
		$0x401c57 = { 8B 5D 20 85 DB }
		$0x401c62 = { 57 E8 ?? ?? ?? ?? 8B D0 83 C4 04 83 FA ?? }
		$0x401c72 = { B9 ?? ?? ?? ?? 33 C0 8D BD 48 EE FF FF C7 85 44 EE FF FF ?? ?? ?? ?? F3 AB 8B 4D 0C 8D 85 44 EE FF FF 50 6A ?? 81 E6 FF FF 00 00 6A ?? 56 51 53 52 E8 ?? ?? ?? ?? 83 C4 1C 85 C0 }
		$0x401caf = { 8B 45 1C 8B 4D 18 8D 95 44 EE FF FF 52 8B 55 14 50 51 52 E8 ?? ?? ?? ?? 8B F0 8D 85 44 EE FF FF 50 E8 ?? ?? ?? ?? 83 C4 14 8B C6 5F 5E 5B 8B E5 5D C3 }
		$0x401ce1 = { 5F 5E B8 ?? ?? ?? ?? 5B 8B E5 5D C3 }
		$0x401ced = { 5F 5E B8 ?? ?? ?? ?? 5B 8B E5 5D C3 }
		$0x401cf9 = { 5F 5E B8 ?? ?? ?? ?? 5B 8B E5 5D C3 }
		$0x401d05 = { 5F 5E B8 ?? ?? ?? ?? 5B 8B E5 5D C3 }
		$0x401d16 = { 5F 5E 5B 8B E5 5D C3 }

	condition:
		all of them
}

rule SIGNATURE_BASE_APT_Artradownloader2_Aug19_1 : FILE
{
	meta:
		description = "Detects ArtraDownloader malware"
		author = "Florian Roth (Nextron Systems)"
		id = "0e688e92-2366-5f36-a32d-083982181eb7"
		date = "2019-08-27"
		modified = "2023-12-05"
		reference = "https://unit42.paloaltonetworks.com/multiple-artradownloader-variants-used-by-bitter-to-target-pakistan/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_patchwork.yar#L2-L30"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "c365c3d678c881eeb626b5d26e6164b473990387619337459ccdd8d9f0633b49"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "f0ef4242cc6b8fa3728b61d2ce86ea934bd59f550de9167afbca0b0aaa3b2c22"

	strings:
		$xc1 = { 47 45 54 20 25 73 20 48 54 54 50 2F 31 2E 30 00
               0D 0A 00 00 48 6F 73 74 3A 20 25 73 00 00 00 00
               3F 61 3D 00 26 62 3D 00 26 63 3D 00 26 64 3D 00
               26 65 3D 00 25 32 30 }
		$xc2 = { 25 73 20 25 73 20 25 73 0D 0A 25 73 20 25 73 0D
               0A 25 73 25 73 0D 0A 25 73 25 73 0D 0A 25 73 20
               25 64 0D 0A 0D 0A 25 73 00 00 00 00 71 72 79 3D }
		$xc3 = { 49 44 3D 25 73 00 00 00 3A 00 00 00 25 73 20 25
               73 20 25 73 0D 0A 25 73 20 25 73 0D 0A 25 73 25
               73 0D 0A 25 73 25 73 0D 0A 43 6F 6E 74 65 6E 74
               2D 6C 65 6E 67 74 68 25 73 20 25 64 }
		$xc4 = { 25 73 20 25 73 20 25 73 0D 0A 25 73 20 25 73 0D
               0A 25 73 25 73 0D 0A 25 73 25 73 0D 0A 43 6F 6E
               74 65 6E 74 2D 6C 65 6E 67 74 68 3A 20 25 64 0D
               0A 0D 0A 25 73 }
		$x1 = "Tpguxbsf]Njdsptpgu" ascii
		$x2 = ".gpsn.vsmfodpefe" ascii

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 600KB and 1 of them
}

rule SIGNATURE_BASE_APT_MAL_SLOTHFULMEDIA_Oct20_1 : FILE
{
	meta:
		description = "Detects SLOTHFULMEDIA malware"
		author = "Florian Roth (Nextron Systems)"
		id = "cc413225-f084-5859-bc27-04eb018d8894"
		date = "2020-10-01"
		modified = "2023-12-05"
		reference = "https://us-cert.cisa.gov/ncas/analysis-reports/ar20-275a"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_iamtheking.yar#L2-L48"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "e50bda40eb05767e0903c3d8dd62b4e0290d89740c82c8b7f391d5763dc35156"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "64d78eec46c9ddd4b9a366de62ba0f2813267dc4393bc79e4c9a51a9bb7e6273"
		hash2 = "927d945476191a3523884f4c0784fb71c16b7738bd7f2abd1e3a198af403f0ae"
		hash3 = "f0503f0131040b805e106eafe64a65d9404a0e279f052237b868e456c34d36e6"
		hash4 = "ed5258306c06d6fac9b13c99c7c8accc7f7fa0de4cf4de4f7d9eccad916555f5"
		hash5 = "04ca010f4c8997a023fabacae230698290e3ff918a86703c5e0a2a6983b039eb"
		hash6 = "cb2adcaaa25bb6b8a9f1c685c219f8d6d78aa5cfd65c633f4d255ff81da2c517"

	strings:
		$xc1 = { 25 73 26 69 3D 25 64 00 48 54 54 50 2F 31 2E 31
               00 00 00 00 50 4F 53 54 00 00 00 00 43 6F 6E 74
               65 6E 74 2D 4C 65 6E 67 74 68 3A 20 25 64 00 00
               5C 00 53 00 65 00 74 00 75 00 70 00 55 00 69 00
               00 00 00 00 25 00 73 00 25 00 73 00 5F 00 25 00
               64 00 2E 00 64 00 61 00 74 }
		$xc2 = { 2F 76 3F 6D 3D 00 00 00 35 30 31 00 32 30 30 00
               2A 00 2E 00 2A 00 00 00 25 00 73 00 00 00 00 00
               53 00 65 00 44 00 65 00 62 00 75 00 67 00 50 00
               72 00 69 00 76 00 69 00 6C 00 65 00 67 00 65 }
		$xc3 = { 00 25 00 73 00 7C 00 25 00 73 00 7C 00 25 00 73
               00 7C 00 25 00 73 00 00 00 5C 00 46 00 69 00 6C
               00 74 00 65 00 72 00 33 00 2E 00 6A 00 70 00 67 }
		$sc1 = { 25 74 65 6D 70 25 00 00 25 73 5C 25 73 2E 65 78
               65 00 00 00 25 74 65 6D 70 25 00 00 25 73 5C 25
               73 2E 65 78 65 }
		$sc2 = { 61 70 70 6C 69 63 61 74 69 6F 6E 2F 6F 63 74 65
               74 2D 73 74 72 65 61 6D 2C 61 70 70 6C 69 63 61
               74 69 6F 6E 2F 78 68 74 6D 6C 00 00 25 73 26 69
               3D 25 64 00 48 54 54 50 2F 31 2E 31 00 00 00 00
               50 4F 53 54 }
		$s1 = "%s%s_%d.dat" wide fullword
		$s2 = "Local Security Process" wide fullword
		$s3 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.75" ascii fullword
		$s4 = "Global%s%d" wide fullword
		$s5 = "ExtKeyloggerStart" ascii fullword
		$s6 = "GetExtendedTcpTable" ascii fullword

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 400KB and ( 1 of ( $x* ) or 3 of them ) or 4 of them
}

rule SIGNATURE_BASE_APT_HAFNIUM_Forensic_Artefacts_Mar21_1
{
	meta:
		description = "Detects forensic artefacts found in HAFNIUM intrusions"
		author = "Florian Roth (Nextron Systems)"
		id = "872822b0-34d9-5ae4-a532-6a8786494fa9"
		date = "2021-03-02"
		modified = "2023-12-05"
		reference = "https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_hafnium.yar#L35-L48"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "eb86595956092506c2e29373faaf39a3987f9feed36a53b191bedd498db05cbb"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s1 = "lsass.exe C:\\windows\\temp\\lsass" ascii wide fullword
		$s2 = "c:\\ProgramData\\it.zip" ascii wide fullword
		$s3 = "powercat.ps1'); powercat -c" ascii wide fullword

	condition:
		1 of them
}

rule SIGNATURE_BASE_APT_MAL_ASPX_HAFNIUM_Chopper_Mar21_3 : FILE
{
	meta:
		description = "Detects HAFNIUM ASPX files dropped on compromised servers"
		author = "Florian Roth (Nextron Systems)"
		id = "9c2ba123-63c4-5e9c-a08f-bd9db3304691"
		date = "2021-03-07"
		modified = "2023-12-05"
		reference = "https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_hafnium.yar#L202-L216"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "391b366d78c2f24dc006a5365ec232a9a3c2fe0ea514b18897701ceeffcc81ca"
		score = 85
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "runat=\"server\">void Page_Load(object" ascii wide
		$s2 = "Request.Files[0].SaveAs(Server.MapPath(" ascii wide

	condition:
		filesize < 50KB and all of them
}

rule SIGNATURE_BASE_APT_MAL_ASPX_HAFNIUM_Chopper_Mar21_4 : FILE
{
	meta:
		description = "Detects HAFNIUM ASPX files dropped on compromised servers"
		author = "Florian Roth (Nextron Systems)"
		id = "93f5b682-642d-5edf-84a9-296bf12cd72b"
		date = "2021-03-07"
		modified = "2023-12-05"
		reference = "https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_hafnium.yar#L218-L233"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "933ab74a0e30e2a728444d491c9eb0ff134db05d905aeb48efe3ba65674a3730"
		score = 85
		quality = 79
		tags = "FILE"

	strings:
		$s1 = "<%@Page Language=\"Jscript\"%>" ascii wide nocase
		$s2 = ".FromBase64String(" ascii wide nocase
		$s3 = "eval(System.Text.Encoding." ascii wide nocase

	condition:
		filesize < 850 and all of them
}

rule SIGNATURE_BASE_APT_HAFNIUM_Forensicartefacts_Cab_Recon_Mar21_1 : FILE
{
	meta:
		description = "Detects suspicious CAB files used by HAFNIUM for recon activity"
		author = "Florian Roth (Nextron Systems)"
		id = "b0caf9d9-af0a-5181-85e4-6091cd6699e3"
		date = "2021-03-11"
		modified = "2023-12-05"
		reference = "https://discuss.elastic.co/t/detection-and-response-for-hafnium-activity/266289/3?u=dstepanic"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_hafnium.yar#L252-L273"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "de3acb2d01ad14d73263af9e62ef7c715cde259e3f2fbbcbbb41d55589c3f0ab"
		score = 70
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "ip.txt" ascii fullword
		$s2 = "arp.txt" ascii fullword
		$s3 = "system" ascii fullword
		$s4 = "security" ascii fullword

	condition:
		uint32( 0 ) == 0x4643534d and filesize < 10000KB and ( $s1 in ( 0 .. 200 ) and $s2 in ( 0 .. 200 ) and $s3 in ( 0 .. 200 ) and $s4 in ( 0 .. 200 ) )
}

rule SIGNATURE_BASE_APT_MAL_ASP_DLL_HAFNIUM_Mar21_1 : FILE
{
	meta:
		description = "Detects HAFNIUM compiled ASP.NET DLLs dropped on compromised servers"
		author = "Florian Roth (Nextron Systems)"
		id = "68b8252e-a07d-5507-b556-a4d473f98157"
		date = "2021-03-05"
		modified = "2023-12-05"
		reference = "https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_hafnium.yar#L297-L325"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "a4a3f9c7029e67647823a13079655b24648f5e4a7e238439b7a933b19477c20c"
		score = 65
		quality = 85
		tags = "FILE"
		hash1 = "097f5f700c000a13b91855beb61a931d34fb0abb738a110368f525e25c5bc738"
		hash2 = "15744e767cbaa9b37ff7bb5c036dda9b653fc54fc9a96fe73fbd639150b3daa3"
		hash3 = "52ae4de2e3f0ef7fe27c699cb60d41129a3acd4a62be60accc85d88c296e1ddb"
		hash4 = "5f0480035ee23a12302c88be10e54bf3adbcf271a4bb1106d4975a28234d3af8"
		hash5 = "6243fd2826c528ee329599153355fd00153dee611ca33ec17effcf00205a6e4e"
		hash6 = "ebf6799bb86f0da2b05e66a0fe5a9b42df6dac848f4b951b2ed7b7a4866f19ef"

	strings:
		$s1 = "Page_Load" ascii fullword
		$sc1 = { 20 00 3A 00 20 00 68 00 74 00 74 00 70 00 3A 00
               2F 00 2F 00 (66|67) 00 2F 00 00 89 A3 0D 00 0A 00 }
		$op1 = { 00 43 00 58 00 77 00 30 00 4a 00 45 00 00 51 7e 00 2f }
		$op2 = { 58 00 77 00 30 00 4a 00 45 00 00 51 7e 00 2f 00 61 00 }
		$op3 = { 01 0e 0e 05 20 01 01 11 79 04 07 01 12 2d 04 07 01 12 31 02 }
		$op4 = { 5e 00 03 00 bc 22 00 00 00 00 01 00 85 03 2b 00 03 00 cc }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 50KB and all of ( $s* ) or all of ( $op* )
}

rule SIGNATURE_BASE_APT_FIN7_Msdoc_Sep21_1 : FILE
{
	meta:
		description = "Detects MalDocs used by FIN7 group"
		author = "Florian Roth (Nextron Systems)"
		id = "4fbde087-ec1e-5614-af1e-f342b1766fa2"
		date = "2021-09-07"
		modified = "2023-12-05"
		reference = "https://www.anomali.com/blog/cybercrime-group-fin7-using-windows-11-alpha-themed-docs-to-drop-javascript-backdoor"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_fin7.yar#L277-L301"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "ffc91cdad91b8ab24840c6ef1a6c39aad081d986c21a88b3f2ea3ec1bcd3b52b"
		score = 85
		quality = 85
		tags = "FILE"
		hash1 = "d60b6a8310373c9b84e6760c24185535"

	strings:
		$xc1 = { 00 4A 00 6F 00 68 00 6E 00 0B 00 57 00 31 00 30
               00 50 00 72 00 6F 00 4F 00 66 00 66 00 31 00 36 }
		$s1 = "word_data.bin" ascii fullword
		$s2 = "V:\\DOC\\For_JS" ascii
		$s3 = "HomeCompany" ascii
		$s4 = "W10ProOff16" ascii

	condition:
		uint16( 0 ) == 0xcfd0 and ( 1 of ( $x* ) or 3 of them )
}

rule SIGNATURE_BASE_APT_EXPL_Sharepoint_CVE_2025_53770_Forensicartefact_Jul25_2 : CVE_2025_53770
{
	meta:
		description = "Detects URIs accessed during the exploitation of SharePoint RCE vulnerability CVE-2025-53770"
		author = "Florian Roth"
		id = "57c2caf8-6458-51d5-80c5-8ceee2f55072"
		date = "2025-07-20"
		modified = "2025-07-24"
		reference = "https://research.eye.security/sharepoint-under-siege/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/expl_sharepoint_jul25.yar#L73-L102"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		hash = "30955794792a7ce045660bb1e1917eef36f1d5865891b8110bf982382b305b27"
		hash = "b336f936be13b3d01a8544ea3906193608022b40c28dd8f1f281e361c9b64e93"
		logic_hash = "5ae0620e7e1c1908ad54ac4e41c53240f738631c20577fd65fb29008945347a8"
		score = 70
		quality = 85
		tags = "CVE-2025-53770"

	strings:
		$x1 = "-EncodedCommand JABiAGEAcwBlADYANABTAHQAcgBpAG4AZwAgAD0" ascii wide
		$x2 = "TEMPLATE\\LAYOUTS\\spinstall" ascii wide
		$x3 = "TEMPLATE\\LAYOUTS\\ghostfile" ascii wide
		$x4 = "TEMPLATE\\LAYOUTS\\1.css" ascii wide
		$x5 = "Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64;+rv:120.0)+Gecko/20100101+Firefox/120.0 /_layouts/SignOut.aspx" ascii wide
		$xe1 = "TQBJAEMAUgBPAFMAfgAxAFwAVwBFAEIAUwBFAFIAfgAxAFwAMQA2AFwAVABFAE0AUABMAEEAVABFAFwATABBAFkATwBVAFQAUwBcA"
		$xe2 = "0ASQBDAFIATwBTAH4AMQBcAFcARQBCAFMARQBSAH4AMQBcADEANgBcAFQARQBNAFAATABBAFQARQBcAEwAQQBZAE8AVQBUAFMAXA"
		$xe3 = "NAEkAQwBSAE8AUwB+ADEAXABXAEUAQgBTAEUAUgB+ADEAXAAxADYAXABUAEUATQBQAEwAQQBUAEUAXABMAEEAWQBPAFUAVABTAFwA"
		$xe4 = "TQBJAEMAUgBPAFMAfgAxAFwAVwBFAEIAUwBFAFIAfgAxAFwAMQA1AFwAVABFAE0AUABMAEEAVABFAFwATABBAFkATwBVAFQAUwBcA"
		$xe5 = "0ASQBDAFIATwBTAH4AMQBcAFcARQBCAFMARQBSAH4AMQBcADEANQBcAFQARQBNAFAATABBAFQARQBcAEwAQQBZAE8AVQBUAFMAXA"
		$xe6 = "NAEkAQwBSAE8AUwB+ADEAXABXAEUAQgBTAEUAUgB+ADEAXAAxADUAXABUAEUATQBQAEwAQQBUAEUAXABMAEEAWQBPAFUAVABTAFwA"

	condition:
		1 of them
}

rule SIGNATURE_BASE_APT_MAL_BKA_Goldenspy_Aug20_1 : FILE
{
	meta:
		description = "Detects variants of GoldenSpy Malware"
		author = "BKA"
		id = "4f47087e-6e68-53ff-9446-72a1751da359"
		date = "2020-08-21"
		modified = "2023-12-05"
		reference = "https://www.bka.de/SharedDocs/Kurzmeldungen/DE/Warnhinweise/200821_Cyberspionage.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_goldenspy.yar#L1-L19"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "ba81a2b081842aaf06bbf623640a87946894df83fd0d7b7149c48afa8ed0a081"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$str01 = {c78510ffffff00000000 c78514ffffff0f000000 c68500ffffff00 c78528ffffff00000000 c7852cffffff0f000000 c68518ffffff00 c78540ffffff00000000 c78544ffffff0f000000 c68530ffffff00 c645fc14 80bd04feffff00}
		$str02 = "Ryeol HTTP Client Class" ascii
		$str03 = "----RYEOL-FB3B405B7EAE495aB0C0295C54D4E096-" ascii
		$str04 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\fwkp.exe" ascii
		$str05 = "svmm" ascii
		$str06 = "PROTOCOL_" ascii
		$str07 = "softList" ascii
		$str08 = "excuteExe" ascii

	condition:
		uint16( 0 ) == 0x5A4D and 5 of ( $str* )
}

rule SIGNATURE_BASE_APT_MAL_IR_Druidfly_Wiper_Jun25 : FILE
{
	meta:
		description = "Detects Wiper used by the Iranian DruidFly group"
		author = "Florian Roth"
		id = "e3490d0e-369a-52ab-a9c1-b1c5b011c7db"
		date = "2025-06-21"
		modified = "2025-07-01"
		reference = "https://x.com/threatintel/status/1936049254432231444"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/mal_wipers_jun25.yar#L61-L87"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "9d3872506b03ea03a2c3cd7304c6b2d9dfafa04a29e19dc9be4924eaaa5db2d6"
		score = 80
		quality = 85
		tags = "FILE"
		hash1 = "81eb22828306f3197b35fef2035cef2c548f587f8511902852964850023389d7"

	strings:
		$xc1 = { 2E 62 61 63 6B 75 70 00 2E 63 6F 6E 66 69 67 00   // .backup .config
               2E 64 62 00 00 00 00 00 2E 73 71 6C 69 74 65 00 }
		$xc2 = { 00 5C 5C 2E 5C 25 63 3A 00 25 63 3A 5C 00 00 00
               00 4E 54 46 53 00 00 00 00 5C }
		$x1 = "%s:%d:%s(): [+] Overwriting \"%s\" \"..." ascii
		$s1 = "C:\\Windows\\System32\\drivers\\beep.sys" ascii fullword
		$s2 = "\\DosDevices\\sectorio" wide fullword

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 2000KB and ( 1 of ( $x* ) or 2 of them ) or 3 of them
}

rule SIGNATURE_BASE_EXT_APT_Bitter_Win32K_0Day_Feb21 : FILE
{
	meta:
		description = "Detects code that exploits a Windows 0day exploited by Bitter APT group"
		author = "dbappsecurity_lieying_lab"
		id = "b1892b52-4b94-5571-ad63-8750a321f1f2"
		date = "2021-01-01"
		modified = "2023-12-05"
		reference = "https://ti.dbappsecurity.com.cn/blog/index.php/2021/02/10/windows-kernel-zero-day-exploit-is-used-by-bitter-apt-in-targeted-attack/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_bitter.yar#L2-L21"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "84a8d0ae14469eb6431e73295d821609c7a8b313630d645085ffd8faff6e5e43"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "NtUserConsoleControl" ascii wide
		$s2 = "NtCallbackReturn" ascii wide
		$s3 = "CreateWindowEx" ascii wide
		$s4 = "SetWindowLong" ascii wide
		$a1 = {48 C1 E8 02 48 C1 E9 02 C7 04 8A}
		$a2 = {66 0F 1F 44 00 00 80 3C 01 E8 74 22 FF C2 48 FF C1}
		$a3 = {48 63 05 CC 69 05 00 8B 0D C2 69 05 00 48 C1 E0 20 48 03 C1}

	condition:
		uint16( 0 ) == 0x5a4d and all of ( $s* ) and 1 of ( $a* )
}

rule SIGNATURE_BASE_APT_Sandworm_Keywords_May20_1 : CVE_2019_10149 FILE
{
	meta:
		description = "Detects commands used by Sandworm group to exploit critical vulernability CVE-2019-10149 in Exim"
		author = "Florian Roth (Nextron Systems)"
		id = "e0d4e90e-5547-5487-8d0c-a141d88fff7c"
		date = "2020-05-28"
		modified = "2023-12-05"
		reference = "https://media.defense.gov/2020/May/28/2002306626/-1/-1/0/CSA%20Sandworm%20Actors%20Exploiting%20Vulnerability%20in%20Exim%20Transfer%20Agent%2020200528.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_sandworm_exim_expl.yar#L2-L15"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "9f9a81ff0c576f05ac063eaca7a5882dbdb09c9a0778610cca2864636a00efce"
		score = 75
		quality = 85
		tags = "CVE-2019-10149, FILE"

	strings:
		$x1 = "MAIL FROM:<$(run("
		$x2 = "exec\\x20\\x2Fusr\\x2Fbin\\x2Fwget\\x20\\x2DO\\x20\\x2D\\x20http"

	condition:
		filesize < 8000KB and 1 of them
}

rule SIGNATURE_BASE_APT_Sandworm_SSH_Key_May20_1 : FILE
{
	meta:
		description = "Detects SSH key used by Sandworm on exploited machines"
		author = "Florian Roth (Nextron Systems)"
		id = "ea2968b8-7ae4-56b8-9547-816c5e37c50a"
		date = "2020-05-28"
		modified = "2023-12-05"
		reference = "https://media.defense.gov/2020/May/28/2002306626/-1/-1/0/CSA%20Sandworm%20Actors%20Exploiting%20Vulnerability%20in%20Exim%20Transfer%20Agent%2020200528.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_sandworm_exim_expl.yar#L17-L31"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "23a43849dfaa80bad2ca4f46b53181b3a4855ee89673ae9b658c854069b9aaa9"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "dc074464e50502459038ac127b50b8c68ed52817a61c2f97f0add33447c8f730"
		hash2 = "538d713cb47a6b5ec6a3416404e0fc1ebcbc219a127315529f519f936420c80e"

	strings:
		$x1 = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC2q/NGN/brzNfJiIp2zswtL33tr74pIAjMeWtXN1p5Hqp5fTp058U1EN4NmgmjX0KzNjjV"

	condition:
		filesize < 1000KB and 1 of them
}

rule SIGNATURE_BASE_APT_Sandworm_SSHD_Config_Modification_May20_1 : FILE
{
	meta:
		description = "Detects ssh config entry inserted by Sandworm on compromised machines"
		author = "Florian Roth (Nextron Systems)"
		id = "dd60eeb7-3d4b-5a6a-8054-50c617ee8c73"
		date = "2020-05-28"
		modified = "2023-12-05"
		reference = "https://media.defense.gov/2020/May/28/2002306626/-1/-1/0/CSA%20Sandworm%20Actors%20Exploiting%20Vulnerability%20in%20Exim%20Transfer%20Agent%2020200528.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_sandworm_exim_expl.yar#L33-L49"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "5775588b3a9d44e9eb2c8ef0f50351d7e3b06f1005f669775fae7187900d5999"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "dc074464e50502459038ac127b50b8c68ed52817a61c2f97f0add33447c8f730"
		hash2 = "538d713cb47a6b5ec6a3416404e0fc1ebcbc219a127315529f519f936420c80e"

	strings:
		$x1 = "AllowUsers mysql_db" ascii
		$a1 = "ListenAddress" ascii fullword

	condition:
		filesize < 10KB and all of them
}

rule SIGNATURE_BASE_APT_Sandworm_Initfile_May20_1 : FILE
{
	meta:
		description = "Detects mysql init script used by Sandworm on compromised machines"
		author = "Florian Roth (Nextron Systems)"
		id = "0bd613e3-6bd4-5cec-bc0d-2bdb83caf142"
		date = "2020-05-28"
		modified = "2023-12-05"
		reference = "https://media.defense.gov/2020/May/28/2002306626/-1/-1/0/CSA%20Sandworm%20Actors%20Exploiting%20Vulnerability%20in%20Exim%20Transfer%20Agent%2020200528.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_sandworm_exim_expl.yar#L51-L66"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "989f37069820d9ecf67dc71e4761a7cde2c1adf8db40b5f8a47e9c610ddec2e6"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "dc074464e50502459038ac127b50b8c68ed52817a61c2f97f0add33447c8f730"
		hash2 = "538d713cb47a6b5ec6a3416404e0fc1ebcbc219a127315529f519f936420c80e"

	strings:
		$s1 = "GRANT ALL PRIVILEGES ON * . * TO 'mysqldb'@'localhost';" ascii
		$s2 = "CREATE USER 'mysqldb'@'localhost' IDENTIFIED BY '" ascii fullword

	condition:
		filesize < 10KB and all of them
}

rule SIGNATURE_BASE_APT_Sandworm_User_May20_1 : FILE
{
	meta:
		description = "Detects user added by Sandworm on compromised machines"
		author = "Florian Roth (Nextron Systems)"
		id = "ada549a4-abcc-5c0a-9601-75631e78c835"
		date = "2020-05-28"
		modified = "2023-12-05"
		reference = "https://media.defense.gov/2020/May/28/2002306626/-1/-1/0/CSA%20Sandworm%20Actors%20Exploiting%20Vulnerability%20in%20Exim%20Transfer%20Agent%2020200528.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_sandworm_exim_expl.yar#L68-L84"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "d052792a674dfa2d93a048b550ea085c3b9225662fdb09bf4a602093b0527e38"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "dc074464e50502459038ac127b50b8c68ed52817a61c2f97f0add33447c8f730"
		hash2 = "538d713cb47a6b5ec6a3416404e0fc1ebcbc219a127315529f519f936420c80e"

	strings:
		$s1 = "mysql_db:x:" ascii
		$a1 = "root:x:"
		$a2 = "daemon:x:"

	condition:
		filesize < 4KB and all of them
}

rule SIGNATURE_BASE_APT_RU_Sandworm_PY_May20_1 : FILE
{
	meta:
		description = "Detects Sandworm Python loader"
		author = "Florian Roth (Nextron Systems)"
		id = "a392d800-1fe8-5ae9-b813-e1dfcedecda6"
		date = "2020-05-28"
		modified = "2023-12-05"
		reference = "https://twitter.com/billyleonard/status/1266054881225236482"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_sandworm_exim_expl.yar#L131-L148"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "2ccc4c7fc75c04cbcab34904de2e7ab055a15c1017ec0f8d01b06454f4395047"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "c025008463fdbf44b2f845f2d82702805d931771aea4b506573b83c8f58bccca"

	strings:
		$x1 = "o.addheaders=[('User-Agent','Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko')]" ascii fullword
		$s1 = "exec(o.open('http://" ascii
		$s2 = "__import__({2:'urllib2',3:'urllib.request'}"

	condition:
		uint16( 0 ) == 0x6d69 and filesize < 1KB and 1 of ( $x* ) or 2 of them
}

rule SIGNATURE_BASE_APT_RU_Sandworm_PY_May20_2 : FILE
{
	meta:
		description = "Detects Sandworm Python loader"
		author = "Florian Roth (Nextron Systems)"
		id = "5b32ad64-d959-5632-a03c-17aa055b213f"
		date = "2020-05-28"
		modified = "2023-12-05"
		reference = "https://twitter.com/billyleonard/status/1266054881225236482"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_sandworm_exim_expl.yar#L150-L167"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "5fb61a9cef64ecf97adc78bf67db667cfd9e5e6f3e03f1bba8f3cdbf6c257520"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "abfa83cf54db8fa548942acd845b4f34acc94c46d4e1fb5ce7e97cc0c6596676"

	strings:
		$x1 = "import sys;import re, subprocess;cmd" ascii fullword
		$x2 = "UA='Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko';server='http"
		$x3 = "';t='/admin/get.php';req" ascii
		$x4 = "ps -ef | grep Little\\ Snitch | grep " ascii fullword

	condition:
		uint16( 0 ) == 0x6d69 and filesize < 2KB and 1 of them
}

rule SIGNATURE_BASE_APT_MAL_LNX_Turla_Apr202004_1 : FILE
{
	meta:
		description = "Detects Turla Linux malware x64 x32"
		author = "Leonardo S.p.A."
		id = "2da75433-b1c1-51b3-8f7a-a4442ca3de96"
		date = "2020-04-24"
		modified = "2023-12-05"
		reference = "https://www.leonardocompany.com/en/news-and-stories-detail/-/detail/knowledge-the-basis-of-protection"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_turla_penquin.yar#L2-L33"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "1e07963c492f1e6264f01ee292e40b188ca325b76005d9d48e6dc198cb9bdcf4"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "67d9556c695ef6c51abf6fbab17acb3466e3149cf4d20cb64d6d34dc969b6502"
		hash2 = "8ccc081d4940c5d8aa6b782c16ed82528c0885bbb08210a8d0a8c519c54215bc"
		hash3 = "8856a68d95e4e79301779770a83e3fad8f122b849a9e9e31cfe06bf3418fa667"
		hash4 = "1d5e4466a6c5723cd30caf8b1c3d33d1a3d4c94c25e2ebe186c02b8b41daf905"
		hash5 = "2dabb2c5c04da560a6b56dbaa565d1eab8189d1fa4a85557a22157877065ea08"
		hash6 = "3e138e4e34c6eed3506efc7c805fce19af13bd62aeb35544f81f111e83b5d0d4"
		hash7 = "5a204263cac112318cd162f1c372437abf7f2092902b05e943e8784869629dd8"
		hash8 = "8856a68d95e4e79301779770a83e3fad8f122b849a9e9e31cfe06bf3418fa667"
		hash9 = "d49690ccb82ff9d42d3ee9d7da693fd7d302734562de088e9298413d56b86ed0"

	strings:
		$ = "/root/.hsperfdata" ascii fullword
		$ = "Desc| Filename | size |state|" ascii fullword
		$ = "VS filesystem: %s" ascii fullword
		$ = "File already exist on remote filesystem !" ascii fullword
		$ = "/tmp/.sync.pid" ascii fullword
		$ = "rem_fd: ssl " ascii fullword
		$ = "TREX_PID=%u" ascii fullword
		$ = "/tmp/.xdfg" ascii fullword
		$ = "__we_are_happy__" ascii
		$ = "/root/.sess" ascii fullword

	condition:
		uint16( 0 ) == 0x457f and filesize < 5000KB and 4 of them
}

rule SIGNATURE_BASE_APT_MAL_LNX_Turla_Apr202004_1_Opcode : FILE
{
	meta:
		description = "Detects Turla Linux malware x64 x32"
		author = "Leonardo S.p.A."
		id = "03043f59-c81a-5423-bec1-6cd88f6e3c52"
		date = "2020-04-24"
		modified = "2023-12-05"
		reference = "https://www.leonardocompany.com/en/news-and-stories-detail/-/detail/knowledge-the-basis-of-protection"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_turla_penquin.yar#L35-L66"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "19524e6ec3b0d49ff9c85ce361ef1922b92e4f7876ddb7d6c9b209b5357080e3"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "67d9556c695ef6c51abf6fbab17acb3466e3149cf4d20cb64d6d34dc969b6502"
		hash2 = "8ccc081d4940c5d8aa6b782c16ed82528c0885bbb08210a8d0a8c519c54215bc"
		hash3 = "8856a68d95e4e79301779770a83e3fad8f122b849a9e9e31cfe06bf3418fa667"
		hash4 = "1d5e4466a6c5723cd30caf8b1c3d33d1a3d4c94c25e2ebe186c02b8b41daf905"
		hash5 = "2dabb2c5c04da560a6b56dbaa565d1eab8189d1fa4a85557a22157877065ea08"
		hash6 = "3e138e4e34c6eed3506efc7c805fce19af13bd62aeb35544f81f111e83b5d0d4"
		hash7 = "5a204263cac112318cd162f1c372437abf7f2092902b05e943e8784869629dd8"
		hash8 = "8856a68d95e4e79301779770a83e3fad8f122b849a9e9e31cfe06bf3418fa667"
		hash9 = "d49690ccb82ff9d42d3ee9d7da693fd7d302734562de088e9298413d56b86ed0"

	strings:
		$op0 = { 8D 41 05 32 06 48 FF C6 88 81 E0 80 69 00 }
		$op1 = { 48FFC14883F94975E9 }
		$op2 = { C7 05 9B 7D 29 00 1D 00 00 00 C7 05 2D 7B 29 00 65 74 68 30 C6 05 2A 7B 29 00 00 E8 }
		$op3 = { BF FF FF FF FF E8 96 9D 0A 00 90 90 90 90 90 90 90 90 90 90 89 F0}
		$op4 = { 88D380C305329AC1D60C08889A60A10F084283FA0876E9 }
		$op5 = { 8B 8D 50 DF FF FF B8 09 00 00 00 89 44 24 04 89 0C 24 E8 DD E5 02 00 }
		$op6 = { 8D 5A 05 32 9A 60 26 0C 08 88 9A 20 F4 0E 08 42 83 FA 48 76 EB }
		$op7 = { 8D 4A 05 32 8A 25 26 0C 08 88 8A 20 F4 0E 08 42 83 FA 08 76 EB}

	condition:
		uint16( 0 ) == 0x457f and filesize < 5000KB and 2 of them
}

rule SIGNATURE_BASE_APT_Dropper_Raw64_TEARDROP_1
{
	meta:
		description = "This rule looks for portions of the TEARDROP backdoor that are vital to how it functions. TEARDROP is a memory only dropper that can read files and registry keys, XOR decode an embedded payload, and load the payload into memory. TEARDROP persists as a Windows service and has been observed dropping Cobalt Strike BEACON into memory."
		author = "FireEye"
		id = "88adad58-ba16-5996-9ea8-ea356c3ed5b2"
		date = "2020-12-14"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_solarwinds_sunburst.yar#L141-L156"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "6ab5197e7a1a123055b361a2ef79f8a77a7935606fccc8f163ea5914c94cd14d"
		score = 85
		quality = 85
		tags = ""

	strings:
		$sb1 = { C7 44 24 ?? 80 00 00 00 [0-64] BA 00 00 00 80 [0-32] 48 8D 0D [4-32] FF 15 [4] 48 83 F8 FF [2-64] 41 B8 40 00 00 00 [0-64] FF 15 [4-5] 85 C0 7? ?? 80 3D [4] FF }
		$sb2 = { 80 3D [4] D8 [2-32] 41 B8 04 00 00 00 [0-32] C7 44 24 ?? 4A 46 49 46 [0-32] E8 [4-5] 85 C0 [2-32] C6 05 [4] 6A C6 05 [4] 70 C6 05 [4] 65 C6 05 [4] 67 }
		$sb3 = { BA [4] 48 89 ?? E8 [4] 41 B8 [4] 48 89 ?? 48 89 ?? E8 [4] 85 C0 7? [1-32] 8B 44 24 ?? 48 8B ?? 24 [1-16] 48 01 C8 [0-32] FF D0 }

	condition:
		all of them
}

rule SIGNATURE_BASE_APT_Dropper_Win64_TEARDROP_1 : FILE
{
	meta:
		description = "This rule is intended match specific sequences of opcode found within TEARDROP, including those that decode the embedded payload. TEARDROP is a memory only dropper that can read files and registry keys, XOR decode an embedded payload, and load the payload into memory. TEARDROP persists as a Windows service and has been observed dropping Cobalt Strike BEACON into memory. (comment by Nextron: prone to False Positives)"
		author = "FireEye"
		id = "15dfdb74-5ca3-5bc6-be7a-730333b03ba5"
		date = "2020-12-14"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_solarwinds_sunburst.yar#L157-L174"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "a1fa9b9c700601d10cb77ec714b972f04308de615dfc519f680fc956227cc11d"
		score = 70
		quality = 85
		tags = "FILE"

	strings:
		$loc_4218FE24A5 = { 48 89 C8 45 0F B6 4C 0A 30 }
		$loc_4218FE36CA = { 48 C1 E0 04 83 C3 01 48 01 E8 8B 48 28 8B 50 30 44 8B 40 2C 48 01 F1 4C 01 FA }
		$loc_4218FE2747 = { C6 05 ?? ?? ?? ?? 6A C6 05 ?? ?? ?? ?? 70 C6 05 ?? ?? ?? ?? 65 C6 05 ?? ?? ?? ?? 67 }
		$loc_5551D725A0 = { 48 89 C8 45 0F B6 4C 0A 30 48 89 CE 44 89 CF 48 F7 E3 48 C1 EA 05 48 8D 04 92 48 8D 04 42 48 C1 E0 04 48 29 C6 }
		$loc_5551D726F6 = { 53 4F 46 54 57 41 52 45 ?? ?? ?? ?? 66 74 5C 43 ?? ?? ?? ?? 00 }

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}


rule SIGNATURE_BASE_APT_MAL_APT27_Rshell_Jul24 : MALWARE RSHELL___SYSUPDATE FILE
{
	meta:
		description = "YARA rule to detect RSHELL of APT27"
		author = "Bundesamt fuer Verfassungsschutz, modified by Florian Roth"
		id = "67c8ac4e-8e2f-5cca-90cb-5d5fdf6f86b5"
		date = "2024-07-11"
		modified = "2024-12-12"
		reference = "https://x.com/bfv_bund/status/1811364839656185985?s=12&t=C0_T_re0wRP_NfKa27Xw9w"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_apt27_rshell.yar#L2-L41"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "be5f6281d722bd07e53acd459c794fe3ae870a05ed8979de4c28d357110617bd"
		score = 75
		quality = 85
		tags = "MALWARE, RSHELL / SYSUPDATE, FILE"
		sharing = "TLP:WHITE"
		category = "MALWARE"
		malware = "RSHELL / SYSUPDATE"
		hash1 = "0433edfad648e1e29be54101abaded690302dc7e49ad916cfbbddf99b3ade12c"
		hash2 = "10bb89fdf25c88d3c5623e8d68573124c9a42549750014e3675e2ca342aeba4a"
		hash3 = "2603e1f61363451891c97b0c4ce8acfbfb680d3df4282f9d151ecce3a5679616"
		hash4 = "70dac42491f8f19568a5d7b1d10b29f732a88d75e7f2bfa07b23202bacadf56f"
		hash5 = "b988a6583ce40f07e5fc8e890ae2b1c84a93db8a2e3ca8769241b94bea332a7a"
		hash6 = "c4fe1e56f601d411e2385352606524fb8bbf773bc2ba14889a8de605c2d14da0"
		hash7 = "c787144d285fcca8a542f7a5525a37bcd089b39068b9a4db7fe3554ee6c08301"
		hash8 = "ddaa4d23e4651a517fffbd29f0924607ba6b6253171144da5e49237afe91666b"

	strings:
		$a1 = "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%" ascii
		$a2 = "/proc/self/exe" ascii
		$s1 = "HISTFILE" ascii fullword
		$s2 = "/tmp/guid" ascii fullword
		$sop1 = { e8 ?? ?? ?? ?? c7 43 04 00 00 00 00 8b 3b 85 ff 7e 2? e8 ?? ?? 0? 00 85 c0 7e 0? }
		$sop2 = { c7 43 04 00 00 00 00 8b 3b 85 ff 7e 2? e8 ?? ?? 0? 00 85 c0 7e 0? f7 d8 }

	condition:
		( uint32be( 0 ) == 0x7f454c46 or ( uint32be( 0 ) == 0xcafebabe and uint32be( 4 ) < 0x20 ) or uint32( 0 ) == 0xfeedface or uint32( 0 ) == 0xfeedfacf ) and filesize < 2MB and all of ( $a* ) and 2 of ( $s* ) or 3 of ( $s* )
}

rule SIGNATURE_BASE_APT_UNC4841_ESG_Barracuda_CVE_2023_2868_Forensic_Artifacts_Jun23_1 : SCRIPT CVE_2023_2868
{
	meta:
		description = "Detects forensic artifacts found in the exploitation of CVE-2023-2868 in Barracuda ESG devices by UNC4841"
		author = "Florian Roth"
		id = "50518fa1-33de-5fe5-b957-904d976fb29a"
		date = "2023-06-15"
		modified = "2023-06-16"
		reference = "https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_barracuda_esg_unc4841_jun23.yar#L2-L28"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "fa7cac1e0f6cb6fa3ac271c1fff0039ff182b6859920b4eca25541457654acde"
		score = 75
		quality = 85
		tags = "SCRIPT, CVE-2023-2868"

	strings:
		$x01 = "=;ee=ba;G=s;_ech_o $abcdefg_${ee}se64" ascii
		$x02 = ";echo $abcdefg | base64 -d | sh" ascii
		$x03 = "setsid sh -c \"mkfifo /tmp/p" ascii
		$x04 = "sh -i </tmp/p 2>&1" ascii
		$x05 = "if string.match(hdr:body(), \"^[%w%+/=" ascii
		$x06 = "setsid sh -c \"/sbin/BarracudaMailService eth0\""
		$x07 = "echo \"set the bvp ok\""
		$x08 = "find ${path} -type f ! -name $excludeFileNameKeyword | while read line ;"
		$x09 = " /mail/mstore | xargs -i cp {} /usr/share/.uc/"
		$x10 = "tar -T /mail/mstore/tmplist -czvf "
		$sa1 = "sh -c wget --no-check-certificate http"
		$sa2 = ".tar;chmod +x "

	condition:
		1 of ( $x* ) or all of ( $sa* )
}

rule SIGNATURE_BASE_APT_MAL_UNC4841_SEASPY_Jun23_1 : CVE_2023_2868 FILE
{
	meta:
		description = "Detects SEASPY malware used by UNC4841 in attacks against Barracuda ESG appliances exploiting CVE-2023-2868"
		author = "Florian Roth"
		id = "bcff58f8-87f6-5371-8b96-5d4c0f349000"
		date = "2023-06-16"
		modified = "2023-12-05"
		reference = "https://blog.talosintelligence.com/alchimist-offensive-framework/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_barracuda_esg_unc4841_jun23.yar#L30-L55"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "c1dcb841fb872f0d5e661bfd90fca3075f5efc95b1f9dfff72fa318ed131e9d1"
		score = 85
		quality = 85
		tags = "CVE-2023-2868, FILE"
		hash1 = "3f26a13f023ad0dcd7f2aa4e7771bba74910ee227b4b36ff72edc5f07336f115"

	strings:
		$sx1 = "usage: ./BarracudaMailService <Network-Interface>. e.g.: ./BarracudaMailService eth0" ascii fullword
		$s1 = "fcntl.tmp.amd64." ascii
		$s2 = "Child process id:%d" ascii fullword
		$s3 = "[*]Success!" ascii fullword
		$s4 = "NO port code" ascii
		$s5 = "enter open tty shell" ascii
		$op1 = { 48 89 c6 f3 a6 0f 84 f7 01 00 00 bf 6c 84 5f 00 b9 05 00 00 00 48 89 c6 f3 a6 0f 84 6a 01 00 00 }
		$op2 = { f3 a6 0f 84 d2 00 00 00 48 89 de bf 51 5e 61 00 b9 05 00 00 00 f3 a6 74 21 48 89 de }
		$op3 = { 72 de 45 89 f4 e9 b8 f4 ff ff 48 8b 73 08 45 85 e4 ba 49 3d 62 00 b8 44 81 62 00 48 0f 45 d0 }

	condition:
		uint16( 0 ) == 0x457f and filesize < 9000KB and 3 of them or 5 of them
}

rule SIGNATURE_BASE_APT_MAL_UNC4841_SEASPY_LUA_Jun23_1 : FILE
{
	meta:
		description = "Detects SEASPY malware related LUA script"
		author = "Florian Roth"
		id = "a44861d0-107e-589b-8cf1-3fbc2f5c78dc"
		date = "2023-06-16"
		modified = "2023-12-05"
		reference = "https://blog.talosintelligence.com/alchimist-offensive-framework/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_barracuda_esg_unc4841_jun23.yar#L57-L74"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "f78823a4ba9e025ba4833a2d5234c7baba33c1167c0247f13b8b2baa430aa4e5"
		score = 90
		quality = 85
		tags = "FILE"
		hash1 = "56e8066bf83ff6fe0cec92aede90f6722260e0a3f169fc163ed88589bffd7451"

	strings:
		$x1 = "os.execute('rverify'..' /tmp/'..attachment:filename())" ascii fullword
		$x2 = "log.debug(\"--- opening archive [%s], mimetype [%s]\", tmpfile" ascii fullword
		$xe1 = "os.execute('rverify'..' /tmp/'..attachment:filename())" ascii base64
		$xe2 = "log.debug(\"--- opening archive [%s], mimetype [%s]\", tmpfile" ascii base64

	condition:
		filesize < 500KB and 1 of them
}

rule SIGNATURE_BASE_APT_HKTL_Proxy_Tool_Jun23_1 : FILE
{
	meta:
		description = "Detects agent used as proxy tool in UNC4841 intrusions - possibly Alchemist C2 framework implant"
		author = "Florian Roth"
		id = "0e406737-3083-53c2-a6d2-14c07794125a"
		date = "2023-06-16"
		modified = "2023-12-05"
		reference = "https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_barracuda_esg_unc4841_jun23.yar#L76-L101"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "7e2152e1aa74e1842519e2eecd2acd3ef8eb8d517f3c0ef9f05c983616f223c3"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "ca72fa64ed0a9c22d341a557c6e7c1b6a7264b0c4de0b6f717dd44bddf550bca"
		hash2 = "57e4b180fd559f15b59c43fb3335bd59435d4d76c4676e51a06c6b257ce67fb2"

	strings:
		$a2 = "/src/runtime/panic.go"
		$s1 = "main.handleClientRequest" ascii fullword
		$s2 = "main.sockIP.toAddr" ascii fullword

	condition:
		( uint16( 0 ) == 0x5a4d or uint32be( 0 ) == 0x7f454c46 or uint16( 0 ) == 0xfeca or uint16( 0 ) == 0xfacf or uint32( 0 ) == 0xbebafeca or uint32( 0 ) == 0xbebafeca ) and filesize < 10MB and all of them
}

rule SIGNATURE_BASE_APT_MAL_Hunting_LUA_SEASIDE_1 : FILE
{
	meta:
		description = "Hunting rule looking for strings observed in SEASIDE samples."
		author = "Mandiant"
		id = "86eaff7b-4ca0-53cd-8886-da66a36c778f"
		date = "2023-06-15"
		modified = "2023-12-05"
		reference = "https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_barracuda_esg_unc4841_jun23.yar#L136-L152"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		hash = "cd2813f0260d63ad5adf0446253c2172"
		logic_hash = "82b61325a78bf8ab09d426cfadceb614a256dfcafb2e1f75595de63593ed2574"
		score = 70
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "function on_helo()"
		$s2 = "local bindex,eindex = string.find(helo,'.onion')"
		$s3 = "helosend = 'pd'..' '..helosend"
		$s4 = "os.execute(helosend)"

	condition:
		filesize < 1MB and all of ( $s* )
}

rule SIGNATURE_BASE_APT_MAL_LNX_Hunting_Linux_WHIRLPOOL_1 : FILE
{
	meta:
		description = "Hunting rule looking for strings observed in WHIRLPOOL samples."
		author = "Mandiant"
		id = "a997bd65-c502-53a0-8bb8-62daaa916f0d"
		date = "2023-06-15"
		modified = "2023-12-05"
		reference = "https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_barracuda_esg_unc4841_jun23.yar#L154-L173"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		hash = "177add288b289d43236d2dba33e65956"
		logic_hash = "d03c0e292b9b97bbf76585fc74208e4263d753807b8e4a445be80d41264d5432"
		score = 70
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "error -1 exit" fullword
		$s2 = "create socket error: %s(error: %d)\n" fullword
		$s3 = "connect error: %s(error: %d)\n" fullword
		$s4 = {C7 00 20 32 3E 26 66 C7 40 04 31 00}
		$c1 = "plain_connect" fullword
		$c2 = "ssl_connect" fullword
		$c3 = "SSLShell.c" fullword

	condition:
		uint32( 0 ) == 0x464c457f and filesize < 15MB and ( all of ( $s* ) or all of ( $c* ) )
}

rule SIGNATURE_BASE_APT_MAL_LUA_Hunting_SKIPJACK_1
{
	meta:
		description = "Hunting rule looking for strings observed in SKIPJACK installation script."
		author = "Mandiant"
		id = "0026375c-7f37-5ef9-bd55-5b9fc499e5d2"
		date = "2023-06-15"
		modified = "2023-12-05"
		reference = "https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_barracuda_esg_unc4841_jun23.yar#L175-L193"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		hash = "e4e86c273a2b67a605f5d4686783e0cc"
		logic_hash = "8890cd9ab8190f12997e0653e43c89816df03c7bd41842e5ad21b1986819843e"
		score = 70
		quality = 85
		tags = ""

	strings:
		$str1 = "hdr:name() == 'Content-ID'" base64
		$str2 = "hdr:body() ~= nil" base64
		$str3 = "string.match(hdr:body(),\"^[%w%+/=\\r\\n]+$\")" base64
		$str4 = "openssl aes-256-cbc" base64
		$str5 = "mod_content.lua"
		$str6 = "#!/bin/sh"

	condition:
		all of them
}

rule SIGNATURE_BASE_APT_MAL_LUA_Hunting_Lua_SKIPJACK_2
{
	meta:
		description = "Hunting rule looking for strings observed in SKIPJACK samples."
		author = "Mandiant"
		id = "e1eac294-fe60-5bb2-bae4-0f7bcbe6b1db"
		date = "2023-06-15"
		modified = "2023-12-05"
		reference = "https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_barracuda_esg_unc4841_jun23.yar#L195-L212"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		hash = "87847445f9524671022d70f2a812728f"
		logic_hash = "093e8857c410bd30a076f87ef63d7e1e66f50e3dce75b4add67161782386ee24"
		score = 70
		quality = 85
		tags = ""

	strings:
		$str1 = "hdr:name() == 'Content-ID'"
		$str2 = "hdr:body() ~= nil"
		$str3 = "string.match(hdr:body(),\"^[%w%+/=\\r\\n]+$\")"
		$str4 = "openssl aes-256-cbc"
		$str5 = "| base64 -d| sh 2>"

	condition:
		all of them
}

rule SIGNATURE_BASE_APT_MAL_LUA_Hunting_Lua_SEASPRAY_1
{
	meta:
		description = "Hunting rule looking for strings observed in SEASPRAY samples."
		author = "Mandiant"
		id = "8c744b85-b61e-56d0-8a9e-ae6a954e1b95"
		date = "2023-06-15"
		modified = "2023-12-05"
		reference = "https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_barracuda_esg_unc4841_jun23.yar#L213-L228"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		hash = "35cf6faf442d325961935f660e2ab5a0"
		logic_hash = "856bfb47557b60f69aa1141477d6ce446ea13ebbe899022d7996ceef08bdefbb"
		score = 70
		quality = 85
		tags = ""

	strings:
		$str1 = "string.find(attachment:filename(),'obt075') ~= nil"
		$str2 = "os.execute('cp '..tostring(tmpfile)..' /tmp/'..attachment:filename())"
		$str3 = "os.execute('rverify'..' /tmp/'..attachment:filename())"

	condition:
		all of them
}

rule SIGNATURE_BASE_APT28_Skinnyboy_Dropper_1 : RUSSIA FILE
{
	meta:
		description = "Detects APT28 SkinnyBoy droppers"
		author = "Cluster25"
		id = "ed0b2d2b-f820-57b5-9654-c24734d81996"
		date = "2021-05-24"
		modified = "2023-12-05"
		reference = "https://cluster25.io/wp-content/uploads/2021/05/2021-05_FancyBear.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_apt28.yar#L103-L118"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "9e29ed985fac8701f72f0860fe101272c3c3342ef6857e30d32f5fea14822945"
		score = 75
		quality = 85
		tags = "RUSSIA, FILE"
		hash1 = "12331809c3e03d84498f428a37a28cf6cbb1dafe98c36463593ad12898c588c9"

	strings:
		$ = "cmd /c DEL " ascii
		$ = {8a 08 40 84 c9 75 f9}
		$ = {0f b7 84 0d fc fe ff ff 66 31 84 0d fc fd ff ff}

	condition:
		( uint16( 0 ) == 0x5A4D and all of them )
}

rule SIGNATURE_BASE_APT_Nazar_Svchost_Commands
{
	meta:
		description = "Detects Nazar's svchost based on supported commands"
		author = "Itay Cohen"
		id = "3e02381d-de03-50c8-8bde-2974ee96b7c1"
		date = "2020-04-26"
		modified = "2023-12-05"
		reference = "https://www.epicturla.com/blog/the-lost-nazar"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_nazar.yar#L1-L18"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "c71e8a3b2d69c51ed3f822f62b90906fc0a21d32f1f1850cdef71c335964f9b1"
		score = 75
		quality = 85
		tags = ""
		hash1 = "2fe9b76496a9480273357b6d35c012809bfa3ae8976813a7f5f4959402e3fbb6"
		hash2 = "be624acab7dfe6282bbb32b41b10a98b6189ab3a8d9520e7447214a7e5c27728"

	strings:
		$str1 = { 33 31 34 00 36 36 36 00 33 31 33 00 }
		$str2 = { 33 31 32 00 33 31 35 00 35 35 35 00 }
		$str3 = { 39 39 39 00 35 39 39 00 34 39 39 00 }
		$str4 = { 32 30 39 00 32 30 31 00 32 30 30 00 }
		$str5 = { 31 39 39 00 31 31 39 00 31 38 39 00 31 33 39 00 33 31 31 00 }

	condition:
		4 of them
}


rule SIGNATURE_BASE_APT_LNX_Academic_Camp_May20_Eraser_1 : FILE
{
	meta:
		description = "Detects malware used in attack on academic data centers"
		author = "Florian Roth (Nextron Systems)"
		id = "36d17887-9844-5fa4-8a0d-89cc41b2d876"
		date = "2020-05-16"
		modified = "2023-12-05"
		reference = "https://csirt.egi.eu/academic-data-centers-abused-for-crypto-currency-mining/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/crime_academic_data_centers_camp_may20.yar#L1-L18"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "9a0410e86fa8fb8b599e5b8a6508d6889eb6e26600f0ecf222561ac4a169676d"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "552245645cc49087dfbc827d069fa678626b946f4b71cb35fa4a49becd971363"

	strings:
		$sc2 = { E6 FF FF 48 89 45 D0 8B 45 E0 BA 00 00 00 00 BE
               00 00 00 00 89 C7 E8 }
		$sc3 = { E6 FF FF 89 45 DC 8B 45 DC 83 C0 01 48 98 BE 01
               00 00 00 48 89 C7 E8 }

	condition:
		uint16( 0 ) == 0x457f and filesize < 60KB and all of them
}

rule SIGNATURE_BASE_APT_LNX_Academic_Camp_May20_Loader_1 : FILE
{
	meta:
		description = "Detects malware used in attack on academic data centers"
		author = "Florian Roth (Nextron Systems)"
		id = "cda65abd-d918-5ee6-8f4a-554d47532d76"
		date = "2020-05-16"
		modified = "2023-12-05"
		reference = "https://csirt.egi.eu/academic-data-centers-abused-for-crypto-currency-mining/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/crime_academic_data_centers_camp_may20.yar#L20-L35"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "a73883f9fdf3d53694d9f9efec5f8f15994c5fd80c5f2a87b1741db6b954a023"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "0efdd382872f0ff0866e5f68f0c66c01fcf4f9836a78ddaa5bbb349f20353897"

	strings:
		$sc1 = { C6 45 F1 00 C6 45 F2 0A C6 45 F3 0A C6 45 F4 4A 
               C6 45 F5 04 C6 45 F6 06 C6 45 F7 1B C6 45 F8 01 }
		$sc2 = { 01 48 39 EB 75 EA 48 83 C4 08 5B 5D 41 5C 41 5D }

	condition:
		uint16( 0 ) == 0x457f and filesize < 10KB and all of them
}

rule SIGNATURE_BASE_Apt_RU_Turla_Kazuar_Debugview_Pefeatures : FILE
{
	meta:
		description = "Turla mimicking SysInternals Tools- peFeatures"
		author = "JAG-S"
		id = "0a1675c0-8645-5288-9ef6-e68ffbfe0c3b"
		date = "2020-05-28"
		modified = "2023-12-05"
		reference = "https://www.epicturla.com/blog/sysinturla"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_turla_kazuar.yar#L15-L59"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "10c2e47e5c1885c7dc19d1fb7933c9b15911cbe4c6fba99b7f763738ae934126"
		score = 85
		quality = 85
		tags = "FILE"
		version = "2.0"
		hash1 = "1749c96cc1a4beb9ad4d6e037e40902fac31042fa40152f1d3794f49ed1a2b5c"
		hash2 = "44cc7f6c2b664f15b499c7d07c78c110861d2cc82787ddaad28a5af8efc3daac"

	condition:
		uint16( 0 ) == 0x5a4d and ( pe.version_info [ "LegalCopyright" ] == "Test Copyright" and ( ( pe.version_info [ "ProductName" ] == "Sysinternals DebugView" and pe.version_info [ "Description" ] == "Sysinternals DebugView" ) or ( pe.version_info [ "FileVersion" ] == "4.80.0.0" and pe.version_info [ "Comments" ] == "Sysinternals DebugView" ) or ( pe.version_info [ "OriginalName" ] contains "DebugView.exe" and pe.version_info [ "InternalName" ] contains "DebugView.exe" ) or ( pe.version_info [ "OriginalName" ] == "Agent.exe" and pe.version_info [ "InternalName" ] == "Agent.exe" ) ) )
}

rule SIGNATURE_BASE_APT_MAL_RU_Turla_Kazuar_May20_1 : FILE
{
	meta:
		description = "Detects Turla Kazuar malware"
		author = "Florian Roth (Nextron Systems)"
		id = "cd0d1fa2-5303-55f8-90a7-4a699ec79230"
		date = "2020-05-28"
		modified = "2023-12-05"
		reference = "https://www.epicturla.com/blog/sysinturla"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_turla_kazuar.yar#L61-L81"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "547ed3cd88057ab91a0804ecf515eacca04fcf6e490aed1ee0f6a26c3d6b8268"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "1749c96cc1a4beb9ad4d6e037e40902fac31042fa40152f1d3794f49ed1a2b5c"
		hash2 = "1fca5f41211c800830c5f5c3e355d31a05e4c702401a61f11e25387e25eeb7fa"
		hash3 = "2d8151dabf891cf743e67c6f9765ee79884d024b10d265119873b0967a09b20f"
		hash4 = "44cc7f6c2b664f15b499c7d07c78c110861d2cc82787ddaad28a5af8efc3daac"

	strings:
		$s1 = "Sysinternals" ascii fullword
		$s2 = "Test Copyright" wide fullword
		$op1 = { 0d 01 00 08 34 2e 38 30 2e 30 2e 30 00 00 13 01 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 2000KB and all of them
}

rule SIGNATURE_BASE_APT_RU_APT27_Hyperbro_Vftrace_Loader_Jan22_1 : FILE
{
	meta:
		description = "Yara rule to detect first Hyperbro Loader Stage, often called vftrace.dll. Detects decoding function."
		author = "Bundesamt fuer Verfassungsschutz (modified by Florian Roth)"
		id = "b049e163-2694-5fb9-a3a3-98cc77bcd0ca"
		date = "2022-01-14"
		modified = "2023-12-05"
		reference = "https://www.verfassungsschutz.de/SharedDocs/publikationen/DE/cyberabwehr/2022-01-bfv-cyber-brief.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_apt27_hyperbro.yar#L3-L19"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "d8785ea937891636bea5ed8128de44fa6084a1a48800c1586739c5ca9e4c43bd"
		score = 75
		quality = 85
		tags = "FILE"
		sharing = "TLP:WHITE"
		hash1 = "333B52C2CFAC56B86EE9D54AEF4F0FF4144528917BC1AA1FE1613EFC2318339A"

	strings:
		$decoder_routine = { 8A ?? 41 10 00 00 8B ?? 28 ?? ?? 4? 3B ?? 72 ?? }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 5MB and $decoder_routine and pe.exports ( "D_C_Support_SetD_File" )
}


rule SIGNATURE_BASE_APT_CN_APT27_Compromised_Certficate_Jan22_1
{
	meta:
		description = "Detects compromised certifcates used by APT27 malware"
		author = "Florian Roth (Nextron Systems)"
		id = "f2f015af-219d-51ab-9529-01687a879ebb"
		date = "2022-01-29"
		modified = "2023-12-05"
		reference = "https://www.verfassungsschutz.de/SharedDocs/publikationen/DE/cyberabwehr/2022-01-bfv-cyber-brief.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_apt27_hyperbro.yar#L21-L34"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "94a40d55936fc341eaba5e1accc8bfe3a401114298e7a3cc4d5c64af36eadf9e"
		score = 80
		quality = 85
		tags = ""

	condition:
		for any i in ( 0 .. pe.number_of_signatures ) : ( pe.signatures [ i ] . issuer contains "DigiCert SHA2 Assured ID Code Signing CA" and pe.signatures [ i ] . serial == "08:68:70:51:50:f1:cf:c1:fc:c3:fc:91:a4:49:49:a6" )
}

rule SIGNATURE_BASE_Hvs_APT27_Hyperbro_Decrypted_Stage2 : FILE
{
	meta:
		description = "HyperBro Stage 2 and compressed Stage 3 detection"
		author = "Moritz Oettle"
		id = "039e5d41-eadb-5c53-82cd-20ffd4105326"
		date = "2022-02-07"
		modified = "2023-12-05"
		reference = "https://www.hvs-consulting.de/en/threat-intelligence-report-emissary-panda-apt27"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_apt27_hyperbro.yar#L35-L57"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "6eb56c4a92e89977e536ccc3c70170062aca072c6981b40aeea184ea2ca461a6"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "fc5a58bf0fce9cb96f35ee76842ff17816fe302e3164bc7c6a5ef46f6eff67ed"

	strings:
		$lznt1_compressed_pe_header_small = { FC B9 00 4D 5A 90 }
		$lznt1_compressed_pe_header_large_1 = { FC B9 00 4D 5A 90 00 03 00 00 00 82 04 00 30 FF FF 00 }
		$lznt1_compressed_pe_header_large_2 = { 00 b8 00 38 0d 01 00 40 04 38 19 00 10 01 00 00 }
		$lznt1_compressed_pe_header_large_3 = { 00 0e 1f ba 0e 00 b4 09 cd 00 21 b8 01 4c cd 21 }
		$lznt1_compressed_pe_header_large_4 = { 54 68 00 69 73 20 70 72 6f 67 72 00 61 6d 20 63 }
		$lznt1_compressed_pe_header_large_5 = { 61 6e 6e 6f 00 74 20 62 65 20 72 75 6e 00 20 69 }
		$lznt1_compressed_pe_header_large_6 = { 6e 20 44 4f 53 20 00 6d 6f 64 65 2e 0d 0d 0a 02 }

	condition:
		filesize < 200KB and ( $lznt1_compressed_pe_header_small at 0x9ce ) or ( all of ( $lznt1_compressed_pe_header_large_* ) )
}

rule SIGNATURE_BASE_Hvs_APT27_Hyperbro_Stage3_Persistence
{
	meta:
		description = "HyperBro Stage 3 registry keys for persistence"
		author = "Marko Dorfhuber"
		id = "2bb1d28b-5fc4-5f0b-b546-c8b8192b0d48"
		date = "2022-02-07"
		modified = "2023-12-05"
		reference = "https://www.hvs-consulting.de/en/threat-intelligence-report-emissary-panda-apt27"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_apt27_hyperbro.yar#L103-L117"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "db4b7be2bafe29b5e7c81a90e17a660cf73cff1c2e8edd04a9421daba09e3e0e"
		score = 75
		quality = 85
		tags = ""
		hash1 = "624e85bd669b97bc55ed5c5ea5f6082a1d4900d235a5d2e2a5683a04e36213e8"

	strings:
		$ = "SOFTWARE\\WOW6432Node\\Microsoft\\config_" ascii
		$ = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\windefenders" ascii

	condition:
		1 of them
}

rule SIGNATURE_BASE_APT_IN_TA397_Wmrat : HUNTING
{
	meta:
		description = "track wmRAT based on socket usage, odd error handling, and reused strings"
		author = "Proofpoint"
		id = "c5855b30-3e75-570f-b327-498dfc382159"
		date = "2024-11-20"
		modified = "2025-01-17"
		reference = "https://www.proofpoint.com/us/blog/threat-insight/hidden-plain-sight-ta397s-new-attack-chain-delivers-espionage-rats"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_ta397_dec24.yar#L2-L80"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		hash = "3bf4bbd5564f4381820fb8da5810bd4d9718b5c80a7e8f055961007c6f30da2b"
		hash = "3e9a08972b8ec9c2e64eeb46ce1db92ae3c40bc8de48d278ba4d436fc3c8b3a4"
		hash = "40ddb4463be9d8131f363fd78e21d9de5d838a3ec4044526aea45a473d6ddd61"
		hash = "4836cb7eed0b20da50acb26472f918b180917101c026ce36074e0e879b604308"
		hash = "4e3e4d476810c95c34b6f2aa9c735f8e57e85e3b7a97c709adc5d6ee4a5f6ccc"
		hash = "5ab76cf85ade810b7ae449e3dff8a19a018174ced45d37062c86568d9b7633f9"
		hash = "811741d9df51a9f16272a64ec7eb8ff12f8f26794368b1ff4ad5d30a1f4bb42a"
		hash = "b588a423b826b57dce72c9ab58f89be2ddc710a0367ed0eed001c047d8bef32a"
		hash = "caf871247b7256945598816e9c5461d64b6bdb68a15ff9f8742ca31dc00865f8"
		logic_hash = "b20a13b87f4b81e7ebc10ff2f6203aeab46980e0d481bad786695339dd59bf7a"
		score = 75
		quality = 85
		tags = "HUNTING"
		category = "hunting"
		malfamily = "wmRAT"
		version = "1.0"

	strings:
		$code_sleep_loop = {
            6a 64              // push    0x64
            ff d6              // call    esi
            6a 01              // push    0x1
            e8 ?? ?? ?? ??     // call    operator new
            83 c4 04           // add     esp, 0x4
            3b c7              // cmp     eax, edi

        }
		$code_error_handling = {
            88 19           // mov     byte [ecx], bl
            4a              // dec     edx
            41              // inc     ecx
            47              // inc     edi
            4e              // dec     esi
            85 d2           // test    edx, edx
            ?? ??           // jne     0x401070
            5f              // pop     edi {__saved_edi}
            49              // dec     ecx
            5e              // pop     esi {__saved_esi}
            b8 7a 00 07 80  // mov     eax, 0x8007007a

        }
		$code_socket_recv_parsing = {
            // 8b 15 20 55 41 00   mov     edx, dword [data_415520]
            6a 00              // push    0x0
            b8 04 00 00 00     // mov     eax, 0x4
            2b c6              // sub     eax, esi
            50                 // push    eax {var_10_1}
            8d 0c 3e           // lea     ecx, [esi+edi]
            51                 // push    ecx {var_14_1}
            52                 // push    edx {var_18_1}
            ff ??              // call    ebx
            83 f8 ff           // cmp     eax, 0xffffffff
            ?? ??              // je      0x4082e3
            03 f0              // add     esi, eax
            83 fe 04           // cmp     esi, 0x4
          }
		$str1 = "-.-.-." ascii
		$str2 = "PATH" ascii
		$str3 = "Path=" ascii
		$str4 = "https://microsoft.com" ascii
		$str5 = "%s%ld M" ascii
		$str6 = "%s%ld K" ascii
		$str7 = "%s(%ld)" ascii
		$str8 = "RFOX" ascii
		$str9 = "1llll" ascii
		$str10 = "%d result(s)" ascii
		$str11 = "%s%ld MB" ascii
		$str12 = "%s%ld KB" ascii
		$str13 = "%.1f" ascii
		$str14 = "%02d-%02d-%d %02d:%02d" ascii

	condition:
		uint16be( 0x0 ) == 0x4d5a and ( 2 of ( $code* ) or 10 of ( $str* ) )
}

rule SIGNATURE_BASE_APT_MAL_RU_WIN_Snake_Malware_May23_1 : MEMORY
{
	meta:
		description = "Hunting Russian Intelligence Snake Malware"
		author = "Matt Suiche (Magnet Forensics)"
		id = "53d2de3c-350c-5090-84bb-b6cde16a80ad"
		date = "2023-05-10"
		modified = "2025-03-21"
		reference = "https://media.defense.gov/2023/May/09/2003218554/-1/-1/0/JOINT_CSA_HUNTING_RU_INTEL_SNAKE_MALWARE_20230509.PDF"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_mal_ru_snake_may23.yar#L17-L42"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "7cff7152259bb17a9b72b91f0fbef220aad2f35a1d2758d7225316a9896bf845"
		score = 70
		quality = 71
		tags = "MEMORY"
		threat_name = "Windows.Malware.Snake"
		scan_context = "memory"
		license = "MIT"

	strings:
		$a = { 25 73 23 31 }
		$b = { 25 73 23 32 }
		$c = { 25 73 23 33 }
		$d = { 25 73 23 34 }
		$e = { 2e 74 6d 70 }
		$g = { 2e 73 61 76 }
		$h = { 2e 75 70 64 }

	condition:
		all of them
}
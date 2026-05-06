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

rule CAPE_Aurastealerbypass
{
	meta:
		description = "Bypass AuraStealer"
		author = "enzok"
		id = "e510f46b-de7c-50d1-bff3-97c3acf0452e"
		date = "2025-09-02"
		modified = "2025-09-02"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/781161f232730012ce5fc49cbe0cf2e57b3f6868/analyzer/windows/data/yara/AuraStealer.yar#L1-L14"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/781161f232730012ce5fc49cbe0cf2e57b3f6868/LICENSE"
		logic_hash = "ae174c96c262b1734c58bd6c5f7112221b08596c180612e4970acada35dbd070"
		score = 75
		quality = 70
		tags = ""
		cape_options = "bp0=$antivm1+3,action0=skip,count=0"
		packed = "a9c47f10d5eb77d7d6b356be00b4814a7c1e5bb75739b464beb6ea03fc36cc85"

	strings:
		$antivm1 = {39 04 11 0f 94 C3 8B 44 ?? ?? 85 C0}
		$conf = {8D BE ?? 00 00 00 68 00 40 00 00 5? 5? FF D1 83 C4 ?? 8B 07 8B 57 04 29 C2}
		$keyexpansion = {31 C0 8A 1C 82 88 1C 81 8A 5C 82 01 88 5C 81 01 8A 5C 82 02 88 5C 81 02 8A 5C 82 03 88 5C 81 03 4? 83 F8 08 75 ?? B? 08 00 00 00}

	condition:
		all of them
}

rule CAPE_Aurastealer
{
	meta:
		description = "AuraStealer Payload"
		author = "enzok"
		id = "1fe058a8-1e87-51bb-8b5c-914442bca2e5"
		date = "2025-09-02"
		modified = "2025-09-02"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/781161f232730012ce5fc49cbe0cf2e57b3f6868/data/yara/CAPE/AuraStealer.yar#L1-L18"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/781161f232730012ce5fc49cbe0cf2e57b3f6868/LICENSE"
		logic_hash = "960b83639a898509dc272f3235822401a8f861fa6607991993285b618b882d8b"
		score = 75
		quality = 70
		tags = ""
		cape_type = "AuraStealer Payload"
		unpacked = "a9c47f10d5eb77d7d6b356be00b4814a7c1e5bb75739b464beb6ea03fc36cc85"
		packed = "bac52ffc8072893ff26cdbf1df1ecbcbb1762ded80249d3c9d420f62ed0dc202"

	strings:
		$conf = {8D BE ?? 00 00 00 68 00 40 00 00 5? 5? FF D1 83 C4 ?? 8B 07 8B 57 04 29 C2}
		$key1 = {FF D2 8B 2B 8D 75 ?? 8B 5D ?? 33 5D ?? 8D 45}
		$key2 = {89 0B 89 F9 5? 5? 5? E8 [4] 8B 3F 8D 6F 38 8B 77 30 33 77 34 8D 47 20 8D 4C 24 ?? 89 FA 5? E8}
		$keyexpansion = {31 C0 8A 1C 82 88 1C 81 8A 5C 82 01 88 5C 81 01 8A 5C 82 02 88 5C 81 02 8A 5C 82 03 88 5C 81 03 4? 83 F8 08 75 ?? B? 08 00 00 00}
		$antivm2 = {8B 43 04 8B 0D [4] 3B 81 [4] B? [2] 00 00 B? [2] 00 00 0F 44 D1 85 C0 0F 44 D1 8B 8A [4] 03 8A [4] FF E1 31 FF EB ?? 8B 78 0C 33 78 10 B? [4] 03 05 [4] FF D0}
		$antivm1 = {39 04 11 0f 94 C3 8B 44 ?? ?? 85 C0}

	condition:
		3 of them
}

rule DEADBITS_Avemaria_Warzone : AVEMARIA WARZONE WINMALWARE INFOSTEALER FILE
{
	meta:
		description = "No description has been set in the source file - DeadBits"
		author = "Adam Swanda"
		id = "1e03927b-d59c-5e1f-bdee-e44dfb172fad"
		date = "2019-07-18"
		modified = "2019-08-08"
		reference = "https://github.com/deadbits/yara-rules"
		source_url = "https://github.com/deadbits/yara-rules//blob/d002f7ecee23e09142a3ac3e79c84f71dda3f001/rules/avemaria_warzone.yara#L1-L32"
		license_url = "N/A"
		logic_hash = "1fe55fc8ea80616b11757193c2c74b9cf577ab661ddca4c6c64cfad63a300614"
		score = 75
		quality = 80
		tags = "AVEMARIA, WARZONE, WINMALWARE, INFOSTEALER, FILE"
		Author = "Adam M. Swanda"

	strings:
		$str1 = "cmd.exe /C ping 1.2.3.4 -n 2 -w 1000 > Nul & Del /f /q " ascii fullword
		$str2 = "MsgBox.exe" wide fullword
		$str4 = "\\System32\\cmd.exe" wide fullword
		$str6 = "Ave_Maria" wide
		$str7 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList" ascii fullword
		$str8 = "SMTP Password" wide fullword
		$str11 = "\\Google\\Chrome\\User Data\\Default\\Login Data" wide fullword
		$str12 = "\\sqlmap.dll" wide fullword
		$str14 = "SELECT * FROM logins" ascii fullword
		$str16 = "Elevation:Administrator!new" wide
		$str17 = "/n:%temp%" ascii wide

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 400KB ) and ( 5 of ( $str* ) or all of them )
}

rule ESET_Kobalos_Ssh_Credential_Stealer
{
	meta:
		description = "Kobalos SSH credential stealer seen in OpenSSH client"
		author = "Marc-Etienne M.Léveillé"
		id = "b1fc5163-de48-57fc-8ae7-1f2be6c64d8a"
		date = "2020-11-02"
		modified = "2021-02-01"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/kobalos/kobalos.yar#L58-L73"
		license_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/LICENSE"
		logic_hash = "be238f5c2cc976a5638584a8c0fc580f2076735aadfe374e8d4162ba723bce10"
		score = 75
		quality = 80
		tags = ""
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$ = "user: %.128s host: %.128s port %05d user: %.128s password: %.128s"

	condition:
		any of them
}

rule ESET_IIS_Group05_Iistealer
{
	meta:
		description = "Detects Group 5 native IIS malware family (IIStealer)"
		author = "ESET Research"
		id = "598ec6b2-0349-5da7-acad-72ef2468b927"
		date = "2021-08-04"
		modified = "2021-08-04"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/badiis/badiis.yar#L201-L232"
		license_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/LICENSE"
		logic_hash = "5dff445121fda59df805d6fcb5db3f8f8e52a6e63e2da2a6875f8c9ad9cafc72"
		score = 75
		quality = 80
		tags = ""
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$s1 = "tojLrGzFMbcDTKcH" ascii wide
		$s2 = "4vUOj3IutgtrpVwh" ascii wide
		$s3 = "SoUnRCxgREXMu9bM" ascii wide
		$s4 = "9Zr1Z78OkgaXj1Xr" ascii wide
		$s5 = "cache.txt" ascii wide
		$s6 = "/checkout/checkout.aspx" ascii wide
		$s7 = "/checkout/Payment.aspx" ascii wide
		$s8 = "/privacy.aspx"
		$s9 = "X-IIS-Data"
		$s10 = "POST"
		$s11 = {C7 ?? CF 2F 00 63 00 C7 ?? D3 68 00 65 00 C7 ?? D7 63 00 6B 00 C7 ?? DB 6F 00 75 00 C7 ?? DF 74 00 2F 00 C7 ?? E3 63 00 68 00 C7 ?? E7 65 00 63 00 C7 ?? EB 6B 00 6F 00 C7 ?? EF 75 00 74 00 C7 ?? F3 2E 00 61 00 C7 ?? F7 73 00 70 00 C7 ?? FB 78 00 00 00}
		$s12 = {C7 ?? AF 2F 00 70 00 C7 ?? B3 72 00 69 00 C7 ?? B7 76 00 61 00 C7 ?? BB 63 00 79 00 C7 ?? BF 2E 00 61 00 C7 ?? C3 73 00 70 00 C7 ?? C7 78 00 00 00}

	condition:
		ESET_IIS_Native_Module_PRIVATE and 3 of ( $s* )
}

rule ESET_IIS_Group07_Iispy
{
	meta:
		description = "Detects Group 7 native IIS malware family (IISpy)"
		author = "ESET Research"
		id = "64ed0189-a0be-5592-b9c6-1622700a7ed7"
		date = "2021-08-04"
		modified = "2021-08-04"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/badiis/badiis.yar#L261-L296"
		license_url = "https://github.com/eset/malware-ioc/blob/32eb0b68d34f8219448197a9892849ac59b3c173/LICENSE"
		logic_hash = "ec5db5f36d06f9b0bdfe598fc72431da35afc1473dcc29f437a0f48ea9835a03"
		score = 75
		quality = 80
		tags = ""
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$s1 = "/credential/username"
		$s2 = "/credential/password"
		$s3 = "/computer/domain"
		$s4 = "/computer/name"
		$s5 = "/password"
		$s6 = "/cmd"
		$s7 = "%.8s%.8s=%.8s%.16s%.8s%.16s"
		$s8 = "ImpersonateLoggedOnUser"
		$s9 = "WNetAddConnection2W"
		$t1 = "X-Forwarded-Proto"
		$t2 = "Sec-Fetch-Mode"
		$t3 = "Sec-Fetch-Site"
		$t4 = "Cookie"
		$t5 = {49 45 4E 44 AE 42 60 82}
		$t6 = {89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52}

	condition:
		ESET_IIS_Native_Module_PRIVATE and 2 of ( $s* ) and any of ( $t* )
}

rule FIREEYE_RT_Hacktool_MSIL_Wmispy_1 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'WMIspy' project."
		author = "FireEye"
		id = "ac394751-da40-564b-8e24-8f353326b46a"
		date = "2020-12-08"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/WMISPY/production/yara/HackTool_MSIL_WMIspy_1.yar#L4-L15"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "dd8805d0e470e59b829d98397507d8c2"
		logic_hash = "a5a9f7c7a7bfe474e8b21306ea220b4d476832f3ad4fafdd8967a2250d15a701"
		score = 75
		quality = 73
		tags = "FILE"
		rev = 1

	strings:
		$typelibguid0 = "5ee2bca3-01ad-489b-ab1b-bda7962e06bb" ascii nocase wide

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule MALPEDIA_Win_Final1Stspy_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "6b262f1e-6f1a-5a41-853b-26929c3926c7"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.final1stspy"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.final1stspy_auto.yar#L1-L120"
		license_url = "N/A"
		logic_hash = "2890f444efdd6c719c6ff20f4502542398a3dec68f7c2fb262ec6568139d72d6"
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
		$sequence_0 = { 80c27a 80f219 881439 41 3bce 7cef 8bc7 }
		$sequence_1 = { 8bd6 0f281d???????? 2bd0 0f10040f 0f28ca 660ffcc2 }
		$sequence_2 = { 8a4803 c1e206 80f93d 7508 47 83ff03 }
		$sequence_3 = { 5d c3 2d???????? 78b0 03d0 8b45fc 8a4803 }
		$sequence_4 = { 7508 47 83ff03 7d3e }
		$sequence_5 = { 7410 8a11 8acb 3aca }
		$sequence_6 = { 81e7ff070080 7908 4f 81cf00f8ffff }
		$sequence_7 = { 81cf00f8ffff 47 33f6 85ff 7e0a e8???????? }
		$sequence_8 = { 84db 7410 8a11 8acb 3aca 7425 8a4801 }
		$sequence_9 = { c3 2d???????? 78dc 8b55fc b9???????? }

	condition:
		7 of them and filesize < 557056
}

rule MALPEDIA_Win_Snowflake_Stealer_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "f7453706-1ba2-5bd7-a0a7-c5c6de296895"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.snowflake_stealer"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.snowflake_stealer_auto.yar#L1-L134"
		license_url = "N/A"
		logic_hash = "c1c0789100e95962556dcffebd1be08f13443b80c1f6c738a94979e3119de2a7"
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
		$sequence_0 = { ff750c 6a5c 53 e8???????? 8b6c2448 56 ff7504 }
		$sequence_1 = { ff742428 e8???????? 83c414 eb88 3dab000000 7530 837c243400 }
		$sequence_2 = { ff3408 ff742444 e8???????? 8b7c2440 83c414 89442410 85c0 }
		$sequence_3 = { e8???????? 59 59 8b4c243c 85c9 7409 51 }
		$sequence_4 = { ff7640 e8???????? 83c42c 85c0 7533 6a08 8d442418 }
		$sequence_5 = { ff742444 ff742440 50 e8???????? 8bf0 83c414 85f6 }
		$sequence_6 = { c744240c01000000 eb08 3c2b 0f8593000000 46 8a0e 0fb6c1 }
		$sequence_7 = { e8???????? 59 59 85c0 7507 8b4510 2138 }
		$sequence_8 = { c744240800000000 29f1 89c6 1b7c2414 f7de c1fe1f 01f1 }
		$sequence_9 = { ff743234 ff7524 ff742428 53 e8???????? 8b542428 83c414 }

	condition:
		7 of them and filesize < 6196224
}

rule MALPEDIA_Win_Cadelspy_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "239b2d97-ceb8-5e5b-be90-aeb9b9fcf209"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cadelspy"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.cadelspy_auto.yar#L1-L128"
		license_url = "N/A"
		logic_hash = "b4d9cbb0d8867220f80a8ce48db839eded436dcbd892904385e6486261b96542"
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
		$sequence_0 = { 3d01010000 7d0d 8a4c181c 888840360110 40 ebe9 }
		$sequence_1 = { 7413 50 8b44241c 56 e8???????? 8bf8 59 }
		$sequence_2 = { 89742424 e8???????? 33c0 bf06020000 57 6689842484040000 8d842486040000 }
		$sequence_3 = { 8d9c2464020000 e8???????? 68???????? 8d9c2464020000 e8???????? }
		$sequence_4 = { 8d859e000000 50 e8???????? 83c40c 56 8d859c000000 50 }
		$sequence_5 = { 89742424 89742428 8974242c 89742430 89742434 89742438 e8???????? }
		$sequence_6 = { 56 57 33ff 8db7b03e0110 ff36 e8???????? }
		$sequence_7 = { ff742414 ffd3 8bc6 e8???????? 33c0 40 eb02 }
		$sequence_8 = { 40 8b8d94260000 5f 5e 33cd 5b e8???????? }
		$sequence_9 = { 39742414 0f84d3000000 397508 7474 8b4508 }

	condition:
		7 of them and filesize < 204800
}

rule MALPEDIA_Win_Industrial_Spy_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "49532f61-1558-5e03-9771-9daa1443f81c"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.industrial_spy"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.industrial_spy_auto.yar#L1-L128"
		license_url = "N/A"
		logic_hash = "09d68278c920c888a9a9161c0ac726f167f616f36cff9042eab3321dfe0c396f"
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
		$sequence_0 = { 03c8 43890c26 3bc8 7302 ffc7 037c242c }
		$sequence_1 = { 33c9 ff15???????? 8b15???????? 4c8d0577020200 498904d0 ffc2 8915???????? }
		$sequence_2 = { 418bd9 498bf8 8bf2 4c8d0d2d9c0000 488be9 4c8d051b9c0000 }
		$sequence_3 = { 4403d3 41c1ca0c 4503d1 4133c2 054239faff 0345d4 03d0 }
		$sequence_4 = { 8bc1 488bce 4803d0 e8???????? 33c0 eb0c b801040000 }
		$sequence_5 = { 442bc9 f7d1 443bc9 418bc0 0f46d6 c1e010 }
		$sequence_6 = { 0345c0 418d91442229f4 03d0 448d8997ff2a43 418bc2 c1c206 f7d0 }
		$sequence_7 = { 418d4a01 418bc1 c1e810 03c2 }
		$sequence_8 = { 33c0 eb3d 452bd3 4533c0 4585c9 742f 482bf9 }
		$sequence_9 = { 488d0d4bf40000 48894b48 4963d0 c6435401 e8???????? eb18 4885c9 }

	condition:
		7 of them and filesize < 339968
}

rule MALPEDIA_Win_Chrgetpdsi_Stealer_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "d3ecdf63-3d7b-56f8-8ebb-39b6f5471caa"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.chrgetpdsi_stealer"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.chrgetpdsi_stealer_auto.yar#L1-L134"
		license_url = "N/A"
		logic_hash = "6bfcd142e96c03742e4fbcd1d45c8791f0f2de988eb9c6e51f8b962532c287a2"
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
		$sequence_0 = { 488dbc2428010000 488d742408 660f1f840000000000 0f1f4000 48896c24f0 488d6c24f0 e8???????? }
		$sequence_1 = { e8???????? 84c0 0f8489010000 488b4c2458 488d7101 488b7c2478 0f1f440000 }
		$sequence_2 = { 48898c24b0000000 4889442468 48895c2460 488d3dd9b32500 be27000000 e8???????? 488b542468 }
		$sequence_3 = { 89d8 e8???????? 4889442458 48895c2448 488d05e3a61c00 0f1f00 e8???????? }
		$sequence_4 = { 90 90 488d05e41e4200 e8???????? 90 488b4c2420 488b542418 }
		$sequence_5 = { b909000000 488bbc2408060000 488bb42410060000 4c8d0575882700 41b91a000000 e8???????? 0f1f4000 }
		$sequence_6 = { 31c0 31c9 31d2 31db e9???????? 4889d9 4889c3 }
		$sequence_7 = { 48c740100f000000 488d0dca832500 48894808 833d????????00 7509 488905???????? eb0c }
		$sequence_8 = { 4c8b842410010000 0f1f4000 e9???????? 4c8b842410010000 4d85c0 7e24 498d48ff }
		$sequence_9 = { 4c89442478 0f1f00 4883fa01 7546 488d0573ca1a00 bb01000000 4889d9 }

	condition:
		7 of them and filesize < 10027008
}

rule MALPEDIA_Win_Xdspy_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "54110d73-619a-59d4-a80b-7be8436504a7"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.xdspy"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.xdspy_auto.yar#L1-L174"
		license_url = "N/A"
		logic_hash = "6256dc971ecf3bb6744674fefad5e90a83cd8cf7acf2f0addd47bba093a56e7a"
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
		$sequence_0 = { 8d85b0510000 50 e8???????? 8d85b0510000 50 897da4 }
		$sequence_1 = { 5e e8???????? c9 c3 53 56 68???????? }
		$sequence_2 = { e8???????? 8d851cd1ffff 50 e8???????? ff35???????? 8d851cd1ffff 50 }
		$sequence_3 = { 89459c ff15???????? 85c0 7413 ff15???????? 3db7000000 7506 }
		$sequence_4 = { 56 8bf8 e8???????? 83c410 8bd8 85ff }
		$sequence_5 = { 85f6 0f84ba000000 8975e0 8b04bd804e4100 0500080000 3bf0 }
		$sequence_6 = { c3 8bff 56 57 33ff 8db730074100 }
		$sequence_7 = { e8???????? 68ff000000 e8???????? 59 59 8b7508 8d34f548044100 }
		$sequence_8 = { 0f8514010000 83fb01 0f850b010000 e8???????? 488d8dc0130000 ff15???????? }
		$sequence_9 = { 88840d80070000 488d4901 84c0 75e8 80bd8007000000 488d8580070000 }
		$sequence_10 = { 48898424c0000000 4889bc24c8000000 488d8c2480000000 ff15???????? }
		$sequence_11 = { 4983e801 75ea b801000000 8d501f 6690 }
		$sequence_12 = { 880413 48ffc3 4883fb0e 7cea }
		$sequence_13 = { 75e8 488bcb 0f1f440000 420fb684399c941700 }
		$sequence_14 = { 7413 0f1f840000000000 fe08 488d4001 403838 75f5 }
		$sequence_15 = { e8???????? 488b05???????? 488d15853a0100 488bcb 83e13f }

	condition:
		7 of them and filesize < 3244032
}

rule MALPEDIA_Win_Gspy_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "cfcf9b9b-4569-5d0f-801d-7a4c03469882"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.gspy"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.gspy_auto.yar#L1-L132"
		license_url = "N/A"
		logic_hash = "5f09532c5cfce71a555d1d7b8c6eb07037f464516d07c67472b924dd34736987"
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
		$sequence_0 = { 51 8d54241b 52 e8???????? 8944242c 8a442413 8b5c242c }
		$sequence_1 = { 83c01c 50 55 56 ff15???????? 85c0 740a }
		$sequence_2 = { 8a442412 3cff 7567 8b4d04 66c744241c3f2a c744241ec0744200 33c0 }
		$sequence_3 = { c20400 8b0d???????? 56 33c0 57 8b3d???????? 3bcd }
		$sequence_4 = { 85c0 757a 8b442414 8b08 8d542420 52 50 }
		$sequence_5 = { 51 ff15???????? 85ff 7409 8d442418 e8???????? 83c304 }
		$sequence_6 = { 8bf0 89742410 85f6 7449 33c0 897c2414 }
		$sequence_7 = { 57 8bf8 32c0 88442407 85ff 0f8456010000 53 }
		$sequence_8 = { 8b4124 ffd0 85c0 0f8464ffffff 8b442410 8b08 8b5108 }
		$sequence_9 = { 7408 3c09 7c0e 3c0d 7f0a 83fa02 }

	condition:
		7 of them and filesize < 421888
}

rule MALPEDIA_Win_Spyder_Patchwork_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "ff9f13ab-f307-5c96-9d42-3d8adb391da2"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.spyder_patchwork"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.spyder_patchwork_auto.yar#L1-L133"
		license_url = "N/A"
		logic_hash = "a4925947525684eeb2c63af57878906d58b4bbbd5876d1885456e41c85c55b5b"
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
		$sequence_0 = { 3930 0f8551010000 8b4004 83f82a 7429 83f839 7424 }
		$sequence_1 = { ff74246c 50 e8???????? 83c410 5f 5e 5b }
		$sequence_2 = { 8904a9 8b4c2444 8b44241c c1e002 0101 8b4c2458 8b442430 }
		$sequence_3 = { e9???????? 6800030000 8d44242c 50 6a07 6801990000 e8???????? }
		$sequence_4 = { 743c ba80000000 be00080000 0f1f8000000000 0fb60419 0fb70445403b4400 }
		$sequence_5 = { e8???????? ff7620 e8???????? 56 e8???????? 83c420 5f }
		$sequence_6 = { 741f 8b542410 3bca 7617 8b4608 2bca 51 }
		$sequence_7 = { 8b4c242c 8d04b0 8b28 4e ba02000000 894c2414 89442420 }
		$sequence_8 = { 6689460c 8b0f 8bc1 83e002 83c800 741d 668b4648 }
		$sequence_9 = { ff15???????? 6a06 6a00 ff15???????? 6a00 6a00 6a00 }

	condition:
		7 of them and filesize < 2260992
}

rule MALPEDIA_Win_Dnespy_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "99cbf088-6549-56a2-969b-60e6f7eba155"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dnespy"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.dnespy_auto.yar#L1-L132"
		license_url = "N/A"
		logic_hash = "4e1c2bd2efe3fbaf06ba8ff5d9f3d8607a9e5d8c5f87336409321d599b08c5ad"
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
		$sequence_0 = { 8b54240c a1???????? 89542414 81faff0f0000 762d 0f1f00 ff774c }
		$sequence_1 = { 83f80a 0f85e6080000 834608fc 8b55dc 85d2 791b 8bc2 }
		$sequence_2 = { 894618 837e0cff 7403 ff4e24 8bce e8???????? 8b4e0c }
		$sequence_3 = { 83f9ff 7245 880a 0facc108 c1e808 884a01 0facc108 }
		$sequence_4 = { 8975b4 c745b80f000000 c645a400 8d8de8feffff e8???????? 8b531c 83fa10 }
		$sequence_5 = { 33c9 c645fc02 8b45e4 85c0 0f95c1 8d0c8d04000000 034d10 }
		$sequence_6 = { e9???????? 6a00 57 53 ff762c 56 e8???????? }
		$sequence_7 = { 3bc3 7304 8bc3 eb0b 3dffffff3f 0f87ca000000 }
		$sequence_8 = { 8be8 8bc2 eb16 8b4618 53 ff761c }
		$sequence_9 = { 6a20 c745e400000000 e8???????? 0f104588 8bc8 c745e400000000 8b45b0 }

	condition:
		7 of them and filesize < 794624
}

rule MALPEDIA_Win_Spyder_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "3b0ab008-5fca-5304-bb77-2526da47aa2d"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.spyder"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.spyder_auto.yar#L1-L174"
		license_url = "N/A"
		logic_hash = "12d22cf7781abc3ab19a5f3d98a04aaf02d5caaba80e64280fab23edd5e8d3b7"
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
		$sequence_0 = { 488d057a150000 488905???????? 488d0590200000 488905???????? 488d0576150000 488905???????? }
		$sequence_1 = { 488bc8 ff15???????? 488d15385f0000 488bce 488905???????? ff15???????? }
		$sequence_2 = { 4181f9000000c0 7532 4585d2 756e 488d4b04 4c8d05563e0000 }
		$sequence_3 = { 4c8d05fc890000 498bd4 488bcd e8???????? 85c0 }
		$sequence_4 = { 486bd258 488b04c1 488d4c1010 48ff25???????? 48895c2408 57 }
		$sequence_5 = { 4c8bd8 488905???????? 4885c0 7422 488d15795e0000 488bce ff15???????? }
		$sequence_6 = { 488d0d68a10000 e8???????? 488d1584a10000 488d0d75a10000 e8???????? 90 }
		$sequence_7 = { 443bce 753c 4585d2 7537 488d4b04 4c8d05173e0000 418d5216 }
		$sequence_8 = { 6803010000 f3ab 66ab aa 8d442414 50 }
		$sequence_9 = { 8b4c2414 81e2ffff0000 25ffff0000 52 8b542416 }
		$sequence_10 = { ff15???????? 5f 5e b801000000 5b 81c47c150000 c3 }
		$sequence_11 = { 8bec 8b4508 ff348570370910 ff15???????? 5d }
		$sequence_12 = { c1f805 8d3c85204b0910 8bc3 83e01f }
		$sequence_13 = { 8944241a 66895c2410 668944241e ff15???????? 8b542418 8b442416 }
		$sequence_14 = { f3ab 8b8c248c150000 8d942488010000 66ab aa 8d842490150000 }
		$sequence_15 = { b918000000 33c0 8d7c2431 885c2430 }

	condition:
		7 of them and filesize < 1458176
}

rule MALPEDIA_Win_Arkei_Stealer_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "1f91473e-0f59-5d43-b31c-36e662e7cb73"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.arkei_stealer"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.arkei_stealer_auto.yar#L1-L118"
		license_url = "N/A"
		logic_hash = "ce62b8dc4f39a6203176e1a77c002f4403d000ee3dbdbb3ae02c853f65ed371e"
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
		$sequence_0 = { 0f849ffeffff ba424d0000 668955ec 8b4620 8b0e 8d1481 }
		$sequence_1 = { 57 57 68000000c0 68???????? ff15???????? 8bf8 }
		$sequence_2 = { 52 57 8945f6 ff15???????? 85c0 0f8458feffff 8b4e20 }
		$sequence_3 = { 6689460c 668b4dd6 66894e0e 6683fb18 }
		$sequence_4 = { ff15???????? 85c0 74be 8b45e0 }
		$sequence_5 = { 8d55ec 52 57 8945f6 }
		$sequence_6 = { 895608 668b45d4 6689460c 668b4dd6 66894e0e }
		$sequence_7 = { 8b16 8d448a0e 6a00 8d4de4 51 6a0e }
		$sequence_8 = { 74be 8b45e0 8d55c4 52 6a18 50 }
		$sequence_9 = { 57 8945e8 ffd3 6a0a 57 8bf0 }

	condition:
		7 of them and filesize < 1744896
}

rule MALPEDIA_Win_Mars_Stealer_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "5d89ff0c-708d-5cb2-bdc2-6969544672dc"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mars_stealer"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.mars_stealer_auto.yar#L1-L121"
		license_url = "N/A"
		logic_hash = "cc94c9b32aabf5299f34d05641ffdf1640d29fa168f4cb92b657b3f5122a585c"
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
		$sequence_0 = { 83c404 8945fc 837dfc00 744c 6a00 }
		$sequence_1 = { e8???????? 83c404 85c0 7443 833d????????00 751e }
		$sequence_2 = { 0f90c1 f7d9 0bc8 51 ff15???????? 83c404 8945f4 }
		$sequence_3 = { 8985fcfdffff c745fcc0270900 6a04 8d45fc 50 6a02 }
		$sequence_4 = { 51 e8???????? c78548fcffff94000000 8d9548fcffff }
		$sequence_5 = { 8bec 81ecc8040000 56 57 c78548fcffff00000000 6890000000 6a00 }
		$sequence_6 = { 8d85e8d7ffff 50 e8???????? 6888130000 8d8d78ecffff }
		$sequence_7 = { 8b55f0 52 ff15???????? 83c404 8b45e8 }
		$sequence_8 = { 8d8d78ecffff 51 e8???????? 8d95e4d7ffff 52 8d85e0d7ffff 50 }
		$sequence_9 = { 50 ff15???????? 83c404 8985dcf7ffff 8b85dcf7ffff }

	condition:
		7 of them and filesize < 219136
}

rule MALPEDIA_Win_Nocturnalstealer_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "5964c83b-5a1b-5913-a49a-303693a90164"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nocturnalstealer"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.nocturnalstealer_auto.yar#L1-L134"
		license_url = "N/A"
		logic_hash = "c662283be69db4ef7dfe1019eca1797cdbfc6ecd9828799d75f57c47594f7be3"
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
		$sequence_0 = { e9???????? bd01000000 81c717a0fb5f 01ef 81ef17a0fb5f 5d 81e7cfaad32f }
		$sequence_1 = { d280e1f107c3 7dbf 41 6c 46 3f a984011afd }
		$sequence_2 = { e9???????? 51 b9dd9abe6f 31c8 59 05f1eb6f2f 05b354dc74 }
		$sequence_3 = { e9???????? bb74bcf36f f7d3 4b 81cb108dfb7b 81e337e4f765 55 }
		$sequence_4 = { c70424009d1a20 891424 ba77a7ee3f 89d3 8b1424 53 89e3 }
		$sequence_5 = { e9???????? 58 81c404000000 e9???????? 81f6d544f73f 58 81eb4703df3d }
		$sequence_6 = { ff3424 8b0c24 57 e9???????? 58 051ff53d3f 01c6 }
		$sequence_7 = { f7d0 2d612e2f1b 053325461d 89c2 58 01542404 5a }
		$sequence_8 = { e9???????? 8365d800 c745dcfedf4900 a1???????? 8d4dd8 33c1 8945e0 }
		$sequence_9 = { e9???????? 81f2209cfd37 81eaf4ffef7d 81c2d90dace9 e9???????? 890c24 812c2439bc9f73 }

	condition:
		7 of them and filesize < 10739712
}

rule MALPEDIA_Win_Metastealer_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "d224b589-7615-5bc0-8bb6-5706cda78332"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.metastealer"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.metastealer_auto.yar#L1-L134"
		license_url = "N/A"
		logic_hash = "6cb10cffce7c1599b69c9e05c260560e4bdcb2bc8aa657b55f875ee3bb8ed71d"
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
		$sequence_0 = { f30f59c3 f30f584104 f30f114104 0f28c1 f30f584108 f30f584918 f30f59c3 }
		$sequence_1 = { f3a5 68???????? 66a5 c680b600000000 e8???????? 68???????? e8???????? }
		$sequence_2 = { ffb6a8000000 8d86d8000000 50 56 e8???????? 83c410 f7d8 }
		$sequence_3 = { f30f59cb f30f5c662c f30f101d???????? f30f5c4e28 f30f1150f8 f30f59e2 f30f59ca }
		$sequence_4 = { ff7624 e8???????? 83c404 894654 85c0 7412 0f57c0 }
		$sequence_5 = { f30f5dc3 f30f107804 f30f102d???????? f20f1035???????? f30f59d3 f30f59c5 f30f5ed7 }
		$sequence_6 = { f20f101d???????? f20f1025???????? f20f102d???????? f20f1035???????? f20f103d???????? 8b5508 8b45fc }
		$sequence_7 = { ffd0 8bd8 83c40c 807d0c00 899f88010000 895df8 c703???????? }
		$sequence_8 = { e8???????? 6a02 8d4704 83c302 50 53 e8???????? }
		$sequence_9 = { ffd0 83c404 85c0 7423 8b8690010000 80781100 74e8 }

	condition:
		7 of them and filesize < 26230784
}

rule MALPEDIA_Win_Observer_Stealer_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "c0737640-3fea-5607-8cf7-00374c1f837c"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.observer_stealer"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.observer_stealer_auto.yar#L1-L131"
		license_url = "N/A"
		logic_hash = "0be9a733455d3fbd7030daf285d74174d225df89f30a4020aa754c9c1ec43bc3"
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
		$sequence_0 = { 59 57 8bc8 e8???????? 6a14 89442418 e8???????? }
		$sequence_1 = { 8bcb e8???????? e9???????? 85ff 74cc 68???????? 8d4c2418 }
		$sequence_2 = { c3 33c0 8bd1 53 56 57 8bfa }
		$sequence_3 = { 59 59 c20400 56 8bf1 8b46e0 8b4004 }
		$sequence_4 = { c3 83ec10 53 8bc1 55 }
		$sequence_5 = { 55 e8???????? 3bc7 0f87ab000000 6bc024 50 89442414 }
		$sequence_6 = { 8b751c 56 68???????? 57 e8???????? 8b4510 }
		$sequence_7 = { 894d0c 894508 3d00100000 7215 8d4508 50 8d450c }
		$sequence_8 = { 8d4dc0 68???????? e8???????? 837d3408 8d4d20 8d4508 0f434d20 }
		$sequence_9 = { 89773c c7474001000000 c74750fb5d7708 e8???????? 8bc7 5f 5e }

	condition:
		7 of them and filesize < 614400
}

rule MALPEDIA_Win_Luca_Stealer_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "962fd693-32a3-53ad-92cd-b5debbabca20"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.luca_stealer"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.luca_stealer_auto.yar#L1-L134"
		license_url = "N/A"
		logic_hash = "41100df83b0cacd06b9716ae5b8e2710b883cf9f1a3da041c06d57097240cc33"
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
		$sequence_0 = { eb0a f6471280 7504 6683e914 4d85f6 7416 6641395e10 }
		$sequence_1 = { e8???????? 85c0 7428 85db 7524 488d0daee71600 e8???????? }
		$sequence_2 = { e9???????? 4156 56 57 53 4883ec28 83791803 }
		$sequence_3 = { e8???????? 4c8d4768 4889f1 ba03003000 e8???????? 4883c770 4889f1 }
		$sequence_4 = { eb06 492130 412131 488b5c2430 8bc6 488b742438 488b7c2440 }
		$sequence_5 = { 8d507e 448d4301 e8???????? 8b442458 448d4301 448bce 89442420 }
		$sequence_6 = { e9???????? 48b8af39a3b04c5dea12 c3 56 4883ec20 4889ce 89f0 }
		$sequence_7 = { ff15???????? 4438bfa8010000 740c 488b8fe8010000 e8???????? 488bcf e8???????? }
		$sequence_8 = { e8???????? 488d8d60110000 e8???????? 488d8d501f0000 e8???????? 488d15683a2c00 488db560110000 }
		$sequence_9 = { e9???????? 488d542468 48c70205000000 e9???????? 488d542468 48c70202000000 eb7d }

	condition:
		7 of them and filesize < 9285632
}

rule MALPEDIA_Win_Ravenstealer_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "84f90220-3279-5007-a5a1-8ce5ade31449"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ravenstealer"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.ravenstealer_auto.yar#L1-L134"
		license_url = "N/A"
		logic_hash = "79823541f3a380244fa96c3e3bd68dec6432b3566c33a9fa586cf37babf2bf66"
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
		$sequence_0 = { 4c8b742430 4883c438 415f 415c 5f 5b c3 }
		$sequence_1 = { f20f5cc8 f20f59ca f20f114c2440 e8???????? 440fbef0 e8???????? 0fbed8 }
		$sequence_2 = { c744247809000000 eb58 448d3c37 0fbe05???????? 4103c7 0fbe0d???????? 33d2 }
		$sequence_3 = { 8b5c2450 8b742454 3bc1 0f84bb130000 0fb605???????? 0fb605???????? 0fb605???????? }
		$sequence_4 = { f20f59c8 f2440f2cf1 8b85e01f0000 83c04c f20f2ad0 0fb605???????? 0fbec8 }
		$sequence_5 = { f2480f2ac0 f20f594590 f20f2cc0 89442428 8b442458 83e86a 660f6ed0 }
		$sequence_6 = { e8???????? 488bf8 488d9424b0000000 488d8c2450090000 e8???????? 488b18 488d9424b8000000 }
		$sequence_7 = { 85c0 7416 81a5fc030000fffeffff 488d8d28100000 e8???????? 4883c420 5d }
		$sequence_8 = { 83f801 750a 488b07 488bcf ff5008 90 4d85f6 }
		$sequence_9 = { 7406 6683f92f 7504 4883c002 483bd8 7442 0f1f8000000000 }

	condition:
		7 of them and filesize < 8337408
}

rule MALPEDIA_Win_Iispy_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "4e322e5f-cd33-52bd-bbf3-6439753e827c"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.iispy"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.iispy_auto.yar#L1-L131"
		license_url = "N/A"
		logic_hash = "a87fdac5aecf4afd1bb012fec4f493869a7cd5fec753856e83872c6436c79acf"
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
		$sequence_0 = { e8???????? 837c242400 8bf8 740c ff742428 e8???????? 83c404 }
		$sequence_1 = { 03d8 eb49 b8d34d6210 f7e3 8bca 8b5514 c1e906 }
		$sequence_2 = { 50 8d4110 50 8d4129 50 }
		$sequence_3 = { 8b048528cf0210 0fb6440828 83e040 5d c3 e8???????? c70009000000 }
		$sequence_4 = { 84c0 0f8429010000 8b4c2408 83c620 8b01 c1e005 }
		$sequence_5 = { b81f85eb51 f7eb 5f c1fa05 8bca c1e91f 03ca }
		$sequence_6 = { 6a01 53 ff15???????? ebe0 b80d000780 5f 5e }
		$sequence_7 = { 68000000c0 57 ff15???????? 8bf8 83ffff 74c5 8b4dec }
		$sequence_8 = { 3245f0 32ec 3245e4 3245e0 3245e8 3245d0 3245ff }
		$sequence_9 = { 50 e8???????? 83a628cf021000 59 83c604 81fe00020000 72dd }

	condition:
		7 of them and filesize < 397312
}

rule MALPEDIA_Win_Temp_Stealer_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "06945ffb-74bb-55c6-897c-840bc8a35717"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.temp_stealer"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.temp_stealer_auto.yar#L1-L130"
		license_url = "N/A"
		logic_hash = "0687eb315a2ca722457708cc43ae8e72e82f9cde0b8833cdb29551011317ae50"
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
		$sequence_0 = { 488b4d08 e8???????? 4403f7 4883c330 443bb518020000 0f8c37ffffff 488b5d00 }
		$sequence_1 = { 488d1537b00300 488bcb ff15???????? 488945b0 488d1533b00300 488bcb ff15???????? }
		$sequence_2 = { f20f58cb f20f58cf f20f102d???????? 488d1592e10100 f20f59ee f2430f1004c1 }
		$sequence_3 = { 4533c0 baa00f0000 e8???????? 488b05???????? 4c8d05f52b0300 488bd5 48c1fa06 }
		$sequence_4 = { 488d0526dc0100 483947f0 741a 488b0f 4885c9 7412 833900 }
		$sequence_5 = { 90 488b8d80000000 e8???????? 90 498bcd }
		$sequence_6 = { 488b13 48c1e205 4883c208 488bcb e8???????? 90 4183660800 }
		$sequence_7 = { 894708 488d5901 41bf20000000 418bc7 48f7e3 498d4fdf 480f40c1 }
		$sequence_8 = { 48895c2478 488d5530 488d4c2460 e8???????? 90 488d5580 }
		$sequence_9 = { 90 488d442440 48894558 4c897c2440 4c897c2450 48895c2458 488d153cc80300 }

	condition:
		7 of them and filesize < 652288
}

rule MALPEDIA_Win_Sysraw_Stealer_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "c0b55ef6-5e72-5427-8051-b4c3cd8766ea"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sysraw_stealer"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.sysraw_stealer_auto.yar#L1-L113"
		license_url = "N/A"
		logic_hash = "c61c4a8b05627678a7ba0afb4e01a7aec8181a910b716ed57582ec5bcddd612c"
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
		$sequence_0 = { ffd3 8bd0 8d8decfeffff ffd6 8b4d90 8d9580feffff 83c114 }
		$sequence_1 = { 56 ff512c 8b55bc 8b06 8d8d54feffff }
		$sequence_2 = { 33c9 8955bc 894de4 ba3f000000 }
		$sequence_3 = { 6a0d 57 56 ff5238 }
		$sequence_4 = { 8bf8 ffd6 3bfb 7472 }
		$sequence_5 = { 8b8df8feffff 8b85f4feffff 898d24feffff 8b8df0feffff 898d1cfeffff }
		$sequence_6 = { 8b550c 8b06 51 52 56 }
		$sequence_7 = { 2bd7 6a00 42 83ec08 895590 db4590 }
		$sequence_8 = { 8bd0 8b45d4 51 f7da }
		$sequence_9 = { 50 ffd3 8bd0 8d8d24ffffff ffd6 }

	condition:
		7 of them and filesize < 1540096
}

rule MALPEDIA_Win_Iconic_Stealer_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "7673e219-b974-5ee5-b8e5-79ce461f9ab7"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.iconic_stealer"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.iconic_stealer_auto.yar#L1-L134"
		license_url = "N/A"
		logic_hash = "5bc33a8c1cdbea6882940424bec9a55b2f154b2fa412fc3e5ed34989f79a9444"
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
		$sequence_0 = { ebc9 4885f6 740f ba68000000 488bce e8???????? eb0a }
		$sequence_1 = { 498b4a18 8b4148 034144 7912 458bc6 498bd2 e8???????? }
		$sequence_2 = { ff8bdc000000 c687c500000003 40387367 7407 c7473407000000 b805000000 394734 }
		$sequence_3 = { e9???????? f7430400000001 488b0e 4489642454 48894c2468 4c896598 0fb64164 }
		$sequence_4 = { e9???????? 41f7450400000100 0f8480020000 4889bc2458010000 498b3e 4c396648 7414 }
		$sequence_5 = { e8???????? 488be8 4885c0 0f849d020000 80783f02 0f8493020000 488b542438 }
		$sequence_6 = { ff15???????? 85c0 0f8494000000 39bc2480000000 0f8487000000 498bd6 4c8d1d8d6c0300 }
		$sequence_7 = { b8e08004e0 48094330 44896374 4c89a378020000 4c89a370020000 4c89a380020000 4c89a330020000 }
		$sequence_8 = { 744d 4c8bc1 eb48 4c8d442440 4889742440 488d150c780300 4489742448 }
		$sequence_9 = { 4d85c0 741a 410fb74010 6685c0 7f05 6603c8 eb0b }

	condition:
		7 of them and filesize < 2401280
}

rule MALPEDIA_Win_Erbium_Stealer_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "4b8a0033-eafb-588e-852d-212657477c66"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.erbium_stealer"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.erbium_stealer_auto.yar#L1-L123"
		license_url = "N/A"
		logic_hash = "52e0e8033201024664e25bae217264a7d239dc0c23fc20bab4e50f4bf89b0343"
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
		$sequence_0 = { 75f8 ba???????? b926000000 2bd0 }
		$sequence_1 = { 7409 83c002 66833800 75f7 668b4c2450 6685c9 7418 }
		$sequence_2 = { 6a04 6800200000 23f0 56 6a00 ff15???????? }
		$sequence_3 = { ff15???????? 8945bc 68???????? 8b55f4 52 }
		$sequence_4 = { eb96 6a04 6800300000 6a18 6a00 8b4508 50 }
		$sequence_5 = { 52 8b4508 50 ff55bc 33c9 }
		$sequence_6 = { 668b8c24a0020000 6685c9 741b 8d9424a0020000 0fb7c9 2bd0 668908 }
		$sequence_7 = { ff55b8 c745cc00000000 837dcc00 0f85a2000000 c745c400000000 8d4dc4 51 }
		$sequence_8 = { 75f8 668b8c24a0020000 6685c9 741b 8d9424a0020000 }
		$sequence_9 = { 8b55f8 8b45fc 0302 8b4de0 0fb711 81e2ff0f0000 }

	condition:
		7 of them and filesize < 33792
}

rule MALPEDIA_Win_Valkyrie_Stealer_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "d4598928-8b14-591c-9777-90769a8eecd7"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.valkyrie_stealer"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.valkyrie_stealer_auto.yar#L1-L134"
		license_url = "N/A"
		logic_hash = "c5262da30071ead337de0712314a64ba13ec652e925a6c656e4cda19b1fcb853"
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
		$sequence_0 = { 89442430 85c0 0f85ab130000 4a8b4c3500 44396914 7d18 e8???????? }
		$sequence_1 = { 85c9 741c 498b07 44386067 750f 498b8788000000 488d0c49 }
		$sequence_2 = { e8???????? 448b4ddc eb2a 8d4101 418907 488d0c49 488b8388000000 }
		$sequence_3 = { 8bc2 c645b82d c1e81f 03d0 c645bb20 c645be3a 8d0492 }
		$sequence_4 = { 8bde eb4e 803c3e75 751b 8d4305 413bc6 7359 }
		$sequence_5 = { e8???????? 8d4701 e9???????? 8bcd 488d15829f0b00 4803ce 41b804000000 }
		$sequence_6 = { 8b8590000000 ffc8 4898 488d0c40 488d1ccf 0fbe4301 3cfa }
		$sequence_7 = { 7417 4c8b542448 41f6427002 750b 410fbae61c 0f820c010000 488b85f0000000 }
		$sequence_8 = { 488bf0 4885c0 0f84cb000000 837d0800 7411 488b4f20 498bd6 }
		$sequence_9 = { eb25 48c744242002000000 4c8d0d17781100 4533c0 ba02000000 488d8c2498000000 e8???????? }

	condition:
		7 of them and filesize < 2895872
}

rule MALPEDIA_Win_Santa_Stealer_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "698b58d7-3beb-5b12-b9ab-ea8db82a9446"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.santa_stealer"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.santa_stealer_auto.yar#L1-L134"
		license_url = "N/A"
		logic_hash = "0ee975510b7aa8f6c88f59ccf7386a44e723fcc4879e58b69b100521065bb285"
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
		$sequence_0 = { e9???????? 488d5640 4c89e1 44896c2458 4c897c2460 e8???????? 89c3 }
		$sequence_1 = { 6644894114 488b4918 41c7422407000000 80796700 75b3 80796800 75ad }
		$sequence_2 = { c744246cffffffff 488b01 4885c0 7464 4c8d44246c ba0a000000 ff5050 }
		$sequence_3 = { e8???????? 89c7 85c0 0f8504f9ffff 8b4334 c7436801000000 4429e0 }
		$sequence_4 = { e8???????? 89c3 85c0 0f84fc000000 31db 662e0f1f840000000000 4c89e2 }
		$sequence_5 = { 7371 418b4120 85c0 755f 4881faffffff3f 7768 4883ec38 }
		$sequence_6 = { c6431770 488d15d8461100 480f44fa 4d85e4 b8011a0000 48896b08 488d15d040fbff }
		$sequence_7 = { e8???????? 4d85ff 7475 440fb74760 410fbf4e36 4139c8 7c66 }
		$sequence_8 = { f77134 8d5001 4439fa 0f84b0010000 4531c9 4c8d442448 4489fa }
		$sequence_9 = { e8???????? 4829c4 488b4548 4885c9 742d 4989ca 4883796800 }

	condition:
		7 of them and filesize < 27009024
}

rule MALPEDIA_Win_Mystic_Stealer_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "ff6d02a5-11a9-5b9c-bc25-58f6a66b5d47"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mystic_stealer"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.mystic_stealer_auto.yar#L1-L120"
		license_url = "N/A"
		logic_hash = "ec33f5bc78df8bf32bd1dfa20b10a2a5389598f3b75f6130cffa6e3d8120ea9d"
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
		$sequence_0 = { 7509 3bef 7505 33db 43 eb02 33db }
		$sequence_1 = { 741f 8b0e 50 8b510c e8???????? 8b06 59 }
		$sequence_2 = { 3b5c242c 7f59 66ff84463c0b0000 33c9 }
		$sequence_3 = { e8???????? 83bd5014000002 59 59 }
		$sequence_4 = { 8bc2 41 3bca 8b542418 0f4ec1 8b4c2414 89442430 }
		$sequence_5 = { 8bcf c7460471000000 e8???????? 33c9 394e14 }
		$sequence_6 = { 5b e9???????? a1???????? 8bcf c746049a020000 894718 e8???????? }
		$sequence_7 = { 3bca 7420 0fb7449d02 8bca }
		$sequence_8 = { 80ea03 c6040101 8b8ea0160000 8b8698160000 41 898ea0160000 c6040100 }
		$sequence_9 = { 57 ffb42444010000 ffb4244c010000 50 }

	condition:
		7 of them and filesize < 465920
}

rule MALPEDIA_Win_Katz_Stealer_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "c49e5ae3-476e-56a3-98bc-9b636f776fa6"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.katz_stealer"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.katz_stealer_auto.yar#L1-L127"
		license_url = "N/A"
		logic_hash = "fd471cd54233791d0b513e7355b1bd82a81ef2e5ff3948f16fb07b4227562780"
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
		$sequence_0 = { ffd5 85c0 7516 6aff 5a 488b8c2480000000 ff15???????? }
		$sequence_1 = { 31c9 e8???????? 4893 e9???????? 85f6 }
		$sequence_2 = { 0f8517ffffff e9???????? 4889f9 ff15???????? 83f8ff 0f84ba030000 85db }
		$sequence_3 = { 488b4c2470 e8???????? 488b5c2450 8b742460 39b42480000000 }
		$sequence_4 = { e9???????? 4885d2 0f8429ffffff 488d0562f30000 4889842490000000 4c8b842490000000 }
		$sequence_5 = { e8???????? 66490f6ec5 66480f6ee7 4889f1 f20f5ec4 488d15dab00000 f20f5905???????? }
		$sequence_6 = { 488b8424b0070000 488d15663a0000 4889d9 488b04f8 448b4004 e8???????? }
		$sequence_7 = { f3ab 488d15f64c0000 4889f1 488dbc2494050000 e8???????? 4885c0 7449 }
		$sequence_8 = { 4c89c7 f3ab 488d0d075d0000 48b80100000006000000 4889842490020000 4c8d8c2480010000 }
		$sequence_9 = { 4489c8 4883c468 5b 5e c3 f6c701 0f8477010000 }

	condition:
		7 of them and filesize < 238592
}

rule MALPEDIA_Win_Ntospy_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "8131d4ba-7ab9-5f25-bfe1-80fb81c429a4"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ntospy"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.ntospy_auto.yar#L1-L117"
		license_url = "N/A"
		logic_hash = "8fbd4c5ffc79f2d95a93b5deb7321b5b82d08f35463db086df64bd3e92a52647"
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
		$sequence_0 = { 5f c3 48897c2408 488d3dacf90000 }
		$sequence_1 = { eb74 85c9 7858 3b15???????? 7350 488bca 4c8d05e5b40000 }
		$sequence_2 = { 8bfa 4c8d0d5d740000 488bd9 488d1553740000 b916000000 4c8d053f740000 e8???????? }
		$sequence_3 = { b808000000 486bc000 488d0deaad0000 48c7040102000000 b808000000 }
		$sequence_4 = { 48890d???????? 488d0512f50000 488d0d3bf70000 488905???????? 48890d???????? e8???????? }
		$sequence_5 = { 4c8d0578760000 488d15016d0000 e8???????? 4885c0 740f 488bcb }
		$sequence_6 = { f20f1000 8b5808 e9???????? 488d05dfc70000 4a8b0ce8 }
		$sequence_7 = { 488d0d4c710000 8364242800 41b803000000 4533c9 }
		$sequence_8 = { c3 4883ec28 e8???????? 488bc8 488d1501040100 }
		$sequence_9 = { 4533f6 4863ce 488d3d20f90000 488bc1 }

	condition:
		7 of them and filesize < 208896
}

rule MALPEDIA_Win_Troll_Stealer_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "40759ced-a25e-5434-bc7c-501cfe15d47a"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.troll_stealer"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.troll_stealer_auto.yar#L1-L130"
		license_url = "N/A"
		logic_hash = "5f0403028aceb1e51ecaa890b1a7ca49efec2e1c71ccfd760d9d2619abef354a"
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
		$sequence_0 = { 49895008 6699 49894010 0fb7d5 9c c0f2b0 66d3f2 }
		$sequence_1 = { d0ca 80c2f3 f9 f8 d0c2 4432ca f7c465491a38 }
		$sequence_2 = { f7d2 f9 d1c2 4153 41ffc3 311424 415b }
		$sequence_3 = { 4181eb2315e85c 313424 458bdd 49c7c33109c930 }
		$sequence_4 = { 81d9d83d744a f6d2 80c253 0fbfc8 d2cd d0c2 }
		$sequence_5 = { 313c24 480fbafbc6 c1eb14 480fb7da 5b 4863ff f8 }
		$sequence_6 = { 453bf3 4153 311424 664181eb996f 415b f9 4863d2 }
		$sequence_7 = { 4d8d141a 48bd0000000002000000 4d8d142a 410fc1f9 4c8bc4 4881ec80010000 450fbfc8 }
		$sequence_8 = { 403ad4 81f6a540bf26 f7d6 f5 d1c6 f8 f7d6 }
		$sequence_9 = { 4112eb 418910 4080dd61 40fec5 660bef 418b2b 4981c304000000 }

	condition:
		7 of them and filesize < 45868032
}

rule MALPEDIA_Win_Goldenspy_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "9a246a47-ca73-52d5-9d24-1b989582e4ce"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.goldenspy"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.goldenspy_auto.yar#L1-L125"
		license_url = "N/A"
		logic_hash = "abc1cc932d348f65dac5bf1d4eeb448d62aaba8c9d68819a9d802639d61024c9"
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
		$sequence_0 = { 8b0cbd48b24700 c644112900 837dfc00 7507 }
		$sequence_1 = { 8bce ff5010 eb2d 8b06 8bce ff501c eb24 }
		$sequence_2 = { 8bc8 e8???????? 8d4de0 c645fc0c e8???????? }
		$sequence_3 = { ff75bc 8bcf e8???????? 3bf3 0f85b4feffff b001 }
		$sequence_4 = { 50 8bcb e8???????? ba01000000 eb0d }
		$sequence_5 = { e8???????? 84c0 0f84d7000000 8b55c8 8d4dd8 e8???????? c745fc01000000 }
		$sequence_6 = { 50 8bce c78588fdffff00000000 e8???????? 8b00 3b06 7507 }
		$sequence_7 = { 51 0f434520 50 51 8d8dccfeffff e8???????? 837d1c10 }
		$sequence_8 = { 8b08 2bd1 52 eb2b 8b8538ffffff a804 752d }
		$sequence_9 = { 6a00 50 6802000080 ff15???????? 85c0 7557 }

	condition:
		7 of them and filesize < 1081344
}

rule MALPEDIA_Win_Ufrstealer_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "ba013c32-c7d7-5540-a7af-23c784527e98"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ufrstealer"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.ufrstealer_auto.yar#L1-L124"
		license_url = "N/A"
		logic_hash = "5a74533151b417ab8386a9dc0bd4bcb97ff632563f715bef9c755e4394a3e888"
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
		$sequence_0 = { 8955f4 3b55f0 0f82ddfcffff 68???????? e8???????? 68???????? }
		$sequence_1 = { 72f2 eb1e 8b75e8 46 }
		$sequence_2 = { ff35???????? ff15???????? 8bd8 ff75fc ff7608 53 ff15???????? }
		$sequence_3 = { 83c304 ebb2 c705????????66666666 6a04 68???????? e8???????? }
		$sequence_4 = { 85c0 7548 803d????????00 7411 6a00 68???????? ff15???????? }
		$sequence_5 = { 6800040000 ff7510 6aff ff7204 6a00 6a00 ff15???????? }
		$sequence_6 = { 8945ec ff75f0 ff15???????? 50 6a06 ff75f0 }
		$sequence_7 = { 6801000080 ff15???????? 85c0 0f85fc030000 68000000f0 6a01 6a00 }
		$sequence_8 = { e8???????? 85c0 0f846c020000 83c00a }
		$sequence_9 = { a1???????? 0305???????? c60000 68???????? ff35???????? e8???????? }

	condition:
		7 of them and filesize < 770048
}

rule MALPEDIA_Win_Stealer_0X3401_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "2ae48584-3f0a-5429-8e37-f6d8d22f0c81"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.stealer_0x3401"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.stealer_0x3401_auto.yar#L1-L126"
		license_url = "N/A"
		logic_hash = "d48e39ba989936cedf7a0bb5dfb1b2a5b1f5da933f4aa10a0b47e5b061091dba"
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
		$sequence_0 = { 83e03f 6bc830 8b0495c8710210 8b440818 83f8ff 7409 }
		$sequence_1 = { c685d07dffff00 83f808 720d 40 50 ffb5487effff }
		$sequence_2 = { 68???????? 8bd0 c645fc21 8d4d90 e8???????? }
		$sequence_3 = { 8d45bc 837dd010 c745cc01000000 0f4345bc c6400100 8d8578ffffff 50 }
		$sequence_4 = { 660fd645bc f30f7e05???????? 8945b4 a1???????? c78500ffffff3f3f3f00 c78523ffffff00000000 }
		$sequence_5 = { 50 b9???????? c645fc19 e8???????? 8d4d90 }
		$sequence_6 = { 735f 8bc6 8bfe 83e03f c1ff06 6bd830 8b04bdc8710210 }
		$sequence_7 = { 7534 40 83f8fe 0f8798020000 3bc8 7310 ff7710 }
		$sequence_8 = { 49 83c9fe 41 99 898cb558f0ffff 2bc2 }
		$sequence_9 = { 0f95c0 8985a8feffff 3bf7 741f 6690 68???????? 8bcb }

	condition:
		7 of them and filesize < 357376
}

rule MALPEDIA_Win_Netspy_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "57c767b8-cd93-5302-911f-6988f847c306"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.netspy"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.netspy_auto.yar#L1-L100"
		license_url = "N/A"
		logic_hash = "ecbb26e5fda724e71586bc695509ce41d8249123e16dac20dd9df75d451bc239"
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
		$sequence_0 = { 4829c4 488b8538340000 4889e1 48898d704d0000 e8???????? }
		$sequence_1 = { e9???????? 8b858c170000 3da1b579e1 0f84d92c0000 e9???????? 8b858c170000 3da646bcce }
		$sequence_2 = { 48898510130000 8b15???????? 833d????????0a 0f9cc1 }
		$sequence_3 = { a801 0f8505000000 e9???????? 488b8da0380000 448b859c380000 }
		$sequence_4 = { b8a51c0a0c f6c201 0f45c8 488b85c84a0000 8908 8b15???????? }
		$sequence_5 = { 4889e1 48898d90560000 e8???????? 4829c4 }
		$sequence_6 = { e9???????? 488b85384d0000 8b00 8985544d0000 e9???????? 488b85404d0000 8a00 }
		$sequence_7 = { 448b855c570000 4889c4 b9bc3715ff b88819ea06 }

	condition:
		7 of them and filesize < 12033024
}

rule MALPEDIA_Win_Taurus_Stealer_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "b1a1c877-dafe-5bd8-aa9e-f033e2a7d793"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.taurus_stealer"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.taurus_stealer_auto.yar#L1-L132"
		license_url = "N/A"
		logic_hash = "45f5adaf95071a60a27cbbf5888b0c101a82ad499a857b2070bb83a96bceb96f"
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
		$sequence_0 = { 0f9445d1 e8???????? 668945d2 8d4d94 8b45c4 8db778020000 3b45c8 }
		$sequence_1 = { 8d45d0 50 8d45f4 50 e8???????? 50 8d45b8 }
		$sequence_2 = { 8bce e8???????? 8bd0 c745f829674844 b129 c745fc4c130900 33c0 }
		$sequence_3 = { 50 8d85c0feffff 50 8d4dcb e8???????? 8b85c4feffff 8d8d40ffffff }
		$sequence_4 = { 33c0 304c05ed 40 83f806 7305 8a4dec }
		$sequence_5 = { e8???????? 8bd0 c744242f74271706 6a07 58 88442436 b174 }
		$sequence_6 = { f7c300200000 7414 81e3ffdfffff 8d8d04ffffff 895df8 e8???????? }
		$sequence_7 = { 57 ffd0 8bf8 897d0c 83ffff 746f 8b9530ffffff }
		$sequence_8 = { c1fa06 8bc7 83e03f 6bc838 8b049578c14300 f644082801 7421 }
		$sequence_9 = { c74654c3280308 c7465881120d0e c7465ce58b8009 c74660d5208b07 c74664359ac202 c74668f19ad809 c7466ca13ba208 }

	condition:
		7 of them and filesize < 524288
}

rule MALPEDIA_Win_Spyeye_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "b5e5088a-e300-5034-889b-970db77fc21d"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.spyeye"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.spyeye_auto.yar#L1-L119"
		license_url = "N/A"
		logic_hash = "eb40febb6f1c9817c33c9124c37ea30f926a02c0c70087f7a1361d98282ccb0d"
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
		$sequence_0 = { 740e 837dfcff 7408 ff75fc }
		$sequence_1 = { 8b65fc c9 c20800 55 8bec }
		$sequence_2 = { 56 6880000000 6a04 56 6a07 6800000040 57 }
		$sequence_3 = { ff7508 ffd0 8b65fc c9 c21400 55 8bec }
		$sequence_4 = { ff750c e8???????? 8bd8 83fbff 751b 57 }
		$sequence_5 = { 837dfcff 7408 ff75fc e8???????? 3bdf }
		$sequence_6 = { 740a 83e0fe 50 57 }
		$sequence_7 = { 6a02 eb08 56 6880000000 6a04 }
		$sequence_8 = { 6a03 57 6a01 56 ff750c e8???????? }
		$sequence_9 = { 50 e8???????? 85c0 7454 57 56 }

	condition:
		7 of them and filesize < 741376
}

rule MALPEDIA_Win_Spygrace_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "3c99942d-74fe-50f1-a9c2-d735c42e0b85"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.spygrace"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.spygrace_auto.yar#L1-L133"
		license_url = "N/A"
		logic_hash = "4d1aafea2b2d6148a5221a777c3a4ed202ce4fd229ea04549615dae7ae9b5684"
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
		$sequence_0 = { 85c0 742a 488bc5 4c8d05d90c0300 488bcd 48c1f906 83e03f }
		$sequence_1 = { 488bc3 48397b18 7203 488b03 48894c2430 4889442428 48c744242013000000 }
		$sequence_2 = { bb01000000 4533e4 448d4b5b 6644394c48fe 7440 483bca 731c }
		$sequence_3 = { 488d4db0 48837dc808 480f434db0 ffd2 85c0 0f85b0010000 4d8d86a0020000 }
		$sequence_4 = { 490f42c0 488d4dd0 48837de808 480f434dd0 4c2bc0 4c8945e0 4e8d044502000000 }
		$sequence_5 = { 488d4d1f e8???????? 90 488b4b10 48b8ffffffffffffff7f 482bc1 4883f807 }
		$sequence_6 = { 4c8b4110 488bf1 4d85c0 b901000000 490f45c8 488be9 }
		$sequence_7 = { e8???????? e9???????? 49638dd0330000 e8???????? 4889442448 498bce be10000000 }
		$sequence_8 = { 488d05bbc60200 4889442460 488d05c7c60200 4889442468 488d05cbc60200 4889442470 488d05cfc60200 }
		$sequence_9 = { 498bc8 e8???????? 4883a31004000000 488bcb 48c783180400000f000000 c6830004000000 4883c420 }

	condition:
		7 of them and filesize < 865280
}

rule MALPEDIA_Win_Eddiestealer_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "e232a61b-2f1e-5ab2-a023-babaefc44f11"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.eddiestealer"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.eddiestealer_auto.yar#L1-L134"
		license_url = "N/A"
		logic_hash = "755d9f27c3527a6497613857d1940285eade46fbad0b63ce47e48a5daf512e5a"
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
		$sequence_0 = { 4c3ba42498000000 0f84da010000 498d7c2410 49897f40 488b842488000000 4c8b28 488b842490000000 }
		$sequence_1 = { b808000000 488d0d6faf0500 48894d00 48895d08 48894510 0f117518 488dbc24500c0000 }
		$sequence_2 = { 4d39d3 4c89d1 490f47cb 4584ff 490f45cb 4c0f45d7 4c8b5c2440 }
		$sequence_3 = { 8b542430 e8???????? 0fb66802 440fb738 4181f7aafa0000 4080f544 b903000000 }
		$sequence_4 = { e8???????? 660fefc0 488365f000 660f7f45d0 660f7f45e0 31c9 488d1578820600 }
		$sequence_5 = { 7720 4c8b0411 4c330408 4c89440c30 4883c108 ebe7 488bb42400010000 }
		$sequence_6 = { e8???????? 668932 4889842488000000 4889942490000000 48c784249800000002000000 c68424a000000005 0f108424b0020000 }
		$sequence_7 = { e8???????? e8???????? 488b4808 48898c2448010000 488b4010 4889842438010000 488d055e330300 }
		$sequence_8 = { c1e80c 31d0 89c2 c1ea10 31c2 69c2fad30000 0fb7c0 }
		$sequence_9 = { 31d2 488d0d72810400 49b8001927cf2367fead 41f6c101 741c 440fb60c0a 4d09c1 }

	condition:
		7 of them and filesize < 1316864
}

rule MALPEDIA_Win_Poscardstealer_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "53d91898-d02d-53b9-9813-59bf55e7c619"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.poscardstealer"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.poscardstealer_auto.yar#L1-L125"
		license_url = "N/A"
		logic_hash = "8ad471a582e54a99878737b3b5b570978ce78744521ef98846f72f0bfe800fbd"
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
		$sequence_0 = { 8b5610 8955e4 8b4614 8945e8 897e10 897e14 837dcc10 }
		$sequence_1 = { 6aff 6a00 50 8bce c645fc02 e8???????? 837de810 }
		$sequence_2 = { e8???????? 83c404 397de8 0f82f6000000 }
		$sequence_3 = { 51 e8???????? 83c420 50 8d8d74ffffff }
		$sequence_4 = { 8901 c9 c3 3b0d???????? 7502 }
		$sequence_5 = { 8bbd90edffff 40 898570edffff 3bc7 0f8ceffbffff 8b0d???????? }
		$sequence_6 = { 7305 83c8ff eb08 33c0 83fe01 0f95c0 3bc7 }
		$sequence_7 = { 8d45f4 64a300000000 8b35???????? c745fc00000000 8975ac 3b35???????? }
		$sequence_8 = { c645fc01 e8???????? 6aff 40 50 8d559c 52 }
		$sequence_9 = { c645fc0e e8???????? c645fc05 397de8 720c 8b4dd4 51 }

	condition:
		7 of them and filesize < 362496
}

rule MALPEDIA_Win_Acr_Stealer_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "547d8bdd-72e9-53c8-a71c-7409f9635ddc"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.acr_stealer"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.acr_stealer_auto.yar#L1-L131"
		license_url = "N/A"
		logic_hash = "c2e01cdbfe17e3a90e2e6ed950f1a1b39c17c8ce5a68e48be7cf324c1277f6cb"
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
		$sequence_0 = { 8b7008 8bce 6a00 ff15???????? 8bcf ffd6 5f }
		$sequence_1 = { 6a0b 68???????? eb07 6a04 68???????? 8b3f 8b07 }
		$sequence_2 = { 72fa 53 ff30 8b45f8 ff37 8b7030 }
		$sequence_3 = { e8???????? 8bf2 33c9 c1ee0f 33f0 33ca }
		$sequence_4 = { 8955f4 ff7407f8 e8???????? 8bfe 8955f0 83c410 }
		$sequence_5 = { ff7034 ff15???????? ffd6 83c410 85c0 0f8490000000 8b4ddc }
		$sequence_6 = { 894e44 83f908 73da 8b95b4feffff 3bd7 0f821affffff 8b4dfc }
		$sequence_7 = { 397df4 7508 3bc1 0f8411ffffff 85c9 7403 49 }
		$sequence_8 = { 8955f4 85c0 7406 c70000000000 85db 0f8420010000 33c0 }
		$sequence_9 = { 85db 7469 83fb03 7329 66019e12860000 0f1f440000 8bc7 }

	condition:
		7 of them and filesize < 1246208
}

rule MALPEDIA_Win_Isr_Stealer_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "f92134ff-d8ee-58cb-8cb8-468d7205306f"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.isr_stealer"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.isr_stealer_auto.yar#L1-L120"
		license_url = "N/A"
		logic_hash = "75691989209029cb7a637cf5df87a857ef3ef18b6fe3194f56cba1ecab86658c"
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
		$sequence_0 = { fb b05e 2bc1 e8???????? 661e }
		$sequence_1 = { 08ac22c115978d 0e e8???????? 07 }
		$sequence_2 = { 1c8b 53 2456 2bd1 807e6543 }
		$sequence_3 = { 46 1e 301b 15c2c8c807 d6 12d8 }
		$sequence_4 = { 8d16 b205 07 d32cb6 08ac22c115978d 0e e8???????? }
		$sequence_5 = { a7 8d16 b205 07 d32cb6 08ac22c115978d }
		$sequence_6 = { 07 fb b05e 2bc1 e8???????? }
		$sequence_7 = { 8d16 b205 07 d32cb6 08ac22c115978d 0e }
		$sequence_8 = { 07 d32cb6 08ac22c115978d 0e e8???????? }
		$sequence_9 = { e8???????? 07 fb b05e 2bc1 e8???????? 661e }

	condition:
		7 of them and filesize < 540672
}

rule MALPEDIA_Win_Aurastealer_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "8c36a500-8774-5585-be5e-1badb5bb0481"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.aurastealer"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.aurastealer_auto.yar#L1-L147"
		license_url = "N/A"
		logic_hash = "8480b12b568e7fb011f2e56db2dfa5eb1d5aeacb4a24d1ba1c2deb0c82ba7d5d"
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
		$sequence_0 = { 09f8 894648 83c110 894e44 8b7e30 }
		$sequence_1 = { 09f9 85d2 0f49c8 89f5 }
		$sequence_2 = { 09fb 895e48 83c110 894e44 }
		$sequence_3 = { 09fb 8b0c24 0fb68c0e32900000 01d1 }
		$sequence_4 = { 0a1c24 751f 8b7920 8b3f }
		$sequence_5 = { 0a442404 89ee 7456 8b6c2410 }
		$sequence_6 = { 09fa d1ea 89f7 83e601 }
		$sequence_7 = { 0a4c2410 751c 6840df0400 6a01 }
		$sequence_8 = { 01442428 8bf1 13d9 33d2 }
		$sequence_9 = { 01442420 13d1 c1eb0b 0fa4c115 }
		$sequence_10 = { 012c18 42 3bd7 72dc }
		$sequence_11 = { 014c241c 13f0 33d2 89742420 }
		$sequence_12 = { 014c2420 8be8 13f0 33ff }
		$sequence_13 = { 0144241c 8b7c2424 136c2414 33c0 }
		$sequence_14 = { 0128 42 3bd7 72db }
		$sequence_15 = { 0002 8a0c0f 83c40c 020e }

	condition:
		7 of them and filesize < 1918976
}

rule MALPEDIA_Win_Spybot_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "f487b739-5a23-52d3-8b27-57437fc4fe82"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.spybot"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.spybot_auto.yar#L1-L132"
		license_url = "N/A"
		logic_hash = "086db381edc017239cf316ebb3a9419f50149c95f9ac3a29e8ecb7d10b4a280d"
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
		$sequence_0 = { 8975f8 8975f0 68???????? ff750c ff7508 e8???????? 83c418 }
		$sequence_1 = { 6a03 8b5c2414 99 59 33ff f7f9 8bf2 }
		$sequence_2 = { 59 e9???????? 57 68???????? e8???????? 59 85c0 }
		$sequence_3 = { 33f6 ff7508 56 ff15???????? 85c0 7429 }
		$sequence_4 = { 33f6 ffb56cffffff 57 e8???????? 59 85c0 59 }
		$sequence_5 = { 8945f0 8945f4 8945f8 8945fc a1???????? 85c0 7411 }
		$sequence_6 = { 8bb43570ffffff 3bf3 897508 0f8469a4ffff 399d54ffffff 0f855da4ffff 68???????? }
		$sequence_7 = { ff7020 8d85fcfdffff 68???????? 50 e8???????? 6a01 }
		$sequence_8 = { ff7514 8975fc e8???????? 56 8945ec ff7510 897514 }
		$sequence_9 = { e9???????? ffb570ffffff 68???????? e8???????? 59 85c0 59 }

	condition:
		7 of them and filesize < 2367488
}

rule MALPEDIA_Win_Agfspy_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "4e342af2-55f5-5fdc-91a0-c4e1164ec1ad"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.agfspy"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.agfspy_auto.yar#L1-L134"
		license_url = "N/A"
		logic_hash = "2c968cb953938166f8c4bb13e44158b837061eedd931abcb024c0888547d30a4"
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
		$sequence_0 = { 8901 8b0b 85c9 7405 8b01 ff5010 8933 }
		$sequence_1 = { 8bc6 8b4d0c 890e 8b4d10 5f 894e04 5e }
		$sequence_2 = { c744c81000000000 8d2cc8 8b4c241c c7451400000000 0f1001 0f114500 f30f7e4110 }
		$sequence_3 = { 8bc8 6a01 ff12 8d4d98 e8???????? 0f57c0 c745e800000000 }
		$sequence_4 = { b801000000 eb40 83ec08 c6462401 50 e8???????? 8945d0 }
		$sequence_5 = { 5e 5b 8be5 5d c20400 8b470c 33f6 }
		$sequence_6 = { 3c0a 7409 6a0a 8bce e8???????? 837f3c10 8d4728 }
		$sequence_7 = { b001 c6460401 e9???????? 8b01 ff5018 83f8ff 7405 }
		$sequence_8 = { e8???????? 0fb7ff eb16 0fb77c2410 8d4c2414 e8???????? 0fb7ff }
		$sequence_9 = { 8bcf e8???????? 8bc8 e8???????? 8bc8 e8???????? 83ec18 }

	condition:
		7 of them and filesize < 1482752
}

rule MALPEDIA_Win_Kiwistealer_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "7bc76ddb-b6a4-53dd-88a7-f41bc1cc2494"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.kiwistealer"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.kiwistealer_auto.yar#L1-L133"
		license_url = "N/A"
		logic_hash = "27341d3fac694e410d992d38e84f32a2cf2b6688bb4c9bbb3f17b7cb4866a5bf"
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
		$sequence_0 = { 4585c9 7462 4183e901 740f 4183f901 0f85d6000000 }
		$sequence_1 = { 4885c0 740e 488d7027 4883e6e0 488946f8 eb14 ff15???????? }
		$sequence_2 = { 488b05???????? 4885c9 480f45c1 483b05???????? 747e 4c8bc6 488d542470 }
		$sequence_3 = { 0f118424b0020000 0f104810 0f118c24c0020000 4c896010 48c740180f000000 c60000 4c8d8c2458030000 }
		$sequence_4 = { e9???????? 4983c5c0 4c896c2428 493bdc 0f85bc000000 4983ee40 4c89742420 }
		$sequence_5 = { e8???????? 43c6042e00 4533f6 488d45d8 48837df010 480f4345d8 4c89742438 }
		$sequence_6 = { 488b05???????? 488905???????? 488d0d3d110200 e8???????? 8bc8 486bc10b 83f803 }
		$sequence_7 = { 0f118590000000 418d4c2440 e8???????? 488bd8 4889442428 33d2 488bc8 }
		$sequence_8 = { 41c70005000000 49894008 498bc0 41c6400401 c3 8bca 81e9d4040000 }
		$sequence_9 = { 4883ec70 488bf9 4533f6 44897098 488d2db0920000 488968a0 0f57c0 }

	condition:
		7 of them and filesize < 403456
}

rule MALPEDIA_Win_Whiskerspy_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "129d540e-8d5c-5460-9975-895a38c68929"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.whiskerspy"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.whiskerspy_auto.yar#L1-L147"
		license_url = "N/A"
		logic_hash = "f82e28f98658c3c783c2c1731be6b16001447d83e33b49e0aaa68c9ddf787261"
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
		$sequence_0 = { 8b06 8bcf d3e8 a801 }
		$sequence_1 = { 33d2 488d4c2460 41b804010000 e8???????? 33d2 }
		$sequence_2 = { 418b37 488bfd 488b8c2420010000 4883c510 }
		$sequence_3 = { 44896ddc 498bd4 498bcd e8???????? 4c8be0 }
		$sequence_4 = { 4803ca 418bc3 4c3bc1 458b4210 8b0d???????? }
		$sequence_5 = { 48d3cf 4933f8 4b87bcfee0740200 33c0 488b5c2450 }
		$sequence_6 = { e8???????? c6043700 488d55e0 498bce e8???????? }
		$sequence_7 = { 4157 488dac24c8fcffff 4881ec38040000 488bda }
		$sequence_8 = { 8d45d4 837de808 8b4db0 0f4345d4 8b16 }
		$sequence_9 = { c685f9fbffff1e c685fafbffff8b 59 c685fbfbffff86 }
		$sequence_10 = { c685e4feffff7b 889de5feffff 8a85b8feffff 8a840db8feffff }
		$sequence_11 = { 6a06 59 f3a5 8b75e8 8b7dd8 }
		$sequence_12 = { 0fbec1 83e820 83e07f 8b0cc5d43b4300 eb02 }
		$sequence_13 = { 7430 8b5304 8d47f8 8d7308 }
		$sequence_14 = { 33c0 f68594f9ffff02 899d9cf8ffff 89b5a0f8ffff }

	condition:
		7 of them and filesize < 591872
}

rule MALPEDIA_Win_Strelastealer_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "8e21e6c9-b196-5772-9b5f-024320f3473e"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.strelastealer"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.strelastealer_auto.yar#L1-L230"
		license_url = "N/A"
		logic_hash = "fdd1b910b27b0b34d135da8196d66e4e45cba2823b849a416c07e1720765f896"
		score = 75
		quality = 73
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
		$sequence_0 = { 488d0575910000 41b91b000000 4889442420 e8???????? 4883c438 }
		$sequence_1 = { ff15???????? 85c0 0f854effffff 488bcb ff15???????? 4881c4d8050000 }
		$sequence_2 = { 50 e8???????? 8b44242c 83c40c 53 53 }
		$sequence_3 = { 08c1 20ca 80f101 89c8 }
		$sequence_4 = { a1???????? 668b08 56 8d5306 55 }
		$sequence_5 = { 488bc2 488d0d05c50000 0f57c0 48890b }
		$sequence_6 = { 015304 eb55 4d85c0 7e27 488bd7 4c8b4dc7 4b8b8ccbc0120600 }
		$sequence_7 = { 53 53 6804010000 8d94247c030000 52 }
		$sequence_8 = { 488d05bd430100 488945e0 895128 488d0d87a30000 }
		$sequence_9 = { 56 53 57 ff15???????? 8bf0 8b442418 8930 }
		$sequence_10 = { 08c1 08da 80f201 89c8 }
		$sequence_11 = { 08c1 0f1f440000 b810000000 e8???????? }
		$sequence_12 = { b913000000 4c8d05d3800000 e8???????? 4885c0 7417 49ba7032d8542306ddea }
		$sequence_13 = { 488d05afff0000 483bd8 74d1 488bcb }
		$sequence_14 = { 8945e4 3d00010000 7d10 8a8c181d010000 888810b80010 40 }
		$sequence_15 = { 03c7 751f 488b85a0010000 488b8888000000 488d0505540100 }
		$sequence_16 = { 50 6819000200 53 8d8c246c010000 51 6801000080 }
		$sequence_17 = { 488d4c2430 ff15???????? 488d3d2a5e0100 488bcf ff15???????? }
		$sequence_18 = { 0fb6c0 eb12 8b45e0 8a8014b90010 08443b1d 0fb64601 47 }
		$sequence_19 = { 01c7 897d14 8d1401 81c200040000 }
		$sequence_20 = { 01c1 b8dc8856d3 29c8 b9dd8856d3 }
		$sequence_21 = { 33c9 4c8d054be10000 488d154ce10000 e8???????? 4885c0 740f 488bcb }
		$sequence_22 = { 305106 33d2 f7f6 0fb68220a30010 304107 }
		$sequence_23 = { 08c1 08d3 89ca 80e201 }

	condition:
		7 of them and filesize < 872448
}

rule MALPEDIA_Win_Fickerstealer_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "c52c8234-c18e-5ab8-95a7-2cfcdb04553b"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.fickerstealer"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.fickerstealer_auto.yar#L1-L134"
		license_url = "N/A"
		logic_hash = "1997b49e36624536afa96468393213120f734d09be7f5a4952b0a008982c9c1f"
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
		$sequence_0 = { 46 4f ebe7 b001 eb02 31c0 83c404 }
		$sequence_1 = { ff74240c ff74240c ff74240c 52 51 53 50 }
		$sequence_2 = { eb44 88df 80c7d0 80ff0a 7241 8b7df0 3a1f }
		$sequence_3 = { c3 8b8424081d0000 f20f108424001d0000 8b7d0c 89442438 f20f11442430 31c0 }
		$sequence_4 = { 8d55f0 8902 894a04 6683620800 89f1 e8???????? 83c40c }
		$sequence_5 = { f20f114808 f20f1100 8d4dd4 6a02 58 50 e8???????? }
		$sequence_6 = { f20f114610 f20f114e08 f20f1116 56 e8???????? 59 83c418 }
		$sequence_7 = { 21f2 8d75d4 8b760c 09da bb08080808 21de 09fe }
		$sequence_8 = { 8d55e4 21c3 8d8518ffffff f20f1000 f20f104808 8d45e4 09fb }
		$sequence_9 = { e8???????? 83c40c 8b542410 6689442422 89f9 6a04 58 }

	condition:
		7 of them and filesize < 598016
}

rule MALPEDIA_Win_Kgh_Spy_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "dc190002-e772-5121-92cd-702f57df5a52"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.kgh_spy"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.kgh_spy_auto.yar#L1-L128"
		license_url = "N/A"
		logic_hash = "e5faa391b98537b62aa0655593e441fa8bf7b12383d96ea8cca680986ba0c716"
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
		$sequence_0 = { ff15???????? 488b8c24a0000000 ff15???????? 0fb605???????? 88842480010000 488d842481010000 488bf8 }
		$sequence_1 = { 488d0dd0fd0000 e8???????? c744244000000000 c744244800000000 488d442460 488d0def150100 488bf8 }
		$sequence_2 = { ff15???????? 4889442468 48837c246800 7507 32c0 e9???????? 48c744243800000000 }
		$sequence_3 = { 448d4202 e8???????? 8bcb e8???????? 85c0 0f84bc020000 488d0517bf0000 }
		$sequence_4 = { 75eb 488b442430 488b8c2490000000 4803c8 488bc1 }
		$sequence_5 = { e8???????? 488905???????? 48833d????????00 7504 32c0 eb26 ba855d05a6 }
		$sequence_6 = { 488d8424f0030000 488bf8 33c0 b908020000 f3aa 4c8d0df7e30000 }
		$sequence_7 = { 89442428 488d8424300e0000 4889442420 448bc9 4c8d8424300a0000 }
		$sequence_8 = { 488b442428 8b4c2430 894808 4863442424 4889442440 488b7c2430 33c0 }
		$sequence_9 = { ff15???????? 0fb605???????? 888424a0030000 488d8424a1030000 488bf8 33c0 }

	condition:
		7 of them and filesize < 207872
}

rule MALPEDIA_Win_Terra_Stealer_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "234ed187-f851-554b-a630-3727e334e709"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.terra_stealer"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.terra_stealer_auto.yar#L1-L134"
		license_url = "N/A"
		logic_hash = "ba7828bda62d9e0272e6a0dfd1c69067ed7e871d009d7d515799e6dd5814f419"
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
		$sequence_0 = { 85c0 0f8523030000 488b0f 4885c9 7405 e8???????? 4180fc05 }
		$sequence_1 = { e8???????? 488983f0120000 4885c0 7456 41b80f000000 488d15302f0900 488bcb }
		$sequence_2 = { eb04 4c8b7d28 4533c9 4533c0 488d1525861d00 488d4c2478 ff15???????? }
		$sequence_3 = { ffca 84c0 7425 8bc8 410fb600 420fb6843840061f00 4238843940061f00 }
		$sequence_4 = { 0f8c6effffff 4533c9 418b5708 498bc1 8b7e08 85d2 498bcc }
		$sequence_5 = { ffc0 84c9 75e9 4863c8 4881f9f4010000 0f8339070000 488d8550010000 }
		$sequence_6 = { eb24 498b4e10 4885c9 7415 0f1f00 8b4164 2403 }
		$sequence_7 = { eb07 896b2c c6430144 488bc3 488b5c2478 4883c430 415d }
		$sequence_8 = { e9???????? 488d8ae80f0000 e9???????? 488d8a00100000 e9???????? 488d8a18100000 e9???????? }
		$sequence_9 = { e9???????? 488b5308 488d05d334f3ff 48ff42f8 4c8b4318 488b3b 4981f8ffffff7f }

	condition:
		7 of them and filesize < 4621312
}

rule MALPEDIA_Win_Deltastealer_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "4fccefcb-7a2e-57a6-ab41-b89b24454179"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.deltastealer"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.deltastealer_auto.yar#L1-L133"
		license_url = "N/A"
		logic_hash = "8e1fc56421c67233761e9d4924d596056974746fe89cb951900a859521620234"
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
		$sequence_0 = { eb5d 31ff eb18 48314618 4889f1 e8???????? 488b4638 }
		$sequence_1 = { 4d89d7 40b601 83ff01 0f8583000000 4181fcff000000 0f873c050000 4885db }
		$sequence_2 = { e8???????? 8a5860 4889f9 e8???????? 448a7060 4889f9 e8???????? }
		$sequence_3 = { c3 4d89c8 e8???????? 0f0b 4157 4156 4155 }
		$sequence_4 = { e8???????? 4889f9 89ea e8???????? 41c60707 4883c438 5b }
		$sequence_5 = { 498b4e28 498b5630 41c60709 41c7471802000000 e8???????? 90 4883c438 }
		$sequence_6 = { eb18 488b4e40 4883c118 e8???????? e8???????? 488906 895608 }
		$sequence_7 = { e8???????? 0f0b ba08000000 4889f0 4883c420 5b 5f }
		$sequence_8 = { e8???????? 4829fe 4c89f1 4889f2 4883c428 5b 5f }
		$sequence_9 = { 8b90cc000000 895108 83a0c400000000 e8???????? c70701000000 894704 }

	condition:
		7 of them and filesize < 3532800
}

rule MALPEDIA_Win_Kpot_Stealer_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "2d1c2c52-a27f-577a-ba10-9c57d7ba8b38"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.kpot_stealer"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.kpot_stealer_auto.yar#L1-L115"
		license_url = "N/A"
		logic_hash = "c16845199544fc6722c4e2fc31a24b6089435ba431e0486f2fdbb3a3dff70b56"
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
		$sequence_0 = { 0bce 0fb67007 0fb64006 c1e608 }
		$sequence_1 = { 8b4608 8b0e ff3481 ff15???????? 8b4608 8b4e04 }
		$sequence_2 = { d1e8 8bc8 81e100000007 8bd8 }
		$sequence_3 = { 8a02 3c2d 7506 33ff 47 42 eb07 }
		$sequence_4 = { 59 8d4df8 51 ff75f8 }
		$sequence_5 = { 57 8bf8 8b4518 0fb67005 }
		$sequence_6 = { 0bd1 8bcf c1e11b d1ef }
		$sequence_7 = { 8bd6 e8???????? c6043700 8bc7 5f }
		$sequence_8 = { 8a07 84c0 7417 8a0c3a 47 3ac8 74f2 }
		$sequence_9 = { 53 56 57 8bf8 8b4518 0fb67005 }

	condition:
		7 of them and filesize < 219136
}

rule MALPEDIA_Win_Ryuk_Stealer_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "5ce42c56-7196-5dab-bbf5-f82410a1858c"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ryuk_stealer"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.ryuk_stealer_auto.yar#L1-L110"
		license_url = "N/A"
		logic_hash = "577b17a6c0c9d94113328d94349dd787eb11b2a9bf82279881b6744cc074e6ff"
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
		$sequence_0 = { 8bcb e8???????? 3bc7 7552 }
		$sequence_1 = { 05???????? 50 8d85b4fdffff 50 e8???????? }
		$sequence_2 = { 8bcb 0f44f2 42 8d7902 }
		$sequence_3 = { 83f801 7410 83ff01 755d }
		$sequence_4 = { 8a443706 3c2f 7404 3c2d }
		$sequence_5 = { b9a0860100 f7f9 81c2f8240100 52 ff15???????? }
		$sequence_6 = { 668945ec 8945ee 668945f2 8d45e0 50 }
		$sequence_7 = { 81c2f8240100 52 ff15???????? 46 }
		$sequence_8 = { e8???????? 99 b9a0860100 f7f9 81c2f8240100 52 ff15???????? }
		$sequence_9 = { 75f4 a1???????? 8907 eb38 }

	condition:
		7 of them and filesize < 368640
}

rule TRELLIX_ARC_STEALER_Lokibot : STEALER FILE
{
	meta:
		description = "Rule to detect Lokibot stealer"
		author = "Marc Rivero | McAfee ATR Team"
		id = "75f502a3-2d9f-5ccf-93f8-2d6a73e9e1b7"
		date = "2020-09-23"
		modified = "2020-09-25"
		reference = "https://github.com/advanced-threat-research/Yara-Rules/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/stealer/STEALER_Lokibot.yar#L1-L39"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/LICENSE"
		logic_hash = "999a69394a545f726cf15e4361e0dfc17eeac6544e6816a0ad140316e9642510"
		score = 75
		quality = 70
		tags = "STEALER, FILE"
		rule_version = "v1"
		malware_type = "stealer"
		malware_family = "Ransomware:W32/Lokibot"
		actor_type = "Cybercrime"
		actor_group = "Unknown"
		hash1 = "0e40f4fdd77e1f90279c585cfc787942b8474e5216ff4d324d952ef6b74f25d2"
		hash2 = "3ad36afad12d8cf245904285c21a8db43f9ed9c82304fdc2f27c4dd1438e4a1d"
		hash3 = "26fbdd516b3c1bfa36784ef35d6bc216baeb0ef2d0c0ba036ff9296da2ce2c84"

	strings:
		$sq1 = { 55 8B EC 56 8B 75 08 57 56 E8 ?? ?? ?? ?? 8B F8 59 85 FF 75 04 33 C0 EB 20 56 6A 00 57 E8 ?? ?? ?? ?? 6A 0C E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 E5 83 60 08 00 89 38 89 70 04 5F 5E 5D C3 }
		$sq2 = { 55 8B EC 83 EC 0C 53 56 57 33 DB BE ?? ?? ?? ?? 53 53 56 6A 09 E8 ?? ?? ?? ?? 6A 10 6A 01 53 53 8D 4D F8 51 FF D0 53 53 56 6A 09 E8 ?? ?? ?? ?? 6A 08 6A 01 53 53 8D 4D F8 51 FF D0 85 C0 0F 84 2B 01 00 00 6A 24 E8 ?? ?? ?? ?? 59 8B D8 33 C0 6A 09 59 8B FB F3 AB 66 8B 4D 24 B8 03 66 00 00 C7 03 08 02 00 00 66 85 C9 74 03 0F B7 C1 8B 4D 08 33 D2 0F B7 C0 89 43 04 89 53 08 85 C9 74 12 C7 43 08 08 00 00 00 8B 01 89 43 0C 8B 41 04 89 43 10 8B 4D 0C 85 C9 74 0F 83 43 08 08 8B 01 89 43 14 8B 41 04 89 43 18 8B 4D 10 85 C9 74 0F 83 43 08 08 8B 01 89 43 1C 8B 41 04 89 43 20 8B 7B 08 8B 75 F8 83 C7 0C 52 52 68 ?? ?? ?? ?? 6A 09 E8 ?? ?? ?? ?? 8D 4D FC 51 6A 00 6A 00 57 53 56 FF D0 85 C0 74 75 8B 75 FC 33 C0 40 83 7D 20 00 0F 45 45 20 33 FF 57 57 68 ?? ?? ?? ?? 6A 09 89 45 F4 E8 ?? ?? ?? ?? 57 8D 4D F4 51 6A 04 56 FF D0 85 C0 74 3B 39 7D 14 74 1A 8B 75 FC 57 57 68 ?? ?? ?? ?? 6A 09 E8 ?? ?? ?? ?? 57 FF 75 14 6A 01 56 FF D0 8B 55 18 8B 4D FC 53 89 0A 8B 55 1C 8B 4D F8 89 0A E8 ?? ?? ?? ?? 33 C0 59 40 EB 21 FF 75 FC E8 BF FB FF FF 59 EB 02 33 FF 53 E8 ?? ?? ?? ?? 57 FF 75 F8 E8 6B FB FF FF 83 C4 0C 33 C0 5F 5E 5B 8B E5 5D C3 }
		$sq3 = { 55 8B EC 83 EC 0C 53 8B 5D 0C 56 57 6A 10 33 F6 89 75 F8 89 75 FC 58 89 45 F4 85 DB 75 0E FF 75 08 E8 ?? ?? ?? ?? 8B D8 8B 45 F4 59 50 E8 ?? ?? ?? ?? 8B F8 59 85 FF 0F 84 B6 00 00 00 FF 75 F4 56 57 E8 C4 ?? ?? ?? 83 C4 0C 56 56 68 ?? ?? ?? ?? 6A 09 E8 ?? ?? ?? ?? 68 00 00 00 F0 6A 01 56 56 8D 4D F8 51 FF D0 85 C0 0F 84 84 00 00 00 8B 75 F8 6A 00 6A 00 68 ?? ?? ?? ?? 6A 09 E8 ?? ?? ?? ?? 8D 4D FC 51 6A 00 6A 00 68 03 80 00 00 56 FF D0 85 C0 74 51 6A 00 53 FF 75 08 FF 75 FC E8 7F FD FF FF 83 C4 10 85 C0 74 3C 8B 75 FC 6A 00 6A 00 68 ?? ?? ?? ?? 6A 09 E8 ?? ?? ?? ?? 6A 00 8D 4D F4 51 57 6A 02 56 FF D0 85 C0 74 19 FF 75 FC E8 16 FD FF FF 6A 00 FF 75 F8 E8 26 FD FF FF 83 C4 0C 8B C7 EB 0E 6A 00 FF 75 F8 E8 15 FD FF FF 59 59 33 C0 5F 5E 5B 8B E5 5D C3 }
		$sq4 = { 55 8B EC 83 7D 10 00 56 57 8B 7D 0C 57 74 0E E8 ?? ?? ?? ?? 8B F0 33 C0 03 F6 40 EB 09 E8 ?? ?? ?? ?? 8B F0 33 C0 83 7D 14 00 59 75 24 50 FF 75 08 E8 2C 00 00 00 59 59 83 F8 01 74 04 33 C0 EB 1D 56 FF 75 08 E8 C5 FE FF FF 59 59 83 F8 01 75 EC 56 57 FF 75 08 E8 CA FE FF FF 83 C4 0C 5F 5E 5D C3 }
		$sq5 = { 55 8B EC 53 56 8B 75 0C 57 85 F6 75 0B FF 75 08 E8 ?? ?? ?? ?? 59 8B F0 6B C6 03 89 45 0C 8D 58 01 53 E8 ?? ?? ?? ?? 8B F8 59 85 FF 74 42 53 6A 00 57 E8 ?? ?? ?? ?? 83 C4 0C 33 D2 85 F6 74 27 8B 45 08 0F B6 0C 02 8B C1 83 E1 0F C1 E8 04 8A 80 ?? ?? ?? ?? 88 04 57 8A 81 ?? ?? ?? ?? 88 44 57 01 42 3B D6 72 D9 8B 45 0C C6 04 07 00 8B C7 5F 5E 5B 5D C3 }
		$sq6 = { 55 8B EC 53 56 57 FF 75 08 E8 ?? ?? ?? ?? 33 C9 6A 02 5B 8D B8 A0 1F 00 00 8B C7 F7 E3 0F 90 C1 F7 D9 0B C8 51 E8 ?? ?? ?? ?? 8B F0 59 59 85 F6 74 6F 8D 0C 3F 51 6A 00 56 E8 ?? ?? ?? ?? 8D 45 0C 50 FF 75 08 56 E8 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 8B F8 83 C4 1C 85 FF 74 40 33 C9 8D 47 02 F7 E3 0F 90 C1 F7 D9 0B C8 51 E8 ?? ?? ?? ?? 8B D8 59 85 DB 74 25 8D 0C 7D 02 00 00 00 51 6A 00 53 E8 ?? ?? ?? ?? 57 56 53 E8 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 83 C4 1C 8B C3 EB 09 56 E8 ?? ?? ?? ?? 59 33 C0 5F 5E 5B 5D C3 }
		$sq7 = { 55 8B EC 81 EC 80 00 00 00 56 57 E8 ?? ?? ?? ?? 6A 1F 59 BE ?? ?? ?? ?? 8D 7D 80 F3 A5 33 C9 6A 02 5A 66 A5 8B 7D 08 8D 47 01 F7 E2 0F 90 C1 F7 D9 0B C8 51 E8 ?? ?? ?? ?? 8B F0 59 85 F6 74 4D 8D 04 7D 02 00 00 00 4F 89 45 08 53 50 6A 00 56 E8 ?? ?? ?? ?? 83 C4 0C 33 DB 85 FF 74 1C E8 ?? ?? ?? ?? 33 D2 6A 7E 59 F7 F1 D1 EA 66 8B 44 55 80 66 89 04 5E 43 3B DF 72 E4 56 E8 ?? ?? ?? ?? 3B F8 8B 45 08 59 77 C4 8B C6 5B EB 02 33 C0 5F 5E 8B E5 5D C3 }
		$sq8 = { 55 8B EC 81 EC 50 02 00 00 53 56 57 6A 0A E8 ?? ?? ?? ?? 59 33 DB 6A 2E 5E 39 5D 14 0F 84 13 01 00 00 FF 75 08 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F0 59 59 85 F6 0F 84 F7 00 00 00 53 53 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 8D 8D B0 FD FF FF 51 56 FF D0 8B D8 83 FB FF 0F 84 CC 00 00 00 F6 85 B0 FD FF FF 10 0F 84 97 00 00 00 83 7D 1C 00 74 2E 8D 85 DC FD FF FF 68 ?? ?? ?? ?? 50 E8 0A ?? ?? ?? 59 59 85 C0 75 7A 8D 85 DC FD FF FF 68 ?? ?? ?? ?? 50 E8 F3 ?? ?? ?? 59 59 85 C0 75 63 8D 85 DC FD FF FF 50 E8 ?? ?? ?? ?? 59 83 F8 03 73 0C 6A 2E 58 66 39 85 DC FD FF FF 74 45 8D 85 DC FD FF FF 50 FF 75 08 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 0C 89 45 14 85 C0 74 27 6A 01 6A 00 6A 01 FF 75 10 FF 75 0C 50 E8 14 FF FF FF FF 75 14 8B F8 E8 ?? ?? ?? ?? 83 C4 1C 85 FF 0F 85 EE 00 00 00 33 C0 50 50 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8D 8D B0 FD FF FF 51 53 FF D0 85 C0 0F 85 3B FF FF FF 53 E8 ?? ?? ?? ?? 59 56 E8 ?? ?? ?? ?? 59 33 DB 6A 2E 5E FF 75 0C FF 75 08 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F8 83 C4 0C 85 FF 0F 84 CF 00 00 00 53 53 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 8D 8D B0 FD FF FF 51 57 FF D0 8B D8 83 FB FF 0F 84 A6 00 00 00 8D 85 DC FD FF FF 50 E8 ?? ?? ?? ?? 59 83 F8 03 73 09 66 39 B5 DC FD FF FF 74 3E 83 BD B0 FD FF FF 10 75 06 83 7D 18 00 74 2F 8D 85 DC FD FF FF 50 FF 75 08 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F0 83 C4 0C 85 F6 74 12 83 7D 10 00 74 40 56 FF 55 10 56 E8 ?? ?? ?? ?? 59 59 33 C0 50 50 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8D 8D B0 FD FF FF 51 53 FF D0 85 C0 74 29 6A 2E 5E EB 85 56 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 59 59 8B C7 EB 22 57 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 59 59 8B C6 EB 10 53 E8 ?? ?? ?? ?? 59 57 E8 ?? ?? ?? ?? 59 33 C0 5F 5E 5B 8B E5 5D C3 }
		$sq9 = { 83 3D 14 ?? ?? ?? ?? 56 74 0A 8B 35 20 ?? ?? ?? 85 F6 75 66 53 57 BB E0 01 00 00 33 FF 53 89 3D 14 ?? ?? ?? E8 F0 F8 FF FF 33 F6 A3 14 ?? ?? ?? 46 59 85 C0 74 12 6A 78 57 50 89 35 20 ?? ?? ?? E8 A6 F8 FF FF 83 C4 0C 53 89 3D 18 ?? ?? ?? E8 C5 F8 FF FF A3 18 ?? ?? ?? 59 85 C0 74 14 6A 78 57 50 89 35 20 ?? ?? ?? E8 7E F8 FF FF 83 C4 0C EB 06 8B 35 20 ?? ?? ?? 5F 5B 8B C6 5E C3 }
		$sq10 = { 55 8B EC 51 51 83 65 FC 00 53 56 57 64 A1 30 00 00 00 89 45 FC 8B 45 FC 8B 40 0C 8B 58 0C 8B F3 8B 46 18 FF 76 28 89 45 F8 E8 CE FA FF FF 8B F8 59 85 FF 74 1F 6A 00 57 E8 32 01 00 00 57 E8 ?? ?? ?? ?? 03 C0 50 57 E8 71 FA FF FF 83 C4 14 39 45 08 74 11 8B 36 3B DE 75 C6 33 C0 5F 5E 5B 8B E5 5D C2 04 00 8B 45 F8 EB F2 }
		$sq11 = { A1 ?? ?? ?? ?? 85 C0 74 07 50 E8 ?? ?? ?? ?? 59 A1 ?? ?? ?? ?? 85 C0 74 07 50 E8 ?? ?? ?? ?? 59 A1 ?? ?? ?? ?? 85 C0 74 07 50 E8 ?? ?? ?? ?? 59 33 C0 A3 ?? ?? ?? ?? A3 ?? ?? ?? ?? A3 ?? ?? ?? ?? C3 }
		$sq12 = { 55 8B EC 56 8B 75 0C 57 85 F6 74 48 56 E8 ?? ?? ?? ?? 59 85 C0 74 3D 56 E8 ?? ?? ?? ?? 59 85 C0 74 32 83 65 0C 00 8D 45 0C 6A 01 50 56 E8 ?? ?? ?? ?? 8B F8 83 C4 0C 85 FF 74 19 8B 45 0C 85 C0 74 12 83 7D 14 00 74 12 39 45 14 73 0D 57 E8 ?? ?? ?? ?? 59 33 C0 5F 5E 5D C3 83 7D 10 00 74 1A 6A 00 6A 01 56 E8 ?? ?? ?? ?? 59 50 FF 75 08 E8 1F 00 00 00 8B 45 0C 83 C4 10 50 57 FF 75 08 E8 FF FE FF FF 57 8B F0 E8 ?? ?? ?? ?? 83 C4 10 8B C6 EB C3 }
		$sq13 = { 55 8B EC 83 EC 18 56 FF 75 08 E8 ?? ?? ?? ?? 50 89 45 F0 E8 ?? ?? ?? ?? 8B F0 59 59 85 F6 0F 84 C0 00 00 00 53 8B 5D 0C 33 C9 57 6A 04 5A 8B C3 F7 E2 0F 90 C1 F7 D9 0B C8 51 E8 ?? ?? ?? ?? 83 65 F4 00 8B F8 83 65 FC 00 59 85 DB 74 6D 8B 45 10 83 C0 FC FF 75 F0 83 C0 04 89 45 E8 6A 00 56 8B 00 89 45 EC E8 ?? ?? ?? ?? FF 75 F0 FF 75 08 56 E8 ?? ?? ?? ?? 83 65 F8 00 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 83 C4 20 EB 1F FF 75 EC 50 E8 ?? ?? ?? ?? 59 59 85 C0 75 32 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? FF 45 F8 59 59 85 C0 75 DD 8B 45 FC 40 89 45 FC 3B C3 8B 45 E8 72 99 56 E8 ?? ?? ?? ?? 59 39 5D F4 75 12 8B C7 EB 17 8B 45 FC 8B 4D F8 FF 45 F4 89 0C 87 EB D7 57 E8 ?? ?? ?? ?? 59 33 C0 5F 5B 5E 8B E5 5D C3 }
		$sq14 = { 55 8B EC 8B 45 0C 53 56 8B 75 08 57 8B 4E 04 03 C1 8D 3C 09 3B F8 77 06 8D B8 F4 01 00 00 33 C9 8B C7 6A 04 5A F7 E2 0F 90 C1 F7 D9 0B C8 51 E8 ?? ?? ?? ?? 8B D8 59 85 DB 74 26 57 6A 00 53 E8 ?? ?? ?? ?? FF 76 08 FF 36 53 E8 ?? ?? ?? ?? FF 36 E8 ?? ?? ?? ?? 33 C0 89 1E 83 C4 1C 89 7E 04 40 5F 5E 5B 5D C3 }
		$sq15 = { 55 8B EC 83 7D 0C 00 57 74 39 8B 7D 10 85 FF 74 32 56 8B 75 08 8B 46 08 03 C7 3B 46 04 76 09 57 56 E8 3F FF FF FF 59 59 8B 46 08 03 06 57 FF 75 0C 50 E8 ?? ?? ?? ?? 01 7E 08 83 C4 0C 33 C0 40 5E EB 02 33 C0 5F 5D C3 }

	condition:
		uint16( 0 ) == 0x5a4d and any of them
}

rule TRELLIX_ARC_Nionspy : FILEINFECTOR FILE
{
	meta:
		description = "Triggers on old and new variants of W32/NionSpy file infector"
		author = "Trellix ARC Team"
		id = "86051ef8-a18b-553c-b06c-490f8d6df5cf"
		date = "2026-05-01"
		modified = "2020-08-14"
		reference = "https://blogs.mcafee.com/mcafee-labs/taking-a-close-look-at-data-stealing-nionspy-file-infector"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/malware/MALW_NionSpy.yar#L1-L25"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/LICENSE"
		logic_hash = "982ba52f39352aee9e2d2dcadfb0816c439e92d0e5947afa7860630720913742"
		score = 75
		quality = 70
		tags = "FILEINFECTOR, FILE"
		malware_type = "fileinfector"
		malware_family = "FileInfector:W32/NionSpy"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$variant2015_infmarker = "aCfG92KXpcSo4Y94BnUrFmnNk27EhW6CqP5EnT"
		$variant2013_infmarker = "ad6af8bd5835d19cc7fdc4c62fdf02a1"
		$variant2013_string = "%s?cstorage=shell&comp=%s"

	condition:
		uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 and 1 of ( $variant* )
}

rule ARKBIRD_SOLG_MAL_Zstealer_Nov_2021_1 : FILE
{
	meta:
		description = "Detect ZStealer stealer used by Void Balaur group"
		author = "Arkbird_SOLG"
		id = "0282884b-569a-5e46-a6ad-d2776ff71ddb"
		date = "2021-11-11"
		modified = "2021-11-12"
		reference = "https://documents.trendmicro.com/assets/white_papers/wp-void-balaur-tracking-a-cybermercenarys-activities.pdf"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-11-11/Void_Balaur/MAL_ZStealer_Nov_2021_1.yara#L1-L19"
		license_url = "N/A"
		logic_hash = "c3bec4fb8338ad71577e63f81c22b5d250083f2475f60610de8dccd4979035d3"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "af89d85a3b579ac754850bd6e52e7516c2e63141107001463486cd01bc175052"
		hash2 = "5a2c9060f6cc1e6e0fd09b2b194631d2c7e7f024d9e2d3a9be64570e263f565f"
		tlp = "white"
		adversary = "Void Balaur"

	strings:
		$s1 = { 53 33 c0 55 68 71 d3 46 00 64 ff 30 64 89 20 a1 80 7f 7b 00 8b 10 ff 52 44 a1 84 7f 7b 00 8b 10 ff 52 44 8d 45 fc 50 68 80 d3 46 00 68 02 00 00 80 e8 e3 a3 f9 ff 85 c0 0f 85 94 01 00 00 8d 45 f8 ba 00 10 00 00 e8 86 83 f9 ff c7 45 f0 00 10 00 00 33 db e9 49 01 00 00 8d 45 f4 50 6a 00 8d 45 f8 e8 36 82 f9 ff 8d 55 e8 e8 e6 cd f9 ff 8b 4d e8 8d 45 ec ba bc d3 46 00 e8 12 80 f9 ff 8b 55 ec b9 fc d3 46 00 b8 02 00 00 80 e8 d4 d8 ff ff 84 c0 0f 84 01 01 00 00 8d 55 e4 8b 45 f4 e8 c5 c0 f9 ff 8b 55 e4 8d 45 f4 e8 6e 7d f9 ff 8b 55 f4 b8 14 d4 46 00 e8 cd 82 f9 ff 85 c0 7e 32 8d 45 e0 50 8b 55 f4 b8 14 d4 46 00 e8 b8 82 f9 ff 8b c8 83 c1 03 ba 01 00 00 00 8b 45 f4 e8 c2 81 f9 ff 8b 55 e0 a1 80 7f 7b 00 8b 08 ff 51 38 eb 0d 8b 55 f4 a1 80 7f 7b 00 8b 08 ff 51 38 8d 45 f4 50 6a 00 8d 45 f8 e8 90 81 f9 ff 8d 55 d8 e8 40 cd f9 ff 8b 4d d8 8d 45 dc ba bc d3 46 00 e8 6c 7f f9 ff 8b 55 dc b9 24 d4 46 00 b8 02 00 00 80 e8 2e d8 ff ff 84 c0 74 42 8d 45 f8 }
		$s2 = { 8b d9 88 55 fb 89 45 fc 33 c0 55 68 b3 2e 46 00 64 ff 30 64 89 20 33 d2 8b 45 fc e8 a0 11 fa ff b2 01 a1 2c 74 41 00 e8 94 11 fa ff 8b 55 fc 89 42 0c 8b 45 fc c6 40 08 00 33 c0 89 45 f4 33 d2 55 68 96 2e 46 00 64 ff 32 64 89 22 8d 45 f0 89 5d ec 8b 55 ec e8 9e 21 fa ff 8b 45 fc 83 c0 04 50 8b 45 f0 e8 b7 25 fa ff 50 e8 2d f5 ff ff 83 c4 08 85 c0 74 66 8b 45 fc 8b 40 04 85 c0 74 39 50 e8 26 f5 ff ff 59 89 45 f4 89 5d dc c6 45 e0 0b 8b 45 f4 89 45 e4 c6 45 e8 06 8d 45 dc 50 6a 01 b9 e4 2e 46 00 b2 01 a1 58 2c 46 00 e8 be a1 fa ff e8 9d 19 fa ff eb 23 89 5d d4 c6 45 d8 0b 8d 45 d4 50 6a 00 b9 10 2f 46 00 b2 01 a1 58 2c 46 00 e8 99 a1 fa ff e8 78 19 fa ff 33 c0 5a 59 59 64 89 10 68 9d 2e 46 00 83 7d f4 00 74 0a 8b 45 f4 50 e8 c4 f4 ff ff }
		$s3 = { 68 1d c7 45 00 64 ff 30 64 89 20 8b c3 e8 d8 89 fa ff 8d 45 fc ba 00 01 00 00 e8 17 90 fa ff c7 45 f8 ff 00 00 00 8d 45 f8 50 8d 45 fc e8 d0 8e fa ff 50 e8 f6 af fa ff c7 45 f4 ff 00 00 00 c7 45 f0 ff 00 00 00 8d 45 ec 50 8d 45 f0 50 8d 85 ec fd ff ff 50 8d 45 f4 50 8d 85 ec fe ff ff 50 8d 45 fc e8 9a 8e fa ff 50 6a 00 e8 d6 af fa ff 85 c0 0f 84 6d 01 00 00 8d 85 ec fe ff ff 50 e8 ba af fa ff 85 c0 0f 84 59 01 00 00 8d 85 ec fe ff ff 50 e8 7e af fa ff 8b f0 8d 85 ec fe ff ff 50 e8 80 af fa ff 0f b6 38 8b c3 ba 34 c7 45 00 e8 89 89 fa ff 80 3e 00 75 }
		$s4 = { a1 9c c2 49 00 8b 00 e8 e3 82 01 00 8b 93 88 01 00 00 8b 08 ff 51 54 8b f8 85 ff 7c 15 a1 9c c2 49 00 8b 00 e8 c6 82 01 00 8b d7 8b 08 ff 51 18 8b f0 6a 01 56 e8 e1 f2 fc ff 8b c3 e8 be 17 00 00 8a 93 84 01 00 00 e8 2f 61 00 00 33 c0 5a 59 59 }
		$s5 = { 45 72 72 6f 72 20 5b 25 64 5d 3a 20 25 73 2e 0d 22 25 73 22 3a 20 25 73 00 00 ff ff ff ff 0a 00 00 00 4e 6f 20 6d 65 73 73 61 67 65 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize > 300KB and all of them
}

rule ARKBIRD_SOLG_MAL_Phoenix_Stealer_Jun_2021_1 : FILE
{
	meta:
		description = "Detect the Phoenix Stealer"
		author = "Arkbird_SOLG"
		id = "8c9df216-cbfe-51f3-a6d7-cfeb99fafbe0"
		date = "2021-11-01"
		modified = "2021-11-01"
		reference = "https://twitter.com/3xp0rtblog/status/1455111070566207493/"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-11-01/Phoenix_Stealer/MAL_Phoenix_Stealer_Jun_2021_1.yara#L1-L20"
		license_url = "N/A"
		logic_hash = "989c2518a42201559265ce4b974b35df5c4b8365e53f789fc124ee969e747c87"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "5bbfeee67b9b087ed228eccdacd4a7e71d40f7f96ad869903e02d9c3b02adbe5"
		hash2 = "34f78f4028c51f6340c1f4846b65252fa6686ba0a5ab8ebc35c737a8960ba43e"
		hash3 = "e51de8c43034fafaa49f81e9cc955c0cf60dc9684f28d8c355baf0724710de1f"
		tlp = "White"
		adversary = "-"

	strings:
		$s1 = { 6a 16 58 0f be c8 88 85 b0 fe ff ff c7 85 d8 fe ff ff 42 73 7a 73 c7 85 dc fe ff ff 71 64 77 7b c7 85 e0 fe ff ff 38 73 6e 73 c6 85 e4 fe ff ff 00 e8 aa 73 ff ff 89 85 94 }
		$s2 = "UPDATE sqlite_temp_master SET sql = sqlite_rename_trigger(sql, %Q), tbl_name = %Q WHERE %s" ascii
		$s3 = { b8 c9 11 47 00 e8 c3 c5 01 00 68 f8 d7 47 00 33 db 53 53 ff 15 cc 20 47 00 53 50 89 85 d0 fc ff ff ff 15 d0 20 47 00 85 c0 0f 85 92 02 00 00 6a 01 ff 15 8c 22 47 00 84 c0 79 f4 53 e8 e2 aa 00 00 50 e8 1e 98 00 00 8b 35 84 22 47 00 8d 85 ec fe ff ff 59 59 50 53 53 6a 1c 53 ff d6 8d 8d ec fe ff ff 8d 51 01 8a 01 41 84 c0 75 f9 2b ca 8d 85 ec fe ff ff 51 50 b9 f0 5b 48 00 e8 bf 0e 00 00 8d 85 e8 fd ff ff 50 68 04 01 00 00 ff 15 40 20 47 00 8d 8d e8 fd ff ff 8d 51 01 8a 01 41 84 c0 75 f9 2b ca 8d 85 e8 fd ff ff 51 50 b9 08 5c 48 00 e8 89 0e 00 00 8d 85 e4 fc ff ff 50 53 53 6a 1a 53 ff d6 8d 8d e4 fc ff ff 8d 51 01 8a 01 41 84 c0 75 f9 2b ca 8d 85 e4 fc ff ff 51 50 b9 90 5b 48 00 e8 57 0e 00 00 8b fb 89 9d dc fc ff ff 8b f3 89 bd d4 fc ff ff 89 b5 d8 fc ff ff 83 65 fc 00 33 c9 6a 16 5a 41 e8 71 05 ff ff 8b cf 89 85 e0 fc }
		$s4 = { 6a 01 ff 15 98 22 47 00 85 c0 74 5d 6a 00 ff 15 a0 22 47 00 85 c0 74 51 56 6a 01 ff 15 94 22 47 00 8b f0 85 f6 74 3b 56 ff 15 38 21 47 00 8b d0 85 d2 74 27 8b ca 57 8d 79 01 8a 01 41 84 c0 75 f9 2b cf 6a 03 51 8b 0d 6c 72 48 00 52 ba 58 d7 47 00 e8 95 1b fe ff 83 c4 0c 5f 56 ff 15 64 21 47 00 }
		$s5 = { 81 ec 14 02 00 00 a1 0c 50 48 00 33 c5 89 45 fc 53 56 8b d9 be 19 27 00 00 57 8b 7d 0c 83 fb ff 75 0c e8 bb eb ff ff 89 37 89 47 04 eb 17 ff 75 08 52 53 ff 15 bc 22 47 00 85 c0 8b cf 0f 95 c2 e8 b8 fe ff ff e8 98 eb ff ff 8b 4f 04 8b 49 04 3b 48 04 75 08 81 3f 34 27 00 00 74 20 e8 80 eb ff ff 8b 4f 04 8b 49 04 3b 48 04 0f 85 b9 00 00 00 81 3f 33 27 00 00 0f 85 ad 00 00 00 83 fb ff 75 0c e8 5b eb ff ff 89 37 e9 99 00 00 00 33 c0 89 9d f8 fd ff ff 40 89 9d fc fe ff ff 89 85 f4 fd ff ff 89 85 f8 fe ff ff 8d 85 f8 fe ff ff 6a 00 50 8d 85 f4 fd ff ff 50 6a 00 8d 43 01 50 ff 15 d8 22 47 00 8b f0 8b cf 85 f6 0f 98 c2 e8 2a fe ff ff 85 f6 78 53 83 a5 f0 fd ff ff 00 8d 85 ec fd ff ff 50 8d 85 f0 fd ff ff c7 85 ec fd ff ff 04 00 00 00 50 68 07 10 00 00 68 ff ff 00 00 53 ff 15 b0 22 47 00 8b f0 8b cf 85 f6 0f 95 c2 e8 e8 fd ff }

	condition:
		uint16( 0 ) == 0x5a4d and filesize > 80KB and 4 of ( $s* )
}

rule ARKBIRD_SOLG_MAL_Cadelspy_Stealer_May_2021_1 : FILE
{
	meta:
		description = "Detect Cadelspy stealer"
		author = "Arkbird_SOLG"
		id = "bac23ed9-f51c-546e-8f4e-320d33b51829"
		date = "2021-05-30"
		modified = "2021-06-05"
		reference = "Internal Research"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-05-30/APT39/MAL_Cadelspy_Stealer_May_2021_1.yara#L1-L24"
		license_url = "N/A"
		logic_hash = "29fade3703c55bd16e67f9bf126cb0d8a06bc0eafe10e145f8d57d8c4abe5656"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "8847a73bbd9477be60685ce8ec8333db933892f4d7b729fcef01ac76600de9ff"
		hash2 = "f3b0ad96c8529399bd7117bd67cdf0297191476d3a81a60b147960306ae5f068"
		hash3 = "88c947d0d0fddd1ea87f5b85982cf231c9c56e4f5e25fac405f608a1c28d8391"
		tlp = "White"
		adversary = "APT39"

	strings:
		$str1 = "C:\\Windows\\SysEvent.exe" fullword wide
		$str2 = "\\sysprep\\sysprep.exe" fullword wide
		$str3 = "Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}" fullword wide
		$str4 = "@C:\\Windows\\systemw.dll" fullword wide
		$str5 = "systemw.dll" fullword ascii
		$str6 = "ApAshell32.dll" fullword wide
		$seq1 = { 55 8b ec 83 ec 14 a1 04 00 41 00 33 c5 89 45 fc 8d 45 f8 c7 45 f0 00 00 00 00 50 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 68 20 02 00 00 6a 20 6a 02 8d 45 f0 66 c7 45 f4 00 05 50 ff 15 08 30 40 00 85 c0 74 25 8d 45 ec 50 ff 75 f8 6a 00 ff 15 04 30 40 00 ff 75 f8 f7 d8 1b c0 21 45 ec ff 15 00 30 40 00 83 7d ec 00 75 05 e8 52 fd ff ff 56 68 2d 02 00 00 ff 15 30 30 40 00 68 1c 33 40 00 ff 15 20 30 40 00 6a 00 6a 00 6a 01 6a 00 6a 00 6a 02 68 1c 33 40 00 89 45 f8 ff 15 1c 30 40 00 6a 00 8b f0 8d 45 f8 50 68 00 ba 00 00 68 68 33 40 00 56 ff 15 6c 30 40 00 56 ff 15 74 30 40 00 6a 01 6a 00 6a 00 68 1c 33 40 00 68 4c 33 40 00 6a 00 ff 15 b0 30 40 00 8b 4d fc 33 c0 33 cd 5e e8 06 00 00 00 }
		$seq2 = { 8b 0d 10 32 40 00 0f 10 05 24 32 40 00 89 08 8b 0d 14 32 40 00 89 48 04 8b 0d 18 32 40 00 89 48 08 8b 0d 1c 32 40 00 89 48 0c 66 8b 0d 20 32 40 00 66 89 48 10 33 c9 a1 3c 32 40 00 0f 11 84 24 34 04 00 00 89 84 24 4c 04 00 00 f3 0f 7e 05 34 32 40 00 66 0f d6 84 24 44 04 00 00 0f 1f 40 00 0f b7 84 0c c8 0f 00 00 8d 49 02 66 89 84 0c 42 08 00 00 66 85 c0 75 e8 8d bc 24 44 08 00 00 83 c7 fe 66 8b 47 02 83 c7 02 66 85 c0 75 f4 b9 0a 00 00 00 be 40 32 40 00 f3 a5 b9 21 00 00 00 0f 10 05 58 33 40 00 66 a5 8d bc 24 54 0c 00 00 be 70 32 40 00 f3 a5 66 a5 0f 11 84 24 5c 0e 00 00 0f 10 05 78 ed 40 00 0f 11 84 24 6c 0e 00 00 0f 10 05 68 ed 40 00 0f 11 84 24 7c 0e 00 00 38 45 08 75 1f 8d 44 24 10 50 e8 23 fa ff ff 5f 5e 5b 8b 8c 24 c8 11 00 00 33 cc e8 1c 04 00 00 8b }
		$seq3 = { 8b 84 b5 e4 d9 ff ff 85 c0 74 66 50 6a 00 68 ff ff 1f 00 ff 15 28 30 40 00 8b f8 85 ff 74 52 8d 85 dc d9 ff ff 50 6a 04 8d 85 d0 d9 ff ff 50 57 ff 15 64 30 40 00 85 c0 74 32 68 04 01 00 00 8d 85 ec fb ff ff 50 ff b5 d0 d9 ff ff 57 ff 15 34 30 40 00 8d 85 ec fb ff ff 68 f8 32 40 00 50 ff 15 38 31 40 00 83 c4 08 85 c0 74 21 57 ff d3 33 ff 8b 85 e0 d9 ff ff 46 c1 e8 02 8b cf 3b f0 0f 82 7b ff ff ff 85 c9 0f 84 43 01 00 00 68 04 01 00 00 8d 85 e4 f9 ff ff 50 6a 00 ff 15 3c 30 40 00 85 c0 0f 84 24 01 00 00 8d 85 f4 fd ff ff 50 68 04 01 00 00 ff 15 14 30 40 00 8d 85 f4 fd ff ff 50 6a 00 68 14 33 40 00 50 ff 15 60 30 40 00 6a 00 8d 85 f4 fd ff ff 50 8d 85 e4 f9 ff ff 50 ff 15 58 30 40 00 85 c0 0f 84 df 00 00 00 6a 00 6a 00 6a 03 6a 00 6a 00 68 00 00 00 c0 8d 85 f4 fd ff ff 50 ff 15 1c 30 40 00 8b f0 83 fe ff 0f 84 b8 00 00 00 6a 00 8d 85 d8 d9 ff ff 50 68 00 10 00 00 8d 85 e4 e9 ff ff 50 56 ff 15 78 30 40 00 85 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize > 30KB and 5 of ( $str* ) and 2 of ( $seq* )
}

rule ARKBIRD_SOLG_Mal_Stealer_NET_Redline_Aug_2020_1 : FILE
{
	meta:
		description = "Detect Redline Stealer (August 2020)"
		author = "Arkbird_SOLG"
		id = "6fda87c3-0d00-5c00-a1ff-6d96dd726ddf"
		date = "2020-08-24"
		modified = "2020-08-24"
		reference = "https://twitter.com/JAMESWT_MHT/status/1297878628450152448"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2020-08-24/Redline/Mal_Stealer_NET_Redline_Aug_2020_1.yar#L1-L31"
		license_url = "N/A"
		logic_hash = "950641dfaf17f332e6a18961aebb2533732d82ce69f3617efa08cc63272f1786"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "4195430d95ac1ede9bc986728fc4211a1e000a9ba05a3e968dd302c36ab0aca0"

	strings:
		$s1 = { 53 00 45 00 4c 00 45 00 43 00 54 00 20 00 2a 00 20 00 46 00 52 00 4f 00 4d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 57 00 68 00 65 00 72 00 65 00 20 00 53 00 65 00 73 00 73 00 69 00 6f 00 6e 00 49 00 64 00 3d 00 27 00 7b 00 30 00 7d }
		$s2 = { 28 00 28 00 28 00 28 00 5b 00 30 00 2d 00 39 00 2e 00 5d 00 29 00 5c 00 64 00 29 00 2b 00 29 00 7b 00 31 00 7d 00 29 }
		$s3 = { 7b 00 30 00 7d 00 5c 00 46 00 69 00 6c 00 65 00 5a 00 69 00 6c 00 6c 00 61 00 5c 00 72 00 65 00 63 00 65 00 6e 00 74 00 73 00 65 00 72 00 76 00 65 00 72 00 73 00 2e 00 78 00 6d 00 6c }
		$s4 = { 7b 00 30 00 7d 00 5c 00 46 00 69 00 6c 00 65 00 5a 00 69 00 6c 00 6c 00 61 00 5c 00 73 00 69 00 74 00 65 00 6d 00 61 00 6e 00 61 00 67 00 65 00 72 00 2e 00 78 00 6d 00 6c }
		$s5 = { 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 61 00 72 00 74 00 69 00 6e 00 20 00 50 00 72 00 69 00 6b 00 72 00 79 00 6c 00 5c 00 57 00 69 00 6e 00 53 00 43 00 50 00 20 00 32 00 5c 00 53 00 65 00 73 00 73 00 69 00 6f 00 6e 00 73 }
		$s6 = "<encrypted_key>k__BackingField" fullword ascii
		$s7 = "set_encrypted_key" fullword ascii
		$s8 = "UserAgentDetector" fullword ascii
		$s9 = "set_encrypted_key" fullword ascii
		$s10 = "set_FtpConnections" fullword ascii
		$s11 = "set_IsProcessElevated" fullword ascii
		$s12 = "SELECT ExecutablePath, ProcessID FROM Win32_Process" fullword wide
		$s13 = "<IsProcessElevated>k__BackingField" fullword ascii
		$s14 = "System.Collections.Generic.IEnumerable<RedLine.Logic.Json.JsonValue>.GetEnumerator" fullword ascii
		$s15 = "System.Collections.Generic.IEnumerator<RedLine.Logic.Json.JsonValue>.get_Current" fullword ascii
		$s16 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\browser.exe" fullword wide
		$s17 = "ProcessExecutablePath" fullword ascii
		$s18 = "IsProcessElevated" fullword ascii
		$s19 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\firefox.exe" fullword wide
		$s20 = "get_encryptedPassword" fullword ascii

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 90KB and 15 of them
}


rule ARKBIRD_SOLG_MAL_Luna_Stealer_Apr_2021_1 : FILE
{
	meta:
		description = "Detect Luna stealer (also Mercurial Grabber)"
		author = "Arkbird_SOLG"
		id = "2fecce99-5869-5de0-afae-6dc245748fa6"
		date = "2021-08-29"
		modified = "2021-08-30"
		reference = "https://github.com/NightfallGT/Mercurial-Grabber"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-08-29/Luna/MAL_Luna_Stealer_Apr_2021_1.yara#L1-L22"
		license_url = "N/A"
		logic_hash = "934ded815c262fa8bee38638e17ed8c2b1f0dcad28037bf1d525e11bf7e34dce"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "a14918133b9b818fa2e8728faa075c4f173fa69abc424f39621d6aa1405f5a18"
		hash2 = "93563f68975a858ff07f7eb91f4e0c997f0212d58b1755704d89fecd442d448f"
		hash3 = "0521bb85472869598d9aa822b11edc04044dbe876dbf9900565bfdc8e02c2b21"
		hash4 = "ce35eb5ba2f3f36b3d2742b33d3dbbe95f5ec6b93942ba20be4693528b163e3a"
		tlp = "White"
		adversary = "-"

	strings:
		$s1 = { 73 ?? 00 00 0a 0b 07 72 [2] 00 70 02 7b ?? 00 00 04 28 ?? 00 00 0a 6f ?? 00 00 0a 0c 08 6f ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 0d 09 6f ?? 00 00 0a 0a 02 72 [2] 00 70 06 28 ?? 00 00 06 7d ?? 00 00 04 02 72 [2] 00 70 06 28 ?? 00 00 06 7d ?? 00 00 04 02 72 [2] 00 70 06 28 ?? 00 00 06 7d ?? 00 00 04 02 72 [2] 00 70 06 28 ?? 00 00 06 7d ?? 00 00 04 02 72 [2] 00 70 06 28 ?? 00 00 06 7d ?? 00 00 04 02 72 [2] 00 70 06 28 ?? 00 00 06 7d ?? 00 00 04 02 72 [2] 00 70 06 28 ?? 00 00 06 7d ?? 00 00 04 06 28 ?? 00 00 0a de 0a 07 2c 06 07 6f ?? 00 00 0a dc de 1a 13 04 72 [2] 00 70 11 04 6f ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a de 00 2a }
		$s2 = { 72 [2] 00 70 02 7b ?? 00 00 04 28 ?? 00 00 06 0a 02 72 [2] 00 70 02 7b ?? 00 00 04 28 ?? 00 00 06 7d ?? 00 00 04 72 [2] 00 70 02 7b ?? 00 00 04 28 ?? 00 00 06 0b 02 06 72 [2] 00 70 07 28 ?? 00 00 0a 7d ?? 00 00 04 72 [2] 00 70 02 7b ?? 00 00 04 28 ?? 00 00 06 0c 02 72 [2] 00 70 02 7b ?? 00 00 04 72 [2] 00 70 08 28 ?? 00 00 0a 7d ?? 00 00 04 02 72 [2] 00 70 02 7b ?? 00 00 04 28 ?? 00 00 06 7d ?? 00 00 04 02 72 [2] 00 70 02 7b ?? 00 00 04 28 ?? 00 00 06 7d ?? 00 00 04 02 72 [2] 00 70 02 7b ?? 00 00 04 28 ?? 00 00 06 7d ?? 00 00 04 02 7b ?? 00 00 04 28 ?? 00 00 0a 1f 16 63 21 00 b0 ca a2 4a 01 00 00 58 0d 09 28 ?? 00 00 0a 13 05 12 05 28 ?? 00 00 0a 13 04 02 12 04 fe 16 ?? 00 00 01 6f ?? 00 00 0a 7d ?? 00 00 04 2a }
		$s3 = { 72 [2] 00 70 73 ?? 00 00 0a 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0c 2b 75 08 6f ?? 00 00 0a 74 ?? 00 00 01 0b 07 72 [2] 00 70 6f ?? 00 00 0a 2c 16 02 07 72 [2] 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 7d ?? 00 00 04 07 72 [2] 00 70 6f ?? 00 00 0a 2c 16 02 07 72 [2] 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 7d ?? 00 00 04 07 72 ?? 19 00 70 6f ?? 00 00 0a 2c 16 02 07 72 ?? 19 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 7d ?? 00 00 04 08 6f ?? 00 00 0a 2d 83 de 0a 08 2c 06 08 6f ?? 00 00 0a dc 2a }
		$x1 = "---------------- mercurial grabber ----------------" fullword wide
		$x2 = { 5c 00 73 00 2a 00 3a 00 5c 00 73 00 2a 00 28 00 22 00 28 00 3f 00 3a 00 5c 00 5c 00 22 00 7c 00 5b 00 5e 00 22 00 5d 00 29 00 2a 00 3f }
		$x3 = { 5b 00 5c 00 77 00 2d 00 5d 00 7b 00 32 00 34 00 7d 00 5c 00 2e 00 5b 00 5c 00 77 00 2d 00 5d 00 7b 00 36 00 7d 00 5c 00 2e 00 5b 00 5c 00 77 00 2d 00 5d 00 7b 00 32 00 37 00 7d 00 01 1d 6d 00 66 00 61 00 5c 00 2e 00 5b 00 5c 00 77 00 2d 00 5d 00 7b 00 38 00 34 00 7d }

	condition:
		uint16( 0 ) == 0x5a4d and filesize > 20KB and 2 of ( $x* ) and 2 of ( $s* )
}

rule ARKBIRD_SOLG_MAL_Sidoh_Stealer_Aug_2021_1 : FILE
{
	meta:
		description = "Detect Sidoh Stealer used by RYUK group"
		author = "Arkbird_SOLG"
		id = "b4661304-6dfa-5c33-95f2-8694271b9e58"
		date = "2021-08-31"
		modified = "2021-09-01"
		reference = "https://www.crowdstrike.com/blog/sidoh-wizard-spiders-mysterious-exfiltration-tool/"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-08-31/Sidoh/MAL_Sidoh_Stealer_Aug_2021_1.yara#L1-L22"
		license_url = "N/A"
		logic_hash = "baeea14c6be42d64d3ca68298bf6ced34c9587fcda91471945cfc7ed1fe267bd"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "a1ce52437252001b56c9ccd2d2da46240dc38db8074a5ed39a396e8c8e387fc2"
		hash2 = "c64269a64b64b20108df89c4f1a415936c9d9923f8761d0667aa8492aa057acb"
		hash3 = "e6762cb7d09cd90d5469e3c3bfc3b47979cd67aa06c06e893015a87b0348c32c"
		hash4 = "cc4a0b4080844e20fb9535679f7b09a3e2449729ce1815d1e5a64272b0225465"
		tlp = "White"
		adversary = "RYUK (RAAS)"

	strings:
		$s1 = { 68 88 13 00 00 ff 15 ?? 30 41 00 ff 76 04 ff 15 ?? 30 41 00 68 10 27 00 00 53 68 ?? f6 41 00 e8 ?? ?? 00 00 83 c4 0c ff 15 ?? 30 41 00 8b f8 8b f3 8b d7 8b ce d3 ea f6 c2 01 74 34 8d 46 41 6a 3a 66 a3 ?? f6 41 00 58 66 a3 ?? f6 41 00 33 c0 68 ?? f6 41 00 66 a3 ?? f6 41 00 ff 15 ?? 30 41 00 83 f8 05 74 0a b9 ?? f6 41 00 e8 ?? ?? 00 00 46 83 fe 1a 7c bb 68 10 27 00 00 53 68 ?? f6 41 00 e8 ?? ?? 00 00 8b 3d ?? 30 41 00 8d 44 24 28 83 c4 0c 89 5c 24 1c 6a 01 50 53 ff d7 8b 35 ?? 30 41 00 6a 04 68 00 10 00 00 ff 74 24 24 53 ff d6 8b d8 8d 44 24 1c 6a 01 50 53 89 5c 24 30 ff d7 6b 0b 18 6a 04 68 00 10 00 00 51 33 c9 51 ff d6 68 00 40 00 00 6a 40 89 44 24 38 ff 15 ?? 30 41 00 33 f6 89 44 24 2c 89 74 24 }
		$s2 = { 8b ca c1 e9 02 f3 a5 8b ca 83 e1 03 f3 a4 33 f6 56 56 56 6a 01 56 ff 15 ?? 31 41 00 a3 ?? ?? 42 00 8b fe 85 c0 74 4e 56 68 00 00 00 08 6a 01 68 ?? ?? 41 00 68 ?? ec 41 00 6a 15 ff 75 f8 50 ff 15 ?? 31 41 00 8b f8 85 ff 74 42 56 6a 02 8d 85 f0 fc ff ff 50 53 57 ff 15 ?? 31 41 00 85 c0 75 0f ff 15 ?? 30 41 00 8b d8 a1 ?? ?? 42 00 eb 08 a1 ?? ?? 42 00 33 db 43 8b 35 ?? 31 41 00 50 ff d6 57 ff d6 8b c3 5f 5e 5b 8b e5 }
		$s3 = { 55 8b ec 83 ec 58 53 8b 1d ?? 30 41 00 56 57 6a 04 68 00 10 00 00 6a 02 6a 00 89 55 f0 8b f1 ff d3 8b f8 85 ff 75 08 83 c8 ff e9 0f 01 00 00 56 68 ?? ?? 41 00 57 e8 93 ff ff ff 83 65 f8 00 8d 45 f8 50 6a 00 57 ff 15 ?? 31 41 00 83 c4 18 8b f0 83 7d f8 00 89 75 f4 74 04 6a fd eb 33 83 65 ac 00 8d 45 ac 50 ff 15 ?? 31 41 00 8d 45 ac 50 6a 00 68 ?? ?? 41 00 56 ff 15 ?? 31 41 00 83 c4 14 83 7d c8 00 77 10 72 06 }
		$s4 = { 6a 04 68 00 10 00 00 ff 75 c4 6a 00 ff d3 8b d8 85 db 75 1a 68 00 80 00 00 50 57 ff 15 ?? 30 41 00 56 ff 15 ?? 31 41 00 59 6a fb 58 eb 79 6a 00 68 ?? ?? 41 00 56 ff 15 ?? 31 41 00 ff 75 c8 8b f0 ff 75 c4 53 56 ff 15 ?? 31 41 00 56 ff 15 ?? 31 41 00 ff 75 f4 ff 15 ?? 31 41 00 ff 75 08 8b 55 c4 8b cb ff 75 f0 e8 3b 02 00 00 8b f0 83 c4 2c 85 f6 75 14 83 7d 08 05 75 0e 8b 55 c4 51 8b cb e8 b3 09 00 00 59 8b f0 68 00 80 00 00 6a 00 53 ff 15 ?? 30 41 00 68 00 80 00 00 6a 00 57 ff 15 ?? 30 41 00 8b c6 5f 5e 5b 8b e5 }

	condition:
		uint16( 0 ) == 0x5A4D and filesize > 20KB and all of ( $s* )
}


rule RUSSIANPANDA_Meduzastealer_1 : FILE
{
	meta:
		description = "Detects MeduzaStealer 1-2024"
		author = "RussianPanda"
		id = "6bc4c048-a32d-5a9c-b213-980c64d08d29"
		date = "2024-01-01"
		modified = "2024-01-01"
		reference = "https://russianpanda.com/2023/06/28/Meduza-Stealer-or-The-Return-of-The-Infamous-Aurora-Stealer/"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/cd712dfbd20050a57e868656a39771b79120595c/MeduzaStealer/MeduzaStealer_1-1-2024.yar#L1-L16"
		license_url = "N/A"
		logic_hash = "0547e51abd04302c45f1319bc21046ade019bc98eb85d9cba67cb2109ff642eb"
		score = 75
		quality = 83
		tags = "FILE"

	strings:
		$s1 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 5c 57 69 6e 55 70 64 61 74 65 2e 65 78 65}
		$s2 = {0f 57 ?? ?? ?? 00 00 66 0f 7f 85 ?? ?? 00 00}
		$s3 = {48 8d 15 ?? ?? 05 00 49 8b cf}
		$s4 = {48 8d 0d ?? ?? 06 00 ff 15 ?? ?? 06 00}

	condition:
		3 of ( $s* ) and filesize < 1MB
}

rule RUSSIANPANDA_Whitesnakestealer : FILE
{
	meta:
		description = "WhiteSnake Stealer"
		author = "RussianPanda"
		id = "70b69aba-5096-59a6-bb0b-44d248aecc26"
		date = "2023-07-04"
		modified = "2023-12-11"
		reference = "https://russianpanda.com/2023/07/04/WhiteSnake-Stealer-Malware-Analysis/"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/cd712dfbd20050a57e868656a39771b79120595c/WhiteSnake-Stealer/WhiteSnake_rc4.yar#L1-L17"
		license_url = "N/A"
		logic_hash = "24985a2c3b0d72858decd17cb2b8e485caa94c01ad72a014edc68ed4facfd71e"
		score = 75
		quality = 83
		tags = "FILE"

	strings:
		$s1 = {73 68 69 74 2e 6a 70 67}
		$s2 = {FE 0C ?? 00 20 00 01 00 00 3F ?? FF FF FF 20 00 00 00 00 FE 0E ?? 00 38 ?? 00 00 00 FE 0C}
		$s3 = "qemu" wide
		$s4 = "vbox" wide

	condition:
		all of ( $s* ) and filesize < 300KB
}

rule RUSSIANPANDA_Whitesnakestealer_1 : FILE
{
	meta:
		description = "Detects WhiteSnake Stealer XOR samples "
		author = "RussianPanda"
		id = "cfe168a6-cc2f-5cfe-985c-78b232dc2651"
		date = "2023-07-04"
		modified = "2023-12-11"
		reference = "https://russianpanda.com/2023/07/04/WhiteSnake-Stealer-Malware-Analysis/"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/cd712dfbd20050a57e868656a39771b79120595c/WhiteSnake-Stealer/WhiteSnake_xor.yar#L1-L15"
		license_url = "N/A"
		logic_hash = "0bd0e250b8598be297296ecf6644d3bf649e3dc4598438325a0913afed04c819"
		score = 75
		quality = 83
		tags = "FILE"

	strings:
		$s1 = {FE 0C 00 00 FE 09 00 00 FE 0C 02 00 6F ?? 00 00 0A FE 0C 03 00 61 D1 FE 0E 04 00 FE}
		$s2 = {61 6e 61 6c 2e 6a 70 67}

	condition:
		all of ( $s* ) and filesize < 600KB
}

rule RUSSIANPANDA_Mal_Asuka_Stealer : FILE
{
	meta:
		description = "Detects AsukaStealer"
		author = "RussianPanda"
		id = "a718be5f-dc76-5610-9237-038a9719d7e5"
		date = "2024-02-02"
		modified = "2024-03-18"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/cd712dfbd20050a57e868656a39771b79120595c/AsukaStealer/mal_asuka_stealer.yar#L1-L12"
		license_url = "N/A"
		logic_hash = "7974e0de821ddcafd4f00b27d587108f0d80f8a231dd0db4d2be4fa6ab44fef4"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = {32 14 3E E8 F6 81 00 00}
		$s2 = {00 58 00 2D 00 43 00 6F 00 6E 00 66 00 69 00 67}
		$s3 = {58 00 2D 00 49 00 6E 00 66 00 6F}

	condition:
		uint16( 0 ) == 0x5A4D and all of them
}

rule RUSSIANPANDA_Win_Mal_Koistealer_PS
{
	meta:
		description = "Detects KoiStealer PowerShell script"
		author = "RussianPanda"
		id = "6dfdb39c-1b6a-5969-9c2d-e09869af6e0f"
		date = "2024-04-04"
		modified = "2024-04-04"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/cd712dfbd20050a57e868656a39771b79120595c/Koi/win_mal_KoiStealer_PS.yar#L1-L12"
		license_url = "N/A"
		hash = "4f55be0b55ec67dfda42b88e9c743a2a"
		logic_hash = "8a60a1d770eb4b5048762ddfd4657fdf7a430b09eb454ae5a5bb3103460907db"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s1 = "index.php?id=$guid&subid="
		$s2 = "$config"

	condition:
		all of ( $s* )
}

rule RUSSIANPANDA_Purelogs_Stealer_Core : FILE
{
	meta:
		description = "Detects Pure Logs Stealer Core Payload"
		author = "RussianPanda"
		id = "bda876c3-76ce-5e1e-8dd4-f06e8240fc11"
		date = "2023-12-26"
		modified = "2024-01-10"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/cd712dfbd20050a57e868656a39771b79120595c/Pure Logs Stealer/purelogs_stealer_core.yar#L3-L18"
		license_url = "N/A"
		logic_hash = "7388299ebcc70aeb86c46c29a787f790993a67148d9f3968def1109e45f69452"
		score = 75
		quality = 83
		tags = "FILE"

	strings:
		$s1 = {7E 58 00 00 0A [15] 28 20 00 00 0A 18 6F 0A 02 00 0A 0B}
		$s2 = {50 6C 67 43 6F 72 65}
		$s3 = {7E 64 01 00 0A 28 65 01 00 0A}

	condition:
		all of ( $s* ) and filesize < 5MB and pe.imports ( "mscoree.dll" )
}

rule RUSSIANPANDA_Purelogs_Stealer_Initial_Dropper : FILE
{
	meta:
		description = "Detects PureLogs Stealer Initial Payload"
		author = "RussianPanda"
		id = "c1e6a0a0-f8ed-5b78-bcae-55c1c1dfc9e4"
		date = "2024-01-10"
		modified = "2024-01-10"
		reference = "https://russianpanda.com/2023/12/26/Pure-Logs-Stealer-Malware-Analysis/"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/cd712dfbd20050a57e868656a39771b79120595c/Pure Logs Stealer/purelogs_stealer_initial_payload.yar#L1-L19"
		license_url = "N/A"
		logic_hash = "0fe94c705b94f82163f952d0a29aac4689947a1d439bdc1847ee510c25cf2e40"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = {73 ?? 00 00 06 28 ?? 00 00 ?? 2A}
		$s2 = {28 ?? 00 00 06 74 ?? 00 00 1B 28 ?? 00 00 0A 2A}
		$s3 = {28 ?? 00 00 ?? 75 ?? 00 00 01 72 ?? 00 00 70 6F ?? 00 00 0A 2A}
		$s4 = {28 ?? 00 00 ?? 75 ?? 00 00 01 72 ?? 00 00 ?? 20 00 01 00 00 14 14 14 6F ?? 00 00 ?? 26}
		$s5 = {28 ?? 00 00 ?? 73 ?? 00 00 [29] 73 15 00 00 0A [22] 28 01 00 00 2B 28 02 00 00 2B}

	condition:
		all of ( $s* ) and uint16( 0 ) == 0x5A4D and filesize < 1MB
}

rule RUSSIANPANDA_Prysmax_Stealer : FILE
{
	meta:
		description = "Detects Prysmax Stealer"
		author = "RussianPanda"
		id = "97ab92b8-1771-5881-9cd1-d8ff76b8f380"
		date = "2024-01-09"
		modified = "2024-01-10"
		reference = "https://www.cyfirma.com/outofband/new-maas-prysmax-launches-fully-undetectable-infostealer/"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/cd712dfbd20050a57e868656a39771b79120595c/Prysmax Stealer/prysmax_stealer.yar#L1-L21"
		license_url = "N/A"
		logic_hash = "869eee7dd5209bdea98c248791b9ac911e3daabe6d440aa62aecefa43539a41c"
		score = 75
		quality = 73
		tags = "FILE"

	strings:
		$a1 = {23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23}
		$s2 = {73 70 72 79 73 6D 61 78}
		$s3 = {56 43 52 55 4E 54 49 4D 45 31 34 30 2E 64 6C 6C}
		$s4 = {56 43 52 55 4E 54 49 4D 45 31 34 30 5F 31 2E 64 6C 6C}
		$s5 = {4D 53 56 43 50 31 34 30 2E 64 6C 6C}
		$s6 = {50 79 49 6E 73 74 61 6C 6C 65 72}

	condition:
		all of ( $s* ) and uint16( 0 ) == 0x5A4D and $a1 in ( 9600000 .. filesize ) and #a1 > 600 and filesize > 60MB and filesize < 200MB
}

rule RUSSIANPANDA_Aurorastealer_March_2023
{
	meta:
		description = "Detects an unobfuscated AuroraStealer March update binary"
		author = "RussianPanda"
		id = "a115de7a-bff7-5bb0-b83f-f66a29bbcf3f"
		date = "2023-03-23"
		modified = "2023-05-05"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/cd712dfbd20050a57e868656a39771b79120595c/AuroraStealer/Aurora_March_2023.yar#L1-L15"
		license_url = "N/A"
		logic_hash = "d74d2843a03e826f334ce3c5eb10cc2b43cfd832174769e5d067fb877abe13a0"
		score = 75
		quality = 85
		tags = ""

	strings:
		$b1 = { 48 8D 0D ?? ?? 05 00 E8 ?? ?? EF FF }
		$ftp = "FOUND FTP"

	condition:
		all of them
}


rule RUSSIANPANDA_AMOS_Stealer : FILE
{
	meta:
		description = "Detects AMOS Stealer"
		author = "RussianPanda"
		id = "f2abe03e-7a29-514d-9125-9ec9d0875179"
		date = "2025-03-31"
		modified = "2025-04-11"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/cd712dfbd20050a57e868656a39771b79120595c/AMOS/amos_stealer.yar#L1-L24"
		license_url = "N/A"
		hash = "55663778a8c593b77a82ea1be072c73dd6a1d7a9567bbfbfad7d3dec9f672996"
		logic_hash = "64bf0753e2696633ed255df9350a01cb1e75fd6e6c0d4fe48194927acf7e2363"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$op1 = {E8 ?? ?? ?? ?? E9 00 00 00 00 48 8D}
		$op2 = {48 3B 85 68 FF FF FF 0F 83 03 01 00 00 C6 85 5F FF FF FF 00 C7 85 58 FF FF FF 00 00 00 00}

	condition:
		( uint32( 0 ) == 0xfeedface or uint32( 0 ) == 0xcefaedfe or uint32( 0 ) == 0xfeedfacf or uint32( 0 ) == 0xcffaedfe or uint32( 0 ) == 0xcafebabe or uint32( 0 ) == 0xbebafeca or uint32( 0 ) == 0xcafebabf or uint32( 0 ) == 0xbfbafeca ) and ( #op1 > 5000 and $op2 )
}

rule RUSSIANPANDA_AMOS_Stealer_1 : FILE
{
	meta:
		description = "Detects AMOS Stealer"
		author = "RussianPanda"
		id = "481c0abc-efa6-5965-a5b8-0164229130e1"
		date = "2025-04-11"
		modified = "2025-04-11"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/cd712dfbd20050a57e868656a39771b79120595c/AMOS/amos_stealer_4_25.yar#L1-L24"
		license_url = "N/A"
		hash = "55663778a8c593b77a82ea1be072c73dd6a1d7a9567bbfbfad7d3dec9f672996"
		logic_hash = "dffaf67bdfb8db07f69fb00720a6638e7a89db2acc1d848d635031a0aec5bdd3"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$op1 = {E8 ?? ?? ?? ?? EB 00 48 8D}
		$op2 = {48 8D BD ?? ?? FF FF E8 ?? ?? 00 00 48 8D BD}

	condition:
		( uint32( 0 ) == 0xfeedface or uint32( 0 ) == 0xcefaedfe or uint32( 0 ) == 0xfeedfacf or uint32( 0 ) == 0xcffaedfe or uint32( 0 ) == 0xcafebabe or uint32( 0 ) == 0xbebafeca or uint32( 0 ) == 0xcafebabf or uint32( 0 ) == 0xbfbafeca ) and ( #op1 > 50000 and #op2 > 4 )
}

rule RUSSIANPANDA_Garystealer : FILE
{
	meta:
		description = "Detects GaryStealer 1-3-2024"
		author = "RussianPanda"
		id = "4b0af30e-2cf1-539d-89fa-7e4e32cd6eab"
		date = "2024-01-03"
		modified = "2024-01-03"
		reference = "https://cybersecurity.att.com/blogs/labs-research/behind-the-scenes-jaskagos-coordinated-strike-on-macos-and-windows"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/cd712dfbd20050a57e868656a39771b79120595c/GaryStealer/garystealer-1-3-2024.yar#L1-L20"
		license_url = "N/A"
		hash = "6efa29a0f9d112cfbb982f7d9c0ddfe395b0b0edb885c2d5409b33ad60ce1435"
		logic_hash = "f71655d0cb237c08af9c298ec9eec1ae9bd1efd50e26d61afddf9056b6883a15"
		score = 75
		quality = 79
		tags = "FILE"

	strings:
		$s1 = {72 75 6e 74 69 6d 65 2e 67 6f 70 61 6e 69 63}
		$s2 = {4c 6f 63 61 6c 20 49 50 20 41 64 64 72 65 73 73 65 73 3a 5b 70 69 63 6b 2d 66 69 72 73 74 2d 6c 62 20 25 70 5d}
		$s3 = {70 65 72 73 69 73 74 61 6E 63 65 20 63 72 65 61 74 65 64}
		$s4 = {C7 40 28 ?? 00 00 00}

	condition:
		uint16( 0 ) == 0x5A4D and 3 of ( $s* ) and filesize < 20MB and #s4 > 2
}

rule RUSSIANPANDA_Metastealer_Core_Payload
{
	meta:
		description = "Detects MetaStealer Core Payload"
		author = "RussianPanda"
		id = "ff5854b5-4dac-59d7-8c5a-d5b808d63483"
		date = "2023-12-29"
		modified = "2023-12-29"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/cd712dfbd20050a57e868656a39771b79120595c/MetaStealer/metastealer_core_payload_12-2023.yar#L2-L19"
		license_url = "N/A"
		logic_hash = "99a319023f2c1b714a70458bd33649d6cc343b500a409af12c2eb1ce38ba4241"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s1 = "FileScannerRule"
		$s2 = "TreeObject"
		$s3 = "Schema"
		$s4 = "StringDecrypt"
		$s5 = "AccountDetails"

	condition:
		4 of ( $s* ) and pe.imports ( "mscoree.dll" )
}


rule RUSSIANPANDA_Metastealer
{
	meta:
		description = "Detects the old version of MetaStealer 11-2023"
		author = "RussianPanda"
		id = "c178630b-d188-5faf-86b3-436894241d77"
		date = "2023-11-16"
		modified = "2023-12-30"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/cd712dfbd20050a57e868656a39771b79120595c/MetaStealer/metastealer.yar#L2-L19"
		license_url = "N/A"
		logic_hash = "f78b376713daf82aa2e0cbd6bf45f33d25530449fa05673c8a7c6b4c0dddca79"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s1 = "FileScannerRule"
		$s2 = "MSObject"
		$s3 = "MSValue"
		$s4 = "GetBrowsers"
		$s5 = "Biohazard"

	condition:
		4 of ( $s* ) and pe.imports ( "mscoree.dll" )
}

rule RUSSIANPANDA_Metastealer_NET_Reactor_Packer : FILE
{
	meta:
		description = "Detects NET_Reactor_packer 12-2023 used in MetaStealer"
		author = "RussianPanda"
		id = "5d4f62d2-6a27-53af-9b03-61daa99c10a4"
		date = "2023-12-29"
		modified = "2023-12-30"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/cd712dfbd20050a57e868656a39771b79120595c/MetaStealer/metastealer_12-2023_packer.yar#L1-L16"
		license_url = "N/A"
		logic_hash = "1951d8b05f11b8a77a5bf792ad2b0ad95b8dede936ab5cd0699383468c3c97a8"
		score = 75
		quality = 83
		tags = "FILE"

	strings:
		$s1 = {C7 84 24 80 02 00 00 24 02 00 00 C6 44 24}
		$s2 = "mscoree.dll" wide
		$s3 = {43 61 76 69 6c 73 20 43 6f 72 70 2e 20 32 30 31 30}
		$s4 = {80 F1 E7 80 F2 44 [16] 80 F1 4B 80 F2 23}

	condition:
		3 of ( $s* ) and filesize < 600KB
}

rule RUSSIANPANDA_Win_Mal_Planetstealer : FILE
{
	meta:
		description = "Detects PlanetStealer"
		author = "RussianPanda"
		id = "f912066f-4151-5f83-8d34-6bffdf9e25e5"
		date = "2024-03-04"
		modified = "2024-03-24"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/cd712dfbd20050a57e868656a39771b79120595c/PlanetStealer/win_mal_PlanetStealer.yar#L1-L14"
		license_url = "N/A"
		logic_hash = "e1660d6fed4c48b45b40bd51fb52254c5b19ca6f1938b68f2344bde473820b86"
		score = 75
		quality = 79
		tags = "FILE"

	strings:
		$s1 = {48 8D 15 ?? ?? ?? 00 0F B6 34 10 0F B6 BC 04 ?? ?? 00 00 ?? ?? 40 88 ?? 04 ?? ?? 00 00 48 FF C0}
		$s2 = {48 83 F8 ?? 7C DA}
		$s3 = {72 75 6E 74 69 6D 65 2E 67 6F 62 75 66}
		$s4 = {74 6F 74 61 6C 5F 77 61 6C 6C 65 74 73}
		$s5 = {74 6F 74 61 6C 5F 63 6F 6F 6B 69 65 73}

	condition:
		uint16( 0 ) == 0x5A4D and all of them and #s2 > 100 and #s1 > 100 and filesize < 20MB
}

rule RUSSIANPANDA_Win_Mal_Glorysprout_Stealer : FILE
{
	meta:
		description = "Detects GlorySprout Stealer"
		author = "RussianPanda"
		id = "44c50f20-479e-5960-9ab9-97b9a17d7cbf"
		date = "2024-03-16"
		modified = "2024-03-16"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/cd712dfbd20050a57e868656a39771b79120595c/GlorySprout/win_mal_GlorySprout_Stealer.yar#L1-L13"
		license_url = "N/A"
		hash = "8996c252fc41b7ec0ec73ce814e84136be6efef898822146c25af2330f4fd04a"
		logic_hash = "c843f7924e69c1b9fc3676178aa630319fe25605deddcd73c4905c51cc97d7eb"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = {25 0F 00 00 80 79 05 48 83 C8 F0 40}
		$s2 = {8B 82 A4 00 00 00 8B F9 89 06 8D 4E 0C 8B 82 A8 00 00 00 89 46 04 0F B7 92 AC 00 00 00 89 56 08}
		$s3 = {0F B6 06 C1 E7 04 03 F8 8B C7 25 00 00 00 F0 74 0B C1 E8 18}

	condition:
		uint16( 0 ) == 0x5A4D and all of them and #s1 > 100
}

rule RUSSIANPANDA_Raccoonstealer : FILE
{
	meta:
		description = "Detects Raccoon Stealer v2.3.1.1"
		author = "RussianPanda"
		id = "29f28cd5-370b-5831-8b71-a253f468f7e4"
		date = "2024-01-08"
		modified = "2024-01-08"
		reference = "https://www.esentire.com/blog/esentire-threat-intelligence-malware-analysis-raccoon-stealer-v2-0"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/cd712dfbd20050a57e868656a39771b79120595c/RaccoonStealer_v2/raccoonstealer_v2.3.1.1.yar#L1-L20"
		license_url = "N/A"
		hash = "c6d0d98dd43822fe12a1d785df4e391db3c92846b0473b54762fbb929de6f5cb"
		logic_hash = "ee2b39c1c2068b97e63a03330a2f9e2f12e53aaf9cfffb274acde2372a11fe45"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = {8B 0D [2] 41 00 A3 [3] 00}
		$s2 = "MachineGuid"
		$s3 = "SELECT name_on_card, card_number_encrypted, expiration_month, expiration_year FROM credit_cards"
		$s4 = "SELECT service, encrypted_token FROM token_service"
		$s5 = "&configId="
		$s6 = "machineId="

	condition:
		all of ( $s* ) and #s1 > 10 and uint16( 0 ) == 0x5A4D and filesize < 5MB
}

rule RUSSIANPANDA_PSWSTEALER : FILE
{
	meta:
		description = "PSWSTEALER"
		author = "RussianPanda"
		id = "8a596074-ffe3-5979-b384-487ebe8b953c"
		date = "2023-04-02"
		modified = "2023-05-05"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/cd712dfbd20050a57e868656a39771b79120595c/PSWSTEALER/pswstealer.yar#L1-L14"
		license_url = "N/A"
		logic_hash = "7d85b0ccaa07419f22b9f38a4bc66435cd689b21fa7e4584ef8bea485b6bd2c1"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$obf = {09 20 FF [3] 5F 06 25 17 58 0A 61 1E 62 09 1E 63 06 25 17 58 0A 61 D2 60 D1 9D}
		$obf1 = {09 06 08 59 61 D2 13 04 09 1E 63 08 61 D2 13 05 07 08 11 05 1E 62 11 04 60 D1 9D 08 17 58 0C}
		$enc = {73 ?? 00 00 0A 73 ?? 00 00 0A}
		$s = {73 ?? 00 00 0A 0C 08 6F ?? 00 00 0A}

	condition:
		all of them and filesize < 200KB
}


rule RUSSIANPANDA_Illyrianstealer : FILE
{
	meta:
		description = "Detects Illyrian Stealer"
		author = "RussianPanda"
		id = "2f85e87c-6883-5f41-a37c-00f9e93f61bf"
		date = "2024-01-08"
		modified = "2024-01-08"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/cd712dfbd20050a57e868656a39771b79120595c/IllyrianStealer/illyrian_stealer.yar#L2-L18"
		license_url = "N/A"
		hash = "fae0aed6173804e8c22027cbb0c121eedd927f16ea7e2b23662dbe6e016980e8"
		logic_hash = "2012d401d3e7ce2d4d6ea12ed01a30b7d3e18f4ed47dbf70d43bae6c328960ea"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "get_TotalPhysicalMemory"
		$s2 = "\\b(bitcoincash)[a-zA-HJ-NP-Z0-9]{36,54}\\b" wide
		$s3 = "[Crypto]" wide
		$s4 = "|Black|" wide

	condition:
		all of ( $s* ) and filesize < 50KB and pe.imports ( "mscoree.dll" )
}

rule RUSSIANPANDA_Win_Mal_Juniperstealer : FILE
{
	meta:
		description = "Detects Juniper Stealer"
		author = "RussianPanda"
		id = "d8ad9175-a226-5e09-a206-b3da42c1db42"
		date = "2025-02-13"
		modified = "2025-02-14"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/cd712dfbd20050a57e868656a39771b79120595c/UNC4108/win_mal_JuniperStealer.yar#L1-L14"
		license_url = "N/A"
		hash = "44dc2777ee8dd6d5cd8ebb10e71caf73b330940131417b5fca2b174a264e19e3"
		logic_hash = "e3d05058bbb0e8e408f2b6cf24cb2462b6a3f237c3c464b891cda705b4968c02"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "OutlookDecryptPwd"
		$s2 = "CookiesNew"
		$s3 = "Cookies128"
		$s4 = "mscoree.dll"

	condition:
		uint16( 0 ) == 0x5A4D and all of them
}

rule RUSSIANPANDA_Sentinel_Stealer
{
	meta:
		description = "Detects Sentinel Stealer"
		author = "RussianPanda"
		id = "8a221d7b-8fa6-53cd-a3e8-63cc67285186"
		date = "2024-01-19"
		modified = "2024-01-19"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/cd712dfbd20050a57e868656a39771b79120595c/SentinelStealer/sentinel_stealer.yar#L1-L14"
		license_url = "N/A"
		hash = "3a540a8a81c5a5b452f154d7875423a3"
		logic_hash = "b9d72848842ea4d26544633bb83fccd17239b28493bde3f73341eb2004d8ee0c"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s1 = "Sentinel.SmallerEncryptedIcon" wide
		$s2 = "SentinelSteals" wide
		$s4 = "_CorExeMain"

	condition:
		all of them
}

rule BLACKBERRY_Mal_Infostealer_Win32_Blackguard : FILE
{
	meta:
		description = "Detects W32 BlackGuard Infostealer"
		author = "BlackBerry Threat Research team "
		id = "e079de0f-c607-5089-b385-ba67ed2cb73e"
		date = "2022-04-14"
		modified = "2022-07-06"
		reference = "https://blogs.blackberry.com/en/2022/04/threat-thursday-blackguard-infostealer"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Blackberry/Mal_Infostealer_Win32_BlackGuard.yar#L3-L39"
		license_url = "N/A"
		hash = "6ab3b21fa7cb638ed68509be1ed6302284e8a9cd1a10f9b6837c057154aa6162"
		logic_hash = "6e819ee656b6d696be1e818eeb8a545e7934c1f5a1171a1192422d8c74c0caa2"
		score = 75
		quality = 85
		tags = "FILE"
		license = "This Yara rule is provided under the Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0) and open to any user or organization, as long as you use it under this license and ensure originator credit in any derivative to The BlackBerry Research & Intelligence Team"

	strings:
		$a1 = { 06 91 06 61 20 AA 00 00 00 61 D2 9C 06 17 58 0A }
		$a2 = "System.Data.SQLite"
		$a3 = "FromBase64String"
		$a4 = "BlockInput"
		$a5 = "UploadFile"
		$a6 = "Passwords"
		$a7 = "Discord"
		$a8 = "GetVolumeInformationA"
		$a9 = "NordVPN"
		$a10 = "OpenVPN"
		$a11 = "ProtonVPN"
		$a12 = "OperaCookies"
		$a13 = "EdgeCookies"
		$a14 = "ChromeCookies"
		$b1 = "upche" wide

	condition:
		uint16( 0 ) == 0x5a4d and pe.imphash ( ) == "f34d5f2d4577ed6d9ceec516c1f5a744" and pe.number_of_sections == 3 and pe.section_index ( ".text" ) == 0 and pe.section_index ( ".rsrc" ) == 1 and pe.section_index ( ".reloc" ) == 2 and ( ( all of ( $a* ) ) or ( ( 12 of ( $a* ) and all of ( $b* ) ) ) )
}


rule BLACKBERRY_Mal_Infostealer_Win32_Jupyter_Main_Module
{
	meta:
		description = "Detects Jupter main module"
		author = "BlackBerry Threat Research Team"
		id = "b6c51dcc-bdf4-5960-b407-70379b948dc1"
		date = "2021-11-23"
		modified = "2022-07-06"
		reference = "https://blogs.blackberry.com/en/2022/01/threat-thursday-jupyter-infostealer-is-a-master-of-disguise"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Blackberry/Mal_Infostealer_Win32_Jupyter_Main_Module.yar#L3-L42"
		license_url = "N/A"
		logic_hash = "bf14defaa9b0c514ddbdd4ed09b69a670d432dd30a3bbe4895ad7f9a796c1897"
		score = 75
		quality = 83
		tags = ""
		license = "This Yara rule is provided under the Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0) and open to any user or organization, as long as you use it under this license and ensure originator credit in any derivative to The BlackBerry Research & Intelligence Team"

	strings:
		$g1 = { 68 00 74 00 74 00 70 00 3A 00 2F 00 2F 00 }
		$g2 = { 5C 00 41 00 50 00 50 00 44 00 41 00 54 00 41 00 5C 00 52 00 4F 00 41 00 4D 00 49 00 4E 00 47 }
		$g3 = { 63 00 68 00 61 00 6E 00 67 00 65 00 5F 00 73 00 74 00 61 00 74 00 75 00 73 }
		$g4 = { 50 00 4F 00 53 00 54 }
		$g5 = { 69 00 73 00 5F 00 73 00 75 00 63 00 63 00 65 00 73 00 73 }
		$g6 = { 75 00 73 00 65 00 72 00 70 00 72 00 6F 00 66 00 69 00 6C 00 65 }
		$g7 = { 44 00 45 00 53 00 4B 00 54 00 4F 00 50 00 2D }
		$g8 = { 4C 00 41 00 50 00 54 00 4F 00 50 00 2D }
		$g9 = { 78 00 38 00 36}
		$g10 = { 78 00 36 00 34 }
		$g11 = { 41 00 64 00 6D 00 69 00 6E }
		$g12 = { 56 00 69 00 73 00 74 00 61 }
		$g13 = { 64 00 6E 00 73 }
		$g14 = { 64 00 7A 00 6B 00 61 00 62 72 }
		$g15 = { 78 00 7A 00 6B 00 61 00 62 00 73 00 72 }
		$g16 = { 64 00 7A 00 6B 00 61 00 62 00 73 00 72 }
		$h1 = { 4F 00 43 00 2D }
		$h2 = { 4E 00 56 00 2D }
		$h3 = { 53 00 50 00 2D }
		$h4 = { 49 00 4E 00 2D }
		$i = "System.Net"

	condition:
		10 of ( $g* ) and 1 of ( $h* ) and ( pe.imports ( "mscoree.dll" , "_CorDllMain" ) or $i )
}


rule BLACKBERRY_Mal_Infostealer_EXE_Jupyter_Cert_36Ff : FILE
{
	meta:
		description = "Detects Jupter executables by certificate OOO Sistema (36ff)"
		author = "BlackBerry Research & Intelligence Team"
		id = "5671b149-4eb6-5b13-92de-01b71a001802"
		date = "2021-10-14"
		modified = "2022-07-06"
		reference = "https://blogs.blackberry.com/en/2022/01/threat-thursday-jupyter-infostealer-is-a-master-of-disguise"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Blackberry/Mal_Infostealer_EXE_Jupyter_Cert_36ff.yar#L3-L18"
		license_url = "N/A"
		logic_hash = "8f543c592f23257bda8902229a9a8a735bb593254b279a1786fc85734cd56905"
		score = 75
		quality = 85
		tags = "FILE"
		license = "This Yara rule is provided under the Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0) and open to any user or organization, as long as you use it under this license and ensure originator credit in any derivative to The BlackBerry Research & Intelligence Team"

	condition:
		uint16( 0 ) == 0x5a4d and for any i in ( 0 .. pe.number_of_signatures ) : ( pe.signatures [ i ] . issuer contains "Certum Extended Validation Code Signing CA SHA2" and pe.signatures [ i ] . serial == "36:ff:67:4e:b3:05:e9:9c:35:56:5f:a3:01:d5:c4:b0" )
}


rule BLACKBERRY_Eternitystealer : FILE
{
	meta:
		description = "Detects Eternity Stealer"
		author = "BlackBerry Threat Research Team"
		id = "8bccc143-c250-5d52-85cb-b315dc6fb679"
		date = "2022-05-22"
		modified = "2022-07-07"
		reference = "https://blogs.blackberry.com/en/2022/06/threat-spotlight-eternity-project-maas-goes-on-and-on"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Blackberry/EternityStealer.yar#L4-L32"
		license_url = "N/A"
		logic_hash = "466030b30c4436c3e3896ca3385ae829696e7f351bba81bc3c0efbc62b86645f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "This Yara rule is provided under the Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0) and open to any user or organization, as long as you use it under this license and ensure originator credit in any derivative to The BlackBerry Research & Intelligence Team"

	strings:
		$s1 = "Corrupting Growtopia.." wide
		$s2 = "growtopia1.com" wide
		$s3 = "Deleting previous file from startup and copying new one." wide
		$s4 = "Debug mode, dont share this stealer anywhere." wide
		$s5 = "Sending info to Eternity.." wide
		$s6 = "Taking and uploading screenshot.." wide
		$s7 = "dcd.exe" wide
		$s8 = "https://eterprx.net" wide
		$s9 = "https://eternitypr.net" wide

	condition:
		( uint16( 0 ) == 0x5a4d and pe.imphash ( ) == "f34d5f2d4577ed6d9ceec516c1f5a744" and all of ( $s* ) )
}

rule BLACKBERRY_Mal_Infostealer_Win32_Jupyter_Download_And_Execute_Module
{
	meta:
		description = "Detects Jupter download and execute module. Research has shown it downloading SolarDelphi / JupyterStealer."
		author = "BlackBerry Threat Research Team"
		id = "318b0327-b4b0-57a6-8a24-51320b1026ec"
		date = "2021-11-09"
		modified = "2022-07-06"
		reference = "https://blogs.blackberry.com/en/2022/01/threat-thursday-jupyter-infostealer-is-a-master-of-disguise"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Blackberry/Mal_Infostealer_Win32_Jupyter_Download_and_Execute_Module.yar#L4-L30"
		license_url = "N/A"
		logic_hash = "7491eeb06e88512711688a1baf6967e6b6bf80ad4937c16fd49059903cac35df"
		score = 75
		quality = 85
		tags = ""
		license = "This Yara rule is provided under the Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0) and open to any user or organization, as long as you use it under this license and ensure originator credit in any derivative to The BlackBerry Research & Intelligence Team"

	strings:
		$e1 = { 68 00 74 00 74 00 70 00 3A 00 2F 00 2F 00 }
		$e2 = { 47 00 45 00 54 00 00 3D 63 00 3A 00 5C 00 77 00 69 00 6E 00 64 00 6F 00 77 00 73 00 5C 00 73 00 79 00 73 00 74 00 65 00 6D 00 33 00 32 00 5C 00 77 00 69 00 6E 00 76 00 65 00 72 00 2E 00 65 00 78 00 65 }
		$e3 = { 00 2F 00 67 00 65 00 74 00 2F 00 }
		$e4 = "FromBase64String"
		$e5 = "get_UTF8"
		$e6 = "WebResponse"
		$e7 = "GetResponse"
		$e8 = "Invoke"

	condition:
		pe.imports( "mscoree.dll" , "_CorDllMain" ) and dotnet.version == "v4.0.30319" and dotnet.assembly.version.major == 0 and dotnet.assembly.version.minor == 0 and all of ( $e* )
}
/*
 * YARA Rule Set
 * Repository Name: Cluster25
 * Repository: https://github.com/mikesxrs/Open-Source-YARA-rules
 * Retrieval Date: 2026-05-03
 * Git Commit: ec0056f767db98bf6d5fd63877ad51fb54d350e9
 * Number of Rules: 8
 * Skipped: 0 (age), 2 (quality), 0 (score), 0 (importance)
 *
 * 
 * LICENSE
 * 
 * NO LICENSE SET
 */

rule EMBEERESEARCH_Win_Mystic_Stealer_Bytecodes_Sep_2023
{
	meta:
		description = "No description has been set in the source file - EmbeeResearch"
		author = "Matthew @ Embee_reserch"
		id = "ef7c51e1-9c8c-5b66-bc1e-f35a796c84f2"
		date = "2023-09-21"
		modified = "2023-11-12"
		reference = "https://github.com/embee-research/Yara-detection-rules/"
		source_url = "https://github.com/embee-research/Yara-detection-rules//blob/ac56d6f6fd2a30c8cb6e5c0455d6519210a8b0f4/Rules/win_mystic_stealer_bytecodes_sep_2023.yar#L1-L29"
		license_url = "N/A"
		hash = "ef9fce75334befe0b435798c0b61dab1239ea5bc62b97654943676dd96dc6318"
		hash = "36d8cb1447e2c5da60d2b86bf29856919c25f8e71a17f1d0d61d03c5e0505e4b"
		hash = "e907c22288dacb37efa07481fef7a0d4ec0ce42954f12b2572ea7f5ffeecf313"
		logic_hash = "f68b6ef307e48b7ff6f944cfcf9c906a83611400af5af7d8621227874356960d"
		score = 75
		quality = 75
		tags = ""

	strings:
		$s1 = {99 d3 d8 c5}
		$s2 = {99 b7 66 df}
		$s3 = {cb 45 92 f8}
		$s4 = {7b cc e1 54}
		$s5 = {7b 9c 29 17}
		$s6 = {01 c4 fb 83}
		$s7 = {b6 0f 74 e3}
		$s8 = {93 58 b5 ee}
		$s9 = {81 d9 df be}
		$s10 = {7b d8 62 00}
		$s12 = {81 d9 df be}
		$s13 = {7b d8 62 00}
		$s14 = {77 4a bc ac}

	condition:
		( all of them )
}


rule EMBEERESEARCH_Win_Exela_Stealer_Simple_Strings_Sep_2023
{
	meta:
		description = "No description has been set in the source file - EmbeeResearch"
		author = "Matthew @embee_research"
		id = "e63aa1d3-997e-5200-93fc-869c177fe1a8"
		date = "2023-09-24"
		modified = "2023-09-26"
		reference = "https://github.com/embee-research/Yara-detection-rules/"
		source_url = "https://github.com/embee-research/Yara-detection-rules//blob/ac56d6f6fd2a30c8cb6e5c0455d6519210a8b0f4/Rules/win_exela_stealer_simple_strings_sep_2023.yar#L4-L32"
		license_url = "N/A"
		hash = "bf5d70ca2faf355d86f4b40b58032f21e99c3944b1c5e199b9bb728258a95c1b"
		logic_hash = "2312b63fe86fd34eb12f42f079f470eb3af27ef8c199f3620253c828ad28441a"
		score = 75
		quality = 75
		tags = ""

	strings:
		$s1 = "https://i.instagram.com/api/v1/accounts/current_user/" wide
		$s2 = "/create /f /sc onlogon /rl highest /tn \"AutoUpdateCheckerOnLogon\" /tr " wide
		$s4 = "https://discord.com/api/webhooks/" wide
		$s5 = "Browser : {0} | Name : {1} | Value : {2} | Date created (timestamp) : {3} |  Date last used (timestamp) : {4} | Count {5}" wide
		$s6 = "Browser : {0} | {1} {2}/{3} {4}" wide
		$e1 = "Exela.Program" wide ascii
		$e2 = "Exela.Wifi" wide ascii
		$e3 = "Exela.Components" wide ascii
		$e4 = "Exela Stealer" wide ascii
		$e5 = "Exela.exe" wide ascii

	condition:
		dotnet.is_dotnet and ( ( all of ( $s* ) ) or ( 3 of ( $e* ) ) )
}


rule EMBEERESEARCH_Win_Marsstealer_Encryption_Bytecodes
{
	meta:
		description = "Encryption observed in MarsStealer"
		author = "Matthew @ Embee_Research"
		id = "7a66ea9c-966e-5780-8b36-a268904b9c1b"
		date = "2023-12-24"
		modified = "2023-12-24"
		reference = "https://github.com/embee-research/Yara-detection-rules/"
		source_url = "https://github.com/embee-research/Yara-detection-rules//blob/ac56d6f6fd2a30c8cb6e5c0455d6519210a8b0f4/Rules/win_marsStealer_encryption_bytecodes_dec_2023.yar#L1-L16"
		license_url = "N/A"
		hash = "7a391340b6677f74bcf896b5cc16a470543e2a384049df47949038df5e770df1"
		logic_hash = "49ffde28c8823c00959ddbaa516fc48c7908b533c8f91608b0e3a645045c9048"
		score = 75
		quality = 75
		tags = ""

	strings:
		$s1 = {31 2d 3d 31 73 30 02 39 c0 74 0a 5b 70 61 73 64 6c 30 71 77 69 8d 5b 01 8d 52 01 39 eb 75 03 83 eb 20 39 ca}

	condition:
		$s1
}


rule DITEKSHEN_INDICATOR_TOOL_PWS_Credstealer : FILE
{
	meta:
		description = "Detects Python executable for stealing credentials including domain environments. Observed in MuddyWater."
		author = "ditekSHen"
		id = "ab587b12-f3e1-5f08-b27c-03ee9752e513"
		date = "2020-11-06"
		modified = "2024-09-25"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/indicator_tools.yar#L22-L41"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "e729c8b0b1db642acabbc4590833c05ce81447bb89e5f40aea5f0b8ebdee4438"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "PYTHON27.DLL" fullword wide
		$s2 = "C:\\Python27\\lib\\site-packages\\py2exe\\boot_common.pyR" fullword ascii
		$s3 = "C:\\Python27\\lib\\site-packages\\py2exe\\boot_common.pyt" fullword ascii
		$s4 = "subprocess.pyc" fullword ascii
		$s5 = "MyGetProcAddress(%p, %p(%s)) -> %p" fullword ascii
		$p1 = "Dump SAM hashes from target systemss" fullword ascii
		$p2 = "Dump LSA secrets from target systemss" fullword ascii
		$p3 = "Dump the NTDS.dit from target DCs using the specifed method" fullword ascii
		$p4 = "Dump NTDS.dit password historys" fullword ascii
		$p5 = "Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameterss" fullword ascii
		$p6 = "Retrieve plaintext passwords and other information for accounts pushed through Group Policy Preferencess" fullword ascii
		$p7 = "Combo file containing a list of domain\\username:password or username:password entriess" fullword ascii

	condition:
		uint16( 0 ) == 0x5a4d and ( 3 of ( $s* ) and 1 of ( $p* ) )
}

rule DITEKSHEN_MALWARE_Win_Isrstealer : FILE
{
	meta:
		description = "ISRStealer payload"
		author = "ditekSHen"
		id = "d6c3acdd-e881-5f97-8856-b7b60f56a1c2"
		date = "2020-11-06"
		modified = "2024-11-01"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/malware.yar#L112-L128"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "5dd030ab8122b5dd432168647c7a3465cb3593a326f68b4863a91d16587641e5"
		score = 75
		quality = 75
		tags = "FILE"
		clamav_sig = "MALWARE.Win.Trojan.ISRStealer"

	strings:
		$s1 = "&password=" wide
		$s2 = "&pcname=" wide
		$s3 = "MSVBVM60.DLL" ascii
		$s4 = "MSVBVM60.DLL" wide
		$s5 = "Core Software For : Public" wide
		$s6 = "</Host>" wide
		$s7 = "</Pass>" wide
		$s8 = "/scomma" wide

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 4000KB and 6 of them ) or all of them
}

rule DITEKSHEN_MALWARE_Win_Cryptostealergo : FILE
{
	meta:
		description = "CryptoStealerGo payload"
		author = "ditekSHen"
		id = "83886aeb-af7e-564c-989a-fb7d955814e2"
		date = "2020-11-06"
		modified = "2024-11-01"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/malware.yar#L676-L692"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "0050be7522e7d89cb9688e63fdca11d24baa74aa858e8c19ee7b4658518536b6"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "Go build ID: \"" ascii
		$s2 = "file_upload.go" ascii
		$s3 = "grequests.FileUpload" ascii
		$s4 = "runtime.newproc" ascii
		$s5 = "credit_cards" ascii
		$s6 = "zip.(*fileWriter).Write" ascii
		$s7 = "autofill_" ascii
		$s8 = "XFxVc2VyIERhdGFcXA==" ascii
		$s9 = "XFxBcHBEYXRhXFxMb2NhbFxc" ascii

	condition:
		uint16( 0 ) == 0x5a4d and 8 of them
}

rule DITEKSHEN_MALWARE_Win_Quasarstealer : FILE
{
	meta:
		description = "Detects Quasar infostealer"
		author = "ditekshen"
		id = "d0d532fe-bd0a-560a-8570-f6038d694338"
		date = "2020-11-06"
		modified = "2024-11-01"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/malware.yar#L2557-L2572"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "4b6ab49992db4d7bf4404d51b0ef1773249de89545ec31176ad45d00803ba703"
		score = 75
		quality = 75
		tags = "FILE"
		clamav_sig = "MALWARE.Win.Trojan.QuasarStealer"

	strings:
		$s1 = "PGma.System.MouseKeyHook, Version=5.6.130.0, Culture=neutral, PublicKeyToken=null" fullword ascii
		$s2 = "DQuasar.Common, Version=1.4.0.0, Culture=neutral, PublicKeyToken=null" fullword ascii
		$s3 = "Process already elevated." fullword wide
		$s4 = "get_PotentiallyVulnerablePasswords" fullword ascii
		$s5 = "GetKeyloggerLogsDirectory" ascii
		$s6 = "set_PotentiallyVulnerablePasswords" fullword ascii
		$s7 = "BQuasar.Client.Extensions.RegistryKeyExtensions+<GetKeyValues>" ascii

	condition:
		uint16( 0 ) == 0x5a4d and 5 of them
}

rule DITEKSHEN_MALWARE_Win_Spyeye : FILE
{
	meta:
		description = "Detects SpyEye"
		author = "ditekSHen"
		id = "aa15220a-6fd4-5c5e-8287-957fc3c3fe52"
		date = "2020-11-06"
		modified = "2024-11-01"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/malware.yar#L4096-L4111"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "352853d600d1f4fbc09e58b783eb4e13b335fefbfe89842873710f0a9085d107"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$x1 = "_CLEANSWEEP_" ascii wide
		$x2 = "config.datUT" fullword ascii
		$x3 = "webinjects.txtUT" fullword ascii
		$s1 = "confirm:processCommand" fullword ascii
		$s2 = "Smth wrong with navigate to REF-PAGE (err code: %d). 0_o" fullword ascii
		$s3 = "(UTC%s%2.2f) %s" fullword wide
		$s4 = "M\\F;u`r" fullword ascii
		$s5 = "]YH0%Yn" fullword ascii

	condition:
		uint16( 0 ) == 0x5a4d and ( 2 of ( $x* ) or ( 1 of ( $x* ) and 1 of ( $s* ) ) )
}


rule DITEKSHEN_MALWARE_Win_PWSH_Poshwifistealer
{
	meta:
		description = "Detects PowerShell PoshWiFiStealer"
		author = "ditekSHen"
		id = "69ac123d-b746-57f1-a488-547f9a9cdd86"
		date = "2020-11-06"
		modified = "2024-11-01"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/malware.yar#L4754-L4765"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "769349360b5d22226a5339a9e8471d06731dc522475c9385c1c145a0488e0ad1"
		score = 75
		quality = 75
		tags = ""

	strings:
		$s1 = "netsh wlan export profile" ascii
		$s2 = "Send-MailMessage" ascii
		$u1 = "https://github.com/axel05869/Wifi-Grab" ascii
		$u2 = "/exploitechx/wifi-password-extractor" ascii

	condition:
		all of ( $s* ) or all of ( $u* )
}

rule DITEKSHEN_MALWARE_Win_Cookiestealer : FILE
{
	meta:
		description = "Detects generic cookie stealer"
		author = "ditekSHen"
		id = "64c6c59d-4046-5949-bf71-22a5f6bfa209"
		date = "2020-11-06"
		modified = "2024-11-01"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/malware.yar#L5841-L5857"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "9cc406ae078e37430b3cf10954c02014b9760bc887344842e724df735d1d9808"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "([\\S]+?)=([^;|^\\r|^\\n]+)" fullword ascii
		$s2 = "(.+?): ([^;|^\\r|^\\n]+)" fullword ascii
		$s3 = "Set-Cookie: ([^\\r|^\\n]+)" fullword ascii
		$s4 = "cmd.exe /c taskkill /f /im chrome.exe" fullword ascii
		$s5 = "FIREFOX.EXE|Google Chrome|IEXPLORE.EXE" ascii
		$pdb1 = "F:\\facebook_svn\\trunk\\database\\Release\\DiskScan.pdb" fullword ascii
		$pdb2 = "D:\\Projects\\crxinstall\\trunk\\Release\\spoofpref.pdb" fullword ascii
		$ua1 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.140 Safari/537.36" fullword ascii
		$ua2 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.86 Safari/537.36" fullword ascii

	condition:
		uint16( 0 ) == 0x5a4d and ( ( all of ( $s* ) and 1 of ( $pdb* ) and 1 of ( $ua* ) ) or ( all of ( $ua* ) and 1 of ( $pdb* ) and 2 of ( $s* ) ) )
}

rule DITEKSHEN_MALWARE_Win_Spyro : FILE
{
	meta:
		description = "Detects Spyro / VoidCrypt / Limbozar ransomware"
		author = "ditekSHen"
		id = "8b3273c4-827e-50ce-983e-a5843f6b5a78"
		date = "2020-11-06"
		modified = "2024-11-01"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/malware.yar#L6649-L6675"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "2e3be361f6d4283fd312a4486eaa39d6594813937cc3f62dbb603babeff17929"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "Decrypt-info.txt" ascii wide
		$s2 = "AbolHidden" ascii wide
		$s3 = "C:\\ProgramData\\prvkey" ascii wide
		$s4 = ".?AV?$TF_CryptoSystemBase@VPK_Encryptor@CryptoPP" ascii
		$s5 = "C:\\Users\\LEGION\\" ascii
		$s6 = "C:\\ProgramData\\pkey.txt" fullword ascii
		$s7 = ".Spyro" fullword ascii
		$m1 = "Go to C:\\ProgramData\\ or in Your other Drives" wide
		$m2 = "saving prvkey.txt.key file will cause" wide
		$m3 = "in Case of no Answer:" wide
		$m4 = "send us prvkey*.txt.key" wide
		$m5 = "Somerhing went wrong while writing payload on disk" ascii
		$m6 = "this country is forbidden.\"}" ascii
		$c1 = "Voidcrypt/1.0" ascii
		$c2 = "h1dd3n.cc" ascii
		$c3 = "/voidcrypt/index.php" ascii
		$c4 = "&user=" ascii
		$c5 = "&disk-size=" ascii
		$c6 = "unique-id=" ascii

	condition:
		uint16( 0 ) == 0x5a4d and ( 5 of ( $s* ) or 4 of ( $c* ) or 3 of ( $m* ) or 8 of them )
}

rule DITEKSHEN_MALWARE_Win_Sweetystealer : FILE
{
	meta:
		description = "Detects SweetyStealer"
		author = "ditekSHen"
		id = "21dd1706-2cb5-5b27-ad3a-c3de8e6fb333"
		date = "2020-11-06"
		modified = "2024-11-01"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/malware.yar#L7590-L7608"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "ecf22240b47af077055260faba0406721f1b4cc5ed04180285df0de86c4e1241"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "SWEETY STEALER" wide
		$s2 = "\\SWEETYLOG.zip" fullword wide
		$s3 = "\\SWEETY STEALER\\SWEETY\\" ascii
		$s4 = "\\Sweety" fullword wide
		$s5 = "SWEETYSTEALER." ascii
		$s6 = "in Virtual Environment, so we prevented stealing" wide
		$s7 = ":purple_square:" wide
		$f1 = "<GetDomainDetect>b__" ascii
		$f2 = "<GetAllProfiles>b__" ascii
		$f3 = "<ProcessExtraFieldZip64>b__" ascii
		$f4 = "<PostExtractCommandLine>k__" ascii

	condition:
		uint16( 0 ) == 0x5a4d and 3 of ( $s* ) or ( 3 of ( $f* ) and 1 of ( $s* ) )
}

rule DITEKSHEN_MALWARE_Win_UNK_Infostealer : FILE
{
	meta:
		description = "Detects unknown information stealer"
		author = "ditekSHen"
		id = "f6f9816f-79bd-527c-9c0f-24e09c95ae35"
		date = "2020-11-06"
		modified = "2024-11-01"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/malware.yar#L8221-L8246"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "ca57ebf4b56020d278ec8a7e721c72de7a1f925a8e7f1f3a9edc8a70b88ff9d1"
		score = 75
		quality = 75
		tags = "FILE"
		snort_sid = "920263"
		hash1 = "b7a2cb34d3bc42d6d4c9d9af7dd406e2a5caef8ea46e5d09773feeb9920a6b21"
		hash2 = "dd95377842932d77e225b126749e1e6e8ecd6f5c6540d084a551a80a54d02d7d"
		hash3 = "12f790d9a0775b5e62effc6ea9e55bbef345fffbfb2f671f85098c4f7661dd0f"
		hash4 = "0a4cea763dffde451c75a434143fc5d014c32c6d1f8f34920ea5f2854e62118f"

	strings:
		$s1 = "%s\\%s\\%s-Qt" fullword wide
		$s2 = "%s\\%s.json" fullword wide
		$s3 = "*.mmd*" fullword wide
		$s4 = "%s\\%s.vdf" fullword wide
		$s5 = "%-50s %s" fullword wide
		$s6 = "dISCORD|lOCAL" fullword ascii nocase
		$s7 = "sTORAGE|LEVELDB" fullword ascii nocase
		$s8 = ".coin" fullword ascii
		$s9 = ".emc" fullword ascii
		$s10 = ".lib" fullword ascii
		$s11 = ".bazar" fullword ascii
		$s12 = "id=%d" fullword ascii
		$s13 = "2:?/v /v /v /^Y" fullword ascii

	condition:
		uint16( 0 ) == 0x5a4d and 8 of them
}

rule DITEKSHEN_MALWARE_Win_PWSH_Poshcookiestealer
{
	meta:
		description = "Detects PowerShell PoshCookieStealer"
		author = "ditekSHen"
		id = "7326a056-288b-534b-811d-172bd6936d7b"
		date = "2020-11-06"
		modified = "2024-11-01"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/malware.yar#L9066-L9080"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "234958098d09732675dd539e8d25c6754ba50bf92b3a19e7fef8c68d70503ec4"
		score = 75
		quality = 75
		tags = ""

	strings:
		$s1 = "\\User Data\\default\\Network\\Cookies" ascii nocase
		$s2 = "Send-ToEmail" ascii
		$s3 = "[Security.Cryptography.ProtectedData]::Unprotect($" ascii
		$s4 = "$($env:LOCALAPPDATA)\\" ascii
		$s5 = "$($env:HOMEPATH)\\" ascii
		$s6 = "|ForEach-Object ToString X2) -join ''" ascii
		$s7 = ".Attachments.Add($" ascii

	condition:
		5 of them
}

rule DITEKSHEN_MALWARE_Win_Soranostealer : FILE
{
	meta:
		description = "Detects SoranoStealer / HogGrabber. Available on Github: /Alexuiop1337/SoranoStealer"
		author = "ditekSHen"
		id = "2fc40a73-5f28-5b5c-938a-35e8336e1d11"
		date = "2020-11-06"
		modified = "2024-11-01"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/malware.yar#L9419-L9443"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "27c9d6bf3f40f3d41c35975e856671fafcd4a0a8143b3bcbdff61c1fb28a37ab"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$x1 = "OiCuntJollyGoodDayYeHavin_" ascii
		$x2 = { 00 56 4d 50 72 6f 74 65 63 74 00 52 65 61 63 74
                6f 72 00 64 65 34 66 75 63 6b 79 6f 75 00 42 61
                62 65 6c 4f 62 66 75 73 63 61 74 6f 72 41 74 74
                72 69 62 75 74 65 00 43 72 79 74 70 6f 4f 62 66
                75 73 63 61 74 6f 72 00 }
		$x3 = { 00 4f 62 66 75 73 63 61 74 65 64 42 79 47 6f 6c
                69 61 74 68 00 42 65 64 73 2d 50 72 6f 74 6f 72 00 }
		$s1 = ".Binaries.whysosad" ascii
		$s2 = "Adminstrator permissons are required" wide
		$s3 = "12:03:33:4A:04:AF" fullword wide
		$s4 = "RemoveEXE" fullword ascii
		$s5 = "$340becfa-1688-4c32-aa49-30fdb4005e4b" fullword ascii
		$s6 = "$99cffbcc-6ad7-4d32-bd1f-450967cf4a6b" fullword ascii
		$s7 = "\"cam\": " ascii
		$s8 = " - 801858595527371999762718088" fullword ascii
		$s9 = "  - 96188142294460126639341306" fullword ascii

	condition:
		uint16( 0 ) == 0x5a4d and ( all of ( $x* ) or ( 2 of ( $x* ) and 3 of ( $s* ) ) or 5 of ( $s* ) )
}

rule DITEKSHEN_MALWARE_Win_Gloomanestealer : FILE
{
	meta:
		description = "Detects GloomaneStealer"
		author = "ditekSHen"
		id = "6e3c7e8f-4b75-5198-aa41-076f29aac227"
		date = "2020-11-06"
		modified = "2024-11-01"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/malware.yar#L9445-L9461"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "36aa9f863efb8172ed6449932169e6cb26cdeedd84bc734e09a8116a9c7774ac"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$x1 = "=GLOOMANE STEALER=" wide
		$x2 = "Maded by GLOOMANE" wide
		$s1 = "\\44CALIBER" ascii
		$s2 = "Ethernet()" fullword wide
		$s3 = ":spy: NEW LOG FROM" wide
		$s4 = ":eye: IP:" wide
		$s5 = ":file_folder: Grabbed Files" wide
		$s6 = "$ebc25cf6-9120-4283-b972-0e5520d0000C" fullword ascii
		$s7 = "$3b0e2d3d-3d66-42bb-8f9c-d6e188f359ae" fullword ascii

	condition:
		uint16( 0 ) == 0x5a4d and ( all of ( $x* ) or ( 1 of ( $x* ) and 3 of ( $s* ) ) or 5 of ( $s* ) )
}

rule DITEKSHEN_MALWARE_Win_Unamedstealer : FILE
{
	meta:
		description = "Detects unknown infostealer. Observed as 2nd stage and injects into .NET AppLaunch.exe"
		author = "ditekSHen"
		id = "cb3d575b-3d53-5b89-abc1-3b3857ec9f46"
		date = "2020-11-06"
		modified = "2024-11-01"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/malware.yar#L9478-L9494"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "84f4ac7489a0d522763f69ce55f816642a8511dc4b9698ce47c983020a2b7bea"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "HideMelt" fullword ascii
		$s2 = ".Implant" ascii
		$s3 = "SetUseragent" fullword ascii
		$s4 = "SendReport" fullword ascii
		$s5 = "cookiesList" fullword ascii
		$s6 = "WriteAppsList" fullword ascii
		$s7 = "Timeout /T 2 /Nobreak" fullword wide
		$s8 = "Directory not exists" wide
		$s9 = "### {0} ### ({1})" wide

	condition:
		uint16( 0 ) == 0x5a4d and 6 of them
}

rule DITEKSHEN_MALWARE_Win_Cyberstealer : FILE
{
	meta:
		description = "Detects CyberStealer infostealer"
		author = "ditekSHen"
		id = "cb02013f-ffb2-5a17-9d6e-1d19b0e98fb8"
		date = "2020-11-06"
		modified = "2024-11-01"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/malware.yar#L9920-L9941"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "72413b68fa1381656202165dcd878761727e7caf0f15ccd65f3f2f842243a1f6"
		score = 75
		quality = 71
		tags = "FILE"

	strings:
		$x1 = "\\Cyber Stealer\\" ascii
		$s1 = "[Virtualization]" fullword wide
		$s2 = "\"encryptedPassword\":\"([^\"]+)\"" fullword wide
		$s3 = "CreditCard" fullword ascii
		$s4 = "DecryptPassword" fullword ascii
		$s5 = "_modTime" fullword ascii
		$s6 = "_pathname" fullword ascii
		$s7 = "_pathnameInZip" fullword ascii
		$s8 = "GetBookmarksDBPath" fullword ascii
		$s9 = "GrabberImages" fullword ascii
		$r1 = "^1[a-km-zA-HJ-NP-Z1-9]{25,34}$" wide
		$r2 = "^3[a-km-zA-HJ-NP-Z1-9]{25,34}$" wide
		$r3 = "^([a-zA-Z0-9_\\-\\.]+)@([a-zA-Z0-9_\\-\\.]+)\\.([a-zA-Z]{2,5})$" wide
		$r4 = "^(?!:\\/\\/)([a-zA-Z0-9-_]+\\.)*[a-zA-Z0-9][a-zA-Z0-9-_]+\\.[a-zA-Z]{2,11}?$" wide

	condition:
		uint16( 0 ) == 0x5a4d and ( ( 1 of ( $x* ) and ( 2 of ( $s* ) or 2 of ( $r* ) ) ) or 7 of ( $s* ) or ( 5 of ( $s* ) and 2 of ( $r* ) ) or ( all of ( $r* ) and 4 of ( $s* ) ) )
}

rule DITEKSHEN_MALWARE_Win_Ragestealer : FILE
{
	meta:
		description = "Detect Rage / Priv8 infostealer"
		author = "ditekShen"
		id = "dfc1abaa-d975-5e6a-ad4d-344031b0c40c"
		date = "2020-11-06"
		modified = "2024-11-01"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/malware.yar#L10507-L10522"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "a26b86845bcd62d4a360a8dae9cfa56b5d96ebc521f224c18a01cc0a2bd958e9"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$x1 = "\\RageStealer\\obj\\" ascii
		$x2 = "Priv8 Stealer" wide
		$s1 = "\\Screen.png" wide
		$s2 = "Content-Disposition: form-data; name=\"document\"; filename=\"{1}\"" wide
		$s3 = "NEW LOG FROM" wide
		$s4 = "GRABBED SOFTWARE" wide
		$s5 = "DOMAINS DETECTED" wide
		$s6 = "snder" ascii

	condition:
		uint16( 0 ) == 0x5a4d and ( 1 of ( $x* ) and 4 of ( $s* ) )
}

rule DITEKSHEN_MALWARE_Win_Blankstealer : FILE
{
	meta:
		description = "Detects BlankStealer / BlankGrabber / Blank-c Stealer"
		author = "ditekSHen"
		id = "19686781-4be8-56c1-b606-d8fe14dbdc48"
		date = "2020-11-06"
		modified = "2024-11-01"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/malware.yar#L10691-L10703"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "cc0c8d3e0061d192e445ef661387360644ab428a9e9fc2480e966db96bc8264c"
		score = 75
		quality = 75
		tags = "FILE"
		snort = "923829001"

	strings:
		$s1 = "Blank-c" ascii
		$s2 = "Stealer License" ascii
		$s3 = "UID=" ascii
		$h1 = { 42 6c 61 6e 6b 2d 63 0a 53 74 65 61 6c 65 72 20 4c 69 63 65 6e 73 65 0a 55 49 44 3d }

	condition:
		( uint16( 0 ) == 0x4152 and 2 of them ) or ( all of ( $s* ) or 1 of ( $h* ) )
}

rule DITEKSHEN_MALWARE_Win_Povertystealer : FILE
{
	meta:
		description = "Detects PovertyStealer"
		author = "ditekSHen"
		id = "a431b82a-81cb-51a9-b3a8-61d71f36a60e"
		date = "2020-11-06"
		modified = "2024-11-01"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/malware.yar#L10904-L10917"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "0d8a4dd1f3a9935935878840d19e16d91d240da776f99eb2dd3f12df96efa1d9"
		score = 75
		quality = 75
		tags = "FILE"
		clamav1 = "MALWARE.Win.Trojan.PovertyStealer"

	strings:
		$x1 = "Poverty is the parent of crime." ascii
		$s2 = "OperationSystem: %d:%d:%d" ascii
		$s3 = "ScreenSize: {lWidth=%d, lHeight=%d}" ascii
		$s4 = "VideoAdapter #%d: %s" ascii
		$s5 = "$d.log" fullword wide

	condition:
		(( uint16( 0 ) == 0x5a4d and ( 1 of ( $x* ) or all of ( $s* ) ) ) or all of them )
}

rule DITEKSHEN_MALWARE_Win_Sapphirestealer : FILE
{
	meta:
		description = "Detects SapphireStealer"
		author = "ditekSHen"
		id = "ed6cffe4-23f1-5791-b07d-75abb698c899"
		date = "2020-11-06"
		modified = "2024-11-01"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/malware.yar#L11172-L11190"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "97088c0decf158d45a02571bd50b5f370c139339c19b8071f38c0f9816232d1f"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "Sapphire.Modules." ascii
		$s2 = "sapphire\\" wide
		$s3 = "by r3vengerx0" wide
		$s4 = "Sapphire\\obj\\" ascii
		$s5 = "[ERROR_GETSECRETKEY_METHOD]" fullword wide
		$s6 = "[ERROR_CANT_GET_PASSWORD]" fullword wide
		$s7 = "<h2>------NEW LOGS------</h2>" wide
		$s8 = "[ERROR] can't create grab directory" wide
		$s9 = "<UploadToTelegram>d__" ascii
		$s10 = "UploadToTelegram" ascii
		$s11 = ".SendLog+<UploadToTelegram>d__" ascii

	condition:
		uint16( 0 ) == 0x5a4d and 5 of them
}


rule DITEKSHEN_MALWARE_Win_Nppspy : FILE
{
	meta:
		description = "Detects NPPSpy / Ntospy"
		author = "ditekShen"
		id = "3867ba96-1162-5693-b58e-fc6fa04d880a"
		date = "2020-11-06"
		modified = "2024-11-01"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/malware.yar#L11305-L11325"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "53e929b52dddd5e3d060d2dd9937411f1ff215be4d3c67f5935c2a3fbab006d6"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "ntskrnl.dll" fullword ascii
		$s2 = "PasswordStealing.dll" fullword ascii
		$s3 = "ntoskrnl.dll" fullword ascii
		$s4 = "\\programdata\\packag~" ascii
		$s5 = "NPPSPY.dll" fullword ascii
		$s6 = "MSControll.dll" fullword ascii
		$s7 = "\\Windows\\Temp\\" ascii
		$s8 = "\\NPPSpy\\" ascii
		$s9 = "NPGetCaps" fullword ascii
		$s10 = "NPLogonNotify" fullword ascii
		$path = "\\GrzegorzTworek\\" ascii

	condition:
		uint16( 0 ) == 0x5a4d and ( ( pe.is_dll ( ) and filesize < 110KB and pe.number_of_exports == 2 and ( ( pe.exports ( "NPGetCaps" ) and pe.exports ( "NPLogonNotify" ) ) or ( 1 of ( $s* ) and ( pe.exports ( "NPGetCaps" ) or pe.exports ( "NPLogonNotify" ) ) ) ) ) or ( ( $path ) and any of ( $s* ) ) )
}

rule DITEKSHEN_MALWARE_Win_Metastealer : FILE
{
	meta:
		description = "Detects MetaStealer infostealer"
		author = "ditekSHen"
		id = "46aa30c1-12c2-56df-8c65-0b96147f9051"
		date = "2020-11-06"
		modified = "2024-11-01"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/malware.yar#L11400-L11423"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "260c6d90a89ddb6219a5cbad18058e41611ae2dc68a8d4e589fa6ca81853752f"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "! #\"'&(&*)>=@?POQOROSOTOUOVOWOXOYOZO[O^]{z|z}z~z" fullword wide
		$s2 = "{0}{1}{2}" fullword wide
		$s3 = "localhost" fullword wide
		$s4 = "\\tdata" fullword wide
		$s5 = "DecryptBlob" fullword ascii
		$s6 = "GetMac" fullword ascii
		$s7 = "GetHdc" fullword ascii
		$s8 = "FindProc" fullword ascii
		$s9 = "targetPid" fullword ascii
		$s10 = "MessageSecurityOverTcp" fullword ascii
		$s11 = "ListOfProcesses" fullword ascii
		$s12 = "ListOfPrograms" fullword ascii
		$s13 = "browserPaths" fullword ascii
		$s14 = "configs" fullword ascii
		$s15 = "scanners" fullword ascii
		$s16 = "FileScannerRule" fullword ascii

	condition:
		uint16( 0 ) == 0x5a4d and 7 of ( $s* )
}


rule DITEKSHEN_INDICATOR_KB_ID_Powershellcookiestealer
{
	meta:
		description = "Detects email accounts used for exfiltration observed in PowerShellCookieStealer"
		author = "ditekShen"
		id = "c2bbb9a8-3e4c-5676-9676-2708a196ef8d"
		date = "2021-01-21"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/indicator_knownbad_id.yar#L706-L715"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "bd404e94939acb92dd56a7d2a1f7536bcb3f520ca1e9dc614b53828afbc6dac8"
		score = 75
		quality = 71
		tags = ""

	strings:
		$s1 = "senmn0w@gmail.com" ascii wide nocase
		$s2 = "mohamed.trabelsi.ena2@gmail.com" ascii wide nocase

	condition:
		any of them
}

rule DITEKSHEN_INDICATOR_KB_Gobuildid_Gostealer : FILE
{
	meta:
		description = "Detects Golang Build IDs in known bad samples"
		author = "ditekSHen"
		id = "25c0eb8b-c69c-5f50-b622-daaa3c8c62a4"
		date = "2021-01-21"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/indicator_knownbad_id.yar#L1552-L1562"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "d548bc2580c8e8233a5fcdf85b947547c10f2c4d0056d14e990f30dd7b9a0672"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "Go build ID: \"xQV-b1Fr7d576TTTpbXi/gq4FgVQqMcg--9tmY13y/76rKNEUBENlDFDcecmm_/mbw17A_6WrROaNCYDEQF\"" ascii
		$s2 = "Go build ID: \"x4VqrSSsx8iysxVdfB-z/gIF3p7SUxiZsVgTuq7bN/93XHuILGnGYq2L83fRpj/eoY6nTqwk1sdMHTaXzlw\"" ascii
		$s3 = "Go build ID: \"BPRThIYWbHcZQQ4K1y2t/2mO0-FjLC50P0QZuMTgC/9i6TYw_akiEF9ZPN0s3p/s1XoqXr7EyXMDVw5TTP3\"" ascii

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 8000KB and 1 of them
}

rule HARFANGLAB_Xdspy_LNK_2025 : FILE
{
	meta:
		description = "Matches XDSpy malicious LNK files, used in 2025"
		author = "HarfangLab"
		id = "ddd86b11-2d48-5383-9893-d7ed44210a38"
		date = "2025-05-16"
		modified = "2026-01-29"
		reference = "TRR250601"
		source_url = "https://github.com/HarfangLab/iocs/blob/278c38e11e99d35af836cb9140e0857fd9226574/hl_public_reports_master.yar#L627-L648"
		license_url = "N/A"
		hash = "904db68a915b4bbd0b4b2d665bb1e2c51fa1b71b9c44ce45ccd4b4664f2bfd8e"
		hash = "536cd589cd685806b4348b9efa06843a90decae9f4135d1b11d8e74c7911f37d"
		hash = "0b705938e0063e73e03645e0c7a00f7c8d8533f1912eab5bf9ad7bc44d2cf9c3"
		logic_hash = "742dc83a60812609810e30b7f9d60ed0e0f6ce1294b2d29b084b0ea939ee71cb"
		score = 75
		quality = 80
		tags = "FILE"
		context = "file"

	strings:
		$c1 = "/nologo /r:System.IO.Compression.FileSystem.dll /out:%TEMP%" wide fullword
		$c2 = "%SystemRoot%\\Microsoft.Net\\Framework\\*jsc.exe" wide fullword
		$c3 = "+Convert.ToChar(46)+Convert.ToChar(105)+Convert.ToChar(110)+Convert.ToChar(105)" wide fullword

	condition:
		( filesize > 1KB ) and ( filesize < 10KB ) and ( uint32( 0 ) == 0x0000004C ) and ( ( uint32be( 4 ) == 0x01140200 ) and ( uint32be( 8 ) == 0x00000000 ) and ( uint32be( 12 ) == 0xC0000000 ) and ( uint32be( 16 ) == 0x00000046 ) ) and ( uint8( 0x14 ) & 0x20 == 0x20 ) and ( uint8( 0x14 ) & 0x80 == 0x80 ) and ( any of ( $c* ) )
}

rule HARFANGLAB_Xdspy_Etdownloader : FILE
{
	meta:
		description = "Matches XDSpy 1st stage ET Downloader malware"
		author = "HarfangLab"
		id = "b335d868-7904-5270-a55e-c1445f0c4c9c"
		date = "2025-05-16"
		modified = "2026-01-29"
		reference = "https://github.com/HarfangLab/iocs"
		source_url = "https://github.com/HarfangLab/iocs/blob/278c38e11e99d35af836cb9140e0857fd9226574/hl_public_reports_master.yar#L649-L682"
		license_url = "N/A"
		hash = "792c5a2628ec1be86e38b0a73a44c1a9247572453555e7996bb9d0a58e37b62b"
		logic_hash = "050bf26c5665c68055f1f31b4cdce40fb8c6d2b9d8e08925e684cf70e80eb2dd"
		score = 75
		quality = 80
		tags = "FILE"
		context = "file"

	strings:
		$dotNet = ".NETFramework,Version=" ascii
		$s1 = "$fcca44e8-9635-4cd7-974b-e86e6bce12cd" ascii fullword
		$s2 = "/startup" wide fullword
		$s3 = "ExportTests.dll" ascii wide fullword
		$s4 = "+<PayloadDownload>d__" ascii
		$s5 = "+<PayloadDownloadExecution>d__" ascii
		$f1 = "HttpWebResponse" ascii fullword
		$f2 = "set_UseShellExecute" ascii fullword
		$f3 = "set_CreateNoWindow" ascii fullword
		$f4 = "FromBase64String" ascii fullword
		$f5 = "set_ServerCertificateValidationCallback" ascii fullword
		$f6 = "AsyncTaskMethodBuilder" ascii fullword
		$f7 = "rangeDecoder" ascii fullword
		$f8 = "NumBitLevels" ascii fullword
		$f9 = "GetCallingAssembly" ascii fullword
		$f10 = "BlockCopy" ascii fullword
		$f11 = "MemoryStream" ascii fullword

	condition:
		uint16( 0 ) == 0x5a4d and filesize > 20KB and filesize < 120KB and $dotNet and ( ( ( 2 of ( $s* ) ) and ( 3 of ( $f* ) ) ) or ( all of ( $f* ) ) )
}

rule HARFANGLAB_Xdspy_Xdigo : FILE
{
	meta:
		description = "Rule to catch XDSpy Main module, written in golang"
		author = "HarfangLab"
		id = "d7df9c81-c237-5ee9-a368-fb8a90ac1889"
		date = "2025-05-16"
		modified = "2026-01-29"
		reference = "https://github.com/HarfangLab/iocs"
		source_url = "https://github.com/HarfangLab/iocs/blob/278c38e11e99d35af836cb9140e0857fd9226574/hl_public_reports_master.yar#L683-L710"
		license_url = "N/A"
		hash = "49714e2a0eb4d16882654fd60304e6fa8bfcf9dbd9cd272df4e003f68c865341"
		hash = "0d983f5fb403b500ec48f13a951548d5a10572fde207cf3f976b9daefb660f7e"
		hash = "3adeda2a154dcf017ffed634fba593f80df496eb2be4bee0940767c8631be7c1"
		logic_hash = "3d98768a15eda41b156355919d9876c3f4a9cf1f4a2207ad3e3a391255960438"
		score = 75
		quality = 80
		tags = "FILE"
		context = "file"

	strings:
		$a1 = "main.oooo_" ascii
		$b1 = "anti.go" ascii fullword
		$b2 = "crypto.go" ascii fullword
		$b3 = "file.go" ascii fullword
		$b4 = "main.go" ascii fullword
		$b5 = "net.go" ascii fullword
		$b6 = "log.go" ascii fullword
		$b7 = "settings.go" ascii fullword
		$b8 = "screenshot_windows.go" ascii fullword
		$c1 = "passwords.go" ascii fullword
		$c2 = "keylog.go" ascii fullword

	condition:
		uint16( 0 ) == 0x5a4d and filesize > 1MB and filesize < 15MB and #a1 > 100 and ( any of ( $c* ) or all of ( $b* ) )
}

rule SEKOIA_Infostealer_Win_Banditstealer : FILE
{
	meta:
		description = "Finds BanditStealer samples based on specific strings"
		author = "Sekoia.io"
		id = "d1e45a5c-c06d-4161-8d30-fa94bcf0ea7a"
		date = "2023-07-03"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/infostealer_win_banditstealer.yar#L1-L35"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "64d4860dd8a783be10541dd5c939dcd2a2b08309a7cd17b9dbbda1ba8b26485d"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$spe01 = "Banditstealer" ascii
		$spe02 = "BANDIT STEALER" ascii
		$spe03 = "Location: Geolocation: " ascii
		$spe04 = "awesomeProject2/core.GetWallets" ascii
		$spe05 = "awesomeProject2/core.GetCreditCards" ascii
		$spe06 = "awesomeProject2/core.GetCookies" ascii
		$spe07 = "awesomeProject2/core.KillProcessByName" ascii
		$spe08 = "main.sendZipToTelegram" ascii
		$str01 = "json:\"city\"" ascii
		$str02 = "UAC disabled" ascii
		$str03 = "\\OpenVPN Connect\\profiles\\" ascii
		$str04 = "\\Documents\\Monero\\wallets\\" ascii
		$str05 = "cookies.sqlite" ascii
		$str06 = "creditcard.txt" ascii
		$str07 = "vmware.exe" ascii
		$str08 = "aeachknmefphepccionboohckonoeemg" ascii
		$str09 = "\\Documents\\NetSarang\\Xftp\\Sessions\\" ascii
		$str10 = "\\WhatsApp\\Local Storage\\leveldb\\" ascii
		$str11 = "Visited Time: %s" ascii
		$str12 = "\\Google\\Chrome\\User Data\\Telegram Desktop\\tdata\\" ascii

	condition:
		uint16( 0 ) == 0x5a4d and 2 of ( $spe* ) and 6 of ( $str* )
}

rule SEKOIA_Loader_Amadey_Stealer_Plugin : FILE
{
	meta:
		description = "Finds Amadey's stealer plugin based on characteristic strings"
		author = "Sekoia.io"
		id = "50154e39-98b3-40e5-8986-18bbb7b15647"
		date = "2023-05-16"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/loader_amadey_stealer_plugin.yar#L1-L27"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "0410492f9424797b670a14f43ce063458e59d7958e213c07c3d488a40bf370e6"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$str01 = "STEALERDLL.dll" ascii
		$str02 = "?wal=1" fullword ascii
		$str03 = "Content-Disposition: form-data; name=\"data\"; filename=\"" ascii
		$str04 = "tar.exe -cf \"" ascii
		$str05 = "SELECT origin_url, username_value, password_value FROM logins" ascii
		$str06 = "\\Google\\Chrome\\User Data\\Default\\Login Data" ascii
		$str07 = "\\SputnikLab\\Sputnik\\User Data\\Default\\Login Data" ascii
		$str08 = "\\Mozilla\\Firefox\\Profiles\\" ascii
		$str09 = "\"hostname\":\"([^\"]+)\"" ascii
		$str10 = "\"encryptedUsername\":\"([^\"]+)\"" ascii
		$str11 = "\"encryptedPassword\":\"([^\"]+)\"" ascii
		$str12 = "&cred=" fullword ascii
		$str13 = "D:\\Mktmp\\Amadey\\StealerDLL\\x64\\Release\\STEALERDLL.pdb" ascii

	condition:
		uint16( 0 ) == 0x5A4D and 7 of them
}


rule SEKOIA_Infostealer_Win_Acridrain_Mar23 : FILE
{
	meta:
		description = "Finds AcridRain samples"
		author = "Sekoia.io"
		id = "049b502a-0fb6-4fa9-a1ce-f01a40269bdb"
		date = "2023-03-21"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/infostealer_win_acridrain_mar23.yar#L1-L40"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "7fa1822acc6264a3a58fffef3fc572f8818d99037b20d5abb8bfb41f025949d4"
		score = 75
		quality = 78
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$str01 = "\",\"r\":" ascii
		$str02 = "\",\"s\":\"" ascii
		$str03 = "\",\"p\":\"" ascii
		$str04 = "\",\"a\":\"" ascii
		$str05 = ",\"c\":" ascii
		$str06 = ",\"g\" :" ascii
		$str07 = "v7166637466625297979 t2537736810932639330 ath5ee645e0 altpriv cvcv=2 cexpw=1 smf=0" ascii
		$str08 = "Content-Type: multipart/form-data; boundary=----974767299852498929531610575" ascii
		$str09 = "\\Roaming\\Bitwarden\\data\\bitwarden.sqlite3" ascii
		$ste01 = "\\Roaming\\Exodus\\exodus.wallet" ascii
		$ste02 = "\\Roaming\\Electron Cash\\wallets" ascii
		$ste03 = "\\Roaming\\com.liberty.jaxx\\IndexedDB\\file__0.indexeddb.leveldb" ascii
		$ste04 = "\\Local Extension Settings\\" ascii
		$ste05 = "cnmamaachppnkjgnildpdmkaakejnhae" ascii
		$ste06 = "ffnbelfdoeiohenkjibnmadjiehjhajb" ascii
		$ste07 = "\\formhistory.sqlite" ascii
		$ste08 = "\\logins.json" ascii
		$ste09 = "encrypted_key" ascii
		$ste10 = "\\Login Data" ascii
		$enc01 = "bX5cVw8FKyAKZVxXXUAdSTUXCXdCV0FoOxoSF0ZEUEZS" ascii
		$enc02 = "bX5cVw8FKywUaVVbRlkyPAQAFCB1U0dV" ascii
		$enc03 = "bX5cVw8FKzQvUBFhRkYINSIWA3IRdlJADw==" ascii
		$enc04 = "bX5cVw8FKzYWdUVcWl8iCBU5NXBERl1dBTUiFgNyEXZSQA8=" ascii
		$enc05 = "bWBcVQMAGQI6UEJbGGgeGxgDD2xUQW9QCw8WEAp0" ascii

	condition:
		uint16( 0 ) == 0x5A4D and 5 of ( $str* ) and 7 of ( $ste* ) and 1 of ( $enc* )
}

rule SEKOIA_Infostealer_Win_Monster_Stub : FILE
{
	meta:
		description = "Finds Monster Stealer stub (Python payload) based on specific strings."
		author = "Sekoia.io"
		id = "10d27d49-79ae-4edc-8c30-35506bdf2c42"
		date = "2024-08-07"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/infostealer_win_monster_stub.yar#L1-L31"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "d6362c54b1f56ffa878423fbb1a3f57508d20e06b573c732f892494178a49200"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$str01 = "https://t.me/monster_free_cloud" ascii
		$str02 = "MonsterUpdateService" ascii
		$str03 = "Monster.exe" ascii
		$str04 = "schtasks /create /f /sc daily /ri 30 /tn" ascii
		$str05 = "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\" ascii
		$str06 = "banned_uuids" ascii
		$str07 = "banned_computer_names" ascii
		$str08 = "banned_process" ascii
		$str09 = "register_X_browsers" ascii
		$str10 = "register_payload" ascii
		$str11 = "tiktok_sessions.txt" ascii
		$str12 = "spotify_sessions.txt" ascii
		$str13 = "network_info.txt" ascii
		$str14 = "lolz.guru" ascii
		$str15 = "echo ####System Info####" ascii
		$str16 = "echo ####Firewallinfo####" ascii
		$str17 = "/injection/main/injection.js" ascii

	condition:
		uint16( 0 ) == 0x5A4D and 10 of them
}


rule SEKOIA_Hacktool_Ntospy_Strings : FILE
{
	meta:
		description = "Detects Ntospy based on strings"
		author = "Sekoia.io"
		id = "c3281666-6a31-4718-a9c0-82944c6fdcb0"
		date = "2023-12-05"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/hacktool_ntospy_strings.yar#L1-L19"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "e5bd963419e515d65a03592051822fd801f4a21d54cdb18d408556c4bfef78f5"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "NPGetCaps"
		$ = "NPLogonNotify"
		$ = {43 00 3A 00 5C 00 [10-150] 00 2E 00 6D 00 73 00 75}

	condition:
		uint16be( 0 ) == 0x4d5a and filesize < 300KB and all of them
}

rule SEKOIA_Stealer_Win_Demotryspy : FILE
{
	meta:
		description = "No description has been set in the source file - SEKOIA"
		author = "Sekoia.io"
		id = "70af0e40-b177-49a3-bff4-723f3f4aa375"
		date = "2024-02-09"
		modified = "2024-12-19"
		reference = "https://paper.seebug.org/3115/"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/stealer_win_demotryspy.yar#L1-L22"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "b7a910e4d394d2122e6b4fe76daa6691a642396e27f7a47d09232f4b7eb424ee"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$demotry1 = "DemoTry.exe"
		$demotry2 = "DemoTry\\Release\\DemoTry.pdb"
		$wide1 = "\\loc.tmp" wide
		$wide2 = "\\log.tmp" wide
		$wide3 = "\\Google\\Chrome\\User Data" wide
		$wide4 = "\\Default\\Login data" wide
		$wide5 = "\\Local State" wide

	condition:
		uint16be( 0 ) == 0x4d5a and ( 1 of ( $demotry* ) or all of ( $wide* ) )
}

rule SEKOIA_Infostealer_Win_Redline_Strings : FILE
{
	meta:
		description = "Finds Redline samples based on characteristic strings"
		author = "Sekoia.io"
		id = "0c9fcb0e-ce8f-44f4-90b2-abafcdd6c02e"
		date = "2022-09-07"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/infostealer_win_redline_strings.yar#L1-L47"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "44443e16b788231b3f256b4d1e91c458c33963d5737d69fc5850f6b0efa7726b"
		score = 75
		quality = 78
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$gen01 = "ChromeGetRoamingName" ascii
		$gen02 = "ChromeGetLocalName" ascii
		$gen03 = "get_UserDomainName" ascii
		$gen04 = "get_encrypted_key" ascii
		$gen05 = "browserPaths" ascii
		$gen06 = "GetBrowsers" ascii
		$gen07 = "get_InstalledInputLanguages" ascii
		$gen08 = "BCRYPT_INIT_AUTH_MODE_INFO_VERSION" ascii
		$spe0 = "Profile_encrypted_value" wide
		$spe1 = "[AString-ZaString-z\\d]{2String4}\\.[String\\w-]{String6}\\.[\\wString-]{2String7}" wide
		$spe2 = "AFileSystemntivFileSystemirusPrFileSystemoduFileSystemct|AntiFileSystemSpyWFileSystemareProFileSystemduct|FireFileSystemwallProdFileSystemuct" wide
		$spe3 = "OpHandlerenVPHandlerN ConHandlernect%DSK_23%Opera GXcookies" wide
		$spe4 = "//settinString.Removeg[@name=\\PasswString.Removeord\\]/valuString.RemoveeROOT\\SecurityCenter" wide
		$spe5 = "ROOT\\SecurityCenter2Web DataSteamPath" wide
		$spe6 = "windows-1251, CommandLine:" wide
		$spe7 = "OFileInfopeFileInfora GFileInfoX StabFileInfole" wide
		$spe8 = "ApGenericpDaGenericta\\RGenericoamiGenericng\\" wide
		$spe9 = "*wallet*" wide
		$typ01 = "359A00EF6C789FD4C18644F56C5D3F97453FFF20" ascii
		$typ02 = "F413CEA9BAA458730567FE47F57CC3C94DDF63C0" ascii
		$typ03 = "A937C899247696B6565665BE3BD09607F49A2042" ascii
		$typ04 = "D67333042BFFC20116BF01BC556566EC76C6F7E2" ascii
		$typ05 = "4E3D7F188A5F5102BEC5B820632BBAEC26839E63" ascii
		$typ06 = "FB10FF1AD09FE8F5CA3A85B06BC96596AF83B350" ascii
		$typ07 = "77A9683FAF2EC9EC3DABC09D33C3BD04E8897D60" ascii
		$typ08 = "A8F9B62160DF085B926D5ED70E2B0F6C95A25280" ascii
		$typ09 = "718D1294A5C2D3F3D70E09F2F473155C4F567201" ascii
		$typ10 = "2FBDC611D3D91C142C969071EA8A7D3D10FF6301" ascii
		$typ11 = "2A19BFD7333718195216588A698752C517111B02" ascii
		$typ12 = "EB7EF1973CDC295B7B08FE6D82B9ECDAD1106AF2" ascii
		$typ13 = "04EC68A0FC7D9B6A255684F330C28A4DCAB91F13" ascii

	condition:
		uint16( 0 ) == 0x5A4D and ( 7 of ( $gen* ) or 3 of ( $spe* ) or 2 of ( $typ* ) )
}

rule SEKOIA_Stealer_Win_Mgbot_Credential_Stealer : FILE
{
	meta:
		description = "Detect MgBot credential stealer plugin"
		author = "Sekoia.io"
		id = "e06501c1-c842-43f7-a429-9026bc0a4fd4"
		date = "2024-03-20"
		modified = "2024-12-19"
		reference = "https://www.welivesecurity.com/2023/04/26/evasive-panda-apt-group-malware-updates-popular-chinese-software/"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/stealer_win_mgbot_credential_stealer.yar#L1-L21"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "27f1b0ac818753804f0e67ac158d9376ab6beff8613ef94a1aa6cf8dd6815d49"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"
		hash1 = "174a62201c7e2af67b7ad37bf7935f064a379f169cf257ca16e912a46ecc9841"
		hash2 = "cb7d9feda7d8ebfba93ec428d5a8a4382bf58e5a70e4b51eb1938d2691d5d4a5"

	strings:
		$ = "Software\\Aerofox\\Foxmail\\Indenties" wide
		$ = "Software\\Aerofox\\FoxmailPreview" wide
		$ = "IMAP Password" wide
		$ = "POP3 Password" wide

	condition:
		uint16be( 0 ) == 0x4d5a and all of them
}

rule SEKOIA_Infostealer_Win_Enigma_Initial_Loader : FILE
{
	meta:
		description = "Find initial loader of Enigma Stealer based on specific strings"
		author = "Sekoia.io"
		id = "664fe8de-b406-4d63-9a4b-1c350b444f00"
		date = "2023-01-30"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/infostealer_win_enigma_initial_loader.yar#L1-L24"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		hash = "03b9d7296b01e8f3fb3d12c4d80fe8a1bb0ab2fd76f33c5ce11b40729b75fb23"
		logic_hash = "b7687a480a2a633e7cc9a60d62f3392011712bd018ed634927419cfb4edb4a78"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$str01 = "/getFile?file_id=" ascii
		$str02 = "/file/bot" ascii
		$str03 = "?file_id=" ascii
		$str04 = "pInternetSetOptionA failed" wide
		$str05 = "list_messages[file_path] failed" wide
		$str06 = "iE&xit" wide
		$str07 = "[GetTgFileById][GetTgRequest] reply is NULL" wide
		$str08 = "Telegram request failed" wide
		$str09 = "bot getted" wide

	condition:
		uint16( 0 ) == 0x5A4D and 4 of them
}

rule SEKOIA_Infostealer_Win_Blackguard_Mar23 : FILE
{
	meta:
		description = "Finds BlackGuard samples based on specific strings (March 2023, version 5)"
		author = "Sekoia.io"
		id = "65804d31-2a0c-4b22-a8d9-8cbe1497f155"
		date = "2023-03-27"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/infostealer_win_blackguard_mar23.yar#L1-L24"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "63d77808036478da0c8d38a6d3581ccd2d4e46ae16ec9e817f09f8b633b01843"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$str01 = "==================  5.0 ==============" wide
		$str02 = "/concerts/disk.php" wide
		$str03 = "/concerts/memory.php" wide
		$str04 = "/loader_v2.txt" wide
		$str05 = "io.solarwallet.app\\Local Storage\\leveldb" wide
		$str06 = "costura.dotnetzip.dll.compressed" ascii wide
		$str07 = "set_Laskakakaska" ascii
		$str08 = "get_Yliana" ascii
		$str09 = "set_Illeona" ascii
		$str10 = "set_Gyttettfd" ascii

	condition:
		uint16( 0 ) == 0x5A4D and 4 of them
}


rule SEKOIA_Win_Malware_Agnianestealer : FILE
{
	meta:
		description = "Detect the Agniane stealer using strings"
		author = "Sekoia.io"
		id = "704c85b7-8b82-4160-ae1b-fd1054cae8e2"
		date = "2023-08-10"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/win_malware_agnianestealer.yar#L1-L18"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "0aa40fcb713ab40711108290e8274d783c1336a2c4c03eba2fcc4a44f2ebe39f"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = "Agniane.pdb" ascii
		$s2 = "Agniane.exe" wide ascii

	condition:
		( uint16be( 0 ) == 0x4d5a ) and filesize > 100KB and filesize < 3MB and 2 of them
}

rule SEKOIA_Infostealer_Win_Raccoon_Str_Takemypainback : FILE
{
	meta:
		description = "Detect Raccoon based on specific strings"
		author = "Sekoia.io"
		id = "2148636e-47c7-4bf2-8d1e-df68faf65111"
		date = "2022-10-03"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/infostealer_win_raccoon_str_takemypainback.yar#L1-L19"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "50d30828dab7e197619eeac4ebd2ab6692a9ac40a5091e23642cd1bdde8e9910"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$str0 = "\\ffcookies.txt" wide
		$str1 = "TakeMyPainBack" wide
		$str2 = "wallet.dat" wide
		$str3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall" wide
		$str4 = "Network\\Cookies" wide

	condition:
		uint16( 0 ) == 0x5a4d and 4 of them
}

rule SEKOIA_Infostealer_Win_Mars_Stealer : FILE
{
	meta:
		description = "Detect Mars Stealer based on specific strings"
		author = "Sekoia.io"
		id = "3e2c7440b2fc9e4b039e6fa8152ac8fd"
		date = "2022-02-03"
		modified = "2024-12-19"
		reference = "https://3xp0rt.com/posts/mars-stealer"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/infostealer_win_mars_stealer.yar#L3-L44"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "b2b36a280c3c6cbbb8cbb9f1dd3eb48a4943ebbddb48eba2ac3d0db03924cafd"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		modification_date = "2022-02-14"
		classification = "TLP:CLEAR"

	strings:
		$dec = {a3 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? 00 00 83 c4 ??}
		$api00 = "LoadLibrary" ascii
		$api01 = "GetProcAddress" ascii
		$api02 = "ExitProcess" ascii
		$api03 = "advapi32.dll" ascii
		$api04 = "crypt32.dll" ascii
		$api05 = "GetTickCount" ascii
		$api06 = "Sleep" ascii
		$api07 = "GetUserDefaultLangID" ascii
		$api08 = "CreateMutex" ascii
		$api09 = "GetLastError" ascii
		$api10 = "HeapAlloc" ascii
		$api11 = "GetProcessHeap" ascii
		$api12 = "GetComputerName" ascii
		$api13 = "VirtualProtect" ascii
		$api14 = "GetUserName" ascii
		$api15 = "CryptStringToBinary" ascii
		$str0 = "JohnDoe" ascii

	condition:
		uint16( 0 ) == 0x5A4D and ( #dec > 400 and 12 of ( $api* ) and $str0 ) or for any i in ( 0 .. pe.number_of_sections -1 ) : ( pe.sections [ i ] . name == "LLCPPC" and pe.sections [ i ] . raw_data_size < 5000 )
}

rule SEKOIA_Infostealer_Win_Enigma_Stealer_Module : FILE
{
	meta:
		description = "Find stealer module of Enigma Stealer based on specific strings"
		author = "Sekoia.io"
		id = "664fe8de-b406-4d63-9a4b-1c350b444f02"
		date = "2023-01-30"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/infostealer_win_enigma_stealer_module.yar#L1-L28"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		hash = "4d2fb518c9e23c5c70e70095ba3b63580cafc4b03f7e6dce2931c54895f13b2c"
		logic_hash = "0a6615d65867a160e1c87fbcfe30090d44d7f5c25b3a904f8719be7b385b14bb"
		score = 75
		quality = 78
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$eni01 = "enigma.common" nocase ascii wide
		$eni02 = "--ENIGMA STEALER--" wide
		$str01 = "SELECT * FROM Win32_PnPEntity WHERE (PNPClass = 'Image' OR PNPClass = 'Camera')" wide
		$str02 = "/C chcp 65001 && netsh wlan show profile | findstr All" wide
		$str03 = "/C chcp 65001 && netsh wlan show networks mode=bssid" wide
		$str04 = "[Open google maps]" wide
		$str05 = "Stealerium.Target." ascii
		$str06 = "--- ClipperBCH ---" wide
		$str07 = "//setting[@name='Username']/value" wide
		$str08 = "Stealer >> Failed recursive remove directory with passwords" wide
		$str09 = "[a-zA-Z0-9]{24}\\.[a-zA-Z0-9]{6}\\.[a-zA-Z0-9_\\-]{27}|mfa\\.[a-zA-Z0-9_\\-]{84}" wide
		$str10 = "^(5018|5020|5038|6304|6759|6761|6763)[0-9]{8,15}$" wide

	condition:
		uint16( 0 ) == 0x5A4D and 1 of ( $eni* ) and 4 of ( $str* )
}

rule SEKOIA_Spyware_And_Fastfire : FILE
{
	meta:
		description = "Detect the FastFire malware"
		author = "Sekoia.io"
		id = "93c0ffd5-faa5-4ead-8848-1c44b459dc29"
		date = "2022-11-03"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/spyware_and_fastfire.yar#L1-L23"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "2600fc0a8fc6279936decf80256be1fc8cb581a59ef6646fe48b5885e104365e"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$funct1 = {22 00 87 18 70 20 f3 ae 40 00 6e 10 f4 ae 00 00 0c 04 1f 04 16 19 13 00 28 23 6e 20 e3 ae 04 00 12 10 6e 20 e5 ae 04 00 1a 00 25 19 6e 20 ea ae 04 00 28 05 0d 00 6e 10 ef ae 00 00 6e 10 da ae 04 00 6e 10 e1 ae 04 00 0a 00 13 01 c8 00 32 10 20 00 1c 00 ea 17 6e 10 73 ad 00 00 0c 00 22 01 60 18 70 10 5d ae 01 00 1a 02 ff 50 6e 20 69 ae 21 00 6e 10 e1 ae 04 00 0a 04 6e 20 64 ae 41 00 6e 10 72 ae 01 00 0c 04 71 20 1d 09 40 00}
		$funct2 = {22 00 77 00 1a 01 88 56 70 20 f1 02 10 00 15 01 00 10 6e 20 f4 02 10 00 1a 01 80 8d 6e 20 32 ae 13 00 0a 01 38 01 0b 00 1a 01 25 76 71 10 b3 06 01 00 0c 01 6e 20 22 03 10 00 1a 01 56 61 6e 20 32 ae 13 00 0a 01 38 01 0b 00 1a 01 23 76 71 10 b3 06 01 00 0c 01 6e 20 22 03 10 00 1a 01 55 66 6e 20 32 ae 13 00 0a 03 38 03 0b 00 1a 03 24 76 71 10 b3 06 03 00 0c 03 6e 20 22 03 30 00 13 03 64 00 15 01 00 08 71 40 07 02 32 10 0c 03 11 03}
		$s0 = "TokenResult{token="
		$s1 = "[-] Send Resp Code ="
		$s2 = "/report_token/report_token.php?token="
		$s3 = "naver"
		$s4 = "daum"
		$s5 = "facebook"

	condition:
		uint32be( 0 ) == 0x6465780A and ( 1 of ( $funct* ) or all of ( $s* ) )
}

rule SEKOIA_Infostealer_Win_Pennywise_Mar23 : FILE
{
	meta:
		description = "Finds PennyWise samples based on strings"
		author = "Sekoia.io"
		id = "9852b7e7-dfff-44e6-9068-d287cc84b069"
		date = "2023-03-22"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/infostealer_win_pennywise_mar23.yar#L1-L26"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "55d7d6894de23af38230eaaff0a38c31d11d3df34aacd21fd93393d266c9357c"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$chr01 = "MvgmsudRT3loHygSj1F9K" ascii
		$chr02 = "WebInfidelity2023" ascii
		$chr03 = "PennyWise" ascii
		$str01 = "get_Handle" ascii
		$str02 = "get_Now" ascii
		$str03 = "get_Ticks" ascii
		$str04 = "set_Expect100Continue" ascii
		$str05 = "get_Jpeg" ascii
		$str06 = "set_UseShellExecute" ascii
		$str07 = "get_ProcessName" ascii
		$str08 = "get_UtcNow" ascii

	condition:
		uint16( 0 ) == 0x5A4D and 1 of ( $chr* ) and 5 of ( $str* )
}

rule SEKOIA_Infostealer_Win_Fwit_Strings : FILE
{
	meta:
		description = "No description has been set in the source file - SEKOIA"
		author = "Sekoia.io"
		id = "332e89ad-d1fe-4da6-9354-0978ef173e78"
		date = "2023-06-22"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/infostealer_win_fwit_strings.yar#L1-L18"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "4e28b6d67e2087b2f28817b19812b8bd56227175cd3d9c7037290127d4ec05a5"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = "C:\\ProgramData\\Temp" wide
		$s2 = "{:08x}" wide
		$s3 = "CURL_SSLVERSION" ascii

	condition:
		( uint16be( 0 ) == 0x4d5a ) and all of them
}


rule SEKOIA_Infostealer_Win_Aurora_Str : FILE
{
	meta:
		description = "Finds Aurora botnet samples based on characteristic strings."
		author = "Sekoia.io"
		id = "1f4391b8-700f-4702-9ef6-68ce3d55a176"
		date = "2022-07-21"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/infostealer_win_aurora_str.yar#L3-L34"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "745443bb58f00cb09a1f323f530219913eaaf0d0e71c9a25af2072006f8c5f92"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$str01 = "Logs.tar" ascii
		$str02 = "*main.StealerData" ascii
		$str03 = "AppData\\Roaming\\Armory" ascii
		$str04 = "AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data" ascii
		$str05 = "github.com/TheTitanrain/w32" ascii
		$str06 = "github.com/mattn/go-sqlite3" ascii
		$str07 = "ScreenShot" ascii
		$str08 = "*sql.stmtConnGrabber" ascii
		$str09 = "Default\\Network\\Cookies" ascii
		$str10 = "BuildID" ascii
		$str11 = "Clipper" ascii
		$str12 = "GeoPos" ascii
		$str13 = "AppData\\Roaming\\Exodus\\exodus.wallet" ascii
		$str14 = "FileGrabber\\Documents" ascii
		$str15 = "193.233.48." ascii
		$str16 = "ShellExecute" ascii
		$str17 = "crypto/aes.(*aesCipherGCM).Encrypt" ascii
		$str18 = "File-Download" ascii

	condition:
		uint16( 0 ) == 0x5A4D and ( 14 of them or pe.imphash ( ) == "8ee5c1c09f740fbe63e8b35dac5d6f70" or pe.imphash ( ) == "369b4f5b6c99674f15070689e1f675af" )
}

rule SEKOIA_Infostealer_Win_Edgeguard : FILE
{
	meta:
		description = "Finds EdgeGuard Stealer samples based on specific strings"
		author = "Sekoia.io"
		id = "bbdb362f-d235-48f8-8fa5-d340d4e3e3f0"
		date = "2023-08-22"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/infostealer_win_edgeguard.yar#L1-L32"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "11396aea2e166456ec8311f95a8037aac41f69caf3158f8c19cb0c38327842d6"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$str01 = "main.downloadnecessary" ascii
		$str02 = "main.extractchromepasswords" ascii
		$str03 = "main.extracttasksch" ascii
		$str04 = "main.BrowserDownloadsViewExtract" ascii
		$str05 = "main.stealmetamask" ascii
		$str06 = "main.stealexoduswallet" ascii
		$str07 = "main.moveatomic" ascii
		$str08 = "main.movefirefoxcookies" ascii
		$str09 = "main.movepasswords" ascii
		$str10 = "main.FinallyZIPIPFolder" ascii
		$str11 = "edgeguard.business" ascii
		$str12 = "/License.XenArmor" ascii
		$str13 = "/TaskSchedulerView.exe" ascii
		$str14 = "/BrowsingHistoryView.exe" ascii
		$str15 = "/outlookfiles/starter.exe" ascii
		$str16 = "/outlookfiles/External.zip" ascii
		$str17 = "/outlookfiles/XenManager.dll" ascii
		$str18 = "/outlookfiles/EmailPasswordRecoveryPro.exe" ascii

	condition:
		uint16( 0 ) == 0x5a4d and 10 of ( $str* )
}

rule SEKOIA_Infostealer_Win_Enigma_Loader_Module : FILE
{
	meta:
		description = "Find loader module of Enigma Stealer based on specific strings"
		author = "Sekoia.io"
		id = "664fe8de-b406-4d63-9a4b-1c350b444f01"
		date = "2023-01-30"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/infostealer_win_enigma_loader_module.yar#L1-L25"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		hash = "f1623c2f7c00affa3985cf7b9cdf25e39320700fa9d69f9f9426f03054b4b712"
		logic_hash = "f5485b14291acc299d66b72aefd2d5e558d82f6a90450d293eb147f05423f2d8"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$str01 = "Enigma.Loader.Driver_x64.dll" ascii
		$str02 = "C:\\projects\\driver\\Driver\\x64\\Release\\driver.pdb" ascii
		$str03 = "/getFile?file_id=" ascii
		$str04 = "/file/bot" ascii
		$str05 = "Fatal error: failed to acquire SE_LOAD_DRIVER_PRIVILEGE. Make sure you are running as administrator." wide
		$str06 = "[GetTgFileById][GetTgRequest] reply is NULL" wide
		$str07 = "Telegram request failed" wide
		$str08 = "Vul driver data destroyed before unlink" wide
		$str09 = "GetExportAddress hash not found: %x" wide
		$str10 = "\\REGISTRY\\MACHINE\\HARDWARE\\RESOURCEMAP\\PnP Manager\\PnpManager" wide

	condition:
		uint16( 0 ) == 0x5A4D and 4 of them
}

rule SEKOIA_Infostealer_Win_Lighting : FILE
{
	meta:
		description = "Detect the Lighting infostealer based on specific strings"
		author = "Sekoia.io"
		id = "3c160c16-f417-4fa2-aa44-fb7b981fb2b3"
		date = "2022-04-07"
		modified = "2024-12-19"
		reference = "https://blog.cyble.com/2022/04/05/inside-lightning-stealer/"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/infostealer_win_lighting.yar#L1-L40"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "1c1d39ce886a433a352c55bf436b959ef528ad7ce38027243ed5b5f1ac79822f"
		score = 75
		quality = 78
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$str0 = "\\logins.json" wide
		$str1 = "key3.db" wide
		$str2 = "\\key4.db" wide
		$str3 = "cert9.db" wide
		$str4 = "\\places.sqlite" wide
		$str5 = "7D78CB380BF5EFB7B851409CA6A875F77DECF09D19B9149DA17A3EBF674BC0F9" ascii
		$str6 = "potentiallyVulnerablePasswords" wide
		$dll0 = "\\mozglue.dll" wide
		$dll1 = "\\nss3.dll" wide
		$dll2 = "SbieDll.dll" wide
		$app00 = "\\discord\\Local Storage\\leveldb\\" wide
		$app01 = "Software\\Valve\\Steam" wide
		$app02 = "Telegram Desktop\\tdata" wide
		$app03 = "\\Wallets\\Armory\\" wide
		$app04 = "\\Wallets\\Atomic\\Local Storage\\leveldb\\" wide
		$app05 = "\\Exodus\\exodus.wallet\\" wide
		$app06 = "\\Wallets\\Zcash\\" wide
		$app07 = "uCozMedia\\Uran" wide
		$app08 = "Comodo\\IceDragon" wide
		$app09 = "8pecxstudios\\Cyberfox" wide
		$app10 = "NETGATE Technologies\\BlackHaw" wide
		$app11 = "Moonchild Productions\\Pale Moon" wide

	condition:
		uint16( 0 ) == 0x5A4D and 6 of ( $str* ) and all of ( $dll* ) and 10 of ( $app* )
}

rule SEKOIA_Pe_Stealer_Scarletstealer_Strings : FILE
{
	meta:
		description = "ScarletStealer strings"
		author = "Sekoia.io"
		id = "ca930851-513f-44e5-abb4-ca0edfde3428"
		date = "2023-12-15"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/pe_stealer_scarletstealer_strings.yar#L1-L33"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "308055cbe960614112682585b5709a62c2639752df07661d6b2bb13e390b3b08"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = "Scarlet Client" wide
		$s2 = "] PC NAME:   (" wide
		$s3 = "] IP:   (" wide
		$s4 = " - Wallets -" wide
		$s5 = "] Exodus:  (" wide
		$s6 = "] Electrum:  (" wide
		$s7 = "] Atomic:  (" wide
		$s8 = "] Guarda:  (" wide
		$s9 = "] Coinomi: (" wide
		$s10 = "] Monero:  (" wide
		$s11 = "] Ledger:  (" wide
		$s12 = "] Bitbox:  (" wide
		$s13 = "] Trezor:  (" wide
		$s14 = ") Support: PointX@exploit.im - @isPointX" wide
		$a2 = "/config/tk.txt" wide
		$a3 = "/config/chatid.txt" wide
		$a1 = "telebyt.com" wide

	condition:
		uint16be( 0 ) == 0x4d5a and filesize > 50KB and filesize < 2MB and 13 of ( $s* ) and 2 of ( $a* )
}

rule SEKOIA_Infostealer_Win_Vidar_Strings_Nov23 : FILE
{
	meta:
		description = "Finds Vidar samples based on the specific strings"
		author = "Sekoia.io"
		id = "b2c17627-f9b8-4401-b657-1cce560edc76"
		date = "2023-11-10"
		modified = "2024-12-19"
		reference = "https://twitter.com/crep1x/status/1722652451319202242"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/infostealer_win_vidar_strings_nov23.yar#L1-L33"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "1a2fc421fb4058b78de28d97d69b126e685f7677b7998f5b6ae3cbcee0ef3f00"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$str01 = "MachineID:" ascii
		$str02 = "Work Dir: In memory" ascii
		$str03 = "[Hardware]" ascii
		$str04 = "VideoCard:" ascii
		$str05 = "[Processes]" ascii
		$str06 = "[Software]" ascii
		$str07 = "information.txt" ascii
		$str08 = "%s\\*" ascii
		$str09 = "Select * From AntiVirusProduct" ascii
		$str10 = "SELECT target_path, tab_url from downloads" ascii
		$str11 = "Software\\Martin Prikryl\\WinSCP 2\\Configuration" ascii
		$str12 = "UseMasterPassword" ascii
		$str13 = "Soft: WinSCP" ascii
		$str14 = "<Pass encoding=\"base64\">" ascii
		$str15 = "Soft: FileZilla" ascii
		$str16 = "passwords.txt" ascii
		$str17 = "build_id" ascii
		$str18 = "file_data" ascii

	condition:
		uint16( 0 ) == 0x5A4D and 10 of ( $str* )
}

rule SEKOIA_Infostealer_Win_Blustealer : FILE
{
	meta:
		description = "Detect the BluStealer infostealer based on characteristic strings"
		author = "Sekoia.io"
		id = "a56b3c12-9d83-4a0b-81e8-43332e64d599"
		date = "2022-10-05"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/infostealer_win_blustealer.yar#L1-L29"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "fc7c11a9ddd21228aa773da6054220211327727a87d48008b7edb202c48666d8"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$cha01 = "@top\\LOGGERS\\DARKCLOUD" wide
		$cha02 = "===============DARKCLOUD===============" wide
		$cha03 = "#######################################DARKCLOUD#######################################" wide
		$cha04 = "fireballsabadafirebricksfisherboat" ascii
		$cha05 = "Moonchild Pro2ductions" wide
		$str01 = "\\Microsoft\\Windows\\Templates\\credentials.txt" wide
		$str02 = "\\NETGATE Technologies\\BlackHawK\\Profiles" wide
		$str03 = "SysWOW64\\winsqlite3.dll" wide
		$str04 = "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*RD_" wide
		$str05 = "Expiry Date;" wide
		$str06 = "SELECT c0subject, c3author, c4recipients, c1body  FROM messagesText_content" wide
		$str07 = "http://www.mediacollege.com/internet/utilities/show-ip.shtml" wide
		$str08 = "\\163MailContacts.txt" wide
		$key_0 = {ba ?? ?? 40 00 8d 4?}

	condition:
		uint16( 0 ) == 0x5A4D and 2 of ( $cha* ) and 4 of ( $str* ) and $key_0
}

rule SEKOIA_Infostealer_Win_Phoenix : FILE
{
	meta:
		description = "Finds Phoenix Stealer samples based on specific strings"
		author = "Sekoia.io"
		id = "d63a8fcf-f897-4c36-a6ce-4bd4ae0154e5"
		date = "2023-06-20"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/infostealer_win_phoenix.yar#L1-L33"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "c8a3a9a36c978cfc28fc6e21af10894161279dfd2e2ad665c3296fda10f6303d"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$str01 = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii
		$str02 = "Discord\\Tokens.txt" ascii
		$str03 = "SOFTWARE\\OpenVP" ascii
		$str04 = "config_dir" ascii
		$str05 = "| Last Login:" ascii
		$str06 = "| Games:" ascii
		$str07 = "| Host:" ascii
		$str08 = "| Port:" ascii
		$str09 = "| User:" ascii
		$str10 = "| Pass:" ascii
		$str11 = "Grabber.rar" ascii
		$str12 = "\\GHISLER\\wcx_ftp.ini" ascii
		$str13 = "Clipboard.txt" ascii
		$str14 = "PROCESSOR_ARCHITECTURE" ascii
		$str15 = "PROCESSOR_IDENTIFIER" ascii
		$str16 = "Log.txt" ascii
		$str17 = "xXxXxXxXxXx" ascii
		$str18 = "hq101ejedmwcvvasd02kw" ascii

	condition:
		uint16( 0 ) == 0x5a4d and 15 of them and filesize > 500KB
}

rule SEKOIA_Typhon_Reborn_Stealer
{
	meta:
		description = "Typhon Reborn v2 string based detection"
		author = "Sekoia.io"
		id = "aab7279b-b651-4092-b988-d186d0a433de"
		date = "2023-05-15"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/typhon_reborn_stealer.yar#L3-L18"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "0db77a2e1d6b7274b0256fe469b72953c1b8598cbfc1715a43e5fbfa7899fe4c"
		score = 75
		quality = 80
		tags = ""
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = "api.telegram.org/bot" wide
		$s2 = "TyphonReborn Stealer v2 log!" wide

	condition:
		all of them and pe.is_pe
}

rule SEKOIA_Infostealer_Win_Stealc_Str_Oct24 : FILE
{
	meta:
		description = "Finds Stealc standalone samples (or dumps) based on the strings"
		author = "Sekoia.io"
		id = "7448fafe-206c-4f9c-b5a3-cbabec12a45b"
		date = "2024-10-20"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/infostealer_win_stealc_str_oct24.yar#L1-L27"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "4f7fece81c3fe1e56b57aed4030b48331b53443a200799046fe84c895b591a71"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$str01 = "-nop -c \"iex(New-Object Net.WebClient).DownloadString(" ascii
		$str02 = "Azure\\.IdentityService" ascii
		$str03 = "steam_tokens.txt" ascii
		$str04 = "\"encrypted_key\":\"" ascii
		$str05 = "prefs.js" ascii
		$str06 = "browser: FileZilla" ascii
		$str07 = "profile: null" ascii
		$str08 = "url:" ascii
		$str09 = "login:" ascii
		$str10 = "password:" ascii
		$str11 = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" ascii
		$str12 = "ChromeFuckNewCookies" ascii
		$str13 = "/c timeout /t 10 & del /f /q \"" ascii

	condition:
		uint16( 0 ) == 0x5A4D and 9 of them
}

rule SEKOIA_Infostealer_Win_Solarmarker_Dll : FILE
{
	meta:
		description = "Finds SolarMarker DLL based on characteristic strings"
		author = "Sekoia.io"
		id = "a2fe7f09-7134-4054-ba40-5ea66785a26c"
		date = "2022-12-09"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/infostealer_win_solarmarker_dll.yar#L1-L28"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "5be0a95adb7e486cdec5f0e8433afed41516fc1a990e1d1ba00db7e8fb32dbbb"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$zka = "zkabsr" wide
		$str0 = "set_PersistKeyInCsp" ascii
		$str1 = "get_IV" ascii
		$str2 = "get_MachineName" ascii
		$str3 = "get_Current" ascii
		$str4 = "ps_script" ascii
		$str5 = "request_data" ascii
		$str6 = "WindowsBuiltInRole" ascii
		$str7 = "DllImportAttribute" ascii
		$str8 = "get_BlockSize" ascii
		$str9 = "GetRequestStream" ascii

	condition:
		uint16( 0 ) == 0x5A4D and ( ( $zka and 3 of ( $str* ) ) or ( all of ( $str* ) ) ) and filesize < 1MB
}

rule SEKOIA_Infostealer_Win_44Caliber : FILE
{
	meta:
		description = "Finds samples of the 44Caliber stealer"
		author = "Sekoia.io"
		id = "44e5bbc1-f442-47d3-8431-25182f38439d"
		date = "2022-03-08"
		modified = "2024-12-19"
		reference = "https://github.com/razexgod/44CALIBER"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/infostealer_win_44caliber.yar#L1-L28"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "4b80d6b2116f53926897aa79a7c232413974caefaf524f50e6a7cede11f3aaa0"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$str0 = "44 CALIBER" fullword ascii
		$str1 = "https://api.vimeworld.ru/user/name/" wide
		$str2 = "https://freegeoip.app/xml/" wide
		$str3 = "SOFTWARE\\Wow6432Node\\Valve\\Steam" wide
		$str4 = "VPN\\NordVPN\\\\accounts.txt" wide
		$str5 = "OpenVPN Connect\\profiles" wide
		$str6 = "FuckTheSystem Copyright" wide
		$str7 = "lolz.guru" wide
		$str8 = "xss.is" wide
		$str9 = "Test message recieved successfully! :raised_hands:" wide
		$str10 = "Specify a single character: either D or F" wide

	condition:
		uint16( 0 ) == 0x5A4D and 9 of ( $str* ) and filesize > 100KB and filesize < 1MB
}

rule SEKOIA_Infostealer_Win_Blackcap : FILE
{
	meta:
		description = "Finds BlackCap Grabber samples (Python code obfuscated using Py-Fuscate)"
		author = "Sekoia.io"
		id = "1aa1fadb-3413-46e2-b733-1ad2134f7be2"
		date = "2023-03-06"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/infostealer_win_blackcap.yar#L1-L19"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "b826c88d557ea0a516534946ad9531eda1a875cb9c4ddf92d9b98f8c7b86623e"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$imp01 = "import asyncio, json, ntpath, random, re, shutil, sqlite3, subprocess, threading, winreg, zipfile, httpx, psutil, win32gui, win32con, pyperclip, base64, requests, ctypes, time" ascii
		$imp02 = "from ctypes import windll, wintypes, byref, cdll, Structure, POINTER, c_char, c_buffer;from Crypto.Cipher import AES;from PIL import ImageGrab;from win32crypt import CryptUnprotectData" ascii
		$pyf01 = "import marshal,lzma,gzip,bz2,binascii,zlib;exec(marshal.loads(binascii.a2b_base64(b'YwAAAAAA" ascii

	condition:
		($imp01 in ( 0 .. 500 ) and $pyf01 in ( @imp01 + 200 .. @imp01 + 1000 ) or $imp02 in ( 0 .. 1000 ) and $pyf01 in ( @imp02 + 100 .. @imp02 + 500 ) ) and filesize > 100KB and filesize < 500KB
}

rule SEKOIA_Spyware_And_Bahamut
{
	meta:
		description = "Detect Bahamut's spyware based on common information gathering function names"
		author = "Sekoia.io"
		id = "d416997e-baf1-412c-bf39-905a6e19b65e"
		date = "2022-11-23"
		modified = "2024-12-19"
		reference = "https://www.welivesecurity.com/2022/11/23/bahamut-cybermercenary-group-targets-android-users-fake-vpn-apps/"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/spyware_and_bahamut.yar#L1-L20"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "5f44c938fed9b32eaf183be979a67e0c7fde409e72875359105ad7ffb393893d"
		score = 75
		quality = 80
		tags = ""
		version = "1.0"
		classification = "TLP:CLEAR"
		hash1 = "c51dc2132c830c560aaeae4bf48e5f0d28c84b36d27840b5c2ba170d87f4afa5"
		hash2 = "d7e2cf642b236dba9ba0cbe5a9dc28baf22477973d5ce163e21ec40f5f26e078"

	strings:
		$ = "FbDao"
		$ = "SignalDao"
		$ = "conionDao"

	condition:
		all of them
}

rule SEKOIA_Infostealer_Win_Nemesis_In_Memory : FILE
{
	meta:
		description = "Finds Nemesis Stealer samples based on specific strings, from samples without strings obsucation, or from memory"
		author = "Sekoia.io"
		id = "01d85bd5-ea93-44ff-b36a-9cd9eb54d634"
		date = "2023-03-29"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/infostealer_win_nemesis_in_memory.yar#L1-L27"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "65d2dd9a10238e6d65d8992aa9cc145f73bcba9be49ed552f8b0c44723ec4c87"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$str01 = "NemesisProject.Modules." ascii
		$str02 = "~[NEMESIS INIZIALIZE]~" wide
		$str03 = "Clip_BoardText.txt" wide
		$str04 = "stealer_out.zip" wide
		$str05 = "<span style=\"color:#FFFFFF\">Number of running processes:</span>" wide
		$str06 = "<span style=\"color:#FFFFFF\">Installed FireWall: </span>" wide
		$str07 = "~[Panel_Receiving_Data]~ Incorrect data when receiving data on the panel" wide
		$str08 = "ProcessInfo_Log.txt" wide
		$str09 = "Installed_Software_Log.txt" wide
		$str10 = "Detect Data ClipBoard] - [ {DateTime.Now:MM.dd.yyyy - HH:mm:ss}]" wide
		$str11 = "VPN/ProtonVPN_Log.txt" wide
		$str12 = "VPN/Nord_Log.txt" wide
		$str13 = "Steam/SteamID_Log.txt" wide

	condition:
		uint16( 0 ) == 0x5A4D and 6 of them
}

rule SEKOIA_Infostealer_Win_Stormkitty_Exfil_Urls : FILE
{
	meta:
		description = "Detect the open-source StormKitty spyware by looking for the github path"
		author = "Sekoia.io"
		id = "d3b6e778-85da-4ab6-bc98-921897677485"
		date = "2022-04-20"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/infostealer_win_stormkitty_exfil_urls.yar#L1-L19"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "ccf0efe9ccba8e37bc19fa241e2d7698b1a798a3e8026b1b6930452b8a8ba9b4"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = "https://github.com/LimerBoy/StormKitty" ascii
		$telegram = "https://api.telegram.org" wide
		$discord = "https://cdn.discordapp.com" wide

	condition:
		uint16( 0 ) == 0x5A4D and all of them and ( #telegram > 3 or #discord > 3 )
}

rule SEKOIA_Infostealer_Win_Nosu : FILE
{
	meta:
		description = "Finds Nosu samples based on characteristic strings"
		author = "Sekoia.io"
		id = "9823af25-e30b-4514-a59c-02dd19fe368d"
		date = "2022-12-15"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/infostealer_win_nosu.yar#L1-L17"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "f18db2008aa9175fc423133fd6d5872c5750d011aad73c373505347443d5032c"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$str0 = "C:\\xampp\\htdocs\\nosu\\core\\release\\lilly.pdb" ascii
		$str1 = "{\"gp\":\"%s\",\"app\":\"%S\"," ascii
		$str2 = "stored in zip:\\%s" wide

	condition:
		uint16( 0 ) == 0x5A4D and 1 of them and filesize < 1MB
}

rule SEKOIA_Stealer_Win_Luca : FILE
{
	meta:
		description = "Detect Luca stealer. Open source Rust stealer."
		author = "Sekoia.io"
		id = "d2cc1442-0ba5-4e81-9fea-e9e078903eed"
		date = "2022-07-26"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/stealer_win_luca.yar#L3-L49"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "3694db49d84f92c70c51e4fe6f126fd56b3d7d8ed26619137fd55b0adb97865e"
		score = 75
		quality = 78
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "cookies"
		$ = "creditcards"
		$ = "/Default/Network/CookiesUser Data/Default/Network/Cookies_cookies"
		$ = "/Default/Web DataUser Data/Default/Web Data_webdata"
		$ = "SELECT action_url, username_value, password_value FROM loginsSELECT card_number_encrypted, name_on_card, expiration_month, expiration_year FROM credit_cardsSELECT host_key, name, encrypted_value, path, expires_utc, is_secure FROM cookiesLOCALAPPDATA"
		$ = "\\logsxc\\passwords_.txt"
		$ = " Name:"
		$ = "User: "
		$ = "Installed Languages:  "
		$ = "Operating System: "
		$ = "Used/Installed RAM:  GB "
		$ = "Cores available: "
		$ = "\\screen-.png"
		$ = "Username: "
		$ = "Computer name: "
		$ = "OS: "
		$ = "Language: "
		$ = "Hostname: "
		$ = "=> networks: B"
		$ = "=> system:total memory:  KB"
		$ = "used memory : "
		$ = "total swap  : "
		$ = "used swap   : "
		$ = "NB CPUs: "
		$ = "Passwords: "
		$ = "Wallets: "
		$ = "Files: "
		$ = "Credit Cards: "
		$ = "sensfiles.zip"

	condition:
		uint16( 0 ) == 0x5A4D and filesize > 4000KB and pe.rich_signature.toolid ( 0 , 0 ) and pe.number_of_resources == 0 and 15 of them
}

rule SEKOIA_Infostealer_Win_Doenerium_Str : FILE
{
	meta:
		description = "Detect the Doenerium infostealer based on specific strings"
		author = "Sekoia.io"
		id = "1645a86f-1063-4e98-a1fa-85fc8c4e9691"
		date = "2022-09-29"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/infostealer_win_doenerium_str.yar#L1-L29"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "9bc28d89ad2654c33f2ecd9736f5fb3a10dfc68dfef44ece6e628f5bb8db0800"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$str01 = "doenerium" ascii
		$str02 = "<================[   User Info   ]>================>" ascii
		$str03 = "<================[WiFi connections]>================>" ascii
		$str04 = "<================[Executable Info]>================>" ascii
		$str05 = "<================[ Network Data ]>================>" ascii
		$str06 = "\\Network Data.txt" ascii
		$str07 = "\\Update.exe\" --processStart" ascii
		$str09 = "\\WiFi Connections.txt" ascii
		$str10 = "\\User Info.txt" ascii
		$str11 = "\\Executable Info.txt" ascii
		$str12 = "\\Found Wallets.txt" ascii
		$str13 = "SELECT origin_url, username_value, password_value FROM logins" ascii
		$str14 = "https://cdn.discordapp.com/embed/avatars/0.png" ascii
		$str15 = "detectClipboard" ascii
		$str16 = ".gofile.io/uploadFile" ascii

	condition:
		uint16( 0 ) == 0x5A4D and 6 of them
}

rule SEKOIA_Infostealer_Win_Titan : FILE
{
	meta:
		description = "Finds samples of the Titan Stealer"
		author = "Sekoia.io"
		id = "0adbe616-0d91-4b05-b7a8-812cd79f9252"
		date = "2023-01-12"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/infostealer_win_titan.yar#L1-L25"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "996dc320c83f57c47afe50ad032bac43ad1fbfbbd5a86e517089a062b0382993"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$str0 = "/sendlog" ascii
		$str1 = "/stealer/grabfiles.go" ascii
		$str2 = "/stealer/installedsoft.go" ascii
		$str3 = "/stealer/screenshot.go" ascii
		$str4 = "/stealer/sendlog.go" ascii
		$str5 = "/stealer/userinformation.go" ascii
		$str6 = "C:/Program Files (x86)/Steam/config/" ascii
		$str7 = "/com.liberty.jaxx/IndexedDB/file__0.indexeddb.leveldb/" ascii
		$str8 = "MAC Adresses:" ascii
		$str9 = "/Coowon/Coowon/" ascii
		$str10 = "_/C_/Users/admin/Desktop/stealer_v7/stealer" ascii

	condition:
		uint16( 0 ) == 0x5A4D and 5 of them
}

rule SEKOIA_Infostealer_Win_Stormkitty : FILE
{
	meta:
		description = "Finds StormKitty samples (or their variants) based on specific strings"
		author = "Sekoia.io"
		id = "5014d2e5-af5c-4800-ab1e-b57de37a2450"
		date = "2023-03-29"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/infostealer_win_stormkitty.yar#L1-L31"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "57a4603faf6af9742db79f9bc8751f3a5c091b6271998434f0a3b9f5c30cb1e8"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$sk01 = "LimerBoy/StormKitty" ascii wide
		$sk02 = "StormKitty-Latest.log" wide
		$sk03 = "StormKitty.exe" ascii
		$sk04 = "Debug\\StormKitty.pdb" ascii
		$sk05 = "StormKitty.Implant" ascii
		$str01 = "set_sUsername" ascii
		$str02 = "set_sIsSecure" ascii
		$str03 = "set_sExpMonth" ascii
		$str04 = "WritePasswords" ascii
		$str05 = "WriteCookies" ascii
		$str06 = "sChromiumPswPaths" ascii
		$str07 = "sGeckoBrowserPaths" ascii
		$str08 = "Username: {1}" wide
		$str09 = "Password: {2}" wide
		$str10 = "encrypted_key\":\"(.*?)\"" wide

	condition:
		uint16( 0 ) == 0x5A4D and ( ( 1 of ( $sk* ) and 3 of ( $str* ) ) or 7 of ( $str* ) )
}

rule SEKOIA_Infostealer_Win_Bebra : FILE
{
	meta:
		description = "Find samples of Bebra Stealer based on specific strings"
		author = "Sekoia.io"
		id = "e84d04a7-1232-47e5-b797-ac8e56066796"
		date = "2023-02-06"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/infostealer_win_bebra.yar#L1-L26"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		hash = "7841746c54c53dbcafdf3f357c7a84b90fe3b089e07f30dea15ef6f7f15b0f00"
		logic_hash = "588fa3091f0dc565123c60d59479202d036e092499eca6204d420395ddc332f9"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$str01 = "https://studio.youtube.com/youtubei/v1/att/esr?alt=json&key=" ascii
		$str02 = "https://www.youtube.com/getAccountSwitcher" ascii
		$str03 = "\"challenge\":\"" ascii
		$str04 = "\"botguardResponse\":\"" ascii
		$str05 = "\"continueUrl\":\"https://studio.youtube.com/reauth\"," ascii
		$str06 = "\"flow\":\"REAUTH_FLOW_YT_STUDIO_COLD_LOAD\"," ascii
		$str07 = "\"xguardClientStatus\":0" ascii
		$str08 = "SAPISIDHASH" ascii
		$str09 = "system32\\cmd.exe /C choice /C Y /N /D Y /T 0 &Del" ascii
		$str10 = "/new.php" ascii
		$str11 = "github.com/mattn/go-sqlite3" ascii

	condition:
		uint16( 0 ) == 0x5A4D and 9 of them
}

rule SEKOIA_Infostealer_Win_Phoenixwave : FILE
{
	meta:
		description = "Detect the PhoenixWave infostealer based on specific strings"
		author = "Sekoia.io"
		id = "67c05ea8-2f1b-4c60-b108-e05d7d0c6508"
		date = "2022-04-07"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/infostealer_win_phoenixwave.yar#L1-L35"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "efeffb2f0df4c2f8156c401bac5f44c415c4c3e02e84e8db55dad68488f39fea"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$str0 = "##################################################\n                  Information\n##################################################\n" wide
		$str1 = "Specify a single character: either D or F" wide
		$str2 = "// This SFX source file was generated by DotNetZip " wide
		$str3 = "aHR0cDovL2lwLWFwaS5jb20vanNvbg==" wide
		$str4 = "TG9jYWxBcHBEYXRh" wide
		$str5 = "UGhvZW5peFdhdmU=" wide
		$str6 = "virustotal" wide
		$str7 = "SELECT * FROM win32_operatingsystem" wide
		$str8 = "SELECT * FROM Win32_VideoController" wide
		$app0 = "\\discordcanary\\Local Storage\\leveldb" wide
		$app1 = "\\discordptb\\Local Storage\\leveldb" wide
		$app2 = "\\discorddevelopment\\Local Storage\\leveldb" wide
		$app3 = "\\D877F783D5D3EF8C\\" wide
		$app4 = "\\IndexedDB\\file__0.indexeddb.leveldb" wide
		$app5 = "\\Steam\\Games.txt" wide
		$app6 = "nkbihfbeogaeaoehlefnkodbefgpgknn" wide
		$app7 = "fhbohimaelbohpjbbldcngcnapndodjp" wide
		$app8 = "fnjhmkhhmkbjkkabndcnnogagogbneec" wide
		$app9 = "\\Opera Software\\Opera GX Stable" wide

	condition:
		uint16( 0 ) == 0x5A4D and 7 of ( $str* ) and 8 of ( $app* )
}

rule SEKOIA_Infostealer_Win_Eternity : FILE
{
	meta:
		description = "Detect the Eternity infostealer based on specific strings"
		author = "Sekoia.io"
		id = "0ed8d4bd-d57f-40a8-a709-d69531d59847"
		date = "2022-03-23"
		modified = "2024-12-19"
		reference = "hxxp://xssforumv3isucukbxhdhwz67hoa5e2voakcfkuieq4ch257vsburuid.]onion/threads/62331/"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/infostealer_win_eternity.yar#L3-L31"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "06f0f7f51100278160f5bc4f588bb6a9d749be308f879bd5704666bf90764bf9"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$str0 = "Sending info to Eternity.." wide
		$str1 = "Debug mode, dont share this stealer anywhere." wide
		$str2 = "\\Growtopia.exe" wide
		$str3 = "Software\\Growtopia" wide
		$str4 = "Corrupting Growtopia.." wide
		$str5 = "Disabling Task Manager.." wide
		$str6 = "Deleting previous file from startup and copying new one." wide
		$str7 = "Hiding file in Startup folder.." wide
		$str8 = "Initializing File watcher.." wide
		$str9 = "Decoder: Failed to delete temp login. No problem, continuing.." wide
		$str10 = "dcd.exe" wide

	condition:
		uint16( 0 ) == 0x5A4D and ( for any i in ( 0 .. pe.number_of_sections -1 ) : ( pe.sections [ i ] . name == ".eter0" ) and for any i in ( 0 .. pe.number_of_sections -1 ) : ( pe.sections [ i ] . name == ".eter1" ) ) or 4 of ( $str* )
}

rule SEKOIA_Infostealer_Win_Ducklogs : FILE
{
	meta:
		description = "Detects DuckLogs based on specific strings"
		author = "Sekoia.io"
		id = "165c7d3d-de7e-4d71-b94a-8ab4a0e5ddd5"
		date = "2022-12-01"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/infostealer_win_ducklogs.yar#L1-L30"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "5db1a5595ec41488da620606bbcb36d0d686f9d6b7a0479439c53625df0886a0"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$dck = "DuckLogs" ascii wide
		$str01 = "CheckRemoteDebuggerPresent" ascii
		$str02 = "MozGlueNotFound" ascii
		$str03 = "get_DecryptedPassword" ascii
		$str04 = "get_Extension" ascii
		$str05 = "set_UseShellExecute" ascii
		$str06 = "FirefoxPasswords" ascii
		$str07 = "GetAllGeckoCookies" ascii
		$str08 = "GetAllBlinkDownloadsBy" ascii
		$str09 = "Grabbers" ascii
		$str10 = "Utility" ascii
		$str11 = "Persistance" ascii
		$str12 = "Clipboard" ascii
		$str13 = "WaterfoxGrabber" ascii
		$str14 = "AvastGrabber" ascii

	condition:
		uint16( 0 ) == 0x5A4D and ( ( #dck > 4 and 2 of ( $str* ) ) or 12 of them )
}

rule SEKOIA_Infostealer_Win_Stealerium : FILE
{
	meta:
		description = "Detects Stealerium based on specific strings"
		author = "Sekoia.io"
		id = "165c7d3d-de7e-4d71-b94a-8ab4a0e5ddd5"
		date = "2022-12-01"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/infostealer_win_stealerium.yar#L1-L36"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "f420848164ad4b6966f2a776a58d90b7d70c8b151a42d6f56b654f1700b5e564"
		score = 75
		quality = 78
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$stl = "Stealerium" ascii wide
		$str01 = "Processe: " wide
		$str02 = "Compname: " wide
		$str03 = "Language: " wide
		$str04 = "SandBoxie: " wide
		$str05 = "== System Info ==" wide
		$str06 = "== Hardware ==" wide
		$str07 = "== Domains ==" wide
		$str08 = "WEBCAMS COUNT: " wide
		$str09 = "[Virtualization]" wide
		$str10 = "[Open google maps](" wide
		$str11 = "Remember password: " wide
		$str12 = "Target.Browsers.Firefox" ascii
		$str13 = "Modules.Keylogger" ascii
		$str14 = "ClipperAddresses" ascii
		$str15 = "ChromiumPswPaths" ascii
		$str16 = "DetectedBankingServices" ascii
		$str17 = "DetectCryptocurrencyServices" ascii
		$str18 = "CheckRemoteDebuggerPresent" ascii
		$str19 = "GetConnectedCamerasCount" ascii
		$str20 = "costura.discord-webhook-client.dll.compressed" ascii wide

	condition:
		uint16( 0 ) == 0x5A4D and filesize > 1MB and ( ( #stl > 5 and 2 of ( $str* ) ) or 15 of ( $str* ) )
}

rule SEKOIA_Koi_Netstealer : FILE
{
	meta:
		description = "Detects NET ofbuscated Stealer used loaded by KoiLoader"
		author = "Sekoia.io"
		id = "deb06e2a-848c-44b3-be95-017ebccf11f8"
		date = "2024-03-20"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/koi_netstealer.yar#L1-L20"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "814db1092820ff1ed9e592dc92c72ad73643eb6d68df9f593ed637434373e41b"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$name_1 = "pg20"
		$name_2 = "pg40"
		$s1 = "Curve25519"
		$s2 = "ConsoleApp"
		$s3 = "e0d2eec7-eb14-48ba-8709-dcc9de65947d"

	condition:
		uint16be( 0 ) == 0x4d5a and filesize < 150KB and any of ( $name_* ) and all of ( $s* )
}

rule SEKOIA_Infostealer_Win_Xenostealer_Strings : FILE
{
	meta:
		description = "Finds XenoStealer standalone samples based on the strings"
		author = "Sekoia.io"
		id = "0a41788b-1fa7-44ff-af85-9c1ff1892aad"
		date = "2024-10-30"
		modified = "2024-12-19"
		reference = "https://github.com/moom825/XenoStealer/"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/infostealer_win_xenostealer_strings.yar#L1-L35"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		hash = "b74733d68e95220ab0630a68ddf973b0c959fd421628e639c1b91e465ba9299b"
		logic_hash = "1c48b15b8e9648c1c4d2f9c0a9ee3f4c48605fa44772b87a03ad81923e5adf15"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$str01 = "XenoStealer" ascii wide
		$str02 = "$d05de59c-9ee5-4e7e-abb5-8f2cc3f72cd1" ascii
		$str03 = "SteamInfo" ascii
		$str04 = "TelegramInfo" ascii
		$str05 = "NgrokInfo" ascii
		$str06 = "pAuthInfo" ascii
		$str07 = "FoxMailInfo" ascii
		$str08 = "_hasNitro" ascii
		$str09 = "_games" ascii
		$str10 = "_profiles" ascii
		$str11 = "_cookies" ascii
		$str12 = "_creditCards" ascii
		$str13 = "_cryptoExtensions" ascii
		$str14 = "_passwordManagerExtensions" ascii
		$str15 = "ChromiumBrowsersLikelyLocations" ascii
		$str16 = "EdgeCryptoExtensions" ascii
		$str17 = "ChromePasswordManagerExtensions" ascii
		$str18 = "GeckoBrowserOptions" ascii
		$str19 = "get_programFiles" ascii

	condition:
		uint16( 0 ) == 0x5A4D and 15 of them
}

rule SEKOIA_Infostealer_Win_Daolpu_Str : FILE
{
	meta:
		description = "Finds Daolpu Stealer samples based on specific strings."
		author = "Sekoia.io"
		id = "dde1cf12-48d8-45b6-b453-b7196e6b1271"
		date = "2024-07-23"
		modified = "2024-12-19"
		reference = "https://www.crowdstrike.com/blog/fake-recovery-manual-used-to-deliver-unidentified-stealer/"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/infostealer_win_daolpu_str.yar#L1-L26"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "9372a88efcdca6ca57f354fb31569522e5458271cc51dfedf09c6178a47a5b67"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$str01 = "Content-Type: %s%s%s" ascii
		$str02 = "Content-Disposition: %s%s%s%s%s%s%s" ascii
		$str03 = "\\CocCoc\\Browser\\User Data\\Local State" ascii
		$str04 = "\\Microsoft\\Edge\\User Data\\Default\\Login Data" ascii
		$str05 = "\\Mozilla\\Firefox\\Profiles" ascii
		$str06 = "No MAC Address Found" ascii
		$str07 = "C:\\Windows\\Temp\\" ascii
		$str08 = "C:\\Windows\\Temp\\result.txt" ascii
		$str09 = "Privatekey@2211#$" ascii
		$str10 = "CryptStringToBinaryA Failed to convert BASE64 private key." ascii
		$str11 = "taskkill /F /IM chrome.exe" ascii

	condition:
		uint16( 0 ) == 0x5A4D and 8 of them
}

rule SEKOIA_Infostealer_Win_Mars_Stealer_Xor_Routine : FILE
{
	meta:
		description = "Detect Mars Stealer based on a specific XOR routine"
		author = "Sekoia.io"
		id = "3e2c7440b2fc9e4b039e6fa8152ac8ff"
		date = "2022-04-06"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/infostealer_win_mars_stealer_xor_routine.yar#L1-L15"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "c7e65550a225431552e8a81bbce81dd66350021b6444c94fe7a37aa96712e9b1"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$xor = {8b 4d ?? 03 4d ?? 0f be 19 8b 55 ?? 52 e8 ?? ?? ?? ?? 83 c4 ?? 8b c8 8b 45 ?? 33 d2 f7 f1 8b 45 ?? 0f be 0c 10 33 d9 8b 55 ?? 03 55 ?? 88 1a eb be}

	condition:
		uint16( 0 ) == 0x5A4D and $xor
}

rule SEKOIA_Infostealer_Win_Xfiles : FILE
{
	meta:
		description = "Detect the X-FILES infostealer based on specific strings"
		author = "Sekoia.io"
		id = "3ad3ee19-6be8-484b-943c-05813cdcbd18"
		date = "2022-02-03"
		modified = "2024-12-19"
		reference = "https://twitter.com/3xp0rtblog/status/1375206169384521730"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/infostealer_win_xfiles.yar#L1-L50"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "404ee02fa1905f49c3c3ca525cfb3c5ba1d2ec46554239035c1891d21f547a2c"
		score = 75
		quality = 78
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$xfi0 = "Telegram bot - @XFILESShop_Bot" wide
		$xfi1 = "Telegram support - @XFILES_Seller" wide
		$brw0 = "\\Google\\Chrome\\User Data\\Default\\Network\\Cookies" wide
		$brw1 = "\\Chromium\\User Data\\Default\\Cookies" wide
		$brw2 = "\\Slimjet\\User Data\\Default\\Cookies" wide
		$brw3 = "\\Vivaldi\\User Data\\Default\\Cookies" wide
		$brw4 = "\\Opera Software\\Opera GX Stable\\Cookies" wide
		$brw5 = "\\Opera Software\\Opera Stable\\Cookies" wide
		$crp00 = "Tronlink" wide
		$crp01 = "NiftyWallet" wide
		$crp02 = "MetaMask" wide
		$crp03 = "MathWallet" wide
		$crp04 = "Coinbase" wide
		$crp05 = "BinanceChain" wide
		$crp06 = "GuardaWallet" wide
		$crp07 = "EqualWallet" wide
		$crp08 = "BitAppWallet" wide
		$crp09 = "iWallet" wide
		$crp10 = "Wombat" wide
		$crp11 = "Zcash" wide
		$crp12 = "Armory" wide
		$crp13 = "Bytecoin" wide
		$crp14 = "Jaxx" wide
		$crp15 = "Exodus" wide
		$crp16 = "Ethereum" wide
		$crp17 = "AtomicWallet" wide
		$crp18 = "Guarda" wide
		$crp19 = "Coinomi" wide
		$crp20 = "Litecoin" wide
		$crp21 = "Dash" wide
		$crp22 = "Bitcoin" wide

	condition:
		uint16( 0 ) == 0x5A4D and any of ( $xfi* ) or 5 of ( $brw* ) and 20 of ( $crp* )
}

rule SEKOIA_Infostealer_Win_Whitesnake_Stealer_Feb23 : FILE
{
	meta:
		description = "Finds WhiteSnake samples (stealer module)"
		author = "Sekoia.io"
		id = "68ae7fbc-4486-4b60-af5e-f37ddc58f170"
		date = "2023-03-01"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/infostealer_win_whitesnake_stealer_feb23.yar#L1-L31"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "90007c38c644b79b2a60d9a252bd95071c5be57c649d73b66a73a1158cddc2fb"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$fun01 = "Ibhiyptxjhiacrnxomvqjb" ascii
		$fun02 = "Irwcvmgzsduiiizaabbczm" ascii
		$whi = "WhiteSnake.Properties.Resources" ascii
		$str01 = "get_UtcNow" ascii
		$str02 = "get_IPAddress" ascii
		$str03 = "get_Ticks" ascii
		$str04 = "set_commands" ascii
		$str05 = "set_Information" ascii
		$str06 = "set_filedata" ascii
		$str07 = "get_Jpeg" ascii
		$str08 = "set_Culture" ascii
		$str09 = "MakeScreenshot" ascii

	condition:
		uint16( 0 ) == 0x5A4D and ( ( all of ( $fun* ) or $whi ) and 3 of ( $str* ) or 7 of ( $str* ) ) and filesize < 100KB
}

rule SEKOIA_Infostealer_Win_Nekostealer : FILE
{
	meta:
		description = "Detect the NekoStealer infostealer based on specific strings"
		author = "Sekoia.io"
		id = "8b7d2708-9d33-4855-8e02-f6afedb7dda8"
		date = "2023-01-24"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/infostealer_win_nekostealer.yar#L1-L20"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "f027775bebb48ceb128392040ec2ac8ad84f2a2009760c040e4d376c2f06b663"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$nek = "NekoStealer.Stealing" ascii
		$str01 = "\\Local Storage\\leveldb" wide
		$str02 = "======================= Discord Tokens =======================" wide
		$str03 = "======================== IP Information ========================" wide
		$str04 = "https://ipapi.co/" wide

	condition:
		uint16( 0 ) == 0x5A4D and ( #nek > 10 or all of ( $str* ) )
}

rule SEKOIA_Infostealer_Win_Meduzastealer : FILE
{
	meta:
		description = "Finds MeduzaStealer samples based on specific strings"
		author = "Sekoia.io"
		id = "1276f485-aa5d-491b-89d8-77f98dc496e1"
		date = "2023-06-20"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/infostealer_win_meduzastealer.yar#L1-L26"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "e81a5a9611662422eb7a87c0c1a370cee6f138fd6169225d969b669337d91a06"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$str01 = "emoji" ascii
		$str02 = "%d-%m-%Y, %H:%M:%S" ascii
		$str03 = "[UTC" ascii
		$str04 = "user_name" ascii
		$str05 = "computer_name" ascii
		$str06 = "timezone" ascii
		$str07 = "current_path()" ascii
		$str08 = "[json.exception." ascii
		$str09 = "GDI32.dll" ascii
		$str10 = "GdipGetImageEncoders" ascii
		$str11 = "GetGeoInfoA" ascii

	condition:
		uint16( 0 ) == 0x5a4d and 8 of them and filesize > 500KB
}

rule SEKOIA_Pe_Stealer_Axilestealer_Strings : FILE
{
	meta:
		description = "AxileStealer strings"
		author = "Sekoia.io"
		id = "412bfc3e-6bb7-4b0d-8bb3-96eae0cc9782"
		date = "2023-12-13"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/pe_stealer_axilestealer_strings.yar#L1-L28"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "829b80c07ed4d9439d66956dbb106aa0cc9961dd2e5c05ffbe6c67e516613590"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = "http://ip-api.com/line/?fields=query,country,countryCode,city,regionName,zip,isp" wide
		$s2 = "Axile.su" wide
		$s3 = "Unknown Tokens.txt" wide
		$a1 = "[ <b>General</b> ]" wide
		$a2 = "[ <b>Browsers</b> ]" wide
		$a3 = "[ <b>Wallets</b> ]" wide
		$a4 = "[ <b>Messengers</b> ]" wide
		$a5 = "[ <b>Applications</b> ]" wide
		$a6 = "[ <b>Games</b> ]" wide
		$a7 = "[ <b>Mails</b> ]" wide
		$a8 = "[ <b>VPNs</b> ]" wide
		$a9 = "[ <b>FTPs</b> ]" wide

	condition:
		uint16be( 0 ) == 0x4d5a and filesize > 50KB and filesize < 200KB and 2 of ( $s* ) and 7 of ( $a* )
}

rule SEKOIA_Infostealer_Win_Whitesnake_Loader_Feb23 : FILE
{
	meta:
		description = "Finds WhiteSnake samples (loader module, bat file)"
		author = "Sekoia.io"
		id = "f81a8a96-6fd2-4f5c-8a56-ff66ff1a80d3"
		date = "2023-03-01"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/infostealer_win_whitesnake_loader_feb23.yar#L1-L23"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "c9d4414fb17c28a3ea2e75837732e1657bdc7b2df4a7ab34e458d659441759e8"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$str01 = "echo         Please wait... a while Loading data ...." ascii
		$str02 = "CERTUTIL -f -decode" ascii
		$str03 = "%Temp%\\build.exe" ascii
		$crt = "-----BEGIN CERTIFICATE-----" ascii
		$mz = "TVqQAAMAAAAEAAAA" ascii

	condition:
		($str01 in ( 0 .. 200 ) or $str02 in ( 0 .. 200 ) or $str03 in ( 0 .. 200 ) ) and $mz in ( @crt .. @crt + 50 ) and filesize < 100KB
}

rule SEKOIA_Infostealer_Win_Irontiger_Chrome_Stealer : FILE
{
	meta:
		description = "Detect the chrome_stealer malware"
		author = "Sekoia.io"
		id = "8c5c3ed0-e1ea-4079-b330-ace8724bff2a"
		date = "2023-03-01"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/infostealer_win_irontiger_chrome_stealer.yar#L3-L32"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "dfddebf9623661508e993541106d4dcbb2270b311b2902567bd309810aff58dd"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = "passwords.txt"
		$ = "CryptUnprotectData: 0x%08x"
		$ = "cookies.txt"
		$ = "decrypt to %s"
		$ = ".\\chromedb_tmp" wide ascii
		$ = "SELECT ORIGIN_URL,USERNAME_VALUE,PASSWORD_VALUE FROM LOGINS;"
		$ = "decrypt successful!"
		$ = "url: %s"
		$ = "user: %s"
		$ = "pass: %s"
		$ = "aes key:"
		$ = "\\Google\\Chrome\\User Data\\Default\\Login Data" wide
		$ = "password file %s" wide
		$ = "cookies file %s" wide
		$ = "keyfile: %s" wide

	condition:
		( uint16( 0 ) == 0x5A4D and all of them ) or pe.imphash ( ) == "e862f5a6671f9dbd6f53d3d557e568f0"
}

rule SEKOIA_Infostealer_Win_Ginzostealer_Str : FILE
{
	meta:
		description = "Finds samples of the Ginzo Stealer"
		author = "Sekoia.io"
		id = "ef87e94b-9c53-44b4-b8a1-87d371a6d2cb"
		date = "2022-04-21"
		modified = "2024-12-19"
		reference = "https://blog.talosintelligence.com/2022/04/haskers-gang-zingostealer.html"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/infostealer_win_ginzostealer_str.yar#L1-L20"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "b1c811a13cf0f632ac839b6a6de050fc59ffe3ed0704545feff02e13521ea53f"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$str0 = "Ginzo.pdb" ascii
		$str1 = "Ginzo.exe" wide
		$str2 = "SELECT creation_utc,top_frame_site_key,host_key,name,value,encrypted_value,path,expires_utc,is_secure,is_httponly,last_access_utc,has_expires,is_persistent,priority,samesite,source_scheme,source_port,is_same_party FROM cookies" wide
		$str3 = "SELECT origin_url,action_url,username_element,username_value,password_element,password_value,submit_element,signon_realm,date_created,blacklisted_by_user,scheme,password_type,times_used,form_data,display_name,icon_url,federation_url,skip_zero_click,generation_upload_status,possible_username_pairs,id,date_last_used,moving_blocked_for,date_password_modified FROM logins" wide
		$str4 = "SELECT id,originAttributes,name,value,host,path,expiry,lastAccessed,creationTime,isSecure,isHttpOnly,inBrowserElement,sameSite,rawSameSite,schemeMap FROM moz_cookies" wide

	condition:
		uint16( 0 ) == 0x5A4D and 4 of them
}


rule SEKOIA_Win_Infostealer_Serpent_Strings : FILE
{
	meta:
		description = "Serpent Stealer string"
		author = "Sekoia.io"
		id = "ad9e2366-c95e-4090-a0db-48f3cc325209"
		date = "2023-12-04"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/win_infostealer_serpent_strings.yar#L1-L23"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "5266d1c8228f02e8ac9da5ddd8b968fde0d0e83afa408d405ec4ca50c3453928"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = "User Has SSH Dir." wide
		$s2 = "[+] Executing Wallets" wide
		$s3 = "'serpent' folder" wide
		$s4 = "Buddy Kys!!!" wide
		$s5 = "http://checkip.dyndns.org/" wide
		$s6 = "[+] Target has discord installed" wide
		$s7 = "Target has minecraft." wide

	condition:
		( uint16be( 0 ) == 0x4d5a ) and filesize < 100KB and 5 of them
}

rule SEKOIA_Infostealer_Win_Agrat : FILE
{
	meta:
		description = "No description has been set in the source file - SEKOIA"
		author = "Sekoia.io"
		id = "472effe8-5044-4ca1-88e0-3e19d445b9d1"
		date = "2022-06-01"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/infostealer_win_agrat.yar#L1-L27"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "5b02880dbc75d9e4d95ec55c8e8630a47198ee4cc25e3ff79c93e9fe634fadca"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$str00 = "Vault.txt" wide
		$str01 = "Credman.txt" wide
		$str02 = "[Networks] {0}" wide
		$str03 = "[Screenshot] {0}" wide
		$str04 = "[Twitch] {0}" wide
		$str05 = "Servers.txt" wide
		$str06 = "[WindscribeVPN] {0}" wide
		$str07 = "[{0}] Thread finished!" wide
		$str08 = "[ERROR] Unable to enumerate vaults. Error (0x" wide
		$str09 = "snowflake-ssh" wide
		$str10 = "//setting[@name='Password']/value" wide
		$str11 = "MakeScreenshot" ascii
		$sys = "System.Collections.Generic.IEnumerator<Stealer." ascii

	condition:
		uint16( 0 ) == 0x5A4D and all of them and #sys > 10
}


rule SEKOIA_Infostealer_Win_Acrstealer_Str : FILE
{
	meta:
		description = "Finds ACR Stealer standalone samples based on specific strings."
		author = "Sekoia.io"
		id = "63b4d6ff-0cab-44ec-9d53-bb2612371a48"
		date = "2024-04-22"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/infostealer_win_acrstealer_str.yar#L1-L29"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "53d313857577b39b51a3e396c078d39a8b8ab803295b689357c3e8ea94cac9f7"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$str01 = "ref.txt" ascii
		$str02 = "Wininet.dll" ascii
		$str03 = "Content-Type: application/octet-stream; boundary=----" ascii
		$str04 = "POST" ascii
		$str05 = "os_c" ascii fullword
		$str06 = "en_k" ascii fullword
		$str07 = "MyApp/1.0" ascii
		$str08 = "/Up/b" ascii
		$str09 = "Hello, World!" ascii
		$str10 = "/ujs/" ascii
		$str11 = "/Up/" ascii fullword
		$str12 = "ostr" ascii fullword
		$str13 = "brCH" ascii fullword
		$str14 = "brGk" ascii fullword
		$str15 = "https://steamcommunity.com/profiles/" ascii

	condition:
		uint16( 0 ) == 0x5A4D and 10 of them
}

rule SEKOIA_Infostealer_Win_Leaf : FILE
{
	meta:
		description = "Find samples of Leaf Stealer based on specific strings"
		author = "Sekoia.io"
		id = "17d8e384-1092-4f27-b4f7-c0c0f7efcaa3"
		date = "2023-02-07"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/infostealer_win_leaf.yar#L1-L32"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "f8c0ff694c9f7a02613000d85a40f6b400dcca60711e589f7ccd3546f571aea6"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$str01 = "Leaf $tealer" ascii
		$str02 = "KiwiFolder" ascii
		$str03 = "key_wordsFiles" ascii
		$str04 = "**[Click to copy](https://superfurrycdn.nl/copy/" ascii
		$str05 = "Early_Verified_Bot_Developer" ascii
		$str06 = "getCookie.<locals>.<genexpr>" ascii
		$str07 = "C:\\Program Files (x86)\\Steam\\config" ascii
		$str08 = "[crunchyroll](https://crunchyroll.com)" ascii
		$str09 = "-m pip install" ascii
		$str10 = "taskkill /im " ascii
		$str11 = "/loginusers.vdf" ascii
		$str12 = "mot_de_passe" ascii
		$str13 = "Interesting files found on user PC" ascii
		$str14 = "NationsGlory/Local Storage/leveldb" ascii
		$str15 = "wppassw.txt" ascii
		$str16 = "wpcook.txt" ascii
		$str17 = "ProcesName < 1 >" ascii
		$str18 = "Metamask_" ascii

	condition:
		uint16( 0 ) == 0x5A4D and 10 of them
}

rule SEKOIA_Infostealer_Win_Xehook_Str : FILE
{
	meta:
		description = "Finds XehookStealer standalone samples based on specific strings."
		author = "Sekoia.io"
		id = "fa76988d-f0a2-4fc2-a122-c104fd585f34"
		date = "2024-06-12"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/infostealer_win_xehook_str.yar#L1-L32"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "543ec3b523e5f00d3c285e453c8d11f3d5c7778b2986b7fe03f2d62ff18c2778"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$str01 = "xehook" ascii
		$str02 = "Classes.LogRecord" ascii
		$str03 = "__  _____| |__   ___   ___ | | __" wide
		$str04 = "\\ \\/ / _ \\ '_ \\ / _ \\ / _ \\| |/ /" wide
		$str05 = " >  <  __/ | | | (_) | (_) |   <" wide
		$str06 = "/_/\\_\\___|_| |_|\\___/ \\___/|_|\\_\\" wide
		$str07 = "https://t.me/xehook" wide
		$str08 = "About PC.txt" wide
		$str09 = "Browser: {4} v{5} ({6})" wide
		$str10 = "http://ip-api.com/json/?fields=11827" wide
		$str11 = "{0}gate.php?id={1}&build={2}&passwords={3}&cookies={4}" wide
		$str12 = "getjson.php?id=" wide
		$com01 = "CheckRemoteDebuggerPresent" ascii
		$com02 = "get_CurrentThread" ascii
		$com03 = "get_InstalledInputLanguages" ascii
		$com04 = "get_Ticks" ascii
		$com05 = "System.Security.Cryptography" ascii

	condition:
		uint16( 0 ) == 0x5A4D and 2 of ( $str* ) and 4 of ( $com* )
}


rule SEKOIA_Infostealer_Win_Aurora : FILE
{
	meta:
		description = "Finds Aurora samples based on characteristic strings"
		author = "Sekoia.io"
		id = "22ae81b4-647f-4b46-9b2a-dd96e0615d65"
		date = "2022-11-15"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/infostealer_win_aurora.yar#L1-L35"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "e88cbb012ffb65aa8a70b76163a834c0bc4615b0effc93945c6d915e33c04549"
		score = 75
		quality = 78
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$str00 = "I'm a teapot" ascii
		$str01 = "wmic cpu get name" ascii
		$str02 = "wmic path win32_VideoController get" ascii
		$str03 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Time Zones" ascii
		$str04 = "Exodus\\exodus.wallet" ascii
		$str05 = "PaliWallet" ascii
		$str06 = "cookies.sqlite" ascii
		$str07 = "Startup\\Documents\\User Data" ascii
		$str08 = "atomic\\Local Storage\\leveldb" ascii
		$str09 = "com.liberty.jaxx\\IndexedDB" ascii
		$str10 = "Guarda\\Local Storage\\leveldb" ascii
		$str11 = "AppData\\Roaming\\Telegram Desktop\\tdata" ascii
		$str12 = "Ethereum\\keystore" ascii
		$str13 = "Coin98" ascii
		$str14 = ".bat.cmd.com.css.exe.gif.htm.jpg.mjs.pdf.png.svg.xml.zip" ascii
		$str15 = "type..eq.main.Grabber" ascii
		$str16 = "type..eq.main.Loader_A" ascii
		$str17 = "type..eq.net/http.socksUsernamePassword" ascii
		$str18 = "powershell" ascii
		$str19 = "start-process" ascii
		$str20 = "http/httpproxy" ascii

	condition:
		uint16( 0 ) == 0x5A4D and 15 of them and filesize > 4MB
}

rule SEKOIA_Infostealer_Win_Cinoshistealer : FILE
{
	meta:
		description = "Finds Cinoshi Stealer samples based on specific strings, or PE resources"
		author = "Sekoia.io"
		id = "2e9c066b-d5e3-4a25-8954-c10af285bcd3"
		date = "2023-06-23"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/infostealer_win_cinoshistealer.yar#L1-L29"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "c4d8418a7bd1bf205295100d993562c89b17b80889cad5aac7a74f89e66543ce"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$str01 = "Anaida.exe" ascii wide
		$str02 = "Anaida.pdb" ascii
		$str03 = "embedder_download_data" ascii
		$str04 = "date_password_modified" ascii
		$str05 = "card_number_encrypted" ascii
		$str06 = "set_UseZip64WhenSaving" ascii
		$str07 = "set_CommandText" ascii
		$str08 = "Nss3CouldNotBeLoaded" ascii
		$str09 = "formhistory.sqlite" wide
		$str10 = "logins.json" wide
		$str11 = "\\nss3.dll" wide
		$str12 = "\\cookies.sqlite" wide
		$str13 = "\\places.sqlite" wide
		$str14 = "\\autofill-profiles.json" wide

	condition:
		uint16( 0 ) == 0x5a4d and 9 of them and filesize > 400KB
}

rule SEKOIA_Infostealer_Win_Vulturi : FILE
{
	meta:
		description = "Detect the Vulturi infostealer based on specific strings"
		author = "Sekoia.io"
		id = "5369cbfb-ff94-4484-b5a4-894feeed97e1"
		date = "2022-03-14"
		modified = "2024-12-19"
		reference = "https://lamp-ret.club/t/vulturi-cracked-by-tr0uble-and-eshelon_mayskih.193/"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/infostealer_win_vulturi.yar#L1-L35"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "2d442768499ea0d4b6f5ac0d85521d73bb8337a53f1641485b0ce0054e2dc91c"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$vul = "Vulturi_" ascii
		$str01 = "/C chcp 65001 && ping 127.0.0.1 && DEL /F /S /Q /A" wide
		$str02 = "SELECT ExecutablePath, ProcessID FROM Win32_Process" wide
		$str03 = "Apps\\Gaming\\Minecraft" wide
		$str04 = "Apps\\Gaming\\Steam\\Apps" wide
		$str05 = "Messengers\\Facebook\\Contacts.txt" wide
		$str06 = "Messengers\\Discord\\Tokens.txt" wide
		$str07 = "Apps\\VPN\\NordVPN\\accounts.txt" wide
		$str08 = "Apps\\VPN\\DUC\\credentials.txt" wide
		$str09 = "System\\Screenshots\\Webcam.png" wide
		$str10 = "System\\Screenshots\\Desktop.png" wide
		$str11 = "GTA San Andreas User Files\\SAMP\\USERDATA.DAT" wide
		$str12 = "http://ip-api.com/line?fields=query" wide
		$str13 = "Wireshark" wide
		$str14 = "KeePass.config.xml" wide
		$str15 = "Apps\\TheBat!" wide
		$str16 = "Vulturi" wide
		$str17 = "StealerStub" wide

	condition:
		uint16( 0 ) == 0x5A4D and ( #vul > 50 or 12 of ( $str* ) )
}

rule SEKOIA_Infostealer_Win_Spacestealer : FILE
{
	meta:
		description = "Detects SpaceStealer based on specific strings"
		author = "Sekoia.io"
		id = "aceae3b3-1f5a-48b4-84cb-d0ba68d26df5"
		date = "2022-11-29"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/infostealer_win_spacestealer.yar#L1-L31"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "94edfd0606816ff01d1345357a852cab4321d8881921e51ba96d8d2d4cb893b5"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$str01 = "spacestealerxD" ascii
		$str02 = "\\spacex" ascii
		$str03 = "@~$~@spacex-" ascii
		$str04 = "StealerClient" ascii
		$str05 = "kill-process-by-name" ascii
		$str06 = "\\BetterDiscord\\data\\betterdiscord.asar" ascii
		$str07 = "api/webhooks" ascii
		$str08 = "discordPath" ascii
		$str09 = "SELECT host_key, name, encrypted_value FROM cookies" ascii
		$str10 = "SELECT origin_url, username_value, password_value FROM logins" ascii
		$str11 = "SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards" ascii
		$str12 = "Cookies don't found." ascii
		$str13 = "/api/cookies?auth=" ascii
		$str14 = "/api/passwords?auth=" ascii
		$str15 = "/api/autofill?auth=" ascii
		$str16 = "/api/creditcards?auth=" ascii
		$str17 = "\\Yandex\\YandexBrowser\\User Data\\Guest Profile\\Network\\" ascii

	condition:
		uint16( 0 ) == 0x5A4D and filesize > 10MB and 13 of them
}

rule SEKOIA_Radx_Stealer : FILE
{
	meta:
		description = "detection of RADX stealer based on function named in the .NET payload"
		author = "Sekoia.io"
		id = "bf2aae08-169c-4bc9-a1ac-80f4b79ef6d7"
		date = "2023-12-22"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/radx_stealer.yar#L1-L20"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "b83ca089bb0ea7ad8b0f372de9a95ea9d35514f6a063b63986e6fd25bdc07095"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$s1 = "get_FileName" ascii fullword
		$s2 = "set_FileName" ascii fullword
		$f1 = "TripleDESCryptoServiceProvider" ascii fullword
		$f2 = "SendBase64ToServer" ascii fullword
		$f3 = "SendCommandOutputToServer" ascii fullword

	condition:
		( uint32be( 0 ) == 0x7f454c46 or uint16be( 0 ) == 0x4d5a ) and filesize > 500KB and all of them
}

rule SEKOIA_Infostealer_Win_Mars_Stealer_Variant_Llcppc1 : FILE
{
	meta:
		description = "Detect Mars Stealer variand llcppc1"
		author = "Sekoia.io"
		id = "3e2c7440b2fc9e4b039e6fa8152ac8fe"
		date = "2022-03-10"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/infostealer_win_mars_stealer_variant_llcppc1.yar#L1-L15"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "f9d92338fa31c38648b72d7f9a953201c7e498237bc9d02d6247d1882d1e3432"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$a = {ff 15 ?? ?? ?? ?? 89 45 ?? 6a 14 68 ?? ?? ?? ?? ff 75 ?? e8 23 00 00 00 ff 75 ?? ff 75 ?? ff 75 ?? e8 5c 00 00 00}

	condition:
		uint16( 0 ) == 0x5A4D and $a
}

rule SEKOIA_Infostealer_Win_Whitesnake_Xor_Rc4_July12 : FILE
{
	meta:
		description = "Detects WhiteSnake Stealer XOR and RC4 version"
		author = "Sekoia.io"
		id = "f2ebfcbd-9667-459a-a543-ce0be62c0dc4"
		date = "2023-07-12"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/infostealer_win_whitesnake_xor_rc4_july12.yar#L1-L20"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "f14b95e5cb6ffaab14d0890847fe6e9dcfc3ee0b884c34d24d786420e2411a80"
		score = 75
		quality = 76
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$1 = {FE 0C 00 00 FE 09 00 00 FE 0C 02 00 6F ?? 00 00 0A FE 0C 03 00 61 D1 FE 0E 04 00 FE}
		$2 = {61 6e 61 6c 2e 6a 70 67}
		$3 = {73 68 69 74 2e 6a 70 67}
		$4 = {FE 0C ?? 00 20 00 01 00 00 3F ?? FF FF FF 20 00 00 00 00 FE 0E ?? 00 38 ?? 00 00 00 FE 0C}
		$5 = "qemu" wide
		$6 = "vbox" wide

	condition:
		($1 and $2 and filesize < 600KB ) or ( $3 and $4 and $5 and $6 and filesize < 300KB )
}

rule SEKOIA_Infostealer_Win_Lumma_Strings_Aug23 : FILE
{
	meta:
		description = "Finds Lumma samples based on the specific strings"
		author = "Sekoia.io"
		id = "728f7825-a463-4b19-b2d3-3460e4c06dc9"
		date = "2023-09-14"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/infostealer_win_lumma_strings_aug23.yar#L1-L23"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "704a31b0f7c30602305768f13bf6108ebaf08c62451833731d2f2f020efce386"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$str01 = "lid=%s&j=%s&ver" ascii
		$str02 = "%s (%d.%d.%d)" ascii
		$str03 = "- Screen Resoluton:" ascii
		$str04 = "- Physical Installed Memory:" ascii
		$str05 = "Content-Type: attachment/x-object" ascii
		$str06 = "Content-Type: application/x-www-form-urlencoded" ascii
		$str07 = "Content-Type: multipart/form-data; boundary=%s" wide
		$str08 = "SysmonDrv" wide
		$str09 = "TeslaBrowser/5.5" wide

	condition:
		uint16( 0 ) == 0x5A4D and 6 of them
}


rule SEKOIA_Infostealer_Win_Vidar_Str_Jul22 : FILE
{
	meta:
		description = "Detect the Vidar infostealer based on specific strings"
		author = "Sekoia.io"
		id = "1dc18694-aaac-41e6-979a-c06d5d62f5ea"
		date = "2022-07-26"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/infostealer_win_vidar_str_jul22.yar#L1-L29"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "394d148155d46753df188a252678c5ce9d0aa321da8907e74b844d5aa8494a47"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		modification_date = "2022-08-23"
		classification = "TLP:CLEAR"

	strings:
		$str01 = "vcruntime140.dll" ascii
		$str02 = "\\screenshot.jpg" ascii
		$str03 = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor" ascii
		$str04 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall" ascii
		$str05 = "%s\\%s\\%s\\chrome-extension_%s_0.indexeddb.leveldb" ascii
		$str06 = "\\CC\\%s_%s.txt" ascii
		$str07 = "\\Autofill\\%s_%s.txt" ascii
		$str08 = "\\History\\%s_%s.txt" ascii
		$str09 = "\\Downloads\\%s_%s.txt" ascii
		$str10 = "Content-Disposition: form-data; name=" ascii
		$str11 = "Exodus\\exodus.wallet" ascii
		$str12 = "*%DRIVE_REMOVABLE%*" ascii
		$opc = {55 8b ec 51 56 8b 75 ?? 33 c0 c7 46 14 ?? ?? ?? ?? 89 46 ?? 68 ?? ?? ?? ?? 8b ce 89 45 ?? 88 06 e8 1f b6 ff ff 8b c6 5e c9 c2 ?? ??}

	condition:
		uint16( 0 ) == 0x5A4D and ( 7 of them or $opc )
}

rule SIGNATURE_BASE_SUSP_MAL_EXFIL_Stealer_Output_Characteristics_Sep22_1 : FILE
{
	meta:
		description = "Detects typical stealer output files as created by RedLine or Racoon stealer"
		author = "Florian Roth (Nextron Systems)"
		id = "c1cab3c3-c4f3-5a19-9ea3-9e4242238359"
		date = "2022-09-17"
		modified = "2023-12-05"
		reference = "https://twitter.com/cglyer/status/1570965878480719873"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/crime_stealer_exfil_zip.yar#L2-L30"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "197bb4b837cdd635f9340547b10a90c3a2a17f0113076c5ccbc0a91b7ae18eeb"
		score = 70
		quality = 85
		tags = "FILE"
		hash1 = "8ce14c6b720281f43c75ce52e23ec13d08e7b2be1c5fbc2d704238f1fdd1a07f"
		hash2 = "011c19d18fa446a2619b3a2512dacb2694e1da99a2c2ea7828769f1373ecd8fe"
		hash3 = "418530bc7210f74ada8e7f16b41ea2033054e99f0c4423ce1d3ebf973c89e3a3"
		hash4 = "aa6e2c8447f66527f9b6f4d54f57edc6cabe56095df94dc0656dca02e11356ab"
		hash5 = "bbfb608061931565debac405ffebe3c4bb5dac8042443fe4e80aa03395955bd2"
		hash6 = "c15107beecf3301fb12d140690034717e16bd5312a746e7ff43a7925e5533260"

	strings:
		$sa1 = "passwords.txt" ascii
		$sa2 = "autofills/" ascii
		$sa3 = "browsers/cookies/" ascii
		$sa4 = "wallets/" ascii
		$sb1 = "Passwords.txt" ascii
		$sb2 = "Autofills/" ascii
		$sb3 = "Browsers/Cookies/" ascii
		$sb4 = "Wallets/" ascii

	condition:
		uint16( 0 ) == 0x4b50 and filesize < 5000KB and ( 2 of ( $sa* ) or 2 of ( $sb* ) )
}

rule SIGNATURE_BASE_HKTL_NET_GUID_RAT_Telegramspybot : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "57d22201-a051-5040-927c-30da3fc684fd"
		date = "2020-12-13"
		modified = "2025-08-15"
		reference = "https://github.com/SebastianEPH/RAT.TelegramSpyBot"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/gen_github_net_redteam_tools_guids.yar#L1855-L1868"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "9fc671ef600548d962a2d5ab12ba3111ed19e83ef96d2d536eb343bb8fb4b0d2"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "8653fa88-9655-440e-b534-26c3c760a0d3" ascii wide

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule SIGNATURE_BASE_HKTL_NET_GUID_Ispykeylogger : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "8607de67-b472-5afc-b2b9-cc758b5ec474"
		date = "2020-12-13"
		modified = "2025-08-15"
		reference = "https://github.com/mwsrc/iSpyKeylogger"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/gen_github_net_redteam_tools_guids.yar#L2225-L2241"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "0c0b0a8d53efc5e922f73eec7550e6927f19aaef950921fde95b7bd651adeec7"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "ccc0a386-c4ce-42ef-aaea-b2af7eff4ad8" ascii wide
		$typelibguid1lo = "816b8b90-2975-46d3-aac9-3c45b26437fa" ascii wide
		$typelibguid2lo = "279b5533-d3ac-438f-ba89-3fe9de2da263" ascii wide
		$typelibguid3lo = "88d3dc02-2853-4bf0-b6dc-ad31f5135d26" ascii wide

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule SIGNATURE_BASE_HKTL_NET_GUID_Stealer : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "c721a0ac-e898-52aa-9bdf-a19bc0bd783d"
		date = "2020-12-29"
		modified = "2025-08-15"
		reference = "https://github.com/malwares/Stealer"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/gen_github_net_redteam_tools_guids.yar#L3848-L3863"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "37f829449b4f8a9524400d9409b985fab2ff70024a88fdd96ba391956a3398e3"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "8fcd4931-91a2-4e18-849b-70de34ab75df" ascii wide
		$typelibguid1lo = "e48811ca-8af8-4e73-85dd-2045b9cca73a" ascii wide
		$typelibguid2lo = "d3d8a1cc-e123-4905-b3de-374749122fcf" ascii wide

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule SIGNATURE_BASE_MAL_Katz_Stealer_May25 : FILE
{
	meta:
		description = "Detects Katz stealer"
		author = "MalGamy (Nextron Systems)"
		id = "efa42aec-b653-5e94-8d5b-73f0aab2a54d"
		date = "2025-05-16"
		modified = "2025-05-22"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/mal_katz_stealer.yar#L1-L21"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		hash = "fdc86a5b3d7df37a72c3272836f743747c47bfbc538f05af9ecf78547fa2e789"
		hash = "d92bb6e47cb0a0bdbb51403528ccfe643a9329476af53b5a729f04a4d2139647"
		logic_hash = "73364c2291dc792f46858dda057f08805db55fe1f1e54d6b0dee0a0c8a412259"
		score = 80
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "Motherboard Product: %s" ascii
		$s2 = "cmd.exe /c %s" ascii
		$s3 = "reg export \"%s\" \"%s\" /y" ascii
		$s4 = ").request({ hostname: '" ascii
		$s5 = "Type: Removable"
		$s6 = "%s\\Microsoft\\Windows Live Mail" ascii

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 300KB and 4 of them
}

rule SIGNATURE_BASE_MAL_NET_Katz_Stealer_Loader_May25
{
	meta:
		description = "Detects .NET based Katz stealer loader"
		author = "Jonathan Peters (cod3nym)"
		id = "90e86bb2-ffb2-5968-9cdc-705efac73b0d"
		date = "2025-05-21"
		modified = "2025-05-22"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/mal_katz_stealer.yar#L65-L84"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		hash = "0df13fd42fb4a4374981474ea87895a3830eddcc7f3bd494e76acd604c4004f7"
		logic_hash = "1922520d8c34660a0afff2f552ef0d1c6ec093fb10a00816e0216f574b686221"
		score = 80
		quality = 85
		tags = ""

	strings:
		$x = "ExecutarMetodoVAI" ascii
		$s1 = "VirtualMachineDetector" ascii
		$s2 = "Wow64SetThreadContext_API" ascii
		$s3 = "nomedoarquivo" ascii
		$s4 = { 65 78 74 65 6E C3 A7 61 6F 00 }
		$s5 = "payloadBuffer" ascii
		$s6 = "caminhovbs" ascii

	condition:
		3 of ( $s* ) or $x
}

rule SIGNATURE_BASE_MAL_DLL_Stealer_Nov23 : CVE_2023_4966 FILE
{
	meta:
		description = "Detects a DLL that steals authentication credentials - was seen being used by LockBit 3.0 affiliates exploiting CVE-2023-4966"
		author = "X__Junior"
		id = "9cfed8ec-1d04-53d7-88ef-2576075cfc33"
		date = "2023-11-23"
		modified = "2023-12-05"
		reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-325a"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_ransom_lockbit_citrixbleed_nov23.yar#L41-L54"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "7d0c46d855973cb2c0636aed9c67cfbe47ca260ab1bc842fef1d532725c26910"
		score = 80
		quality = 85
		tags = "CVE-2023-4966, FILE"
		hash1 = "17a27b1759f10d1f6f1f51a11c0efea550e2075c2c394259af4d3f855bbcc994"

	strings:
		$op1 = { C7 45 ?? 4D 69 6E 69 C7 45 ?? 44 75 6D 70 C7 45 ?? 57 72 69 74 C7 45 ?? 65 44 75 6D C7 45 ?? 70 00 27 00 C7 45 ?? 44 00 62 00 C7 45 ?? 67 00 68 00 C7 45 ?? 65 00 6C 00 C7 45 ?? 70 00 2E 00 C7 45 ?? 64 00 6C 00 C7 45 ?? 6C 00 00 00}

	condition:
		uint16( 0 ) == 0x5a4d and all of them
}

rule SIGNATURE_BASE_HKTL_Koh_Tokenstealer : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project."
		author = "Will Schroeder (@harmj0y)"
		id = "76b6cc9f-5db7-5e9b-939c-e713bad8137a"
		date = "2022-07-09"
		modified = "2023-12-05"
		reference = "https://github.com/GhostPack/Koh"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/gen_hktl_koh_tokenstealer.yar#L2-L18"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "e2c4d948e23f1a3a92689f35fedde6e041d09cd88deac9ff3249556be0b8f789"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$x_typelibguid = "4d5350c8-7f8c-47cf-8cde-c752018af17e" ascii
		$s1 = "[*] Already SYSTEM, not elevating" wide fullword
		$s2 = "S-1-[0-59]-\\d{2}-\\d{8,10}-\\d{8,10}-\\d{8,10}-[1-9]\\d{2}" wide
		$s3 = "0x[0-9A-Fa-f]+$" wide
		$s4 = "\\Koh.pdb" ascii

	condition:
		uint16( 0 ) == 0x5A4D and 1 of ( $x* ) or 3 of them
}

rule SIGNATURE_BASE_MAL_Compromised_Cert_Ducktail_Stealer_Jun23 : FILE
{
	meta:
		description = "Detects binaries signed with compromised certificates used by DuckTail stealer - identified in June 2023"
		author = "dr4k0nia"
		id = "b491e1b6-42c4-58e9-8efa-19e697804f96"
		date = "2023-06-16"
		modified = "2023-08-12"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/mal_ducktail_compromised_certs_jun23.yar#L2-L37"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "9b7916700359d662e99003727f5293f5a937254ff265c3bc8bb8763e196daa0e"
		score = 80
		quality = 85
		tags = "FILE"
		hash1 = "17c75f2d14af9f00822fc1dba00ccc9ec71fc50962e196d7e6f193f4b2ee0183"
		hash2 = "b3cfdb442772d07a7f037b0bb093ba315dfd1e79b0e292736c52097355495270"
		hash3 = "9afe013cae0167993a6a7ccd650eb1221a5ec163110565eb3a49a8b57949d4ee"

	strings:
		$sx1 = "AZM MARKETING COMPANY LIMITED" ascii fullword
		$sx2 = "CONG TY TNHH" ascii
		$sx3 = {43 C3 94 4E 47 20 54 59 20 54 4E 48 48 20}
		$sx4 = "CONG TY TRACH" ascii
		$se1 = {65 78 BE 85 2D 48 E3 3D 4E 48 B8 D4 73 F5 B7 60}
		$se2 = {1D 53 38 32 74 2B 58 37 87 C0 A2 53 32 F7 FB 06}
		$se3 = {00 BD 7B 85 B2 6A 69 C9 7D 6D 68 CC 95 67 34 C0 6B}
		$se4 = {06 5F 5C 57 0B D6 A7 98 92 FB B0 E6 34 61 3A 4D}
		$se5 = {41 55 3F 07 13 37 11 7A 99 B4 58 57}
		$se6 = {1E AA E4 CE E7 EE 89 FB 20 32 59 27 88 13 D8 53}
		$se7 = {56 DC DB 85 D4 89 F9 87 B2 D6 76 72}
		$se8 = {2D A4 50 57 C2 74 3C 1A 3C A4 93 7A}
		$se9 = {37 AE 95 F5 4C 8E 9B D0 B6 47 68 6A}
		$se10 = {3D C8 F5 3B 62 7A 34 07 AC 7E 01 00 13 87 A3 B3}
		$se11 = {01 C9 87 5A 5F A8 59 68 6D 34 17 C9}
		$se12 = {1B 35 19 E1 CD C2 6B 57 DA EE 06 C9}
		$se13 = {79 7D 0B 5E 22 AA 0F C7 A2 97 E6 48}
		$se14 = {57 9E 5C 89 B0 85 A7 96 B3 3C F3 19}

	condition:
		uint16( 0 ) == 0x5a4d and 1 of ( $sx* ) and 1 of ( $se* )
}
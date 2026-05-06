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

rule DEADBITS_Dacls_Trojan_Windows : FILE
{
	meta:
		description = "No description has been set in the source file - DeadBits"
		author = "Adam Swanda"
		id = "424b2c0d-2373-5a72-9a97-52b4bfc5cdcf"
		date = "2020-01-07"
		modified = "2020-01-07"
		reference = "https://github.com/deadbits/yara-rules"
		source_url = "https://github.com/deadbits/yara-rules//blob/d002f7ecee23e09142a3ac3e79c84f71dda3f001/rules/Dacls_Windows.yara#L1-L30"
		license_url = "N/A"
		logic_hash = "b77df7e3be9c264d6a63d40dbf49c41e9dd55b4e570c063b5710b849c36cc166"
		score = 75
		quality = 80
		tags = "FILE"
		Author = "Adam M. Swanda"

	strings:
		$fext00 = ".exe" ascii wide
		$fext01 = ".cmd" ascii wide
		$fext02 = ".bat" ascii wide
		$fext03 = ".com" ascii wide
		$str00 = "Software\\mthjk" ascii wide
		$str01 = "WindowsNT.dll" ascii fullword
		$str02 = "GET %s HTTP/1.1" ascii fullword
		$str03 = "content-length:" ascii fullword
		$str04 = "Connection: keep-alive" ascii fullword
		$cls00 = "c_2910.cls" ascii fullword
		$cls01 = "k_3872.cls" ascii fullword

	condition:
		( uint16( 0 ) == 0x5a4d ) and ( ( all of ( $cls* ) ) or ( all of ( $fext* ) and all of ( $str* ) ) )
}

rule DEADBITS_Dacls_Trojan_Linux
{
	meta:
		description = "No description has been set in the source file - DeadBits"
		author = "Adam Swanda"
		id = "bb83ba2b-70a3-5a0f-9588-d93b7f07f67f"
		date = "2020-01-07"
		modified = "2020-01-07"
		reference = "https://github.com/deadbits/yara-rules"
		source_url = "https://github.com/deadbits/yara-rules//blob/d002f7ecee23e09142a3ac3e79c84f71dda3f001/rules/Dacls_Linux.yara#L1-L32"
		license_url = "N/A"
		logic_hash = "752d7daf9178e4fa20f2ce781c6ff70f83758f01479696f0808e1588da9a3d78"
		score = 75
		quality = 80
		tags = ""
		Author = "Adam M. Swanda"

	strings:
		$cls00 = "c_2910.cls" ascii fullword
		$cls01 = "k_3872.cls" ascii fullword
		$str00 = "{\"result\":\"ok\"}" ascii fullword
		$str01 = "SCAN  %s  %d.%d.%d.%d %d" ascii fullword
		$str02 = "/var/run/init.pid" ascii fullword
		$str03 = "/flash/bin/mountd" ascii fullword
		$str04 = "Name:" ascii fullword
		$str05 = "Uid:" ascii fullword
		$str06 = "Gid:" ascii fullword
		$str08 = "PPid:" ascii fullword
		$str09 = "session_id" ascii fullword

	condition:
		uint32be( 0x0 ) == 0x7f454c46 and ( ( all of ( $cls* ) ) or ( all of ( $str* ) ) )
}

rule FIREEYE_RT_Trojan_MSIL_GORAT_Module_Powershell_1 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'RedFlare - Module - PowerShell' project."
		author = "FireEye"
		id = "b0fba130-9cd9-5b7f-a806-9ff8099f5731"
		date = "2020-12-08"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/REDFLARE (Gorat)/production/yara/Trojan_MSIL_GORAT_Module_PowerShell_1.yar#L4-L16"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "dd8805d0e470e59b829d98397507d8c2"
		logic_hash = "e596bc0316a4ef85f04c2683ebc7c94bf9b831843232c33e62c84991e4caeb97"
		score = 75
		quality = 71
		tags = "FILE"
		rev = 1

	strings:
		$typelibguid0 = "38d89034-2dd9-4367-8a6e-5409827a243a" ascii nocase wide
		$typelibguid1 = "845ee9dc-97c9-4c48-834e-dc31ee007c25" ascii nocase wide

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule FIREEYE_RT_Trojan_MSIL_GORAT_Plugin_DOTNET_1 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'RedFlare - Plugin - .NET' project."
		author = "FireEye"
		id = "faa73d64-4bb1-5c06-a3a5-1f1aa99ea932"
		date = "2020-12-08"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/REDFLARE (Gorat)/production/yara/Trojan_MSIL_GORAT_Plugin_DOTNET_1.yar#L4-L16"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "dd8805d0e470e59b829d98397507d8c2"
		logic_hash = "e979822273c6d1ccdfebd341c9e2cb1040fe34a04e8b41c024885063fd946ad5"
		score = 75
		quality = 71
		tags = "FILE"
		rev = 1

	strings:
		$typelibguid0 = "cd9407d0-fc8d-41ed-832d-da94daa3e064" ascii nocase wide
		$typelibguid1 = "fc3daedf-1d01-4490-8032-b978079d8c2d" ascii nocase wide

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule FIREEYE_RT_Trojan_Win64_Generic_23 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "470bfeed-e000-58c6-b115-dfa8aea25bef"
		date = "2020-12-02"
		date = "2020-12-02"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/EXCAVATOR/supplemental/yara/Trojan_Win64_Generic_23.yar#L4-L22"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "b66347ef110e60b064474ae746701d4a"
		logic_hash = "4c1860801b26abbab8c4aea730bf69f388c902083b9945e11e6782af3ab22789"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$api1 = "VirtualAllocEx" fullword
		$api2 = "UpdateProcThreadAttribute" fullword
		$api3 = "DuplicateTokenEx" fullword
		$api4 = "CreateProcessAsUserA" fullword
		$inject = { 8B 85 [4] C7 44 24 20 40 00 00 00 41 B9 00 30 00 00 44 8B C0 33 D2 48 8B 8D [4] FF 15 [4] 48 89 45 ?? 48 83 7D ?? 00 75 ?? 48 8B 45 ?? E9 [4] 8B 85 [4] 48 C7 44 24 20 00 00 00 00 44 8B C8 4C 8B 85 [4] 48 8B 55 ?? 48 8B 8D [4] FF 15 [4] 85 C0 75 ?? 48 8B 45 ?? EB ?? 8B 85 [4] 48 8B 4D ?? 48 03 C8 48 8B C1 48 89 45 48 48 8D 85 [4] 48 89 44 24 30 C7 44 24 28 00 00 00 00 48 8B 85 [4] 48 89 44 24 20 4C 8B 4D ?? 41 B8 00 00 10 00 33 D2 48 8B 8D [4] FF 15 }
		$process = { 48 C7 44 24 30 00 00 00 00 48 C7 44 24 28 00 00 00 00 48 C7 44 24 20 08 00 00 00 4C 8D 8D [4] 41 B8 00 00 02 00 33 D2 48 8B 8D [4] FF 15 [4] 85 C0 75 ?? E9 [4] 48 8B 85 [4] 48 89 85 [4] 48 8D 85 [4] 48 89 44 24 50 48 8D 85 [4] 48 89 44 24 48 48 C7 44 24 40 00 00 00 00 48 C7 44 24 38 00 00 00 00 C7 44 24 30 04 00 08 00 C7 44 24 28 00 00 00 00 48 C7 44 24 20 00 00 00 00 45 33 C9 4C 8D 05 [4] 33 D2 48 8B [2-5] FF 15 }
		$token = { FF 15 [4] 4C 8D 45 ?? BA 0A 00 00 00 48 8B C8 FF 15 [4] 85 C0 75 ?? E9 [4] 48 8D [2-5] 48 89 44 24 28 C7 44 24 20 02 00 00 00 41 B9 02 00 00 00 45 33 C0 BA 0B 00 00 00 48 8B 4D ?? FF 15 [4] 85 C0 75 ?? E9 [4] 4C 8D 8D [4] 45 33 C0 BA 01 00 00 00 33 C9 FF 15 }

	condition:
		(( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x020B ) ) and all of them
}

rule FIREEYE_RT_Trojan_Win64_Generic_22 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "e79661a8-5254-5e8e-b92b-edf1ddb072ff"
		date = "2020-11-26"
		date = "2020-11-26"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/EXCAVATOR/supplemental/yara/Trojan_Win64_Generic_22.yar#L4-L22"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "f7d9961463b5110a3d70ee2e97842ed3"
		logic_hash = "52fbe5c0ee7c05df5fcd62c26caaa5498e32352da9c5940e522aa31d6c808028"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 2

	strings:
		$api1 = "VirtualAllocEx" fullword
		$api2 = "UpdateProcThreadAttribute" fullword
		$api3 = "DuplicateTokenEx" fullword
		$api4 = "CreateProcessAsUserA" fullword
		$inject = { C7 44 24 20 40 00 00 00 33 D2 41 B9 00 30 00 00 41 B8 [4] 48 8B CB FF 15 [4] 48 8B F0 48 85 C0 74 ?? 4C 89 74 24 20 41 B9 [4] 4C 8D 05 [4] 48 8B D6 48 8B CB FF 15 [4] 85 C0 75 [5-10] 4C 8D 0C 3E 48 8D 44 24 ?? 48 89 44 24 30 44 89 74 24 28 4C 89 74 24 20 33 D2 41 B8 [4] 48 8B CB FF 15 }
		$process = { 89 74 24 30 ?? 8D 4C 24 [2] 89 74 24 28 33 D2 41 B8 00 00 02 00 48 C7 44 24 20 08 00 00 00 48 8B CF FF 15 [4] 85 C0 0F 84 [4] 48 8B [2-3] 48 8D 45 ?? 48 89 44 24 50 4C 8D 05 [4] 48 8D 45 ?? 48 89 7D 08 48 89 44 24 48 45 33 C9 ?? 89 74 24 40 33 D2 ?? 89 74 24 38 C7 44 24 30 04 00 08 00 [0-1] 89 74 24 28 ?? 89 74 24 20 FF 15 }
		$token = { FF 15 [4] 4C 8D 44 24 ?? BA 0A 00 00 00 48 8B C8 FF 15 [4] 85 C0 0F 84 [4] 48 8B 4C 24 ?? 48 8D [2-3] 41 B9 02 00 00 00 48 89 44 24 28 45 33 C0 C7 44 24 20 02 00 00 00 41 8D 51 09 FF 15 [4] 85 C0 0F 84 [4] 45 33 C0 4C 8D 4C 24 ?? 33 C9 41 8D 50 01 FF 15 }

	condition:
		(( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and ( uint16( uint32( 0x3C ) + 0x18 ) == 0x020B ) ) and all of them
}

rule FIREEYE_RT_APT_Trojan_Win_REDFLARE_5 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "892981d6-f310-5ee8-95b5-dd4bd720a86c"
		date = "2020-12-01"
		date = "2020-12-01"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/REDFLARE/production/yara/APT_Trojan_Win_REDFLARE_5.yar#L4-L20"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "dfbb1b988c239ade4c23856e42d4127b, 3322fba40c4de7e3de0fda1123b0bf5d"
		logic_hash = "ab38e5ebded026829672941709797b40f8e13fb244b6a8ed3545de4358f727b8"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 3

	strings:
		$s1 = "AdjustTokenPrivileges" fullword
		$s2 = "LookupPrivilegeValueW" fullword
		$s3 = "ImpersonateLoggedOnUser" fullword
		$s4 = "runCommand" fullword
		$steal_token = { FF 15 [4] 85 C0 [1-40] C7 44 24 ?? 01 00 00 00 [0-20] C7 44 24 ?? 02 00 00 00 [0-20] FF 15 [4] FF [1-5] 85 C0 [4-40] 00 04 00 00 FF 15 [4-5] 85 C0 [2-20] ( BA 0F 00 00 00 | 6A 0F ) [1-4] FF 15 [4] 85 C0 74 [1-20] FF 15 [4] 85 C0 74 [1-20] ( 6A 0B | B9 0B 00 00 00 ) E8 }

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule FIREEYE_RT_APT_Trojan_Win_REDFLARE_2 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "84881e5c-05df-5911-af42-ec82e559588c"
		date = "2020-11-27"
		date = "2020-11-27"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/REDFLARE/production/yara/APT_Trojan_Win_REDFLARE_2.yar#L4-L20"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "9529c4c9773392893a8a0ab8ce8f8ce1,05b99d438dac63a5a993cea37c036673"
		logic_hash = "1f2e1f644b1932486444dfda30b7dad7f50121f59fa493eb8a1a0528ae46db26"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 2

	strings:
		$1 = "initialize" fullword
		$2 = "getData" fullword
		$3 = "putData" fullword
		$4 = "fini" fullword
		$5 = "Cookie: SID1=%s" fullword

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule FIREEYE_RT_APT_Trojan_Win_REDFLARE_7 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "f891e477-9ff2-57be-9ca5-dd87d9baee29"
		date = "2020-12-02"
		date = "2020-12-02"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/REDFLARE/production/yara/APT_Trojan_Win_REDFLARE_7.yar#L4-L21"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "e7beece34bdf67cbb8297833c5953669, 8025bcbe3cc81fc19021ad0fbc11cf9b"
		logic_hash = "6d7822256ac1bef05304d3396df773e2b20a397311ad820d6ec5fe4cb6bdfbbc"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$1 = "initialize" fullword
		$2 = "getData" fullword
		$3 = "putData" fullword
		$4 = "fini" fullword
		$5 = "NamedPipe"
		$named_pipe = { 88 13 00 00 [1-8] E8 03 00 00 [20-60] 00 00 00 00 [1-8] 00 00 00 00 [1-40] ( 6A 00 6A 00 6A 03 6A 00 6A 00 68 | 00 00 00 00 [1-6] 00 00 00 00 [1-6] 03 00 00 00 45 33 C? 45 33 C? BA ) 00 00 00 C0 [2-10] FF 15 [4-30] FF 15 [4-7] E7 00 00 00 [4-40] FF 15 [4] 85 C0 }

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule FIREEYE_RT_APT_Trojan_Win_REDFLARE_3 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "2f6785c4-f4d0-52ff-8c46-da953e2ca92a"
		date = "2020-12-01"
		date = "2020-12-01"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/REDFLARE/production/yara/APT_Trojan_Win_REDFLARE_3.yar#L4-L19"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "9ccda4d7511009d5572ef2f8597fba4e,ece07daca53dd0a7c23dacabf50f56f1"
		logic_hash = "ee104bc145686a134e4d6d620dae7d1dacff7645d47f1a8d7a212327352b8e87"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$calc_image_size = { 28 00 00 00 [2-30] 83 E2 1F [4-20] C1 F8 05 [0-8] 0F AF C? [0-30] C1 E0 02 }
		$str1 = "CreateCompatibleBitmap" fullword
		$str2 = "BitBlt" fullword
		$str3 = "runCommand" fullword

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule FIREEYE_RT_APT_Trojan_Win_REDFLARE_4 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "6e8621b0-a0ee-5fc7-a2b8-1973a42d6e37"
		date = "2020-12-01"
		date = "2020-12-01"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/REDFLARE/production/yara/APT_Trojan_Win_REDFLARE_4.yar#L4-L19"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "a8b5dcfea5e87bf0e95176daa243943d, 9dcb6424662941d746576e62712220aa"
		logic_hash = "d027e98ad8fa6d03a49ceffd81fba6a621173e2dbabae652bee2f4e8489bb378"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 2

	strings:
		$s1 = "LogonUserW" fullword
		$s2 = "ImpersonateLoggedOnUser" fullword
		$s3 = "runCommand" fullword
		$user_logon = { 22 02 00 00 [1-10] 02 02 00 00 [0-4] E8 [4-40] ( 09 00 00 00 [1-10] 03 00 00 00 | 6A 03 6A 09 ) [4-30] FF 15 [4] 85 C0 7? }

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule FIREEYE_RT_APT_Trojan_Win_REDFLARE_8 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "b090df60-8f4e-51ca-944c-6f9ce2d9c913"
		date = "2020-12-02"
		date = "2020-12-02"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/REDFLARE/production/yara/APT_Trojan_Win_REDFLARE_8.yar#L4-L22"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "9c8eb908b8c1cda46e844c24f65d9370, 9e85713d615bda23785faf660c1b872c"
		logic_hash = "5b8a0402886daebefb995e7df0877d51727c5b8dc58eeb8ff16ceec5e7811a20"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$1 = "PSRunner.PSRunner" fullword
		$2 = "CorBindToRuntime" fullword
		$3 = "ReportEventW" fullword
		$4 = "InvokePS" fullword wide
		$5 = "runCommand" fullword
		$6 = "initialize" fullword
		$trap = { 03 40 00 80 E8 [4] CC }

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule FIREEYE_RT_APT_Trojan_Linux_REDFLARE_1 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "220302bc-4ed3-5e10-9bd2-a8ed2bdaef73"
		date = "2020-12-02"
		date = "2020-12-02"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/REDFLARE/supplemental/yara/APT_Trojan_Linux_REDFLARE_1.yar#L4-L20"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "79259451ff47b864d71fb3f94b1774f3, 82773afa0860d668d7fe40e3f22b0f3e"
		logic_hash = "282f11c4c86d88d05f11e92f5483701d9a54c2dd39f21316cd271aa78a338d0f"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$s1 = "find_applet_by_name" fullword
		$s2 = "bb_basename" fullword
		$s3 = "hk_printf_chk" fullword
		$s4 = "runCommand" fullword
		$s5 = "initialize" fullword

	condition:
		( uint32( 0 ) == 0x464c457f ) and all of them
}

rule FIREEYE_RT_APT_Trojan_Win_REDFLARE_6 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "5875a9ec-c3ee-57f0-a430-4443db585def"
		date = "2020-12-01"
		date = "2020-12-01"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/REDFLARE/supplemental/yara/APT_Trojan_Win_REDFLARE_6.yar#L4-L20"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "294b1e229c3b1efce29b162e7b3be0ab, 6902862bd81da402e7ac70856afbe6a2"
		logic_hash = "1e6f8320e0c0b601fc72fa4d9c61e46adfbcd84638c97da5988ca848e036312a"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 2

	strings:
		$s1 = "RevertToSelf" fullword
		$s2 = "Unsuccessful" fullword
		$s3 = "Successful" fullword
		$s4 = "runCommand" fullword
		$s5 = "initialize" fullword

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and all of them
}

rule FIREEYE_RT_Trojan_Win_Generic_101 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "0290aaea-d65b-5883-97f9-549d107e3e1f"
		date = "2020-11-25"
		date = "2020-11-25"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/BEACON/supplemental/yara/Trojan_Win_Generic_101.yar#L4-L20"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "2e67c62bd0307c04af469ee8dcb220f2"
		logic_hash = "e530183f3cab01560b1abc91e2111e5d9e5aadc1c8134027ac07d8917f9419a0"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 3

	strings:
		$s0 = { 2A [1-16] 17 [1-16] 02 04 00 00 [1-16] FF 15 }
		$s1 = { 81 7? [1-3] 02 04 00 00 7? [1-3] 83 7? [1-3] 17 7? [1-3] 83 7? [1-3] 2A 7? }
		$s2 = { FF 15 [4-16] FF D? [1-16] 3D [1-24] 89 [1-8] E8 [4-16] 89 [1-8] F3 A4 [1-24] E8 }
		$si1 = "PeekMessageA" fullword
		$si2 = "PostThreadMessageA" fullword

	condition:
		( uint16( 0 ) == 0x5A4D ) and ( uint32( uint32( 0x3C ) ) == 0x00004550 ) and @s0 [ 1 ] < @s1 [ 1 ] and @s1 [ 1 ] < @s2 [ 1 ] and all of them
}

rule FIREEYE_RT_Trojan_Raw_Generic_4 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "9092f9bb-cab6-55c0-9452-70a6407db93a"
		date = "2020-12-02"
		date = "2020-12-02"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/BEACON/supplemental/yara/Trojan_Raw_Generic_4.yar#L4-L17"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "f41074be5b423afb02a74bc74222e35d"
		logic_hash = "8ffd23631c1a9d1abe6695858ec34d61261b3b3f097be94372f3f34e46e7211e"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 1

	strings:
		$s0 = { 83 ?? 02 [1-16] 40 [1-16] F3 A4 [1-16] 40 [1-16] E8 [4-32] FF ( D? | 5? | 1? ) }
		$s1 = { 0F B? [1-16] 4D 5A [1-32] 3C [16-64] 50 45 [8-32] C3 }

	condition:
		uint16( 0 ) != 0x5A4D and all of them
}

rule FIREEYE_RT_Trojan_Macro_RESUMEPLEASE_1
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "068662f6-28b8-5538-8bc3-6506565305ae"
		date = "2020-12-01"
		date = "2020-12-01"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/RESUMEPLEASE/production/yara/Trojan_Macro_RESUMEPLEASE_1.yar#L4-L21"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "d5d3d23c8573d999f1c48d3e211b1066"
		logic_hash = "040457bc446e496431129ff4623ddda5d9c2ce339ba65a7fbe42114626f36c60"
		score = 75
		quality = 75
		tags = ""
		rev = 1

	strings:
		$str00 = "For Binary As"
		$str01 = "Range.Text"
		$str02 = "Environ("
		$str03 = "CByte("
		$str04 = ".SpawnInstance_"
		$str05 = ".Create("

	condition:
		all of them
}

rule MALPEDIA_Win_Ncctrojan_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "621539aa-975e-51db-993a-fe0f56fb0b46"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ncctrojan"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.ncctrojan_auto.yar#L1-L164"
		license_url = "N/A"
		logic_hash = "1a1a856a6ccef6fe3d5ce45ce3caa49b1b9096f7072cb08e6fd3fa9a04b80075"
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
		$sequence_0 = { 83f805 7536 8b85e8feffff 85c0 750a }
		$sequence_1 = { 68???????? e9???????? 83f801 750a 68???????? }
		$sequence_2 = { 750a 68???????? e9???????? 83f802 }
		$sequence_3 = { d1f9 8d4101 50 e8???????? 8b542410 83c404 8bca }
		$sequence_4 = { 50 e8???????? 8d45f4 50 8d85e8adffff }
		$sequence_5 = { c785ccbdffff00000000 668985dcbdffff 8d85ecfdffff 8985d4bdffff }
		$sequence_6 = { 85d2 0f8407010000 83faff 0f84fe000000 33c0 85d2 }
		$sequence_7 = { e8???????? 68???????? 6a20 68???????? e8???????? 83c418 e8???????? }
		$sequence_8 = { 0f99c0 8d044501000000 5e 5d c3 3b0d???????? }
		$sequence_9 = { 03c1 50 51 ff7304 }
		$sequence_10 = { 837dec08 8d45d8 0f4345d8 83ec18 }
		$sequence_11 = { 8965f0 6a01 8945ec 40 6a00 }
		$sequence_12 = { 7e6f 8945c8 8b400c 8b7004 }
		$sequence_13 = { 0f437d08 ff15???????? 50 56 }
		$sequence_14 = { 50 51 8d4d08 e8???????? 56 8985c8feffff 8d4d08 }
		$sequence_15 = { 02c9 2480 7403 80f11b 83ea01 }

	condition:
		7 of them and filesize < 1160192
}

rule MALPEDIA_Win_Bundestrojaner_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "47ea5615-8136-5cb4-9bef-7286571c39f9"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bundestrojaner"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.bundestrojaner_auto.yar#L1-L131"
		license_url = "N/A"
		logic_hash = "fd1e7fa09fb34d70736eb8553b933219d912c7ea6e3c9d3818f4d8762292bdc7"
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
		$sequence_0 = { 85c0 7e15 8bc5 2bdd d90403 d800 41 }
		$sequence_1 = { 3bca 7e5a 8b4e10 85c9 7443 c1f803 8d542801 }
		$sequence_2 = { 33d5 89a8c4000000 33f2 89542418 8990c8000000 8bd6 }
		$sequence_3 = { 895610 89560c 895614 7415 8b44240c 3bc2 740d }
		$sequence_4 = { 8b7e1b 8ac8 80e902 f6d9 1bc9 2c02 83e102 }
		$sequence_5 = { 740f 6a00 6a00 6a27 8bc8 e8???????? eb02 }
		$sequence_6 = { 8b44243c c68424c800000002 8b4830 51 8bce e8???????? }
		$sequence_7 = { 8bcf 8b442418 8d1476 896c2460 f7d9 8bac2430010000 83e103 }
		$sequence_8 = { 50 8986b4000000 e8???????? 83c420 b802000000 89bec0000000 89bec4000000 }
		$sequence_9 = { 50 e8???????? 8b4c2410 8b542408 51 50 }

	condition:
		7 of them and filesize < 729088
}

rule MALPEDIA_Win_Bka_Trojaner_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "ef77dd44-0b56-55a7-bd80-bb8aedf02909"
		date = "2026-01-05"
		modified = "2026-01-06"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bka_trojaner"
		source_url = "https://github.com/malpedia/signator-rules//blob/173f2e2012643b57ff6521a58ba6dd57331de3c6/rules/win.bka_trojaner_auto.yar#L1-L121"
		license_url = "N/A"
		logic_hash = "f15473c37bfc124735dc99ab7490e1138bd0e34fbe32e10f0ddc7571161a090f"
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
		$sequence_0 = { 8365d800 c745dce7384000 a1???????? 8945e0 }
		$sequence_1 = { 50 56 e8???????? 83c408 8b54241c 55 }
		$sequence_2 = { 83ec4c 56 8b742454 6808020000 68???????? }
		$sequence_3 = { ff15???????? 8b542414 56 52 ff15???????? 8b4570 }
		$sequence_4 = { 0fb6442404 8a4c240c 8488e1eb4000 751e 837c240800 7410 }
		$sequence_5 = { 5e c3 56 8b742408 8b06 813863736de0 751c }
		$sequence_6 = { ff7508 83c008 e8???????? 3b4514 59 752d 837df800 }
		$sequence_7 = { 50 8db6b4e14000 ff36 e8???????? }
		$sequence_8 = { 83ff01 751a 8b442414 8b08 8b542408 51 }
		$sequence_9 = { 7508 8b4508 a3???????? 5b 33c0 5f }

	condition:
		7 of them and filesize < 221184
}

rule TRELLIX_ARC_Trojan_Coinminer : FILE
{
	meta:
		description = "Rule to detect Coinminer malware"
		author = "Trellix ATR"
		id = "ec1f4fb7-bce3-5d5b-bbff-50f9bfc90298"
		date = "2021-07-22"
		modified = "2022-01-19"
		reference = "https://github.com/advanced-threat-research/Yara-Rules/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/miners/Trojan_CoinMiner.yar#L3-L23"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/LICENSE"
		logic_hash = "0d9d502eb0a54f90044f42f8ce485a2df6814064172cb7bf006a8c8a51976acd"
		score = 75
		quality = 70
		tags = "FILE"
		version = "v1"
		hash1 = "3bdac08131ba5138bcb5abaf781d6dc7421272ce926bc37fa27ca3eeddcec3c2"
		hash2 = "d60766c4e6e77de0818e59f687810f54a4e08505561a6bcc93c4180adb0f67e7"

	strings:
		$seq0 = { df 75 ab 7b 80 bf 83 c1 48 b3 18 74 70 01 24 5c }
		$seq1 = { 08 37 4e 6e 0f 50 0b 11 d0 98 0f a8 b8 27 47 4e }
		$seq2 = { bf 17 5a 08 09 ab 80 2f a1 b0 b1 da 47 9f e1 61 }
		$seq3 = { 53 36 34 b2 94 01 cc 05 8c 36 aa 8a 07 ff 06 1f }
		$seq4 = { 25 30 ae c4 44 d1 97 82 a5 06 05 63 07 02 28 3a }
		$seq5 = { 01 69 8e 1c 39 7b 11 56 38 0f 43 c8 5f a8 62 d0 }

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 5000KB and pe.imphash ( ) == "e4290fa6afc89d56616f34ebbd0b1f2c" and 3 of ( $seq* ) )
}

rule TRELLIX_ARC_Hermeticwiper : TROJAN FILE
{
	meta:
		description = "Detecting variants of Hermetic Wiper malware discovered in UA"
		author = " cb @ Trellix ATR"
		id = "fc6d9238-b732-541d-b083-11b43fe8770d"
		date = "2022-02-24"
		modified = "2022-02-24"
		reference = "https://github.com/advanced-threat-research/Yara-Rules/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/APT/APT_Troj_HermWiper.yar#L1-L27"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/LICENSE"
		logic_hash = "b48e91afa19e09c7035ccda1b9293448e834d612b9a953b593f9412acb78faac"
		score = 75
		quality = 70
		tags = "TROJAN, FILE"
		rule_version = "v1"
		malware_type = "Trojan"

	strings:
		$0 = {E4B5518CD941310A015E4AF8E5968C8231492FE19246A293A569D5D7A36F56EB2FC5B68FFF6F3359C19AF6806920C3FE6628F90A75440E6616297A031BA6075100D72DFAA9829E772E45D77B89F862081EAFDB19B4B2DCEF3F273FF645ACCEAA4B991F98373973C0FB25829E860D9BC195EF1A0AD9219456AD077D42868EE03EE00E88D04C434BA97E88DF99273A35E2C668A1C69954B4762390ABDFBE4CD4AF}
		$1 = {90506F1C825F7AE0D8605F5C627CA325BFF199AB60A63DE8A90E923F4B18D7FB039E1DEC89D573AAB0A14C1D4BA70EB444753A41C03082A60CB4DB551393F2C50988A3181E7F31D01B5AAD94070432D98F18655AB8A555919FEFEA9DE1EDF1}
		$2 = {D5EEF61336015A85FF04ED298A6BDD6742FF153E33DAF9B383A5FFDCE7E64D47748DB5FF2609DF9BD5C66735FF6916797B2D365313FF1461EAEB9DAEA754FF6D4D55D1956CC8CBFF75C10CE74BF88C8DFF3B553B839D42609FFF2916227230}
		$3 = {6C750DDC932124500CE9B5AB91CE101BE9AD348220E9423124512282373675152281023428825C51770FE9841F853375125382F732750A5B83F60FEB6AEE2282647462228269745AEE22826F7452228275744AEE2282787442}
		$4 = {19A8A063FFAAAF6C1E7F78A896FFFA5C8F30BA98B69CFF1961E107BEB7636AFF9EA56A4FC4EDE3F1FF295235ACD0185726FFADA6B8CB54B342C9FF86F58524DC91617BFFB4388DBE01B6CF86}
		$5 = {50C449606B20184A6328556032197660AAF9507861609F6160640560B4546160C3A194056070C4A09EC4A01A0461A4C4A0831B16600561916069A291607061C09160AA1CB6204A}
		$6 = {FFEB19D2636B8B95273156BB63E8C78470D55970F47CF26574B46DE86EE084704590CA8053F15320258BBD1AACF18B04F2E965C6605CB10880B7E8FCF53DF5EB0621635EFF}
		$7 = {7E31126E14B8FF98554F6FCFB64207FFCF8D93B2573609C2FF99E4409F73BB9322FF1E5E380DC0BBABCAFF4B901EDF61BD6A68FFEE3253728C7769ABFF7BCDA939C959A282}
		$8 = {1970FFC6F8AA7C32EE693CFF369579E5355EF62CFF682CEAF20BA3EA1CFF1AAC638666431B20FF54293D1E709C231AFFCD11B55599F64CB9FF1E5A9015DC867F}
		$9 = {8DFF93B2573609C299E4FF409F73BB93221E5EFF380DC0BBABCA4B90FF1EDF61BD6A68EE32FF53728C7769AB7BCDFFA939C959A282D312FF5DD04F0370CE811F}
		$10 = {DF5519064E31101CF3DA96C15FF96728B708F358F51759E3A22FFA1CF1BB986A2038D6753E6BF037945B8469ADF20BAB71E10F3DE27735F640704C970DFE8672}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 200KB and all of them
}

rule TRELLIX_ARC_Chimera_Recordedtv_Modified : TROJAN FILE
{
	meta:
		description = "Rule to detect the modified version of RecordedTV.ms found in the Operation Skeleton"
		author = "Marc Rivero | McAfee ATR Team"
		id = "b0969713-41a4-550c-9545-f02783fa8d02"
		date = "2020-04-21"
		modified = "2020-08-14"
		reference = "https://medium.com/@cycraft_corp/taiwan-high-tech-ecosystem-targeted-by-foreign-apt-group-5473d2ad8730"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/APT/APT_operation_skeleton.yar#L1-L33"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/LICENSE"
		hash = "66f13964c87fc6fe093a9d8cc0de0bf2b3bdaea9564210283fdb97a1dde9893b"
		logic_hash = "7165779b66999259a079fa68f898c5f9fb634adcb9d249366d321dff1014184b"
		score = 75
		quality = 70
		tags = "TROJAN, FILE"
		rule_version = "v1"
		malware_type = "trojan"
		malware_family = "Trojan:W32/RecordedTV"
		actor_type = "Apt"
		actor_group = "Unknown"

	strings:
		$byte = { C0 0E 5B C3 }
		$s1 = "Encrypted file:  CRC failed in %s (password incorrect ?)" fullword wide
		$s2 = "EBorland C++ - Copyright 1999 Inprise Corporation" fullword ascii
		$s3 = " MacOS file type:  %c%c%c%c  ; " fullword wide
		$s4 = "rar.lng" fullword ascii

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 900KB and all of them
}


rule TRELLIX_ARC_Milum_Trojan : TROJAN FILE
{
	meta:
		description = "Rule to detect Milum trojan from the Wildpressure operation"
		author = "Marc Rivero | McAfee ATR Team"
		id = "acc56237-a93a-55c0-a90c-11ca1da683db"
		date = "2020-04-24"
		modified = "2020-08-14"
		reference = "https://securelist.com/wildpressure-targets-industrial-in-the-middle-east/96360/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/APT/APT_milum_wildpressure.yar#L3-L28"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/LICENSE"
		hash = "86456ebf6b807e8253faf1262e7a2b673131c80174f6133b253b2e5f0da442a9"
		logic_hash = "3ab1ff129517cb4a829edac289c00d7701d6f667ba2ef5a28024fd01a3a52e8e"
		score = 75
		quality = 70
		tags = "TROJAN, FILE"
		rule_version = "v1"
		malware_type = "trojan"
		malware_family = "Trojan:W32/Milum"
		actor_type = "Apt"
		actor_group = "Unknown"

	strings:
		$pattern = { 558B??6A??68????????64??????????5081??????????A1????????33??89????535657508D????64??????????8B????89??????????C7????????????8D????C7??????????33??6A??89??????????89????E8????????83????3B??0F84????????89????89??8B????89????8B????89????8B????C6??????8B????C6??????C6??????8B??????????BE????????89????89????88????C6??????6A??68????????8D??????????89??????????89??????????88??????????E8????????C6??????6A??538D????528D??????????89??????????89??????????88??????????E8????????C6??????8D??????????508B??E8????????508D??????????5157E8????????C6??????83????????????72??8B??????????52E8????????83????89??????????89??????????88??????????C6??????83????????????72??8B??????????50E8????????83????6A??68????????8D????89??????????89??????????88??????????89????89????88????E8????????C6??????6A??538D????518D????89????89????88????E8????????C6??????8D????528B??E8????????508D??????????5057E8????????C6??????83??????72??8B????51E8????????83????89????89????88????C6??????83??????72??8B????52E8????????83????6A??68????????8D????89????89????88????89????89????88????E8????????C6??????6A??538D????508D????89????89????88????E8????????C6??????83????8B??89??????????6A??89????89????68????????88??E8????????C6??????83????8B??89??????????6A??538D????89????89????5288??E8????????C6??????8D??????????50C6??????E8????????83????C6??????8B??????????2B??????????B8????????F7??03??C1????8B??C1????03??83????75??8B??????????6A??53528D????E8????????8B??????????6A??83????53508D????E8????????6A??538D????508D????89????89????88????E8????????C6??????6A??538D????518D????89????89????88????E8????????C6??????8D????528B??E8????????508D??????????5057E8????????C6??????BF????????39????72??8B????51E8????????83????89????89????88????C6??????39????72??8B????52E8????????83????89????89????88????C6??????8B??????????3B??74??8B??????????E8????????8B??????????50E8????????83????BF????????89??????????89??????????89??????????C6??????39????72??8B????51E8????????83????89????89????88????C6??????39????72??8B????52E8????????83????89????89????88????C6??????39????72??8B????50E8????????83????89????89????88????88????39????72??8B????51E8????????83????89????89????88????C7????????????39????72??8B????52E8????????83????8B??????????89????89????88????8B????64????????????595F5E5B8B????33??E8????????8B??5DC2????8D??????????508D??????????89??????????E8????????C6??????C7??????????????????C6??????68????????8D??????????51E8????????CCCC558B??6A??68????????64??????????5051535657A1????????33??508D????64??????????8B????C7??????????C7????????????8D????33??83??????89????72??8B??EB??8B??8D????88??8B????8B????518B??E8????????8B????89????8B????89??8B????89????89????88????83??????72??8B??50E8????????83????89????C7????????????88??83????89????89????C7????????????8B????8B??50518D????E8????????89????8B????52E8????????83????8B????64????????????595F5E5B8B??5DC2????CCCCCCCCCCCCCCCCCCCCCCCCCC558B??6A??68????????64??????????505156A1????????33??508D????64??????????83????C7????????????8B????5156E8????????C7????????????C7????????????8B??8B????64????????????595E8B??5DC2????CCCCCCCCCCCC558B??6A??68????????64??????????5081??????????A1????????33??89????535657508D????64??????????8B????33??8B??89??????????8B????8B??89??????????89??????????89??????????3B??0F84????????8D????39??????????0F85????????68????????8D????5750E8????????C7????????????83????8D????57518B??E8????????83????C6??????8B??????????6A??535083????E8????????C6??????BF????????39????72??8B????52E8????????83????C7????????????89????88????88????39????72??8B????50E8????????83????C7????????????89????88????E9????????578D????68????????51E8????????C7????????????508D??????????52BA????????E8????????C6??????83????8D????57518B??E8????????83????C6??????8B??????????6A??535083????E8????????C6??????BF????????39????72??8B????52E8????????83????C7????????????89????88????C6??????39??????????72??8B??????????50E8????????83????C7??????????????????89??????????88??????????88????39????72??8B????51E8????????83????C7????????????89????88????FF??????????38????75??8B????38????75??8B??8B??38????75??8D????8B??8B??38????74??EB??8B????38????75??3B????75??8B??8B????38????74??8B??8B??????????3B????0F85????????8B??????????8B??6A??5383????C7????????????89????508B??88??E8????????89????C7??????????????????8B??8B????64????????????595F5E5B8B????33??E8????????8B??5DC2????CCCCCCCCCCCCCCCCCCCCCCCCCCCC558B??6A??68????????64??????????50515356A1????????33??508D????64??????????8B??89????C7??????????33??89????83??????72??8B????50E8????????83????C7????????????89????88????C7????????????83??????72??8B????50E8????????83????C7????????????89????88????8B????64????????????595E5B8B??5DC3CCCCCCCCCC558B??6A??68????????64??????????5083????A1????????33??89????5356508D????64??????????33??89????538B??68????????8D????89????C7????????????89????88????E8????????C7????????????6A??8D????38????74??68????????EB??68????????E8????????8D????5083????8D????5651E8????????C6??????8D????52578B??E8????????83????C7????????????C6??????BE????????39????72??8B????50E8????????83????C7????????????89????88????88????39????72??8B????51E8????????83????C7????????????89????88????8B??8B????64????????????595E5B8B????33??E8????????8B??5DC3CCCCCCCCCCCCCCCCCCCCCCCCCCCCCC558B??6A??68????????64??????????50515356A1????????33??508D????64??????????8B??89????C7??????????33??89????83??????72??8B????50E8????????83????C7????????????89????88????C7????????????83??????72??8B????50E8????????83????F6??????C7????????????89????88????74??56E8????????83????8B??8B????64????????????595E5B8B??5DC2????CCCC558B??6A??68????????64??????????50A1????????33??508D????64??????????C7????????????6A??6A??8D????5083????E8????????C7????????????83??????72??8B????51E8????????83????C7????????????C7????????????C6??????8B????64????????????598B??5DC2????CCCCCCCCCCCCCCCCCCCCCC558B??6A??68????????64??????????5083????A1????????33??89????535657508D????64??????????33??89????8B????89????89????B8????????89????C7????????????89????88??89????8D????BF????????39????72??8B??8B????39????73??8D????8B????518D????518B??E8????????C6??????508B??E8????????C6??????39????72??8B????52E8????????83????C7????????????89????88????88????39????72??8B????50E8????????83????C7????????????89????88????8B??8B????64????????????595F5E5B8B????33??E8????????8B??5DC2????CCCCCCCCCCCCCCCC558B??6A??68????????64??????????5081??????????A1????????33??89????535657508D????64??????????8B??33??89????8B????89??????????89?????????? }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 2000KB and pe.imphash ( ) == "548d9f5f1e74f34b85612667335d41f2" and all of them
}

rule DITEKSHEN_MALWARE_Win_Trojan_Expresscms : FILE
{
	meta:
		description = "Detects ExpressCMS"
		author = "ditekSHen"
		id = "d096db0c-05f6-5b69-9d84-0105f2182ff3"
		date = "2020-11-06"
		modified = "2024-11-01"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/malware.yar#L3366-L3382"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "64d551e0c11b6394f9ae2b8fa749c36cb1b5c3f498592f95dc19fdea23c53160"
		score = 75
		quality = 75
		tags = "FILE"
		clamav_sig = "MALWARE.Win.Trojan.ExpressCMS"

	strings:
		$s1 = "/click.php?cnv_id=" fullword wide
		$s2 = "/click.php?key=" wide
		$s3 = "jdlnb" fullword wide
		$s4 = "Gkjfdshfkjjd: dsdjdsjdhv" fullword wide
		$s5 = "--elevated" fullword wide
		$s6 = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\%d" wide
		$s7 = "\\Microsoft\\Manager.exe" fullword wide
		$s8 = "\\Microsoft\\svchost.exe" fullword wide

	condition:
		uint16( 0 ) == 0x5a4d and 6 of them
}

rule SEKOIA_Trojan_And_Keepspy : FILE
{
	meta:
		description = "Finds KeepSpy samples based on specific strings"
		author = "Sekoia.io"
		id = "9390e7c8-a996-45cc-b642-c23d4b7dcf34"
		date = "2023-06-28"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/trojan_and_keepspy.yar#L1-L22"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "03a954a5585a9a80fdc5a0cd2644a819c540d43b260e040b627530ca88ee08fa"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$str01 = "Characters entered %1$d of %2$d" ascii
		$str02 = "com.google.android.material.behavior.HideBottomViewOnScrollBehavior" ascii
		$str03 = "com/j256/ormlite/core/VERSION.txt" ascii
		$str04 = "res/raw/empty.wav" ascii
		$str05 = "res/mipmap/ic_launcher.png" ascii
		$str06 = "res/interpolator/fast_out_slow_in.xml" ascii
		$str07 = "OnePixelActivity" ascii

	condition:
		uint32be( 0 ) == 0x504B0304 and 6 of them and filesize > 2MB
}

rule SEKOIA_Trojan_Win_Grandoreiro : FILE
{
	meta:
		description = "Finds Grandorerio samples based on the specific strings"
		author = "Sekoia.io"
		id = "e48c86a1-e34f-4945-817a-9c85198a77bb"
		date = "2022-08-24"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/trojan_win_grandoreiro.yar#L1-L26"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "7424478b0cdfe922c2f98bf42e505f22fb0700cfeb54912630ce404c59b05c5e"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$mut = "ZTP@11" wide
		$reg01 = "Software\\Embarcadero\\Locales" wide
		$reg02 = "Software\\CodeGear\\Locales" wide
		$reg03 = "Software\\Borland\\Locales" wide
		$reg04 = "Software\\Borland\\Delphi\\Locale" wide
		$reg05 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\FontSubstitutes" wide
		$str01 = "SELECT * FROM AntiVirusProduct" wide
		$str02 = "GetTickCount64" wide
		$str03 = "C:\\Program Files (x86)\\Embarcadero\\Studio\\20.0\\lib\\Clever Internet Suite" wide
		$str04 = "{43826D1E-E718-42EE-BC55-A1E261C37BFE}" wide

	condition:
		uint16( 0 ) == 0x5A4D and all of them
}

rule SEKOIA_Trojan_Android_Brata : FILE
{
	meta:
		description = "Detect samples of the Android banking trojan BRATA"
		author = "Sekoia.io"
		id = "fde9b82e-c677-44ed-b512-b225a3aba201"
		date = "2022-01-27"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/trojan_android_brata.yar#L1-L29"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "0c94e5e0c01d4fa9bf28603787029938a3159f468dd3876e7d25646e93dd68b8"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$goo0 = "Google Play services error"
		$goo1 = "Error de Serveis de Google Play"
		$goo2 = "Fehler bei Zugriff auf Google Play-Dienste"
		$goo3 = "Erro nos servizos de Google Play"
		$goo4 = "Fout met Google Play-services"
		$goo5 = "Virhe Google Play -palveluissa"
		$goo6 = "Erro do Google Play Services"
		$goo7 = "Error de Google Play Services"
		$res0 = "res/xml/device_admin.xml"
		$res1 = "res/xml/windowchangedetectingservice.xml"
		$res2 = "res/xml-v22/windowchangedetectingservice.xml"

	condition:
		uint32be( 0 ) == 0x504B0304 and filesize > 2MB and filesize < 6MB and 7 of ( $goo* ) and 2 of ( $res* )
}


rule SEKOIA_Trojan_Win_Bbtok_Dll1_Sep23 : FILE
{
	meta:
		description = "Finds BBTok installation DLL file"
		author = "Sekoia.io"
		id = "eebed24b-24ec-4a85-852c-52d0acc9a698"
		date = "2023-09-26"
		modified = "2024-12-19"
		reference = "https://research.checkpoint.com/2023/behind-the-scenes-of-bbtok-analyzing-a-bankers-server-side-components/"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/trojan_win_bbtok_dll1_sep23.yar#L1-L28"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		hash = "5353956345206982af9bde55300fc405ba6e40722e8f51e8717c30ad32bc8f91"
		logic_hash = "1b1e25f7d760d275d2ef01390c215edb1752ad65383c92a21d71d9e65da3c5f8"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$str01 = "C:\\Windows\\System32\\rundll32.exe" wide
		$str02 = "C:\\ProgramData\\mmd.exe" wide
		$str03 = "REG ADD HKCU\\Software\\Classes\\.pwn\\Shell\\Open\\command -ve /d" wide
		$str04 = "C:\\ProgramData\\mmd.exe \\\\" wide
		$str05 = "\\file\\Trammy.dll" wide
		$str06 = "Dacl & REG DELETE HKCU\\Software\\Classes\\ms-settings /f" wide
		$str07 = "REG DELETE  HKCU\\Software\\Classes\\.pwn /f" wide
		$str08 = "REG ADD HKCU\\Software\\Classes\\ms-settings\\CurVer -ve /d \".pwn\" /f" wide
		$str09 = "timeout /t 3 >nul & start /MIN computerdefaults.exe" wide
		$str10 = "set_StartInfo" ascii
		$str11 = "set_WindowStyle" ascii

	condition:
		uint16( 0 ) == 0x5a4d and 7 of them and filesize < 50KB
}

rule SEKOIA_Trojan_Android_Xenomorph : FILE
{
	meta:
		description = "Detect samples of the Android banking trojan Xenomorph"
		author = "Sekoia.io"
		id = "ec65ca1b-e71f-4772-8be0-2a2b6a690987"
		date = "2022-02-25"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/trojan_android_xenomorph.yar#L1-L20"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "d44e5742449cd9c19b50ab23f452378d5627e19140554d12086994d820df9c64"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ass0 = "assets/shadows/knife_shadow_"
		$ass1 = "assets/knife_"
		$ass2 = "okhttp3"

	condition:
		uint32be( 0 ) == 0x504B0304 and filesize > 1MB and filesize < 4MB and #ass0 > 10 and #ass1 > 10 and $ass2
}

rule SEKOIA_Trojan_Win_Bbtok_Iso_Sep23 : FILE
{
	meta:
		description = "Finds BBTok installation ISO file"
		author = "Sekoia.io"
		id = "6032853d-b872-4b2e-913d-366e7f3d0f32"
		date = "2023-09-26"
		modified = "2024-12-19"
		reference = "https://research.checkpoint.com/2023/behind-the-scenes-of-bbtok-analyzing-a-bankers-server-side-components/"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/trojan_win_bbtok_iso_sep23.yar#L1-L22"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		hash = "140e83d2e0d012cdd5625ea89c3b3af05a80877cfc8215bbe20823e7e88c80b1"
		logic_hash = "efef1e4e50d84cd30c025c86beb751c73a996cca896f90729571f48259ffc110"
		score = 75
		quality = 78
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$iso = {43 44 30 30 31}
		$str01 = "POWERISO" ascii
		$str02 = "%ProgramFiles(x86)%\\Microsoft\\Edge\\Application\\msedge.exe" ascii wide
		$str03 = ".pdf /Y & start" wide
		$str04 = "\\MSBuild.exe -nologo \\\\" ascii wide

	condition:
		all of them and filesize < 500KB
}

rule SEKOIA_Trojan_Win_Bbtok_Lnk_Sep23 : FILE
{
	meta:
		description = "Finds BBTok installation LNK file"
		author = "Sekoia.io"
		id = "b1d5dae6-d92f-4a4a-ae90-528cdb3e9e4c"
		date = "2023-09-26"
		modified = "2024-12-19"
		reference = "https://research.checkpoint.com/2023/behind-the-scenes-of-bbtok-analyzing-a-bankers-server-side-components/"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/trojan_win_bbtok_lnk_sep23.yar#L1-L21"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		hash = "32bf07e3740399105359b62d8a612dfa731b024e06c9104b71b496919b5efe9e"
		logic_hash = "5783487585dde1314c485bdcf3942b7e8b572c0689522ea136240833d2a64f5b"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$lnk = {4C 00 00 00}
		$str01 = "%ProgramFiles(x86)%\\Microsoft\\Edge\\Application\\msedge.exe" ascii wide
		$str02 = ".pdf /Y & start" wide
		$str03 = "\\Microsoft.NET\\Framework\\v4.0.30319\\MSBuild.exe -nologo" wide

	condition:
		all of them and filesize < 10KB
}

rule SEKOIA_Trojan_Android_Cerberus : FILE
{
	meta:
		description = "Detect samples of the Android banking trojan Cerberus, or its family"
		author = "Sekoia.io"
		id = "3ea398bd-a80c-40f4-ad52-73b528add4ad"
		date = "2022-01-24"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/yara_rules/trojan_android_cerberus.yar#L1-L26"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/4a791f6fe20b053bc2acd963bb9955f6cd385791/LICENSE.md"
		logic_hash = "18109733d15c994015646e786a7c6177a1209200fd4c80042db3d48c97c02030"
		score = 75
		quality = 80
		tags = "FILE"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$str0 = "assets/neurax.txt"
		$str1 = "assets/Card_UpPotency_UI.json"
		$str2 = "assets/Card_SignetFoster_UI.json"
		$str3 = "assets/Gene_EmpathyTrainer.png"
		$bin0 = "assets/180417.bin"
		$bin1 = "assets/180513.bin"
		$bin2 = "assets/180527.bin"
		$bin3 = "assets/180528.bin"

	condition:
		uint32be( 0 ) == 0x504B0304 and filesize > 1MB and filesize < 4MB and 3 of ( $str* ) and 3 of ( $bin* )
}

rule SIGNATURE_BASE_FE_APT_Trojan_Linux32_LOCKPICK_1 : FILE
{
	meta:
		description = "Detects samples mentioned in PulseSecure report"
		author = "Mandiant"
		id = "00c09378-25a0-55f1-8d93-7b22d98bd8c2"
		date = "2021-04-16"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_pulsesecure.yar#L66-L80"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		hash = "e8bfd3f5a2806104316902bbe1195ee8"
		logic_hash = "1623c2dc63fe7d595069a024b715bbca267ec1c9400afcadc377ae58afb81a2a"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$sb1 = { 83 ?? 63 0F 84 [4] 8B 45 ?? 83 ?? 01 89 ?? 24 89 44 24 04 E8 [4] 85 C0 }
		$sb2 = { 83 [2] 63 74 ?? 89 ?? 24 04 89 ?? 24 E8 [4] 83 [2] 01 85 C0 0F [5] EB 00 8B ?? 04 83 F8 02 7? ?? 83 E8 01 C1 E0 02 83 C0 00 89 44 24 08 8D 83 [4] 89 44 24 04 8B ?? 89 04 24 E8 }

	condition:
		(( uint32( 0 ) == 0x464c457f ) and ( uint8( 4 ) == 1 ) ) and ( @sb1 [ 1 ] < @sb2 [ 1 ] )
}

rule SIGNATURE_BASE_FE_APT_Trojan_Linux32_PACEMAKER : FILE
{
	meta:
		description = "Detects samples mentioned in PulseSecure report"
		author = "Mandiant"
		id = "459e26f1-4ea9-56dd-ad71-0ed2c7499aea"
		date = "2021-04-16"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_pulsesecure.yar#L81-L98"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		hash = "d7881c4de4d57828f7e1cab15687274b"
		logic_hash = "f3f89744ce558179f36da3b412ba4afb3798684e6d976ef59de565b5a3323ad6"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "\x00/proc/%d/mem\x00"
		$s2 = "\x00/proc/%s/maps\x00"
		$s3 = "\x00/proc/%s/cmdline\x00"
		$sb1 = { C7 44 24 08 10 00 00 00 C7 44 24 04 00 00 00 00 8D 45 E0 89 04 24 E8 [4] 8B 45 F4 83 C0 0B C7 44 24 08 10 00 00 00 89 44 24 04 8D 45 E0 89 04 24 E8 [4] 8D 45 E0 89 04 24 E8 [4] 85 C0 74 ?? 8D 45 E0 89 04 24 E8 [4] 85 C0 74 ?? 8D 45 E0 89 04 24 E8 [4] EB }
		$sb2 = { 8B 95 [4] B8 [4] 8D 8D [4] 89 4C 24 10 8D 8D [4] 89 4C 24 0C 89 54 24 08 89 44 24 04 8D 85 [4] 89 04 24 E8 [4] C7 44 24 08 02 00 00 00 C7 44 24 04 00 00 00 00 8B 45 ?? 89 04 24 E8 [4] 89 45 ?? 8D 85 [4] 89 04 24 E8 [4] 89 44 24 08 8D 85 [4] 89 44 24 04 8B 45 ?? 89 04 24 E8 [4] 8B 45 ?? 89 45 ?? C7 45 ?? 00 00 00 00 [0-16] 83 45 ?? 01 8B 45 ?? 3B 45 0C }

	condition:
		(( uint32( 0 ) == 0x464c457f ) and ( uint8( 4 ) == 1 ) ) and all of them
}

rule SIGNATURE_BASE_FE_APT_Trojan_Linux_PACEMAKER : FILE
{
	meta:
		description = "Detects samples mentioned in PulseSecure report"
		author = "Mandiant"
		id = "5a20260a-5389-57da-956c-97063fed5015"
		date = "2021-04-16"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_pulsesecure.yar#L99-L115"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		hash = "d7881c4de4d57828f7e1cab15687274b"
		logic_hash = "cf83024cbbd500a301ac3c859b680cd79acabc232ea6f42c23fe9f8918a8d914"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "\x00Name:%s || Pwd:%s || AuthNum:%s\x0a\x00"
		$s2 = "\x00/proc/%d/mem\x00"
		$s3 = "\x00/proc/%s/maps\x00"
		$s4 = "\x00/proc/%s/cmdline\x00"

	condition:
		( uint32( 0 ) == 0x464c457f ) and all of them
}

rule SIGNATURE_BASE_HKTL_NET_GUID_Usbtrojan : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "d25c9033-13e8-5fc9-8561-f8862cca39b8"
		date = "2020-12-13"
		modified = "2025-08-15"
		reference = "https://github.com/mashed-potatoes/USBTrojan"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/gen_github_net_redteam_tools_guids.yar#L1891-L1904"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "2280803c42311b8b78a51f0917d9fb4cdd8ca427ce2361372914e5922a1a0b68"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "4eee900e-adc5-46a7-8d7d-873fd6aea83e" ascii wide

	condition:
		( uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 ) and any of them
}

rule SIGNATURE_BASE_MAL_Trojan_DLL_Nov23 : CVE_2023_4966 FILE
{
	meta:
		description = "Detects a trojan DLL that installs other components - was seen being used by LockBit 3.0 affiliates exploiting CVE-2023-4966"
		author = "X__Junior"
		id = "1dd87d0a-2b8b-5386-8fdd-40d184c731a4"
		date = "2023-11-23"
		modified = "2023-12-05"
		reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-325a"
		source_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/yara/apt_ransom_lockbit_citrixbleed_nov23.yar#L24-L39"
		license_url = "https://github.com/Neo23x0/signature-base/blob/682f9b011abd6af6c2adf3270d4bfad7d28bb21f/LICENSE"
		logic_hash = "9be42742711b4d0440244b507945e074b61c456588580b3263f899a7eb84d8aa"
		score = 80
		quality = 85
		tags = "CVE-2023-4966, FILE"
		hash1 = "e557e1440e394537cca71ed3d61372106c3c70eb6ef9f07521768f23a0974068"

	strings:
		$op1 = { C7 84 24 ?? ?? ?? ?? 52 70 63 53 C7 84 24 ?? ?? ?? ?? 74 72 69 6E C7 84 24 ?? ?? ?? ?? 67 42 69 6E C7 84 24 ?? ?? ?? ?? 64 69 6E 67 C7 84 24 ?? ?? ?? ?? 43 6F 6D 70 C7 84 24 ?? ?? ?? ?? 6F 73 65 41 C7 84 24 ?? ?? ?? ?? 00 40 01 01 }
		$op2 = { C7 84 24 ?? ?? ?? ?? 6C 73 61 73 C7 84 24 ?? ?? ?? ?? 73 70 69 72 66 C7 84 24 ?? ?? 00 00 70 63 }
		$op3 = { C7 84 24 ?? ?? ?? ?? 4E 64 72 43 C7 84 24 ?? ?? ?? ?? 6C 69 65 6E C7 84 24 ?? ?? ?? ?? 74 43 61 6C C7 84 24 ?? ?? ?? ?? 6C 33 00 8D }

	condition:
		uint16( 0 ) == 0x5a4d and all of them
}
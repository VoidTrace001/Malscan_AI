/*
   MalScan AI - detection rule set
   ------------------------------------------------------------------
   These rules are *detection* signatures. They describe patterns that
   defensive tooling looks for in suspicious files. Each rule carries a
   `severity` meta value from 1 (informational) to 5 (high confidence),
   which MalScan feeds to the model as a feature and shows in the report.

   Author: Tamal Mishra
*/

/* ================================================================== */
/*  Packing and obfuscation                                            */
/* ================================================================== */

rule Packer_UPX
{
    meta:
        description = "UPX-packed executable"
        severity    = 2
        category    = "packing"
    strings:
        $a = "UPX!"
        $b = "UPX0"
        $c = "UPX1"
        $d = "$Info: This file is packed with the UPX executable packer"
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule Packer_Commercial_Protector
{
    meta:
        description = "Commercial protector or virtualiser (Themida/VMProtect/ASPack/Enigma)"
        severity    = 3
        category    = "packing"
    strings:
        $themida  = "Themida"
        $winlic   = "WinLicense"
        $vmp      = ".vmp0"
        $vmp2     = "VMProtect"
        $aspack   = "ASPack"
        $enigma   = "Enigma Protector"
        $pecomp   = "PECompact2"
        $mpress   = "MPRESS1"
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule Obfuscation_Base64_Payload
{
    meta:
        description = "Long base64 blob embedded in the file (possible packed payload)"
        severity    = 2
        category    = "obfuscation"
    strings:
        $b64 = /[A-Za-z0-9+\/]{300,}={0,2}/
    condition:
        $b64
}

/* ================================================================== */
/*  Process injection                                                  */
/* ================================================================== */

rule Injection_Classic_RemoteThread
{
    meta:
        description = "Classic remote-thread process injection API sequence"
        severity    = 5
        category    = "injection"
    strings:
        $open  = "OpenProcess"       ascii wide
        $alloc = "VirtualAllocEx"    ascii wide
        $write = "WriteProcessMemory" ascii wide
        $exec  = "CreateRemoteThread" ascii wide
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule Injection_Process_Hollowing
{
    meta:
        description = "Process hollowing / RunPE indicators"
        severity    = 5
        category    = "injection"
    strings:
        $a = "NtUnmapViewOfSection" ascii wide
        $b = "ZwUnmapViewOfSection" ascii wide
        $c = "SetThreadContext"     ascii wide
        $d = "GetThreadContext"     ascii wide
        $e = "ResumeThread"         ascii wide
        $f = "CreateProcessInternalW" ascii wide
    condition:
        uint16(0) == 0x5A4D and (($a or $b) and 2 of ($c, $d, $e, $f))
}

rule Injection_APC_Queue
{
    meta:
        description = "APC-injection primitives"
        severity    = 4
        category    = "injection"
    strings:
        $a = "QueueUserAPC"     ascii wide
        $b = "NtQueueApcThread" ascii wide
        $c = "VirtualAllocEx"   ascii wide
    condition:
        uint16(0) == 0x5A4D and ($a or $b) and $c
}

rule Injection_Dynamic_API_Resolution
{
    meta:
        description = "Resolves APIs at runtime while importing almost nothing"
        severity    = 3
        category    = "obfuscation"
    strings:
        $ll  = "LoadLibraryA"   ascii wide
        $llw = "LoadLibraryW"   ascii wide
        $gpa = "GetProcAddress" ascii wide
        $ldr = "LdrLoadDll"     ascii wide
    condition:
        uint16(0) == 0x5A4D and ($ll or $llw or $ldr) and $gpa
}

/* ================================================================== */
/*  Anti-analysis                                                      */
/* ================================================================== */

rule AntiDebug_API_Checks
{
    meta:
        description = "Anti-debugging API checks"
        severity    = 3
        category    = "anti-analysis"
    strings:
        $a = "IsDebuggerPresent"            ascii wide
        $b = "CheckRemoteDebuggerPresent"   ascii wide
        $c = "NtQueryInformationProcess"    ascii wide
        $d = "OutputDebugString"            ascii wide
        $e = "NtSetInformationThread"       ascii wide
    condition:
        2 of them
}

rule AntiVM_Environment_Checks
{
    meta:
        description = "Looks for virtual machine or sandbox artefacts"
        severity    = 4
        category    = "anti-analysis"
    strings:
        $a = "VMware"        ascii wide nocase
        $b = "VirtualBox"    ascii wide nocase
        $c = "VBoxService"   ascii wide nocase
        $d = "QEMU"          ascii wide
        $e = "Sandboxie"     ascii wide nocase
        $f = "SbieDll.dll"   ascii wide nocase
        $g = "vmtoolsd"      ascii wide nocase
        $h = "wine_get_unix_file_name" ascii
    condition:
        2 of them
}

rule AntiAnalysis_Tool_Detection
{
    meta:
        description = "Checks for the presence of analysis tools"
        severity    = 4
        category    = "anti-analysis"
    strings:
        $a = "ollydbg"   ascii wide nocase
        $b = "x64dbg"    ascii wide nocase
        $c = "windbg"    ascii wide nocase
        $d = "procmon"   ascii wide nocase
        $e = "wireshark" ascii wide nocase
        $f = "processhacker" ascii wide nocase
        $g = "ida64"     ascii wide nocase
    condition:
        2 of them
}

/* ================================================================== */
/*  Persistence and privilege                                          */
/* ================================================================== */

rule Persistence_Registry_Run_Key
{
    meta:
        description = "Writes to a Run key for persistence"
        severity    = 4
        category    = "persistence"
    strings:
        $key1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"    ascii wide nocase
        $key2 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii wide nocase
        $api1 = "RegSetValueEx" ascii wide
        $api2 = "RegCreateKeyEx" ascii wide
    condition:
        any of ($key*) and any of ($api*)
}

rule Persistence_Scheduled_Task_Or_Service
{
    meta:
        description = "Creates a scheduled task or a Windows service"
        severity    = 3
        category    = "persistence"
    strings:
        $a = "schtasks"        ascii wide nocase
        $b = "/create /sc"     ascii wide nocase
        $c = "CreateServiceA"  ascii wide
        $d = "CreateServiceW"  ascii wide
        $e = "OpenSCManager"   ascii wide
    condition:
        2 of them
}

rule Privilege_Token_Manipulation
{
    meta:
        description = "Adjusts process privileges (e.g. SeDebugPrivilege)"
        severity    = 3
        category    = "privilege"
    strings:
        $a = "AdjustTokenPrivileges" ascii wide
        $b = "LookupPrivilegeValue"  ascii wide
        $c = "SeDebugPrivilege"      ascii wide
        $d = "OpenProcessToken"      ascii wide
    condition:
        2 of them
}

/* ================================================================== */
/*  Credential and data theft                                          */
/* ================================================================== */

rule Theft_Credential_Access
{
    meta:
        description = "Targets stored credentials or LSASS memory"
        severity    = 5
        category    = "credential-theft"
    strings:
        $a = "lsass.exe"           ascii wide nocase
        $b = "CryptUnprotectData"  ascii wide
        $c = "MiniDumpWriteDump"   ascii wide
        $d = "Login Data"          ascii wide
        $e = "logins.json"         ascii wide
        $f = "wallet.dat"          ascii wide
        $g = "vaultcli.dll"        ascii wide nocase
    condition:
        2 of them
}

rule Theft_Keylogging
{
    meta:
        description = "Keyboard or clipboard capture primitives"
        severity    = 4
        category    = "spyware"
    strings:
        $a = "GetAsyncKeyState"  ascii wide
        $b = "SetWindowsHookEx"  ascii wide
        $c = "GetKeyboardState"  ascii wide
        $d = "GetClipboardData"  ascii wide
        $e = "GetForegroundWindow" ascii wide
    condition:
        2 of them
}

/* ================================================================== */
/*  Ransomware                                                         */
/* ================================================================== */

rule Ransomware_Shadow_Copy_Deletion
{
    meta:
        description = "Deletes volume shadow copies to block recovery"
        severity    = 5
        category    = "ransomware"
    strings:
        $a = "vssadmin"              ascii wide nocase
        $b = "delete shadows"        ascii wide nocase
        $c = "Win32_ShadowCopy"      ascii wide nocase
        $d = "bcdedit"               ascii wide nocase
        $e = "recoveryenabled no"    ascii wide nocase
        $f = "wbadmin delete catalog" ascii wide nocase
    condition:
        2 of them
}

rule Ransomware_Note_Language
{
    meta:
        description = "Extortion / ransom note wording"
        severity    = 5
        category    = "ransomware"
    strings:
        $a = "your files have been encrypted" ascii wide nocase
        $b = "to decrypt your files"          ascii wide nocase
        $c = "pay the ransom"                 ascii wide nocase
        $d = "bitcoin wallet"                 ascii wide nocase
        $e = "all your important files"       ascii wide nocase
        $f = "decryption key"                 ascii wide nocase
        $g = ".onion"                         ascii wide nocase
    condition:
        2 of them
}

rule Ransomware_Crypto_Primitives
{
    meta:
        description = "Bulk file enumeration combined with encryption APIs"
        severity    = 4
        category    = "ransomware"
    strings:
        $f1 = "FindFirstFile" ascii wide
        $f2 = "FindNextFile"  ascii wide
        $c1 = "CryptEncrypt"  ascii wide
        $c2 = "CryptGenKey"   ascii wide
        $c3 = "CryptAcquireContext" ascii wide
        $c4 = "BCryptEncrypt" ascii wide
    condition:
        1 of ($f*) and 2 of ($c*)
}

/* ================================================================== */
/*  Command and control / downloaders                                  */
/* ================================================================== */

rule C2_Network_Download_Execute
{
    meta:
        description = "Downloads a file and executes it"
        severity    = 4
        category    = "downloader"
    strings:
        $d1 = "URLDownloadToFile" ascii wide
        $d2 = "InternetReadFile"  ascii wide
        $d3 = "WinHttpReadData"   ascii wide
        $e1 = "ShellExecute"      ascii wide
        $e2 = "WinExec"           ascii wide
        $e3 = "CreateProcess"     ascii wide
    condition:
        1 of ($d*) and 1 of ($e*)
}

rule C2_Hardcoded_IP_Endpoint
{
    meta:
        description = "Hardcoded IP address plus socket APIs"
        severity    = 3
        category    = "c2"
    strings:
        $ip  = /([1-9][0-9]{0,2}\.){3}[0-9]{1,3}:[0-9]{2,5}/
        $s1  = "WSAStartup" ascii wide
        $s2  = "connect"    ascii
        $s3  = "InternetOpen" ascii wide
    condition:
        $ip and 1 of ($s*)
}

/* ================================================================== */
/*  Living off the land / script abuse                                 */
/* ================================================================== */

rule LOLBin_PowerShell_Encoded
{
    meta:
        description = "Encoded or hidden PowerShell command line"
        severity    = 4
        category    = "lolbin"
    strings:
        $a = "powershell" ascii wide nocase
        $b = "-EncodedCommand" ascii wide nocase
        $c = "-enc "           ascii wide nocase
        $d = "-w hidden"       ascii wide nocase
        $e = "-nop"            ascii wide nocase
        $f = "-ExecutionPolicy Bypass" ascii wide nocase
    condition:
        $a and 1 of ($b, $c, $d, $e, $f)
}

rule LOLBin_Script_Download_Cradle
{
    meta:
        description = "Script download-and-run cradle"
        severity    = 4
        category    = "lolbin"
    strings:
        $a = "DownloadString"     ascii wide nocase
        $b = "DownloadFile"       ascii wide nocase
        $c = "Invoke-Expression"  ascii wide nocase
        $d = "IEX("               ascii wide nocase
        $e = "FromBase64String"   ascii wide nocase
        $f = "WScript.Shell"      ascii wide nocase
        $g = "certutil -decode"   ascii wide nocase
        $h = "mshta http"         ascii wide nocase
    condition:
        2 of them
}

rule Document_Macro_AutoExec
{
    meta:
        description = "Office document with auto-executing macro entry points"
        severity    = 4
        category    = "maldoc"
    strings:
        $ole  = { D0 CF 11 E0 A1 B1 1A E1 }
        $zip  = { 50 4B 03 04 }
        $m1   = "AutoOpen"        ascii wide nocase
        $m2   = "Document_Open"   ascii wide nocase
        $m3   = "Workbook_Open"   ascii wide nocase
        $m4   = "AutoClose"       ascii wide nocase
        $m5   = "Shell("          ascii wide nocase
        $m6   = "vbaProject.bin"  ascii nocase
    condition:
        ($ole at 0 or $zip at 0) and 2 of ($m*)
}

rule PDF_Suspicious_Action
{
    meta:
        description = "PDF containing JavaScript or an auto-launch action"
        severity    = 3
        category    = "maldoc"
    strings:
        $pdf  = "%PDF"
        $js   = "/JavaScript" nocase
        $ojs  = "/OpenAction" nocase
        $aa   = "/AA"         nocase
        $emb  = "/EmbeddedFile" nocase
        $lnch = "/Launch"     nocase
    condition:
        $pdf at 0 and 2 of ($js, $ojs, $aa, $emb, $lnch)
}

/* ================================================================== */
/*  Structural anomalies                                               */
/* ================================================================== */

rule Anomaly_Embedded_Executable
{
    meta:
        description = "A second PE executable is embedded inside the file"
        severity    = 3
        category    = "structure"
    strings:
        $mz = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 }
    condition:
        #mz > 1
}

rule Anomaly_Reversed_Strings
{
    meta:
        description = "API names stored reversed to defeat string scanning"
        severity    = 3
        category    = "obfuscation"
    strings:
        $a = "sserddAcorPteG" ascii wide
        $b = "AyrarbiLdaoL"   ascii wide
        $c = "collAlautriV"   ascii wide
        $d = "exe.dmc"        ascii wide
    condition:
        any of them
}

rule Test_EICAR_Signature
{
    meta:
        description = "EICAR anti-malware test file (harmless, used to verify scanners)"
        severity    = 5
        category    = "test"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

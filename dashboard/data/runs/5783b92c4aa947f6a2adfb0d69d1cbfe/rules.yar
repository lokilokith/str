/* =========================================================
   Sysmon Detection Rules (YARA-based, with MITRE metadata)
   Author: Stark
   ========================================================= */

/* ------------------------------
   DET-001: PowerShell execution
   ------------------------------ */
rule DET_001_PowerShell_High_Severity
{
    meta:
        rule_id      = "DET-001"
        description  = "PowerShell execution (non-benign parent heuristic)"
        mitre_id     = "T1059.001"      // Command and Scripting Interpreter: PowerShell
        mitre_tactic = "Execution"
        severity     = "high"

    strings:
        $img1 = /powershell\.exe/i
        $img2 = /pwsh\.exe/i

    condition:
        any of ($img*)
}


/* ------------------------------
   DET-002: CMD execution
   ------------------------------ */
rule DET_002_CMD_High_Severity
{
    meta:
        rule_id      = "DET-002"
        description  = "Cmd.exe execution (non-benign parent heuristic)"
        mitre_id     = "T1059.003"      // Command and Scripting Interpreter: Windows Command Shell
        mitre_tactic = "Execution"
        severity     = "high"

    strings:
        $cmd = /cmd\.exe/i

    condition:
        $cmd
}


/* ----------------------------------------
   DET-003: LOLBIN network connection (C2)
   ---------------------------------------- */
rule DET_003_LOLBIN_Network_Activity
{
    meta:
        rule_id      = "DET-003"
        description  = "LOLBIN making suspicious network connection (potential C2)"
        mitre_id     = "T1071"          // Application Layer Protocol
        mitre_tactic = "Command and Control"
        severity     = "medium"

    strings:
        $cmd  = /cmd\.exe/i
        $ps   = /powershell\.exe/i
        $pwsh = /pwsh\.exe/i

        // crude HTTP/HTTPS / IP indicators in commandline or URL
        $net1 = /http:\/\//i
        $net2 = /https:\/\//i
        $net3 = /\b\d{1,3}(\.\d{1,3}){3}\b/

    condition:
        any of ($cmd,$ps,$pwsh) and any of ($net*)
}


/* ----------------------------------------
   DET-004: LOLBIN file creation (exec)
   ---------------------------------------- */
rule DET_004_LOLBIN_File_Creation
{
    meta:
        rule_id      = "DET-004"
        description  = "LOLBIN creating files on disk"
        mitre_id     = "T1059"          // Command and Scripting Interpreter (generic)
        mitre_tactic = "Execution"
        severity     = "medium"

    strings:
        $cmd  = /cmd\.exe/i
        $ps   = /powershell\.exe/i
        $pwsh = /pwsh\.exe/i

        // crude indicator for writing to C:\ paths
        $fs1  = /c:\\\\/i

    condition:
        any of ($cmd,$ps,$pwsh) and $fs1
}


/* --------------------------------------------------------
   DET-005: PowerShell writing to user/programdata paths
   -------------------------------------------------------- */
rule DET_005_PowerShell_User_Write
{
    meta:
        rule_id      = "DET-005"
        description  = "PowerShell writing into user or programdata directories"
        mitre_id     = "T1059.001"      // Still Execution via PowerShell
        mitre_tactic = "Execution"
        severity     = "high"

    strings:
        $ps = /powershell\.exe/i

        // user profiles and ProgramData (often misused for staging)
        $u1 = /c:\\\\users\\\\/i
        $u2 = /c:\\\\programdata\\\\/i

    condition:
        $ps and any of ($u*)
}

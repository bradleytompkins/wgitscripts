<#
.SYNOPSIS
    Read-only triage script that hunts for SOGU / PlugX / KORPLUG indicators on a
    Windows host and prints a single INFECTED / NOT INFECTED verdict.

.DESCRIPTION
    Checks performed (all READ-ONLY - nothing is deleted, quarantined, or changed):
      1. Active TCP connections to the published C2 IPs (+ owning process)
      2. Known persistence directories under C:\ProgramData (+ hash of contents)
      3. Run registry keys (HKLM + every loaded user hive)
      4. Suspicious scheduled tasks ("Autodesk plugin" / launch-from-ProgramData)
      5. RECYCLER.BIN / RECYCLERS.BIN staging folders at drive roots
      6. Base64 recon staging file "c3lzLmluZm8" (= "sys.info")
      7. DLL side-loading: signed vendor EXE loading an unsigned/known-bad DLL
         from a suspicious path (the core SOGU loader trick), + module hashing
      8. USB lateral-movement artifacts (hidden single-space folder, root .lnk)
      9. Prefetch execution history for abused executable names (context only)

    VERDICT LOGIC:
      - Any CRITICAL finding          -> INFECTED
      - Any HIGH (no CRITICAL)        -> LIKELY INFECTED (investigate now)
      - Only REVIEW items             -> INCONCLUSIVE (manual review)
      - Nothing                       -> NO INDICATORS FOUND

    HONESTY CAVEAT: "NO INDICATORS FOUND" is not a guarantee of clean. The C2 IPs
    are from 2023 and rotate; SOGU can also beacon over ICMP/UDP (not caught by the
    TCP check). Always corroborate with firewall/proxy logs.

.PARAMETER FullDiskScan
    Recursively search every fixed drive for the recon filename. Slow. Off by default.

.PARAMETER OutputCsv
    Optional path to export findings as CSV.

.NOTES
    Run elevated (Run as Administrator) for full registry-hive, task, and module visibility.

.EXAMPLE
    .\Invoke-SoguTriage.ps1

.EXAMPLE
    .\Invoke-SoguTriage.ps1 -FullDiskScan -OutputCsv .\host_findings.csv
#>

[CmdletBinding()]
param(
    [switch]$FullDiskScan,
    [string]$OutputCsv
)

# ----------------------------------------------------------------------
# IOCs - edit/extend if you receive fresher indicators
# ----------------------------------------------------------------------
$C2_IPs = @('45.142.166.112','103.56.53.46','45.251.240.55','43.254.217.165')

$BadHashes = @{   # MD5 -> friendly name (matches the public IOC list)
    'EBB7749069A9B5BCDA98D89F04D889DB' = 'AvastAuth.dat (SOGU payload)'
    'B061D981D224454FFD8D692CF7EE92B7' = 'hex.dll (SOGU loader)'
    '38BAABDDFFB1D732A05FFA2C70331E21' = 'adobeupdate.dat (SOGU payload)'
    'FC55344597D540453326D94EB673E750' = 'SmadHook32c.dll (SOGU loader)'
    '028201D92B2B41CB6164430232192062' = 'smadavupdate.dat (SOGU payload)'
    '722B15BBC15845E4E265A1519C800C34' = 'wsc.dll (SOGU loader)'
    'AB5D85079E299AC49FCC9F12516243DE' = 'SmadavMain.exe (SOGU)'
    '848FEEC343111BC11CCEB828B5004AAD' = 'coreclr.dll (FROZENHILL)'
    'E1CEA747A64C0D74E24419AB1AFE1970' = 'ZIPDLL.dll (ZIPZAG)'
}

$ReconFileName       = 'c3lzLmluZm8'                 # Base64 for "sys.info"
$RecyclerFolderNames = @('RECYCLER.BIN','RECYCLERS.BIN')

$PersistenceDirs = @(
    "$env:ProgramData\AvastSvcpCP",
    "$env:ProgramData\AAM UpdatesHtA",
    "$env:ProgramData\AcroRd32cWP",
    "$env:ProgramData\Smadav\SmadavNSK"
)
$RunKeyValueNames = @('AvastSvcpCP','AAM UpdatesHtA','AcroRd32cWP','SmadavNSK')

# Legit, signed executables abused for DLL side-loading in these campaigns
$AbusedExeNames = @('CEFHelper.exe','Smadav.exe','SmadavMain.exe','AdobeUpdate.exe',
    'AcroRd32.exe','AvastSvc.exe','AAM Updates.exe','GUP.exe',
    'Silverlight.Configuration.exe','spoololk.exe','CUZ.exe')

# Malicious DLLs known to be side-loaded
$KnownBadDllNames = @('wsc.dll','hex.dll','SmadHook32c.dll','smadhook32c.dll',
    'coreclr.dll','libcurl.dll','VNTFXF32.dll','ZIPDLL.dll')

$SuspiciousPathPattern = 'ProgramData|\\Users\\Public\\|RECYCLER|\\AppData\\Roaming\\Intel'

# Known-good directories that legitimately live under ProgramData (signed agents/AV).
# Used to suppress noise ONLY for validly-signed binaries; module inspection still runs.
$BenignPathPattern = '\\Windows Defender\\|\\Microsoft\\(Windows Defender|EdgeUpdate)\\|' +
                     '\\WRCore\\|\\WRData\\|\\Webroot\\|\\Package Cache\\'

# ----------------------------------------------------------------------
# Setup
# ----------------------------------------------------------------------
$ErrorActionPreference = 'SilentlyContinue'
$Findings = New-Object System.Collections.Generic.List[object]
$ComputerName = $env:COMPUTERNAME

function Add-Finding {
    param([string]$Category,[string]$Severity,[string]$Detail)
    $Findings.Add([pscustomobject]@{
        Computer  = $ComputerName
        Timestamp = (Get-Date).ToString('s')
        Category  = $Category
        Severity  = $Severity
        Detail    = $Detail
    })
}

function Get-Md5 { param($Path) try { (Get-FileHash -LiteralPath $Path -Algorithm MD5).Hash } catch { $null } }
function Get-Sig { param($Path) try { (Get-AuthenticodeSignature -LiteralPath $Path).Status } catch { 'Unknown' } }

$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Write-Host "=== SOGU triage on $ComputerName ===" -ForegroundColor Cyan
if (-not $isAdmin) { Write-Host "[!] Not elevated - some checks will be incomplete." -ForegroundColor Yellow }

$drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -match '^[A-Za-z]:\\$' }

# ----------------------------------------------------------------------
# 1. Network: active TCP connections to known C2 IPs
# ----------------------------------------------------------------------
Write-Host "`n[1/9] Active TCP connections vs C2 IPs..." -ForegroundColor Cyan
try {
    $conns = Get-NetTCPConnection | Where-Object { $C2_IPs -contains $_.RemoteAddress }
    if ($conns) {
        foreach ($c in $conns) {
            $proc = Get-Process -Id $c.OwningProcess
            $pn = if ($proc.Path) { $proc.Path } else { $proc.Name }
            Add-Finding 'Network' 'CRITICAL' ("Connection to C2 {0}:{1} state {2} pid {3} ({4})" -f `
                $c.RemoteAddress,$c.RemotePort,$c.State,$c.OwningProcess,$pn)
        }
    } else { Write-Host "    No active connections to known C2 IPs." -ForegroundColor Green }
} catch { Add-Finding 'Network' 'INFO' "TCP enumeration failed: $($_.Exception.Message)" }

# ----------------------------------------------------------------------
# 2. Persistence directories
# ----------------------------------------------------------------------
Write-Host "`n[2/9] Persistence directories..." -ForegroundColor Cyan
$hit = $false
foreach ($dir in $PersistenceDirs) {
    if (Test-Path -LiteralPath $dir) {
        $hit = $true
        Add-Finding 'Persistence-Dir' 'HIGH' "Suspicious directory exists: $dir"
        Get-ChildItem -LiteralPath $dir -Recurse -File | ForEach-Object {
            $h = Get-Md5 $_.FullName
            if ($h -and $BadHashes.ContainsKey($h)) {
                Add-Finding 'Hash-Match' 'CRITICAL' ("{0} -> {1}" -f $_.FullName,$BadHashes[$h])
            }
        }
    }
}
if (-not $hit) { Write-Host "    None present." -ForegroundColor Green }

# ----------------------------------------------------------------------
# 3. Run registry keys (HKLM + all user hives)
# ----------------------------------------------------------------------
Write-Host "`n[3/9] Run registry keys..." -ForegroundColor Cyan
$runPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
)
Get-ChildItem 'Registry::HKEY_USERS' | Where-Object { $_.Name -notmatch '_Classes$' } | ForEach-Object {
    $runPaths += "Registry::$($_.Name)\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
}
$hit = $false
foreach ($rp in $runPaths) {
    if (Test-Path $rp) {
        (Get-ItemProperty -Path $rp).PSObject.Properties |
            Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
            $name = $_.Name; $val = [string]$_.Value
            if ($RunKeyValueNames -contains $name) {
                $hit = $true; Add-Finding 'Persistence-Run' 'CRITICAL' "Run '$name' = '$val' in $rp"
            } elseif (($val -match $SuspiciousPathPattern) -and ($val -notmatch $BenignPathPattern)) {
                Add-Finding 'Persistence-Run' 'REVIEW' "Run '$name' launches from suspicious path: '$val'"
            }
        }
    }
}
if (-not $hit) { Write-Host "    No known SOGU Run values (review any REVIEW items)." -ForegroundColor Green }

# ----------------------------------------------------------------------
# 4. Scheduled tasks
# ----------------------------------------------------------------------
Write-Host "`n[4/9] Scheduled tasks..." -ForegroundColor Cyan
try {
    foreach ($t in (Get-ScheduledTask)) {
        $actions = ($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join '; '
        if ($t.TaskName -like '*Autodesk plugin*') {
            Add-Finding 'Persistence-Task' 'CRITICAL' "Task '$($t.TaskName)' -> $actions"
        } elseif (($actions -match $SuspiciousPathPattern) -and ($actions -notmatch $BenignPathPattern)) {
            Add-Finding 'Persistence-Task' 'REVIEW' "Task '$($t.TaskName)' -> $actions"
        }
    }
    Write-Host "    Task review complete." -ForegroundColor Green
} catch { Add-Finding 'Persistence-Task' 'INFO' "Task enumeration failed: $($_.Exception.Message)" }

# ----------------------------------------------------------------------
# 5. Recycler staging folders + 6. recon file + 8. USB artifacts (per drive root)
# ----------------------------------------------------------------------
Write-Host "`n[5/9] Recycler staging folders..." -ForegroundColor Cyan
$hit = $false
foreach ($d in $drives) {
    foreach ($rf in $RecyclerFolderNames) {
        $path = Join-Path $d.Root $rf
        if (Test-Path -LiteralPath $path) {
            $hit = $true
            Add-Finding 'Staging-Folder' 'HIGH' "Recycler staging folder: $path"
            Get-ChildItem -LiteralPath $path -Recurse -File | ForEach-Object {
                $h = Get-Md5 $_.FullName
                if ($h -and $BadHashes.ContainsKey($h)) {
                    Add-Finding 'Hash-Match' 'CRITICAL' ("{0} -> {1}" -f $_.FullName,$BadHashes[$h])
                }
            }
        }
    }
}
if (-not $hit) { Write-Host "    None found." -ForegroundColor Green }

Write-Host "`n[6/9] Recon staging file ($ReconFileName)..." -ForegroundColor Cyan
$seen = @{}; $hit = $false
$searchRoots = @("$env:APPDATA\Intel","$env:USERPROFILE\AppData\Roaming\Intel",'C:\Users\Public') +
               ($drives | ForEach-Object { $_.Root })
foreach ($root in ($searchRoots | Select-Object -Unique)) {
    if (-not (Test-Path -LiteralPath $root)) { continue }
    $args = @{ Path = $root; Filter = $ReconFileName; File = $true; Force = $true }
    if ($root -match 'Intel|RECYCLER') { $args['Recurse'] = $true }
    Get-ChildItem @args | ForEach-Object {
        if (-not $seen[$_.FullName]) { $seen[$_.FullName]=$true; $hit=$true
            Add-Finding 'Recon-File' 'CRITICAL' "sys.info staging file: $($_.FullName)" }
    }
}
if ($FullDiskScan) {
    Write-Host "    -FullDiskScan: scanning all drives (slow)..." -ForegroundColor Yellow
    foreach ($d in $drives) {
        Get-ChildItem -LiteralPath $d.Root -Filter $ReconFileName -Recurse -File -Force | ForEach-Object {
            if (-not $seen[$_.FullName]) { $seen[$_.FullName]=$true; $hit=$true
                Add-Finding 'Recon-File' 'CRITICAL' "sys.info staging file: $($_.FullName)" }
        }
    }
}
if (-not $hit) { Write-Host "    Not found in checked locations." -ForegroundColor Green }

# ----------------------------------------------------------------------
# 7. DLL side-loading inspection of running processes
# ----------------------------------------------------------------------
Write-Host "`n[7/9] DLL side-loading inspection (running processes)..." -ForegroundColor Cyan
$hit = $false
foreach ($p in (Get-Process)) {
    $exePath = $p.Path
    $exeSus  = $exePath -and ($exePath -match $SuspiciousPathPattern)
    $modules = $null
    try { $modules = $p.Modules } catch { continue }
    if (-not $modules) { continue }

    if ($exeSus) {
        $exeName = Split-Path $exePath -Leaf
        $exeSig  = Get-Sig $exePath
        if ($exePath -match $BenignPathPattern -and $exeSig -eq 'Valid') {
            # Validly-signed binary in a known-good agent/AV directory: suppress the
            # path finding (still scan its modules below for injected/bad DLLs).
        }
        elseif (($AbusedExeNames -contains $exeName) -or ($exeSig -ne 'Valid')) {
            $hit = $true
            Add-Finding 'SideLoad' 'HIGH' `
                ("Process '{0}' (pid {1}) runs from suspicious path: {2} [exe sig: {3}]" -f `
                 $p.ProcessName,$p.Id,$exePath,$exeSig)
        }
        else {
            # Signed, unknown-but-not-abused binary from a suspicious dir: surface for a
            # human, but do not drive an INFECTED verdict on this alone.
            Add-Finding 'SideLoad' 'REVIEW' `
                ("Process '{0}' (pid {1}) runs from suspicious path (signed): {2}" -f `
                 $p.ProcessName,$p.Id,$exePath)
        }
    }
    foreach ($m in $modules) {
        $mName = $m.ModuleName
        $nameBad = $KnownBadDllNames -contains $mName
        if (-not ($nameBad -or $exeSus)) { continue }   # cheap gate before expensive checks
        $mPath = $m.FileName
        if ($nameBad) {
            # A bad-NAME match alone is NOT sufficient: several of these names are
            # legitimate, ubiquitously-loaded DLLs (coreclr.dll = the .NET runtime,
            # libcurl.dll, ZIPDLL.dll). Their genuine copies are vendor-signed and
            # load from normal paths; the malicious copy is unsigned and/or loads
            # from a suspicious path. Require that corroboration before flagging.
            # The hash check immediately below is the authoritative confirmation and
            # still fires even for a (stolen-cert) signed copy.
            $sig     = Get-Sig $mPath
            $pathSus = $mPath -match $SuspiciousPathPattern
            if ($sig -ne 'Valid') {
                $hit = $true
                $sev = if ($pathSus) { 'CRITICAL' } else { 'HIGH' }
                Add-Finding 'SideLoad' $sev `
                    ("Bad-named DLL '{0}' loaded by '{1}' from {2} [sig: {3}, suspPath: {4}]" -f `
                     $mName,$p.ProcessName,$mPath,$sig,[bool]$pathSus)
            }
            # else: a validly-signed DLL of the same name -> legitimate; ignore here
            # and let the hash check below catch a stolen-cert match if present.
        }
        $h = Get-Md5 $mPath
        if ($h -and $BadHashes.ContainsKey($h)) {
            $hit = $true
            Add-Finding 'Hash-Match' 'CRITICAL' ("Loaded module {0} -> {1}" -f $mPath,$BadHashes[$h])
        }
        if ($exeSus -and ($mPath -match $SuspiciousPathPattern)) {
            $sig = Get-Sig $mPath
            if ($sig -ne 'Valid') {
                Add-Finding 'SideLoad' 'HIGH' `
                    ("Unsigned/untrusted DLL '{0}' ({1}) loaded by '{2}': {3}" -f `
                     $mName,$sig,$p.ProcessName,$mPath)
            }
        }
    }
}
if (-not $hit) { Write-Host "    No side-loading indicators." -ForegroundColor Green }

# ----------------------------------------------------------------------
# 8. USB lateral-movement artifacts at drive roots
# ----------------------------------------------------------------------
Write-Host "`n[8/9] USB lateral-movement artifacts..." -ForegroundColor Cyan
$hit = $false
foreach ($d in $drives) {
    # A folder whose name is ALL whitespace is the documented SOGU artifact.
    # Enumerate real directory entries (Test-Path on a trailing-space path is
    # normalized by Windows to the drive root and gives a false positive).
    Get-ChildItem -LiteralPath $d.Root -Force -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^\s+$' } | ForEach-Object {
            $hit = $true
            Add-Finding 'Lateral-USB' 'HIGH' `
                ("Whitespace-named folder at {0} -> '{1}'" -f $d.Root,$_.FullName)
        }
    Get-ChildItem -LiteralPath $d.Root -Filter '*.lnk' -Force -ErrorAction SilentlyContinue | ForEach-Object {
        Add-Finding 'Lateral-USB' 'REVIEW' "Shortcut at drive root (USB-spread artifact?): $($_.FullName)"
    }
}
if (-not $hit) { Write-Host "    No whitespace-named folders at drive roots." -ForegroundColor Green }

# ----------------------------------------------------------------------
# 9. Prefetch execution history (context only - many names are legit)
# ----------------------------------------------------------------------
Write-Host "`n[9/9] Prefetch execution history (context)..." -ForegroundColor Cyan
$pf = 'C:\Windows\Prefetch'
if (Test-Path $pf) {
    foreach ($n in ($AbusedExeNames | Select-Object -Unique)) {
        $base = [IO.Path]::GetFileNameWithoutExtension($n)
        Get-ChildItem -LiteralPath $pf -Filter "$base*.pf" | ForEach-Object {
            Add-Finding 'Execution-History' 'INFO' "Prefetch: $($_.Name) ran at $($_.LastWriteTime) (legit names possible)"
        }
    }
    Write-Host "    Prefetch reviewed." -ForegroundColor Green
} else { Write-Host "    Prefetch not available." -ForegroundColor Yellow }

# ----------------------------------------------------------------------
# VERDICT
# ----------------------------------------------------------------------
$crit   = ($Findings | Where-Object Severity -eq 'CRITICAL').Count
$high   = ($Findings | Where-Object Severity -eq 'HIGH').Count
$review = ($Findings | Where-Object Severity -eq 'REVIEW').Count

if ($crit -gt 0)        { $verdict='INFECTED';              $vcolor='Red' }
elseif ($high -gt 0)    { $verdict='LIKELY INFECTED';       $vcolor='Red' }
elseif ($review -gt 0)  { $verdict='INCONCLUSIVE - REVIEW'; $vcolor='Yellow' }
else                    { $verdict='NO INDICATORS FOUND';   $vcolor='Green' }

Write-Host "`n=============================================================" -ForegroundColor $vcolor
Write-Host ("   VERDICT [{0}] : {1}" -f $ComputerName,$verdict) -ForegroundColor $vcolor
Write-Host ("   CRITICAL={0}  HIGH={1}  REVIEW={2}  (total findings={3})" -f $crit,$high,$review,$Findings.Count) -ForegroundColor $vcolor
Write-Host "=============================================================" -ForegroundColor $vcolor

if ($Findings.Count -gt 0) {
    Write-Host ""
    $Findings | Where-Object Severity -ne 'INFO' |
        Sort-Object @{e={switch($_.Severity){'CRITICAL'{0}'HIGH'{1}'REVIEW'{2}default{3}}}} |
        Format-Table Category,Severity,Detail -AutoSize -Wrap
}

if ($verdict -in @('INFECTED','LIKELY INFECTED')) {
    Write-Host "ACTION: isolate this host from the network before remediating, and preserve volatile data (memory, connections) if you need forensics." -ForegroundColor Red
} elseif ($verdict -eq 'NO INDICATORS FOUND') {
    Write-Host "NOTE: clean against THESE indicators only. Does not rule out newer C2 infra or ICMP/UDP beaconing - corroborate with firewall/proxy logs." -ForegroundColor Yellow
}

if ($OutputCsv) {
    $Findings | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8
    Write-Host "`nFindings exported to $OutputCsv" -ForegroundColor Cyan
}

# Machine-readable verdict object (useful when fanned out via Invoke-Command)
[pscustomobject]@{
    Computer = $ComputerName
    Verdict  = $verdict
    Critical = $crit
    High     = $high
    Review   = $review
    Findings = $Findings
}

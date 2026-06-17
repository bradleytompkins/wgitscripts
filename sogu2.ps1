#Requires -RunAsAdministrator

# ============================================================
#  SOGU / PlugX Triage
#  Outputs: INFECTED / SUSPICIOUS / CLEAN
#  Safe: read-only. Never deletes or modifies anything.
#  USB checks run automatically if a removable drive is found.
# ============================================================

# ---- IOCs --------------------------------------------------
$BadFileNames  = @('wsc.dll', 'AvastAuth.dat', 'c3lzLmluZm8',
                   'del_AsvastSvcpCP.bat', 'tmp.bat')
$BadExeNames   = @('AvastSvc.exe', 'wsc_proxy.exe', 'cefhelper.exe',
                   'AAM Updates.exe', 'adobe_licensing.exe')
$BadMutexes    = @('USB_NOTIFY_COP', 'USB_NOTIFY_INF')
$KnownC2       = @('45.142.166.112')
$KnownHashes   = @{
    '352FB4985FDD150D251FF9E20CA14023EAB4F2888E481CBD8370C4ED40CFBB9A' = 'wsc.dll loader'
}
$StagingPathRx = '\\[A-Z0-9]{16}\\[a-zA-Z0-9+/]{5,}={0,3}$'
$IntelDirRx    = '\\AppData\\Roaming\\Intel\\'

# ---- Scan roots --------------------------------------------
$Roots = @($env:ProgramData, $env:APPDATA, $env:LOCALAPPDATA, $env:USERPROFILE) |
    Where-Object { $_ -and (Test-Path $_) } | Sort-Object -Unique

# ---- Helpers -----------------------------------------------
$Hits     = [System.Collections.Generic.List[string]]::new()
$SigCache = @{}

function Hit([string]$level, [string]$msg) { $Hits.Add("[$level] $msg") }

function IsSigned([string]$path) {
    if ($SigCache.ContainsKey($path)) { return $SigCache[$path] }
    try { $ok = ((Get-AuthenticodeSignature -LiteralPath $path -EA Stop).Status -eq 'Valid') }
    catch { $ok = $false }
    $SigCache[$path] = $ok; return $ok
}

function IsCloudPlaceholder([System.IO.FileInfo]$f) {
    try { return (([int]$f.Attributes -band 0x441000) -ne 0) } catch { return $false }
}

# RECYCLER.BIN / RECYCLERS.BIN folder check - shared by USB and fixed-drive scans.
# Legit Windows recycle bins are 'RECYCLER' (XP NTFS), 'RECYCLED' (FAT) or
# '$Recycle.Bin' (Vista+); the '.BIN' variants are the PlugX/Sogu masquerade.
function CheckRecycler([string]$rootPath, [string]$context) {
    foreach ($name in @('RECYCLER.BIN', 'RECYCLERS.BIN')) {
        $p = Join-Path $rootPath $name
        if (Test-Path -LiteralPath $p) {
            $ini = Join-Path $p 'desktop.ini'
            $sev = if (Test-Path -LiteralPath $ini) { 'HIGH' } else { 'MED' }
            Hit $sev "$name at $rootPath ($context)"
        }
    }
}

# ============================================================
#  CHECKS
# ============================================================

# 1. USB checks — only runs if a removable drive is present
$removableDrives = Get-PSDrive -PSProvider FileSystem -EA SilentlyContinue | Where-Object {
    try { (Get-Volume -DriveLetter ($_.Root.TrimEnd('\')) -EA Stop).DriveType -eq 'Removable' }
    catch { $false }
}

if ($removableDrives) {
    Write-Host "  [!] Removable drive(s) detected - running USB checks..." -ForegroundColor Yellow
    foreach ($drive in $removableDrives) {
        # RECYCLER.BIN / RECYCLERS.BIN with desktop.ini = shell-folder masquerade
        CheckRecycler $drive.Root 'USB worm staging folder'
        # Hidden single-space folder = payload hiding spot
        $sp = Join-Path $drive.Root ' '
        if (Test-Path -LiteralPath $sp) {
            Hit 'HIGH' "Hidden space-folder at $($drive.Root) (USB worm payload folder)"
        }
        # Shortcut at drive root named after the drive = infection lure
        Get-ChildItem -LiteralPath $drive.Root -Filter '*.lnk' -Force -EA SilentlyContinue |
        ForEach-Object { Hit 'HIGH' "Suspicious .lnk at drive root: $($_.FullName) (USB worm lure)" }
    }
} else {
    Write-Host "  No removable drives found - USB checks skipped." -ForegroundColor DarkGray
}

# 1b. Fixed-drive roots - PlugX/Sogu also stages RECYCLER.BIN on fixed drives,
#     not just removable media. Root-only Test-Path, no recursion here.
$fixedRoots = try {
    [System.IO.DriveInfo]::GetDrives() |
        Where-Object { $_.DriveType -eq 'Fixed' -and $_.IsReady } |
        ForEach-Object { $_.RootDirectory.FullName }
} catch { @() }
foreach ($fr in $fixedRoots) {
    CheckRecycler $fr 'RECYCLER folder on fixed-drive root'
}

# 2. Filesystem: bad names, staging paths, side-load triads
foreach ($root in $Roots) {
    Get-ChildItem -LiteralPath $root -Recurse -Depth 3 -Force -EA SilentlyContinue |
    ForEach-Object {
        $item = $_

        if ($item -is [System.IO.FileInfo] -and $BadFileNames -contains $item.Name) {
            Hit 'HIGH' "Known PlugX filename: $($item.FullName)"
        }

        if ($item -is [System.IO.FileInfo] -and $BadExeNames -contains $item.Name -and
            $item.FullName -notmatch '(?i)\\(Avast Software|Adobe)\\') {
            Hit 'HIGH' "Loader outside expected path: $($item.FullName)"
        }

        if ($item -is [System.IO.FileInfo] -and $item.FullName -match $StagingPathRx) {
            Hit 'HIGH' "Data staging path: $($item.FullName)"
        }

        if ($item -is [System.IO.DirectoryInfo] -and $item.FullName -match $IntelDirRx) {
            Hit 'MED' "Suspicious Intel staging dir: $($item.FullName)"
        }

        if ($item -is [System.IO.DirectoryInfo] -and
            @('RECYCLER.BIN','RECYCLERS.BIN') -contains $item.Name) {
            $ini = Join-Path $item.FullName 'desktop.ini'
            $sev = if (Test-Path -LiteralPath $ini) { 'HIGH' } else { 'MED' }
            Hit $sev "RECYCLER folder in profile/data path: $($item.FullName)"
        }

        if ($item -is [System.IO.FileInfo] -and
            $item.Extension -match '\.(exe|dll|dat)$' -and
            -not (IsCloudPlaceholder $item)) {
            try {
                $h = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256 -EA Stop).Hash
                if ($KnownHashes.ContainsKey($h)) {
                    Hit 'HIGH' "Hash match $h ($($KnownHashes[$h])): $($item.FullName)"
                }
            } catch {}
        }

        if ($item -is [System.IO.DirectoryInfo]) {
            $files = Get-ChildItem -LiteralPath $item.FullName -File -Force -EA SilentlyContinue
            if ($files) {
                $benignDat = @('icudtl.dat','snapshot_blob.dat','v8_context_snapshot.dat',
                                'natives_blob.dat','resources.dat')
                $exes = @($files | Where-Object Extension -eq '.exe')
                $dlls = @($files | Where-Object Extension -eq '.dll')
                $dats = @($files | Where-Object { $_.Extension -eq '.dat' -and $benignDat -notcontains $_.Name })
                if ($exes.Count -and $dlls.Count -and $dats.Count) {
                    $named = @($files | Where-Object {
                        $BadExeNames -contains $_.Name -or $BadFileNames -contains $_.Name }).Count
                    if ($named -ge 1) {
                        Hit 'HIGH' "Side-load triad with known PlugX filename: $($item.FullName)"
                    } else {
                        $signedExe   = $exes | Where-Object { IsSigned $_.FullName }
                        $unsignedDll = $dlls | Where-Object { -not (IsSigned $_.FullName) }
                        if ($signedExe -and $unsignedDll) {
                            Hit 'MED' "Side-load triad (trusted EXE + unsigned DLL + .dat): $($item.FullName)"
                        }
                    }
                }
            }
        }
    }
}

# 3. Persistence: Run keys, services, scheduled tasks
$RunKeys = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
)
foreach ($rk in $RunKeys) {
    if (Test-Path $rk) {
        (Get-ItemProperty $rk -EA SilentlyContinue).PSObject.Properties |
        Where-Object { $_.Name -notlike 'PS*' } |
        ForEach-Object {
            $v = $_.Value
            if ($v -match '(?i)(RECYCLER|AvastSvc|wsc\.dll|c3lzLmluZm8)') {
                Hit 'HIGH' "Run key IOC: $rk :: $($_.Name) = $v"
            } elseif ($v -match '(?i)(rundll32|regsvr32|mshta).*(AppData|ProgramData)') {
                Hit 'MED'  "LOLBin from user path in Run key: $rk :: $($_.Name) = $v"
            }
        }
    }
}

Get-CimInstance Win32_Service -EA SilentlyContinue | ForEach-Object {
    if ($_.PathName -match '(?i)(RECYCLER|AvastSvc|wsc\.dll)') {
        Hit 'HIGH' "Service IOC: $($_.Name) -> $($_.PathName)"
    }
}

if (Get-Command Get-ScheduledTask -EA SilentlyContinue) {
    Get-ScheduledTask -EA SilentlyContinue | ForEach-Object {
        foreach ($a in $_.Actions) {
            $cmd = "$($a.Execute) $($a.Arguments)"
            if ($cmd -match '(?i)(RECYCLER|AvastSvc|wsc\.dll|c3lzLmluZm8)') {
                Hit 'HIGH' "Scheduled task IOC: $($_.TaskName) -> $cmd"
            }
        }
    }
}

# 4. Mutexes
foreach ($m in $BadMutexes) {
    foreach ($name in @($m, "Global\$m")) {
        try {
            $ref = $null
            if ([System.Threading.Mutex]::TryOpenExisting($name, [ref]$ref)) {
                Hit 'HIGH' "Known PlugX mutex: $name"
                if ($ref) { $ref.Dispose() }
            }
        } catch {}
    }
}

# 5. Running processes
Get-Process -EA SilentlyContinue | ForEach-Object {
    $name = "$($_.ProcessName).exe"
    if ($BadExeNames -contains $name) {
        $path = try { $_.Path } catch { 'unknown' }
        Hit 'HIGH' "PlugX loader process running: $name (PID $($_.Id)) at $path"
    }
}

# 6. Network: C2 connections
if (Get-Command Get-NetTCPConnection -EA SilentlyContinue) {
    Get-NetTCPConnection -EA SilentlyContinue |
    Where-Object { $KnownC2 -contains $_.RemoteAddress } |
    ForEach-Object {
        $proc = (Get-Process -Id $_.OwningProcess -EA SilentlyContinue).ProcessName
        Hit 'HIGH' "C2 connection: $($_.RemoteAddress):$($_.RemotePort) state=$($_.State) proc=$proc"
    }
}

# ============================================================
#  VERDICT
# ============================================================

$high = @($Hits | Where-Object { $_ -like '[HIGH]*' }).Count
$med  = @($Hits | Where-Object { $_ -like '[MED]*'  }).Count

$verdict = if     ($high -gt 0) { 'INFECTED'   }
           elseif ($med  -gt 0) { 'SUSPICIOUS' }
           else                  { 'CLEAN'      }

$color = switch ($verdict) {
    'INFECTED'   { 'Red'    }
    'SUSPICIOUS' { 'Yellow' }
    'CLEAN'      { 'Green'  }
}

Write-Host ''
Write-Host '========================================' -ForegroundColor $color
Write-Host "  VERDICT: $verdict  ($high HIGH, $med MED findings)" -ForegroundColor $color
Write-Host "  Host:    $env:COMPUTERNAME"              -ForegroundColor $color
Write-Host "  Time:    $(Get-Date -Format 'u')"        -ForegroundColor $color
Write-Host '========================================' -ForegroundColor $color
Write-Host ''

if ($Hits.Count -gt 0) {
    Write-Host '  Findings:'
    $Hits | ForEach-Object {
        $c = if ($_ -like '[HIGH]*') { 'Red' } else { 'Yellow' }
        Write-Host "    $_" -ForegroundColor $c
    }
    Write-Host ''
}
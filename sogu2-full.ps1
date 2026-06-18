#Requires -RunAsAdministrator

# ============================================================
#  SOGU / PlugX Triage
#  Outputs: INFECTED / SUSPICIOUS / CLEAN
#  Safe: read-only. Never deletes or modifies anything.
#  Worm-root checks run on ALL removable drives AND the C: drive.
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

# ---- Scan roots (deep scan in check 2) ---------------------
# $env:PUBLIC is C:\Users\Public, a documented SOGU/PlugX persistence location
# (it drops a hidden self-copy under ProgramData / Users\Public / %APPDATA%).
$Roots = @($env:ProgramData, $env:PUBLIC, $env:APPDATA, $env:LOCALAPPDATA, $env:USERPROFILE) |
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

# Uncapped recursive enumerator for the check-2 data roots. PlugX/Sogu staging
# depth varies by variant (a shallow drop in ProgramData up through
# ...\AppData\Roaming\Intel\<16-char serial>\<payload> and deeper), so a fixed
# -Depth always risks missing one. This walks the full tree, but:
#   * skips reparse points (junctions/symlinks) so the legacy profile junctions
#     like 'AppData\Local\Application Data' -> 'AppData\Local' can't cause an
#     infinite loop, and symlinks can't bounce the scan out of scope; and
#   * takes a shared $seen set so overlapping roots (USERPROFILE already
#     contains APPDATA/LOCALAPPDATA) are each walked only once -> no duplicate
#     findings.
function Get-ScanItems {
    param(
        [string]$root,
        [System.Collections.Generic.HashSet[string]]$seen
    )
    $stack = [System.Collections.Generic.Stack[string]]::new()
    $stack.Push($root)
    while ($stack.Count) {
        $dir = $stack.Pop()
        if (-not $seen.Add($dir.TrimEnd('\').ToLowerInvariant())) { continue }
        Get-ChildItem -LiteralPath $dir -Force -EA SilentlyContinue | ForEach-Object {
            $_                                              # emit file or directory
            if ($_.PSIsContainer -and
                (([int]$_.Attributes -band [int][System.IO.FileAttributes]::ReparsePoint) -eq 0)) {
                $stack.Push($_.FullName)
            }
        }
    }
}

# RECYCLER.BIN / RECYCLERS.BIN folder check - shared by all root scans.
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

# Full worm-root check for a drive root: RECYCLER masquerade + hidden
# single-space payload folder + .lnk infection lure at the root.
function CheckDriveRoot([string]$rootPath, [string]$context) {
    CheckRecycler $rootPath $context

    # A folder literally named " " at a drive root is a PlugX/Sogu worm artifact.
    # We can't Test-Path for it: Windows strips trailing spaces from the last path
    # segment, so "C:\ " normalizes to "C:\" and Test-Path returns $true on every
    # drive (false positive). Enumerate the real on-disk directory names instead,
    # where the trailing whitespace is preserved. -Force is required: the folder
    # is hidden+system. Use '^\s+$' to also catch the multi-space / tab variants;
    # switch to "$_.Name -eq ' '" to match only the exact single-space artifact.
    Get-ChildItem -LiteralPath $rootPath -Directory -Force -EA SilentlyContinue |
        Where-Object { $_.Name -match '^\s+$' } |
        ForEach-Object { Hit 'HIGH' "Hidden space-folder at $rootPath ($context)" }

    # A .lnk at a removable-drive root is the PlugX/Sogu worm lure pattern -- but
    # ONLY when its target is a launcher (cmd/rundll32/mshta/...) or points at a
    # hidden payload. Plain user shortcuts (e.g. game/web links saved to a stick)
    # are not malware, so resolve the target and classify instead of flagging
    # every .lnk HIGH. Reading a shortcut's target does not execute it.
    $wsh = $null
    try { $wsh = New-Object -ComObject WScript.Shell } catch {}
    Get-ChildItem -LiteralPath $rootPath -Filter '*.lnk' -Force -EA SilentlyContinue |
        ForEach-Object {
            $tgt = ''; $arg = ''
            if ($wsh) {
                try { $s = $wsh.CreateShortcut($_.FullName); $tgt = $s.TargetPath; $arg = $s.Arguments } catch {}
            }
            $cmdline = "$tgt $arg"
            $looksWorm = ($cmdline -match '(?i)\b(cmd|powershell|pwsh|rundll32|regsvr32|mshta|wscript|cscript)\b') -or
                         ($cmdline -match '(?i)(RECYCLER|\.dll|\.dat|AppData|ProgramData|\\ \\)')
            if ($looksWorm) {
                Hit 'HIGH' "Worm-style .lnk at drive root: $($_.FullName) -> $cmdline ($context)"
            } else {
                Hit 'LOW' "Shortcut at drive root (target: $tgt) ($context) -- review, likely benign"
            }
        }
    if ($wsh) { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($wsh) }
}

# ============================================================
#  CHECKS
# ============================================================

# ---- Determine which drive roots to scan -------------------
# Removable drives. NOTE: PSDrive .Name is already the bare letter (e.g. 'E'),
# so use that instead of Root.TrimEnd('\') which leaves a trailing colon and
# breaks Get-Volume -DriveLetter. Fall back to USB bus type for USB sticks/SSDs
# that report DriveType=Fixed.
$removableDrives = Get-PSDrive -PSProvider FileSystem -EA SilentlyContinue | Where-Object {
    $letter = $_.Name
    if ($letter -notmatch '^[A-Za-z]$') { return $false }
    try {
        $vol = Get-Volume -DriveLetter $letter -EA Stop
        if ($vol.DriveType -eq 'Removable') { return $true }
        ((Get-Partition -DriveLetter $letter -EA Stop | Get-Disk -EA Stop).BusType -eq 'USB')
    } catch { $false }
}
$removableRoots = @($removableDrives | ForEach-Object { $_.Root })

# Fixed drives (for the cheap RECYCLER-only sweep on non-C fixed roots).
$fixedRoots = try {
    [System.IO.DriveInfo]::GetDrives() |
        Where-Object { $_.DriveType -eq 'Fixed' -and $_.IsReady } |
        ForEach-Object { $_.RootDirectory.FullName }
} catch { @() }

$systemRoot = if ($env:SystemDrive) { "$env:SystemDrive\" } else { 'C:\' }

# Full worm-root checks run on every removable drive PLUS the C: (system) drive.
$fullCheckRoots    = @($removableRoots + $systemRoot) | Sort-Object -Unique
# Any other fixed drives still get the cheap RECYCLER folder check.
$recyclerOnlyRoots = @($fixedRoots | Where-Object { $fullCheckRoots -notcontains $_ })

# 1. Drive-root worm checks
if ($removableRoots.Count) {
    Write-Host "  [!] Removable drive(s) detected: $($removableRoots -join ', ')" -ForegroundColor Yellow
} else {
    Write-Host "  No removable drives found." -ForegroundColor DarkGray
}
Write-Host "  Full root checks on: $($fullCheckRoots -join ', ')" -ForegroundColor Yellow

foreach ($r in $fullCheckRoots) {
    $ctx = if ($removableRoots -contains $r) { 'removable drive root' } else { 'system drive root' }
    CheckDriveRoot $r $ctx
}
foreach ($r in $recyclerOnlyRoots) {
    CheckRecycler $r 'RECYCLER folder on fixed-drive root'
}

# 2. Filesystem: bad names, staging paths, side-load triads.
# Uncapped full-tree walk (see Get-ScanItems). Speed notes:
#   * We hash only small exe/dll/dat (PlugX loaders are small). Hashing every
#     large signed framework binary in the tree was the main cost and can never
#     match the known-bad list anyway. Raise $MaxHashMB if you add a hash for a
#     larger artifact.
#   * Triad/side-load files are captured during this single walk (only the
#     extensions/names that matter) instead of re-listing every directory.
#   * Signature checks (the slow call, and the one that stalls on a
#     network-isolated host) run later, only on directories that form a triad.
$MaxHashMB = 10
$benignDat = @('icudtl.dat','snapshot_blob.dat','v8_context_snapshot.dat',
               'natives_blob.dat','resources.dat')
$hashLimit = $MaxHashMB * 1MB

$seen     = [System.Collections.Generic.HashSet[string]]::new()
$dirFiles = @{}   # directory FullName -> List[FileInfo]; only triad-relevant files

foreach ($root in $Roots) {
    Get-ScanItems $root $seen |
    ForEach-Object {
        $item = $_

        if ($item -is [System.IO.FileInfo]) {
            if ($BadFileNames -contains $item.Name) {
                Hit 'HIGH' "Known PlugX filename: $($item.FullName)"
            }

            if ($BadExeNames -contains $item.Name -and
                $item.FullName -notmatch '(?i)\\(Avast Software|Adobe)\\') {
                Hit 'HIGH' "Loader outside expected path: $($item.FullName)"
            }

            # -cmatch (case-SENSITIVE): -match defaults to case-insensitive, which
            # makes [A-Z0-9] also accept lowercase, so a normal 16-char CamelCase
            # folder (e.g. ...\RingCentralVideo\argsFile) false-positives. The real
            # IOC is an uppercase volume-serial folder; -cmatch enforces that.
            if ($item.FullName -cmatch $StagingPathRx) {
                Hit 'HIGH' "Data staging path: $($item.FullName)"
            }

            # Hash only SMALL, locally-present exe/dll/dat. Large files can't be
            # the (small) loader, so skipping them is a free, lossless speedup.
            if ($item.Extension -match '\.(exe|dll|dat)$' -and
                $item.Length -le $hashLimit -and -not (IsCloudPlaceholder $item)) {
                try {
                    $h = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256 -EA Stop).Hash
                    if ($KnownHashes.ContainsKey($h)) {
                        Hit 'HIGH' "Hash match $h ($($KnownHashes[$h])): $($item.FullName)"
                    }
                } catch {}
            }

            # Capture only files the triad pass needs (exe/dll/dat or a bad name),
            # grouped by directory, so we never re-enumerate directories later.
            if ($item.Extension -match '\.(exe|dll|dat)$' -or
                $BadExeNames -contains $item.Name -or $BadFileNames -contains $item.Name) {
                $d = $item.DirectoryName
                if ($d) {
                    $list = $dirFiles[$d]
                    if (-not $list) { $list = [System.Collections.Generic.List[System.IO.FileInfo]]::new(); $dirFiles[$d] = $list }
                    $list.Add($item)
                }
            }
        }
        elseif ($item -is [System.IO.DirectoryInfo]) {
            if ($item.FullName -match $IntelDirRx) {
                Hit 'MED' "Suspicious Intel staging dir: $($item.FullName)"
            }

            if (@('RECYCLER.BIN','RECYCLERS.BIN') -contains $item.Name) {
                $ini = Join-Path $item.FullName 'desktop.ini'
                $sev = if (Test-Path -LiteralPath $ini) { 'HIGH' } else { 'MED' }
                Hit $sev "RECYCLER folder in profile/data path: $($item.FullName)"
            }
        }
    }
}

# Side-load triad pass: one directory at a time, using files captured above.
# Signature checks (IsSigned) only fire here, on directories that already hold
# an exe + dll + non-benign dat -- a tiny fraction of the tree.
foreach ($d in $dirFiles.Keys) {
    $files = $dirFiles[$d]
    $exes = @($files | Where-Object Extension -eq '.exe')
    $dlls = @($files | Where-Object Extension -eq '.dll')
    $dats = @($files | Where-Object { $_.Extension -eq '.dat' -and $benignDat -notcontains $_.Name })
    if ($exes.Count -and $dlls.Count -and $dats.Count) {
        $named = @($files | Where-Object {
            $BadExeNames -contains $_.Name -or $BadFileNames -contains $_.Name }).Count
        if ($named -ge 1) {
            Hit 'HIGH' "Side-load triad with known PlugX filename: $d"
        } else {
            $signedExe   = $exes | Where-Object { IsSigned $_.FullName }
            $unsignedDll = $dlls | Where-Object { -not (IsSigned $_.FullName) }
            if ($signedExe -and $unsignedDll) {
                Hit 'MED' "Side-load triad (trusted EXE + unsigned DLL + .dat): $d"
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

# NOTE: do NOT use -like here. '[HIGH]' in a wildcard pattern is a character
# class (one char from H/I/G), not the literal text, so '[HIGH]*' never matches
# a string that starts with a '[' bracket -> counts were always 0 -> verdict was
# always CLEAN. StartsWith does a literal, no-wildcard comparison.
$high = @($Hits | Where-Object { $_.StartsWith('[HIGH]') }).Count
$med  = @($Hits | Where-Object { $_.StartsWith('[MED]')  }).Count

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
        $c = if ($_.StartsWith('[HIGH]')) { 'Red' } else { 'Yellow' }
        Write-Host "    $_" -ForegroundColor $c
    }
    Write-Host ''
}
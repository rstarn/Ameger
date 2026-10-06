# Binary PE mutation engine for Ameger Injector.
#
# Inspired by Kiy0w0/kernel-mmi "Layer 2 Binary PE mutation", adapted to this
# repo: strict Windows PowerShell 5.1 (no PS7-only syntax), AV-scan retry
# handling like AddPE.ps1, fail-safe GUID stamping (verified zero
# slack only), and PE32+ data-directory math computed from the section table
# instead of hardcoded offsets.
#
# After linking, 11 mutations are applied in place (file size never changes):
#   1. TimeDateStamp      - crypto-random compile timestamp (also in
#                           AddPE.ps1; re-randomized here, idempotent)
#   2. Checksum           - crypto-random PE checksum (ignored by the loader
#                           for user-mode DLL/EXE)
#   3. Rich Header        - destroy MSVC toolchain fingerprint (DanS..Rich)
#   4. Section Names      - rename standard sections to neutral names and
#                           custom groups (.mmap_sec/.veh_sec/REMOTE_T) to
#                           random names; loader and repo validator key off
#                           directories/addresses, never names
#   5. Debug Directory    - randomize debug blobs (PDB path/GUID), then zero
#                           the directory RVA/Size; skipped when absent
#   6. Linker Version     - plausible MSVC linker version numbers
#   7. OS Version         - declared OS/image/subsystem versions; pinned to
#                           10.0 so the mutated image never under-reports the
#                           Win10/11 APIs the build actually links against
#                           (under-reporting is loader-legal but a fingerprint
#                           lie, and it breaks GetVersionEx-based tooling)
#   8. Code Caves         - homogeneous 0x00/0xCC runs (>= 64 bytes) inside
#                           EXECUTE sections that are NOT covered by any
#                           .pdata (exception directory) function range, so
#                           only linker slack is ever touched; filled with
#                           multi-byte NOPs
#   9. Build GUID         - 128-bit watermark, but ONLY into verified
#                           trailing-zero slack of the last section; skipped
#                           otherwise (never overwrites real bytes)
#  10. DOS Stub           - randomize [0x40, e_lfanew); MZ magic and e_lfanew
#                           itself are outside the range and untouched
#  11. Export Name        - overwrite the export directory's DLL-name field
#                           (link-time TargetName) with same-length random
#                           alphanumerics; the loader never reads it
#
# Exit code 0 = file written (individual mutations may report skipped);
# exit code 1 = structural validation, IO, or mutation failure (fail closed:
# the caller must refuse to continue with an inconsistent build).

param(
    [Parameter(Mandatory = $true)]
    [string[]]$Files
)

$ErrorActionPreference = "Stop"

# Console styling, matching the palette Create.bat already uses for the build
# log (92/91/93/0m). Windows PowerShell 5.1's console host does not expose
# RawUI.SupportsVirtualTerminal, so capability is not probed here: 5.1 is only
# ever run on Windows 10+ hosts where conhost renders VT sequences, and output
# is stripped whenever stdout is redirected so build logs and CI captures stay
# free of escape sequences.
$script:UseColor = -not [Console]::IsOutputRedirected

$script:Esc = [char]27
$script:C_Green = "$($script:Esc)[92m"
$script:C_Red = "$($script:Esc)[91m"
$script:C_Yellow = "$($script:Esc)[93m"
$script:C_Dim = "$($script:Esc)[90m"
$script:C_Bold = "$($script:Esc)[1m"
$script:C_Reset = "$($script:Esc)[0m"

function Get-Painted([string]$Color, [string]$Text) {
    if (-not $script:UseColor) { return $Text }
    return ($Color + $Text + $script:C_Reset)
}

# Both numerals are painted; the brackets and the separating slash stay in the
# host default so the counter reads as structure around two highlighted numbers.
function Get-StepCounter([int]$Index, [int]$Total) {
    return ("[" + (Get-Painted $script:C_Green ("{0}" -f $Index)) + "/" + (Get-Painted $script:C_Green ("{0}" -f $Total)) + "]")
}

$IMAGE_NT_SIGNATURE = 0x00004550
$IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20B
$IMAGE_SCN_MEM_EXECUTE = 0x20000000

$SectionNamePools = @{
    ".text"  = @(".code", ".exec", ".txts", ".main", ".core")
    ".rdata" = @(".cnst", ".rdat", ".rodt", ".read", ".conf")
    ".data"  = @(".vars", ".heap", ".dats", ".stor", ".memo")
    ".pdata" = @(".xdta", ".pdta", ".ehdt", ".unwd", ".trap")
    ".rsrc"  = @(".icon", ".ress", ".rcdt", ".rbin", ".resx")
    ".reloc" = @(".fixs", ".rloc", ".base", ".relc", ".patc")
    ".edata" = @(".expt", ".xprt", ".symb", ".edta", ".func")
    ".idata" = @(".impt", ".idta", ".deps", ".link", ".refs")
}

$script:AlnumChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
$script:LinkerMajors = @(14, 15, 16, 17)
$OsVersions = @(
    @{ Major = 10; Minor = 0 }
)

$script:Rng = New-Object Security.Cryptography.RNGCryptoServiceProvider

function Get-RandomBytes([int]$Count) {
    $buf = New-Object byte[] $Count
    $script:Rng.GetBytes($buf)
    return $buf
}

function Get-RandomUInt32 {
    $b = Get-RandomBytes 4
    return [BitConverter]::ToUInt32($b, 0)
}

function Get-RandomUInt16 {
    $b = Get-RandomBytes 2
    return [BitConverter]::ToUInt16($b, 0)
}

function Read-UInt16([byte[]]$Data, [int]$Offset) {
    return [BitConverter]::ToUInt16($Data, $Offset)
}

function Read-UInt32([byte[]]$Data, [int]$Offset) {
    return [BitConverter]::ToUInt32($Data, $Offset)
}

function Write-UInt16([byte[]]$Data, [int]$Offset, [uint16]$Value) {
    $b = [BitConverter]::GetBytes($Value)
    [Array]::Copy($b, 0, $Data, $Offset, 2)
}

function Write-UInt32([byte[]]$Data, [int]$Offset, [uint32]$Value) {
    $b = [BitConverter]::GetBytes($Value)
    [Array]::Copy($b, 0, $Data, $Offset, 4)
}

function Get-SectionName([byte[]]$Data, [int]$SectionOffset) {
    $s = ""
    for ($i = 0; $i -lt 8; $i++) {
        $c = $Data[$SectionOffset + $i]
        if ($c -eq 0) { break }
        $s += [char]$c
    }
    return $s
}

function Set-SectionName([byte[]]$Data, [int]$SectionOffset, [string]$Name) {
    for ($i = 0; $i -lt 8; $i++) { $Data[$SectionOffset + $i] = 0 }
    $n = [Text.Encoding]::ASCII.GetBytes($Name)
    $len = [Math]::Min($n.Length, 8)
    [Array]::Copy($n, 0, $Data, $SectionOffset, $len)
}

function New-RandomSectionName {
    $first = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    $s = "" + $first[(Get-Random -Maximum $first.Length)]
    for ($i = 1; $i -lt 8; $i++) {
        $s += $script:AlnumChars[(Get-Random -Maximum $script:AlnumChars.Length)]
    }
    return $s
}

function Get-PeLayout([byte[]]$Data) {
    if ($Data.Length -lt 64 -or $Data[0] -ne 77 -or $Data[1] -ne 90) { throw "not MZ" }
    $e = [BitConverter]::ToInt32($Data, 60)
    if ($e -le 0 -or ($e + 6) -gt $Data.Length) { throw "bad e_lfanew" }
    if ([BitConverter]::ToUInt32($Data, $e) -ne $IMAGE_NT_SIGNATURE) { throw "not PE" }
    $coff = $e + 4
    $numSections = [BitConverter]::ToUInt16($Data, $coff + 2)
    if ($numSections -le 0 -or $numSections -gt 96) { throw "bad section count" }
    $optSize = [BitConverter]::ToUInt16($Data, $coff + 16)
    $opt = $e + 24
    if ([BitConverter]::ToUInt16($Data, $opt) -ne $IMAGE_NT_OPTIONAL_HDR64_MAGIC) { throw "not PE32+" }
    $numRva = [BitConverter]::ToUInt32($Data, $opt + 108)
    if ($numRva -gt 16) { throw "bad NumberOfRvaAndSizes" }
    return @{
        NtOffset = $e
        CoffOffset = $coff
        NumSections = $numSections
        OptOffset = $opt
        DataDirOffset = $opt + 112
        SectionTable = $e + 24 + $optSize
    }
}

function Convert-RvaToOffset([byte[]]$Data, $Layout, [uint32]$Rva) {
    for ($i = 0; $i -lt $Layout.NumSections; $i++) {
        $sec = $Layout.SectionTable + ($i * 40)
        $va = Read-UInt32 $Data ($sec + 12)
        $rawSize = Read-UInt32 $Data ($sec + 16)
        $rawPtr = Read-UInt32 $Data ($sec + 20)
        if ($rawSize -gt 0 -and $Rva -ge $va -and $Rva -lt ($va + $rawSize)) {
            return ($rawPtr + ($Rva - $va))
        }
    }
    return -1
}

function Get-PlausibleTimeDateStamp {
    # A uniformly random 32-bit stamp decodes to an arbitrary instant in
    # 1970-2106, and most of those are impossible: pre-2001 (no PE), far
    # future, or 03:14 local-time junk. An impossible timestamp is itself a
    # fingerprint, so pick a believable one instead: a random instant inside
    # a 30..180 day window ending today, truncated to a whole minute (the
    # granularity the linker itself uses). This removes the build-date
    # correlation without introducing the "impossible date" tell.
    $epoch = [DateTime]::new(1970, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)
    $now = [DateTime]::UtcNow
    $daysBack = Get-Random -Minimum 30 -Maximum 181
    $stamp = $now.AddDays(-$daysBack).AddSeconds(-(Get-Random -Minimum 0 -Maximum 86400))
    $minuteFloor = [DateTime]::new($stamp.Year, $stamp.Month, $stamp.Day, $stamp.Hour, $stamp.Minute, 0, [DateTimeKind]::Utc)
    return [UInt32][int64]($minuteFloor - $epoch).TotalSeconds
}

function Invoke-MutateTimeDateStamp([byte[]]$Data, $Layout) {
    $ts = Get-PlausibleTimeDateStamp
    Write-UInt32 $Data ($Layout.CoffOffset + 4) $ts
    $decoded = [DateTime]::new(1970, 1, 1, 0, 0, 0, [DateTimeKind]::Utc).AddSeconds($ts)
    return ("TimeDateStamp -> 0x{0:X8} ({1:yyyy-MM-dd})" -f $ts, $decoded)
}

function Invoke-MutateChecksum([byte[]]$Data, $Layout) {
    $cs = Get-RandomUInt32
    Write-UInt32 $Data ($Layout.OptOffset + 64) $cs
    return ("Checksum -> 0x{0:X8}" -f $cs)
}

function Invoke-MutateRichHeader([byte[]]$Data, $Layout) {
    $e = $Layout.NtOffset
    $rich = -1
    for ($i = $e - 4; $i -ge 0x80; $i--) {
        if ($Data[$i] -eq 0x52 -and $Data[$i + 1] -eq 0x69 -and $Data[$i + 2] -eq 0x63 -and $Data[$i + 3] -eq 0x68) {
            $rich = $i
            break
        }
    }
    if ($rich -lt 0) { return "Rich Header - not found (skipped)" }
    $xorKey = Read-UInt32 $Data ($rich + 4)
    $dansXored = 0x534E6144 -bxor $xorKey
    $dans = -1
    for ($i = 0x80; $i -lt $rich; $i += 4) {
        if ((Read-UInt32 $Data $i) -eq $dansXored) {
            $dans = $i
            break
        }
    }
    if ($dans -lt 0) { $dans = 0x80 }
    $size = ($rich + 8) - $dans
    $rnd = Get-RandomBytes $size
    [Array]::Copy($rnd, 0, $Data, $dans, $size)
    return ("Rich Header - destroyed ({0} bytes randomized)" -f $size)
}

function Invoke-MutateSectionNames([byte[]]$Data, $Layout) {
    $used = @{}
    for ($i = 0; $i -lt $Layout.NumSections; $i++) {
        $sec = $Layout.SectionTable + ($i * 40)
        $used[(Get-SectionName $Data $sec)] = $true
    }
    $renamed = 0
    for ($i = 0; $i -lt $Layout.NumSections; $i++) {
        $sec = $Layout.SectionTable + ($i * 40)
        $old = Get-SectionName $Data $sec
        $choice = $null
        if ($SectionNamePools.ContainsKey($old)) {
            $alts = $SectionNamePools[$old]
            $pool = @()
            foreach ($a in $alts) { if (-not $used.ContainsKey($a)) { $pool += $a } }
            if ($pool.Count -gt 0) { $choice = $pool[(Get-Random -Maximum $pool.Count)] }
        }
        if ($null -eq $choice) {
            for ($t = 0; $t -lt 32; $t++) {
                $cand = New-RandomSectionName
                if (-not $used.ContainsKey($cand)) { $choice = $cand; break }
            }
        }
        if ($null -eq $choice) { continue }
        $used.Remove($old)
        $used[$choice] = $true
        Set-SectionName $Data $sec $choice
        $renamed++
    }
    return ("Section Names - {0} sections renamed" -f $renamed)
}

function Invoke-MutateDebugDirectory([byte[]]$Data, $Layout) {
    $rva = Read-UInt32 $Data ($Layout.DataDirOffset + 48)
    $size = Read-UInt32 $Data ($Layout.DataDirOffset + 52)
    if ($rva -eq 0 -or $size -eq 0) { return "Debug Directory - none present (skipped)" }
    $off = Convert-RvaToOffset $Data $Layout $rva
    if ($off -lt 0) { return "Debug Directory - could not resolve RVA (skipped)" }
    $wiped = 0
    for ($e = $off; ($e + 28) -le ($off + $size); $e += 28) {
        if (($e + 28) -gt $Data.Length) { break }
        $dataSize = Read-UInt32 $Data ($e + 16)
        $dataPtr = Read-UInt32 $Data ($e + 24)
        if ($dataPtr -gt 0 -and $dataSize -gt 0 -and ($dataPtr + $dataSize) -le $Data.Length) {
            $rnd = Get-RandomBytes $dataSize
            [Array]::Copy($rnd, 0, $Data, $dataPtr, $dataSize)
            $wiped++
        }
    }
    Write-UInt32 $Data ($Layout.DataDirOffset + 48) 0
    Write-UInt32 $Data ($Layout.DataDirOffset + 52) 0
    return ("Debug Directory - {0} entries wiped" -f $wiped)
}

function Invoke-MutateLinkerVersion([byte[]]$Data, $Layout) {
    $majors = $script:LinkerMajors
    $Data[$Layout.OptOffset + 2] = [byte]$majors[(Get-Random -Maximum $majors.Count)]
    $Data[$Layout.OptOffset + 3] = [byte](Get-Random -Minimum 10 -Maximum 40)
    return ("Linker Version -> {0}.{1}" -f $Data[$Layout.OptOffset + 2], $Data[$Layout.OptOffset + 3])
}

function Invoke-MutateOSVersion([byte[]]$Data, $Layout) {
    $ver = $OsVersions[(Get-Random -Maximum $OsVersions.Count)]
    Write-UInt16 $Data ($Layout.OptOffset + 40) ([uint16]$ver.Major)
    Write-UInt16 $Data ($Layout.OptOffset + 42) ([uint16]$ver.Minor)
    Write-UInt16 $Data ($Layout.OptOffset + 44) ([uint16]$ver.Major)
    Write-UInt16 $Data ($Layout.OptOffset + 46) ([uint16]$ver.Minor)
    Write-UInt16 $Data ($Layout.OptOffset + 48) ([uint16]$ver.Major)
    Write-UInt16 $Data ($Layout.OptOffset + 50) ([uint16]$ver.Minor)
    return ("OS Version -> {0}.{1}" -f $ver.Major, $ver.Minor)
}

function Get-ExceptionRanges([byte[]]$Data, $Layout) {
    $ranges = New-Object System.Collections.ArrayList
    $rva = Read-UInt32 $Data ($Layout.DataDirOffset + 24)
    $size = Read-UInt32 $Data ($Layout.DataDirOffset + 28)
    if ($rva -eq 0 -or $size -lt 12) { return $ranges }
    $off = Convert-RvaToOffset $Data $Layout $rva
    if ($off -lt 0) { return $ranges }
    $count = [int]($size / 12)
    for ($i = 0; $i -lt $count; $i++) {
        $rec = $off + ($i * 12)
        if (($rec + 12) -gt $Data.Length) { break }
        $begin = Read-UInt32 $Data $rec
        $end = Read-UInt32 $Data ($rec + 4)
        if ($end -le $begin) { continue }
        [void]$ranges.Add(@{ Begin = $begin; End = $end })
    }
    # Sort by Begin so the junk-fill loop below can stop at the first range
    # starting past a padding run instead of walking every entry.
    return ($ranges | Sort-Object -Property Begin)
}

function Invoke-MutatePolymorphicJunk([byte[]]$Data, $Layout) {
    # Bound: only runs of >= 64 bytes of 0x00/0xCC that sit inside an
    # EXECUTABLE section carrying .pdata coverage are considered, and only the
    # parts of such a run that fall outside every exception range are filled.
    # Real code, real data and any exception-covered bytes are never written.
    $nops = @(
        @(0x90),
        @(0x66, 0x90),
        @(0x0F, 0x1F, 0x00),
        @(0x0F, 0x1F, 0x40, 0x00),
        @(0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00),
        @(0x48, 0x87, 0xC0),
        @(0x48, 0x89, 0xC0),
        @(0x48, 0x8D, 0x00)
    )
    $filled = 0
    $exceptions = @(Get-ExceptionRanges $Data $Layout)

    # Locate padding runs with a native regex per section instead of a per-byte
    # PowerShell loop. The old loop called Test-RangeCovered once for every
    # padding byte, and a packed section is several MB of 0x00 slack, so the
    # function-call overhead alone was the ~20s stall. Encoding 28591 is
    # Latin-1, which maps bytes 1:1 so match indices are byte offsets.
    $padRun = [regex]'[\x00\xCC]{64,}'

    for ($i = 0; $i -lt $Layout.NumSections; $i++) {
        $sec = $Layout.SectionTable + ($i * 40)
        $chars = Read-UInt32 $Data ($sec + 36)
        if (($chars -band $IMAGE_SCN_MEM_EXECUTE) -eq 0) { continue }
        $rawPtr = Read-UInt32 $Data ($sec + 20)
        $rawSize = Read-UInt32 $Data ($sec + 16)
        if ($rawSize -eq 0) { continue }
        $end = $rawPtr + $rawSize
        if ($end -gt $Data.Length) { $end = $Data.Length }
        if ($end -le $rawPtr) { continue }
        $secVa = Read-UInt32 $Data ($sec + 12)

        # Skip a section that carries no exception coverage at all. Compiler
        # emitted code always has .pdata entries, so a section with none is
        # almost certainly hand-written asm (the thread-hijack stub), where a run
        # of 0x00/0xCC is real data rather than slack. Section NAMES cannot be
        # used for this - mutation step 4 renames every section.
        $secHasExceptions = $false
        foreach ($r in $exceptions) {
            if ($r.Begin -ge $secVa -and $r.Begin -lt ($secVa + $rawSize)) { $secHasExceptions = $true; break }
        }
        if (-not $secHasExceptions) { continue }

        $seg = [byte[]]::new($end - $rawPtr)
        [Array]::Copy($Data, $rawPtr, $seg, 0, $seg.Length)
        $text = [System.Text.Encoding]::GetEncoding(28591).GetString($seg)

        foreach ($m in $padRun.Matches($text)) {
            $runBegin = [uint32]($secVa + $m.Index)
            $runEnd = [uint32]($runBegin + $m.Length)

            # Split the run around any exception range overlapping it and fill
            # each uncovered gap that is still >= 64 bytes. Runs are few, so this
            # stays cheap; only the per-byte scan was expensive.
            $cursor = $runBegin
            foreach ($r in $exceptions) {
                if ($r.End -le $cursor) { continue }
                if ($r.Begin -ge $runEnd) { break }
                if ($r.Begin -gt $cursor) {
                    $gap = $r.Begin - $cursor
                    if ($gap -ge 64) {
                        $from = $rawPtr + ($cursor - $secVa)
                        $filled += Set-CaveBytes $Data $from ($from + $gap) $nops
                    }
                }
                if ($r.End -gt $cursor) { $cursor = $r.End }
            }
            if ($runEnd -gt $cursor) {
                $gap = $runEnd - $cursor
                if ($gap -ge 64) {
                    $from = $rawPtr + ($cursor - $secVa)
                    $filled += Set-CaveBytes $Data $from ($from + $gap) $nops
                }
            }
        }
    }
    return ("Polymorphic Junk - {0} bytes filled in code caves" -f $filled)
}

function Set-CaveBytes([byte[]]$Data, [int]$From, [int]$To, $Patterns) {
    $n = 0
    $pos = $From
    while ($pos -lt $To) {
        $pat = $Patterns[(Get-Random -Maximum $Patterns.Count)]
        if (($pos + $pat.Count) -le $To) {
            for ($k = 0; $k -lt $pat.Count; $k++) { $Data[$pos + $k] = [byte]$pat[$k] }
            $pos += $pat.Count
            $n += $pat.Count
        } else {
            $Data[$pos] = 0x90
            $pos++
            $n++
        }
    }
    return $n
}

function Invoke-MutateBuildGUID([byte[]]$Data, $Layout) {
    $last = $Layout.SectionTable + (($Layout.NumSections - 1) * 40)
    $rawPtr = Read-UInt32 $Data ($last + 20)
    $rawSize = Read-UInt32 $Data ($last + 16)
    if ($rawSize -lt 16 -or ($rawPtr + $rawSize) -gt $Data.Length) {
        return "Build GUID - no room in last section (skipped)"
    }
    for ($i = $rawPtr + $rawSize - 16; $i -lt $rawPtr + $rawSize; $i++) {
        if ($Data[$i] -ne 0) { return "Build GUID - slack not zeroed (skipped)" }
    }
    $guid = Get-RandomBytes 16
    [Array]::Copy($guid, 0, $Data, ($rawPtr + $rawSize - 16), 16)
    $hex = ([BitConverter]::ToString($guid) -replace "-", "")
    return ("Build GUID -> {0}" -f $hex)
}

function Invoke-MutateDOSStub([byte[]]$Data, $Layout) {
    $e = $Layout.NtOffset
    $from = 0x40
    $to = $e
    if (($to - $from) -lt 16) { return "DOS Stub - too small to randomize (skipped)" }
    $rnd = Get-RandomBytes ($to - $from)
    [Array]::Copy($rnd, 0, $Data, $from, ($to - $from))
    return ("DOS Stub - {0} bytes randomized" -f ($to - $from))
}

function Invoke-MutateExportName([byte[]]$Data, $Layout) {
    # The export directory's DLL-name field otherwise carries the link-time
    # TargetName into every build verbatim: a stable in-memory signature
    # ("Ameger Injector - x64.dll"). Overwrite it in place with crypto-random
    # alphanumerics of identical length (null terminator preserved), so file
    # size and every RVA stay valid. The loader locates this DLL by file path
    # and resolves its exports by function name; the directory's own name is
    # never read by the loader or the repo validator.
    $rva = Read-UInt32 $Data ($Layout.DataDirOffset + 0)
    $size = Read-UInt32 $Data ($Layout.DataDirOffset + 4)
    if ($rva -eq 0 -or $size -lt 40) { return "Export Name - none present (skipped)" }
    $off = Convert-RvaToOffset $Data $Layout $rva
    if ($off -lt 0 -or ($off + 40) -gt $Data.Length) { return "Export Name - could not resolve RVA (skipped)" }
    $nameRva = Read-UInt32 $Data ($off + 12)
    $nameOff = Convert-RvaToOffset $Data $Layout $nameRva
    if ($nameOff -lt 0 -or $nameOff -ge $Data.Length) { return "Export Name - could not resolve name (skipped)" }
    $len = 0
    while (($nameOff + $len) -lt $Data.Length -and $Data[$nameOff + $len] -ne 0) { $len++ }
    if ($len -lt 5) { return "Export Name - name too short (skipped)" }
    $letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    $alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    $Data[$nameOff] = [byte][char]$letters[(Get-Random -Maximum $letters.Length)]
    for ($i = 1; $i -lt $len; $i++) {
        $Data[$nameOff + $i] = [byte][char]$alnum[(Get-Random -Maximum $alnum.Length)]
    }
    return ("Export Name - {0} chars randomized" -f $len)
}

$failed = $false
try {
    foreach ($f in $Files) {
        if (-not (Test-Path -LiteralPath $f)) {
            Write-Host ("  " + (Get-Painted $script:C_Red ("[x] File not found: " + $f)))
            $failed = $true
            continue
        }

        $done = $false
        $bytes = $null
        for ($attempt = 1; $attempt -le 20 -and -not $done; $attempt++) {
            try {
                $bytes = [IO.File]::ReadAllBytes($f)
                $done = $true
            } catch {
                $chain = $_.Exception
                while ($chain -and -not ($chain -is [System.IO.IOException])) { $chain = $chain.InnerException }
                if ($chain -and $attempt -lt 20) {
                    Start-Sleep -Milliseconds 500
                } else {
                    Write-Host ("  " + (Get-Painted $script:C_Red ("[x] Read failed: " + $f + " : " + $_.Exception.Message)))
                    $failed = $true
                }
            }
        }
        if (-not $done) { continue }

        try {
            $layout = Get-PeLayout $bytes
        } catch {
            Write-Host ("  " + (Get-Painted $script:C_Red ("[x] Not a valid PE32+ file: " + $f + " : " + $_.Exception.Message)))
            $failed = $true
            continue
        }

        $steps = @(
            @{ N = 1; T = "TimeDateStamp"; F = { Invoke-MutateTimeDateStamp $bytes $layout }.GetNewClosure() },
            @{ N = 2; T = "Checksum"; F = { Invoke-MutateChecksum $bytes $layout }.GetNewClosure() },
            @{ N = 3; T = "Rich Header"; F = { Invoke-MutateRichHeader $bytes $layout }.GetNewClosure() },
            @{ N = 4; T = "Section Names"; F = { Invoke-MutateSectionNames $bytes $layout }.GetNewClosure() },
            @{ N = 5; T = "Debug Directory"; F = { Invoke-MutateDebugDirectory $bytes $layout }.GetNewClosure() },
            @{ N = 6; T = "Linker Version"; F = { Invoke-MutateLinkerVersion $bytes $layout }.GetNewClosure() },
            @{ N = 7; T = "OS Version"; F = { Invoke-MutateOSVersion $bytes $layout }.GetNewClosure() },
            @{ N = 8; T = "Polymorphic Junk"; F = { Invoke-MutatePolymorphicJunk $bytes $layout }.GetNewClosure() },
            @{ N = 9; T = "Build GUID"; F = { Invoke-MutateBuildGUID $bytes $layout }.GetNewClosure() },
            @{ N = 10; T = "DOS Stub"; F = { Invoke-MutateDOSStub $bytes $layout }.GetNewClosure() },
            @{ N = 11; T = "Export Name"; F = { Invoke-MutateExportName $bytes $layout }.GetNewClosure() }
        )

        $total = $steps.Count
        Write-Host ""
        Write-Host ("  " + (Get-Painted $script:C_Bold "Mutating:") + " " + (Get-Painted $script:C_Dim $f))
        Write-Host ""
        # applied = a mutation that returned a non-skipped result; skipped = a
        # mutation that explicitly reported "skipped"; failed = one that threw.
        # They partition $total, so the closing summary is always self-consistent.
        $applied = 0
        $skipped = 0
        $failedSteps = 0
        foreach ($s in $steps) {
            try {
                $r = & $s.F
                $tint = $script:C_Dim
                if ($r -like "*skipped*") { $tint = $script:C_Yellow; $skipped++ }
                else { $applied++ }
                Write-Host ("    " + (Get-StepCounter $s.N $total) + " " + (Get-Painted $tint $r))
            } catch {
                $failedSteps++
                $failed = $true
                Write-Host ("    " + (Get-StepCounter $s.N $total) + " " + (Get-Painted $script:C_Red ("FAILED: " + $_.Exception.Message)))
            }
        }

        # Fail closed: a mutation that throws already set $failed above, and
        # this structural re-validation catches one that silently corrupted the
        # section table. Either way the file is not written and the caller
        # refuses to continue on a nonzero exit, so a bad image never ships.
        try {
            $check = Get-PeLayout $bytes
            if ($check.NumSections -ne $layout.NumSections) { throw "section count changed" }
        } catch {
            Write-Host ("  " + (Get-Painted $script:C_Red ("[x] Post-mutation validation failed: " + $_.Exception.Message)))
            $failed = $true
            continue
        }

        $written = $false
        for ($attempt = 1; $attempt -le 20 -and -not $written; $attempt++) {
            try {
                [IO.File]::WriteAllBytes($f, $bytes)
                $written = $true
            } catch {
                $chain = $_.Exception
                while ($chain -and -not ($chain -is [System.IO.IOException])) { $chain = $chain.InnerException }
                if ($chain -and $attempt -lt 20) {
                    Start-Sleep -Milliseconds 500
                } else {
                    Write-Host ("  " + (Get-Painted $script:C_Red ("[x] Write failed: " + $f + " : " + $_.Exception.Message)))
                    $failed = $true
                }
            }
        }
        if ($written) {
            # Keep "{0}/{1} mutations applied" exactly 23 chars: Create.bat pads the
            # "Runtime SHA-256:" line to match this column. A ", N skipped" suffix
            # pushes the path right; that is intentional, it stays readable.
            # "[+]" and the two numerals are painted green; the separating slash and
            # the trailing words stay in the host default (same rule as Get-StepCounter).
            $tail = (Get-Painted $script:C_Green ("{0}" -f $applied)) + "/" +
                    (Get-Painted $script:C_Green ("{0}" -f $total)) + " mutations applied"
            if ($skipped -gt 0) { $tail += (", " + $skipped + " skipped") }
            if ($failedSteps -gt 0) { $tail += (", " + $failedSteps + " failed") }
            Write-Host ""
            Write-Host ("  " + (Get-Painted $script:C_Green "[+]") + " " + $tail + " " + (Get-Painted $script:C_Dim $f))
        }
    }
} finally {
    $script:Rng.Dispose()
}
if ($failed) { exit 1 }

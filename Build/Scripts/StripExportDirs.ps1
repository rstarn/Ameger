param(
    [Parameter(Mandatory = $true)][string]$Path
)

# Remove the export directory from a payload on disk.
#
# Rationale: after manual mapping nothing resolves exports - there is no loader
# entry, so GetProcAddress cannot work on the image (see the export wipe in
# ManualMapping.cpp). The directory exists on disk only as leftover plaintext,
# and it carries the single most identifying symbol in the binary
# ("ManualEntry"), plus the original DLL file name. Stripping it removes that
# without affecting mapping or entry invocation, which travel by RVA.
#
# Import tables are deliberately NOT touched: the loader reads import
# descriptors straight out of the mapped image, so they are functionally
# required at rest.
#
# Exit 0 = stripped (or already absent), 1 = refused/failed.

$ErrorActionPreference = 'Stop'

# Colour handling. This script is launched from the protect stages, which set
# their own ANSI variables, but a child PowerShell process cannot see them - so
# the escapes are emitted here instead. AMEGER_NO_COLOR is honoured to match the
# rest of the build.
$noColour = ($env:AMEGER_NO_COLOR -eq '1')
$esc = [string][char]27
if ($noColour) {
    $G = ''; $E = ''; $X = ''
} else {
    $G = "$esc[92m"   # green, result values
    $E = "$esc[91m"   # red, failures
    $X = "$esc[0m"    # reset
}

if (-not (Test-Path -LiteralPath $Path)) { Write-Host "  $E[!]$X export strip: file not found: $Path"; exit 1 }

$b = [IO.File]::ReadAllBytes($Path)
$e = [BitConverter]::ToInt32($b, 0x3C)
if ([Text.Encoding]::ASCII.GetString($b, $e, 4) -ne "PE`0`0") { Write-Host "  $E[!]$X export strip: not a PE"; exit 1 }

$coff = $e + 4
$opt = $coff + 20
$pe32p = ([BitConverter]::ToUInt16($b, $opt) -eq 0x20b)
$ddoff = if ($pe32p) { $opt + 112 } else { $opt + 96 }
$expRva = [BitConverter]::ToUInt32($b, $ddoff + 0)
$expSz = [BitConverter]::ToUInt32($b, $ddoff + 4)

if ($expRva -eq 0 -or $expSz -eq 0) {
    Write-Host "  $G[+]$X Export directory already absent."
    exit 0
}

$secs = @()
$secBase = $opt + [BitConverter]::ToUInt16($b, $coff + 16)
$nsec = [BitConverter]::ToUInt16($b, $coff + 2)
for ($i = 0; $i -lt $nsec; $i++) {
    $o = $secBase + 40 * $i
    $secs += [pscustomobject]@{
        VA = [BitConverter]::ToUInt32($b, $o + 12)
        VS = [BitConverter]::ToUInt32($b, $o + 8)
        Ptr = [BitConverter]::ToUInt32($b, $o + 20)
        Sz = [BitConverter]::ToUInt32($b, $o + 16)
    }
}

function Convert-RvaToOffset([uint32]$rva) {
    foreach ($s in $secs) {
        $span = [Math]::Max($s.VS, $s.Sz)
        if ($rva -ge $s.VA -and $rva -lt ($s.VA + $span)) { return [int](($rva - $s.VA) + $s.Ptr) }
    }
    return -1
}

$eo = Convert-RvaToOffset $expRva
if ($eo -lt 0) { Write-Host "  $E[!]$X export strip: export RVA 0x$($expRva.ToString('X')) outside every section"; exit 1 }

# Collect every plaintext string the directory points at so none survives.
$strings = New-Object System.Collections.Generic.List[int]
$nameRva = [BitConverter]::ToUInt32($b, $eo + 12)
if ($nameRva -ne 0) { $strings.Add((Convert-RvaToOffset $nameRva)) }
$nNames = [BitConverter]::ToUInt32($b, $eo + 24)
$anOff = Convert-RvaToOffset ([BitConverter]::ToUInt32($b, $eo + 32))
if ($nNames -gt 0 -and $anOff -ge 0) {
    if ($nNames -gt 65536) { Write-Host "  $E[!]$X export strip: implausible name count $nNames"; exit 1 }
    for ($i = 0; $i -lt $nNames; $i++) {
        $nr = Convert-RvaToOffset ([BitConverter]::ToUInt32($b, $anOff + 4 * $i))
        if ($nr -ge 0) { $strings.Add($nr) }
    }
}

$zeroed = 0
foreach ($o in $strings) {
    if ($o -lt 0 -or $o -ge $b.Length) { continue }
    while ($o -lt $b.Length -and $b[$o] -ne 0) { $b[$o] = 0; $o++; $zeroed++ }
    if ($o -lt $b.Length) { $b[$o] = 0 }
}

# Clear the directory structure and the data-directory entry that advertises it.
$end = [Math]::Min($eo + [int]$expSz, $b.Length)
for ($o = $eo; $o -lt $end; $o++) { $b[$o] = 0 }
for ($o = $ddoff; $o -lt ($ddoff + 8); $o++) { $b[$o] = 0 }

[IO.File]::WriteAllBytes($Path, $b)

# Verify: the entry must read empty and no export name may survive.
$v = [IO.File]::ReadAllBytes($Path)
$ve = [BitConverter]::ToInt32($v, 0x3C)
$vdd = if ($pe32p) { $ve + 4 + 20 + 112 } else { $ve + 4 + 20 + 96 }
$vRva = [BitConverter]::ToUInt32($v, $vdd + 0)
$vSz = [BitConverter]::ToUInt32($v, $vdd + 4)
if ($vRva -ne 0 -or $vSz -ne 0) { Write-Host "  $E[x]$X export strip: data directory still set"; exit 1 }
if ([Text.Encoding]::ASCII.GetString($v).Contains('ManualEntry')) { Write-Host "  $E[x]$X export strip: ManualEntry still present"; exit 1 }

Write-Host "  $G[+]$X Export directory stripped ($G$zeroed$X name byte(s) zeroed, directory cleared)."
exit 0
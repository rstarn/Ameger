# Auto-discovers protectable functions in a PE32+ binary for VMProtect.
#
# Proven against VMProtect Ultimate 3.8.4 console (Sep 2026):
#   * MapAddress="EntryPoint" / export names resolve (Loading [U] <VA> <name>).
#   * Raw VA hex (VA, RVA, 0x-prefixed, either case) does NOT resolve via CLI:
#     every entry warns 'not found in the objects list', even for real exports
#     like Memory_Inject. Address-keyed projects only work GUI-side.
# Hence this script enumerates the EXPORT table (the only CLI-namable set)
# and appends one Ultra (CompilationType=2) Complexity=100 procedure per
# *function* export. Data exports (e.g. g_LibraryState) are excluded via an
# executable-section check. Binaries with no exports (the interface EXE) keep
# the base template as-is (EntryPoint keyword); full internal coverage there
# needs a GUI-saved project or SDK markers, not CLI automation.
#
# Usage:
#   VMPProcedures.ps1 -InputFile <binary> -BaseProject <template.vmp> -OutputProject <out.vmp>
#
# The base template keeps its Protection attributes (Options, VMComplexity=100,
# VMInstances=10) and keyword procedures. Exit 0 = project written (count
# printed), 1 = fatal PE/XML error.
param(
    [Parameter(Mandatory = $true)][string]$InputFile,
    [Parameter(Mandatory = $true)][string]$BaseProject,
    [Parameter(Mandatory = $true)][string]$OutputProject
)

$ErrorActionPreference = "Stop"

function Read-U16([byte[]]$b, [int]$o) { return [BitConverter]::ToUInt16($b, $o) }
function Read-U32([byte[]]$b, [int]$o) { return [BitConverter]::ToUInt32($b, $o) }
function Read-U64([byte[]]$b, [int]$o) { return [BitConverter]::ToUInt64($b, $o) }

if (-not (Test-Path -LiteralPath $InputFile)) { Write-Host "Discover: input not found: $InputFile"; exit 1 }
if (-not (Test-Path -LiteralPath $BaseProject)) { Write-Host "Discover: base project not found: $BaseProject"; exit 1 }

$bytes = [IO.File]::ReadAllBytes($InputFile)
if ($bytes.Length -lt 64 -or $bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) { Write-Host "Discover: no MZ signature."; exit 1 }
$e_lfanew = Read-U32 $bytes 0x3C
if ([BitConverter]::ToUInt32($bytes, $e_lfanew) -ne 0x00004550) { Write-Host "Discover: no PE signature."; exit 1 }
$fhOff = $e_lfanew + 4
$numSec = Read-U16 $bytes ($fhOff + 2)
$optSize = Read-U16 $bytes ($fhOff + 16)
$optOff = $fhOff + 20
if ((Read-U16 $bytes $optOff) -ne 0x20B) { Write-Host "Discover: not PE32+ (x64 required)."; exit 1 }
$sizeHeaders = Read-U32 $bytes ($optOff + 60)
$numDirs = Read-U32 $bytes ($optOff + 108)
$dirsOff = $optOff + 112
$expRva = 0; $expSize = 0
if ($numDirs -gt 0) {
    $expRva = Read-U32 $bytes $dirsOff
    $expSize = Read-U32 $bytes ($dirsOff + 4)
}
$secOff = $optOff + $optSize
$sections = @()
for ($i = 0; $i -lt $numSec; $i++) {
    $o = $secOff + $i * 40
    $chars = Read-U32 $bytes ($o + 36)
    $vsize = Read-U32 $bytes ($o + 8); $vaddr = Read-U32 $bytes ($o + 12)
    $rawsize = Read-U32 $bytes ($o + 16); $rawptr = Read-U32 $bytes ($o + 20)
    $sections += ,@($vaddr, $vsize, $rawsize, $rawptr, $chars)
}
function Convert-RvaToOffset([uint32]$rva) {
    foreach ($s in $sections) {
        $span = [Math]::Max($s[1], $s[2])
        if ($rva -ge $s[0] -and $rva -lt ($s[0] + $span)) { return ($s[3] + ($rva - $s[0])) }
    }
    if ($rva -lt $sizeHeaders) { return [int]$rva }
    return -1
}
function Test-IsCodeRva([uint32]$rva) {
    foreach ($s in $sections) {
        $span = [Math]::Max($s[1], $s[2])
        if ($rva -ge $s[0] -and $rva -lt ($s[0] + $span)) {
            return (($s[4] -band 0x00000020) -ne 0)  # IMAGE_SCN_MEM_EXECUTE
        }
    }
    return $false
}

$names = @()
if ($expSize -gt 0 -and $expRva -ne 0) {
    $off = Convert-RvaToOffset $expRva
    if ($off -lt 0) { Write-Host "Discover: export directory not file-backed."; exit 1 }
    $nFunc = Read-U32 $bytes ($off + 20)
    $nNames = Read-U32 $bytes ($off + 24)
    $addrFuncs = Read-U32 $bytes ($off + 28)
    $addrNames = Read-U32 $bytes ($off + 32)
    $addrOrd = Read-U32 $bytes ($off + 36)
    $fo = Convert-RvaToOffset $addrFuncs
    $no = Convert-RvaToOffset $addrNames
    $oo = Convert-RvaToOffset $addrOrd
    if ($fo -lt 0 -or $no -lt 0 -or $oo -lt 0) { Write-Host "Discover: export tables not file-backed."; exit 1 }
    for ($i = 0; $i -lt $nNames; $i++) {
        $nameRva = Read-U32 $bytes ($no + $i * 4)
        $so = Convert-RvaToOffset $nameRva
        if ($so -lt 0) { continue }
        $sb = New-Object Text.StringBuilder
        $p = $so
        while ($p -lt $bytes.Length -and $bytes[$p] -ne 0) { [void]$sb.Append([char]$bytes[$p]); $p++ }
        $ord = Read-U16 $bytes ($oo + $i * 2)
        if ($ord -ge $nFunc) { continue }
        $funcRva = Read-U32 $bytes ($fo + $ord * 4)
        # Skip forwarders (func RVA inside the export dir) and data exports.
        if ($funcRva -ge $expRva -and $funcRva -lt ($expRva + $expSize)) { continue }
        if (-not (Test-IsCodeRva $funcRva)) { continue }
        $names += $sb.ToString()
    }
}
$names = $names | Sort-Object -Unique

[xml]$xml = Get-Content -LiteralPath $BaseProject -Encoding UTF8
$procs = $xml.SelectSingleNode("//Protection/Procedures")
if (-not $procs) { Write-Host "Discover: no //Protection/Procedures node in base project."; exit 1 }
foreach ($n in $names) {
    $el = $xml.CreateElement("Procedure")
    $el.SetAttribute("MapAddress", $n)
    $el.SetAttribute("Options", "0")
    $el.SetAttribute("CompilationType", "2")
    $el.SetAttribute("Complexity", "100")
    [void]$procs.AppendChild($el)
}
$xml.Save($OutputProject)
Write-Host ("Discover: wrote {0} Ultra/100 export procedures (+keywords) to {1}." -f $names.Count, (Split-Path -Leaf $OutputProject))
exit 0

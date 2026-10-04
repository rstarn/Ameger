# Post-build integration verifier for Ameger Injector.
#
# Create.bat calls this after the interface EXE is built. Two checks, both
# fatal (exit 1) on failure:
#   Embed - the interface EXE must contain the runtime DLL's 8 SHA-256 words
#           (AmegerRuntimeHash0..7, passed from Create.bat) as little-endian
#           dwords, in order. A sequential search proves the build really
#           linked against the mutated runtime DLL instead of leaving the
#           default zero constants (which Main.cpp rejects at startup).
#   Magic - the deployed Configuration.ini must start with the "AMEGERC1"
#           DPAPI marker, proving the shipped config is the encrypted copy
#           rather than a plaintext (or absent) file.
#
# Exit code 0 = verified, 1 = fatal.
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Embed", "Magic")]
    [string]$Check,

    [Parameter(Mandatory = $true)]
    [string]$Path,

    # Comma-separated "0x........" words (AmegerRuntimeHash0..7). A single
    # string, not [string[]]: powershell.exe -File does not bind array
    # parameters reliably, and Create.bat invokes this with -File.
    [string]$Words,

    [string]$Magic
)

$ErrorActionPreference = "Stop"

# Same styling rule as BuildPE.ps1: paint only when stdout is a real console,
# so redirected build logs and CI captures stay free of escape sequences.
$script:UseColor = -not [Console]::IsOutputRedirected
$script:Esc = [char]27
$script:C_Green = "$($script:Esc)[92m"
$script:C_Red = "$($script:Esc)[91m"
$script:C_Dim = "$($script:Esc)[90m"
$script:C_Reset = "$($script:Esc)[0m"

function Get-Painted([string]$Color, [string]$Text) {
    if (-not $script:UseColor) { return $Text }
    return ($Color + $Text + $script:C_Reset)
}

function Write-Ok([string]$Text) {
    Write-Host ("  " + (Get-Painted $script:C_Green "OK") + " " + $Text)
}

function Write-Fail([string]$Text) {
    Write-Host ("  " + (Get-Painted $script:C_Red "[x]") + " " + $Text)
}

if (-not (Test-Path -LiteralPath $Path)) {
    Write-Fail ("Not found: " + $Path)
    exit 1
}

$data = [IO.File]::ReadAllBytes($Path)

if ($Check -eq "Embed") {
    $wordList = @()
    if (-not [string]::IsNullOrWhiteSpace($Words)) { $wordList = $Words -split ',' }
    if ($wordList.Count -ne 8) {
        Write-Fail ("Expected 8 runtime hash words, got " + $wordList.Count)
        exit 1
    }

    # Walk the image once, advancing past each match, so the 8 words must occur
    # in order (and not overlap). Bytes are compared little-endian, matching the
    # uint32 constants the compiler emits for AMEGER_RUNTIME_DLL_HASH0..7.
    $pos = 0
    $last = $data.Length - 4
    for ($i = 0; $i -lt $wordList.Count; $i++) {
        $w = [string]$wordList[$i]
        if ($w.StartsWith("0x") -or $w.StartsWith("0X")) { $w = $w.Substring(2) }
        $val = [Convert]::ToUInt32($w, 16)
        $b = [BitConverter]::GetBytes([uint32]$val)

        $found = -1
        for ($j = $pos; $j -le $last; $j++) {
            if ($data[$j] -eq $b[0] -and $data[$j + 1] -eq $b[1] -and
                $data[$j + 2] -eq $b[2] -and $data[$j + 3] -eq $b[3]) {
                $found = $j
                break
            }
        }
        if ($found -lt 0) {
            Write-Fail ("Runtime hash word " + $i + " not found in order: " + (Get-Painted $script:C_Dim $Path))
            exit 1
        }
        $pos = $found + 4
    }

    Write-Ok ("Embedded runtime hash: " + (Get-Painted $script:C_Green "8") + "/" + (Get-Painted $script:C_Green "8") + " dwords in order (" + (Get-Painted $script:C_Dim $Path) + ")")
    exit 0
}

# Check -eq "Magic"
if ([string]::IsNullOrEmpty($Magic)) {
    Write-Fail "Expected a config magic string"
    exit 1
}
$expected = [Text.Encoding]::ASCII.GetBytes($Magic)
if ($data.Length -lt $expected.Length) {
    Write-Fail ("Encrypted config magic '" + $Magic + "' missing: " + (Get-Painted $script:C_Dim $Path))
    exit 1
}
for ($i = 0; $i -lt $expected.Length; $i++) {
    if ($data[$i] -ne $expected[$i]) {
        Write-Fail ("Encrypted config magic '" + $Magic + "' missing: " + (Get-Painted $script:C_Dim $Path))
        exit 1
    }
}
Write-Ok ("Encrypted config magic: " + (Get-Painted $script:C_Green $Magic) + " (" + (Get-Painted $script:C_Dim $Path) + ")")
exit 0

# DPAPI-encrypts a plaintext configuration into a runtime copy.
#
# A plaintext Configuration.ini names the target process and every stealth
# toggle, so it is a self-describing on-disk artifact. This writes an
# encrypted copy (CurrentUser scope) for deployment; the plaintext master in
# Build\ stays editable and is only used when no encrypted copy is present.
#
# Usage:
#   ProtectConfig.ps1 -Source <plaintext.ini> -Destination <encrypted.ini>
#   ProtectConfig.ps1 -Source <plaintext.ini> -Destination <encrypted.ini> `
#                     -PinPayload <deployed-payload> `
#                     -PayloadName <name> -RuntimeName <name> -ExportMap <map>
#   ProtectConfig.ps1 -Source <plaintext.ini> -Destination <plaintext.ini> `
#                     -PinPayload <deployed-payload> -Plaintext
#
# -PinPayload overrides the PayloadSha256 value in the output with the SHA-256
# of the named file. The master config carries the pristine asset pin and is
# never rewritten; the deployed config, however, must pin the exact DLL that
# ships beside it, which is a different digest once a prepared or protected
# payload is deployed. Deriving the pin here (rather than copying the master's)
# keeps the two consistent without mutating the master.
#
# -PayloadName, -RuntimeName and -ExportMap are the per-build anti-detection
# values (V-02/V-03/V-32): the deployed payload file name, the deployed runtime
# DLL file name, and the runtime DLL export-rename map. The master config does
# not carry them; Create.bat passes them for the initial deploy. When they are
# NOT passed (the legacy path used by ProtectDLL.bat to re-encrypt the config
# after virtualizing the payload), the values already present in the existing
# Destination are preserved verbatim, so the shipped config keeps a stable
# rename map across re-encryptions.
#
# -Plaintext writes the merged text without DPAPI. It is the explicit opt-out
# path (AMEGER_ENCRYPT_CONFIG=0), never a silent fallback: the default still
# encrypts, and an encryption failure is fatal.
#
# Format: 8-byte ASCII magic "SYSCFG01" followed by a raw DPAPI blob of the
# exact input bytes (BOM included), which Interface/Source/Main.cpp
# (DecryptConfigBlob) reverses before the normal UTF-8 parse. The magic is
# what distinguishes an encrypted file from a legacy plaintext one.
#
# Exit codes: 0 = written, 1 = fatal.
param(
    [Parameter(Mandatory = $true)][string]$Source,
    [Parameter(Mandatory = $true)][string]$Destination,

    # Optional payload file whose SHA-256 becomes the PayloadSha256 pin in the
    # output. A prepared/protected payload does not match the pristine asset
    # pin in the master, so the caller passes the deployed payload here.
    [string]$PinPayload,

    # Per-build deployed payload file name (V-02).
    [string]$PayloadName,

    # Per-build deployed runtime DLL file name (V-03).
    [string]$RuntimeName,

    # Per-build runtime export-rename map, "old=new,..." (V-32).
    [string]$ExportMap,

    # Write the merged text without DPAPI. Explicit opt-out only.
    [switch]$Plaintext
)

$ErrorActionPreference = "Stop"
$magic = [Text.Encoding]::ASCII.GetBytes("SYSCFG01")

# Reads a config file as plaintext: decrypts a SYSCFG01-prefixed blob in the
# CurrentUser scope, or returns the bytes as UTF-8 text. Returns $null when the
# file is absent or unreadable so a caller can fall back to "no value".
function Read-ConfigText([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $raw = [IO.File]::ReadAllBytes($Path)
    $enc = $false
    if ($raw.Length -gt $magic.Length) {
        $enc = $true
        for ($i = 0; $i -lt $magic.Length; $i++) {
            if ($raw[$i] -ne $magic[$i]) { $enc = $false; break }
        }
    }
    if ($enc) {
        Add-Type -AssemblyName System.Security | Out-Null
        $blob = New-Object byte[] ($raw.Length - $magic.Length)
        [Array]::Copy($raw, $magic.Length, $blob, 0, $blob.Length)
        $plainBytes = [Security.Cryptography.ProtectedData]::Unprotect($blob, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
        return [Text.Encoding]::UTF8.GetString($plainBytes)
    }
    return [Text.Encoding]::UTF8.GetString($raw)
}

# Case-insensitive ini lookup matching the runtime's own reader (first '='
# splits key from value).
function Get-IniValue([string]$Text, [string]$Key) {
    if ($null -eq $Text) { return $null }
    foreach ($line in [regex]::Split($Text, "\r?\n")) {
        $trimmed = $line.Trim()
        if ($trimmed.Length -eq 0 -or $trimmed.StartsWith(";") -or $trimmed.StartsWith("#")) { continue }
        $eq = $trimmed.IndexOf("=")
        if ($eq -lt 1) { continue }
        if ($trimmed.Substring(0, $eq).Trim() -ieq $Key) { return $trimmed.Substring($eq + 1).Trim() }
    }
    return $null
}

# Removes any existing PayloadName/RuntimeName/ExportMap lines, then inserts the
# supplied pairs (deterministic order) at the end of the [General] section,
# anchored on the PayloadSha256 line so the values never land in a later
# section. Keys with no value are omitted.
function Set-IniKeys([string]$Text, $Pairs) {
    $order = @("PayloadName", "RuntimeName", "ExportMap")
    $rx = '^\s*(PayloadName|RuntimeName|ExportMap)\s*='
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($line in [regex]::Split($Text, "\r?\n")) {
        if ($line -match $rx) { continue }
        $lines.Add($line)
    }

    $insert = New-Object System.Collections.Generic.List[string]
    foreach ($k in $order) {
        if ($Pairs.ContainsKey($k) -and -not [string]::IsNullOrEmpty($Pairs[$k])) {
            $insert.Add($k + " = " + $Pairs[$k])
        }
    }
    if ($insert.Count -eq 0) { return ($lines -join "`r`n") }

    $anchor = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '^\s*PayloadSha256\s*=') { $anchor = $i; break }
    }
    if ($anchor -lt 0) {
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i].Trim() -ieq "[General]") { $anchor = $i; break }
        }
    }
    if ($anchor -lt 0) {
        # No anchor at all: synthesize a [General] header so the keys do not
        # silently land in whatever section happens to be last.
        $lines.Insert(0, "")
        $lines.Insert(0, "[General]")
        $anchor = 0
    }

    for ($j = 0; $j -lt $insert.Count; $j++) {
        $lines.Insert($anchor + 1 + $j, $insert[$j])
    }
    return ($lines -join "`r`n")
}

if (-not (Test-Path -LiteralPath $Source)) { Write-Host "ProtectConfig: source not found: $Source"; exit 1 }

# Resolve the pin override, if any, before touching the source. Fail closed if
# the payload cannot be read: a config whose pin does not match the deployed
# DLL makes the launcher abort at startup.
$pinOverride = $null
if (-not [string]::IsNullOrEmpty($PinPayload)) {
    if (-not (Test-Path -LiteralPath $PinPayload)) {
        Write-Host "ProtectConfig: pin payload not found: $PinPayload"
        exit 1
    }
    $pinOverride = ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([IO.File]::ReadAllBytes($PinPayload))) -replace "-", "")
}

$hasNewKeys = (-not [string]::IsNullOrEmpty($PayloadName)) -or
              (-not [string]::IsNullOrEmpty($RuntimeName)) -or
              (-not [string]::IsNullOrEmpty($ExportMap))

# Already encrypted? Leave it alone so the step is idempotent. An override or
# a new-key injection cannot be applied to an encrypted source (there is no
# plaintext to rewrite), so that combination is a hard error rather than a
# silent no-op.
$existing = [IO.File]::ReadAllBytes($Source)
$isEncrypted = $false
if ($existing.Length -gt $magic.Length) {
    $same = $true
    for ($i = 0; $i -lt $magic.Length; $i++) {
        if ($existing[$i] -ne $magic[$i]) { $same = $false; break }
    }
    $isEncrypted = $same
}
if ($isEncrypted) {
    if ($null -ne $pinOverride) {
        Write-Host "ProtectConfig: cannot apply a pin override to an already-encrypted source"
        exit 1
    }
    if ($hasNewKeys) {
        Write-Host "ProtectConfig: cannot inject deployment keys into an already-encrypted source"
        exit 1
    }
    Write-Host "ProtectConfig: source is already encrypted; copying verbatim."
    Copy-Item -LiteralPath $Source -Destination $Destination -Force
    exit 0
}

# --- plaintext source: build the output text -----------------------------
$text = [Text.Encoding]::UTF8.GetString($existing)
$modified = $false

if ($null -ne $pinOverride) {
    if ($text -notmatch '(?m)^PayloadSha256\s*=.*$') {
        Write-Host "ProtectConfig: source has no PayloadSha256 line to override"
        exit 1
    }
    $text = [regex]::Replace($text, '(?m)^PayloadSha256\s*=.*$', 'PayloadSha256 = ' + $pinOverride)
    $modified = $true
    Write-Host ("ProtectConfig: PayloadSha256 pinned to " + $pinOverride)
}

# The three per-build values: prefer the caller's arguments; otherwise carry
# over whatever the existing destination already carries (legacy re-encrypt).
$preserved = $null
if ((-not $hasNewKeys) -and (Test-Path -LiteralPath $Destination)) {
    $preserved = Read-ConfigText $Destination
}

$pairs = @{}
if (-not [string]::IsNullOrEmpty($PayloadName)) {
    $pairs["PayloadName"] = $PayloadName
} elseif ($null -ne $preserved) {
    $carry = Get-IniValue $preserved "PayloadName"
    if (-not [string]::IsNullOrEmpty($carry)) { $pairs["PayloadName"] = $carry }
}
if (-not [string]::IsNullOrEmpty($RuntimeName)) {
    $pairs["RuntimeName"] = $RuntimeName
} elseif ($null -ne $preserved) {
    $carry = Get-IniValue $preserved "RuntimeName"
    if (-not [string]::IsNullOrEmpty($carry)) { $pairs["RuntimeName"] = $carry }
}
if (-not [string]::IsNullOrEmpty($ExportMap)) {
    $pairs["ExportMap"] = $ExportMap
} elseif ($null -ne $preserved) {
    $carry = Get-IniValue $preserved "ExportMap"
    if (-not [string]::IsNullOrEmpty($carry)) { $pairs["ExportMap"] = $carry }
}

if ($pairs.Count -gt 0) {
    $before = $text
    $text = Set-IniKeys $text $pairs
    if ($text -ne $before) { $modified = $true }
    foreach ($k in @("PayloadName", "RuntimeName", "ExportMap")) {
        if ($pairs.ContainsKey($k)) {
            Write-Host ("ProtectConfig: " + $k + " = " + $pairs[$k])
        }
    }
}

if ($modified) {
    $plain = (New-Object Text.UTF8Encoding($false)).GetBytes($text)
} else {
    $plain = $existing
}

if ($Plaintext) {
    # Explicit opt-out: write the merged text without DPAPI.
    [IO.File]::WriteAllBytes($Destination, $plain)
    Write-Host "ProtectConfig: wrote plaintext (opt-out)."
    exit 0
}

Add-Type -AssemblyName System.Security | Out-Null
try {
    $blob = [Security.Cryptography.ProtectedData]::Protect(
        $plain, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
} catch {
    Write-Host ("ProtectConfig: DPAPI failed: " + $_.Exception.Message)
    exit 1
}

$out = New-Object byte[] ($magic.Length + $blob.Length)
[Array]::Copy($magic, 0, $out, 0, $magic.Length)
[Array]::Copy($blob, 0, $out, $magic.Length, $blob.Length)
[IO.File]::WriteAllBytes($Destination, $out)

exit 0

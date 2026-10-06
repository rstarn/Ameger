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
#                     -PinPayload <deployed-payload>
#
# -PinPayload overrides the PayloadSha256 value in the output with the SHA-256
# of the named file. The master config carries the pristine asset pin and is
# never rewritten; the deployed config, however, must pin the exact DLL that
# ships beside it, which is a different digest once a prepared or protected
# payload is deployed. Deriving the pin here (rather than copying the master's)
# keeps the two consistent without mutating the master.
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
    [string]$PinPayload
)

$ErrorActionPreference = "Stop"
$magic = [Text.Encoding]::ASCII.GetBytes("SYSCFG01")

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

# Already encrypted? Leave it alone so the step is idempotent. An override
# cannot be applied to an encrypted source (there is no plaintext to rewrite),
# so that combination is a hard error rather than a silent no-op.
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
    Write-Host "ProtectConfig: source is already encrypted; copying verbatim."
    Copy-Item -LiteralPath $Source -Destination $Destination -Force
    exit 0
}

if ($null -ne $pinOverride) {
    # Rewrite in memory: read as text (BOM-stripping), replace the single
    # PayloadSha256 line, and protect the UTF-8 bytes. No intermediate file is
    # written, so nothing has to be swept afterwards.
    $text = [Text.Encoding]::UTF8.GetString($existing)
    if ($text -notmatch '(?m)^PayloadSha256\s*=.*$') {
        Write-Host "ProtectConfig: source has no PayloadSha256 line to override"
        exit 1
    }
    $text = [regex]::Replace($text, '(?m)^PayloadSha256\s*=.*$', 'PayloadSha256 = ' + $pinOverride)
    $plain = (New-Object Text.UTF8Encoding($false)).GetBytes($text)
    Write-Host ("ProtectConfig: PayloadSha256 pinned to " + $pinOverride)
} else {
    $plain = $existing
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

# DPAPI-encrypts a plaintext configuration into a runtime copy.
#
# A plaintext Configuration.ini names the target process and every stealth
# toggle, so it is a self-describing on-disk artifact. This writes an
# encrypted copy (CurrentUser scope) for deployment; the plaintext master in
# Build\ stays editable and is only used when no encrypted copy is present.
#
# Usage:
#   ProtectConfig.ps1 -Source <plaintext.ini> -Destination <encrypted.ini>
#
# Format: 8-byte ASCII magic "AMEGERC1" followed by a raw DPAPI blob of the
# exact input bytes (BOM included), which Interface/Source/Main.cpp
# (DecryptConfigBlob) reverses before the normal UTF-8 parse. The magic is
# what distinguishes an encrypted file from a legacy plaintext one.
#
# Exit codes: 0 = written, 1 = fatal.
param(
    [Parameter(Mandatory = $true)][string]$Source,
    [Parameter(Mandatory = $true)][string]$Destination
)

$ErrorActionPreference = "Stop"
$magic = [Text.Encoding]::ASCII.GetBytes("AMEGERC1")

if (-not (Test-Path -LiteralPath $Source)) { Write-Host "ProtectConfig: source not found: $Source"; exit 1 }

# Already encrypted? Leave it alone so the step is idempotent.
$existing = [IO.File]::ReadAllBytes($Source)
if ($existing.Length -gt $magic.Length) {
    $same = $true
    for ($i = 0; $i -lt $magic.Length; $i++) {
        if ($existing[$i] -ne $magic[$i]) { $same = $false; break }
    }
    if ($same) {
        Write-Host "ProtectConfig: source is already encrypted; copying verbatim."
        Copy-Item -LiteralPath $Source -Destination $Destination -Force
        exit 0
    }
}

Add-Type -AssemblyName System.Security | Out-Null
try {
    $plain = [IO.File]::ReadAllBytes($Source)
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

Write-Host ("ProtectConfig: wrote encrypted config ({0} -> {1} bytes) to {2}" -f `
    $plain.Length, $out.Length, (Split-Path -Leaf $Destination))
exit 0

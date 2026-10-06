# Emits the per-build deployed file names for the payload DLL and the runtime
# DLL (V-02/V-03).
#
# Create.bat deploys the payload to DLLs\<PayloadName> and the runtime DLL to
# DLLs\<RuntimeName>, so a shipped release folder never exposes the stable
# Jlov.dll / rtdll_* on-disk names that identified every previous build.
#
# Each name is 8..12 ASCII alphanumeric characters (the first a letter)
# followed by ".dll", drawn from the OS CSPRNG. The two names are guaranteed
# distinct within a build.
#
# Output is two KEY=VALUE lines consumed by Create.bat:
#   PAYLOAD_NAME=<name>.dll
#   RUNTIME_NAME=<name>.dll
#
# Strict Windows PowerShell 5.1. Exit code 0 = names produced, 1 = failure
# (fatal: the caller refuses to deploy a stable or missing name).

param()

$ErrorActionPreference = "Stop"

$script:Letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
$script:Alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

function New-DeployedName($Rng) {
    # Length 8..12, then a random letter, then alphanumerics. One reusable byte
    # buffer keeps the CSPRNG draw simple and PS5.1-safe.
    $buf = New-Object byte[] 1
    $Rng.GetBytes($buf)
    $length = 8 + ($buf[0] % 5)

    $chars = New-Object 'char[]' $length
    $Rng.GetBytes($buf)
    $chars[0] = $script:Letters[$buf[0] % $script:Letters.Length]
    for ($i = 1; $i -lt $length; $i++) {
        $Rng.GetBytes($buf)
        $chars[$i] = $script:Alnum[$buf[0] % $script:Alnum.Length]
    }
    return (-join $chars)
}

try {
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
} catch {
    Write-Host ("  [x] ERROR: name generation failed (RNG unavailable): " + $_.Exception.Message)
    exit 1
}

try {
    $payload = New-DeployedName $rng
    do { $runtime = New-DeployedName $rng } while ($runtime -eq $payload)
} finally {
    $rng.Dispose()
}

# Fail closed on any shape violation rather than emit a name the fixed contract
# does not allow.
foreach ($n in @($payload, $runtime)) {
    if ($n.Length -lt 8 -or $n.Length -gt 12) {
        Write-Host "  [x] ERROR: generated name has invalid length"
        exit 1
    }
    if ($n -notmatch '^[A-Za-z][A-Za-z0-9]+$') {
        Write-Host "  [x] ERROR: generated name has invalid characters"
        exit 1
    }
}
if ($payload -eq $runtime) {
    Write-Host "  [x] ERROR: generated names collide"
    exit 1
}

Write-Output ("PAYLOAD_NAME=" + $payload + ".dll")
Write-Output ("RUNTIME_NAME=" + $runtime + ".dll")
exit 0

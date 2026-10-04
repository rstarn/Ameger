# Emits per-build compile-time seeds for the Ameger Injector runtime.
#
# These are compiled into the binary as ordinary constants (see
# AmegerMmapSentinel in Interface/Template/AmegerInjector.vcxproj), so every
# link produces a different instruction encoding without touching any source
# file on disk.
#
# Output is one MSBuild global property, one per line:
#   AmegerMmapSentinel=0xXXXXXXXX   MMAP_SEC_END() return value
#
# The sentinel is only an address/range anchor inside its own code section,
# so any value is valid; it is forced odd to avoid looking like a plausible
# "0" or a small loop counter in a disassembly diff.
#
# Strict Windows PowerShell 5.1. Exit code 0 = seeds produced,
# 1 = failure (the caller must fall back to the default vcxproj values).

param()

$ErrorActionPreference = "Stop"

try {
    $rng = New-Object Security.Cryptography.RNGCryptoServiceProvider
    $buf = New-Object byte[] 4
    $rng.GetBytes($buf)
    $rng.Dispose()
} catch {
    Write-Host ("  [x] Seed generation failed: " + $_.Exception.Message)
    exit 1
}

if ($buf.Length -ne 4) { Write-Host "  [x] RNG returned a short buffer"; exit 1 }

$mmap = ([BitConverter]::ToUInt32($buf, 0) -bor 1) -band 0xFFFFFFFF

Write-Output ("AmegerMmapSentinel=0x{0:X8}" -f $mmap)
exit 0

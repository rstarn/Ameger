# Emits per-build compile-time seeds for the Ameger Injector runtime.
#
# These are compiled into the binary as ordinary constants (see
# AmegerMmapSentinel in Interface/Template/AmegerInjector.vcxproj), so every
# link produces a different instruction encoding without touching any source
# file on disk.
#
# Output is two MSBuild global properties, one per line:
#   AmegerMmapSentinel=0xXXXXXXXX   MMAP_SEC_END() return value
#   AmegerStringSeed=0xXXXXXXXX     per-build rotation for every string-tier
#   key (XOR/KC/layered ciphertext in .rdata changes on every link, so no
#   cross-build byte signature survives even with identical sources)
#
# Both values are forced odd to avoid looking like a plausible "0" or a small
# loop counter in a disassembly diff.
#
# Strict Windows PowerShell 5.1. Exit code 0 = seeds produced,
# 1 = failure (fatal: the caller refuses to build with a fixed sentinel).

param()

$ErrorActionPreference = "Stop"

# Both draws happen before the RNG is released: the sentinel and the string
# seed come from the same provider, so disposing after the first draw would
# make the second GetBytes a use-after-dispose. The finally block guarantees
# the handle is released on every path, including the failure path.
try {
    $rng = New-Object Security.Cryptography.RNGCryptoServiceProvider
    $buf = New-Object byte[] 4
    $rng.GetBytes($buf)
    $mmap = ([BitConverter]::ToUInt32($buf, 0) -bor 1) -band 0xFFFFFFFF
    $rng.GetBytes($buf)
    $str = ([BitConverter]::ToUInt32($buf, 0) -bor 1) -band 0xFFFFFFFF
} catch {
    Write-Host ("  [x] ERROR: seed generation failed (RNG unavailable): " + $_.Exception.Message) -ForegroundColor Red
    exit 1
} finally {
    if ($null -ne $rng) { $rng.Dispose() }
}

if ($buf.Length -ne 4) {
    Write-Host "  [x] ERROR: RNG returned a short buffer; refusing to build with a fixed sentinel." -ForegroundColor Red
    exit 1
}

Write-Output ("AmegerMmapSentinel=0x{0:X8}" -f $mmap)
Write-Output ("AmegerStringSeed=0x{0:X8}" -f $str)
exit 0

# VMProtect wrapper for Ameger Injector (Windows PowerShell 5.1).
#
# Protects one PE binary with VMProtect Ultimate console edition and replaces
# the input in place. Designed to slot into Build\Create.bat:
#   runtime DLL : *before* the SHA-256 hash step (the Interface embeds the
#                 hash of the *protected* DLL, so protecting after hashing
#                 would break the VerifyRuntimeBytes gate).
#   interface EXE: *after* its timestamp/mutate steps (nothing embeds the
#                 EXE hash, so last-write-wins is fine).
#
# Usage:
#   CompileVmp.ps1 -InputFile <path> [-Project <path.vmp>] [-Tool <path>]
#
# Exit codes:
#   0 = protected, input replaced
#   2 = skipped (console tool not found; caller warns and continues unprotected)
#   1 = fatal (tool ran but failed, or IO error; caller must fail closed)
param(
    [Parameter(Mandatory = $true)][string]$InputFile,
    [string]$Project = "",
    [string]$Tool = "",
    # Enumerate every CLI-addressable function (export names; raw VAs do not
    # resolve in the 3.8.4 console) and protect each with Ultra/100 (template
    # keeps Options + VMComplexity=100/VMInstances=10 + EntryPoint keyword;
    # discovered names are appended per build).
    [switch]$AutoProcedures
)

$ErrorActionPreference = "Stop"

function Resolve-VmpTool([string]$hint) {
    if ($hint -ne "" -and (Test-Path -LiteralPath $hint)) { return $hint }
    $envHint = $env:AMEGER_VMP_CON
    if ($null -ne $envHint -and $envHint -ne "" -and (Test-Path -LiteralPath $envHint)) { return $envHint }
    $candidates = @(
        "$env:ProgramFiles\VMProtect Ultimate\VMProtect_Con.exe",
        "${env:ProgramFiles(x86)}\VMProtect Ultimate\VMProtect_Con.exe"
    )
    foreach ($c in $candidates) {
        if ($null -ne $c -and $c -ne "" -and (Test-Path -LiteralPath $c)) { return $c }
    }
    try {
        $found = (Get-Command "VMProtect_Con.exe" -ErrorAction SilentlyContinue).Source
        if ($null -ne $found -and $found -ne "" -and (Test-Path -LiteralPath $found)) { return $found }
    } catch { }
    return ""
}

if (-not (Test-Path -LiteralPath $InputFile)) {
    Write-Host "CompileVmp: input not found: $InputFile"
    exit 1
}

$toolPath = Resolve-VmpTool $Tool
if ($toolPath -eq "") {
    Write-Host "CompileVmp: VMProtect_Con.exe not found; skipping protection for $(Split-Path -Leaf $InputFile)."
    exit 2
}

$projectPath = ""
$autoProject = ""
if ($Project -ne "") {
    if (Test-Path -LiteralPath $Project) {
        if ($AutoProcedures) {
            $discover = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) "VMPProcedures.ps1"
            # PID-suffixed temp name: spaces in the input file name must not
            # leak into temp paths (PS 5.1 Start-Process does not quote array
            # args, which broke "Ameger Injector - x64.vmp" mid-build).
            $autoProject = Join-Path ([IO.Path]::GetTempPath()) ("ameger_vmp_" + $PID + ".vmp")
            if (Test-Path -LiteralPath $discover) {
                & powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File $discover -InputFile $InputFile -BaseProject $Project -OutputProject $autoProject
                if ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $autoProject)) {
                    $projectPath = $autoProject
                } else {
                    Write-Host "CompileVmp: auto-discovery failed; using base project as-is."
                    $projectPath = $Project
                }
            } else {
                Write-Host "CompileVmp: VMPProcedures.ps1 missing; using base project as-is."
                $projectPath = $Project
            }
        } else {
            $projectPath = $Project
        }
    } else {
        Write-Host "CompileVmp: project not found ($Project); using VMProtect defaults."
    }
}

$dir = Split-Path -Parent $InputFile
$tmpOut = Join-Path $dir ("~vmp_" + [IO.Path]::GetFileName($InputFile))
if (Test-Path -LiteralPath $tmpOut) { Remove-Item -LiteralPath $tmpOut -Force }

Write-Host "CompileVmp: $toolPath `"$(Split-Path -Leaf $InputFile)`" ..."
# Single pre-quoted command line: PS 5.1 Start-Process joins array args with
# bare spaces, which split paths like "Ameger Injector - x64.dll" and the
# -pf project. Every path is quoted here instead.
$argLine = '"' + $InputFile + '" "' + $tmpOut + '"'
if ($projectPath -ne "") { $argLine += ' -pf "' + $projectPath + '"' }
# -bd keeps VMProtect's internal build date plausible and consistent with the
# PE TimeDateStamp that BuildPE stamps. Without it VMP uses the wall clock,
# which is the same build-date correlation the mutation layer removes.
$buildDate = (Get-Date).AddDays(-(Get-Random -Minimum 30 -Maximum 181)).ToString("yyyy-MM-dd")
$argLine += ' -bd ' + $buildDate
$proc = Start-Process -FilePath $toolPath -ArgumentList $argLine -NoNewWindow -Wait -PassThru
if ($proc.ExitCode -ne 0) {
    Write-Host "CompileVmp: VMProtect failed with exit $($proc.ExitCode)."
    if (Test-Path -LiteralPath $tmpOut) { Remove-Item -LiteralPath $tmpOut -Force -ErrorAction SilentlyContinue }
    if ($autoProject -ne "" -and (Test-Path -LiteralPath $autoProject)) { Remove-Item -LiteralPath $autoProject -Force -ErrorAction SilentlyContinue }
    exit 1
}
if (-not (Test-Path -LiteralPath $tmpOut)) {
    Write-Host "CompileVmp: VMProtect reported success but produced no output file."
    if ($autoProject -ne "" -and (Test-Path -LiteralPath $autoProject)) { Remove-Item -LiteralPath $autoProject -Force -ErrorAction SilentlyContinue }
    exit 1
}
$size = (Get-Item -LiteralPath $tmpOut).Length
if ($size -le 0) {
    Write-Host "CompileVmp: output file is empty."
    Remove-Item -LiteralPath $tmpOut -Force -ErrorAction SilentlyContinue
    exit 1
}

Move-Item -LiteralPath $tmpOut -Destination $InputFile -Force
if ($autoProject -ne "" -and (Test-Path -LiteralPath $autoProject)) { Remove-Item -LiteralPath $autoProject -Force -ErrorAction SilentlyContinue }
Write-Host "CompileVmp: protected $(Split-Path -Leaf $InputFile) ($size bytes)."
exit 0

param(
    [Parameter(Mandatory = $true)][string]$Project,
    [Parameter(Mandatory = $true)][string]$Out
)

# Produce a build-local copy of a .vmp project with a randomized protector
# segment name.
#
# The shipped projects set VMCodeSectionName=".???", which tells VMProtect to
# substitute a name of its choosing. In practice that produced the SAME name
# every build (.Tlp observed on 3.8.4), which makes the segment a stable static
# fingerprint: anything that enumerates sections sees a fixed, unusual,
# multi-megabyte executable segment and can conclude "this binary was protected".
# Choosing the name here makes it vary per build, so the signature has to be
# rediscovered each time.
#
# The original template is never modified; the rewritten copy lives in the
# staging directory and is deleted with it.
#
# Prints SEG_NAME=<name> on success.

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $Project)) { Write-Host "  [!] project not found: $Project"; exit 1 }

$text = [IO.File]::ReadAllText($Project)

# Segment names live in an 8-byte PE field, so stay well inside that.
$alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ'
$name = '.' + (-join (1..4 | ForEach-Object { $alphabet[[int](Get-Random -Maximum $alphabet.Length)] }))

if ($text -notmatch 'VMCodeSectionName="[^"]*"') {
    Write-Host "  [!] no VMCodeSectionName attribute in $Project"
    exit 1
}

$rewritten = [regex]::Replace($text, 'VMCodeSectionName="[^"]*"', 'VMCodeSectionName="' + $name + '"')

# Belt and braces: the rewritten project must still name the same input binary,
# otherwise the protection stage would cross-wire the two templates.
$before = ([regex]::Match($text, 'InputFileName="([^"]+)"')).Groups[1].Value
$after = ([regex]::Match($rewritten, 'InputFileName="([^"]+)"')).Groups[1].Value
if ($before -ne $after) { Write-Host '  [!] InputFileName changed during rewrite'; exit 1 }

[IO.File]::WriteAllText($Out, $rewritten, (New-Object Text.UTF8Encoding($false)))
if (-not (Test-Path -LiteralPath $Out)) { Write-Host '  [!] failed to write rewritten project'; exit 1 }

Write-Host ("SEG_NAME={0}" -f $name)
exit 0
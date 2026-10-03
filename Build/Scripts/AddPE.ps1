$failed = $false
$Files = @($args)
foreach ($f in $Files) {
  # Freshly-linked binaries are often briefly memory-mapped by real-time AV
  # scanning them, which fails the rewrite with "user-mapped section open".
  # Retry transient IO locks; fail fast on permanent validation errors.
  $done = $false
  for ($attempt = 1; $attempt -le 20 -and -not $done; $attempt++) {
    try {
      $d = [IO.File]::ReadAllBytes($f)
      if ($d.Length -lt 64 -or $d[0] -ne 77 -or $d[1] -ne 90) { throw 'not MZ' }
      $e = [BitConverter]::ToInt32($d, 60)
      if ($e -le 0 -or ($e + 8 + 4) -gt $d.Length) { throw 'bad e_lfanew' }
      if ([BitConverter]::ToUInt32($d, $e) -ne 0x4550) { throw 'not PE' }
        $epoch = [DateTime]::new(1970, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)
        $now = [DateTime]::UtcNow
        $daysBack = Get-Random -Minimum 30 -Maximum 181
        $stamp = $now.AddDays(-$daysBack).AddSeconds(-(Get-Random -Minimum 0 -Maximum 86400))
        $minuteFloor = [DateTime]::new($stamp.Year, $stamp.Month, $stamp.Day, $stamp.Hour, $stamp.Minute, 0, [DateTimeKind]::Utc)
        $ts = [UInt32][int64]($minuteFloor - $epoch).TotalSeconds
        $rnd = [BitConverter]::GetBytes($ts)
        [Array]::Copy($rnd, 0, $d, ($e + 8), 4)
      [IO.File]::WriteAllBytes($f, $d)
      Write-Host ("Retimestamped: " + $f)
      $done = $true
    } catch {
      # Method invocations wrap the real error (InnerException), so walk
      # the chain: only IOExceptions (locks, AV scans) are retried.
      $chain = $_.Exception
      while ($chain -and -not ($chain -is [System.IO.IOException])) { $chain = $chain.InnerException }
      if ($chain -and $attempt -lt 20) {
        Start-Sleep -Milliseconds 500
      } else {
        Write-Host ("FAILED: " + $f + " : " + $_.Exception.Message)
        $failed = $true
      }
    }
  }
}
if ($failed) { exit 1 }

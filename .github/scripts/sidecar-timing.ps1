# SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
# SPDX-License-Identifier: GPL-3.0-or-later
# Lane 3c diagnostic: time the bundled sidecar on its own for the Standard list, without and with
# --elevate, so the e2e's elevated hang can be told apart from a slow scan. Writes sidecar-timing.json.
param([string]$Exe = 'vendor/rongroi-scan.exe', [int]$LimitSeconds = 600)
$ErrorActionPreference = 'Stop'
$collectors = @('posture','driver_service','antivirus_product','autostart','defender_exclusion','fivem_dir','net_config','os_image','install_marker','process','evtx','prefetch','bam','pca','userassist','pci_device','hid_device','windows_start','event_fields','usn')
$request = [ordered]@{
  binding = [ordered]@{ ticket = '0123456789abcdef0123456789abcdef'; nonce = 'ci-timing-nonce' }
  policy = [ordered]@{ profile = 'standard'; required_collectors = $collectors; require_elevation = $true; server_name = 'CI timing'; policy_hash = '0000000000000000' }
  producer = [ordered]@{ name = 'rongroi-connect'; version = '0.1.0'; mode = 'single-shot' }
} | ConvertTo-Json -Compress -Depth 5
$exePath = (Resolve-Path $Exe).Path
$results = @()
foreach ($elevate in @($false, $true)) {
  $hex = -join ((1..32) | ForEach-Object { '{0:x}' -f (Get-Random -Maximum 16) })
  $name = "rongroi-$hex"
  $server = New-Object System.IO.Pipes.NamedPipeServerStream($name, [System.IO.Pipes.PipeDirection]::InOut, 1, [System.IO.Pipes.PipeTransmissionMode]::Byte, [System.IO.Pipes.PipeOptions]::Asynchronous)
  $argList = @('--pipe', "\\.\pipe\$name")
  if ($elevate) { $argList += '--elevate' }
  $out = Join-Path $env:RUNNER_TEMP "timing-$elevate.out"
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $p = Start-Process -FilePath $exePath -ArgumentList $argList -PassThru -WindowStyle Hidden -RedirectStandardOutput $out
  $null = $p.Handle
  $wait = $server.WaitForConnectionAsync()
  $connected = $wait.Wait(60000)
  $connectMs = $sw.ElapsedMilliseconds
  $bytes = 0
  $readDone = $false
  if ($connected) {
    $line = [Text.Encoding]::UTF8.GetBytes($request + "`n")
    $server.Write($line, 0, $line.Length); $server.Flush()
    $ms = New-Object IO.MemoryStream; $buf = New-Object byte[] 65536
    $task = $null
    while ($sw.Elapsed.TotalSeconds -lt $LimitSeconds) {
      $task = $server.ReadAsync($buf, 0, $buf.Length)
      if (-not $task.Wait(([int]($LimitSeconds - $sw.Elapsed.TotalSeconds) * 1000))) { break }
      if ($task.Result -le 0) { $readDone = $true; break }
      $ms.Write($buf, 0, $task.Result)
    }
    $bytes = $ms.Length
  }
  $exited = $p.WaitForExit(5000)
  if (-not $exited) { try { $p.Kill() } catch {} }
  $server.Dispose()
  $stdout = if (Test-Path $out) { (Get-Content $out -Raw) } else { '' }
  $results += [ordered]@{
    elevate = $elevate; connected = $connected; connect_ms = $connectMs; record_bytes = $bytes
    read_complete = $readDone; seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1)
    exit_code = $(if ($exited) { $p.ExitCode } else { $null }); stdout = "$stdout".Trim()
  }
}
$results | ConvertTo-Json -Depth 4 | Tee-Object -FilePath sidecar-timing.json

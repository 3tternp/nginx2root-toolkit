<#
.SYNOPSIS
  Vairav Technology CSOC - NGINX2Root (CVE-2026-123007 + 4 related) exposure check for Windows hosts.
.DESCRIPTION
  Read-only. Never sends exploit traffic. Per nginx.exe instance it checks:
    1. Version vs fixed releases (OSS 1.31.9 / 1.30.7; Plus 37.3.0.1 / 37.0.8.1)
    2. Running process older than the binary on disk (restart required)
    3. Affected features in the active config (HTTP/2, HTTP/3, resolver+SSI/mirror, mail proxy)
    4. Optional handshake-only remote probe for HTTP/2 (ALPN h2) and HTTP/3 (Alt-Svc) - needs PowerShell 7+
  Also works with PowerShell 7 on Linux/macOS for the local checks.
.PARAMETER NginxBin    Path to nginx.exe (default: auto-discover)
.PARAMETER ConfigDump  File containing 'nginx -T' output
.PARAMETER Probe       One or more HOST[:PORT] targets for the handshake-only probe
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\nginx2root_check_windows.ps1
  pwsh .\nginx2root_check_windows.ps1 -Probe www.example.com:443
.NOTES
  Exit codes: 0 no exposure found | 1 vulnerable / restart required | 2 review needed | 3 nginx not found
#>
[CmdletBinding()]
param(
  [string]$NginxBin,
  [string]$ConfigDump,
  [string[]]$Probe = @()
)
$ErrorActionPreference = 'Continue'

$CVES = @(
  @{Id='CVE-2026-123007'; Title='HTTP/2 flow-control overflow (nginx2root)';                         Since=[version]'1.9.5'},
  @{Id='CVE-2026-123633'; Title='HTTP/2 connection draining use-after-free';                         Since=[version]'1.19.7'},
  @{Id='CVE-2026-123634'; Title='DNS resolver use-after-free (variable proxy_pass + SSI/mirror)';    Since=[version]'1.13.4'},
  @{Id='CVE-2026-121810'; Title='HTTP/3 (QUIC) stream use-after-free';                               Since=[version]'1.25.0'},
  @{Id='CVE-2026-113425'; Title='Mail proxy auth_http use-after-free';                               Since=[version]'0.5.15'}
)

function Test-Fixed([version]$v) {
  return ($v -ge [version]'1.31.9') -or (($v -ge [version]'1.30.7') -and ($v -lt [version]'1.31.0'))
}
function Invoke-Native([string]$exe, [string[]]$arguments) {
  # Capture stdout+stderr (nginx writes -v / -V to stderr) as plain text
  $dir = Split-Path -Parent $exe
  $old = Get-Location
  try { if ($dir) { Set-Location $dir }
        $o = & $exe @arguments 2>&1 | ForEach-Object { $_.ToString() }
        return ($o -join "`n") }
  catch { return "" }
  finally { Set-Location $old }
}
function Say($text, $color = 'White') { Write-Host $text -ForegroundColor $color }

Say '==================================================================' Cyan
Say " NGINX2Root (CVE-2026-123007 + 4) exposure check - $env:COMPUTERNAME - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" Cyan
Say '==================================================================' Cyan

# ---- locate binaries ----------------------------------------------------------
$bins = New-Object System.Collections.Generic.List[string]
function Add-Bin($p) {
  if ($p -and (Test-Path -LiteralPath $p -PathType Leaf)) {
    $full = (Resolve-Path -LiteralPath $p).Path
    if (-not ($bins -contains $full)) { $bins.Add($full) }
  }
}
if ($NginxBin) { Add-Bin $NginxBin } else {
  $cmd = Get-Command nginx -ErrorAction SilentlyContinue; if ($cmd) { Add-Bin $cmd.Source }
  Get-Process -Name nginx -ErrorAction SilentlyContinue | ForEach-Object { try { Add-Bin $_.Path } catch {} }
  foreach ($p in @('C:\nginx\nginx.exe','C:\Program Files\nginx\nginx.exe','C:\tools\nginx\nginx.exe','D:\nginx\nginx.exe','/usr/sbin/nginx','/usr/local/sbin/nginx')) { Add-Bin $p }
}
if ($bins.Count -eq 0) { Say '[i] No nginx binary found on this host.' Cyan }

$worst = 0   # 0 ok, 2 review, 1 vulnerable (1 wins)
function Set-Worst($n) { if ($n -eq 1) { $script:worst = 1 } elseif ($n -eq 2 -and $script:worst -ne 1) { $script:worst = 2 } }
$foundAny = $bins.Count -gt 0

foreach ($bin in $bins) {
  Write-Host ''; Say "--- $bin ---" White
  $vtxt = (Invoke-Native $bin @('-v')).Trim().Split("`n")[0]
  $flags = (Invoke-Native $bin @('-V'))
  $plus = $vtxt -match 'nginx-plus'
  $ver = $null
  if ($vtxt -match 'nginx/(\d+\.\d+\.\d+)') { $ver = [version]$Matches[1] }
  Say "  $vtxt"
  if ($plus) { Say '  NGINX Plus detected: confirm against F5 - fixed 37.3.0.1 / 37.0.8.1; R33-R36 have no fix.' Yellow }

  # config
  $cfg = $null
  if ($ConfigDump) { $cfg = Get-Content -Raw -LiteralPath $ConfigDump -ErrorAction SilentlyContinue }
  else { $o = Invoke-Native $bin @('-T'); if ($o -match 'configuration file' -and $o.Split("`n")[0] -notmatch 'emerg') { $cfg = $o } }
  $f = @{ h2=$false; h3=$false; proxy=$false; varproxy=$false; res=$false; ssi=$false; mir=$false; mail=$false }
  if ($cfg) {
    $t = ($cfg -split "`n" | ForEach-Object { $_ -replace '#.*$','' }) -join ' '
    $f.h2       = ($t -match '(?:^|[;{}])\s*listen[^;]*\shttp2(?:[\s;]|$)') -or ($t -match '(?:^|[;{}])\s*http2\s+on\s*;')
    $f.h3       = ($t -match '(?:^|[;{}])\s*listen[^;]*\squic(?:[\s;]|$)')  -or ($t -match '(?:^|[;{}])\s*http3\s+on\s*;')
    $f.proxy    = $t -match '(?:^|[;{}\s])proxy_pass\s'
    $f.varproxy = $t -match 'proxy_pass\s+[^;]*\$'
    $f.res      = $t -match '(?:^|[;{}])\s*resolver\s'
    $f.ssi      = $t -match '(?:^|[;{}])\s*ssi\s+on\s*;'
    $f.mir      = $t -match '(?:^|[;{}])\s*mirror\s+(?!off\b)\S+'
    $f.mail     = ($t -match '(?:^|[;{}])\s*mail\s*\{') -and ($t -match 'auth_http\s')
    if ($flags -match 'configure arguments') {
      if ($flags -notmatch 'http_v2_module') { $f.h2 = $false }
      if ($flags -notmatch 'http_v3_module') { $f.h3 = $false }
      if ($flags -notmatch '--with-mail')    { $f.mail = $false }
    }
  }
  $chain = $f.res -and $f.varproxy -and ($f.ssi -or $f.mir)
  $used = @{
    'CVE-2026-123007' = $f.h2
    'CVE-2026-123633' = ($f.h2 -and $f.proxy)
    'CVE-2026-123634' = $chain
    'CVE-2026-121810' = $f.h3
    'CVE-2026-113425' = $f.mail
  }

  foreach ($c in $CVES) {
    if (-not $ver)                  { $st='REVIEW';     $dt='version not parsed';                         $col='Yellow' }
    elseif (Test-Fixed $ver)        { $st='FIXED';      $dt='version >= fixed release';                   $col='Green' }
    elseif ($ver -lt $c.Since)      { $st='N/A';        $dt="feature introduced in $($c.Since)";          $col='Cyan' }
    elseif (-not $cfg)              { $st='POSSIBLE';   $dt='config not readable (use -ConfigDump / run as admin)'; $col='Yellow' }
    elseif ($used[$c.Id])           { $st='EXPOSED';    $dt='affected feature in use';                    $col='Red' }
    else                            { $st='VULN-BUILD'; $dt='vulnerable build, affected feature not seen in config'; $col='Yellow' }
    Say ('  {0,-10} {1}  {2}  [{3}]' -f $st, $c.Id, $c.Title, $dt) $col
  }

  # running process older than binary on disk?
  $stale = $false
  $binItem = Get-Item -LiteralPath $bin
  Get-Process -Name nginx -ErrorAction SilentlyContinue | Where-Object { try { $_.Path -eq $bin } catch { $false } } |
    Sort-Object StartTime | Select-Object -First 1 | ForEach-Object {
      if ($binItem.LastWriteTime -gt $_.StartTime) { $stale = $true; Say "  nginx PID $($_.Id): started before the binary was replaced - RESTART required (reload is not enough)" Red }
      else { Say "  nginx PID $($_.Id): running current binary" Green }
    }

  if ($plus -or -not $ver) { $v = 'REVIEW'; Set-Worst 2; $col = 'Yellow' }
  elseif (Test-Fixed $ver) { if ($stale) { $v = 'RESTART-REQUIRED'; Set-Worst 1; $col = 'Red' } else { $v = 'PATCHED'; $col = 'Green' } }
  else { $v = 'VULNERABLE'; Set-Worst 1; $col = 'Red' }
  Say "  VERDICT: $v" $col
}

# ---- probes (PowerShell 7+) -----------------------------------------------------
foreach ($target in $Probe) {
  $h, $p = $target -split ':', 2; if (-not $p) { $p = 443 }
  Write-Host ''; Say "--- Probe ${h}:${p} (handshake only) ---" White
  if ($PSVersionTable.PSVersion.Major -lt 7) { Say '  ALPN probe needs PowerShell 7+ (SslStream ALPN support). Use the Python or bash script instead.' Yellow; continue }
  try {
    $tcp = [System.Net.Sockets.TcpClient]::new()
    if (-not $tcp.ConnectAsync($h, [int]$p).Wait(6000)) { throw 'connection timed out' }
    $ssl = [System.Net.Security.SslStream]::new($tcp.GetStream(), $false)
    $opt = [System.Net.Security.SslClientAuthenticationOptions]::new()
    $opt.TargetHost = $h
    $opt.RemoteCertificateValidationCallback = { $true }
    $opt.ApplicationProtocols = [System.Collections.Generic.List[System.Net.Security.SslApplicationProtocol]]::new()
    $opt.ApplicationProtocols.Add([System.Net.Security.SslApplicationProtocol]::Http2)
    $opt.ApplicationProtocols.Add([System.Net.Security.SslApplicationProtocol]::Http11)
    $ssl.AuthenticateAsClientAsync($opt, [System.Threading.CancellationToken]::None).GetAwaiter().GetResult()
    $neg = [System.Text.Encoding]::ASCII.GetString($ssl.NegotiatedApplicationProtocol.Protocol.ToArray())
    $ssl.Dispose(); $tcp.Dispose()
    if ($neg -eq 'h2') { Say '  HTTP/2 (ALPN h2): OFFERED' Red } else { Say '  HTTP/2 (ALPN h2): not offered' Green }
    try {
      $r = Invoke-WebRequest -Uri "https://${h}:${p}/" -Method Head -SkipCertificateCheck -TimeoutSec 8 -ErrorAction Stop
      $alt = $r.Headers['Alt-Svc']
      if ($alt) { Say "  Alt-Svc: $alt" Red } else { Say '  Alt-Svc: none' }
    } catch { Say '  Alt-Svc: could not be read' Yellow }
    Say '  Note: a CDN/LB may terminate HTTP/2 in front of NGINX - test the origin directly.' Cyan
  } catch { Say "  Could not complete handshake: $($_.Exception.Message)" Yellow }
}

Write-Host ''
Say 'Note: heuristics only; version and config checks cannot prove a host is safe. Patch and RESTART.'
if (-not $foundAny) { exit 3 }
exit $worst

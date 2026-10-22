# Install the zro CLI on Windows.
#   irm https://raw.githubusercontent.com/sombochea/zro/main/scripts/install.ps1 | iex
# Environment: ZRO_VERSION (e.g. v0.1.0, default: latest), ZRO_INSTALL_DIR
# (default: %LOCALAPPDATA%\zro).
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$repo = 'sombochea/zro'
$base = if ($env:ZRO_DOWNLOAD_BASE) { $env:ZRO_DOWNLOAD_BASE } else { "https://github.com/$repo/releases" }

$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
  'AMD64' { 'amd64' }
  'ARM64' { 'arm64' }
  default { throw "unsupported architecture $($env:PROCESSOR_ARCHITECTURE)" }
}

$tag = $env:ZRO_VERSION
if (-not $tag) {
  # /releases/latest redirects to /releases/tag/<tag>; this avoids the API rate limit.
  $req = [System.Net.HttpWebRequest]::Create("$base/latest")
  $req.AllowAutoRedirect = $false
  $loc = $req.GetResponse().Headers['Location']
  if (-not $loc) { throw 'cannot look up the latest release' }
  $tag = ($loc -split '/')[-1]
}
$version = $tag.TrimStart('v')
$name = "zro_${version}_windows_${arch}.zip"

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
  Write-Host "Downloading zro $tag (windows/$arch)..."
  Invoke-WebRequest "$base/download/$tag/$name" -OutFile (Join-Path $tmp $name)
  Invoke-WebRequest "$base/download/$tag/checksums.txt" -OutFile (Join-Path $tmp 'checksums.txt')

  $line = Get-Content (Join-Path $tmp 'checksums.txt') | Where-Object { $_ -match "\s$([regex]::Escape($name))$" } | Select-Object -First 1
  if (-not $line) { throw "checksums.txt has no entry for $name" }
  $want = ($line -split '\s+')[0]
  $got = (Get-FileHash (Join-Path $tmp $name) -Algorithm SHA256).Hash
  if ($got -ne $want) { throw "checksum mismatch for $name; refusing to install" }

  Expand-Archive (Join-Path $tmp $name) -DestinationPath $tmp -Force
  $dir = if ($env:ZRO_INSTALL_DIR) { $env:ZRO_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'zro' }
  New-Item -ItemType Directory -Path $dir -Force | Out-Null
  Copy-Item (Join-Path $tmp 'zro.exe') (Join-Path $dir 'zro.exe') -Force
  Write-Host "Installed $dir\zro.exe"

  $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
  if (($userPath -split ';') -notcontains $dir) {
    [Environment]::SetEnvironmentVariable('Path', "$userPath;$dir", 'User')
    Write-Host "Added $dir to your user PATH; open a new terminal to use 'zro'."
  }
  & (Join-Path $dir 'zro.exe') version
} finally {
  Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

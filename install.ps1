# Nachuan Community Windows user-level install, update, doctor and uninstall.
# This bootstrap does not require elevation or execute unverified remote text.
[CmdletBinding()]
param(
  [ValidateSet('Install', 'Update', 'Doctor', 'Start', 'Uninstall')]
  [string]$Action = 'Install',
  [string]$InstallRoot = '',
  [ValidatePattern('^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')]
  [string]$Repository = 'wg5759/nachuan',
  [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$')]
  [string]$Ref = 'main',
  [switch]$NoPath,
  [switch]$PurgeData,
  [switch]$Yes,
  [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$UvVersion = '0.11.3'
$PythonVersion = '3.12.9'
$UvArchiveName = 'uv-x86_64-pc-windows-msvc.zip'
$UvArchiveSize = 23128087
$UvArchiveSha256 = 'AE681C0AAEC7CC96AF184648CB88D73F8393ED60FA5880ABDD6BDB910F9B227C'
$UvArchiveUrl = "https://github.com/astral-sh/uv/releases/download/$UvVersion/$UvArchiveName"
$StateSchema = 'nachuan.community-install.v1'
$SnapshotSchema = 'nachuan.open-source-snapshot.v1'

if ([string]::IsNullOrWhiteSpace($InstallRoot)) {
  if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
    throw 'LOCALAPPDATA is required for the default user installation.'
  }
  $InstallRoot = Join-Path $env:LOCALAPPDATA 'Nachuan\community'
}

function Get-FullPath([string]$Path) {
  return [IO.Path]::GetFullPath($Path).TrimEnd([char[]]'\/')
}

function Assert-SafeInstallRoot([string]$Path) {
  $full = Get-FullPath $Path
  $root = [IO.Path]::GetPathRoot($full).TrimEnd([char[]]'\/')
  if ([string]::IsNullOrWhiteSpace($root) -or
      [string]::Equals($full, $root, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'InstallRoot must not be a drive root.'
  }
  if ($full.Length -lt ($root.Length + 8)) {
    throw 'InstallRoot is too broad for a managed installation.'
  }
  $cursor = $full
  while (-not [string]::IsNullOrWhiteSpace($cursor)) {
    if (Test-Path -LiteralPath $cursor) {
      $item = Get-Item -LiteralPath $cursor -Force
      if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "InstallRoot crosses a reparse point: $cursor"
      }
    }
    $parent = [IO.Path]::GetDirectoryName($cursor)
    if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $cursor) { break }
    $cursor = $parent
  }
  return $full
}

function Invoke-CheckedNative(
  [string]$Label,
  [string]$FilePath,
  [string[]]$Arguments
) {
  & $FilePath @Arguments
  $code = $LASTEXITCODE
  if ($null -eq $code -or $code -ne 0) {
    throw "$Label failed with exit code $code"
  }
}

function Get-CheckedNativeOutput(
  [string]$Label,
  [string]$FilePath,
  [string[]]$Arguments
) {
  $output = @(& $FilePath @Arguments)
  $code = $LASTEXITCODE
  if ($null -eq $code -or $code -ne 0) {
    throw "$Label failed with exit code $code"
  }
  return ($output -join "`n").Trim()
}

function Invoke-Download([string]$Url, [string]$Destination) {
  $uri = [Uri]$Url
  if ($uri.Scheme -cne 'https' -or $uri.UserInfo -or $uri.Fragment) {
    throw "Refusing non-HTTPS or credential-bearing download: $Url"
  }
  Invoke-WebRequest -UseBasicParsing -Uri $uri -OutFile $Destination -Headers @{
    'User-Agent' = 'Nachuan-Community-Installer/0.2.0'
  }
}

function Get-Sha256([string]$Path) {
  return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToUpperInvariant()
}

function Resolve-SourceCommit([string]$Repo, [string]$RequestedRef) {
  if ($RequestedRef -cmatch '^[0-9a-f]{40}$') { return $RequestedRef }
  if ($RequestedRef.Contains('..') -or $RequestedRef.StartsWith('/') -or $RequestedRef.EndsWith('/')) {
    throw 'Ref contains an unsafe segment.'
  }
  $encodedRef = [Uri]::EscapeDataString($RequestedRef)
  $url = "https://api.github.com/repos/$Repo/commits/$encodedRef"
  $response = Invoke-RestMethod -UseBasicParsing -Uri $url -Headers @{
    'Accept' = 'application/vnd.github+json'
    'User-Agent' = 'Nachuan-Community-Installer/0.2.0'
    'X-GitHub-Api-Version' = '2022-11-28'
  }
  $commit = [string]$response.sha
  if ($commit -cnotmatch '^[0-9a-f]{40}$') {
    throw 'GitHub did not return an immutable commit SHA.'
  }
  return $commit
}

function Test-SnapshotClosure(
  [string]$SourceRoot,
  [switch]$AllowManagedRuntime
) {
  $sourceFull = Get-FullPath $SourceRoot
  $prefix = $sourceFull + [IO.Path]::DirectorySeparatorChar
  $receiptPath = Join-Path $sourceFull 'OPEN_SOURCE_SNAPSHOT.json'
  if (-not (Test-Path -LiteralPath $receiptPath -PathType Leaf)) {
    throw 'Source archive has no OPEN_SOURCE_SNAPSHOT.json receipt.'
  }
  $receiptItem = Get-Item -LiteralPath $receiptPath -Force
  if (($receiptItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'Source receipt must not be a reparse point.'
  }
  $receipt = Get-Content -LiteralPath $receiptPath -Raw -Encoding UTF8 | ConvertFrom-Json
  if ([string]$receipt.schema -cne $SnapshotSchema) {
    throw 'Unsupported source snapshot schema.'
  }
  $entries = @($receipt.files)
  if ($entries.Count -lt 1 -or [int]$receipt.file_count -ne $entries.Count) {
    throw 'Source snapshot inventory count is invalid.'
  }
  $expected = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
  foreach ($entry in $entries) {
    $relative = ([string]$entry.path).Replace('\', '/')
    if ([string]::IsNullOrWhiteSpace($relative) -or
        $relative.StartsWith('/') -or
        $relative.Contains(':') -or
        @($relative.Split('/')) -contains '..') {
      throw 'Source snapshot contains an unsafe path.'
    }
    if (-not $expected.Add($relative)) { throw 'Source snapshot contains a duplicate path.' }
    $path = Get-FullPath (Join-Path $sourceFull $relative)
    if (-not $path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
      throw 'Source snapshot path escaped its root.'
    }
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
      throw "Source snapshot file is missing: $relative"
    }
    $item = Get-Item -LiteralPath $path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "Source snapshot file is redirected: $relative"
    }
    if ([int64]$entry.size -ne $item.Length) {
      throw "Source snapshot size mismatch: $relative"
    }
    $expectedHash = ([string]$entry.sha256).ToUpperInvariant()
    if ($expectedHash -cnotmatch '^[0-9A-F]{64}$' -or (Get-Sha256 $path) -cne $expectedHash) {
      throw "Source snapshot hash mismatch: $relative"
    }
  }
  $managedRuntimePrefix = '.venv/'
  $actual = @(
    Get-ChildItem -LiteralPath $sourceFull -Recurse -Force | ForEach-Object {
      $relative = $_.FullName.Substring($prefix.Length).Replace('\', '/')
      $managedRuntime = $AllowManagedRuntime -and (
        $relative -ceq '.venv' -or $relative.StartsWith($managedRuntimePrefix, [StringComparison]::Ordinal)
      )
      if (($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Source snapshot contains a reparse point: $($_.FullName)"
      }
      if (-not $managedRuntime -and -not $_.PSIsContainer -and $_.FullName -cne $receiptPath) {
        $relative
      }
    }
  )
  if ($actual.Count -ne $expected.Count) {
    throw 'Source snapshot contains missing or extra files.'
  }
  foreach ($relative in $actual) {
    if (-not $expected.Contains($relative)) {
      throw "Source snapshot contains an undeclared file: $relative"
    }
  }
  return @{
    Receipt = $receipt
    ReceiptSha256 = Get-Sha256 $receiptPath
  }
}

function Write-JsonAtomic([string]$Path, [object]$Value) {
  $parent = Split-Path -Parent $Path
  New-Item -ItemType Directory -Path $parent -Force | Out-Null
  $temporary = Join-Path $parent ('.state-' + [Guid]::NewGuid().ToString('N') + '.tmp')
  [IO.File]::WriteAllText(
    $temporary,
    (($Value | ConvertTo-Json -Depth 10) + "`n"),
    (New-Object Text.UTF8Encoding($false))
  )
  Move-Item -LiteralPath $temporary -Destination $Path -Force
}

function Remove-ManagedBuildResidue([string]$SourceRoot) {
  $sourceFull = Get-FullPath $SourceRoot
  $prefix = $sourceFull + [IO.Path]::DirectorySeparatorChar
  if (-not (Test-Path -LiteralPath (Join-Path $sourceFull 'OPEN_SOURCE_SNAPSHOT.json') -PathType Leaf)) {
    throw 'Refusing build cleanup outside a verified source root.'
  }
  foreach ($relative in @('build', 'llm_aggregator.egg-info', '__pycache__')) {
    $target = Get-FullPath (Join-Path $sourceFull $relative)
    if (-not $target.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
      throw 'Managed build cleanup escaped the source root.'
    }
    if (-not (Test-Path -LiteralPath $target)) { continue }
    $item = Get-Item -LiteralPath $target -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "Refusing redirected managed build cleanup: $relative"
    }
    $redirected = @(
      Get-ChildItem -LiteralPath $target -Recurse -Force | Where-Object {
        ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
      }
    )
    if ($redirected.Count -ne 0) {
      throw "Refusing managed build cleanup containing a reparse point: $relative"
    }
    Remove-Item -LiteralPath $target -Recurse -Force
    if (Test-Path -LiteralPath $target) {
      throw "Managed build cleanup left a residual path: $relative"
    }
  }
}

function Read-InstallState([string]$Root) {
  $statePath = Join-Path $Root 'state\install.json'
  if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) {
    throw "Install state is missing: $statePath"
  }
  $state = Get-Content -LiteralPath $statePath -Raw -Encoding UTF8 | ConvertFrom-Json
  if ([string]$state.schema -cne $StateSchema -or
      [string]$state.edition -cne 'community' -or
      ([string]$state.resolved_commit) -cnotmatch '^[0-9a-f]{40}$') {
    throw 'Install state is invalid.'
  }
  return $state
}

function Ensure-Uv([string]$Root) {
  $runtimeRoot = Join-Path $Root 'runtime\uv'
  $uvPath = Join-Path $runtimeRoot 'uv.exe'
  if (Test-Path -LiteralPath $uvPath -PathType Leaf) {
    $versionText = Get-CheckedNativeOutput 'uv version' $uvPath @('--version')
    if ($versionText -notmatch ('^uv ' + [regex]::Escape($UvVersion) + '(?:\s|$)')) {
      throw "Managed uv version drifted: $versionText"
    }
    return $uvPath
  }
  if ($DryRun) {
    Write-Host "[DRY-RUN] download pinned uv $UvVersion into $runtimeRoot"
    return $uvPath
  }
  $staging = Join-Path $Root ('staging\uv-' + [Guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $staging -Force | Out-Null
  $archive = Join-Path $staging $UvArchiveName
  Invoke-Download $UvArchiveUrl $archive
  $archiveItem = Get-Item -LiteralPath $archive -Force
  if ($archiveItem.Length -ne $UvArchiveSize -or (Get-Sha256 $archive) -cne $UvArchiveSha256) {
    throw 'Pinned uv archive size or SHA-256 mismatch.'
  }
  $expanded = Join-Path $staging 'expanded'
  Expand-Archive -LiteralPath $archive -DestinationPath $expanded
  $uvCandidates = @(Get-ChildItem -LiteralPath $expanded -Recurse -File -Filter 'uv.exe')
  if ($uvCandidates.Count -ne 1) { throw 'Pinned uv archive has an unexpected layout.' }
  New-Item -ItemType Directory -Path $runtimeRoot -Force | Out-Null
  Copy-Item -LiteralPath $uvCandidates[0].FullName -Destination $uvPath
  $versionText = Get-CheckedNativeOutput 'pinned uv version' $uvPath @('--version')
  if ($versionText -notmatch ('^uv ' + [regex]::Escape($UvVersion) + '(?:\s|$)')) {
    throw "Pinned uv executable reported an unexpected version: $versionText"
  }
  return $uvPath
}

function Write-Launchers([string]$Root, [string]$VersionRoot) {
  $bin = Join-Path $Root 'bin'
  New-Item -ItemType Directory -Path $bin -Force | Out-Null
  $runnerPath = Join-Path $bin 'nachuan.ps1'
  $runner = @'
[CmdletBinding()]
param([Parameter(ValueFromRemainingArguments = $true)][string[]]$NachuanArguments)
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$state = Get-Content -LiteralPath (Join-Path $root 'state\install.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$versionRoot = Join-Path $root ('versions\' + [string]$state.resolved_commit)
$python = Join-Path $versionRoot '.venv\Scripts\python.exe'
$maintenanceName = -join ([char[]](0x7ef4, 0x62a4))
$maintenance = Join-Path (Join-Path $root $maintenanceName) 'nachuan-maintenance.ps1'
if ($NachuanArguments.Count -eq 0) { $NachuanArguments = @('start') }
$verb = $NachuanArguments[0].ToLowerInvariant()
if ($verb -in @('update', 'doctor', 'uninstall')) {
  $action = $verb.Substring(0, 1).ToUpperInvariant() + $verb.Substring(1)
  & $maintenance -Action $action -InstallRoot $root
  exit $LASTEXITCODE
}
if ($verb -eq 'start') {
  $env:DATA_DIR = Join-Path ([IO.Path]::GetDirectoryName($root)) 'data'
}
& $python -m cli @NachuanArguments
exit $LASTEXITCODE
'@
  [IO.File]::WriteAllText($runnerPath, $runner, (New-Object Text.UTF8Encoding($false)))
  $cmd = "@echo off`r`npowershell.exe -NoLogo -NoProfile -File `"%~dp0nachuan.ps1`" %*`r`nexit /b %ERRORLEVEL%`r`n"
  [IO.File]::WriteAllText((Join-Path $bin 'nachuan.cmd'), $cmd, [Text.Encoding]::ASCII)

  $maintenanceName = -join ([char[]](0x7ef4, 0x62a4))
  $maintenanceDir = Join-Path $Root $maintenanceName
  New-Item -ItemType Directory -Path $maintenanceDir -Force | Out-Null
  $newInstaller = Join-Path $VersionRoot 'install.ps1'
  if (-not (Test-Path -LiteralPath $newInstaller -PathType Leaf)) {
    throw 'Verified source does not contain the maintenance installer.'
  }
  Copy-Item -LiteralPath $newInstaller -Destination (Join-Path $maintenanceDir 'nachuan-maintenance.ps1') -Force
}

function Add-UserPath([string]$BinPath) {
  $current = [Environment]::GetEnvironmentVariable('Path', 'User')
  $parts = @($current -split ';' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
  foreach ($part in $parts) {
    try { $candidate = Get-FullPath $part } catch { continue }
    if ([string]::Equals($candidate, $BinPath, [StringComparison]::OrdinalIgnoreCase)) {
      return
    }
  }
  $updated = (@($parts) + $BinPath) -join ';'
  [Environment]::SetEnvironmentVariable('Path', $updated, 'User')
  if (-not (($env:Path -split ';') -contains $BinPath)) { $env:Path += ";$BinPath" }
}

function Remove-UserPath([string]$BinPath) {
  $current = [Environment]::GetEnvironmentVariable('Path', 'User')
  $kept = @()
  foreach ($part in @($current -split ';')) {
    if ([string]::IsNullOrWhiteSpace($part)) { continue }
    $matches = $false
    try {
      $matches = [string]::Equals((Get-FullPath $part), $BinPath, [StringComparison]::OrdinalIgnoreCase)
    } catch { $matches = $false }
    if (-not $matches) { $kept += $part }
  }
  [Environment]::SetEnvironmentVariable('Path', ($kept -join ';'), 'User')
}

function Install-OrUpdate([string]$Root, [bool]$Updating) {
  if ($DryRun) {
    Write-Host "[DRY-RUN] action=$(if ($Updating) { 'Update' } else { 'Install' })"
    Write-Host "[DRY-RUN] root=$Root repository=$Repository ref=$Ref"
    Write-Host "[DRY-RUN] source will be resolved to one immutable GitHub commit and checked against OPEN_SOURCE_SNAPSHOT.json"
    return
  }
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  New-Item -ItemType Directory -Path $Root -Force | Out-Null
  $previous = $null
  if (Test-Path -LiteralPath (Join-Path $Root 'state\install.json') -PathType Leaf) {
    $previous = Read-InstallState $Root
  } elseif ($Updating) {
    throw 'Cannot update because no existing community installation was found.'
  }

  $uvPath = Ensure-Uv $Root
  $commit = Resolve-SourceCommit $Repository $Ref
  if ($previous -and [string]$previous.resolved_commit -ceq $commit) {
    Write-Host "[OK] Already current at $commit"
    Invoke-Doctor $Root
    return
  }

  $versions = Join-Path $Root 'versions'
  $versionRoot = Join-Path $versions $commit
  if (Test-Path -LiteralPath $versionRoot) {
    throw "Version directory already exists without active state: $versionRoot"
  }
  $staging = Join-Path $Root ('staging\source-' + [Guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $staging -Force | Out-Null
  $archive = Join-Path $staging 'source.zip'
  Invoke-Download "https://codeload.github.com/$Repository/zip/$commit" $archive
  $expanded = Join-Path $staging 'expanded'
  Expand-Archive -LiteralPath $archive -DestinationPath $expanded
  $sourceCandidates = @(
    Get-ChildItem -LiteralPath $expanded -Directory | Where-Object {
      Test-Path -LiteralPath (Join-Path $_.FullName 'OPEN_SOURCE_SNAPSHOT.json') -PathType Leaf
    }
  )
  if ($sourceCandidates.Count -ne 1) { throw 'GitHub source archive has an unexpected layout.' }
  $verified = Test-SnapshotClosure $sourceCandidates[0].FullName
  New-Item -ItemType Directory -Path $versions -Force | Out-Null
  Move-Item -LiteralPath $sourceCandidates[0].FullName -Destination $versionRoot

  $pythonRoot = Join-Path $Root 'runtime\python'
  $cacheRoot = Join-Path $Root 'cache\uv'
  $env:UV_CACHE_DIR = $cacheRoot
  $env:UV_PYTHON_INSTALL_DIR = $pythonRoot
  Invoke-CheckedNative 'managed Python install' $uvPath @(
    'python', 'install', $PythonVersion, '--install-dir', $pythonRoot, '--no-bin', '--no-registry'
  )
  Invoke-CheckedNative 'locked community environment sync' $uvPath @(
    'sync', '--directory', $versionRoot, '--frozen', '--no-dev', '--no-editable',
    '--managed-python', '--python', $PythonVersion, '--cache-dir', $cacheRoot
  )
  Remove-ManagedBuildResidue $versionRoot
  $python = Join-Path $versionRoot '.venv\Scripts\python.exe'
  $actualPython = Get-CheckedNativeOutput 'community Python version' $python @(
    '-I', '-S', '-B', '-X', 'utf8', '-c', 'import platform; print(platform.python_version())'
  )
  if ($actualPython -cne $PythonVersion) { throw "Unexpected managed Python version: $actualPython" }
  Invoke-CheckedNative 'community import smoke' $python @(
    '-I', '-B', '-X', 'utf8', '-c', 'import cli, gateway; print(gateway.__version__)'
  )
  Invoke-CheckedNative 'distribution synchronization contract' $python @(
    '-I', '-B', '-X', 'utf8', (Join-Path $versionRoot 'scripts\verify_distribution_contract.py'), '--root', $versionRoot
  )

  Write-Launchers $Root $versionRoot
  $coreContract = Get-Content -LiteralPath (Join-Path $versionRoot 'config\distribution-channels.v1.json') -Raw -Encoding UTF8 | ConvertFrom-Json
  $state = [ordered]@{
    schema = $StateSchema
    edition = 'community'
    core_version = [string]$coreContract.core_version
    repository = $Repository
    requested_ref = $Ref
    resolved_commit = $commit
    previous_commit = if ($previous) { [string]$previous.resolved_commit } else { $null }
    source_receipt_sha256 = [string]$verified.ReceiptSha256
    uv_version = $UvVersion
    uv_sha256 = Get-Sha256 $uvPath
    python_version = $PythonVersion
    installed_at_utc = [DateTime]::UtcNow.ToString('o')
  }
  Write-JsonAtomic (Join-Path $Root 'state\install.json') $state
  if (-not $NoPath) { Add-UserPath (Join-Path $Root 'bin') }
  Write-Host "[OK] Nachuan Community $($state.core_version) installed at $Root"
  Write-Host "[OK] Source commit: $commit"
  Write-Host '[NEXT] Open a new terminal and run: nachuan start'
}

function Invoke-Doctor([string]$Root) {
  $failures = New-Object 'System.Collections.Generic.List[string]'
  try { $state = Read-InstallState $Root } catch { $failures.Add($_.Exception.Message); $state = $null }
  if ($state) {
    $versionRoot = Join-Path $Root ('versions\' + [string]$state.resolved_commit)
    $python = Join-Path $versionRoot '.venv\Scripts\python.exe'
    try {
      $verified = Test-SnapshotClosure $versionRoot -AllowManagedRuntime
      if ([string]$verified.ReceiptSha256 -cne [string]$state.source_receipt_sha256) {
        $failures.Add('Source receipt hash drifted from install state.')
      }
    } catch { $failures.Add($_.Exception.Message) }
    $uvPath = Join-Path $Root 'runtime\uv\uv.exe'
    if (-not (Test-Path -LiteralPath $uvPath -PathType Leaf)) {
      $failures.Add('Managed uv.exe is missing.')
    } elseif ((Get-Sha256 $uvPath) -cne ([string]$state.uv_sha256).ToUpperInvariant()) {
      $failures.Add('Managed uv.exe hash drifted from install state.')
    } else {
      try {
        Invoke-CheckedNative 'locked community environment check' $uvPath @(
          'sync', '--check', '--offline', '--directory', $versionRoot, '--frozen', '--no-dev', '--no-editable',
          '--python', $python, '--cache-dir', (Join-Path $Root 'cache\uv')
        )
      } catch { $failures.Add($_.Exception.Message) }
    }
    if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
      $failures.Add('Managed Python environment is missing.')
    } else {
      try {
        Invoke-CheckedNative 'community runtime smoke' $python @(
          '-I', '-B', '-X', 'utf8', '-c', 'import cli, gateway; print(gateway.__version__)'
        )
        Invoke-CheckedNative 'distribution synchronization contract' $python @(
          '-I', '-B', '-X', 'utf8', (Join-Path $versionRoot 'scripts\verify_distribution_contract.py'), '--root', $versionRoot
        )
      } catch { $failures.Add($_.Exception.Message) }
    }
  }
  if ($failures.Count -ne 0) {
    foreach ($failure in $failures) { Write-Error "[FAIL] $failure" -ErrorAction Continue }
    throw "Nachuan Community doctor failed with $($failures.Count) finding(s)."
  }
  Write-Host "[OK] Nachuan Community doctor passed: $Root"
}

function Invoke-Start([string]$Root) {
  Invoke-Doctor $Root
  $runner = Join-Path $Root 'bin\nachuan.ps1'
  & $runner start
  exit $LASTEXITCODE
}

function Invoke-Uninstall([string]$Root) {
  $state = Read-InstallState $Root
  if (-not $Yes) {
    $answer = Read-Host 'Uninstall Nachuan Community? Program files will be removed and user data kept by default (type YES)'
    if ($answer -cne 'YES') { Write-Host 'Cancelled.'; return }
  }
  $bin = Join-Path $Root 'bin'
  Remove-UserPath $bin
  $rootFull = Assert-SafeInstallRoot $Root
  if ([string]$state.schema -cne $StateSchema) { throw 'Refusing to remove an unowned directory.' }
  Set-Location ([IO.Path]::GetTempPath())
  Remove-Item -LiteralPath $rootFull -Recurse -Force
  if (Test-Path -LiteralPath $rootFull) { throw 'Installation directory still exists after uninstall.' }
  if ($PurgeData) {
    if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) { throw 'LOCALAPPDATA is required to purge data.' }
    $dataRoot = Get-FullPath (Join-Path $env:LOCALAPPDATA 'Nachuan\data')
    $expectedParent = Get-FullPath (Join-Path $env:LOCALAPPDATA 'Nachuan')
    if (-not [string]::Equals([IO.Path]::GetDirectoryName($dataRoot), $expectedParent, [StringComparison]::OrdinalIgnoreCase)) {
      throw 'Refusing to purge data outside the Nachuan user root.'
    }
    if (Test-Path -LiteralPath $dataRoot) { Remove-Item -LiteralPath $dataRoot -Recurse -Force }
  }
  Write-Host '[OK] Nachuan Community uninstalled.'
  if (-not $PurgeData) { Write-Host '[KEPT] User data remains under %LOCALAPPDATA%\Nachuan\data.' }
}

$InstallRoot = Assert-SafeInstallRoot $InstallRoot
switch ($Action) {
  'Install' { Install-OrUpdate $InstallRoot $false }
  'Update' { Install-OrUpdate $InstallRoot $true }
  'Doctor' { Invoke-Doctor $InstallRoot }
  'Start' { Invoke-Start $InstallRoot }
  'Uninstall' { Invoke-Uninstall $InstallRoot }
}

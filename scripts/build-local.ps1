# Build one Windows release candidate locally without relying on GitHub CI.
# Usage: .\scripts\build-local.ps1 [lean|full]   (default: lean)
param(
  [ValidateSet('lean', 'full')]
  [string]$Want = 'lean'
)

$ErrorActionPreference = 'Stop'
$ExpectedUv = '0.11.3'
$ExpectedPython = '3.12.9'
$ExpectedNode = '24.14.0'
$ExpectedNpm = '11.12.1'
$Root = (Resolve-Path "$PSScriptRoot\..").Path
$RootPrefix = $Root.TrimEnd('\') + '\'
Set-Location $Root

if (-not (Test-Path -LiteralPath (Join-Path $Root 'pyproject.toml') -PathType Leaf) -or
    -not (Test-Path -LiteralPath (Join-Path $Root 'desktop\package.json') -PathType Leaf)) {
  throw "Refusing to build outside the repository root: $Root"
}

# Close ambient code-execution and binary-override inputs before invoking Node,
# npm, Python, Electron, or esbuild. npm lifecycle scripts stay disabled during
# dependency installation; reviewed project scripts are invoked explicitly later.
foreach ($name in @(
  'NODE_OPTIONS',
  'NODE_PATH',
  'NODE_EXTRA_CA_CERTS',
  'NODE_TLS_REJECT_UNAUTHORIZED',
  'ELECTRON_RUN_AS_NODE',
  'ELECTRON_MIRROR',
  'ELECTRON_BUILDER_BINARIES_MIRROR',
  'ELECTRON_CUSTOM_DIR',
  'ELECTRON_CUSTOM_FILENAME',
  'ELECTRON_CUSTOM_VERSION',
  'ELECTRON_OVERRIDE_DIST_PATH',
  'ESBUILD_BINARY_PATH',
  'npm_config_electron_mirror',
  'npm_config_electron_custom_dir',
  'npm_config_electron_custom_filename',
  'npm_config_electron_custom_version',
  'npm_config_node_options',
  'PYTHONHOME',
  'PYTHONPATH',
  'PYTHONSTARTUP',
  'PYTHONUSERBASE'
)) {
  [Environment]::SetEnvironmentVariable($name, $null, 'Process')
}
$TrustedCommandShell = Join-Path ([Environment]::SystemDirectory) 'cmd.exe'
if (-not (Test-Path -LiteralPath $TrustedCommandShell -PathType Leaf)) {
  throw "Trusted npm command shell is missing: $TrustedCommandShell"
}
$env:npm_config_script_shell = $TrustedCommandShell

function Resolve-RequiredTool([string]$Name) {
  $command = Get-Command $Name -ErrorAction Stop | Select-Object -First 1
  $resolved = (Resolve-Path -LiteralPath $command.Source).Path
  if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
    throw "$Name did not resolve to a regular executable/script: $resolved"
  }
    return $resolved
}

# Windows PowerShell 5.1 does not turn a native program's non-zero exit code
# into a terminating error.  Every release command must therefore cross this
# explicit gate; otherwise pytest/PyInstaller/verifiers can fail while the
# script continues and prints a false [OK].
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
  return $output
}

function Remove-ControlledPath([string]$RelativePath) {
  $target = [IO.Path]::GetFullPath((Join-Path $Root $RelativePath))
  if (-not $target.StartsWith($RootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing cleanup outside repository: $target"
  }
  Remove-Item -LiteralPath $target -Recurse -Force -ErrorAction SilentlyContinue
}

# Resolve each tool exactly once. All direct release commands use these absolute paths;
# this script never prepends or otherwise mutates PATH.
$UvBin = Resolve-RequiredTool 'uv.exe'
$NodeBin = Resolve-RequiredTool 'node.exe'
$NpmBin = Resolve-RequiredTool 'npm.cmd'

$ActualUvText = (Get-CheckedNativeOutput 'uv version' $UvBin @('--version')) -join "`n"
$ActualUv = (($ActualUvText.Trim()) -split '\s+')[1]
if ($ActualUv -cne $ExpectedUv) {
  throw "uv $ExpectedUv is required (resolved $UvBin)"
}
$ActualNode = ((Get-CheckedNativeOutput 'node version' $NodeBin @('--version')) -join "`n").Trim()
if ($ActualNode -cne "v$ExpectedNode") {
  throw "Node.js $ExpectedNode is required (resolved $NodeBin)"
}
$ActualNpm = ((Get-CheckedNativeOutput 'npm version' $NpmBin @('--version')) -join "`n").Trim()
if ($ActualNpm -cne $ExpectedNpm) {
  throw "npm $ExpectedNpm is required (resolved $NpmBin)"
}

$env:UV_PYTHON = $ExpectedPython
$env:npm_config_registry = 'https://registry.npmjs.org'
if (-not $env:GH_OWNER) { $env:GH_OWNER = 'wg5759' }
if (-not $env:GH_REPO) { $env:GH_REPO = 'nachuan' }

Write-Host '==> 1/5 Exact Python environment and tests'
Invoke-CheckedNative 'uv python install' $UvBin @('python', 'install', $ExpectedPython)
Invoke-CheckedNative 'uv sync' $UvBin @('sync', '--locked', '--extra', 'dev', '--python', $ExpectedPython)
$ActualPython = ((Get-CheckedNativeOutput 'python version' $UvBin @('run', 'python', '-c', 'import platform; print(platform.python_version())')) -join "`n").Trim()
if ($ActualPython -cne $ExpectedPython) { throw "Unexpected Python version $ActualPython" }
Invoke-CheckedNative 'pytest' $UvBin @('run', 'pytest', '-q', '-p', 'no:cacheprovider')

Write-Host '==> 2/5 Build the engine binary'
Remove-ControlledPath 'build'
Remove-ControlledPath 'dist\engine.exe'
Invoke-CheckedNative 'PyInstaller' $UvBin @('run', 'pyinstaller', 'engine.spec', '--noconfirm', '--distpath', 'dist', '--workpath', 'build')
$EnginePath = Join-Path $Root 'dist\engine.exe'
if (-not (Test-Path -LiteralPath $EnginePath -PathType Leaf)) {
  throw "PyInstaller returned success without engine.exe: $EnginePath"
}
$EngineItem = Get-Item -LiteralPath $EnginePath -Force
if (($EngineItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
  throw "Refusing reparse-point engine output: $EnginePath"
}

Write-Host '==> 3/5 Prepare reviewed local-runtime inputs'
if ($Want -eq 'lean') {
  $env:LLAMA_SRC = $null
  $env:MODELS_SRC = $null
  Write-Host '    lean: cloud/BYOK only; local runtime intentionally excluded'
} else {
  if (-not $env:MODELS_SRC -or -not (Test-Path -LiteralPath $env:MODELS_SRC -PathType Container)) {
    throw 'MODELS_SRC must be a reviewed directory containing at least one GGUF for full'
  }
  if (-not (Get-ChildItem -LiteralPath $env:MODELS_SRC -File -Filter '*.gguf' | Select-Object -First 1)) {
    throw 'MODELS_SRC contains no GGUF; refusing to create a misleading full package'
  }
  if (-not $env:LLAMA_URL) { throw 'LLAMA_URL must point to a pinned official llama.cpp asset' }
  try { $LlamaUri = [Uri]$env:LLAMA_URL } catch { throw 'LLAMA_URL must be an absolute URL' }
  if ($LlamaUri.Scheme -cne 'https' -or
      $LlamaUri.Host -cne 'github.com' -or
      -not $LlamaUri.AbsolutePath.StartsWith('/ggml-org/llama.cpp/releases/download/', [StringComparison]::Ordinal) -or
      $LlamaUri.UserInfo -or $LlamaUri.Fragment) {
    throw 'LLAMA_URL must be credential-free HTTPS on github.com/ggml-org/llama.cpp/releases/download/'
  }
  if ($env:LLAMA_SHA256 -notmatch '^[0-9a-fA-F]{64}$') {
    throw 'LLAMA_SHA256 must be the reviewed 64-character SHA-256 for LLAMA_URL'
  }
  if (-not $env:NACHUAN_FULL_RUNTIME_TRUST_MANIFEST -or
      -not (Test-Path -LiteralPath $env:NACHUAN_FULL_RUNTIME_TRUST_MANIFEST -PathType Leaf)) {
    throw 'NACHUAN_FULL_RUNTIME_TRUST_MANIFEST must bind size/hash/license/source for every full artifact'
  }
  Remove-ControlledPath 'dist\_llama_dl'
  New-Item -ItemType Directory -Force (Join-Path $Root 'dist\_llama_dl') | Out-Null
  $Archive = Join-Path $Root 'dist\_llama.zip'
  Invoke-WebRequest $env:LLAMA_URL -OutFile $Archive
  $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Archive).Hash
  if ($actual -cne $env:LLAMA_SHA256.ToUpperInvariant()) {
    throw 'llama-server SHA-256 mismatch; refusing to extract'
  }
  Expand-Archive $Archive -DestinationPath (Join-Path $Root 'dist\_llama_dl') -Force
  $server = Get-ChildItem -LiteralPath (Join-Path $Root 'dist\_llama_dl') -Recurse -File -Filter 'llama-server.exe' |
    Select-Object -First 1
  if (-not $server) { throw 'verified llama archive does not contain llama-server.exe' }
  $env:LLAMA_SRC = $server.DirectoryName
}

Write-Host '==> 4/5 Install locked desktop dependencies and build'
Set-Location (Join-Path $Root 'desktop')
Invoke-CheckedNative 'prepare-pack' $NodeBin @('scripts/prepare-pack.mjs', $Want)
# Step 2 cleaned build\ entirely, which also removes the checksum-pinned Node
# runtime that 'npm test' (node-runtime-policy.mjs run) verifies before it can
# start Vitest.  Re-prepare it here; prepare is a verify-only no-op when the
# runtime is already present and re-downloads only through the locked SHA-256
# and Authenticode checks when it is not.
Invoke-CheckedNative 're-prepare checksum-pinned Node runtime after build clean' $NodeBin @(
  'scripts/node-runtime-policy.mjs', 'prepare'
)
Invoke-CheckedNative 'locked npm dependency install without lifecycle scripts' $NpmBin @(
  'ci', '--ignore-scripts', '--no-audit', '--no-fund', '--registry', 'https://registry.npmjs.org'
)
Invoke-CheckedNative 'prepare checksum-pinned Electron runtime' $NodeBin @(
  'scripts/electron-runtime-policy.mjs', 'prepare'
)
Invoke-CheckedNative 'stage payload license evidence' $NodeBin @('scripts/license-stage.mjs', 'prepare')
Invoke-CheckedNative 'engine digest' $NodeBin @('scripts/write-engine-digest.mjs')
# A local candidate is deliberately update-disabled.  Overwrite any generated
# trust left by an earlier release/audit before compiling the ASAR.
$env:NACHUAN_UPDATE_TIER = $null
Invoke-CheckedNative 'disable generated update trust' $NodeBin @('scripts/write-update-trust.mjs')
Invoke-CheckedNative 'desktop typecheck' $NpmBin @('run', 'typecheck')
Invoke-CheckedNative 'desktop tests' $NpmBin @('test')
Invoke-CheckedNative 'desktop build' $NpmBin @('run', 'build')

Write-Host "==> 5/5 Package and verify $Want from an empty release directory"
$env:DMX_VARIANT = $Want
Invoke-CheckedNative 'release clean' $NodeBin @('scripts/release-output.mjs', 'clean')
Invoke-CheckedNative 'electron-builder' $NpmBin @('exec', '--offline', '--', 'electron-builder', '--publish', 'never')
Invoke-CheckedNative 'release prune' $NodeBin @('scripts/release-output.mjs', 'prune', $Want)
Invoke-CheckedNative 'package verifier' $NodeBin @('scripts/_verify_pack.mjs', $Want)

Write-Host "`n[OK] Verified local candidate is in desktop\release (not a production publish approval):"
$Installers = @(Get-ChildItem -LiteralPath (Join-Path $Root 'desktop\release') -File -Filter '*-win.exe')
if ($Installers.Count -ne 1) {
  throw "Expected exactly one verified installer, found $($Installers.Count)"
}
$Installers | Select-Object Name, @{n='MB';e={[int]($_.Length / 1MB)}}

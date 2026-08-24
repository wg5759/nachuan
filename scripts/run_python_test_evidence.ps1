[CmdletBinding()]
param(
    [string]$RunId = ("python-full-{0}-{1}" -f (Get-Date -Format "yyyyMMdd-HHmmss"), ([guid]::NewGuid().ToString("N").Substring(0, 8)))
)

$ErrorActionPreference = "Stop"

$ProjectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$DesktopRoot = Join-Path $ProjectRoot "desktop"
$NodePath = Join-Path $ProjectRoot "build\node-runtime\node.exe"
$EvidenceParent = Join-Path $ProjectRoot "build\test-evidence"
$EvidenceDir = Join-Path $EvidenceParent $RunId
$SystemTemp = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd("\")
$TestTemp = Join-Path $SystemTemp ("np-{0}" -f ([guid]::NewGuid().ToString("N").Substring(0, 8)))

if (-not (Test-Path -LiteralPath $NodePath -PathType Leaf)) {
    throw "Pinned Node runtime is missing: $NodePath"
}
if (Test-Path -LiteralPath $EvidenceDir) {
    throw "Evidence directory already exists: $EvidenceDir"
}

New-Item -ItemType Directory -Path $EvidenceDir, $TestTemp | Out-Null
$StdoutPath = Join-Path $EvidenceDir "stdout.log"
$StderrPath = Join-Path $EvidenceDir "stderr.log"
$Start = [DateTimeOffset]::Now
$Arguments = @(
    "scripts\node-runtime-policy.mjs",
    "run",
    "scripts\python-release-policy.mjs",
    "test"
)

$env:TEMP = $TestTemp
$env:TMP = $TestTemp
$env:TMPDIR = $TestTemp

$StartInfo = New-Object System.Diagnostics.ProcessStartInfo
$StartInfo.FileName = $NodePath
$StartInfo.Arguments = $Arguments -join " "
$StartInfo.WorkingDirectory = $DesktopRoot
$StartInfo.UseShellExecute = $false
$StartInfo.CreateNoWindow = $true
$StartInfo.RedirectStandardOutput = $true
$StartInfo.RedirectStandardError = $true
$Process = New-Object System.Diagnostics.Process
$Process.StartInfo = $StartInfo
$StdoutStream = New-Object IO.FileStream(
    $StdoutPath,
    [IO.FileMode]::CreateNew,
    [IO.FileAccess]::Write,
    [IO.FileShare]::Read
)
$StderrStream = New-Object IO.FileStream(
    $StderrPath,
    [IO.FileMode]::CreateNew,
    [IO.FileAccess]::Write,
    [IO.FileShare]::Read
)
if (-not $Process.Start()) {
    throw "Failed to start pinned Python test policy"
}
$ProcessId = [int]$Process.Id
$StdoutCopy = $Process.StandardOutput.BaseStream.CopyToAsync($StdoutStream)
$StderrCopy = $Process.StandardError.BaseStream.CopyToAsync($StderrStream)

[ordered]@{
    schema = 1
    run_id = $RunId
    started_at = $Start.ToString("o")
    node_path = $NodePath
    node_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $NodePath).Hash
    command = "$NodePath $($Arguments -join ' ')"
    working_directory = $DesktopRoot
    pid = $ProcessId
    test_temp = $TestTemp
    stdout = $StdoutPath
    stderr = $StderrPath
} | ConvertTo-Json -Depth 4 | Set-Content -Encoding UTF8 (Join-Path $EvidenceDir "run-start.json")

Write-Output "EVIDENCE_DIR=$EvidenceDir"
Write-Output "TEST_TEMP=$TestTemp"
Write-Output "PID=$ProcessId"

$Process.WaitForExit()
[void]$StdoutCopy.GetAwaiter().GetResult()
[void]$StderrCopy.GetAwaiter().GetResult()
$StdoutStream.Flush()
$StderrStream.Flush()
$StdoutStream.Dispose()
$StderrStream.Dispose()
$End = [DateTimeOffset]::Now
$ExitCode = [int]$Process.ExitCode
$Process.Dispose()
$StdoutHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $StdoutPath).Hash
$StderrHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $StderrPath).Hash
$Cleanup = "preserved_after_failure"

if ($ExitCode -eq 0) {
    $ResolvedTemp = [IO.Path]::GetFullPath($TestTemp).TrimEnd("\")
    $ResolvedParent = [IO.Path]::GetDirectoryName($ResolvedTemp).TrimEnd("\")
    $ResolvedName = [IO.Path]::GetFileName($ResolvedTemp)
    if ($ResolvedParent -cne $SystemTemp -or -not $ResolvedName.StartsWith("np-")) {
        throw "Owned test temp safety check failed: $ResolvedTemp"
    }
    Remove-Item -LiteralPath $ResolvedTemp -Recurse -Force
    $Cleanup = "removed_owned_root_after_success"
}

[ordered]@{
    schema = 1
    run_id = $RunId
    started_at = $Start.ToString("o")
    finished_at = $End.ToString("o")
    duration_seconds = [math]::Round(($End - $Start).TotalSeconds, 3)
    pid = $ProcessId
    exit_code = $ExitCode
    stdout_sha256 = $StdoutHash
    stderr_sha256 = $StderrHash
    test_temp = $TestTemp
    test_temp_cleanup = $Cleanup
} | ConvertTo-Json -Depth 4 | Set-Content -Encoding UTF8 (Join-Path $EvidenceDir "run-result.json")

Write-Output "EXIT_CODE=$ExitCode"
Write-Output "DURATION_SECONDS=$([math]::Round(($End - $Start).TotalSeconds, 3))"
Write-Output "STDOUT_SHA256=$StdoutHash"
Write-Output "STDERR_SHA256=$StderrHash"
Write-Output "TEMP_CLEANUP=$Cleanup"

if ($ExitCode -ne 0) {
    exit $ExitCode
}

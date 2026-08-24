param(
    [string]$ArchivePath = '',
    [switch]$Download,
    [switch]$Replace,
    [switch]$LibraryMode,
    [string]$InputRootOverride = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

if ($InputRootOverride -and -not $LibraryMode) {
    throw 'MEDIA_RUNTIME_INPUT_ROOT_OVERRIDE_FORBIDDEN: 正式入口只能使用项目内固定构建输入目录'
}

$ArchiveUrl = 'https://www.gyan.dev/ffmpeg/builds/packages/ffmpeg-8.0.1-essentials_build.zip'
$ArchiveName = 'ffmpeg-8.0.1-essentials_build.zip'
$ArchiveSize = 106259850
$ArchiveSha256 = 'e2aaeaa0fdbc397d4794828086424d4aaa2102cef1fb6874f6ffd29c0b88b673'
$ArchiveRootName = 'ffmpeg-8.0.1-essentials_build'
$InputRoot = if ($InputRootOverride) {
    [IO.Path]::GetFullPath($InputRootOverride)
}
else {
    [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '构建输入'))
}
$DownloadRoot = Join-Path $InputRoot '下载'
$ReceiptRoot = Join-Path $InputRoot 'records'
$Destination = Join-Path $InputRoot $ArchiveRootName

$ReviewedFiles = @(
    [pscustomobject]@{
        ArchiveEntry = "$ArchiveRootName/bin/ffmpeg.exe"
        RelativePath = 'bin\ffmpeg.exe'
        Size = 99264000
        Sha256 = '5af82a0d4fe2b9eae211b967332ea97edfc51c6b328ca35b827e73eac560dc0d'
        PeX64 = $true
    },
    [pscustomobject]@{
        ArchiveEntry = "$ArchiveRootName/bin/ffprobe.exe"
        RelativePath = 'bin\ffprobe.exe'
        Size = 99066368
        Sha256 = '192a1d6899059765ac8c39764fc3148d4e6049955956dc2029f81f4bd6a8972d'
        PeX64 = $true
    },
    [pscustomobject]@{
        ArchiveEntry = "$ArchiveRootName/LICENSE"
        RelativePath = 'LICENSE'
        Size = 35147
        Sha256 = '8ceb4b9ee5adedde47b31e975c1d90c73ad27b6b165a1dcd80c7c545eb65b903'
        PeX64 = $false
    },
    [pscustomobject]@{
        ArchiveEntry = "$ArchiveRootName/README.txt"
        RelativePath = 'README.txt'
        Size = 40985
        Sha256 = 'a0e976df3cf1d781264c41db8ee3421978c1278be92ed00edbc96337529670be'
        PeX64 = $false
    }
)

function Assert-NoReparseComponents {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$Label = '路径'
    )
    $full = [IO.Path]::GetFullPath($Path)
    $volumeRoot = [IO.Path]::GetPathRoot($full)
    $cursor = $volumeRoot
    $relativeParts = $full.Substring($volumeRoot.Length).Split(
        @([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar),
        [StringSplitOptions]::RemoveEmptyEntries
    )
    foreach ($part in $relativeParts) {
        $cursor = Join-Path $cursor $part
        if (-not (Test-Path -LiteralPath $cursor)) { break }
        $item = Get-Item -LiteralPath $cursor -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "$Label 含重解析组件，拒绝继续: $cursor"
        }
    }
    return $full
}

function Assert-RealInputRoot {
    $full = Assert-NoReparseComponents -Path $InputRoot -Label '构建输入根目录'
    if (-not (Test-Path -LiteralPath $full -PathType Container)) {
        throw "构建输入根目录不存在或不是目录: $full"
    }
    $item = Get-Item -LiteralPath $full -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or -not $item.PSIsContainer) {
        throw "构建输入根目录必须是真实非重解析目录: $full"
    }
    return $full
}

function Assert-UnderInputRoot {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (Test-Path -LiteralPath $InputRoot) { $null = Assert-RealInputRoot }
    else { $null = Assert-NoReparseComponents -Path $InputRoot -Label '构建输入根目录' }
    $full = Assert-NoReparseComponents -Path $Path -Label '构建输入目标路径'
    $prefix = $InputRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    if (-not $full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "拒绝操作项目构建输入目录之外的路径: $full"
    }
    return $full
}

function Assert-RealDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$Label = '目录'
    )
    $full = Assert-UnderInputRoot -Path $Path
    if (-not (Test-Path -LiteralPath $full -PathType Container)) {
        throw "$Label 不存在或不是目录: $full"
    }
    $item = Get-Item -LiteralPath $full -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or -not $item.PSIsContainer) {
        throw "$Label 必须是真实非重解析目录: $full"
    }
    $null = Assert-NoReparseComponents -Path $full -Label $Label
    return $full
}

function Assert-RegularNonReparseFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$Label = '文件'
    )
    $full = Assert-NoReparseComponents -Path $Path -Label $Label
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
        throw "$Label 不存在或不是普通文件: $full"
    }
    $item = Get-Item -LiteralPath $full -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.PSIsContainer) {
        throw "$Label 必须是非重解析普通文件: $full"
    }
    return $full
}

function Get-LowerSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-ParentProcessIdentity {
    $record = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $PID"
    if (-not $record -or -not $record.ParentProcessId) {
        throw 'DOWNLOAD_PARENT_IDENTITY_UNAVAILABLE: 无法取得下载父进程身份'
    }
    $parent = Get-Process -Id ([int]$record.ParentProcessId) -ErrorAction Stop
    return [pscustomobject]@{
        Pid = [int]$parent.Id
        StartTimeUtcTicks = [Int64]$parent.StartTime.ToUniversalTime().Ticks
    }
}

function Test-ProcessIdentityAlive {
    param([Parameter(Mandatory = $true)]$Identity)
    try {
        $process = Get-Process -Id ([int]$Identity.Pid) -ErrorAction Stop
        return ([Int64]$process.StartTime.ToUniversalTime().Ticks -eq [Int64]$Identity.StartTimeUtcTicks)
    }
    catch {
        return $false
    }
}

function Write-DownloadEvent {
    param(
        [Parameter(Mandatory = $true)][IO.StreamWriter]$Writer,
        [Parameter(Mandatory = $true)][string]$Event,
        [Parameter(Mandatory = $true)][Int64]$Bytes,
        [Parameter(Mandatory = $true)][Int64]$ExpectedBytes,
        [Parameter(Mandatory = $true)][DateTime]$StartedUtc,
        [string]$Message = ''
    )
    $elapsed = [Math]::Round(([DateTime]::UtcNow - $StartedUtc).TotalSeconds, 1)
    $percent = if ($ExpectedBytes -gt 0) { [Math]::Round(($Bytes * 100.0) / $ExpectedBytes, 2) } else { 0 }
    $record = [ordered]@{
        schema = 'nachuan.media-runtime-download-event.v1'
        event = $Event
        atUtc = [DateTime]::UtcNow.ToString('o')
        bytes = $Bytes
        expectedBytes = $ExpectedBytes
        percent = $percent
        elapsedSeconds = $elapsed
        message = $Message
    }
    $Writer.WriteLine(($record | ConvertTo-Json -Compress))
    $Writer.Flush()
    Write-Host ("DOWNLOAD_{0} bytes={1}/{2} percent={3} elapsed={4}s {5}" -f $Event.ToUpperInvariant(), $Bytes, $ExpectedBytes, $percent, $elapsed, $Message)
}

function Invoke-DownloadGuard {
    param(
        [Parameter(Mandatory = $true)]$ParentIdentity,
        [Parameter(Mandatory = $true)][DateTime]$StartedUtc,
        [Parameter(Mandatory = $true)][DateTime]$LastProgressUtc,
        [Parameter(Mandatory = $true)][ref]$LastHeartbeatUtc,
        [Parameter(Mandatory = $true)][int]$TotalTimeoutSeconds,
        [Parameter(Mandatory = $true)][int]$IdleTimeoutSeconds,
        [Parameter(Mandatory = $true)][int]$HeartbeatSeconds,
        [Parameter(Mandatory = $true)][Int64]$Bytes,
        [Parameter(Mandatory = $true)][Int64]$ExpectedBytes,
        [Parameter(Mandatory = $true)][IO.StreamWriter]$Writer,
        [DateTime]$NowUtc = [DateTime]::UtcNow
    )
    $now = $NowUtc
    if (-not (Test-ProcessIdentityAlive -Identity $ParentIdentity)) {
        throw 'DOWNLOAD_PARENT_EXITED: 父进程已退出或 PID 身份变化，下载主动收敛'
    }
    if (($now - $StartedUtc).TotalSeconds -ge $TotalTimeoutSeconds) {
        throw "DOWNLOAD_TOTAL_TIMEOUT: 下载超过总时限 ${TotalTimeoutSeconds}s"
    }
    if (($now - $LastProgressUtc).TotalSeconds -ge $IdleTimeoutSeconds) {
        throw "DOWNLOAD_IDLE_TIMEOUT: 下载连续 ${IdleTimeoutSeconds}s 没有收到字节"
    }
    if (($now - $LastHeartbeatUtc.Value).TotalSeconds -ge $HeartbeatSeconds) {
        Write-DownloadEvent -Writer $Writer -Event 'heartbeat' -Bytes $Bytes -ExpectedBytes $ExpectedBytes -StartedUtc $StartedUtc
        $LastHeartbeatUtc.Value = $now
    }
}

function Invoke-BoundedDownload {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)][string]$StatusLog,
        [Parameter(Mandatory = $true)][Int64]$ExpectedBytes,
        [Parameter(Mandatory = $true)]$ParentIdentity,
        [int]$TotalTimeoutSeconds = 3600,
        [int]$IdleTimeoutSeconds = 120,
        [int]$HeartbeatSeconds = 10
    )
    if ($ExpectedBytes -le 0 -or $TotalTimeoutSeconds -lt 1 -or $IdleTimeoutSeconds -lt 1 -or $HeartbeatSeconds -lt 1) {
        throw 'DOWNLOAD_BOUNDS_INVALID: 下载边界必须为正数'
    }
    $Destination = Assert-UnderInputRoot -Path $Destination
    $StatusLog = Assert-UnderInputRoot -Path $StatusLog
    $null = Assert-RealDirectory -Path (Split-Path -Parent $Destination) -Label '下载目标父目录'
    $null = Assert-RealDirectory -Path (Split-Path -Parent $StatusLog) -Label '下载状态父目录'
    if ((Test-Path -LiteralPath $Destination) -or (Test-Path -LiteralPath $StatusLog)) {
        throw 'DOWNLOAD_CANDIDATE_EXISTS: 下载候选或状态日志已经存在'
    }

    Add-Type -AssemblyName System.Net.Http
    $startedUtc = [DateTime]::UtcNow
    $lastProgressUtc = $startedUtc
    $lastHeartbeatUtc = $startedUtc
    $received = [Int64]0
    $statusStream = $null
    $statusWriter = $null
    $output = $null
    $handler = $null
    $client = $null
    $response = $null
    $input = $null
    $cancellation = $null
    try {
        $statusStream = [IO.File]::Open($StatusLog, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
        $statusWriter = New-Object IO.StreamWriter($statusStream, (New-Object Text.UTF8Encoding($false)))
        $statusWriter.AutoFlush = $true
        Write-DownloadEvent -Writer $statusWriter -Event 'start' -Bytes 0 -ExpectedBytes $ExpectedBytes -StartedUtc $startedUtc -Message $Uri
        Invoke-DownloadGuard -ParentIdentity $ParentIdentity -StartedUtc $startedUtc -LastProgressUtc $lastProgressUtc -LastHeartbeatUtc ([ref]$lastHeartbeatUtc) -TotalTimeoutSeconds $TotalTimeoutSeconds -IdleTimeoutSeconds $IdleTimeoutSeconds -HeartbeatSeconds $HeartbeatSeconds -Bytes 0 -ExpectedBytes $ExpectedBytes -Writer $statusWriter

        $handler = New-Object System.Net.Http.HttpClientHandler
        $handler.AllowAutoRedirect = $false
        $client = New-Object System.Net.Http.HttpClient($handler)
        $client.Timeout = [Threading.Timeout]::InfiniteTimeSpan
        $client.DefaultRequestHeaders.UserAgent.ParseAdd('NachuanMediaRuntimePrep/1.0')
        $cancellation = New-Object Threading.CancellationTokenSource
        $cancellation.CancelAfter($TotalTimeoutSeconds * 1000)
        $requestTask = $client.GetAsync($Uri, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead, $cancellation.Token)
        while (-not $requestTask.IsCompleted) {
            Start-Sleep -Milliseconds 250
            Invoke-DownloadGuard -ParentIdentity $ParentIdentity -StartedUtc $startedUtc -LastProgressUtc $lastProgressUtc -LastHeartbeatUtc ([ref]$lastHeartbeatUtc) -TotalTimeoutSeconds $TotalTimeoutSeconds -IdleTimeoutSeconds $IdleTimeoutSeconds -HeartbeatSeconds $HeartbeatSeconds -Bytes $received -ExpectedBytes $ExpectedBytes -Writer $statusWriter
        }
        $response = $requestTask.GetAwaiter().GetResult()
        if (-not $response.IsSuccessStatusCode) {
            throw "DOWNLOAD_HTTP_STATUS: HTTP $([int]$response.StatusCode)"
        }
        if ($null -ne $response.Content.Headers.ContentLength -and [Int64]$response.Content.Headers.ContentLength -ne $ExpectedBytes) {
            throw "DOWNLOAD_CONTENT_LENGTH: expected=$ExpectedBytes actual=$($response.Content.Headers.ContentLength)"
        }

        $input = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
        $output = [IO.File]::Open($Destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
        $buffer = New-Object byte[] (1024 * 1024)
        while ($true) {
            $readTask = $input.ReadAsync($buffer, 0, $buffer.Length, $cancellation.Token)
            while (-not $readTask.IsCompleted) {
                Start-Sleep -Milliseconds 250
                Invoke-DownloadGuard -ParentIdentity $ParentIdentity -StartedUtc $startedUtc -LastProgressUtc $lastProgressUtc -LastHeartbeatUtc ([ref]$lastHeartbeatUtc) -TotalTimeoutSeconds $TotalTimeoutSeconds -IdleTimeoutSeconds $IdleTimeoutSeconds -HeartbeatSeconds $HeartbeatSeconds -Bytes $received -ExpectedBytes $ExpectedBytes -Writer $statusWriter
            }
            $count = $readTask.GetAwaiter().GetResult()
            if ($count -eq 0) { break }
            $received += $count
            if ($received -gt $ExpectedBytes) {
                throw "DOWNLOAD_SIZE_OVERFLOW: received=$received expected=$ExpectedBytes"
            }
            $output.Write($buffer, 0, $count)
            $lastProgressUtc = [DateTime]::UtcNow
            Invoke-DownloadGuard -ParentIdentity $ParentIdentity -StartedUtc $startedUtc -LastProgressUtc $lastProgressUtc -LastHeartbeatUtc ([ref]$lastHeartbeatUtc) -TotalTimeoutSeconds $TotalTimeoutSeconds -IdleTimeoutSeconds $IdleTimeoutSeconds -HeartbeatSeconds $HeartbeatSeconds -Bytes $received -ExpectedBytes $ExpectedBytes -Writer $statusWriter
        }
        $output.Flush($true)
        if ($received -ne $ExpectedBytes) {
            throw "DOWNLOAD_SIZE_TRUNCATED: received=$received expected=$ExpectedBytes"
        }
        Write-DownloadEvent -Writer $statusWriter -Event 'complete' -Bytes $received -ExpectedBytes $ExpectedBytes -StartedUtc $startedUtc
    }
    catch {
        if ($cancellation) { $cancellation.Cancel() }
        if ($statusWriter) {
            Write-DownloadEvent -Writer $statusWriter -Event 'failed' -Bytes $received -ExpectedBytes $ExpectedBytes -StartedUtc $startedUtc -Message $_.Exception.Message
        }
        throw
    }
    finally {
        if ($input) { $input.Dispose() }
        if ($response) { $response.Dispose() }
        if ($output) { $output.Dispose() }
        if ($client) { $client.Dispose() }
        if ($handler) { $handler.Dispose() }
        if ($cancellation) { $cancellation.Dispose() }
        if ($statusWriter) { $statusWriter.Dispose() }
        elseif ($statusStream) { $statusStream.Dispose() }
    }
}

function Assert-Archive {
    param([Parameter(Mandatory = $true)][string]$Path)
    $Path = Assert-RegularNonReparseFile -Path $Path -Label 'FFmpeg 官方 ZIP'
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.Length -ne $ArchiveSize) {
        throw "FFmpeg ZIP 大小不匹配: expected=$ArchiveSize actual=$($item.Length)"
    }
    $actual = Get-LowerSha256 -Path $Path
    if ($actual -ne $ArchiveSha256) {
        throw "FFmpeg ZIP SHA-256 不匹配: expected=$ArchiveSha256 actual=$actual"
    }
}

function Assert-PeX64 {
    param([Parameter(Mandatory = $true)][string]$Path)
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $reader = New-Object IO.BinaryReader($stream)
        if ($reader.ReadUInt16() -ne 0x5A4D) { throw "不是 PE 文件: $Path" }
        $stream.Position = 0x3c
        $peOffset = $reader.ReadUInt32()
        if ($peOffset -lt 64 -or $peOffset -gt 1048576) { throw "PE 头偏移非法: $Path" }
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) { throw "PE 签名非法: $Path" }
        if ($reader.ReadUInt16() -ne 0x8664) { throw "不是 x64 PE: $Path" }
    }
    finally {
        $stream.Dispose()
    }
}

function Assert-PreparedSource {
    param([Parameter(Mandatory = $true)][string]$Root)
    $Root = Assert-RealDirectory -Path $Root -Label 'FFmpeg 构建输入目录'
    $rootEntries = @((Get-ChildItem -LiteralPath $Root -Force | Sort-Object Name | ForEach-Object Name))
    if (($rootEntries -join ',') -ne 'bin,LICENSE,README.txt') {
        throw "FFmpeg 构建输入根目录不是闭集: $($rootEntries -join ',')"
    }
    $binRoot = Assert-RealDirectory -Path (Join-Path $Root 'bin') -Label 'FFmpeg bin 目录'
    $binEntries = @((Get-ChildItem -LiteralPath $binRoot -Force | Sort-Object Name | ForEach-Object Name))
    if (($binEntries -join ',') -ne 'ffmpeg.exe,ffprobe.exe') {
        throw "FFmpeg bin 目录不是严格双文件闭集: $($binEntries -join ',')"
    }
    foreach ($reviewed in $ReviewedFiles) {
        $path = Assert-RegularNonReparseFile -Path (Join-Path $Root $reviewed.RelativePath) -Label "受审文件 $($reviewed.RelativePath)"
        $item = Get-Item -LiteralPath $path -Force
        if ($item.Length -ne $reviewed.Size) {
            throw "受审文件大小不匹配: $($reviewed.RelativePath)"
        }
        $actual = Get-LowerSha256 -Path $path
        if ($actual -ne $reviewed.Sha256) {
            throw "受审文件 SHA-256 不匹配: $($reviewed.RelativePath)"
        }
        if ($reviewed.PeX64) { Assert-PeX64 -Path $path }
    }
}

function Assert-SafePartialSourceTree {
    param([Parameter(Mandatory = $true)][string]$Root)
    $Root = Assert-RealDirectory -Path $Root -Label 'FFmpeg 临时候选目录'
    $allowedRoot = @('bin', 'LICENSE', 'README.txt')
    foreach ($entry in @(Get-ChildItem -LiteralPath $Root -Force)) {
        if ($allowedRoot -cnotcontains $entry.Name) {
            throw "临时候选目录含未审条目，拒绝递归清理: $($entry.Name)"
        }
        if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "临时候选目录含重解析条目，拒绝递归清理: $($entry.FullName)"
        }
    }
    $binRoot = Join-Path $Root 'bin'
    if (Test-Path -LiteralPath $binRoot) {
        $binRoot = Assert-RealDirectory -Path $binRoot -Label 'FFmpeg 临时候选 bin 目录'
        foreach ($entry in @(Get-ChildItem -LiteralPath $binRoot -Force)) {
            if (@('ffmpeg.exe', 'ffprobe.exe') -cnotcontains $entry.Name) {
                throw "临时候选 bin 含未审条目，拒绝递归清理: $($entry.Name)"
            }
            $null = Assert-RegularNonReparseFile -Path $entry.FullName -Label 'FFmpeg 临时候选文件'
        }
    }
    foreach ($name in @('LICENSE', 'README.txt')) {
        $path = Join-Path $Root $name
        if (Test-Path -LiteralPath $path) {
            $null = Assert-RegularNonReparseFile -Path $path -Label 'FFmpeg 临时候选凭证'
        }
    }
    return $Root
}

function Write-Receipt {
    param(
        [Parameter(Mandatory = $true)][string]$Archive,
        [Parameter(Mandatory = $true)][string]$SourceRoot
    )
    if (-not (Test-Path -LiteralPath $ReceiptRoot)) {
        $null = Assert-UnderInputRoot -Path $ReceiptRoot
        New-Item -ItemType Directory -Path $ReceiptRoot -Force | Out-Null
    }
    $null = Assert-RealDirectory -Path $ReceiptRoot -Label '构建输入回执目录'
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $receiptPath = Assert-UnderInputRoot -Path (Join-Path $ReceiptRoot ("$stamp-media-runtime-source-" + [Guid]::NewGuid().ToString('N') + '.json'))
    $receipt = [ordered]@{
        schema = 'nachuan.media-runtime-source-receipt.v1'
        verifiedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        archive = [ordered]@{
            name = $ArchiveName
            size = $ArchiveSize
            sha256 = $ArchiveSha256
            sourceUrl = $ArchiveUrl
        }
        selectedFiles = @($ReviewedFiles | ForEach-Object {
            [ordered]@{
                path = $_.RelativePath.Replace('\', '/')
                size = $_.Size
                sha256 = $_.Sha256
            }
        })
        excludedExecutable = 'bin/ffplay.exe'
        sourceDirectory = $ArchiveRootName
    }
    $json = $receipt | ConvertTo-Json -Depth 8
    if (Test-Path -LiteralPath $receiptPath) { throw "回执候选路径已存在: $receiptPath" }
    [IO.File]::WriteAllText($receiptPath, $json + [Environment]::NewLine, (New-Object Text.UTF8Encoding($false)))
    return $receiptPath
}

if ($LibraryMode) { return }

if (-not $ArchivePath) { $ArchivePath = Join-Path $DownloadRoot $ArchiveName }
try {
    $ArchivePath = Assert-UnderInputRoot -Path ([IO.Path]::GetFullPath($ArchivePath))
}
catch {
    throw "MEDIA_RUNTIME_ARCHIVE_OUTSIDE_PROJECT: $($_.Exception.Message)"
}
$null = Assert-NoReparseComponents -Path $InputRoot -Label '构建输入根目录'
if (-not (Test-Path -LiteralPath $InputRoot)) {
    New-Item -ItemType Directory -Path $InputRoot -Force | Out-Null
}
$null = Assert-RealInputRoot
if (-not (Test-Path -LiteralPath $DownloadRoot)) {
    $null = Assert-UnderInputRoot -Path $DownloadRoot
    New-Item -ItemType Directory -Path $DownloadRoot -Force | Out-Null
}
$null = Assert-RealDirectory -Path $DownloadRoot -Label '构建输入下载目录'

if ($Download) {
    $downloadCandidate = Assert-UnderInputRoot -Path (Join-Path $DownloadRoot ("$ArchiveName.download-" + [Guid]::NewGuid().ToString('N')))
    $downloadStatusLog = Assert-UnderInputRoot -Path ($downloadCandidate + '.progress.jsonl')
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $parentIdentity = Get-ParentProcessIdentity
        Write-Host "正在流式下载 Gyan 官方固定归档；总时限 3600s、空闲时限 120s、每 10s 心跳。"
        Write-Host "下载状态日志: $downloadStatusLog"
        Invoke-BoundedDownload -Uri $ArchiveUrl -Destination $downloadCandidate -StatusLog $downloadStatusLog -ExpectedBytes $ArchiveSize -ParentIdentity $parentIdentity -TotalTimeoutSeconds 3600 -IdleTimeoutSeconds 120 -HeartbeatSeconds 10
        Assert-Archive -Path $downloadCandidate
        if (Test-Path -LiteralPath $ArchivePath) {
            $existing = Assert-UnderInputRoot -Path $ArchivePath
            $existing = Assert-RegularNonReparseFile -Path $existing -Label '已有 FFmpeg ZIP'
            Remove-Item -LiteralPath $existing -Force
        }
        $null = Assert-RegularNonReparseFile -Path $downloadCandidate -Label '已下载 FFmpeg ZIP 候选'
        Move-Item -LiteralPath $downloadCandidate -Destination $ArchivePath
    }
    finally {
        if (Test-Path -LiteralPath $downloadCandidate) {
            $downloadCandidate = Assert-UnderInputRoot -Path $downloadCandidate
            $downloadCandidate = Assert-RegularNonReparseFile -Path $downloadCandidate -Label 'FFmpeg ZIP 临时下载'
            Remove-Item -LiteralPath $downloadCandidate -Force
        }
    }
}

Assert-Archive -Path $ArchivePath
if ((Test-Path -LiteralPath $Destination -PathType Container) -and -not $Replace) {
    try {
        Assert-PreparedSource -Root $Destination
        $receipt = Write-Receipt -Archive $ArchivePath -SourceRoot $Destination
        Write-Host "FFmpeg 构建输入已经受审，无需替换。"
        Write-Host "SOURCE=$Destination"
        Write-Host "RECEIPT=$receipt"
        exit 0
    }
    catch {
        throw "已有构建输入未通过复核；如需重建请加 -Replace。原因: $($_.Exception.Message)"
    }
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
$candidate = Assert-UnderInputRoot -Path (Join-Path $InputRoot (".ffmpeg-candidate-" + [Guid]::NewGuid().ToString('N')))
$backup = $null
try {
    New-Item -ItemType Directory -Path (Join-Path $candidate 'bin') -Force | Out-Null
    $null = Assert-RealDirectory -Path $candidate -Label 'FFmpeg 临时候选目录'
    $null = Assert-RealDirectory -Path (Join-Path $candidate 'bin') -Label 'FFmpeg 临时候选 bin 目录'
    $null = Assert-RegularNonReparseFile -Path $ArchivePath -Label 'FFmpeg 官方 ZIP'
    $zip = [IO.Compression.ZipFile]::OpenRead($ArchivePath)
    try {
        foreach ($reviewed in $ReviewedFiles) {
            $matches = @($zip.Entries | Where-Object { $_.FullName.Replace('\', '/') -ceq $reviewed.ArchiveEntry })
            if ($matches.Count -ne 1) {
                throw "ZIP 中受审条目缺失或重复: $($reviewed.ArchiveEntry)"
            }
            if ($matches[0].Length -ne $reviewed.Size) {
                throw "ZIP 中受审条目大小不匹配: $($reviewed.ArchiveEntry)"
            }
            $destinationFile = Assert-UnderInputRoot -Path (Join-Path $candidate $reviewed.RelativePath)
            $parent = Split-Path -Parent $destinationFile
            New-Item -ItemType Directory -Path $parent -Force | Out-Null
            $null = Assert-RealDirectory -Path $parent -Label 'FFmpeg 临时解包父目录'
            $input = $matches[0].Open()
            $output = [IO.File]::Open($destinationFile, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            try { $input.CopyTo($output) }
            finally {
                $output.Dispose()
                $input.Dispose()
            }
        }
    }
    finally {
        $zip.Dispose()
    }

    Assert-PreparedSource -Root $candidate
    if (Test-Path -LiteralPath $Destination) {
        if (-not $Replace) { throw '目标目录已存在；请加 -Replace。' }
        $null = Assert-PreparedSource -Root $Destination
        $backup = Assert-UnderInputRoot -Path (Join-Path $InputRoot (".ffmpeg-previous-" + [Guid]::NewGuid().ToString('N')))
        Move-Item -LiteralPath $Destination -Destination $backup
        $null = Assert-PreparedSource -Root $backup
    }
    $null = Assert-PreparedSource -Root $candidate
    Move-Item -LiteralPath $candidate -Destination $Destination
    Assert-PreparedSource -Root $Destination
    if ($backup -and (Test-Path -LiteralPath $backup)) {
        $backup = Assert-PreparedSource -Root $backup
        $backup = Assert-PreparedSource -Root $backup
        Remove-Item -LiteralPath $backup -Recurse -Force
        $backup = $null
    }
}
catch {
    if ($backup -and (Test-Path -LiteralPath $backup) -and -not (Test-Path -LiteralPath $Destination)) {
        $backup = Assert-PreparedSource -Root $backup
        $null = Assert-UnderInputRoot -Path $Destination
        Move-Item -LiteralPath $backup -Destination $Destination
        $backup = $null
    }
    throw
}
finally {
    if (Test-Path -LiteralPath $candidate) {
        $candidate = Assert-SafePartialSourceTree -Root $candidate
        $candidate = Assert-SafePartialSourceTree -Root $candidate
        Remove-Item -LiteralPath $candidate -Recurse -Force
    }
}

$receipt = Write-Receipt -Archive $ArchivePath -SourceRoot $Destination
Write-Host "FFmpeg 构建输入准备完成：仅 ffmpeg.exe、ffprobe.exe、LICENSE、README.txt。"
Write-Host 'ffplay.exe 未解出。正式构建不会从 PATH 或 Program Files 取二进制。'
Write-Host "SOURCE=$Destination"
Write-Host "RECEIPT=$receipt"

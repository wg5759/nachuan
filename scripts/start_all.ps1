[CmdletBinding()]
param(
    [ValidateSet('Run', 'Resume', 'Status', 'Stop', 'InstallTask', 'Validate')]
    [string]$Action = 'Run',
    [string]$Root = '',
    [int]$EnginePort = 8080,
    [int]$PollSeconds = 10,
    [int]$UnhealthyThreshold = 3,
    [int]$BackupIntervalSeconds = 21600,
    [switch]$Scheduled,
    [switch]$Once,
    [switch]$DryRun,
    [switch]$Json
)

# 纳川本机监督器（PowerShell 5.1+）。
#
# 启动/守护：
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\start_all.ps1
# 状态（可给监控采集）：
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\start_all.ps1 -Action Status -Json
# 停止监督器、引擎和桥：
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\start_all.ps1 -Action Stop
# Stop 会留下持久停机闩锁，计划任务重启也不会绕过。显式恢复：
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\start_all.ps1 -Action Resume
# 安全演练（不启动/不停止进程）：
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\start_all.ps1 -Once -DryRun -Json
# 源码树禁止注册登录任务。正式安装必须由签名安装器从受保护安装目录注册；
# `InstallTask` 保留为兼容入口，但始终失败关闭。

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Service/CI launches may intentionally carry no PSModulePath. Import the
# inbox CIM module by its PSHOME-owned manifest instead of trusting ambient
# module discovery; process identity fencing depends on Get-CimInstance.
$CimModuleManifest = Join-Path $PSHOME 'Modules\CimCmdlets\CimCmdlets.psd1'
if (-not (Test-Path -LiteralPath $CimModuleManifest -PathType Leaf)) {
    throw 'trusted Windows CIM module manifest is missing'
}
Import-Module -Name $CimModuleManifest -ErrorAction Stop

# Windows services/tasks commonly inherit a legacy GBK console code page.
# Force every managed Python child and helper to emit deterministic UTF-8;
# otherwise a single emoji in a startup message can crash a bridge before it
# writes health state, causing an endless watchdog restart loop.
$env:PYTHONUTF8 = '1'
$env:PYTHONIOENCODING = 'utf-8'

if ([string]::IsNullOrWhiteSpace($Root)) {
    $Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
} else {
    $Root = [IO.Path]::GetFullPath($Root)
}

$DataDir = Join-Path $Root 'data'
$LogDir = Join-Path $DataDir 'logs'
$Python = Join-Path $Root '.venv\Scripts\python.exe'
$SupervisorPidFile = Join-Path $DataDir 'nachuan-supervisor.pid'
$SupervisorStopFile = Join-Path $DataDir 'nachuan-supervisor.stop.json'
$SupervisorLockFile = Join-Path $DataDir 'nachuan-supervisor.lock'
$SupervisorScriptPath = [IO.Path]::GetFullPath($MyInvocation.MyCommand.Path)
$GatewayKeyFile = Join-Path $DataDir 'gateway_api_key.txt'
$ApprovalKeyFile = Join-Path $DataDir 'approval_admin_key.txt'
$WeixinBridgeKeyFile = Join-Path $DataDir 'weixin_bridge_api_key.txt'
$FeishuBridgeKeyFile = Join-Path $DataDir 'feishu_bridge_api_key.txt'
$EngineBootTokenFile = Join-Path $DataDir 'engine_boot_token.txt'
$MediaConfigFile = Join-Path $DataDir 'media-binaries.json'
$BackupRoot = Join-Path $DataDir 'backup\sqlite'
$WeixinTokenFile = Join-Path $DataDir 'ilink_token.json'
$WeixinHealthFile = Join-Path $DataDir 'weixin_bridge_health.json'
$FeishuHealthFile = Join-Path $DataDir 'feishu_bridge_health.json'
$SupervisorLog = Join-Path $LogDir 'supervisor.log'
$ManagedLauncherPath = [IO.Path]::GetFullPath((Join-Path $Root 'scripts\managed_launcher.py'))
$Taskkill = Join-Path ([Environment]::SystemDirectory) 'taskkill.exe'
$script:Unhealthy = @{ engine = 0; weixin = 0; feishu = 0 }
$script:StartAttempt = @{ engine = 0; weixin = 0; feishu = 0 }
$script:NextStartAt = @{ engine = [DateTimeOffset]::MinValue; weixin = [DateTimeOffset]::MinValue; feishu = [DateTimeOffset]::MinValue }
$script:StartedAt = @{ engine = [DateTimeOffset]::MinValue; weixin = [DateTimeOffset]::MinValue; feishu = [DateTimeOffset]::MinValue }
$script:EngineGenerationCounter = [long]0
$script:ProcessSnapshot = @()
$script:ProcessSnapshotAt = [datetime]::MinValue
$script:SupervisorInstanceId = ''
$runtimeTreeInitialized = $false
$WeixinInboundClaimTtlSeconds = 5 * 60
# The bridge reclaims at 300s. Allow one extra minute for heartbeat/write
# jitter before treating an otherwise alive worker as irrecoverably stuck.
$WeixinProcessingStuckThresholdSeconds = $WeixinInboundClaimTtlSeconds + 60
$FeishuStartupGraceSeconds = 180

function Ensure-Directory([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Get-Sha256Hex([string]$Value) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Get-FileSha256Hex([string]$Path) {
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
        $stream.Dispose()
    }
}

function Assert-NoReparseComponents([string]$Path) {
    $cursor = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    while ($null -ne $cursor) {
        if (($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "path contains a reparse point: $Path"
        }
        $parent = [IO.Directory]::GetParent($cursor.FullName)
        if ($null -eq $parent) { break }
        $cursor = Get-Item -LiteralPath $parent.FullName -Force -ErrorAction Stop
    }
}

function Assert-TrustedRegularFile(
    [string]$Path,
    [string]$Label,
    [switch]$AllowReparseAncestors
) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw ("{0} is unavailable: {1}" -f $Label, $Path)
    }
    if (-not $AllowReparseAncestors) { Assert-NoReparseComponents $Path }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (-not ($item -is [IO.FileInfo]) -or
        (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw ("{0} must be a regular non-reparse file: {1}" -f $Label, $Path)
    }
}

if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
    throw "project root does not exist: $Root"
}
Assert-NoReparseComponents $Root
if ($Scheduled) {
    $scriptRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
    if (-not [string]::Equals($Root.TrimEnd('\'), $scriptRoot.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) {
        throw 'scheduled production mode refuses an alternate project root'
    }
    Assert-TrustedRegularFile $SupervisorScriptPath 'supervisor script'
}
Assert-NoReparseComponents $Taskkill
$taskkillItem = Get-Item -LiteralPath $Taskkill -Force -ErrorAction Stop
if (-not ($taskkillItem -is [IO.FileInfo])) {
    throw 'trusted System32 taskkill.exe is unavailable'
}

function Invoke-BoundedTaskkill([long]$TargetPid) {
    if ($TargetPid -le 0) { return -1 }
    # Native stderr is not an authority signal here.  On Windows PowerShell
    # 5.1, taskkill can report a child as already gone while the wrapper's
    # KILL_ON_JOB_CLOSE job is concurrently finishing the same tree; with the
    # global Stop preference that text otherwise becomes a terminating
    # NativeCommandError before the exact process-identity recheck can run.
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Taskkill
    $psi.Arguments = "/PID $TargetPid /T /F"
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi
    try {
        if (-not $proc.Start()) { return -1 }
        $outTask = $proc.StandardOutput.ReadToEndAsync()
        $errTask = $proc.StandardError.ReadToEndAsync()
        if (-not $proc.WaitForExit(15000)) {
            $proc.Kill()
            [void]$proc.WaitForExit(5000)
            return -1
        }
        $proc.WaitForExit()
        [void]$outTask.Wait(5000)
        [void]$errTask.Wait(5000)
        return [int]$proc.ExitCode
    } finally {
        $proc.Dispose()
    }
}

function Get-SafeMediaExecutable([string]$RawPath, [string]$ExpectedHash, [string]$ExpectedName) {
    if ([string]::IsNullOrWhiteSpace($RawPath) -or
        -not [IO.Path]::IsPathRooted($RawPath) -or
        $RawPath.StartsWith('\\') -or
        [IO.Path]::GetExtension($RawPath) -ne '.exe' -or
        [IO.Path]::GetFileName($RawPath) -ne $ExpectedName -or
        $ExpectedHash -notmatch '^[0-9a-f]{64}$') {
        throw "invalid $ExpectedName media attestation"
    }
    $path = [IO.Path]::GetFullPath($RawPath)
    Assert-NoReparseComponents $path
    $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if (-not ($item -is [IO.FileInfo]) -or $item.Length -le 0 -or $item.Length -gt 536870912) {
        throw "$ExpectedName is not a bounded regular file"
    }
    $actual = Get-FileSha256Hex $path
    if (-not [string]::Equals($actual, $ExpectedHash, [StringComparison]::OrdinalIgnoreCase)) {
        throw "$ExpectedName SHA-256 mismatch"
    }
    return $path
}

function Configure-MediaBinaries {
    Remove-Item Env:FFMPEG_BIN,Env:FFMPEG_SHA256,Env:FFPROBE_BIN,Env:FFPROBE_SHA256 `
        -ErrorAction SilentlyContinue
    if (-not (Test-Path -LiteralPath $MediaConfigFile -PathType Leaf)) { return }
    $item = Get-Item -LiteralPath $MediaConfigFile -Force -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $item.Length -le 0 -or $item.Length -gt 8192) {
        throw 'media binary config is not a bounded regular file'
    }
    $document = Get-Content -Raw -Encoding UTF8 -LiteralPath $MediaConfigFile |
        ConvertFrom-Json -ErrorAction Stop
    $names = @($document.PSObject.Properties.Name | Sort-Object)
    $expectedNames = @('ffmpeg_bin', 'ffmpeg_sha256', 'ffprobe_bin', 'ffprobe_sha256', 'schema')
    if (@(Compare-Object $names $expectedNames).Count -ne 0 -or
        [string]$document.schema -ne 'nachuan.media-binaries.v1') {
        throw 'media binary config schema is not the exact reviewed contract'
    }
    $ffmpegHash = ([string]$document.ffmpeg_sha256).Trim().ToLowerInvariant()
    $ffprobeHash = ([string]$document.ffprobe_sha256).Trim().ToLowerInvariant()
    $ffmpeg = Get-SafeMediaExecutable ([string]$document.ffmpeg_bin) $ffmpegHash 'ffmpeg.exe'
    $ffprobe = Get-SafeMediaExecutable ([string]$document.ffprobe_bin) $ffprobeHash 'ffprobe.exe'
    $ffmpegParent = [IO.Path]::GetDirectoryName($ffmpeg)
    if (-not [string]::Equals(
        $ffmpegParent,
        [IO.Path]::GetDirectoryName($ffprobe),
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw 'ffmpeg and ffprobe must share one closed static directory'
    }
    $allowed = @('ffmpeg.exe', 'ffplay.exe', 'ffprobe.exe')
    foreach ($entry in [IO.Directory]::EnumerateFileSystemEntries($ffmpegParent)) {
        $entryItem = Get-Item -LiteralPath $entry -Force -ErrorAction Stop
        if (-not ($entryItem -is [IO.FileInfo]) -or
            ($entryItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            $allowed -notcontains $entryItem.Name.ToLowerInvariant()) {
            throw 'media binary directory contains an unreviewed sidecar'
        }
    }
    $env:FFMPEG_BIN = $ffmpeg
    $env:FFMPEG_SHA256 = $ffmpegHash
    $env:FFPROBE_BIN = $ffprobe
    $env:FFPROBE_SHA256 = $ffprobeHash
}

function Write-AtomicJson([string]$Path, [object]$Payload) {
    Ensure-Directory ([IO.Path]::GetDirectoryName($Path))
    $tmp = "{0}.tmp.{1}.{2}" -f $Path, $PID, ([Guid]::NewGuid().ToString('N'))
    try {
        $Payload | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $tmp -Encoding UTF8
        Move-Item -LiteralPath $tmp -Destination $Path -Force
    } finally {
        if (Test-Path -LiteralPath $tmp) {
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        }
    }
}

function Get-PropertyValue([object]$Object, [string]$Name, [object]$Default = $null) {
    if ($null -eq $Object) { return $Default }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $Default }
    return $property.Value
}

function Get-StopState {
    if (-not (Test-Path -LiteralPath $SupervisorStopFile -PathType Leaf)) {
        return [pscustomobject][ordered]@{ active = $false; valid = $true; requested_at = '' }
    }
    try {
        $item = Get-Item -LiteralPath $SupervisorStopFile -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            $item.Length -le 0 -or $item.Length -gt 65536) {
            throw 'unsafe stop latch file'
        }
        $document = Get-Content -Raw -Encoding UTF8 -LiteralPath $SupervisorStopFile |
            ConvertFrom-Json -ErrorAction Stop
        $schema = [string](Get-PropertyValue $document 'schema' '')
        $latchRoot = [string](Get-PropertyValue $document 'root' '')
        $requestedAt = [string](Get-PropertyValue $document 'requested_at' '')
        $valid = $schema -eq 'nachuan.supervisor-stop.v1' -and
            [string]::Equals($latchRoot, $Root, [StringComparison]::OrdinalIgnoreCase) -and
            -not [string]::IsNullOrWhiteSpace($requestedAt)
        return [pscustomobject][ordered]@{
            active = $true
            valid = [bool]$valid
            requested_at = $requestedAt
        }
    } catch {
        # 存在但损坏的停机闩锁必须失败关闭，不能让计划任务借解析错误自动复活。
        return [pscustomobject][ordered]@{ active = $true; valid = $false; requested_at = '' }
    }
}

function Write-StopLatch {
    $payload = [ordered]@{
        schema = 'nachuan.supervisor-stop.v1'
        root = $Root
        requested_at = [DateTimeOffset]::UtcNow.ToString('o')
        requester_pid = $PID
    }
    Write-AtomicJson $SupervisorStopFile $payload
}

function Test-StopRequested {
    $state = Get-StopState
    return [bool]$state.active
}

function Get-SupervisorRecord {
    if (-not (Test-Path -LiteralPath $SupervisorPidFile -PathType Leaf)) { return $null }
    try {
        $item = Get-Item -LiteralPath $SupervisorPidFile -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            $item.Length -le 0 -or $item.Length -gt 65536) {
            return $null
        }
        $document = Get-Content -Raw -Encoding UTF8 -LiteralPath $SupervisorPidFile |
            ConvertFrom-Json -ErrorAction Stop
        if ([string](Get-PropertyValue $document 'schema' '') -ne 'nachuan.supervisor.v1') {
            return $null
        }
        $recordPid = 0
        $startedTicks = [long]0
        if (-not [int]::TryParse([string](Get-PropertyValue $document 'pid' ''), [ref]$recordPid) -or
            $recordPid -le 0 -or
            -not [long]::TryParse([string](Get-PropertyValue $document 'started_utc_ticks' ''), [ref]$startedTicks) -or
            $startedTicks -le 0) {
            return $null
        }
        $recordRoot = [string](Get-PropertyValue $document 'root' '')
        $recordScript = [string](Get-PropertyValue $document 'script_path' '')
        $instanceId = [string](Get-PropertyValue $document 'instance_id' '')
        $commandHash = [string](Get-PropertyValue $document 'command_line_sha256' '')
        $ignoredGuid = [Guid]::Empty
        if (-not [string]::Equals($recordRoot, $Root, [StringComparison]::OrdinalIgnoreCase) -or
            -not [string]::Equals($recordScript, $SupervisorScriptPath, [StringComparison]::OrdinalIgnoreCase) -or
            -not [Guid]::TryParse($instanceId, [ref]$ignoredGuid) -or
            $commandHash -notmatch '^[0-9a-f]{64}$') {
            return $null
        }
        return [pscustomobject][ordered]@{
            schema = 'nachuan.supervisor.v1'
            pid = $recordPid
            root = $recordRoot
            script_path = $recordScript
            instance_id = $instanceId
            started_utc_ticks = $startedTicks
            command_line_sha256 = $commandHash
        }
    } catch {
        return $null
    }
}

function Test-SupervisorRecordOwnership([object]$Record) {
    if ($null -eq $Record) { return $false }
    try {
        $process = Get-Process -Id ([int]$Record.pid) -ErrorAction Stop
        if (@('powershell', 'pwsh') -notcontains $process.ProcessName.ToLowerInvariant()) {
            return $false
        }
        if ($process.StartTime.ToUniversalTime().Ticks -ne [long]$Record.started_utc_ticks) {
            return $false
        }
        $cim = Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f [int]$Record.pid) -ErrorAction Stop
        $commandLine = [string]$cim.CommandLine
        if ([string]::IsNullOrWhiteSpace($commandLine) -or
            (Get-Sha256Hex $commandLine) -ne [string]$Record.command_line_sha256) {
            return $false
        }
        $low = $commandLine.ToLowerInvariant()
        $scriptUnderRoot = $SupervisorScriptPath.StartsWith(
            ($Root.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar),
            [StringComparison]::OrdinalIgnoreCase
        )
        if (-not $low.Contains($SupervisorScriptPath.ToLowerInvariant()) -or
            (-not $low.Contains($Root.ToLowerInvariant()) -and -not $scriptUnderRoot)) {
            return $false
        }
        return $true
    } catch {
        return $false
    }
}

function Write-SupervisorRecord([string]$InstanceId) {
    $cim = Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f $PID) -ErrorAction Stop
    $commandLine = [string]$cim.CommandLine
    if ([string]::IsNullOrWhiteSpace($commandLine)) {
        throw 'cannot bind supervisor identity: command line unavailable'
    }
    $process = Get-Process -Id $PID -ErrorAction Stop
    $payload = [ordered]@{
        schema = 'nachuan.supervisor.v1'
        pid = $PID
        root = $Root
        script_path = $SupervisorScriptPath
        instance_id = $InstanceId
        started_utc_ticks = $process.StartTime.ToUniversalTime().Ticks
        command_line_sha256 = Get-Sha256Hex $commandLine
        started_at = [DateTimeOffset]::UtcNow.ToString('o')
    }
    Write-AtomicJson $SupervisorPidFile $payload
}

function Ensure-GatewayKey {
    $configured = ([string]$env:GATEWAY_API_KEYS).Trim()
    if (-not [string]::IsNullOrWhiteSpace($configured) -and
        $configured -ne 'sk-local-dev-changeme') {
        return
    }

    $key = ''
    if (Test-Path -LiteralPath $GatewayKeyFile -PathType Leaf) {
        $item = Get-Item -LiteralPath $GatewayKeyFile -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'gateway key file must not be a reparse point'
        }
        $key = (Get-Content -Raw -Encoding UTF8 -LiteralPath $GatewayKeyFile).Trim()
    }
    if ($key -notmatch '^sk-local-[0-9a-f]{64}$') {
        [byte[]]$bytes = New-Object byte[] 32
        $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
        try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
        $key = 'sk-local-' + ([BitConverter]::ToString($bytes).Replace('-', '').ToLowerInvariant())
        $tmp = "$GatewayKeyFile.tmp.$PID"
        try {
            Set-Content -LiteralPath $tmp -Value $key -Encoding ASCII -NoNewline
            # Tighten the temporary inode before it ever becomes the canonical
            # secret file; inherited directory ACLs may be broader than intended.
            Protect-CurrentUserSecret $tmp
            Move-Item -LiteralPath $tmp -Destination $GatewayKeyFile -Force
        } finally {
            if (Test-Path -LiteralPath $tmp -PathType Leaf) {
                Remove-Item -LiteralPath $tmp -Force
            }
        }
    }
    # 新旧 key 都重新收紧 ACL，不能把历史宽权限默认为可信。
    Protect-CurrentUserSecret $GatewayKeyFile
    $env:GATEWAY_API_KEYS = $key
}

function Protect-CurrentUserSecret([string]$Path) {
    # Secret files never inherit a potentially broad data-directory ACL.
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $acl = New-Object Security.AccessControl.FileSecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($identity.User)
    $rule = New-Object Security.AccessControl.FileSystemAccessRule(
        $identity.User,
        [Security.AccessControl.FileSystemRights]::FullControl,
        [Security.AccessControl.AccessControlType]::Allow
    )
    $acl.AddAccessRule($rule)
    $secretFile = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($secretFile.PSIsContainer -or
        (($secretFile.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw 'secret ACL target must remain a regular non-reparse file'
    }
    $secretFile.SetAccessControl($acl)
}

function New-PrivateRuntimeAcl([bool]$Directory) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $systemSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    if ($Directory) {
        $acl = New-Object Security.AccessControl.DirectorySecurity
        $inheritance = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
        $propagation = [Security.AccessControl.PropagationFlags]::None
        foreach ($sid in @($identity.User, $systemSid)) {
            $rule = New-Object Security.AccessControl.FileSystemAccessRule(
                $sid,
                [Security.AccessControl.FileSystemRights]::FullControl,
                $inheritance,
                $propagation,
                [Security.AccessControl.AccessControlType]::Allow
            )
            [void]$acl.AddAccessRule($rule)
        }
    } else {
        $acl = New-Object Security.AccessControl.FileSecurity
        foreach ($sid in @($identity.User, $systemSid)) {
            $rule = New-Object Security.AccessControl.FileSystemAccessRule(
                $sid,
                [Security.AccessControl.FileSystemRights]::FullControl,
                [Security.AccessControl.AccessControlType]::Allow
            )
            [void]$acl.AddAccessRule($rule)
        }
    }
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($identity.User)
    return $acl
}

function Protect-PrivateRuntimeTree([string]$Path) {
    # Runtime state contains credentials, personal messages and delivery queues.
    # Refuse reparse points instead of traversing an attacker-controlled target.
    Assert-NoReparseComponents $Path
    $rootItem = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (-not $rootItem.PSIsContainer -or
        (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw 'runtime data directory must be a real directory, not a reparse point'
    }
    $pending = New-Object 'Collections.Generic.Stack[IO.DirectoryInfo]'
    $pending.Push([IO.DirectoryInfo]$rootItem)
    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        Assert-NoReparseComponents $directory.FullName
        $directory = Get-Item -LiteralPath $directory.FullName -Force -ErrorAction Stop
        if (-not $directory.PSIsContainer -or
            (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw 'runtime data directory changed during ACL hardening'
        }
        $directory.SetAccessControl((New-PrivateRuntimeAcl $true))
        foreach ($child in @(Get-ChildItem -LiteralPath $directory.FullName -Force -ErrorAction Stop)) {
            if (($child.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw ("runtime data tree contains forbidden reparse point: {0}" -f $child.FullName)
            }
            if ($child.PSIsContainer) {
                $pending.Push([IO.DirectoryInfo]$child)
            } else {
                $verifiedChild = Get-Item -LiteralPath $child.FullName -Force -ErrorAction Stop
                if ($verifiedChild.PSIsContainer -or
                    (($verifiedChild.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
                    throw 'runtime data file changed during ACL hardening'
                }
                $verifiedChild.SetAccessControl((New-PrivateRuntimeAcl $false))
            }
        }
    }
}

function Initialize-PrivateRuntimeTree {
    # Validate/ACL the data root before creating any child beneath it.  If data
    # is a junction, creating logs first would already modify the redirect
    # target before the later reparse check could fail closed.
    Ensure-Directory $DataDir
    Assert-NoReparseComponents $DataDir
    $dataItem = Get-Item -LiteralPath $DataDir -Force -ErrorAction Stop
    if (-not $dataItem.PSIsContainer -or
        (($dataItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw 'runtime data root must be a real directory'
    }
    Protect-PrivateRuntimeTree $DataDir
    Ensure-Directory $LogDir
    Assert-NoReparseComponents $LogDir
}

function Ensure-ApprovalAdminKey {
    $configured = ([string]$env:APPROVAL_ADMIN_KEY).Trim()
    $runtimeKeys = @(
        ([string]$env:GATEWAY_API_KEYS).Split(',') |
            ForEach-Object { $_.Trim() } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )
    if (-not [string]::IsNullOrWhiteSpace($configured)) {
        if ($runtimeKeys -contains $configured) {
            throw 'APPROVAL_ADMIN_KEY must be independent from GATEWAY_API_KEYS'
        }
        return
    }

    $key = ''
    if (Test-Path -LiteralPath $ApprovalKeyFile -PathType Leaf) {
        $item = Get-Item -LiteralPath $ApprovalKeyFile -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'approval key file must not be a reparse point'
        }
        $key = (Get-Content -Raw -Encoding UTF8 -LiteralPath $ApprovalKeyFile).Trim()
    }
    if ($key -notmatch '^sk-approval-[0-9a-f]{64}$') {
        [byte[]]$bytes = New-Object byte[] 32
        $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
        try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
        $key = 'sk-approval-' + ([BitConverter]::ToString($bytes).Replace('-', '').ToLowerInvariant())
        $tmp = "$ApprovalKeyFile.tmp.$PID"
        try {
            Set-Content -LiteralPath $tmp -Value $key -Encoding ASCII -NoNewline
            Protect-CurrentUserSecret $tmp
            Move-Item -LiteralPath $tmp -Destination $ApprovalKeyFile -Force
        } finally {
            if (Test-Path -LiteralPath $tmp -PathType Leaf) {
                Remove-Item -LiteralPath $tmp -Force
            }
        }
    }
    # Re-assert exact ACL on every boot, including an existing valid key file.
    Protect-CurrentUserSecret $ApprovalKeyFile
    if ($runtimeKeys -contains $key) {
        throw 'approval key file overlaps GATEWAY_API_KEYS; refusing to start'
    }
    $env:APPROVAL_ADMIN_KEY = $key
}

function New-CryptographicHex([int]$Bytes = 32) {
    if ($Bytes -lt 16 -or $Bytes -gt 64) { throw 'invalid random secret size' }
    [byte[]]$buffer = New-Object byte[] $Bytes
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($buffer) } finally { $rng.Dispose() }
    return ([BitConverter]::ToString($buffer)).Replace('-', '').ToLowerInvariant()
}

function Ensure-PaidMediaApiKey {
    # This capability is intentionally process-only.  The standalone
    # supervisor has no paid-media UI client, so persisting or publishing it
    # would only enlarge the financial trust boundary.  Keep one value stable
    # across engine restarts for this supervisor session, then let process exit
    # destroy it.
    $runtimeKeys = @(
        ([string]$env:GATEWAY_API_KEYS).Split(',') |
            ForEach-Object { $_.Trim() } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )
    $approvalKey = ([string]$env:APPROVAL_ADMIN_KEY).Trim()
    $reserved = @($runtimeKeys) + @($approvalKey)
    do {
        $key = 'sk-paid-media-' + (New-CryptographicHex 32)
    } while ($reserved -contains $key)
    [Environment]::SetEnvironmentVariable('NACHUAN_PAID_MEDIA_API_KEY', $key, 'Process')
}

function Ensure-ChannelBridgeKey(
    [string]$Path,
    [string]$Prefix,
    [string]$EnvironmentName
) {
    $key = ''
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $item.Length -gt 256) {
            throw 'channel bridge key file is unsafe'
        }
        $key = (Get-Content -Raw -Encoding UTF8 -LiteralPath $Path).Trim()
    }
    $pattern = '^{0}[0-9a-f]{{64}}$' -f [Regex]::Escape($Prefix)
    if ($key -notmatch $pattern) {
        $key = $Prefix + (New-CryptographicHex 32)
        $tmp = "$Path.tmp.$PID"
        try {
            Set-Content -LiteralPath $tmp -Value $key -Encoding ASCII -NoNewline
            Protect-CurrentUserSecret $tmp
            Move-Item -LiteralPath $tmp -Destination $Path -Force
        } finally {
            if (Test-Path -LiteralPath $tmp -PathType Leaf) {
                Remove-Item -LiteralPath $tmp -Force
            }
        }
    }
    Protect-CurrentUserSecret $Path
    [Environment]::SetEnvironmentVariable($EnvironmentName, $key, 'Process')
    return $key
}

function Ensure-ChannelBridgeKeys {
    # v2 intentionally invalidates every key used by the former plaintext
    # loopback Bearer protocol.  A key captured from a crashed/rebound engine
    # port must not remain capable of deriving the new HMAC/AES-GCM keys.
    $weixin = Ensure-ChannelBridgeKey $WeixinBridgeKeyFile 'sk-bridge-v2-weixin-' 'NACHUAN_WEIXIN_BRIDGE_API_KEY'
    $feishu = Ensure-ChannelBridgeKey $FeishuBridgeKeyFile 'sk-bridge-v2-feishu-' 'NACHUAN_FEISHU_BRIDGE_API_KEY'
    $reserved = @(
        ([string]$env:GATEWAY_API_KEYS).Split(',') |
            ForEach-Object { $_.Trim() } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    ) + @(([string]$env:APPROVAL_ADMIN_KEY).Trim())
    if ($weixin -eq $feishu -or $reserved -contains $weixin -or $reserved -contains $feishu) {
        throw 'channel bridge keys must be distinct from every other trust domain'
    }
}

function Ensure-EngineBootToken([switch]$Rotate) {
    $token = ''
    if (-not $Rotate -and (Test-Path -LiteralPath $EngineBootTokenFile -PathType Leaf)) {
        $item = Get-Item -LiteralPath $EngineBootTokenFile -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 -and $item.Length -le 128) {
            $token = (Get-Content -Raw -Encoding UTF8 -LiteralPath $EngineBootTokenFile).Trim()
        }
    }
    if ($token -notmatch '^[0-9a-f]{64}$') {
        $token = New-CryptographicHex 32
        $tmp = "$EngineBootTokenFile.tmp.$PID"
        try {
            Set-Content -LiteralPath $tmp -Value $token -Encoding ASCII -NoNewline
            Protect-CurrentUserSecret $tmp
            Move-Item -LiteralPath $tmp -Destination $EngineBootTokenFile -Force
        } finally {
            if (Test-Path -LiteralPath $tmp -PathType Leaf) {
                Remove-Item -LiteralPath $tmp -Force
            }
        }
    }
    Protect-CurrentUserSecret $EngineBootTokenFile
    $env:NACHUAN_ENGINE_BOOT_TOKEN = $token
    return $token
}

function Get-EngineBootToken {
    if (-not (Test-Path -LiteralPath $EngineBootTokenFile -PathType Leaf)) { return '' }
    try {
        $item = Get-Item -LiteralPath $EngineBootTokenFile -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $item.Length -gt 128) { return '' }
        $token = (Get-Content -Raw -Encoding UTF8 -LiteralPath $EngineBootTokenFile).Trim()
        if ($token -match '^[0-9a-f]{64}$') { return $token }
    } catch {
        return ''
    }
    return ''
}

function Rotate-Log([string]$Path, [long]$MaxBytes = 10485760, [int]$Keep = 3) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    if ((Get-Item -LiteralPath $Path).Length -lt $MaxBytes) { return }
    for ($i = $Keep - 1; $i -ge 1; $i--) {
        $src = "$Path.$i"
        $dst = "$Path.$($i + 1)"
        if (Test-Path -LiteralPath $src) { Move-Item -LiteralPath $src -Destination $dst -Force }
    }
    Move-Item -LiteralPath $Path -Destination "$Path.1" -Force
}

function Write-SupervisorLog([string]$Message) {
    Ensure-Directory $LogDir
    Rotate-Log $SupervisorLog
    $line = "{0} {1}" -f (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssK'), $Message
    Add-Content -LiteralPath $SupervisorLog -Value $line -Encoding UTF8
    if (-not $Json) { Write-Host $line }
}

function Get-MinimalPythonEnvironment {
    $result = @{}
    foreach ($name in @(
        'APPDATA','COMPUTERNAME','COMSPEC','HOMEDRIVE','HOMEPATH','LANG','LC_ALL',
        'LOCALAPPDATA','NUMBER_OF_PROCESSORS','PATHEXT','PROGRAMDATA','SYSTEMROOT',
        'TEMP','TMP','TZ','USERDOMAIN','USERNAME','USERPROFILE','WINDIR'
    )) {
        $value = [Environment]::GetEnvironmentVariable($name, 'Process')
        if (-not [string]::IsNullOrWhiteSpace($value)) { $result[$name] = $value }
    }
    $result['PATH'] = @(
        (Split-Path -Parent $Python),
        [Environment]::SystemDirectory,
        (Split-Path -Parent ([Environment]::SystemDirectory))
    ) -join ';'
    $trustedWindows = Split-Path -Parent ([Environment]::SystemDirectory)
    $result['SYSTEMROOT'] = $trustedWindows
    $result['WINDIR'] = $trustedWindows
    $result['COMSPEC'] = Join-Path ([Environment]::SystemDirectory) 'cmd.exe'
    $result['PATHEXT'] = '.COM;.EXE;.BAT;.CMD'
    $result['PYTHONUTF8'] = '1'
    $result['PYTHONIOENCODING'] = 'utf-8'
    $result['PYTHONUNBUFFERED'] = '1'
    return $result
}

function Set-CleanProcessEnvironment(
    [System.Diagnostics.ProcessStartInfo]$StartInfo,
    [hashtable]$Variables
) {
    $StartInfo.EnvironmentVariables.Clear()
    foreach ($name in $Variables.Keys) {
        $value = [string]$Variables[$name]
        if (-not [string]::IsNullOrWhiteSpace($name) -and $null -ne $value) {
            $StartInfo.EnvironmentVariables[[string]$name] = $value
        }
    }
}

function New-CleanPythonStartInfo(
    [string]$Arguments,
    [switch]$Redirect,
    [hashtable]$Environment = $null
) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Python
    # -I implies -E, so PYTHONUTF8/PYTHONIOENCODING in the closed environment
    # are intentionally ignored by CPython. Force UTF-8 on the command line
    # before isolation or a Chinese path can crash receipt output under cp1252.
    $psi.Arguments = '-X utf8 -I -S {0}' -f $Arguments
    $psi.WorkingDirectory = $Root
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = [bool]$Redirect
    $psi.RedirectStandardError = [bool]$Redirect
    if ($null -eq $Environment) { $Environment = Get-MinimalPythonEnvironment }
    Set-CleanProcessEnvironment $psi $Environment
    return $psi
}

function Get-ManagedServiceEnvironment([string]$Service) {
    $result = Get-MinimalPythonEnvironment
    $injection = @(
        'BASH_ENV','ENV','NODE_OPTIONS','NODE_PATH','PROMPT_COMMAND','PYTHONHOME',
        'PYTHONINSPECT','PYTHONPATH','PYTHONSTARTUP'
    )
    if ($Service -eq 'engine') {
        $engineAllowed = @(
            'ADMISSION_BACKGROUND_JOB_TTL_SEC','ADMISSION_BACKGROUND_JOBS_GLOBAL',
            'ADMISSION_BACKGROUND_JOBS_PER_KEY','ADMISSION_DAILY_EXPENSIVE_PER_KEY',
            'ADMISSION_MAX_CONCURRENCY_GLOBAL','ADMISSION_MAX_CONCURRENCY_PER_KEY',
            'ADMISSION_ROLLING_MINUTE_PER_KEY','AGENT_ALLOWED_TOOLS','AGENT_DAILY_CALL_CAP',
            'AGENT_EXEC_WORKDIR','AGENT_PERSONA','APPROVAL_ACTION_TTL_SEC',
            'APPROVAL_ADMIN_KEY','BACKUP_DIR','BACKUP_INTERVAL_SEC','CODEX_CLI_PATH','CODEX_CLI_SHA256',
            'CODEX_HOME','COMPRESS_ENABLED','COMPRESS_LONG_CHARS','COMPRESS_MIN_CHARS',
            'CONTENT_DENYLIST','FFMPEG_BIN','FFMPEG_SHA256','FFPROBE_BIN','FFPROBE_SHA256',
            'GATEWAY_API_KEYS','HOME','IMAGEHOST_BUCKET','LLAMA_SERVER_BIN','LLAMA_SERVER_DIR',
            'LLMLINGUA2_DIR','LLMLINGUA2_ONNX','LOCAL_LLAMA_CTX','LOCAL_LLAMA_PORT',
            'LOCAL_LLAMA_START_TIMEOUT','LOCAL_MODEL_DIR','LOCAL_MODEL_ID','LOCAL_MODEL_PATH',
            'LOCAL_MODEL_REVISION','LOCAL_MODEL_SHA256','NACHUAN_AGENT_WALL_MIN',
            'NACHUAN_CHANNEL_ATTEMPT_TIMEOUT','NACHUAN_CHANNEL_TOTAL_TIMEOUT',
            'NACHUAN_CONNECTION_HOST_ALLOWLIST','NACHUAN_COORDINATOR_BACKBONE_DIR',
            'NACHUAN_EMBED_DISABLED','NACHUAN_EMBED_MODEL','NACHUAN_ENABLE_VERIFIED_MODEL_DOWNLOAD',
            'NACHUAN_ENGINE_BOOT_TOKEN','NACHUAN_FAILOVER_ATTEMPT_TIMEOUT',
            'NACHUAN_FAILOVER_FIRST_CHUNK_TIMEOUT','NACHUAN_FAILOVER_IDLE_CHUNK_TIMEOUT',
            'NACHUAN_FAILOVER_STREAM_ATTEMPT_TIMEOUT','NACHUAN_FAILOVER_STREAM_TOTAL_TIMEOUT',
             'NACHUAN_FAILOVER_TOTAL_TIMEOUT',
             'NACHUAN_FEISHU_BRIDGE_API_KEY','NACHUAN_GUARD_HOME',
             'NACHUAN_LOCAL_RUNTIME_MANIFEST','NACHUAN_PAID_MEDIA_API_KEY',
             'NACHUAN_SUPABASE_HOST_ALLOWLIST','NACHUAN_TRINITY',
            'NACHUAN_WARM_AUDIO','NACHUAN_WEIXIN_BRIDGE_API_KEY','NEMOTRON_ASR',
            'NEMOTRON_ASR_DIR','NEMOTRON_ASR_THREADS','SAVERS_WARM','SEMCACHE_DB_DIR',
            'SEMCACHE_EMBED_DIR','SEMCACHE_ENABLED','SEMCACHE_THRESHOLD','SENSEVOICE_ASR',
            'SENSEVOICE_DIR','SENSEVOICE_THREADS','STUDIO_DOWNLOAD_TIMEOUT_SECONDS',
            'STUDIO_FFMPEG_TIMEOUT_SECONDS','STUDIO_FRAME_TIMEOUT_SECONDS','SYNC_INTERVAL_SEC',
            'SYNC_SERVER_URL','VOLCANO_API_KEY','VOLCANO_BASE_URL','WHISPER_MODEL',
            'WHISPER_MODEL_DIR'
        )
        foreach ($item in @(Get-ChildItem Env:)) {
            $upper = ([string]$item.Name).ToUpperInvariant()
            if ($injection -contains $upper -or
                $upper.StartsWith('FEISHU_') -or
                $upper.StartsWith('WEIXIN_') -or
                $upper.StartsWith('TELEGRAM_') -or
                $engineAllowed -notcontains $upper) { continue }
            $result[[string]$item.Name] = [string]$item.Value
        }
         $result['NACHUAN_ENGINE_BOOT_TOKEN'] = [string]$env:NACHUAN_ENGINE_BOOT_TOKEN
         # Desktop Engine Session authority trio: generation + listener port + boot token.
         # Inherited values never survive (both stay outside the allowlist above);
         # the supervisor signs a fresh monotonic generation per engine start, and a
         # new generation invalidates prior session receipts. Identity also binds pid/port.
         $script:EngineGenerationCounter = $script:EngineGenerationCounter + 1
         $result['NACHUAN_ENGINE_GENERATION'] = [string]$script:EngineGenerationCounter
         $result['NACHUAN_ENGINE_PORT'] = [string]$EnginePort
         $result['NACHUAN_PAID_MEDIA_API_KEY'] = [string]$env:NACHUAN_PAID_MEDIA_API_KEY
         $result['NACHUAN_WEIXIN_BRIDGE_API_KEY'] = [string]$env:NACHUAN_WEIXIN_BRIDGE_API_KEY
        $result['NACHUAN_FEISHU_BRIDGE_API_KEY'] = [string]$env:NACHUAN_FEISHU_BRIDGE_API_KEY
    } else {
        $prefix = $Service.ToUpperInvariant() + '_'
        foreach ($item in @(Get-ChildItem Env:)) {
            $upper = ([string]$item.Name).ToUpperInvariant()
            if (-not $upper.StartsWith($prefix) -or $injection -contains $upper -or
                $upper -eq ($prefix + 'ALLOW_ALL') -or
                $upper -eq ($prefix + 'ALLOWED') -or
                $upper -eq ($prefix + 'OWNER') -or
                $upper -eq 'FEISHU_ALLOWED_USERS' -or
                $upper -eq 'FEISHU_OWNER_OPEN_ID') { continue }
            $result[[string]$item.Name] = [string]$item.Value
        }
        $scopedName = 'NACHUAN_' + $Service.ToUpperInvariant() + '_BRIDGE_API_KEY'
        $result[$scopedName] = [Environment]::GetEnvironmentVariable($scopedName, 'Process')
    }
    $result['NACHUAN_ENV'] = 'production'
    $result['DATA_DIR'] = $DataDir
    $result['USAGE_DB_PATH'] = Join-Path $DataDir 'usage.db'
    if ($Service -eq 'engine') {
        $result['NACHUAN_PROVIDER_CALL_LEDGER_MODE'] = 'required'
        $result['NACHUAN_PROVIDER_CALL_LEDGER_PATH'] = Join-Path $DataDir 'provider-calls.db'
    }
    $result['BRIDGE_ENGINE_URL'] = 'http://127.0.0.1:{0}' -f $EnginePort
    $result['GATEWAY_HOST'] = '127.0.0.1'
    $result['GATEWAY_PORT'] = [string]$EnginePort
    $result['NO_PROXY'] = '127.0.0.1,localhost,::1'
    return $result
}

function Get-PythonProcessSnapshot {
    if (((Get-Date) - $script:ProcessSnapshotAt).TotalSeconds -lt 1) {
        return @($script:ProcessSnapshot)
    }
    $lastError = $null
    for ($attempt = 0; $attempt -lt 3; $attempt++) {
        try {
            $script:ProcessSnapshot = @(
                Get-CimInstance Win32_Process -Filter "Name='python.exe'" -ErrorAction Stop
            )
            $script:ProcessSnapshotAt = Get-Date
            return @($script:ProcessSnapshot)
        } catch {
            $lastError = $_
            if ($attempt -lt 2) {
                Start-Sleep -Milliseconds (100 * ($attempt + 1))
            }
        }
    }
    throw $lastError
}

function Clear-ProcessSnapshot {
    $script:ProcessSnapshot = @()
    $script:ProcessSnapshotAt = [datetime]::MinValue
}

function Get-ProjectProcesses([string[]]$Markers) {
    $rootNeedle = $Root.TrimEnd('\', '/').ToLowerInvariant()
    $rootPrefix = $rootNeedle + '\'
    $commandRootPattern = '(?i)(?:^|[\s"]){0}(?=$|[\\/"\s])' -f [Regex]::Escape($rootNeedle)
    @(Get-PythonProcessSnapshot | Where-Object {
        $cmd = [string]$_.CommandLine
        if ([string]::IsNullOrWhiteSpace($cmd)) { return $false }
        $low = $cmd.ToLowerInvariant()
        $executable = ([string]$_.ExecutablePath).ToLowerInvariant()
        $underRoot = $executable.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase) -or
            [Regex]::IsMatch($cmd, $commandRootPattern)
        if (-not $underRoot) { return $false }
        foreach ($marker in $Markers) {
            if ($low.Contains($marker.ToLowerInvariant())) { return $true }
        }
        return $false
    })
}

function Get-ManagedLauncherProcesses([string]$Service, [string]$Marker) {
    if ($Service -notin @('engine', 'weixin', 'feishu')) { return @() }
    $pythonPattern = [Regex]::Escape([IO.Path]::GetFullPath($Python))
    $launcherPattern = [Regex]::Escape($ManagedLauncherPath)
    $servicePattern = [Regex]::Escape($Service)
    $markerPattern = [Regex]::Escape($Marker)
    $portPattern = [Regex]::Escape([string]$EnginePort)
    $pattern = ('(?i)^"?{0}"?\s+-X\s+utf8\s+-I\s+-S\s+-u\s+"?{1}"?\s+{2}\s+{3}\s+{4}\s+[1-9][0-9]*\s+[1-9][0-9]*\s*$' -f `
        $pythonPattern, $launcherPattern, $servicePattern, $markerPattern, $portPattern)
    return @(Get-PythonProcessSnapshot | Where-Object {
        $cmd = [string]$_.CommandLine
        $exe = [string]$_.ExecutablePath
        -not [string]::IsNullOrWhiteSpace($cmd) -and
            -not [string]::IsNullOrWhiteSpace($exe) -and
            [string]::Equals([IO.Path]::GetFullPath($exe), [IO.Path]::GetFullPath($Python), [StringComparison]::OrdinalIgnoreCase) -and
            [Regex]::IsMatch($cmd, $pattern)
    })
}

function Test-ManagedPythonPid([long]$CandidatePid, [object[]]$Roots) {
    if ($CandidatePid -le 0 -or $null -eq $Roots -or @($Roots).Count -eq 0) {
        return $false
    }
    $rootIds = @{}
    foreach ($rootProcess in @($Roots)) {
        $rootIds[[long]$rootProcess.ProcessId] = $true
    }
    $byPid = @{}
    foreach ($process in @(Get-PythonProcessSnapshot)) {
        $byPid[[long]$process.ProcessId] = $process
    }
    $visited = @{}
    $cursor = [long]$CandidatePid
    for ($depth = 0; $depth -lt 32; $depth++) {
        if ($rootIds.ContainsKey($cursor)) { return $true }
        if ($visited.ContainsKey($cursor)) { return $false }
        $visited[$cursor] = $true
        $process = $byPid[$cursor]
        if ($null -eq $process) { return $false }
        $parent = [long]$process.ParentProcessId
        if ($parent -le 0 -or $parent -eq $cursor) { return $false }
        $cursor = $parent
    }
    return $false
}

function Get-HmacSha256Hex([string]$HexKey, [string]$Message) {
    if ($HexKey -notmatch '^[0-9a-f]{64}$') { throw 'invalid HMAC key' }
    [byte[]]$key = New-Object byte[] 32
    for ($i = 0; $i -lt 32; $i++) {
        $key[$i] = [Convert]::ToByte($HexKey.Substring($i * 2, 2), 16)
    }
    $hmac = New-Object Security.Cryptography.HMACSHA256 -ArgumentList (,$key)
    try {
        $digest = $hmac.ComputeHash([Text.Encoding]::ASCII.GetBytes($Message))
        return ([BitConverter]::ToString($digest)).Replace('-', '').ToLowerInvariant()
    } finally {
        $hmac.Dispose()
    }
}

function Test-FixedTimeHex([string]$Left, [string]$Right) {
    if ($Left.Length -ne 64 -or $Right.Length -ne 64) { return $false }
    $difference = 0
    for ($i = 0; $i -lt 64; $i++) {
        $difference = $difference -bor (([int][char]$Left[$i]) -bxor ([int][char]$Right[$i]))
    }
    return ($difference -eq 0)
}

function Get-EngineHealth {
    $processes = @(Get-ManagedLauncherProcesses 'engine' 'gateway.app')
    $processIds = @($processes | ForEach-Object { [int]$_.ProcessId })
    if ($processIds.Count -eq 0) {
        return [pscustomobject][ordered]@{
            ready = $false; alive = $false; attested = $false; restart_recommended = $true
            state = 'process_missing'; pid = 0; managed_pids = @(); managed_process_count = 0
        }
    }
    $bootToken = Get-EngineBootToken
    if ($bootToken -notmatch '^[0-9a-f]{64}$') {
        return [pscustomobject][ordered]@{
            ready = $false; alive = $true; attested = $false; restart_recommended = $true
            state = 'boot_token_missing'; pid = 0; managed_pids = $processIds; managed_process_count = $processIds.Count
        }
    }
    $challenge = New-CryptographicHex 32
    $expectedProof = Get-HmacSha256Hex $bootToken $challenge
    try {
        $uri = "http://127.0.0.1:{0}/health?challenge={1}" -f $EnginePort, $challenge
        $h = Invoke-RestMethod -Uri $uri -TimeoutSec 2
        if ([string](Get-PropertyValue $h 'status' '') -ne 'ok') {
            return [pscustomobject][ordered]@{
                ready = $false; alive = $true; attested = $false; restart_recommended = $true
                state = 'response_not_ok'; pid = 0; managed_pids = $processIds; managed_process_count = $processIds.Count
            }
        }
        $proof = ([string](Get-PropertyValue $h 'boot_proof' '')).Trim().ToLowerInvariant()
        if (-not (Test-FixedTimeHex $proof $expectedProof)) {
            return [pscustomobject][ordered]@{
                ready = $false; alive = $true; attested = $false; restart_recommended = $true
                state = 'attestation_mismatch'; pid = 0; managed_pids = $processIds; managed_process_count = $processIds.Count
            }
        }
        $healthPid = 0
        if (-not [int]::TryParse([string](Get-PropertyValue $h 'pid' ''), [ref]$healthPid) -or $healthPid -le 0) {
            return [pscustomobject][ordered]@{
                ready = $false; alive = $true; attested = $false; restart_recommended = $true
                state = 'identity_missing'; pid = 0; managed_pids = $processIds; managed_process_count = $processIds.Count
            }
        }
        if (-not (Test-ManagedPythonPid $healthPid $processes)) {
            return [pscustomobject][ordered]@{
                ready = $false; alive = $true; attested = $false; restart_recommended = $true
                state = 'identity_mismatch'; pid = $healthPid; managed_pids = $processIds; managed_process_count = $processIds.Count
            }
        }
        $boundProcessIds = @($processIds)
        if ($boundProcessIds -notcontains $healthPid) { $boundProcessIds += $healthPid }
        $readiness = [string](Get-PropertyValue $h 'readiness' '')
        $checks = Get-PropertyValue $h 'checks' $null
        $database = if ($null -ne $checks) { Get-PropertyValue $checks 'database' $null } else { $null }
        $financialLedger = if ($null -ne $checks) { Get-PropertyValue $checks 'financial_ledger' $null } else { $null }
        $providers = if ($null -ne $checks) { Get-PropertyValue $checks 'providers' $null } else { $null }
        $databaseReady = if ($null -ne $database) { Get-PropertyValue $database 'ready' $null } else { $null }
        $financialRequired = if ($null -ne $financialLedger) { Get-PropertyValue $financialLedger 'required' $null } else { $null }
        $financialReady = if ($null -ne $financialLedger) { Get-PropertyValue $financialLedger 'ready' $null } else { $null }
        $providersReady = if ($null -ne $providers) { Get-PropertyValue $providers 'ready' $null } else { $null }
        if ($readiness -notin @('ok', 'degraded') -or
            $databaseReady -isnot [bool] -or
            $financialRequired -isnot [bool] -or
            $financialReady -isnot [bool] -or
            $providersReady -isnot [bool]) {
            return [pscustomobject][ordered]@{
                ready = $false; alive = $true; attested = $true; restart_recommended = $true
                state = 'health_schema_invalid'; pid = $healthPid; managed_pids = $boundProcessIds; managed_process_count = $boundProcessIds.Count
            }
        }
        if (-not [bool]$databaseReady) {
            return [pscustomobject][ordered]@{
                ready = $false; alive = $true; attested = $true; restart_recommended = $true
                state = 'database_unready'; pid = $healthPid; managed_pids = $boundProcessIds; managed_process_count = $boundProcessIds.Count
            }
        }
        if (-not [bool]$financialRequired -or -not [bool]$financialReady) {
            return [pscustomobject][ordered]@{
                ready = $false; alive = $true; attested = $true; restart_recommended = $false
                state = 'financial_ledger_unready'; pid = $healthPid; managed_pids = $boundProcessIds; managed_process_count = $boundProcessIds.Count
            }
        }
        if ($readiness -ne 'ok') {
            return [pscustomobject][ordered]@{
                ready = $false; alive = $true; attested = $true; restart_recommended = $false
                state = 'engine_degraded'; pid = $healthPid; managed_pids = $boundProcessIds; managed_process_count = $boundProcessIds.Count
            }
        }
        if (-not [bool]$providersReady) {
            return [pscustomobject][ordered]@{
                ready = $false; alive = $true; attested = $true; restart_recommended = $false
                state = 'provider_unavailable'; pid = $healthPid; managed_pids = $boundProcessIds; managed_process_count = $boundProcessIds.Count
            }
        }
        return [pscustomobject][ordered]@{
            ready = $true; alive = $true; attested = $true; restart_recommended = $false
            state = 'ready'; pid = $healthPid; managed_pids = $boundProcessIds; managed_process_count = $boundProcessIds.Count
        }
    } catch {
        return [pscustomobject][ordered]@{
            ready = $false; alive = $true; attested = $false; restart_recommended = $true
            state = 'unreachable'; pid = 0; managed_pids = $processIds; managed_process_count = $processIds.Count
        }
    }
}

function Test-EngineReady {
    $health = Get-EngineHealth
    return [bool]$health.ready
}

function Get-NonNegativeHealthCount([object]$Health, [string]$Name) {
    $value = [long]0
    if (-not [long]::TryParse([string](Get-PropertyValue $Health $Name '0'), [ref]$value) -or
        $value -lt 0) {
        return [long]0
    }
    return $value
}

function Get-StrictFiniteNonNegativeHealthNumber([object]$Health, [string]$Name) {
    $raw = Get-PropertyValue $Health $Name $null
    if ($null -eq $raw -or $raw -is [bool] -or $raw -is [string]) {
        throw ("invalid finite non-negative health number: {0}" -f $Name)
    }
    $value = [double]0
    if (-not [double]::TryParse(
        [string]$raw,
        [Globalization.NumberStyles]::Float,
        [Globalization.CultureInfo]::InvariantCulture,
        [ref]$value
    ) -or [double]::IsNaN($value) -or [double]::IsInfinity($value) -or $value -lt 0) {
        throw ("invalid finite non-negative health number: {0}" -f $Name)
    }
    return $value
}

function Get-WeixinHealth {
    if (-not (Test-Path -LiteralPath $WeixinHealthFile -PathType Leaf)) {
        return [pscustomobject][ordered]@{
            fresh = $false; ready = $false; connected = $false; process_bound = $false
            age_sec = $null; state = 'missing'; pid = 0; fresh_until = 0
            pending_inbound = 0; pending_outbound = 0
            dead_inbound = 0; dead_outbound = 0
            oldest_processing_age_seconds = $null; processing_stuck = $false
            consecutive_poll_failures = 0; access_configured = $false
            bridge_key_configured = $false; engine_available = $false
            last_error_code = ''; reason = 'missing'
        }
    }
    try {
        $item = Get-Item -LiteralPath $WeixinHealthFile -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            $item.Length -le 0 -or $item.Length -gt 65536) {
            throw 'unsafe Weixin health file'
        }
        $h = Get-Content -Raw -Encoding UTF8 -LiteralPath $WeixinHealthFile |
            ConvertFrom-Json -ErrorAction Stop
        if ([string](Get-PropertyValue $h 'schema' '') -ne 'nachuan.weixin-bridge-health.v1') {
            throw 'invalid Weixin health schema'
        }
        $publishedReady = Get-PropertyValue $h 'ready' $null
        $connected = Get-PropertyValue $h 'connected' $null
        $publishedFresh = Get-PropertyValue $h 'fresh' $null
        $accessConfigured = Get-PropertyValue $h 'access_configured' $null
        $bridgeKeyConfigured = Get-PropertyValue $h 'bridge_key_configured' $null
        $engineAvailable = Get-PropertyValue $h 'engine_available' $null
        foreach ($value in @(
            $publishedReady, $connected, $publishedFresh, $accessConfigured,
            $bridgeKeyConfigured, $engineAvailable
        )) {
            if ($value -isnot [bool]) { throw 'Weixin readiness fields must be JSON booleans' }
        }
        $updatedAt = [double]0
        $freshUntil = [double]0
        $freshnessTtl = [double]0
        foreach ($pair in @(
            @('updated_at', [ref]$updatedAt),
            @('fresh_until', [ref]$freshUntil),
            @('freshness_ttl_seconds', [ref]$freshnessTtl)
        )) {
            if (-not [double]::TryParse(
                [string](Get-PropertyValue $h ([string]$pair[0]) ''),
                [Globalization.NumberStyles]::Float,
                [Globalization.CultureInfo]::InvariantCulture,
                $pair[1]
            )) {
                throw ("invalid Weixin health timestamp: {0}" -f $pair[0])
            }
        }
        $now = [double][DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() / 1000.0
        $declaredWindow = $freshUntil - $updatedAt
        $fresh = $updatedAt -gt 0 -and $updatedAt -le ($now + 5.0) -and
            $freshUntil -ge $now -and $freshnessTtl -ge 1.0 -and
            $freshnessTtl -le 60.0 -and $declaredWindow -ge 1.0 -and
            $declaredWindow -le 61.0 -and
            [math]::Abs($declaredWindow - $freshnessTtl) -le 1.0
        $age = [math]::Max(0, [long]($now - $updatedAt))
        $state = [string](Get-PropertyValue $h 'state' 'unknown')
        $healthPid = Get-StrictHealthCount $h 'pid'
        $pendingInbound = Get-StrictHealthCount $h 'pending_inbound'
        $pendingOutbound = Get-StrictHealthCount $h 'pending_outbound'
        $deadInbound = Get-StrictHealthCount $h 'dead_inbound'
        $deadOutbound = Get-StrictHealthCount $h 'dead_outbound'
        $pollFailures = Get-StrictHealthCount $h 'consecutive_poll_failures'
        $oldestProcessingAge = Get-StrictFiniteNonNegativeHealthNumber `
            $h 'oldest_processing_age_seconds'
        $processingStuck = [bool](
            $oldestProcessingAge -gt [double]$WeixinProcessingStuckThresholdSeconds
        )
        $lastErrorCode = [string](Get-PropertyValue $h 'last_error_code' '')
        if ($lastErrorCode -notmatch '^[A-Za-z0-9_.-]{0,64}$') {
            throw 'invalid Weixin health error code'
        }
        $reasons = New-Object Collections.Generic.List[string]
        if (-not $fresh) { $reasons.Add('stale') }
        if ($state -ne 'healthy') { $reasons.Add("state:$state") }
        if (-not [bool]$connected) { $reasons.Add('disconnected') }
        if (-not [bool]$publishedReady) { $reasons.Add('reported_not_ready') }
        if (-not [bool]$publishedFresh) { $reasons.Add('reported_not_fresh') }
        if (-not [bool]$accessConfigured) { $reasons.Add('access_locked') }
        if (-not [bool]$bridgeKeyConfigured) { $reasons.Add('bridge_key_missing') }
        if (-not [bool]$engineAvailable) { $reasons.Add('engine_unavailable') }
        if ($pendingInbound -gt 0) { $reasons.Add('pending_inbound') }
        if ($pendingOutbound -gt 0) { $reasons.Add('pending_outbound') }
        if ($deadInbound -gt 0) { $reasons.Add('dead_inbound') }
        if ($deadOutbound -gt 0) { $reasons.Add('dead_outbound') }
        if ($pollFailures -gt 0) { $reasons.Add('poll_failures') }
        if ($processingStuck) { $reasons.Add('processing_stuck') }
        return [pscustomobject][ordered]@{
            fresh = [bool]$fresh
            ready = [bool]($reasons.Count -eq 0)
            connected = [bool]$connected
            process_bound = $false
            age_sec = $age
            state = $state
            pid = $healthPid
            fresh_until = $freshUntil
            pending_inbound = $pendingInbound
            pending_outbound = $pendingOutbound
            dead_inbound = $deadInbound
            dead_outbound = $deadOutbound
            oldest_processing_age_seconds = $oldestProcessingAge
            processing_stuck = $processingStuck
            consecutive_poll_failures = $pollFailures
            access_configured = [bool]$accessConfigured
            bridge_key_configured = [bool]$bridgeKeyConfigured
            engine_available = [bool]$engineAvailable
            last_error_code = $lastErrorCode
            reason = ($reasons -join ',')
        }
    } catch {
        return [pscustomobject][ordered]@{
            fresh = $false; ready = $false; connected = $false; process_bound = $false
            age_sec = $null; state = 'invalid'; pid = 0; fresh_until = 0
            pending_inbound = 0; pending_outbound = 0
            dead_inbound = 0; dead_outbound = 0
            oldest_processing_age_seconds = $null; processing_stuck = $false
            consecutive_poll_failures = 0; access_configured = $false
            bridge_key_configured = $false; engine_available = $false
            last_error_code = ''; reason = 'invalid'
        }
    }
}

function Get-StrictHealthCount([object]$Health, [string]$Name) {
    $value = [long]0
    if (-not [long]::TryParse([string](Get-PropertyValue $Health $Name ''), [ref]$value) -or
        $value -lt 0) {
        throw ("invalid non-negative health count: {0}" -f $Name)
    }
    return $value
}

function Get-FeishuHealth {
    if (-not (Test-Path -LiteralPath $FeishuHealthFile -PathType Leaf)) {
        return [pscustomobject][ordered]@{
            fresh = $false; ready = $false; connected = $false; process_bound = $false
            age_sec = $null; state = 'missing'; pid = 0; fresh_until = 0
            pending_inbound = 0; pending_outbound = 0
            dead_inbound = 0; dead_outbound = 0
            consecutive_reconnect_failures = 0; access_configured = $false
            bridge_key_configured = $false; engine_available = $false
            last_error_code = ''; reason = 'missing'
        }
    }
    try {
        $item = Get-Item -LiteralPath $FeishuHealthFile -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            $item.Length -le 0 -or $item.Length -gt 65536) {
            throw 'unsafe Feishu health file'
        }
        $h = Get-Content -Raw -Encoding UTF8 -LiteralPath $FeishuHealthFile |
            ConvertFrom-Json -ErrorAction Stop
        if ([string](Get-PropertyValue $h 'schema' '') -ne 'nachuan.feishu-bridge-health.v1') {
            throw 'invalid Feishu health schema'
        }
        $publishedReady = Get-PropertyValue $h 'ready' $null
        $connected = Get-PropertyValue $h 'connected' $null
        $publishedFresh = Get-PropertyValue $h 'fresh' $null
        $accessConfigured = Get-PropertyValue $h 'access_configured' $null
        $bridgeKeyConfigured = Get-PropertyValue $h 'bridge_key_configured' $null
        $engineAvailable = Get-PropertyValue $h 'engine_available' $null
        foreach ($value in @(
            $publishedReady, $connected, $publishedFresh, $accessConfigured,
            $bridgeKeyConfigured, $engineAvailable
        )) {
            if ($value -isnot [bool]) { throw 'Feishu readiness fields must be JSON booleans' }
        }
        $updatedAt = [double]0
        $freshUntil = [double]0
        $freshnessTtl = [double]0
        foreach ($pair in @(
            @('updated_at', [ref]$updatedAt),
            @('fresh_until', [ref]$freshUntil),
            @('freshness_ttl_seconds', [ref]$freshnessTtl)
        )) {
            if (-not [double]::TryParse(
                [string](Get-PropertyValue $h ([string]$pair[0]) ''),
                [Globalization.NumberStyles]::Float,
                [Globalization.CultureInfo]::InvariantCulture,
                $pair[1]
            )) {
                throw ("invalid Feishu health timestamp: {0}" -f $pair[0])
            }
        }
        $now = [double][DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() / 1000.0
        $declaredWindow = $freshUntil - $updatedAt
        $fresh = $updatedAt -gt 0 -and $updatedAt -le ($now + 5.0) -and
            $freshUntil -ge $now -and $freshnessTtl -ge 1.0 -and
            $freshnessTtl -le 60.0 -and $declaredWindow -ge 1.0 -and
            $declaredWindow -le 61.0 -and
            [math]::Abs($declaredWindow - $freshnessTtl) -le 1.0
        $age = [math]::Max(0, [long]($now - $updatedAt))
        $state = [string](Get-PropertyValue $h 'state' 'unknown')
        $healthPid = Get-StrictHealthCount $h 'pid'
        $pendingInbound = Get-StrictHealthCount $h 'pending_inbound'
        $pendingOutbound = Get-StrictHealthCount $h 'pending_outbound'
        $deadInbound = Get-StrictHealthCount $h 'dead_inbound'
        $deadOutbound = Get-StrictHealthCount $h 'dead_outbound'
        $reconnectFailures = Get-StrictHealthCount $h 'consecutive_reconnect_failures'
        $lastErrorCode = [string](Get-PropertyValue $h 'last_error_code' '')
        if ($lastErrorCode -notmatch '^[A-Za-z0-9_.-]{0,64}$') {
            throw 'invalid Feishu health error code'
        }
        $reasons = New-Object Collections.Generic.List[string]
        if (-not $fresh) { $reasons.Add('stale') }
        if ($state -ne 'healthy') { $reasons.Add("state:$state") }
        if (-not [bool]$connected) { $reasons.Add('disconnected') }
        if (-not [bool]$publishedReady) { $reasons.Add('reported_not_ready') }
        if (-not [bool]$publishedFresh) { $reasons.Add('reported_not_fresh') }
        if (-not [bool]$accessConfigured) { $reasons.Add('access_locked') }
        if (-not [bool]$bridgeKeyConfigured) { $reasons.Add('bridge_key_missing') }
        if (-not [bool]$engineAvailable) { $reasons.Add('engine_unavailable') }
        if ($pendingInbound -gt 0) { $reasons.Add('pending_inbound') }
        if ($pendingOutbound -gt 0) { $reasons.Add('pending_outbound') }
        if ($deadInbound -gt 0) { $reasons.Add('dead_inbound') }
        if ($deadOutbound -gt 0) { $reasons.Add('dead_outbound') }
        if ($reconnectFailures -gt 0) { $reasons.Add('reconnect_failures') }
        return [pscustomobject][ordered]@{
            fresh = [bool]$fresh
            ready = [bool]($reasons.Count -eq 0)
            connected = [bool]$connected
            process_bound = $false
            age_sec = $age
            state = $state
            pid = [long]$healthPid
            fresh_until = $freshUntil
            pending_inbound = [long]$pendingInbound
            pending_outbound = [long]$pendingOutbound
            dead_inbound = [long]$deadInbound
            dead_outbound = [long]$deadOutbound
            consecutive_reconnect_failures = [long]$reconnectFailures
            access_configured = [bool]$accessConfigured
            bridge_key_configured = [bool]$bridgeKeyConfigured
            engine_available = [bool]$engineAvailable
            last_error_code = $lastErrorCode
            reason = ($reasons -join ',')
        }
    } catch {
        return [pscustomobject][ordered]@{
            fresh = $false; ready = $false; connected = $false; process_bound = $false
            age_sec = $null; state = 'invalid'; pid = 0; fresh_until = 0
            pending_inbound = 0; pending_outbound = 0
            dead_inbound = 0; dead_outbound = 0
            consecutive_reconnect_failures = 0; access_configured = $false
            bridge_key_configured = $false; engine_available = $false
            last_error_code = ''; reason = 'invalid'
        }
    }
}

function Test-WeixinConfigured {
    if (-not (Test-Path -LiteralPath $script:WeixinTokenFile -PathType Leaf)) {
        return $false
    }
    try {
        $item = Get-Item -LiteralPath $script:WeixinTokenFile -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            $item.Length -le 0 -or $item.Length -gt 4194304) {
            return $false
        }
        $document = Get-Content -Raw -Encoding UTF8 -LiteralPath $script:WeixinTokenFile |
            ConvertFrom-Json -ErrorAction Stop
        if ($null -eq $document) { return $false }

        $schema = $document.PSObject.Properties['schema']
        $protection = $document.PSObject.Properties['protection']
        $ciphertext = $document.PSObject.Properties['ciphertext']
        $hasEnvelopeField = ($null -ne $schema) -or ($null -ne $protection) -or ($null -ne $ciphertext)
        if ($hasEnvelopeField) {
            if ($null -eq $schema -or $null -eq $protection -or $null -eq $ciphertext) {
                return $false
            }
            if ([string]$schema.Value -ne 'nachuan.protected-json.v1' -or
                [string]$protection.Value -ne 'windows-dpapi-current-user' -or
                $ciphertext.Value -isnot [string] -or
                [string]::IsNullOrWhiteSpace([string]$ciphertext.Value)) {
                return $false
            }
            try {
                # 这里只验证安全信封结构；真正的当前用户 DPAPI 解密由桥启动时失败关闭。
                $decoded = [Convert]::FromBase64String([string]$ciphertext.Value)
                return ($decoded.Length -ge 16)
            } catch {
                return $false
            }
        }

        $legacyToken = $document.PSObject.Properties['bot_token']
        return ($null -ne $legacyToken -and
                $legacyToken.Value -is [string] -and
                -not [string]::IsNullOrWhiteSpace([string]$legacyToken.Value) -and
                ([string]$legacyToken.Value).Length -le 65536)
    } catch {
        return $false
    }
}

function Test-VerifiedBackupSnapshot([IO.DirectoryInfo]$Candidate) {
    $scriptPath = Join-Path $Root 'scripts\sqlite_backup.py'
    if (-not (Test-Path -LiteralPath $Python -PathType Leaf) -or
        -not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
        return $null
    }

    Assert-NoReparseComponents $scriptPath
    $psi = New-CleanPythonStartInfo ('-u "{0}" verify "{1}"' -f $scriptPath, $Candidate.FullName) -Redirect
    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi
    try {
        if (-not $proc.Start()) { return $null }
        $outTask = $proc.StandardOutput.ReadToEndAsync()
        $errTask = $proc.StandardError.ReadToEndAsync()
        if (-not $proc.WaitForExit(120000)) {
            [void](Invoke-BoundedTaskkill ([long]$proc.Id))
            [void]$proc.WaitForExit(10000)
            return $null
        }
        $proc.WaitForExit()
        [void]$outTask.Wait(10000)
        [void]$errTask.Wait(10000)
        if ($proc.ExitCode -ne 0 -or [string]::IsNullOrWhiteSpace($outTask.Result)) {
            return $null
        }
        return ($outTask.Result | ConvertFrom-Json -ErrorAction Stop)
    } catch {
        return $null
    } finally {
        $proc.Dispose()
    }
}

function Get-BackupHealth {
    if (-not (Test-Path -LiteralPath $BackupRoot -PathType Container)) {
        return [pscustomobject]@{ available = $false; verified = $false; state = 'missing'; age_sec = $null; snapshot = ''; database_count = 0 }
    }
    $candidates = @(Get-ChildItem -LiteralPath $BackupRoot -Directory -ErrorAction Stop |
        Where-Object {
            -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -and
            $_.Name -match '^snapshot-\d{8}T\d{6}\.\d{6}Z-[0-9a-f]{8}$' -and
            (Test-Path -LiteralPath (Join-Path $_.FullName 'manifest.json') -PathType Leaf)
        } |
        Sort-Object Name -Descending |
        Select-Object -First 1)
    $sawCandidate = ($candidates.Count -gt 0)
    foreach ($candidate in $candidates) {
        $validation = Test-VerifiedBackupSnapshot $candidate
        if ($null -eq $validation -or
            [string]$validation.status -ne 'verified' -or
            [string]$validation.snapshot_id -ne $candidate.Name -or
            [int]$validation.database_count -le 0) {
            continue
        }
        try {
            $createdAt = [DateTimeOffset]::Parse([string]$validation.created_at).ToUniversalTime()
        } catch {
            continue
        }
        $now = [DateTimeOffset]::UtcNow
        if ($createdAt -gt $now.AddMinutes(5)) { continue }
        $age = [math]::Max(0, [long]($now - $createdAt).TotalSeconds)
        return [pscustomobject]@{
            available = $true
            verified = $true
            state = 'verified'
            age_sec = $age
            snapshot = $candidate.Name
            database_count = [int]$validation.database_count
        }
    }
    return [pscustomobject]@{
        available = $false
        verified = $false
        state = $(if ($sawCandidate) { 'invalid' } else { 'missing' })
        age_sec = $null
        snapshot = ''
        database_count = 0
    }
}

function Invoke-BackupIfDue {
    $health = Get-BackupHealth
    if ($health.available -and $health.age_sec -lt [math]::Max(300, $BackupIntervalSeconds)) {
        return $true
    }
    $scriptPath = Join-Path $Root 'scripts\sqlite_backup.py'
    if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
        Write-SupervisorLog 'sqlite backup tool is missing'
        return $false
    }
    Ensure-Directory $BackupRoot
    $stdout = Join-Path $LogDir 'backup.out.log'
    $stderr = Join-Path $LogDir 'backup.err.log'
    Rotate-Log $stdout
    Rotate-Log $stderr
    # Windows PowerShell 5.1 的 Start-Process + Redirect + 手动 WaitForExit 会丢 ExitCode。
    # 直接用 .NET Process 保留有界等待、输出和真实退出码，避免成功/失败都假绿。
    Assert-NoReparseComponents $scriptPath
    $exitCode = 1
    for ($attempt = 1; $attempt -le 2; $attempt++) {
        $psi = New-CleanPythonStartInfo ('-u "{0}" backup --data-dir "{1}" --backup-root "{2}" --keep 14' -f $scriptPath, $DataDir, $BackupRoot) -Redirect
        $proc = New-Object System.Diagnostics.Process
        $proc.StartInfo = $psi
        try {
            if (-not $proc.Start()) { throw 'failed to start sqlite backup process' }
            $outTask = $proc.StandardOutput.ReadToEndAsync()
            $errTask = $proc.StandardError.ReadToEndAsync()
            if (-not $proc.WaitForExit(300000)) {
                [void](Invoke-BoundedTaskkill ([long]$proc.Id))
                [void]$proc.WaitForExit(10000)
                Write-SupervisorLog 'sqlite backup exceeded 300 seconds and was stopped'
                return $false
            }
            $proc.WaitForExit()
            [void]$outTask.Wait(10000)
            [void]$errTask.Wait(10000)
            if ($outTask.Result) { Add-Content -LiteralPath $stdout -Value $outTask.Result -Encoding UTF8 }
            if ($errTask.Result) { Add-Content -LiteralPath $stderr -Value $errTask.Result -Encoding UTF8 }
            $exitCode = $proc.ExitCode
        } finally {
            $proc.Dispose()
        }
        if ($exitCode -eq 0) { break }
        if ($attempt -eq 1) {
            Write-SupervisorLog 'sqlite backup first attempt failed; retrying once after source-set convergence'
            Start-Sleep -Milliseconds 250
        }
    }
    if ($exitCode -ne 0) {
        Write-SupervisorLog ("sqlite backup failed exit={0}; see backup.err.log" -f $exitCode)
        return $false
    }
    Write-SupervisorLog 'sqlite backup completed and verified'
    return $true
}

function Test-FeishuConfigured {
    return (-not [string]::IsNullOrWhiteSpace($env:FEISHU_APP_ID)) -and
           (-not [string]::IsNullOrWhiteSpace($env:FEISHU_APP_SECRET))
}

function Get-RuntimeState([switch]$Plan) {
    $engineProc = @(Get-ManagedLauncherProcesses 'engine' 'gateway.app')
    $weixinProc = @(Get-ManagedLauncherProcesses 'weixin' 'run_weixin_ilink_bridge.py')
    $feishuProc = @(Get-ManagedLauncherProcesses 'feishu' 'run_feishu_bridge.py')
    $engineHealth = Get-EngineHealth
    $engineReady = [bool]$engineHealth.ready
    [bool]$weixinConfigured = Test-WeixinConfigured
    $feishuConfigured = Test-FeishuConfigured
    $weixinHealth = Get-WeixinHealth
    $feishuHealth = Get-FeishuHealth
    $weixinPidBound = $false
    if ($weixinHealth.pid -gt 0) {
        $weixinPidBound = Test-ManagedPythonPid ([long]$weixinHealth.pid) $weixinProc
    }
    $weixinHealth.process_bound = [bool]$weixinPidBound
    if (-not $weixinPidBound) {
        $weixinHealth.ready = $false
        $weixinHealth.reason = $(
            if ([string]::IsNullOrWhiteSpace([string]$weixinHealth.reason)) {
                'process_unbound'
            } elseif (-not ([string]$weixinHealth.reason).Contains('process_unbound')) {
                '{0},process_unbound' -f $weixinHealth.reason
            } else {
                [string]$weixinHealth.reason
            }
        )
    }
    $feishuPidBound = $false
    if ($feishuHealth.pid -gt 0) {
        $feishuPidBound = Test-ManagedPythonPid ([long]$feishuHealth.pid) $feishuProc
    }
    $feishuHealth.process_bound = [bool]$feishuPidBound
    if (-not $feishuPidBound) {
        $feishuHealth.ready = $false
        $feishuHealth.reason = $(
            if ([string]::IsNullOrWhiteSpace([string]$feishuHealth.reason)) {
                'process_unbound'
            } elseif (-not ([string]$feishuHealth.reason).Contains('process_unbound')) {
                '{0},process_unbound' -f $feishuHealth.reason
            } else {
                [string]$feishuHealth.reason
            }
        )
    }
    $stopState = Get-StopState

    $services = @(
        [pscustomobject][ordered]@{
            name = 'engine'
            configured = $true
            running = [bool]($engineProc.Count -gt 0)
            ready = $engineReady
            action = $(
                if ($Plan -and $stopState.active) { 'blocked-suspended' }
                elseif ($Plan -and $engineProc.Count -eq 0) { 'would-start' }
                elseif ($Plan -and -not $engineReady) { 'would-restart' }
                else { 'none' }
            )
        },
        [pscustomobject][ordered]@{
            name = 'weixin'
            configured = $weixinConfigured
            running = [bool]($weixinProc.Count -gt 0)
            ready = [bool]($engineReady -and $weixinConfigured -and $weixinHealth.ready)
            action = $(
                if ($Plan -and $stopState.active) { 'blocked-suspended' }
                elseif ($Plan -and $weixinConfigured -and $weixinProc.Count -eq 0) { 'would-start' }
                elseif ($Plan -and $weixinConfigured -and -not $weixinHealth.ready) { 'degraded' }
                else { 'none' }
            )
        },
        [pscustomobject][ordered]@{
            name = 'feishu'
            configured = [bool]$feishuConfigured
            running = [bool]($feishuProc.Count -gt 0)
            ready = [bool]($engineReady -and $feishuConfigured -and $feishuHealth.ready)
            action = $(
                if ($Plan -and $stopState.active) { 'blocked-suspended' }
                elseif ($Plan -and $feishuConfigured -and $feishuProc.Count -eq 0) { 'would-start' }
                elseif ($Plan -and $feishuConfigured -and -not $feishuHealth.ready) { 'degraded' }
                else { 'none' }
            )
        }
    )

    return [pscustomobject][ordered]@{
        root = $Root
        dry_run = [bool]$DryRun
        scheduled = [bool]$Scheduled
        supervisor = [pscustomobject][ordered]@{
            suspended = [bool]$stopState.active
            stop_latch_valid = [bool]$stopState.valid
            stop_requested_at = [string]$stopState.requested_at
        }
        services = $services
        engine_health = $engineHealth
        weixin_health = $weixinHealth
        feishu_health = $feishuHealth
        backup = Get-BackupHealth
        log_dir = $LogDir
    }
}

function Start-ManagedProcess([string]$Name) {
    Assert-TrustedRegularFile $Python 'managed Python' -AllowReparseAncestors:(-not $Scheduled)
    Assert-TrustedRegularFile $ManagedLauncherPath 'managed launcher' -AllowReparseAncestors:(-not $Scheduled)
    $now = [DateTimeOffset]::UtcNow
    if ($now -lt [DateTimeOffset]$script:NextStartAt[$Name]) {
        Write-SupervisorLog ("deferred {0} restart until {1:o}" -f $Name, $script:NextStartAt[$Name])
        return $false
    }
    $marker = switch ($Name) {
        'engine' { 'gateway.app' }
        'weixin' { 'run_weixin_ilink_bridge.py' }
        'feishu' { 'run_feishu_bridge.py' }
        default { throw 'unsupported managed service' }
    }
    Ensure-Directory $LogDir
    $stdout = Join-Path $LogDir "$Name.out.log"
    $stderr = Join-Path $LogDir "$Name.err.log"
    Rotate-Log $stdout
    Rotate-Log $stderr
    $environment = Get-ManagedServiceEnvironment $Name
    $supervisorProcess = Get-Process -Id $PID -ErrorAction Stop
    $parentFileTime = $supervisorProcess.StartTime.ToUniversalTime().ToFileTimeUtc()
    $arguments = '-u "{0}" {1} {2} {3} {4} {5}' -f `
        $ManagedLauncherPath, $Name, $marker, $EnginePort, $PID, $parentFileTime
    $psi = New-CleanPythonStartInfo $arguments -Environment $environment
    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi
    if (-not $proc.Start()) {
        $proc.Dispose()
        throw "failed to start managed service: $Name"
    }
    $startedPid = $proc.Id
    $proc.Dispose()
    $script:StartedAt[$Name] = $now
    $script:StartAttempt[$Name] = [math]::Min(9, [int]$script:StartAttempt[$Name] + 1)
    $delay = [math]::Min(300, [math]::Pow(2, [int]$script:StartAttempt[$Name]))
    $script:NextStartAt[$Name] = $now.AddSeconds($delay)
    Clear-ProcessSnapshot
    Write-SupervisorLog ("started {0} wrapper pid={1}; retry floor={2}s" -f $Name, $startedPid, $delay)
    return $true
}

function Stop-ProjectProcesses([string[]]$Markers, [string]$Name) {
    $marker = switch ($Name) {
        'engine' { 'gateway.app' }
        'weixin' { 'run_weixin_ilink_bridge.py' }
        'feishu' { 'run_feishu_bridge.py' }
        default { throw 'unsupported managed service' }
    }
    $procs = @(Get-ManagedLauncherProcesses $Name $marker)
    foreach ($proc in $procs) {
        if ($DryRun) {
            if (-not $Json) { Write-Host ("would stop {0} pid={1}" -f $Name, $proc.ProcessId) }
        } else {
            $targetPid = [long]$proc.ProcessId
            $stopped = $false
            for ($attempt = 0; $attempt -lt 2 -and -not $stopped; $attempt++) {
                [void](Invoke-BoundedTaskkill $targetPid)
                $deadline = [DateTimeOffset]::UtcNow.AddSeconds(10)
                do {
                    Start-Sleep -Milliseconds 100
                    Clear-ProcessSnapshot
                    $stillBound = @(
                        Get-ManagedLauncherProcesses $Name $marker |
                            Where-Object { [long]$_.ProcessId -eq $targetPid }
                    )
                    if ($stillBound.Count -eq 0) {
                        $stopped = $true
                        break
                    }
                } while ([DateTimeOffset]::UtcNow -lt $deadline)
            }
            if (-not $stopped) {
                throw "failed to stop $Name process tree pid=$targetPid"
            }
            Write-SupervisorLog ("stopped {0} pid={1}" -f $Name, $targetPid)
        }
    }
    if (-not $DryRun) { Clear-ProcessSnapshot }
}

function Invoke-WeixinWatchdog([object[]]$WeixinProc) {
    if (-not (Test-WeixinConfigured)) { return }
    $managedProcesses = @($WeixinProc)
    $health = Get-WeixinHealth
    $healthPidBound = $false
    if ($health.pid -gt 0) {
        $healthPidBound = Test-ManagedPythonPid ([long]$health.pid) $managedProcesses
    }
    if ($managedProcesses.Count -eq 0) {
        [void](Start-ManagedProcess 'weixin')
        $script:Unhealthy.weixin = 0
    } elseif (-not $health.fresh -or -not $healthPidBound) {
        $script:Unhealthy.weixin += 1
        Write-SupervisorLog ("weixin liveness/identity failed ({0}/{1}, state={2}, bound={3})" -f $script:Unhealthy.weixin, $UnhealthyThreshold, $health.state, $healthPidBound)
        if ($script:Unhealthy.weixin -ge $UnhealthyThreshold) {
            Stop-ProjectProcesses @('run_weixin_ilink_bridge.py') 'weixin'
            $script:Unhealthy.weixin = 0
            [void](Start-ManagedProcess 'weixin')
        }
    } elseif ([bool]$health.processing_stuck) {
        Write-SupervisorLog ("weixin processing claim exceeded recovery threshold: {0}s" -f $health.oldest_processing_age_seconds)
        Stop-ProjectProcesses @('run_weixin_ilink_bridge.py') 'weixin'
        $script:Unhealthy.weixin = 0
        [void](Start-ManagedProcess 'weixin')
    } elseif (-not $health.ready) {
        $script:Unhealthy.weixin = 0
        Write-SupervisorLog ("weixin is alive but not ready: {0}" -f $health.reason)
        if ($health.consecutive_poll_failures -ge [math]::Max(1, $UnhealthyThreshold)) {
            Stop-ProjectProcesses @('run_weixin_ilink_bridge.py') 'weixin'
            [void](Start-ManagedProcess 'weixin')
        }
    } else {
        $script:Unhealthy.weixin = 0
        $script:StartAttempt.weixin = 0
        $script:NextStartAt.weixin = [DateTimeOffset]::MinValue
    }
}

function Invoke-WatchdogCycle {
    $engineHealth = Get-EngineHealth
    $engineProc = @(Get-ManagedLauncherProcesses 'engine' 'gateway.app')
    if ($engineHealth.ready) {
        $script:Unhealthy.engine = 0
        $script:StartAttempt.engine = 0
        $script:NextStartAt.engine = [DateTimeOffset]::MinValue
    } elseif ($engineProc.Count -gt 0) {
        if ($engineHealth.restart_recommended) {
            $script:Unhealthy.engine += 1
            Write-SupervisorLog ("engine health failed ({0}/{1}, state={2})" -f $script:Unhealthy.engine, $UnhealthyThreshold, $engineHealth.state)
            if ($script:Unhealthy.engine -ge $UnhealthyThreshold) {
                Stop-ProjectProcesses @('gateway.app') 'engine'
                $script:Unhealthy.engine = 0
                [void](Start-ManagedProcess 'engine')
            }
        } else {
            $script:Unhealthy.engine = 0
            Write-SupervisorLog ("engine is attested but degraded without restart: {0}" -f $engineHealth.state)
        }
    } else {
        [void](Start-ManagedProcess 'engine')
    }

    $weixinProc = @(Get-ManagedLauncherProcesses 'weixin' 'run_weixin_ilink_bridge.py')
    $feishuProc = @(Get-ManagedLauncherProcesses 'feishu' 'run_feishu_bridge.py')
    if (-not $engineHealth.attested) {
        if ($weixinProc.Count -gt 0) { Stop-ProjectProcesses @('run_weixin_ilink_bridge.py') 'weixin' }
        if ($feishuProc.Count -gt 0) { Stop-ProjectProcesses @('run_feishu_bridge.py') 'feishu' }
        $backupOk = Invoke-BackupIfDue
        if (-not $backupOk -and $Once) { throw 'sqlite backup failed during one-shot validation' }
        return
    }
    # A configured durable channel must stay reachable when the authenticated
    # core is healthy but no model provider has been connected yet.  The bridge
    # can then return the local model-connection guidance instead of silently
    # disappearing.  Every other non-ready state (boot/auth attestation,
    # database, financial ledger, schema or transport failure) remains closed.
    $channelEngineUsable = [bool](
        $engineHealth.attested -and
        ($engineHealth.ready -or [string]$engineHealth.state -eq 'provider_unavailable')
    )
    if (-not $channelEngineUsable) {
        Write-SupervisorLog ("channel start/restart deferred until engine is ready: {0}" -f $engineHealth.state)
        $backupOk = Invoke-BackupIfDue
        if (-not $backupOk -and $Once) { throw 'sqlite backup failed during one-shot validation' }
        return
    }
    if ([string]$engineHealth.state -eq 'provider_unavailable') {
        Write-SupervisorLog 'channel runtime allowed while providers are unavailable; overall readiness remains degraded'
    }

    Invoke-WeixinWatchdog $weixinProc

    if (Test-FeishuConfigured) {
        $health = Get-FeishuHealth
        $feishuStarting = [bool](
            $feishuProc.Count -gt 0 -and
            [DateTimeOffset]$script:StartedAt.feishu -ne [DateTimeOffset]::MinValue -and
            ([DateTimeOffset]::UtcNow - [DateTimeOffset]$script:StartedAt.feishu).TotalSeconds -lt
                $FeishuStartupGraceSeconds
        )
        $healthPidBound = $false
        if ($health.pid -gt 0) {
            $healthPidBound = Test-ManagedPythonPid ([long]$health.pid) $feishuProc
        }
        if ($feishuProc.Count -eq 0) {
            [void](Start-ManagedProcess 'feishu')
            $script:Unhealthy.feishu = 0
        } elseif ($feishuStarting) {
            $script:Unhealthy.feishu = 0
        } elseif (-not $health.fresh -or -not $healthPidBound -or
            -not $health.connected -or $health.consecutive_reconnect_failures -gt 0) {
            $script:Unhealthy.feishu += 1
            Write-SupervisorLog ("feishu liveness/connection failed ({0}/{1}, state={2}, bound={3}, connected={4})" -f $script:Unhealthy.feishu, $UnhealthyThreshold, $health.state, $healthPidBound, $health.connected)
            if ($script:Unhealthy.feishu -ge $UnhealthyThreshold) {
                Stop-ProjectProcesses @('run_feishu_bridge.py') 'feishu'
                $script:Unhealthy.feishu = 0
                [void](Start-ManagedProcess 'feishu')
            }
        } elseif (-not $health.ready) {
            $script:Unhealthy.feishu = 0
            Write-SupervisorLog ("feishu is connected but not ready: {0}" -f $health.reason)
        } else {
            $script:Unhealthy.feishu = 0
            $script:StartAttempt.feishu = 0
            $script:NextStartAt.feishu = [DateTimeOffset]::MinValue
            $script:StartedAt.feishu = [DateTimeOffset]::MinValue
        }
    }
    $backupOk = Invoke-BackupIfDue
    if (-not $backupOk -and $Once) {
        throw 'sqlite backup failed during one-shot validation'
    }
}

function Emit([object]$Payload) {
    if ($Json) {
        $Payload | ConvertTo-Json -Depth 6 -Compress
    } else {
        $Payload.services | Format-Table name, configured, running, ready, action -AutoSize
        if ($Payload.supervisor.suspended) {
            Write-Host 'supervisor: suspended (use -Action Resume to start explicitly)'
        }
        Write-Host ("logs: {0}" -f $Payload.log_dir)
    }
}

if ($Action -eq 'Validate') {
    Configure-MediaBinaries
    Emit ([pscustomobject][ordered]@{
        root = $Root
        python = [bool](Test-Path -LiteralPath $Python -PathType Leaf)
        media = [pscustomobject][ordered]@{
            configured = -not [string]::IsNullOrWhiteSpace([string]$env:FFMPEG_BIN)
            ffmpeg_sha256 = [string]$env:FFMPEG_SHA256
            ffprobe_sha256 = [string]$env:FFPROBE_SHA256
        }
    })
    exit 0
}

if ($Action -eq 'InstallTask') {
    [Console]::Error.WriteLine(
        'InstallTask is disabled for source-tree launches. Use the signed installer and a protected install directory.'
    )
    exit 78
}

if ($Action -eq 'Status') {
    Emit (Get-RuntimeState)
    exit 0
}

if ($Action -eq 'Stop') {
    if (-not $DryRun) {
        Initialize-PrivateRuntimeTree
        Write-StopLatch
        Write-SupervisorLog 'persistent stop latch written; scheduled restarts are suppressed'
    }
    $record = Get-SupervisorRecord
    $ownedSupervisor = Test-SupervisorRecordOwnership $record
    if ($null -ne $record -and $ownedSupervisor -and [int]$record.pid -ne $PID) {
        if ($DryRun) {
            if (-not $Json) { Write-Host ("would request graceful supervisor stop pid={0}" -f $record.pid) }
        } else {
            $deadline = [DateTimeOffset]::UtcNow.AddSeconds(20)
            while ([DateTimeOffset]::UtcNow -lt $deadline -and
                (Get-Process -Id ([int]$record.pid) -ErrorAction SilentlyContinue)) {
                Start-Sleep -Milliseconds 200
            }
            if (Get-Process -Id ([int]$record.pid) -ErrorAction SilentlyContinue) {
                $current = Get-SupervisorRecord
                if ($null -ne $current -and
                    [string]$current.instance_id -eq [string]$record.instance_id -and
                    (Test-SupervisorRecordOwnership $current)) {
                    Write-SupervisorLog ("graceful stop timed out; force-stopping bound supervisor pid={0}" -f $record.pid)
                    Stop-Process -Id ([int]$record.pid) -Force -ErrorAction Stop
                    [void](Wait-Process -Id ([int]$record.pid) -Timeout 10 -ErrorAction SilentlyContinue)
                } else {
                    Write-SupervisorLog 'refused forced stop because supervisor identity changed'
                }
            }
        }
    } elseif (-not $DryRun -and (Test-Path -LiteralPath $SupervisorPidFile -PathType Leaf)) {
        Write-SupervisorLog 'ignored stale or unbound supervisor pid record; no unrelated process was signaled'
    }
    Stop-ProjectProcesses @('run_weixin_ilink_bridge.py') 'weixin'
    Stop-ProjectProcesses @('run_feishu_bridge.py') 'feishu'
    Stop-ProjectProcesses @('gateway.app', 'engine_main.py') 'engine'
    if (-not $DryRun -and (Test-Path -LiteralPath $SupervisorPidFile)) {
        $remaining = Get-SupervisorRecord
        if ($null -eq $remaining -or
            -not (Get-Process -Id ([int]$remaining.pid) -ErrorAction SilentlyContinue)) {
            Remove-Item -LiteralPath $SupervisorPidFile -Force
        }
    }
    Emit (Get-RuntimeState)
    exit 0
}

if ($Action -eq 'Resume') {
    if ($DryRun) {
        Emit (Get-RuntimeState -Plan)
        exit 0
    }
    Initialize-PrivateRuntimeTree
    $runtimeTreeInitialized = $true
    Assert-TrustedRegularFile $Python 'managed Python' -AllowReparseAncestors:(-not $Scheduled)
    Assert-TrustedRegularFile $ManagedLauncherPath 'managed launcher' -AllowReparseAncestors:(-not $Scheduled)
    if (Test-Path -LiteralPath $SupervisorStopFile -PathType Leaf) {
        Remove-Item -LiteralPath $SupervisorStopFile -Force -ErrorAction Stop
    }
    Write-SupervisorLog 'persistent stop latch cleared by explicit Resume'
    $Action = 'Run'
}

if ($DryRun) {
    Emit (Get-RuntimeState -Plan)
    exit 0
}

if (-not $runtimeTreeInitialized) {
    Initialize-PrivateRuntimeTree
    $runtimeTreeInitialized = $true
}
if (Test-StopRequested) {
    $stopState = Get-StopState
    Write-SupervisorLog ("supervisor start blocked by persistent stop latch (valid={0}, scheduled={1})" -f $stopState.valid, [bool]$Scheduled)
    Emit (Get-RuntimeState)
    exit 0
}
Assert-TrustedRegularFile $Python 'managed Python' -AllowReparseAncestors:(-not $Scheduled)
Assert-TrustedRegularFile $ManagedLauncherPath 'managed launcher' -AllowReparseAncestors:(-not $Scheduled)
$rootHash = (Get-Sha256Hex $Root.ToLowerInvariant()).Substring(0, 16)
$mutexName = 'Global\NachuanSupervisor-{0}' -f $rootHash
$mutex = $null
$ownsMutex = $false
$lockStream = $null
$stopRequested = $false
try {
    $mutex = New-Object Threading.Mutex($false, $mutexName)
    try {
        $ownsMutex = $mutex.WaitOne(0, $false)
    } catch [Threading.AbandonedMutexException] {
        $ownsMutex = $true
        Write-SupervisorLog 'recovered abandoned global supervisor mutex'
    }
    if (-not $ownsMutex) {
        Write-SupervisorLog 'another cross-session supervisor is already running'
        Emit (Get-RuntimeState)
        exit 0
    }
    try {
        $lockStream = [IO.File]::Open(
            $SupervisorLockFile,
            [IO.FileMode]::OpenOrCreate,
            [IO.FileAccess]::ReadWrite,
            [IO.FileShare]::None
        )
    } catch [IO.IOException] {
        Write-SupervisorLog 'another supervisor owns the cross-session filesystem lock'
        Emit (Get-RuntimeState)
        exit 0
    }
    # Scheduled/production lifecycle never trusts ambient credentials inherited
    # from a user shell, registry environment, or task host.  It uses only the
    # supervisor-owned ACL-restricted key files created below.
    if ($Scheduled) {
        Remove-Item Env:GATEWAY_API_KEYS,Env:APPROVAL_ADMIN_KEY,Env:NACHUAN_PAID_MEDIA_API_KEY,`
            Env:NACHUAN_ALLOW_ANONYMOUS_LOCAL,`
            Env:NACHUAN_ENGINE_BOOT_TOKEN,Env:NACHUAN_WEIXIN_BRIDGE_API_KEY,`
            Env:NACHUAN_FEISHU_BRIDGE_API_KEY,Env:BRIDGE_API_KEY,Env:BRIDGE_ENGINE_URL,`
            Env:USAGE_DB_PATH,Env:DATA_DIR,Env:WEIXIN_ALLOW_ALL,Env:FEISHU_ALLOW_ALL,`
            Env:WEIXIN_ALLOWED,Env:WEIXIN_OWNER,Env:FEISHU_ALLOWED_USERS,Env:FEISHU_OWNER_OPEN_ID `
            -ErrorAction SilentlyContinue
    }
    # Key creation is inside the cross-session lock.  Two simultaneous supervisors
    # must never launch with different in-memory secrets while one key file wins a race.
    Ensure-GatewayKey
    Ensure-ApprovalAdminKey
    Ensure-PaidMediaApiKey
    Ensure-ChannelBridgeKeys
    [void](Ensure-EngineBootToken -Rotate)
    Configure-MediaBinaries
    $script:SupervisorInstanceId = [Guid]::NewGuid().ToString('D')
    Write-SupervisorRecord $script:SupervisorInstanceId
    Write-SupervisorLog ("supervisor started pid={0} instance={1} root={2}" -f $PID, $script:SupervisorInstanceId, $Root)
    while ($true) {
        if (Test-StopRequested) {
            $stopRequested = $true
            break
        }
        try {
            Invoke-WatchdogCycle
        } catch {
            Write-SupervisorLog ("watchdog cycle failed: {0}" -f $_.Exception.Message)
            if ($Once) { throw }
        }
        if ($Once) { break }
        $waitSeconds = [math]::Max(2, $PollSeconds)
        for ($waited = 0; $waited -lt $waitSeconds; $waited++) {
            Start-Sleep -Seconds 1
            if (Test-StopRequested) {
                $stopRequested = $true
                break
            }
        }
        if ($stopRequested) { break }
    }
    if ($stopRequested) {
        Write-SupervisorLog 'stop latch acknowledged; shutting down managed services'
        Stop-ProjectProcesses @('run_weixin_ilink_bridge.py') 'weixin'
        Stop-ProjectProcesses @('run_feishu_bridge.py') 'feishu'
        Stop-ProjectProcesses @('gateway.app', 'engine_main.py') 'engine'
    }
    Emit (Get-RuntimeState)
} finally {
    $currentRecord = Get-SupervisorRecord
    if ($null -ne $currentRecord -and
        [int]$currentRecord.pid -eq $PID -and
        [string]$currentRecord.instance_id -eq [string]$script:SupervisorInstanceId) {
        try {
            Remove-Item -LiteralPath $SupervisorPidFile -Force -ErrorAction Stop
        } catch {
            Write-SupervisorLog ("failed to remove supervisor pid file: {0}" -f $_.Exception.Message)
        }
    }
    if ($null -ne $lockStream) { $lockStream.Dispose() }
    if ($ownsMutex -and $null -ne $mutex) { $mutex.ReleaseMutex() }
    if ($null -ne $mutex) { $mutex.Dispose() }
}

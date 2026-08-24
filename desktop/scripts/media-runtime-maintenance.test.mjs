import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { spawn, spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

import { afterEach, describe, expect, it } from 'vitest'

const roots = []
const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..')
const maintenanceScript = join(projectRoot, '安装与维护', '准备FFmpeg构建输入.ps1')

const quote = (value) => `'${String(value).replaceAll("'", "''")}'`
const encodedPowerShellArgs = (encoded) => [
  '-NoLogo',
  '-NoProfile',
  '-NonInteractive',
  '-ExecutionPolicy',
  'Bypass',
  '-EncodedCommand',
  encoded
]

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { force: true, recursive: true })
})

function runPowerShell(source) {
  const encoded = Buffer.from(source, 'utf16le').toString('base64')
  return spawnSync(
    'powershell.exe',
    encodedPowerShellArgs(encoded),
    { encoding: 'utf8', timeout: 30_000, windowsHide: true }
  )
}

function runPowerShellAsync(source, timeoutMs = 30_000) {
  const encoded = Buffer.from(source, 'utf16le').toString('base64')
  return new Promise((accept, reject) => {
    const child = spawn(
      'powershell.exe',
      encodedPowerShellArgs(encoded),
      { windowsHide: true }
    )
    let stdout = ''
    let stderr = ''
    child.stdout.setEncoding('utf8')
    child.stderr.setEncoding('utf8')
    child.stdout.on('data', (chunk) => {
      stdout += chunk
    })
    child.stderr.on('data', (chunk) => {
      stderr += chunk
    })
    const timeout = setTimeout(() => {
      child.kill()
      reject(new Error(`PowerShell test timed out\n${stdout}\n${stderr}`))
    }, timeoutMs)
    child.once('error', (error) => {
      clearTimeout(timeout)
      reject(error)
    })
    child.once('close', (status) => {
      clearTimeout(timeout)
      accept({ status, stderr, stdout })
    })
  })
}

async function listen(server) {
  await new Promise((accept, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', accept)
  })
  return server.address().port
}

async function closeServer(server) {
  await new Promise((accept) => server.close(accept))
}

function boundedDownloadSource({
  inputRoot,
  uri,
  expectedBytes,
  idleSeconds,
  totalSeconds,
  identitySource = `$watched = Get-Process -Id $PID; [pscustomobject]@{ Pid = $PID; StartTimeUtcTicks = [Int64]$watched.StartTime.ToUniversalTime().Ticks }`
}) {
  const downloadRoot = join(inputRoot, '下载')
  const destination = join(downloadRoot, 'candidate.bin')
  const statusLog = join(downloadRoot, 'candidate.progress.jsonl')
  return {
    destination,
    statusLog,
    source: `
$ErrorActionPreference = 'Stop'
. ${quote(maintenanceScript)} -LibraryMode -InputRootOverride ${quote(inputRoot)}
New-Item -ItemType Directory -Path ${quote(downloadRoot)} -Force | Out-Null
$identity = & { ${identitySource} }
Invoke-BoundedDownload -Uri ${quote(uri)} -Destination ${quote(destination)} -StatusLog ${quote(statusLog)} -ExpectedBytes ${expectedBytes} -ParentIdentity $identity -TotalTimeoutSeconds ${totalSeconds} -IdleTimeoutSeconds ${idleSeconds} -HeartbeatSeconds 1
'BOUNDED_DOWNLOAD_OK'
`
  }
}

function runMaintenance(args) {
  return spawnSync(
    'powershell.exe',
    ['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', maintenanceScript, ...args],
    { encoding: 'utf8', timeout: 30_000, windowsHide: true }
  )
}

describe('Chinese FFmpeg maintenance entry safety', () => {
  it.runIf(process.platform === 'win32')(
    'rejects destination, bin, and backup junctions before move or recursive cleanup',
    () => {
      const root = mkdtempSync(join(tmpdir(), 'nachuan-media-maintenance-'))
      roots.push(root)
      const inputRoot = join(root, '构建输入')
      const outside = join(root, 'outside')
      const source = `
$ErrorActionPreference = 'Stop'
. ${quote(maintenanceScript)} -LibraryMode -InputRootOverride ${quote(inputRoot)}
New-Item -ItemType Directory -Path ${quote(inputRoot)} -Force | Out-Null
New-Item -ItemType Directory -Path ${quote(outside)} -Force | Out-Null

function Assert-Blocked([string]$Name, [scriptblock]$Action) {
    $blocked = $false
    try { & $Action }
    catch {
        if ($_.Exception.Message -notmatch '重解析|真实非重解析|redirect|reparse') { throw }
        $blocked = $true
    }
    if (-not $blocked) { throw "$Name junction was accepted" }
}

$destination = Join-Path ${quote(inputRoot)} 'ffmpeg-8.0.1-essentials_build'
New-Item -ItemType Junction -Path $destination -Target ${quote(outside)} | Out-Null
Assert-Blocked 'destination' { Assert-RealDirectory -Path $destination -Label 'destination' }
Remove-Item -LiteralPath $destination -Force

$sourceRoot = Join-Path ${quote(inputRoot)} 'source-with-bin-junction'
New-Item -ItemType Directory -Path $sourceRoot | Out-Null
[IO.File]::WriteAllText((Join-Path $sourceRoot 'LICENSE'), 'placeholder')
[IO.File]::WriteAllText((Join-Path $sourceRoot 'README.txt'), 'placeholder')
$outsideBin = Join-Path ${quote(outside)} 'bin'
New-Item -ItemType Directory -Path $outsideBin | Out-Null
New-Item -ItemType Junction -Path (Join-Path $sourceRoot 'bin') -Target $outsideBin | Out-Null
Assert-Blocked 'bin' { Assert-PreparedSource -Root $sourceRoot }

$backup = Join-Path ${quote(inputRoot)} '.ffmpeg-previous-audit'
New-Item -ItemType Junction -Path $backup -Target ${quote(outside)} | Out-Null
Assert-Blocked 'backup' { Assert-RealDirectory -Path $backup -Label 'backup' }
'POWERSHELL_JUNCTION_GATES_OK'
`
      const result = runPowerShell(source)
      expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0)
      expect(`${result.stdout}\n${result.stderr}`).toContain('POWERSHELL_JUNCTION_GATES_OK')
    }
  )

  it('keeps the PowerShell 5.1 entry as UTF-8 BOM text', () => {
    const bytes = readFileSync(maintenanceScript)
    expect([...bytes.subarray(0, 3)]).toEqual([0xef, 0xbb, 0xbf])
  })

  it.runIf(process.platform === 'win32')(
    'enforces the eight-second idle boundary from injected policy time',
    () => {
      const root = mkdtempSync(join(tmpdir(), 'nachuan-idle-policy-'))
      roots.push(root)
      const inputRoot = join(root, 'input')
      const source = `
$ErrorActionPreference = 'Stop'
. ${quote(maintenanceScript)} -LibraryMode -InputRootOverride ${quote(inputRoot)}
$identityProcess = Get-Process -Id $PID
$identity = [pscustomobject]@{ Pid = $PID; StartTimeUtcTicks = [Int64]$identityProcess.StartTime.ToUniversalTime().Ticks }
$started = [DateTime]::Parse('2026-07-18T00:00:00Z').ToUniversalTime()
$lastProgress = $started
$lastHeartbeat = $started
$stream = New-Object IO.MemoryStream
$writer = New-Object IO.StreamWriter($stream, (New-Object Text.UTF8Encoding($false)))
try {
    Invoke-DownloadGuard -ParentIdentity $identity -StartedUtc $started -LastProgressUtc $lastProgress -LastHeartbeatUtc ([ref]$lastHeartbeat) -TotalTimeoutSeconds 60 -IdleTimeoutSeconds 8 -HeartbeatSeconds 60 -Bytes 0 -ExpectedBytes 32 -Writer $writer -NowUtc ($started.AddMilliseconds(7999))
    $blocked = $false
    try {
        Invoke-DownloadGuard -ParentIdentity $identity -StartedUtc $started -LastProgressUtc $lastProgress -LastHeartbeatUtc ([ref]$lastHeartbeat) -TotalTimeoutSeconds 60 -IdleTimeoutSeconds 8 -HeartbeatSeconds 60 -Bytes 0 -ExpectedBytes 32 -Writer $writer -NowUtc ($started.AddSeconds(8))
    }
    catch {
        if ($_.Exception.Message -notmatch 'DOWNLOAD_IDLE_TIMEOUT') { throw }
        $blocked = $true
    }
    if (-not $blocked) { throw 'eight-second idle boundary was not enforced' }
}
finally {
    $writer.Dispose()
    $stream.Dispose()
}
'DOWNLOAD_IDLE_BOUNDARY_OK'
`
      const result = runPowerShell(source)
      expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0)
      expect(`${result.stdout}\n${result.stderr}`).toContain('DOWNLOAD_IDLE_BOUNDARY_OK')
    }
  )

  it.runIf(process.platform === 'win32')(
    'forbids overriding the project input root outside library-mode audits',
    () => {
      const root = mkdtempSync(join(tmpdir(), 'nachuan-media-root-override-'))
      roots.push(root)
      const forbidden = join(root, 'outside-input-root')
      const result = runMaintenance(['-InputRootOverride', forbidden])
      expect(result.status).not.toBe(0)
      expect(`${result.stdout}\n${result.stderr}`).toContain(
        'MEDIA_RUNTIME_INPUT_ROOT_OVERRIDE_FORBIDDEN'
      )
      expect(existsSync(forbidden)).toBe(false)
    }
  )

  it.runIf(process.platform === 'win32')(
    'rejects every archive path outside the fixed project input root before reading it',
    () => {
      const root = mkdtempSync(join(tmpdir(), 'nachuan-media-external-archive-'))
      roots.push(root)
      const externalArchive = join(root, 'external.zip')
      writeFileSync(externalArchive, 'must-not-be-used')
      const result = runMaintenance(['-ArchivePath', externalArchive])
      expect(result.status).not.toBe(0)
      expect(`${result.stdout}\n${result.stderr}`).toContain('MEDIA_RUNTIME_ARCHIVE_OUTSIDE_PROJECT')
      expect(readFileSync(externalArchive, 'utf8')).toBe('must-not-be-used')
    }
  )

  it.runIf(process.platform === 'win32')(
    'streams with observable heartbeats and exact byte completion in an isolated root',
    async () => {
      const chunks = Array.from({ length: 5 }, (_, index) => Buffer.alloc(4096, index + 1))
      const expectedBytes = chunks.reduce((sum, chunk) => sum + chunk.length, 0)
      const server = createServer((_request, response) => {
        response.writeHead(200, { 'Content-Length': expectedBytes })
        let index = 0
        const timer = setInterval(() => {
          if (index === chunks.length) {
            clearInterval(timer)
            response.end()
            return
          }
          response.write(chunks[index])
          index += 1
        }, 350)
      })
      const port = await listen(server)
      const root = mkdtempSync(join(tmpdir(), 'nachuan-bounded-download-'))
      roots.push(root)
      const probe = boundedDownloadSource({
        inputRoot: join(root, 'input'),
        uri: `http://127.0.0.1:${port}/slow.bin`,
        expectedBytes,
        // This case proves streaming/heartbeat success, not the deadline edge.
        // The exact eight-second idle boundary is covered deterministically above.
        idleSeconds: 15,
        totalSeconds: 25
      })
      try {
        const result = await runPowerShellAsync(probe.source)
        expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0)
        expect(result.stdout).toContain('DOWNLOAD_HEARTBEAT')
        expect(result.stdout).toContain('DOWNLOAD_COMPLETE')
        expect(result.stdout).toContain('BOUNDED_DOWNLOAD_OK')
        expect(readFileSync(probe.destination)).toEqual(Buffer.concat(chunks))
        const events = readFileSync(probe.statusLog, 'utf8')
          .trim()
          .split(/\r?\n/)
          .map((line) => JSON.parse(line))
        expect(events.some(({ event }) => event === 'heartbeat')).toBe(true)
        expect(events.at(-1).event).toBe('complete')
      } finally {
        await closeServer(server)
      }
    }
  )

  it.runIf(process.platform === 'win32')(
    'fails within the internal idle deadline when a response stops producing bytes',
    async () => {
      const server = createServer((_request, response) => {
        response.writeHead(200, { 'Content-Length': 32 })
        response.flushHeaders()
      })
      const port = await listen(server)
      const root = mkdtempSync(join(tmpdir(), 'nachuan-idle-download-'))
      roots.push(root)
      const probe = boundedDownloadSource({
        inputRoot: join(root, 'input'),
        uri: `http://127.0.0.1:${port}/stalled.bin`,
        expectedBytes: 32,
        idleSeconds: 1,
        totalSeconds: 10
      })
      try {
        const result = await runPowerShellAsync(probe.source)
        expect(result.status).not.toBe(0)
        expect(`${result.stdout}\n${result.stderr}`).toContain('DOWNLOAD_IDLE_TIMEOUT')
        const events = readFileSync(probe.statusLog, 'utf8')
          .trim()
          .split(/\r?\n/)
          .map((line) => JSON.parse(line))
        expect(events.at(-1)).toMatchObject({
          event: 'failed',
          bytes: 0,
          expectedBytes: 32
        })
        expect(events.at(-1).message).toContain('DOWNLOAD_IDLE_TIMEOUT')
      } finally {
        await closeServer(server)
      }
    }
  )

  it.runIf(process.platform === 'win32')(
    'converges after the watched parent PID identity exits during a stalled transfer',
    async () => {
      let markRequestSeen
      const requestSeen = new Promise((accept) => {
        markRequestSeen = accept
      })
      const server = createServer((_request, response) => {
        markRequestSeen()
        response.writeHead(200, { 'Content-Length': 32 })
        response.flushHeaders()
      })
      const port = await listen(server)
      const watched = spawn(
        'powershell.exe',
        ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', 'Start-Sleep -Seconds 30'],
        { windowsHide: true }
      )
      const root = mkdtempSync(join(tmpdir(), 'nachuan-parent-download-'))
      roots.push(root)
      const probe = boundedDownloadSource({
        inputRoot: join(root, 'input'),
        uri: `http://127.0.0.1:${port}/parent-stalled.bin`,
        expectedBytes: 32,
        idleSeconds: 10,
        totalSeconds: 20,
        identitySource: `$watched = Get-Process -Id ${watched.pid}; [pscustomobject]@{ Pid = ${watched.pid}; StartTimeUtcTicks = [Int64]$watched.StartTime.ToUniversalTime().Ticks }`
      })
      const childResult = runPowerShellAsync(probe.source)
      try {
        await Promise.race([
          requestSeen,
          childResult.then((result) => {
            throw new Error(
              `bounded download exited before reaching the local server\n${result.stdout}\n${result.stderr}`
            )
          })
        ])
        watched.kill()
        const result = await childResult
        expect(result.status).not.toBe(0)
        expect(`${result.stdout}\n${result.stderr}`).toContain('DOWNLOAD_PARENT_EXITED')
      } finally {
        watched.kill()
        await closeServer(server)
      }
    }
  )
})

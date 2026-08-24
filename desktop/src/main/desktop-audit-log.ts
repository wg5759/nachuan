import {
  appendFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  renameSync,
  rmSync
} from 'node:fs'
import { join } from 'node:path'

const DEFAULT_MAX_BYTES = 5 * 1024 * 1024
const DEFAULT_KEEP = 3
const SENSITIVE_FIELD = /(key|token|secret|password|authorization|payload|content|prompt|message)/i

function safeValue(name: string, value: unknown): string | number | boolean | null {
  if (SENSITIVE_FIELD.test(name)) return '[redacted]'
  if (typeof value === 'number') return Number.isFinite(value) ? value : null
  if (typeof value === 'boolean' || value === null) return value
  return String(value ?? '').replace(/[\r\n\u0000-\u001f\u007f]/g, ' ').slice(0, 256)
}

export class DesktopAuditLog {
  readonly path: string

  constructor(
    directory: string,
    private readonly maxBytes = DEFAULT_MAX_BYTES,
    private readonly keep = DEFAULT_KEEP
  ) {
    mkdirSync(directory, { recursive: true })
    const info = lstatSync(directory)
    if (!info.isDirectory() || info.isSymbolicLink()) {
      throw new Error('desktop audit log directory is redirected or not a directory')
    }
    this.path = join(directory, 'desktop-main.jsonl')
  }

  private rotate(): void {
    if (!existsSync(this.path)) return
    const current = lstatSync(this.path)
    if (!current.isFile() || current.isSymbolicLink()) {
      throw new Error('desktop audit log file is redirected or not a regular file')
    }
    if (current.size < this.maxBytes) return
    const oldest = `${this.path}.${this.keep}`
    if (existsSync(oldest)) rmSync(oldest, { force: true })
    for (let index = this.keep - 1; index >= 1; index -= 1) {
      const source = `${this.path}.${index}`
      if (existsSync(source)) renameSync(source, `${this.path}.${index + 1}`)
    }
    renameSync(this.path, `${this.path}.1`)
  }

  write(event: string, fields: Record<string, unknown> = {}): void {
    try {
      const normalizedEvent = /^[a-z0-9_.-]{1,64}$/.test(event) ? event : 'invalid_event'
      const safeFields = Object.fromEntries(
        Object.entries(fields).slice(0, 32).map(([name, value]) => [name.slice(0, 64), safeValue(name, value)])
      )
      this.rotate()
      appendFileSync(
        this.path,
        `${JSON.stringify({ ts: new Date().toISOString(), event: normalizedEvent, ...safeFields })}\n`,
        { encoding: 'utf8', mode: 0o600 }
      )
    } catch {
      // Diagnostics must never become a new availability dependency.
    }
  }
}

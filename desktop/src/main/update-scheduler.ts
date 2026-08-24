import type { UpdateCheckReason } from './secure-auto-updater'

const MINUTE = 60 * 1000
const HOUR = 60 * MINUTE
const INITIAL_MIN_MS = 30 * 1000
const INITIAL_JITTER_MS = 90 * 1000
const REGULAR_MIN_MS = 4 * HOUR
const REGULAR_JITTER_MS = 2 * HOUR
const RETRY_BASE_MS = 5 * MINUTE
const RETRY_MAX_MS = 4 * HOUR
const RECOVERY_DEBOUNCE_MS = 60 * 1000

export interface UpdateSchedulerOptions {
  check: (reason: UpdateCheckReason) => Promise<void>
  random?: () => number
  now?: () => number
  setTimer?: (callback: () => void, delayMs: number) => ReturnType<typeof setTimeout>
  clearTimer?: (timer: ReturnType<typeof setTimeout>) => void
}

export class UpdateCheckScheduler {
  private readonly options: Required<UpdateSchedulerOptions>
  private timer: ReturnType<typeof setTimeout> | null = null
  private inFlight: Promise<void> | null = null
  private stopped = true
  private failures = 0
  private lastAttemptAt = 0

  constructor(options: UpdateSchedulerOptions) {
    this.options = {
      ...options,
      random: options.random || Math.random,
      now: options.now || Date.now,
      setTimer: options.setTimer || setTimeout,
      clearTimer: options.clearTimer || clearTimeout
    }
  }

  start(): void {
    if (!this.stopped) return
    this.stopped = false
    this.schedule(INITIAL_MIN_MS + Math.floor(this.options.random() * INITIAL_JITTER_MS), 'startup')
  }

  stop(): void {
    this.stopped = true
    if (this.timer) this.options.clearTimer(this.timer)
    this.timer = null
  }

  trigger(reason: UpdateCheckReason): Promise<void> {
    if (this.stopped) return Promise.resolve()
    if (this.inFlight) return this.inFlight
    if (this.timer) this.options.clearTimer(this.timer)
    this.timer = null
    this.lastAttemptAt = this.options.now()
    this.inFlight = this.options
      .check(reason)
      .then(() => {
        this.failures = 0
        this.scheduleRegular()
      })
      .catch((error) => {
        this.failures += 1
        this.scheduleRetry()
        throw error
      })
      .finally(() => {
        this.inFlight = null
      })
    return this.inFlight
  }

  networkRecovered(): Promise<void> {
    if (this.options.now() - this.lastAttemptAt < RECOVERY_DEBOUNCE_MS) return Promise.resolve()
    return this.trigger('network-online')
  }

  resumed(): Promise<void> {
    if (this.options.now() - this.lastAttemptAt < RECOVERY_DEBOUNCE_MS) return Promise.resolve()
    return this.trigger('resume')
  }

  private scheduleRegular(): void {
    const delay = REGULAR_MIN_MS + Math.floor(this.options.random() * REGULAR_JITTER_MS)
    this.schedule(delay, 'periodic')
  }

  private scheduleRetry(): void {
    const exponential = Math.min(RETRY_MAX_MS, RETRY_BASE_MS * 2 ** Math.min(this.failures - 1, 8))
    const jitter = Math.floor(exponential * 0.2 * this.options.random())
    this.schedule(exponential + jitter, 'periodic')
  }

  private schedule(delayMs: number, reason: UpdateCheckReason): void {
    if (this.stopped) return
    if (this.timer) this.options.clearTimer(this.timer)
    this.timer = this.options.setTimer(() => {
      this.timer = null
      void this.trigger(reason).catch(() => undefined)
    }, delayMs)
  }
}

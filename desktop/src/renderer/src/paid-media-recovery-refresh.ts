/** A tiny generation fence for periodic recovery reads. */
export class LatestOnlyRefresh<T> {
  private generation = 0
  private inFlight = false

  get running(): boolean {
    return this.inFlight
  }

  invalidate(): void {
    this.generation += 1
  }

  async run(
    load: () => Promise<T>,
    apply: (value: T) => void,
    fail: (error: unknown) => void = () => undefined
  ): Promise<void> {
    if (this.inFlight) return
    this.inFlight = true
    const ticket = ++this.generation
    try {
      const value = await load()
      if (ticket === this.generation) apply(value)
    } catch (error) {
      if (ticket === this.generation) fail(error)
    } finally {
      this.inFlight = false
    }
  }
}

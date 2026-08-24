import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const scriptPath = fileURLToPath(import.meta.url)
const CLOSED_REASON =
  'early-access publishing requires a verified versioned legal policy with external approval and a candidate-bound fresh audit receipt verifier; neither trust gate is established'

// FORMAL REOPENING BLOCKERS: before this public entry can import or invoke the
// internal transaction, signing must leave the same-user trust domain and the
// candidate must be identity-pinned/rechecked across signing and upload to
// close artifact TOCTOU. The currently unreachable workflow does not prove
// either property, so this is deliberately documentation, not a pretend fix.

export async function publishEarlyAccess(_options = {}) {
  // Deliberately do not inspect options or environment booleans here. Future
  // opening must verify signed receipts bound to the candidate and lock digest.
  throw new Error(CLOSED_REASON)
}

if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
  try {
    await publishEarlyAccess()
  } catch (error) {
    console.error(`[early-publisher] BLOCKED: ${error instanceof Error ? error.message : String(error)}`)
    process.exitCode = 1
  }
}

import { generateKeyPairSync } from 'node:crypto'
import { chmodSync, mkdirSync, realpathSync, writeFileSync } from 'node:fs'
import { dirname, join, relative, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

const scriptPath = fileURLToPath(import.meta.url)
const repoRoot = resolve(dirname(scriptPath), '..', '..')
const KEY_ID = /^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$/

function outsideRepo(path) {
  const item = relative(repoRoot, path)
  return item === '..' || item.startsWith(`..${sep}`)
}

function main(argv) {
  const [rawOutput, keyId] = argv
  if (!rawOutput || !KEY_ID.test(String(keyId || ''))) {
    throw new Error('usage: init-update-signing-key.mjs <offline-output-directory> <key-id>')
  }
  const passphrase = String(process.env.NACHUAN_UPDATE_PRIVATE_KEY_PASSPHRASE || '')
  if (passphrase.length < 16 || passphrase.length > 1024) {
    throw new Error('NACHUAN_UPDATE_PRIVATE_KEY_PASSPHRASE must contain 16-1024 characters')
  }
  const output = resolve(rawOutput)
  if (!outsideRepo(output)) throw new Error('offline update key directory must be outside the repository')
  mkdirSync(output, { recursive: true, mode: 0o700 })
  const realOutput = realpathSync.native(output)
  if (!outsideRepo(realOutput)) throw new Error('offline update key directory redirected into the repository')
  const pair = generateKeyPairSync('ed25519')
  const privatePath = join(realOutput, 'ed25519-private.pem')
  const publicPath = join(realOutput, 'update-public.json')
  const privatePem = pair.privateKey.export({
    format: 'pem',
    type: 'pkcs8',
    cipher: 'aes-256-cbc',
    passphrase
  })
  const publicKeySpkiBase64 = pair.publicKey
    .export({ format: 'der', type: 'spki' })
    .toString('base64')
  writeFileSync(privatePath, privatePem, { encoding: 'utf8', flag: 'wx', mode: 0o600 })
  writeFileSync(
    publicPath,
    `${JSON.stringify({ schema: 1, algorithm: 'Ed25519', keyId, publicKeySpkiBase64 }, null, 2)}\n`,
    { encoding: 'utf8', flag: 'wx', mode: 0o644 }
  )
  try {
    chmodSync(privatePath, 0o600)
    chmodSync(realOutput, 0o700)
  } catch {
    // Windows does not map POSIX modes to a complete ACL. Keep the key offline
    // or on protected removable media; the PEM is still passphrase-encrypted.
  }
  console.log(`[update-key] initialized encrypted offline Ed25519 key ${keyId}`)
  console.log(`[update-key] public configuration: ${publicPath}`)
}

if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
  try {
    main(process.argv.slice(2))
  } catch (error) {
    console.error(`[update-key] BLOCKED: ${error instanceof Error ? error.message : String(error)}`)
    process.exitCode = 1
  }
}

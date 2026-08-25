import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'


const scriptRoot = dirname(fileURLToPath(import.meta.url))
const desktopRoot = resolve(scriptRoot, '..')
const projectRoot = resolve(desktopRoot, '..')
const required = Object.freeze([
  'NACHUAN_STORE_APPLICATION_ID',
  'NACHUAN_STORE_IDENTITY_NAME',
  'NACHUAN_STORE_PUBLISHER',
  'NACHUAN_STORE_PUBLISHER_DISPLAY_NAME'
])

function plain(value, label, maxLength = 256) {
  if (
    typeof value !== 'string' ||
    value.trim() !== value ||
    value.length < 1 ||
    value.length > maxLength ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    throw new Error(`${label} is invalid`)
  }
  return value
}

export function storeMsixReadiness(environment = process.env) {
  const missing = required.filter((name) => !String(environment[name] ?? '').trim())
  if (missing.length) {
    return Object.freeze({
      ready: false,
      reason: 'partner_center_identity_missing',
      missing: Object.freeze(missing)
    })
  }
  const applicationId = plain(environment.NACHUAN_STORE_APPLICATION_ID, 'applicationId', 64)
  if (!/^[A-Za-z0-9]+$/u.test(applicationId)) {
    throw new Error('applicationId must be alphanumeric')
  }
  const identityName = plain(environment.NACHUAN_STORE_IDENTITY_NAME, 'identityName', 64)
  if (!/^[A-Za-z0-9]+(?:\.[A-Za-z0-9]+)*$/u.test(identityName)) {
    throw new Error('identityName is invalid')
  }
  const publisher = plain(environment.NACHUAN_STORE_PUBLISHER, 'publisher')
  if (!/^CN=[^,]+(?:,\s*[A-Z][A-Z0-9.]*=[^,]+)*$/u.test(publisher)) {
    throw new Error('publisher must be a certificate/Partner Center subject')
  }
  const publisherDisplayName = plain(
    environment.NACHUAN_STORE_PUBLISHER_DISPLAY_NAME,
    'publisherDisplayName'
  )
  const packageJson = JSON.parse(readFileSync(resolve(desktopRoot, 'package.json'), 'utf8'))
  const distribution = JSON.parse(
    readFileSync(resolve(projectRoot, 'config', 'distribution-channels.v1.json'), 'utf8')
  )
  if (packageJson.version !== distribution.core_version) {
    throw new Error('desktop and shared-core versions differ')
  }
  return Object.freeze({
    ready: true,
    version: packageJson.version,
    applicationId,
    identityName,
    publisher,
    publisherDisplayName,
    config: 'electron-builder.store-msix.yml',
    target: 'appx',
    signing: 'microsoft_store_resigns_after_certification'
  })
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const result = storeMsixReadiness(process.env)
    process.stdout.write(`${JSON.stringify(result)}\n`)
    process.exitCode = result.ready ? 0 : 2
  } catch (error) {
    process.stderr.write('[store-msix] FAIL\n')
    process.exitCode = 2
  }
}

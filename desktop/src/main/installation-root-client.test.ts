import { createHash, createHmac } from 'node:crypto'
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import type { AddressInfo } from 'node:net'
import { describe, expect, it } from 'vitest'

import {
  INSTALLATION_ROOT_PATHS,
  InstallationRootBusinessError,
  InstallationRootClient,
  parseInstallationRootMutationResponse,
  parseInstallationRootSnapshotResponse,
  signInstallationRootRequest,
  validateInstallationRootRequest,
  verifyInstallationRootResponse,
  type InstallationRootJsonResponse,
  type InstallationRootPath
} from './installation-root-client'

const BOOT_TOKEN = '0123456789abcdef'.repeat(4)
const TIMESTAMP_MS = 1_720_000_000_123
const NONCE = '11'.repeat(32)
const VECTOR_PATH = '/internal/installation-root/component/advance'
const REQUEST_BODY = Buffer.from('{"component":"desktop","sequence":7}', 'utf8')
const DIGEST_A = 'a'.repeat(64)
const DIGEST_B = 'b'.repeat(64)
const DIGEST_C = 'c'.repeat(64)
const ZERO_DIGEST = '0'.repeat(64)

function validSnapshot() {
  return {
    installationId: DIGEST_A,
    ownerSidDigest: DIGEST_B,
    epoch: 1,
    rootRevision: 8,
    status: 'active',
    lockKind: 'none',
    lockReasonDigest: null,
    reanchorPending: false,
    reanchorOperationDigest: null,
    reanchorSnapshotDigest: null,
    reanchorSourceEpoch: null,
    principalDigest: DIGEST_C,
    components: {
      desktop: {
        identity: DIGEST_B,
        epoch: 1,
        bound: true,
        sequenceFloor: 7,
        stateDigest: DIGEST_A,
        recoveryFloor: null,
        recoveryStateDigest: null
      },
      gateway: {
        identity: DIGEST_C,
        epoch: 1,
        bound: true,
        sequenceFloor: 3,
        stateDigest: DIGEST_B,
        recoveryFloor: null,
        recoveryStateDigest: null
      }
    },
    updater: {
      releaseSequence: 0,
      keyringSequence: 0,
      artifactDigest: ZERO_DIGEST,
      stateDigest: ZERO_DIGEST
    }
  } as const
}

function mutationEnvelope() {
  return {
    schema: 'nachuan.installation-root.mutation.v1',
    snapshot: validSnapshot(),
    applied: true,
    recovered: false
  } as const
}

function u32(value: number): Buffer {
  const output = Buffer.alloc(4)
  output.writeUInt32BE(value)
  return output
}

function u64(value: number): Buffer {
  const output = Buffer.alloc(8)
  output.writeBigUInt64BE(BigInt(value))
  return output
}

function frame(domain: string, fields: readonly Buffer[]): Buffer {
  const domainBytes = Buffer.from(domain, 'ascii')
  return Buffer.concat([
    u32(domainBytes.byteLength),
    domainBytes,
    u32(fields.length),
    ...fields.flatMap((field) => [u64(field.byteLength), field])
  ])
}

function signedResponseHeaders(
  bootToken: string,
  requestNonce: string,
  status: number,
  body: Buffer
): Record<string, string> {
  const bodySha256 = createHash('sha256').update(body).digest('hex')
  const signature = createHmac('sha256', Buffer.from(bootToken, 'hex'))
    .update(
      frame('nachuan.installation-root.internal.response.v1', [
        Buffer.from(requestNonce, 'hex'),
        u32(status),
        Buffer.from(bodySha256, 'hex')
      ])
    )
    .digest('hex')
  return {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store',
    'Content-Length': String(body.byteLength),
    'X-Nachuan-Root-Protocol': '1',
    'X-Nachuan-Root-Request-Nonce': requestNonce,
    'X-Nachuan-Root-Response-Body-SHA256': bodySha256,
    'X-Nachuan-Root-Response-Signature': signature
  }
}

function changedHex(value: string): string {
  return `${value[0] === '0' ? '1' : '0'}${value.slice(1)}`
}

async function readRequest(request: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = []
  for await (const chunk of request) chunks.push(Buffer.from(chunk))
  return Buffer.concat(chunks)
}

async function withLoopbackServer<T>(
  handler: (request: IncomingMessage, response: ServerResponse) => void,
  run: (port: number) => Promise<T>
): Promise<T> {
  const server = createServer(handler)
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject)
    server.listen({ host: '127.0.0.1', port: 0, exclusive: true }, resolve)
  })
  const address = server.address() as AddressInfo
  try {
    return await run(address.port)
  } finally {
    server.closeAllConnections()
    await new Promise<void>((resolve) => server.close(() => resolve()))
  }
}

describe('installation-root protocol vectors', () => {
  it('matches the frozen Python request and response HMAC vectors byte-for-byte', () => {
    const request = signInstallationRootRequest({
      bootToken: BOOT_TOKEN,
      method: 'POST',
      path: VECTOR_PATH,
      body: REQUEST_BODY,
      timestampMs: TIMESTAMP_MS,
      nonce: NONCE
    })

    expect(request.bodySha256).toBe(
      'c4b40a3c7f3e201c7d569ad3bb8843f34e03df348fe6370fecc23449685e950a'
    )
    expect(request.headers['X-Nachuan-Root-Signature']).toBe(
      'f6560bd9f2a516796fca9762742e69210c8a2fc375817df63831812f31c80bf4'
    )
    expect(JSON.stringify(request)).not.toContain(BOOT_TOKEN)

    const responseBody = Buffer.from('{"error":"fenced"}', 'utf8')
    expect(() =>
      verifyInstallationRootResponse({
        bootToken: BOOT_TOKEN,
        requestNonce: NONCE,
        status: 409,
        rawHeaders: [
          'X-Nachuan-Root-Protocol',
          '1',
          'X-Nachuan-Root-Request-Nonce',
          NONCE,
          'X-Nachuan-Root-Response-Body-SHA256',
          'cc7566fcc1963e31bfe59eb56d9d3c68589fbb9d12ce9ae21e98bdc489920541',
          'X-Nachuan-Root-Response-Signature',
          '07601f6202fff71bb1448497aa6615c972ed1de5652eb297153afd935351e9ec'
        ],
        body: responseBody
      })
    ).not.toThrow()
  })
})

describe('installation-root closed business DTOs', () => {
  const requests: readonly [InstallationRootPath, Record<string, unknown>][] = [
    [
      INSTALLATION_ROOT_PATHS.desktopBind,
      {
        installationId: DIGEST_A,
        epoch: 1,
        identity: DIGEST_B,
        stateDigest: DIGEST_C,
        expectedRootRevision: 1,
        sequenceFloor: 0
      }
    ],
    [
      INSTALLATION_ROOT_PATHS.desktopVerify,
      {
        installationId: DIGEST_A,
        epoch: 1,
        identity: DIGEST_B,
        sequenceFloor: 7,
        stateDigest: DIGEST_C,
        previousStateDigest: null
      }
    ],
    [
      INSTALLATION_ROOT_PATHS.desktopAdvance,
      {
        installationId: DIGEST_A,
        epoch: 1,
        identity: DIGEST_B,
        expectedFloor: 6,
        expectedStateDigest: DIGEST_C,
        nextFloor: 7,
        nextStateDigest: DIGEST_A,
        expectedRootRevision: 7
      }
    ],
    [
      INSTALLATION_ROOT_PATHS.desktopRecoveryAck,
      {
        installationId: DIGEST_A,
        epoch: 1,
        identity: DIGEST_B,
        recoveryFloor: 7,
        recoveryStateDigest: DIGEST_C,
        nextFloor: 8,
        nextStateDigest: DIGEST_A,
        expectedRootRevision: 8
      }
    ],
    [
      INSTALLATION_ROOT_PATHS.updaterVerify,
      {
        installationId: DIGEST_A,
        epoch: 1,
        releaseSequence: 0,
        keyringSequence: 0,
        artifactDigest: ZERO_DIGEST,
        stateDigest: ZERO_DIGEST,
        previous: null
      }
    ],
    [
      INSTALLATION_ROOT_PATHS.updaterAdvance,
      {
        installationId: DIGEST_A,
        epoch: 1,
        expectedReleaseSequence: 0,
        expectedKeyringSequence: 0,
        expectedArtifactDigest: ZERO_DIGEST,
        expectedStateDigest: ZERO_DIGEST,
        nextReleaseSequence: 1,
        nextKeyringSequence: 0,
        nextArtifactDigest: DIGEST_B,
        nextStateDigest: DIGEST_C,
        expectedRootRevision: 8
      }
    ]
  ]

  it.each(requests)('accepts only the exact request DTO for %s', (path, request) => {
    expect(validateInstallationRootRequest(path, request)).toEqual(request)
    expect(() =>
      validateInstallationRootRequest(path, { ...request, unexpected: true })
    ).toThrow('request schema')
    const missing = { ...request }
    delete missing.installationId
    expect(() => validateInstallationRootRequest(path, missing)).toThrow('request schema')
    expect(() =>
      validateInstallationRootRequest(path, { ...request, epoch: true })
    ).toThrow('request schema')
  })

  it('rejects component floor transitions that reuse the previous state digest', () => {
    const shared = '44'.repeat(32)
    expect(() =>
      validateInstallationRootRequest(INSTALLATION_ROOT_PATHS.desktopAdvance, {
        installationId: DIGEST_A,
        epoch: 1,
        identity: DIGEST_B,
        expectedFloor: 7,
        expectedStateDigest: shared,
        nextFloor: 8,
        nextStateDigest: shared,
        expectedRootRevision: 9
      })
    ).toThrow('request schema')
    expect(() =>
      validateInstallationRootRequest(INSTALLATION_ROOT_PATHS.desktopRecoveryAck, {
        installationId: DIGEST_A,
        epoch: 1,
        identity: DIGEST_B,
        recoveryFloor: 7,
        recoveryStateDigest: shared,
        nextFloor: 8,
        nextStateDigest: shared,
        expectedRootRevision: 9
      })
    ).toThrow('request schema')
  })

  it('requires updater previous proof to be null or one exact complete nested object', () => {
    const base = requests.find(([path]) => path === INSTALLATION_ROOT_PATHS.updaterVerify)![1]
    const complete = {
      ...base,
      previous: {
        releaseSequence: 0,
        keyringSequence: 0,
        artifactDigest: ZERO_DIGEST,
        stateDigest: ZERO_DIGEST
      }
    }
    expect(validateInstallationRootRequest(INSTALLATION_ROOT_PATHS.updaterVerify, complete))
      .toEqual(complete)
    expect(() =>
      validateInstallationRootRequest(INSTALLATION_ROOT_PATHS.updaterVerify, {
        ...complete,
        previous: { releaseSequence: 0 }
      })
    ).toThrow('request schema')
  })

  it('parses exact snapshot/mutation envelopes and rejects nested extra, missing, or type drift', () => {
    const snapshotEnvelope = {
      schema: 'nachuan.installation-root.snapshot.v1',
      snapshot: validSnapshot()
    }
    const { ownerSidDigest: _removedOwnerSidDigest, ...missingSnapshotField } =
      snapshotEnvelope.snapshot
    expect(
      parseInstallationRootSnapshotResponse({ status: 200, body: snapshotEnvelope })
    ).toEqual(snapshotEnvelope)
    expect(
      parseInstallationRootMutationResponse({ status: 200, body: mutationEnvelope() })
    ).toEqual(mutationEnvelope())

    for (const body of [
      { ...snapshotEnvelope, extra: true },
      {
        ...snapshotEnvelope,
        snapshot: { ...snapshotEnvelope.snapshot, rootRevision: true }
      },
      { ...snapshotEnvelope, snapshot: missingSnapshotField },
      {
        ...snapshotEnvelope,
        snapshot: {
          ...snapshotEnvelope.snapshot,
          components: {
            ...snapshotEnvelope.snapshot.components,
            desktop: {
              ...snapshotEnvelope.snapshot.components.desktop,
              extra: true
            }
          }
        }
      },
      {
        ...snapshotEnvelope,
        snapshot: {
          ...snapshotEnvelope.snapshot,
          updater: { ...snapshotEnvelope.snapshot.updater, stateDigest: 'A'.repeat(64) }
        }
      }
    ]) {
      expect(() =>
        parseInstallationRootSnapshotResponse({
          status: 200,
          body: body as unknown as Record<string, unknown>
        })
      ).toThrow('response schema')
    }

    const mutation = mutationEnvelope()
    const { recovered: _removedRecovered, ...missingMutationField } = mutation
    for (const body of [
      { ...mutation, extra: true },
      missingMutationField,
      { ...mutation, applied: 'true' }
    ]) {
      expect(() =>
        parseInstallationRootMutationResponse({
          status: 200,
          body: body as unknown as Record<string, unknown>
        })
      ).toThrow('response schema')
    }
  })
})

describe('InstallationRootClient transport', () => {
  it('uses one exact signed loopback route and returns only a no-store JSON object', async () => {
    await withLoopbackServer(
      (request, response) => {
        void (async () => {
          const body = await readRequest(request)
          expect(request.method).toBe('POST')
          expect(request.url).toBe(INSTALLATION_ROOT_PATHS.desktopAdvance)
          expect(JSON.parse(body.toString('utf8'))).toEqual({
            installationId: DIGEST_A,
            epoch: 1,
            identity: DIGEST_B,
            expectedFloor: 6,
            expectedStateDigest: DIGEST_C,
            nextFloor: 7,
            nextStateDigest: DIGEST_A,
            expectedRootRevision: 7
          })
          expect(JSON.stringify(request.rawHeaders)).not.toContain(BOOT_TOKEN)

          const raw = new Map<string, string>()
          for (let index = 0; index < request.rawHeaders.length; index += 2) {
            raw.set(request.rawHeaders[index].toLowerCase(), request.rawHeaders[index + 1])
          }
          const timestamp = Number(raw.get('x-nachuan-root-timestamp-ms'))
          const nonce = raw.get('x-nachuan-root-nonce') ?? ''
          const digest = createHash('sha256').update(body).digest('hex')
          const expectedSignature = createHmac('sha256', Buffer.from(BOOT_TOKEN, 'hex'))
            .update(
              frame('nachuan.installation-root.internal.request.v1', [
                u64(timestamp),
                Buffer.from(nonce, 'hex'),
                Buffer.from('POST', 'ascii'),
                Buffer.from(INSTALLATION_ROOT_PATHS.desktopAdvance, 'ascii'),
                Buffer.from(digest, 'hex')
              ])
            )
            .digest('hex')
          expect(raw.get('x-nachuan-root-body-sha256')).toBe(digest)
          expect(raw.get('x-nachuan-root-signature')).toBe(expectedSignature)

          const responseBody = Buffer.from(JSON.stringify(mutationEnvelope()), 'utf8')
          response.writeHead(
            200,
            signedResponseHeaders(BOOT_TOKEN, nonce, 200, responseBody)
          )
          response.end(responseBody)
        })().catch((error) => response.destroy(error as Error))
      },
      async (port) => {
        const session = { generation: 1, pid: 4321, port, bootToken: BOOT_TOKEN }
        const client = new InstallationRootClient({ session: () => session })
        const result = await client.advanceDesktop({
          installationId: DIGEST_A,
          epoch: 1,
          identity: DIGEST_B,
          expectedFloor: 6,
          expectedStateDigest: DIGEST_C,
          nextFloor: 7,
          nextStateDigest: DIGEST_A,
          expectedRootRevision: 7
        })
        expect(result).toEqual(mutationEnvelope())
        expect(JSON.stringify(result)).not.toContain(BOOT_TOKEN)
      }
    )
  })

  it('turns only the exact closed error envelope into a typed business error', async () => {
    await withLoopbackServer(
      (request, response) => {
        void (async () => {
          await readRequest(request)
          const nonce = String(request.headers['x-nachuan-root-nonce'])
          const body = Buffer.from(
            JSON.stringify({
              schema: 'nachuan.installation-root.error.v1',
              code: 'root_locked'
            }),
            'utf8'
          )
          response.writeHead(409, signedResponseHeaders(BOOT_TOKEN, nonce, 409, body))
          response.end(body)
        })().catch((error) => response.destroy(error as Error))
      },
      async (port) => {
        const client = new InstallationRootClient({
          session: () => ({ generation: 1, pid: 4321, port, bootToken: BOOT_TOKEN })
        })
        try {
          await client.snapshot()
          throw new Error('expected typed installation-root error')
        } catch (error) {
          expect(error).toBeInstanceOf(InstallationRootBusinessError)
          expect(error).toMatchObject({ status: 409, code: 'root_locked' })
          expect(String(error)).not.toContain(BOOT_TOKEN)
        }
      }
    )

    const malformed: InstallationRootJsonResponse = {
      status: 409,
      body: {
        schema: 'nachuan.installation-root.error.v1',
        code: 'root_locked',
        detail: 'must not cross the boundary'
      }
    }
    expect(() => parseInstallationRootSnapshotResponse(malformed)).toThrow('response schema')
    expect(() =>
      parseInstallationRootSnapshotResponse({
        status: 409,
        body: {
          schema: 'nachuan.installation-root.error.v1',
          code: 'root_locked_with_detail'
        }
      })
    ).toThrow('response schema')
  })

  it('freezes the seven exact v1 method/path pairs and rejects query or method drift', async () => {
    expect(INSTALLATION_ROOT_PATHS).toEqual({
      snapshot: '/internal/v1/installation-root/snapshot',
      desktopBind: '/internal/v1/installation-root/components/desktop/bind',
      desktopVerify: '/internal/v1/installation-root/components/desktop/verify',
      desktopAdvance: '/internal/v1/installation-root/components/desktop/advance',
      desktopRecoveryAck:
        '/internal/v1/installation-root/components/desktop/recovery/ack',
      updaterVerify: '/internal/v1/installation-root/updater/verify',
      updaterAdvance: '/internal/v1/installation-root/updater/advance'
    })
    const client = new InstallationRootClient({
      session: () => ({ generation: 1, pid: 1, port: 65_535, bootToken: BOOT_TOKEN })
    })
    await expect(
      client.signedJsonCall({
        method: 'GET',
        path: `${INSTALLATION_ROOT_PATHS.snapshot}?debug=1` as InstallationRootPath
      })
    ).rejects.toThrow('not allowed')
    await expect(
      client.signedJsonCall({
        method: 'POST',
        path: INSTALLATION_ROOT_PATHS.snapshot,
        body: {}
      })
    ).rejects.toThrow('not allowed')
    await expect(
      client.signedJsonCall({
        method: 'POST',
        path: INSTALLATION_ROOT_PATHS.desktopAdvance,
        body: { toJSON: () => [] }
      })
    ).rejects.toThrow('must encode a JSON object')
  })

  it.each(['body', 'status', 'nonce', 'digest', 'signature'] as const)(
    'rejects a one-bit %s change in the response authentication tuple',
    async (tamper) => {
      await withLoopbackServer(
        (request, response) => {
          void (async () => {
            await readRequest(request)
            const requestNonce = String(request.headers['x-nachuan-root-nonce'])
            const signedBody = Buffer.from('{"ok":true}', 'utf8')
            const wireBody =
              tamper === 'body'
                ? Buffer.from('{"ok":trud}', 'utf8')
                : signedBody
            const signedStatus = tamper === 'status' ? 201 : 200
            const headers = signedResponseHeaders(
              BOOT_TOKEN,
              requestNonce,
              signedStatus,
              signedBody
            )
            headers['Content-Length'] = String(wireBody.byteLength)
            if (tamper === 'nonce') {
              headers['X-Nachuan-Root-Request-Nonce'] = changedHex(requestNonce)
            } else if (tamper === 'digest') {
              headers['X-Nachuan-Root-Response-Body-SHA256'] = changedHex(
                headers['X-Nachuan-Root-Response-Body-SHA256']
              )
            } else if (tamper === 'signature') {
              headers['X-Nachuan-Root-Response-Signature'] = changedHex(
                headers['X-Nachuan-Root-Response-Signature']
              )
            }
            response.writeHead(200, headers)
            response.end(wireBody)
          })().catch((error) => response.destroy(error as Error))
        },
        async (port) => {
          const client = new InstallationRootClient({
            session: () => ({ generation: 1, pid: 1234, port, bootToken: BOOT_TOKEN })
          })
          await expect(client.snapshot()).rejects.toThrow('authentication failed')
        }
      )
    }
  )

  it.each(['duplicate', 'unknown'] as const)(
    'rejects %s root security headers from rawHeaders',
    async (kind) => {
      await withLoopbackServer(
        (request, response) => {
          void (async () => {
            await readRequest(request)
            const nonce = String(request.headers['x-nachuan-root-nonce'])
            const body = Buffer.from('{"ok":true}', 'utf8')
            const pairs = Object.entries(
              signedResponseHeaders(BOOT_TOKEN, nonce, 200, body)
            ) as [string, string][]
            pairs.push(
              kind === 'duplicate'
                ? ['x-nachuan-root-protocol', '1']
                : ['X-Nachuan-Root-Unrecognised', '1']
            )
            response.writeHead(200, pairs)
            response.end(body)
          })().catch((error) => response.destroy(error as Error))
        },
        async (port) => {
          const client = new InstallationRootClient({
            session: () => ({ generation: 1, pid: 1234, port, bootToken: BOOT_TOKEN })
          })
          await expect(client.snapshot()).rejects.toThrow(/duplicate|Unknown/)
        }
      )
    }
  )

  it('rejects contradictory Content-Length and non-object or cacheable JSON', async () => {
    for (const kind of ['length', 'array', 'cacheable'] as const) {
      await withLoopbackServer(
        (request, response) => {
          void (async () => {
            await readRequest(request)
            const nonce = String(request.headers['x-nachuan-root-nonce'])
            const body = Buffer.from(kind === 'array' ? '[]' : '{"ok":true}', 'utf8')
            const headers = signedResponseHeaders(BOOT_TOKEN, nonce, 200, body)
            if (kind === 'length') headers['Content-Length'] = String(body.byteLength + 1)
            if (kind === 'cacheable') headers['Cache-Control'] = 'private'
            response.writeHead(200, headers)
            response.end(body)
          })().catch((error) => response.destroy(error as Error))
        },
        async (port) => {
          const client = new InstallationRootClient({
            session: () => ({ generation: 1, pid: 1234, port, bootToken: BOOT_TOKEN })
          })
          await expect(client.snapshot()).rejects.toThrow()
        }
      )
    }
  })

  it('enforces 64 KiB on both request and response bodies', async () => {
    const offline = new InstallationRootClient({
      session: () => ({ generation: 1, pid: 1, port: 65_535, bootToken: BOOT_TOKEN })
    })
    await expect(
      offline.signedJsonCall({
        method: 'POST',
        path: INSTALLATION_ROOT_PATHS.desktopAdvance,
        body: { payload: 'x'.repeat(64 * 1024) }
      })
    ).rejects.toThrow('request exceeds')

    await withLoopbackServer(
      (request, response) => {
        void (async () => {
          await readRequest(request)
          const nonce = String(request.headers['x-nachuan-root-nonce'])
          const body = Buffer.from(JSON.stringify({ payload: 'x'.repeat(64 * 1024) }), 'utf8')
          const headers = signedResponseHeaders(BOOT_TOKEN, nonce, 200, body)
          delete headers['Content-Length']
          response.writeHead(200, headers)
          response.end(body)
        })().catch((error) => response.destroy(error as Error))
      },
      async (port) => {
        const client = new InstallationRootClient({
          session: () => ({ generation: 1, pid: 1234, port, bootToken: BOOT_TOKEN })
        })
        await expect(client.snapshot()).rejects.toThrow('response exceeds')
      }
    )
  })

  it('does not follow redirects and bounds slow responses to at most two seconds', async () => {
    await withLoopbackServer(
      (_request, response) => {
        response.writeHead(302, { Location: 'http://example.invalid/steal' })
        response.end()
      },
      async (port) => {
        const client = new InstallationRootClient({
          session: () => ({ generation: 1, pid: 1234, port, bootToken: BOOT_TOKEN })
        })
        await expect(client.snapshot()).rejects.toThrow('redirects are forbidden')
      }
    )

    await withLoopbackServer(
      () => undefined,
      async (port) => {
        const client = new InstallationRootClient({
          session: () => ({ generation: 1, pid: 1234, port, bootToken: BOOT_TOKEN }),
          timeoutMs: 25
        })
        const started = Date.now()
        await expect(client.snapshot()).rejects.toThrow('timed out')
        expect(Date.now() - started).toBeLessThan(1_000)
      }
    )
  })

  it('supports caller abort without allowing an unbounded request', async () => {
    await withLoopbackServer(
      () => undefined,
      async (port) => {
        const controller = new AbortController()
        const client = new InstallationRootClient({
          session: () => ({ generation: 1, pid: 1234, port, bootToken: BOOT_TOKEN })
        })
        const pending = client.snapshot({ signal: controller.signal })
        controller.abort()
        await expect(pending).rejects.toThrow('aborted')
      }
    )
  })

  it.each(['generation', 'pid', 'port', 'bootToken'] as const)(
    'rejects a response after isolated %s session drift',
    async (field) => {
      let session = { generation: 1, pid: 1234, port: 0, bootToken: BOOT_TOKEN }
      await withLoopbackServer(
        (request, response) => {
          void (async () => {
            await readRequest(request)
            const nonce = String(request.headers['x-nachuan-root-nonce'])
            const body = Buffer.from('{"ok":true}', 'utf8')
            session = {
              ...session,
              ...(field === 'generation' ? { generation: 2 } : {}),
              ...(field === 'pid' ? { pid: 5678 } : {}),
              ...(field === 'port'
                ? { port: session.port === 65_535 ? 65_534 : session.port + 1 }
                : {}),
              ...(field === 'bootToken' ? { bootToken: '22'.repeat(32) } : {})
            }
            response.writeHead(200, signedResponseHeaders(BOOT_TOKEN, nonce, 200, body))
            response.end(body)
          })().catch((error) => response.destroy(error as Error))
        },
        async (port) => {
          session = { ...session, port }
          const client = new InstallationRootClient({ session: () => session })
          await expect(client.snapshot()).rejects.toThrow('session changed')
        }
      )
    }
  )

  it('rejects a late old-port response after generation/pid/port/token all rotate', async () => {
    let session = { generation: 1, pid: 1234, port: 0, bootToken: BOOT_TOKEN }
    await withLoopbackServer(
      (request, response) => {
        void (async () => {
          await readRequest(request)
          const nonce = String(request.headers['x-nachuan-root-nonce'])
          const body = Buffer.from('{"ok":true}', 'utf8')
          session = {
            generation: 2,
            pid: 5678,
            port: session.port === 65_535 ? 65_534 : session.port + 1,
            bootToken: '22'.repeat(32)
          }
          setTimeout(() => {
            response.writeHead(200, signedResponseHeaders(BOOT_TOKEN, nonce, 200, body))
            response.end(body)
          }, 20)
        })().catch((error) => response.destroy(error as Error))
      },
      async (port) => {
        session = { ...session, port }
        const client = new InstallationRootClient({ session: () => session })
        await expect(client.snapshot()).rejects.toThrow('session changed')
      }
    )
  })

  it('never exposes an invalid or echoed boot token in headers, errors, or results', async () => {
    const invalidToken = 'A'.repeat(64)
    const invalid = new InstallationRootClient({
      session: () => ({ generation: 1, pid: 1, port: 65_535, bootToken: invalidToken })
    })
    let invalidError = ''
    try {
      await invalid.snapshot()
    } catch (error) {
      invalidError = String(error)
    }
    expect(invalidError).not.toContain(invalidToken)

    await withLoopbackServer(
      (request, response) => {
        void (async () => {
          await readRequest(request)
          expect(JSON.stringify(request.rawHeaders)).not.toContain(BOOT_TOKEN)
          const nonce = String(request.headers['x-nachuan-root-nonce'])
          const escapedToken = [...BOOT_TOKEN]
            .map((character) => `\\u${character.charCodeAt(0).toString(16).padStart(4, '0')}`)
            .join('')
          const body = Buffer.from(`{"echoed":"${escapedToken}"}`, 'utf8')
          expect(body.toString('utf8')).not.toContain(BOOT_TOKEN)
          response.writeHead(200, signedResponseHeaders(BOOT_TOKEN, nonce, 200, body))
          response.end(body)
        })().catch((error) => response.destroy(error as Error))
      },
      async (port) => {
        const client = new InstallationRootClient({
          session: () => ({ generation: 1, pid: 1234, port, bootToken: BOOT_TOKEN })
        })
        let errorText = ''
        try {
          await client.snapshot()
        } catch (error) {
          errorText = `${String(error)} ${JSON.stringify(error)}`
        }
        expect(errorText).toContain('forbidden authority material')
        expect(errorText).not.toContain(BOOT_TOKEN)
      }
    )
  })
})

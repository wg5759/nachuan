// Source-control template for clean-checkout tests; release workflows replace and separately freeze it.
import type { EmbeddedUpdateTrust } from './update-security'

export const EMBEDDED_UPDATE_TRUST: EmbeddedUpdateTrust = Object.freeze({
  "schema": 1,
  "enabled": false,
  "releaseTier": "disabled",
  "channel": "",
  "variant": "",
  "keyId": "",
  "publicKeySpkiBase64": "",
  "manifestUrl": "",
  "currentSequence": 0,
  "keyringSequence": 0,
  "keyringSha256": "",
  "publisherName": "",
  "signerThumbprint": ""
})

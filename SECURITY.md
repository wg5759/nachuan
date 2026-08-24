# Security Policy

## Supported surface

The public source release is an alpha developer release. It is local-first and
single-owner unless a component explicitly documents and proves a stronger
identity boundary. A shared runtime key is not enterprise multi-tenant auth.

Official binaries are supported only when they are published from the official
repository with their exact hashes and signing/provenance receipts. Until that
gate is met, source availability must not be read as an endorsement of an
unofficial binary.

## Reporting a vulnerability

Please use the repository's **Private vulnerability reporting / Security
Advisory** page. Do not open a public issue containing an unpatched exploit,
credential, customer data, private endpoint, or security-sensitive proof of
concept.

A useful report includes:

- affected version or commit;
- exact component and trust boundary;
- minimal reproduction against current source or an official artifact;
- demonstrated impact;
- suggested containment or remediation when available.

Scanner output without a reachable path and demonstrated impact is useful as a
lead, but is not by itself proof that the shipped product is vulnerable.

## Trust boundaries

- Third-party and model-written plugins are untrusted. They must not run in the
  privileged Engine/Main process; use an isolated worker, AppContainer, VM, or
  remote runner with narrow capability receipts.
- Plugin manifests do not grant authority by declaration. Identity, tenant
  binding, credentials, financial/idempotency ledgers, enterprise RAG final
  authorization, audit truth, and install/update trust remain kernel gates.
- The local filesystem, DPAPI/safeStorage, and same Windows SID are not an
  isolation boundary against malicious code already running as that user.
- Prompt injection is untrusted input. A model response cannot authorize a
  payment, public action, credential read, channel send, or destructive change.
- An HTTP 200, process liveness, test pass, or generated file is not proof of
  real channel delivery, production readiness, or absence of malware.

## Secrets and personal data

Never submit real credentials, cookies, private keys, customer documents,
conversation databases, provider receipts, or machine-specific logs. Use
synthetic fixtures. If a secret is exposed, revoke it at the provider; deleting
it from Git does not revoke it.

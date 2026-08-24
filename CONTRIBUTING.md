# Contributing to Nachuan

Nachuan welcomes focused fixes, tests, documentation, provider adapters, tools,
workflows, and plugins that preserve the project's trust boundaries.

## Before opening a change

1. Open or reference an issue that states the user or operational problem.
2. Keep one change focused on one verifiable outcome.
3. Add a red-capable regression test for behavior changes.
4. Run the affected tests and include exact terminal evidence.
5. Mark AI-assisted work and confirm that you understand and have reviewed it.
6. Never include credentials, personal data, customer data, or private logs.

Typical checks:

```powershell
.\.venv\Scripts\python.exe -X utf8 -m pytest -q <affected tests>
npm --prefix desktop run typecheck
git diff --check
```

Changes to packaging, provider identity, plugins, credentials, payment/media,
channels, enterprise auth, RAG authorization, updates, or public release gates
need their dedicated security and artifact tests as well.

## Plugin contributions

- New capability consumers depend on a stable Service Definition, not a
  concrete provider implementation.
- In-process plugins are restricted to built-in, reviewed components shipped in
  the official source/artifact closure.
- Third-party plugins require an isolated runtime, exact-version manifest,
  declared data/network scopes, SBOM/license evidence, and unload/rollback tests.
- A plugin cannot replace or bypass identity, tenant, credential, financial,
  audit, enterprise-RAG authorization, or update-trust choke points.
- Approval is bound to the exact plugin version, digest, and capability set.

## Developer Certificate of Origin

Contributions use the Developer Certificate of Origin 1.1. Add a sign-off to
each commit:

```text
Signed-off-by: Your Name <you@example.com>
```

By signing off, you certify that you have the right to submit the contribution
under this project's license. See https://developercertificate.org/.

## Pull-request evidence

Describe:

- the problem and user impact;
- the chosen boundary and rejected alternatives;
- tests run and their results;
- any remaining non-acceptance or production gate.

Do not describe a source-only, simulated, clean-build, installed, real-channel,
or production result as another evidence level.

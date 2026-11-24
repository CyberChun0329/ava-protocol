# AVA Core / SDK 0.1.0-preview.12

This developer preview includes four matching Apache-2.0 packages and the
WorkOrder example. Use it to install an independent application on a local chain
and verify the Core and SDK version it uses.

## Verify and run

Use Node 24 or newer, npm, tar, Foundry (reference 1.5.1-stable), and solc 0.8.26.
Install these ordinary tools before running the check. On macOS the verifier
also recognises the standard SVM installation under `Library/Application Support/svm`.
For another compiler location, set `AVA_PREVIEW_SOLC` to the executable.

```sh
node verify.mjs --verify-only
node verify.mjs --workdir "$PWD/../ava-work-order-acceptance"
```

The work directory must not exist. The verifier checks every payload and all
four package versions, hashes and exact internal dependencies before installing.
It then uses the bundled lockfile with `npm ci`, an initially empty private npm
cache, private compiler output/cache, and a copied, fingerprinted solc executable.
It needs network access for public npm dependencies and loopback access for a
disposable Anvil node. No repository checkout, workspace links, shared npm/Forge
cache, real wallet, credentials or model API is used. The toolchain executable
itself is a prerequisite, not a reused compilation artifact.

The check compiles the required Solidity sources from scratch with Cancun, viaIR, 200
optimiser runs and metadata bytecode hash `none`. It installs its own app from
Core-only bootstrap receipts and public SDK deployment exports, signs using
synthetic local actors, submits through the public service HTTP interface and
checks recognised state, Allocation, once-only execution, finite correction and
unchanged original history. Invalid actors, absent Allocation, revoked authority,
changed parameters and repeated execution must be rejected. The valid workflow
must still complete.

The separate lifecycle run checks canonical deployment export, administrator
handover, governed retirement of new WorkOrder intake, and a historical
correction after retirement. A signed closure is interrupted before it reaches
the node. Reading and observing keep the original key and hash. Explicit recovery
submits the original signed bytes and observes the canonical receipt after a
second interruption, this time after the node accepts the transaction. The
approved WorkOrder closes once.

Evidence, dependency lock, logs, source/package hashes, compiler identity and raw
receipts remain in the new work directory, including after failure. See
`verification.json`, `lifecycle-evidence.json` and `evidence.json`. The three paired profiles compare split
and combined formation, then fresh and shared stateless policies. Core setup,
shared policy setup, app installation and acceptance-only permission rotations
are counted separately. Vesting and distinct actors remain separate. Local gas
and transaction counts do not predict Base fees, finality or real-world service
completion time; no waiting period is shortened.

While a command is running, `SIGINT` and `SIGTERM` are forwarded to it. The
verifier waits for its cleanup, retains the command log, and finishes with a
failed verification receipt even if that command exits zero after interruption.
Start any later acceptance in a new work directory; the failed directory remains
available for diagnosis.

## Consume the packages

Install the SDK alone when sufficient. The Agent SDK and local service require
the exact SDK version in `manifest.json`; contracts and SDK belong to the same
verified compatibility group. `work-order/package.json` shows relative archive
dependencies and `package-lock.json` fixes all dependencies for this example.
The optional Agent SDK is imported during this check but no model is called.
The contracts archive contains generic sources and Core installation helpers,
while WorkOrder workflow rules and effect adapter remain application-owned.

The local service currently supports one process, loopback HTTP and chain 31337.
Private custody, arbitrary custom policy implementations and external production
systems require their own operating and security review. A fixed external audit
and deployment acceptance remain necessary before real-value use.

`manifest.json` pins component archives, unchanged runtime/source contents,
packaging inputs and supported compatibility. Only release metadata and README
version references differ from workspace 0.1.0 packages. The outer `.sha256`
file identifies the delivered tar archive. Obtain that hash through your trusted
handoff: hashes detect changes, but do not authenticate the publisher. Do not mix
archives from different previews or overwrite a fixed preview with changed code.

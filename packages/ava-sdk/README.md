# AVA Protocol SDK

Use the TypeScript SDK to read AVA records at a fixed block, build calls and check receipts. `AvaSdk` and `AvaExtensions` require a compatible deployment and Node.js 24 or later. Use `localClient` for loopback HTTP RPC on your development machine.

Install the supplied archive in an independent project:

```sh
npm install ./ava-protocol-sdk-0.1.0.tgz
```

```js
import { AvaSdk, localClient } from '@ava-protocol/sdk';
const sdk = new AvaSdk(deployment); // Supply the deployment for your local chain.
const client = localClient('http://127.0.0.1:8545');
```

Supply your deployment configuration and a wallet for the authorised actor. Your application manages keys and calls signing and submission separately. The optional Agent SDK and local service have their own archives. See LICENSE and NOTICE for the Apache-2.0 terms.

Verify the configured chain and choose a block before using `sdk.simulate(client, account, call, applicationAbi, point?)` to test a call without signing. At signing time the SDK checks the current call again. For reads, `readRejection(error)` returns a safe reason or error name when the EVM reports a refusal or a revert decodes against the ABI. A result of `undefined` leaves the refusal unproven. Handle an RPC outage as a read failure.

`readRuntimeContext(client, remote, expected, options?)` checks that the relay and RPC agree on the chain ID and genesis. It verifies any saved checkpoint against the RPC and returns `{chainId, genesisHash, checkpoint: {blockNumber, blockHash}}` for the relay's indexed block. It synchronizes by default. Set `synchronize: false` to read health. Use `AvaRuntimeError` to distinguish `runtime_mismatch` from `runtime_unavailable`. Keep the app's trusted configuration and verify the installation separately. The checkpoint shows what the RPC and relay agreed on at read time and may later change in a reorganisation.

`sdk.verify(client, point?)` checks Core's code and contract links at one block. It reads independent addresses concurrently and reports failures in configuration order. If the saved and relay checkpoint heights match, `readRuntimeContext` reads that block once from the RPC after the relay responds and checks both hashes. Each call reads again.

The SDK exposes the HTTP status and recognised AVA error codes. Other error text becomes `http_error`. For `confirmed` or `reverted`, the relay response must supply the mined block number, block hash and positive confirmations. Check the receipt against the chain when you need independent verification.

`sdk.sign` and `verifySignedIntent` support legacy, EIP-2930 and EIP-1559 transaction envelopes. Unsupported envelopes, including EIP-7702 authorization lists outside AVA call simulation, are refused before the signer is invoked.

`verifySignedIntent(serialized, {chainId, account, call})` verifies a supported canonical signed transaction against the expected signer, chain, target, calldata and value, returning `{hash, from, to, nonce}`. It neither signs nor submits; it does not establish current authority, nonce availability, fees, simulation success or inclusion. A mismatch raises `AvaSigningError` with stage `signing` and code `intent_mismatch`.

`submissionFailure(error)` distinguishes a known local relay rejection of this submission attempt from an uncertain service failure. A rejection is not proof that the transaction was never broadcast elsewhere and does not itself authorize releasing an application claim. `verifyNonceReplacement(client, {chainId, account, nonce, originalHash, replacementHash})` checks a caller-supplied different transaction against its mined receipt and the canonical chain: the replacement must have the same actor and nonce. Either a successful or reverted replacement consumes that nonce. The helper does not search chain history, sign or submit; a missing transaction or an advanced nonce alone is not replacement proof.

To recover a relay submission from an interrupted session:

1. Retrieve the original relay key, transaction hash and exact signed bytes from
   the caller's secure storage. The relay response contains no signed bytes.
2. Use `remote.observeTransaction({ key, hash }, { timeoutMs })` with that
   identity. If it confirms or reverts, read the application's effect separately.
   If observation times out or the RPC is unavailable, preserve the same identity.
3. When explicit rebroadcast is appropriate, call
   `remote.recoverSubmit(key, originalSignedBytes)`. The relay checks its existing
   identity, the chain and canonical receipt. It may resend an unresolved
   transaction with those bytes. Continue observing the original key and hash.

Only share the signed bytes with the intended relay. They can be broadcast by
any holder. Ordinary `submit` for an existing identity refreshes its status.


For an application's own Foundry deployment, the explicit Node-only subpath
provides public declarations from submitted broadcasts and matching receipts:

```js
import { exportPublicDeployment, foundryArtifactLoader } from '@ava-protocol/sdk/deployment';
const config = await exportPublicDeployment({
  broadcasts: [coreBroadcast, appBroadcast],
  artifact: foundryArtifactLoader('./out'),
  verification: { client }, // Optional. Verify mined associations against RPC before exporting.
});
```

The caller supplies the broadcasts and artifact directory; no repository-local
paths or example application are required. For a Core-only installation pass
`allowCoreOnly: true`; incomplete application profiles still fail. The result
declares expected configuration, not observed chain authority. Check it with
`verifyInstallation` before using the app. When a Decision extension is configured directly or discovered through Procedure, verification also probes the Matrix canonical-subject query at that same read point. A reported EVM refusal or inconsistent zero-authority result rejects the installation as a capability mismatch; transport failures remain unavailable. This read-only compatibility check does not establish authority or policy correctness, and does not repair the installation. The separately distributed
`@ava-protocol/contracts` archive supplies Solidity sources and a local Core
bootstrap script.

`@ava-protocol/sdk/costs` exposes the existing app-neutral signed-transaction cost sampler and optional Base fee projection. Importing it sends no request; only explicit caller operations use the supplied client. A local receipt or quote does not prove Base execution/finality. This module was moved from shared example code without changing its pricing or transaction semantics.

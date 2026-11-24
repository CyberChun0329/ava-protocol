# AVA Protocol Local Service

This ESM package provides a local AVA service, queue and query APIs. It requires Node.js 24 or later and is intended for a single process using a loopback RPC on local chain 31337. Install it together with the matching SDK archive:

```sh
npm install ./ava-protocol-sdk-0.1.0.tgz ./ava-protocol-local-service-0.1.0.tgz
```

```js
import { buildAvaService } from '@ava-protocol/local-service';
// Supply a local client, SDK, database path and access token as options.
const service = await buildAvaService(options);
```

Keep the access token and service configuration on the host. The caller signs transactions and decides when to submit or recover them. See LICENSE and NOTICE for the Apache-2.0 terms.

At startup the relay checks the chain ID and genesis against the query index. It checks that identity again on each transaction operation and handles reorganisations within the same chain. A shared sync waits for its outstanding identity reads to finish. Invalid bodies, content types and oversized requests return `400 invalid_request` before the service creates a transaction record.

## Recover an uncertain transaction

Keep the original idempotency key, transaction hash and exact signed bytes in
private storage. Anyone holding the signed bytes can broadcast them. The service
returns the transaction record without those bytes.

1. Query `GET /v1/transactions/:key` and inspect the original hash on the same
   local chain. `unknown` does not prove that the node rejected the transaction.
2. If a known cause prevented broadcasting, fix it first. For example, fund the
   sender if it lacked gas money. To explicitly retry through the relay, call
   `remote.recoverSubmit(key, originalSignedBytes)` with the original key and
   bytes. A local operator can also send the original bytes directly with
   `await client.sendRawTransaction({ serializedTransaction: originalSignedBytes })`.
   Confirm that the returned hash is the original. For an already-known response,
   look up that same hash.
3. Query the original key again until its canonical receipt reaches `confirmed`
   or `reverted`, or investigate why it remains uncertain.

Repeated calls to the ordinary submission endpoint with the same bytes refresh
the original record, including calls under an alias. The relay reserves the
sender and nonce for that transaction. Recovery needs the original signed bytes.

## Optional SDK toolbox modules

Use `@ava-protocol/local-service/custody` to store encrypted materials locally after your application authorises access. It exports `MaterialCustody`, `MaterialReceipt`, `LocalMaterialCustody` and a custody error that omits private details. Configure `appId`, `vaultPath` and `masterKeyFile`. `rootDirectory` defaults to the current directory and `pythonPath` to `python3`. Install `cryptography==50.0.2` in that Python environment. The archive includes the bridge and storage files for the v1/draft-policy1 receipt format.

`@ava-protocol/local-service/testing` is an optional Node/Foundry development entry. It supplies the existing local Anvil lifecycle/checkpoint inspector, artifact loader, decision-host deploy helpers, artifact-capacity admission and owned test-output cleanup. Foundry and the caller's compiled artifacts are external tools/inputs; it installs no business application by itself and is never imported by the normal relay entry. Use synthetic accounts only.

To run the installed service as a child process, resolve `@ava-protocol/local-service/cli` from your project. Set the child's working directory to that project and pass the configuration path as the first argument. Store the file within that directory. Relative `tokenPath` and `databasePath` values resolve from the child's working directory. You can also supply absolute paths for those two values.

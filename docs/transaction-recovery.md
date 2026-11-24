# Local transaction recovery

The local service accepts caller-signed transactions for chain 31337. It persists
the transaction identity and signed bytes before the first RPC broadcast. If the
status is `unknown`, the node may have accepted the transaction before the
response was lost.

## Read status together with receipt evidence

Status describes the latest verified observation, not an irreversible business
outcome. All keys for the same transaction hash share that observation.

| Status and evidence | Meaning | Caller action |
| --- | --- | --- |
| `pending`, with `blockHash` | A canonical receipt exists, but its confirmation depth is insufficient | Keep observing; recovery does not rebroadcast this mined transaction |
| `pending`, without `blockHash` | No current canonical receipt is established; the transaction may be visible to the node, or an earlier receipt may have been orphaned | Observe the original hash; this is not proof of execution or non-broadcast |
| `unknown` | Current execution evidence is unavailable or uncertain | Preserve the original identity; diagnose or explicitly recover the same bytes |
| `confirmed` / `reverted` | A canonical success / reverted receipt meets the configured depth | Read the business effect separately; a reverted call did not complete it |

A reorg or RPC failure can withdraw an earlier confirmed observation. Neither an
alias nor an unavailable receipt creates a new transaction identity. The relay
reports execution evidence; the application still interprets its recognised
state, Allocation and effect history.

## Observe the original transaction

1. Preserve the original key, transaction hash and exact signed bytes in the
   caller's secure custody. The service record omits the bytes. Anyone holding
   them can broadcast the transaction, so protect both the bytes and the service database.
2. Read `GET /v1/transactions/:key` or use `AvaServiceClient.observeTransaction`
   with the original key and hash. The service refreshes against the same chain.
   `confirmed` and `reverted` require the configured confirmation depth. An
   unavailable node, missing transaction or invalid execution status can leave
   the result uncertain.
3. Inspect the same local chain and hash, and resolve any known external cause
   such as insufficient sender funds. Repeating `submit` with the same bytes,
   including under an alias, refreshes the existing identity without rebroadcasting.

## Explicitly rebroadcast the original bytes

Use `AvaServiceClient.recoverSubmit(key, originalSignedBytes)` or send
`{ "serializedTransaction": originalSignedBytes }` to `POST /v1/transactions/:key/recover`.
The service requires the existing identity and exact bytes, verifies the current
chain context, and checks for a canonical receipt. It observes a verified mined
or terminal record without resending. If the result is still unresolved, explicit
recovery may resend the original bytes. If the node reports the transaction is
already known, continue observing the same hash.

The SDK's `readRuntimeContext` compares the relay's indexed block with the RPC
chain and any saved checkpoint. If a valid checkpoint is ahead of the first
head read, the SDK reads the head once more to allow for concurrent indexing.
It still requires the checkpoint hashes to agree with the canonical chain.

Recovery uses the same bounded admission and cancellation as submission. The
queue signal cancels waiting admission; it does not undo an active broadcast or
an already accepted transaction. Recovery does not sign, select a new nonce or reconstruct lost bytes. A different
transaction with the same sender and nonce cannot take over this identity.

If an application supports reconciling a nonce used by a different transaction,
`verifyNonceReplacement` checks the replacement against the original sender and
nonce, and checks that its hash occupies the receipt's reported position in the
canonical block. The replacement remains a separate transaction.


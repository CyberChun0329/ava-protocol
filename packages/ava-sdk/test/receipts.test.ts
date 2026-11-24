import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createPublicClient, custom, encodeAbiParameters, encodeEventTopics, parseAbi, toHex,
  type Abi, type Address, type Hex, type PublicClient } from 'viem';
import { readCanonicalEvent, readCreatedId, readCreatedIdPair, AvaReceiptError, type CreatedIdInput } from '../src/receipts.ts';
import type { CreatedBytes32IdInput, CreatedIdReceipt } from '../src/index.ts';

const abi = parseAbi(['event Created(uint256 indexed id, address owner)']);
const emitter = '0x0000000000000000000000000000000000000020' as Address;
const actor = '0x0000000000000000000000000000000000000030' as Address;
const hash = `0x${'11'.repeat(32)}` as const, blockHash = `0x${'22'.repeat(32)}` as const;
const input = { chainId: 31337, emitter, abi, eventName: 'Created', idField: 'id', confirmations: 2 };
function rpc() {
  const log = { address: emitter, data: encodeAbiParameters([{ type: 'address' }], [actor]),
    topics: encodeEventTopics({ abi, eventName: 'Created', args: { id: 7n } }),
    blockHash, blockNumber: '0x2a', transactionHash: hash, transactionIndex: '0x0', logIndex: '0x3', removed: false };
  const state = { chainId: '0x7a69', head: '0x2b', canonical: blockHash as string, missing: false, unavailable: false,
    chainIdGate: undefined as Promise<void> | undefined,
    receipt: { transactionHash: hash, blockHash, blockNumber: '0x2a', from: actor, to: emitter,
      transactionIndex: '0x0', contractAddress: null, cumulativeGasUsed: '0x5208', gasUsed: '0x5208',
      effectiveGasPrice: '0x1', logsBloom: `0x${'00'.repeat(256)}`, status: '0x1', type: '0x2', logs: [log] } };
  const client = createPublicClient({ cacheTime: 0, transport: custom({ request: async ({ method }) => {
    if (state.unavailable) throw new Error('SECRET-provider-context');
    if (method === 'eth_chainId') { await state.chainIdGate; return state.chainId; }
    if (method === 'eth_blockNumber') return state.head;
    if (method === 'eth_getBlockByNumber') return { number: '0x2a', hash: state.canonical, transactions: [] };
    assert.equal(method, 'eth_getTransactionReceipt');
    return state.missing ? null : state.receipt;
  } }, { retryCount: 0 }) });
  return { client, state, log };
}

test('canonical event exposes decoded fields and exact log identity with shared receipt checks', async () => {
  const { client, state, log } = rpc();
  const eventInput = { chainId: input.chainId, emitter, abi, eventName: 'Created', confirmations: 2 };
  const expected = { chainId: 31337, emitter, eventName: 'Created', transactionHash: hash,
    blockHash, blockNumber: 42n, logIndex: 3, confirmations: 2, args: { id: 7n, owner: actor } };
  assert.deepEqual(await readCanonicalEvent(client, hash, eventInput), expected);
  const second = { ...log, logIndex: '0x4', topics: encodeEventTopics({ abi, eventName: 'Created', args: { id: 12n } }) };
  state.receipt.logs = [log, second];
  await assert.rejects(readCanonicalEvent(client, hash, eventInput), { code: 'event_ambiguous' });
  assert.deepEqual(await readCanonicalEvent(client, hash, { ...eventInput, logIndex: 4 }),
    { ...expected, logIndex: 4, args: { id: 12n, owner: actor } });
  state.receipt.logs = [{ ...log, data: '0x' }, second];
  assert.deepEqual(await readCanonicalEvent(client, hash, { ...eventInput, logIndex: 4 }),
    { ...expected, logIndex: 4, args: { id: 12n, owner: actor } });
  await assert.rejects(readCanonicalEvent(client, hash, { ...eventInput, logIndex: 3 }), { code: 'invalid_receipt' });
  await assert.rejects(readCanonicalEvent(client, hash, eventInput), { code: 'invalid_receipt' });
  state.receipt.logs = [second, { ...log, logIndex: second.logIndex }];
  await assert.rejects(readCanonicalEvent(client, hash, { ...eventInput, logIndex: 4 }), { code: 'event_ambiguous' });
  state.receipt.logs = [log, second];
  await assert.rejects(readCanonicalEvent(client, hash, { ...eventInput, logIndex: 5 }), { code: 'event_missing' });
  await assert.rejects(readCanonicalEvent(client, hash, { ...eventInput, logIndex: -1 }), { code: 'invalid_request' });
  state.receipt.logs = [{ ...log, removed: true }];
  await assert.rejects(readCanonicalEvent(client, hash, eventInput), { code: 'receipt_mismatch' });
  state.receipt.logs = [log];
  state.canonical = hash;
  await assert.rejects(readCanonicalEvent(client, hash, eventInput), { code: 'orphaned' });
});

test('canonical events and created IDs reject the same failed receipt observations', async () => {
  for (const mode of ['pending', 'reverted', 'depth', 'orphaned', 'wrong-chain', 'wrong-log', 'bad-status'] as const) {
    const { client, state, log } = rpc();
    const codes = { pending: 'not_mined', reverted: 'reverted', depth: 'not_confirmed', orphaned: 'orphaned',
      'wrong-chain': 'chain_mismatch', 'wrong-log': 'receipt_mismatch', 'bad-status': 'invalid_receipt' };
    if (mode === 'pending') state.missing = true;
    if (mode === 'reverted') state.receipt.status = '0x0';
    if (mode === 'depth') state.head = '0x2a';
    if (mode === 'orphaned') state.canonical = hash;
    if (mode === 'wrong-chain') state.chainId = '0x1';
    if (mode === 'wrong-log') log.removed = true;
    if (mode === 'bad-status') state.receipt.status = '0x99';
    await assert.rejects(readCanonicalEvent(client, hash, input), { code: codes[mode] });
    await assert.rejects(readCreatedId(client, hash, input), { code: codes[mode] });
  }
});

test('a unique event from the expected emitter returns its actual ID and canonical provenance', async () => {
  const { client, state, log } = rpc();
  state.receipt.logs.unshift({ ...log, address: actor });
  const receipt = await readCreatedId(client, hash, input);
  const numericId: bigint = receipt.id;
  assert.equal(numericId, 7n);
  assert.deepEqual(receipt, {
    id: 7n, transactionHash: hash, blockHash, blockNumber: 42n,
    emitter, eventName: 'Created', logIndex: 3, confirmations: 2,
  });
});

test('a single created ID needs a valid receipt log index', async () => {
  const { client, state, log } = rpc();
  for (const logIndex of ['invalid', '-1', '0x20000000000000']) {
    state.receipt.logs = [{ ...log, logIndex }];
    await assert.rejects(readCreatedId(client, hash, input), { code: 'receipt_mismatch' });
  }
  state.receipt.logs = [{ ...log, logIndex: '0x0' }];
  assert.equal((await readCreatedId(client, hash, input)).logIndex, 0);
});

test('a pair requires two distinct canonical IDs from the emitter and follows log order', async () => {
  const { client, state, log } = rpc();
  const second = { ...log, logIndex: '0x4',
    topics: encodeEventTopics({ abi, eventName: 'Created', args: { id: 12n } }) };
  state.receipt.logs = [second, { ...log, address: actor }, log];
  const pair = await readCreatedIdPair(client, hash, input);
  assert.deepEqual(pair.map(item => [item.id, item.logIndex, item.blockHash]),
    [[7n, 3, blockHash], [12n, 4, blockHash]]);
  await assert.rejects(readCreatedId(client, hash, input), { code: 'event_ambiguous' });

  state.receipt.logs = [log];
  await assert.rejects(readCreatedIdPair(client, hash, input), { code: 'event_missing' });
  state.receipt.logs = [log, { ...second, logIndex: log.logIndex }];
  await assert.rejects(readCreatedIdPair(client, hash, input), { code: 'event_ambiguous' });
  state.receipt.logs = [log, { ...second, topics: log.topics }];
  await assert.rejects(readCreatedIdPair(client, hash, input), { code: 'event_ambiguous' });
  state.receipt.logs = [log, { ...second, blockHash: hash }];
  await assert.rejects(readCreatedIdPair(client, hash, input), { code: 'receipt_mismatch' });
  state.receipt.logs = [log, second];
  assert.deepEqual((await readCreatedIdPair(client, hash, input)).map(item => item.id), [7n, 12n]);
});

test('an explicit bytes32 ID is returned as typed hex with canonical receipt provenance', async () => {
  const { client, state, log } = rpc();
  const bytes32Abi = parseAbi(['event Created(bytes32 indexed id, address owner)']);
  const id = `0x${'Ab'.repeat(32)}` as Hex;
  const canonicalId = id.toLowerCase() as Hex;
  state.receipt.logs = [{ ...log, topics: encodeEventTopics({ abi: bytes32Abi, eventName: 'Created', args: { id } }) }];
  const opaqueInput: CreatedBytes32IdInput = { ...input, abi: bytes32Abi, idType: 'bytes32' };
  const receipt = await readCreatedId(client, hash, opaqueInput);
  const opaqueId: Hex = receipt.id;
  assert.equal(opaqueId, canonicalId);
  assert.deepEqual(receipt, {
    id: canonicalId, transactionHash: hash, blockHash, blockNumber: 42n,
    emitter, eventName: 'Created', logIndex: 3, confirmations: 2,
  });
});

test('a nonindexed bytes32 input is preserved and numeric mode never accepts hex IDs', async () => {
  const { client, state, log } = rpc();
  const nonindexedAbi = parseAbi(['event TermConfigured(bytes32 termId, bool active)']);
  const id = `0x${'cd'.repeat(32)}` as Hex;
  state.receipt.logs = [{ ...log,
    data: encodeAbiParameters([{ type: 'bytes32' }, { type: 'bool' }], [id, true]),
    topics: encodeEventTopics({ abi: nonindexedAbi, eventName: 'TermConfigured' }) }];
  const nonindexedInput: CreatedBytes32IdInput = { ...input, abi: nonindexedAbi,
    eventName: 'TermConfigured', idField: 'termId', idType: 'bytes32' };
  const receipt = await readCreatedId(client, hash, nonindexedInput);
  const opaqueId: Hex = receipt.id;
  assert.equal(opaqueId, id);
  await assert.rejects(readCreatedId(client, hash, { ...nonindexedInput, idType: 'uint' }), error =>
    error instanceof AvaReceiptError && error.code === 'invalid_id');
});

test('bytes32 mode requires one ABI field typed exactly bytes32 and only permits zero by opt-in', async () => {
  const { client, state, log } = rpc();
  const zero = `0x${'00'.repeat(32)}` as Hex;
  const bytes32Abi = parseAbi(['event Created(bytes32 indexed id, address owner)']);
  state.receipt.logs = [{ ...log, topics: encodeEventTopics({ abi: bytes32Abi, eventName: 'Created', args: { id: zero } }) }];
  const bytes32Input: CreatedBytes32IdInput = { ...input, abi: bytes32Abi, idType: 'bytes32' };
  await assert.rejects(readCreatedId(client, hash, bytes32Input), error =>
    error instanceof AvaReceiptError && error.code === 'invalid_id');
  assert.equal((await readCreatedId(client, hash, { ...bytes32Input, allowZeroId: true })).id, zero);

  const wrongTypes = [
    parseAbi(['event Created(uint256 indexed id, address owner)']),
    parseAbi(['event Created(address indexed id, address owner)']),
    parseAbi(['event Created(bytes id, address owner)']),
    parseAbi(['event Created(string id, address owner)']),
  ];
  for (const abi of wrongTypes) await assert.rejects(
    readCreatedId(client, hash, { ...bytes32Input, abi }), error =>
      error instanceof AvaReceiptError && error.code === 'invalid_request');
  const missing = parseAbi(['event Created(bytes32 indexed other, address owner)']);
  await assert.rejects(readCreatedId(client, hash, { ...bytes32Input, abi: missing }), error =>
    error instanceof AvaReceiptError && error.code === 'invalid_request');
  const duplicateName = [{ type: 'event', name: 'Created', anonymous: false, inputs: [
    { name: 'id', type: 'bytes32', indexed: true }, { name: 'id', type: 'bytes32', indexed: false },
  ] }] as unknown as Abi;
  await assert.rejects(readCreatedId(client, hash, { ...bytes32Input, abi: duplicateName }), error =>
    error instanceof AvaReceiptError && error.code === 'invalid_request');
});

test('bytes32 mode rejects duplicate matching events, foreign emitters and receipt-block mismatches', async () => {
  const { client, state, log } = rpc();
  const bytes32Abi = parseAbi(['event Created(bytes32 indexed id, address owner)']);
  const id = `0x${'ef'.repeat(32)}` as Hex;
  log.topics = encodeEventTopics({ abi: bytes32Abi, eventName: 'Created', args: { id } });
  const bytes32Input: CreatedBytes32IdInput = { ...input, abi: bytes32Abi, idType: 'bytes32' };
  state.receipt.logs = [log, { ...log, logIndex: '0x4' }];
  await assert.rejects(readCreatedId(client, hash, bytes32Input), error =>
    error instanceof AvaReceiptError && error.code === 'event_ambiguous');
  state.receipt.logs = [{ ...log, address: actor }];
  await assert.rejects(readCreatedId(client, hash, bytes32Input), error =>
    error instanceof AvaReceiptError && error.code === 'event_missing');
  state.receipt.logs = [{ ...log, blockHash: `0x${'33'.repeat(32)}` }];
  await assert.rejects(readCreatedId(client, hash, bytes32Input), error =>
    error instanceof AvaReceiptError && error.code === 'receipt_mismatch');
});

test('opaque receipt inputs are snapshotted before RPC and a later valid request still works', async () => {
  const { client, state, log } = rpc();
  const abi = structuredClone(parseAbi(['event TermConfigured(bytes32 indexed termId, address owner)']));
  const id = `0x${'42'.repeat(32)}` as Hex;
  log.topics = encodeEventTopics({ abi, eventName: 'TermConfigured', args: { termId: id } });
  state.receipt.logs = [log];
  let resume!: () => void;
  state.chainIdGate = new Promise<void>(resolve => { resume = resolve; });
  const mutableInput: CreatedBytes32IdInput = { ...input, abi,
    eventName: 'TermConfigured', idField: 'termId', idType: 'bytes32' };
  const observed = readCreatedId(client, hash, mutableInput);
  mutableInput.chainId = 1;
  mutableInput.emitter = actor;
  mutableInput.eventName = 'Redirected';
  mutableInput.idField = 'redirectedId';
  const mutableEvent = abi[0] as unknown as { name: string; inputs: { name: string }[] };
  mutableEvent.name = 'Redirected';
  mutableEvent.inputs[0].name = 'redirectedId';
  resume();
  const receipt = await observed;
  assert.equal(receipt.id, id);
  assert.equal(receipt.emitter, emitter);
  assert.equal(receipt.eventName, 'TermConfigured');

  const nextInput: CreatedBytes32IdInput = { ...input,
    abi: parseAbi(['event TermConfigured(bytes32 indexed termId, address owner)']),
    eventName: 'TermConfigured', idField: 'termId', idType: 'bytes32' };
  assert.equal((await readCreatedId(client, hash, nextInput)).id, id);
});

test('unknown ID modes and uncloneable inputs fail as invalid requests before RPC details escape', async () => {
  const { client, state } = rpc();
  state.unavailable = true;
  const invalidMode = { ...input, idType: 'string' } as unknown as CreatedIdInput;
  await assert.rejects(readCreatedId(client, hash, invalidMode), error =>
    error instanceof AvaReceiptError && error.code === 'invalid_request');
  const uncloneable = { ...input, privateContext: () => 'SECRET' } as unknown as CreatedIdInput;
  await assert.rejects(readCreatedId(client, hash, uncloneable), error => {
    assert(error instanceof AvaReceiptError);
    assert.equal(error.code, 'invalid_request');
    assert.equal(String(error).includes('SECRET'), false);
    return true;
  });
  assert.equal(state.unavailable, true);
});

function assertReceiptOverloads(client: PublicClient, numericInput: CreatedIdInput,
  opaqueInput: CreatedBytes32IdInput, unionInput: CreatedIdInput | CreatedBytes32IdInput) {
  const numeric: Promise<CreatedIdReceipt> = readCreatedId(client, hash, numericInput);
  const opaque: Promise<CreatedIdReceipt<Hex>> = readCreatedId(client, hash, opaqueInput);
  const union: Promise<CreatedIdReceipt<bigint | Hex>> = readCreatedId(client, hash, unionInput);
  return [numeric, opaque, union];
}
void assertReceiptOverloads;

function assertOpaqueModeIsNotAssignableToNumeric(opaqueInput: CreatedBytes32IdInput) {
  // @ts-expect-error bytes32 mode must stay discriminated from numeric ID callers
  const numericInput: CreatedIdInput = opaqueInput;
  // @ts-expect-error only the declared numeric and opaque ID modes are accepted
  const unknownMode: CreatedIdInput = { ...input, idType: 'string' };
  return [numericInput, unknownMode];
}
void assertOpaqueModeIsNotAssignableToNumeric;

test('incomplete, failed, orphaned or inconsistent transactions never expose an ID', async () => {
  for (const mode of ['pending', 'reverted', 'depth', 'orphaned', 'wrong-chain', 'wrong-log', 'bad-status'] as const) {
    const { client, state, log } = rpc();
    const codes = { pending: 'not_mined', reverted: 'reverted', depth: 'not_confirmed', orphaned: 'orphaned',
      'wrong-chain': 'chain_mismatch', 'wrong-log': 'receipt_mismatch', 'bad-status': 'invalid_receipt' };
    if (mode === 'pending') state.missing = true;
    if (mode === 'reverted') state.receipt.status = '0x0';
    if (mode === 'depth') state.head = '0x2a';
    if (mode === 'orphaned') state.canonical = `0x${'33'.repeat(32)}`;
    if (mode === 'wrong-chain') state.chainId = '0x1';
    if (mode === 'wrong-log') log.removed = true;
    if (mode === 'bad-status') state.receipt.status = '0x99';
    await assert.rejects(readCreatedId(client, hash, input), error =>
      error instanceof AvaReceiptError && error.code === codes[mode]);
  }
});

test('missing, ambiguous and non-ID events are rejected rather than selecting a convenient number', async () => {
  const { client, state, log } = rpc();
  state.receipt.logs = [{ ...log, address: actor }];
  await assert.rejects(readCreatedId(client, hash, input), error => error instanceof AvaReceiptError && error.code === 'event_missing');
  state.receipt.logs = [log, { ...log, logIndex: '0x4', topics: encodeEventTopics({ abi, eventName: 'Created', args: { id: 8n } }) }];
  await assert.rejects(readCreatedId(client, hash, input), error => error instanceof AvaReceiptError && error.code === 'event_ambiguous');
  state.receipt.logs = [log];
  await assert.rejects(readCreatedId(client, hash, { ...input, idField: 'owner' }), error => error instanceof AvaReceiptError && error.code === 'invalid_id');
});

test('RPC failure preserves a structured unavailable result without provider error details', async () => {
  const { client, state } = rpc();
  state.unavailable = true;
  await assert.rejects(readCreatedId(client, hash, input), error => {
    assert(error instanceof AvaReceiptError);
    assert.equal(error.code, 'rpc_unavailable');
    assert.equal(String(error).includes('SECRET'), false);
    assert.equal(error.cause, undefined);
    return true;
  });
});

test('custom narrow integer IDs are normalised and wide IDs never lose precision', async () => {
  const { client, state, log } = rpc();
  const small = parseAbi(['event Created(uint32 indexed id, address owner)']);
  state.receipt.logs = [{ ...log, topics: encodeEventTopics({ abi: small, eventName: 'Created', args: { id: 7 } }) }];
  assert.equal((await readCreatedId(client, hash, { ...input, abi: small })).id, 7n);
  const wide = 9007199254740993n;
  state.receipt.logs = [{ ...log, topics: encodeEventTopics({ abi, eventName: 'Created', args: { id: wide } }) }];
  assert.equal((await readCreatedId(client, hash, input)).id, wide);
});

test('zero-based application IDs require an explicit opt-in and preserve receipt provenance', async () => {
  const { client, state, log } = rpc();
  const small = parseAbi(['event Created(uint64 indexed id, address owner)']);
  state.receipt.logs = [{ ...log, topics: encodeEventTopics({ abi: small, eventName: 'Created', args: { id: 0n } }) }];
  await assert.rejects(readCreatedId(client, hash, { ...input, abi: small }), error =>
    error instanceof AvaReceiptError && error.code === 'invalid_id');
  const result = await readCreatedId(client, hash, { ...input, abi: small, allowZeroId: true });
  assert.equal(result.id, 0n);
  assert.equal(result.transactionHash, hash);
  assert.equal(result.blockHash, blockHash);
  state.receipt.logs = [log];
  assert.equal((await readCreatedId(client, hash, input)).id, 7n);
});

test('a malformed matching event cannot be skipped to manufacture a unique ID', async () => {
  const { client, state, log } = rpc();
  state.receipt.logs = [log, { ...log, logIndex: '0x4', data: '0x' }];
  await assert.rejects(readCreatedId(client, hash, input), error =>
    error instanceof AvaReceiptError && error.code === 'invalid_receipt');
});

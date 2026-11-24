import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createPublicClient, custom, decodeFunctionData, encodeAbiParameters, encodeEventTopics,
  encodeFunctionResult, type Address, type Hex } from 'viem';
import { AvaSdk, AvaReceiptError, avaAbis, correctionsAbi, executionAbi, kernelAbi, requestsAbi } from '../src/index.ts';

const addresses = Object.fromEntries(Object.keys(avaAbis).map((name, i) =>
  [name, `0x${(i + 1).toString(16).padStart(40, '0')}`])) as ConstructorParameters<typeof AvaSdk>[0]['addresses'];
const registry = '0x0000000000000000000000000000000000000091' as Address;
const execution = '0x0000000000000000000000000000000000000092' as Address;
const hash = `0x${'11'.repeat(32)}` as Hex, blockHash = `0x${'22'.repeat(32)}` as Hex;

function fixture(source: 'corrections' | 'execution' = 'corrections') {
  const emitter = source === 'corrections' ? registry : execution;
  const event = source === 'corrections'
    ? { source, eventName: 'CaseAccepted', idField: 'caseId' }
    : { source, eventName: 'AttemptStarted', idField: 'attemptId' };
  const log = { address: emitter, topics: source === 'corrections'
    ? encodeEventTopics({ abi: correctionsAbi, eventName: 'CaseAccepted', args: {
      caseId: 7n, origin: addresses.requests, originCaseId: 11n } })
    : encodeEventTopics({ abi: executionAbi, eventName: 'AttemptStarted', args: { requestId: 11n, attemptId: 7n } }),
    data: source === 'corrections' ? encodeAbiParameters([{ type: 'uint8' }], [1])
      : encodeAbiParameters([{ type: 'uint256' }], [0n]),
    blockHash, blockNumber: '0x2a', transactionHash: hash, transactionIndex: '0x0', logIndex: '0x0', removed: false };
  const state = { chainId: '0x7a69', host: source === 'corrections' ? addresses.kernel : addresses.requests,
    code: '0x6000', unavailableMethod: undefined as string | undefined, canonical: blockHash as Hex };
  const points: unknown[] = [];
  const client = createPublicClient({ cacheTime: 0, transport: custom({ request: async ({ method, params }) => {
    if (state.unavailableMethod === method) throw new Error('SECRET-HELPER-PROVIDER');
    if (method === 'eth_chainId') return state.chainId;
    if (method === 'eth_getBlockByNumber') return { number: '0x2a', hash: state.canonical, transactions: [] };
    if (method === 'eth_blockNumber') return '0x2b';
    if (method === 'eth_getCode') { points.push((params as unknown[])[1]); return state.code; }
    if (method === 'eth_call') {
      const [call, point] = params as [{ to: Address; data: Hex }, unknown];
      points.push(point);
      if (call.to.toLowerCase() === addresses.kernel.toLowerCase()) {
        assert.equal(decodeFunctionData({ abi: kernelAbi, data: call.data }).functionName, 'CORRECTIONS');
        return encodeFunctionResult({ abi: kernelAbi, functionName: 'CORRECTIONS', result: registry });
      }
      if (call.to.toLowerCase() === addresses.requests.toLowerCase()) {
        assert.equal(decodeFunctionData({ abi: requestsAbi, data: call.data }).functionName, 'EXECUTION');
        return encodeFunctionResult({ abi: requestsAbi, functionName: 'EXECUTION', result: execution });
      }
      assert.equal(call.to.toLowerCase(), emitter.toLowerCase());
      return source === 'corrections'
        ? encodeFunctionResult({ abi: correctionsAbi, functionName: 'GOVERNANCE_KERNEL', result: state.host })
        : encodeFunctionResult({ abi: executionAbi, functionName: 'REQUEST_ALLOCATION', result: state.host });
    }
    assert.equal(method, 'eth_getTransactionReceipt');
    return { transactionHash: hash, blockHash, blockNumber: '0x2a', from: addresses.identities, to: addresses.requests,
      transactionIndex: '0x0', contractAddress: null, cumulativeGasUsed: '0x5208', gasUsed: '0x5208',
      effectiveGasPrice: '0x1', logsBloom: `0x${'00'.repeat(256)}`, status: '0x1', type: '0x2', logs: [log] };
  } }, { retryCount: 0 }) });
  return { sdk: new AvaSdk({ chainId: 31337, addresses }), client, event, log, state, points, emitter };
}

test('Core fixed correction helper yields its actual mined case ID and pinned provenance', async () => {
  const f = fixture();
  const receipt = await f.sdk.createdId(f.client, hash, f.event, 2);
  assert.equal(receipt.id, 7n);
  assert.equal(receipt.emitter, registry);
  assert.equal(receipt.blockHash, blockHash);
  assert.equal(receipt.transactionHash, hash);
  assert.equal(receipt.confirmations, 2);
  assert(f.points.length >= 3);
  assert(f.points.every(point => JSON.stringify(point) === JSON.stringify({ blockHash, requireCanonical: true })));
});

test('the execution helper is discovered from Requests and retains its own event schema', async () => {
  const f = fixture('execution');
  const receipt = await f.sdk.createdId(f.client, hash, f.event);
  assert.equal(receipt.id, 7n);
  assert.equal(receipt.emitter, execution);
  assert.equal(receipt.eventName, 'AttemptStarted');
});

test('missing code or a foreign helper host is refused and repair permits the same receipt', async () => {
  for (const source of ['corrections', 'execution'] as const) {
    for (const fault of ['code', 'host'] as const) {
      const f = fixture(source), host = f.state.host;
      if (fault === 'code') f.state.code = '0x';
      else f.state.host = addresses.identities;
      await assert.rejects(f.sdk.createdId(f.client, hash, f.event), error =>
        error instanceof AvaReceiptError && error.code === 'helper_mismatch');
      f.state.code = '0x6000'; f.state.host = host;
      assert.equal((await f.sdk.createdId(f.client, hash, f.event)).id, 7n);
    }
  }
});

test('another emitter and zero IDs cannot masquerade as a Core case, then the valid case still reads', async () => {
  const f = fixture();
  f.log.address = execution;
  await assert.rejects(f.sdk.createdId(f.client, hash, f.event), error =>
    error instanceof AvaReceiptError && error.code === 'event_missing');
  f.log.address = registry;
  f.log.topics = encodeEventTopics({ abi: correctionsAbi, eventName: 'CaseAccepted', args: {
    caseId: 0n, origin: addresses.requests, originCaseId: 11n } });
  const event = { ...f.event, allowZeroId: true }; // Generic business opt-in cannot weaken Core IDs.
  await assert.rejects(f.sdk.createdId(f.client, hash, event), error =>
    error instanceof AvaReceiptError && error.code === 'invalid_id');
  f.log.topics = encodeEventTopics({ abi: correctionsAbi, eventName: 'CaseAccepted', args: {
    caseId: 7n, origin: addresses.requests, originCaseId: 11n } });
  assert.equal((await f.sdk.createdId(f.client, hash, f.event)).id, 7n);
});

test('helper receipts preserve chain, canonical block and requested confirmation guards', async () => {
  const f = fixture();
  f.state.chainId = '0x1';
  await assert.rejects(f.sdk.createdId(f.client, hash, f.event), error =>
    error instanceof AvaReceiptError && error.code === 'chain_mismatch');
  f.state.chainId = '0x7a69';
  await assert.rejects(f.sdk.createdId(f.client, hash, f.event, 3), error =>
    error instanceof AvaReceiptError && error.code === 'not_confirmed');
  f.state.canonical = `0x${'33'.repeat(32)}`;
  await assert.rejects(f.sdk.createdId(f.client, hash, f.event), error =>
    error instanceof AvaReceiptError && error.code === 'orphaned');
  f.state.canonical = blockHash;
  assert.equal((await f.sdk.createdId(f.client, hash, f.event, 2)).confirmations, 2);
});

test('helper discovery read failures stay safe and do not poison a later successful lookup', async () => {
  for (const method of ['eth_chainId', 'eth_call', 'eth_getCode']) {
    const f = fixture();
    f.state.unavailableMethod = method;
    await assert.rejects(f.sdk.createdId(f.client, hash, f.event), error => {
      assert(error instanceof AvaReceiptError);
      assert.equal(error.code, 'rpc_unavailable');
      assert.equal(error.cause, undefined);
      assert.equal(String(error).includes('SECRET'), false);
      return true;
    });
    f.state.unavailableMethod = undefined;
    assert.equal((await f.sdk.createdId(f.client, hash, f.event)).id, 7n);
  }
});

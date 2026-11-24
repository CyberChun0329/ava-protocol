import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createPublicClient, custom, type Address } from 'viem';
import { createSigningReadDispatcher } from '../src/signing-read.js';

const actor = '0x1111111111111111111111111111111111111111' as Address;
const target = '0x2222222222222222222222222222222222222222' as Address;

test('serves chain ID but never forwards unsupported transaction filling', async () => {
  const seen: string[] = [];
  const client = createPublicClient({ transport: custom({ request: async ({ method }) => {
    seen.push(method); return '0x1';
  } }) });
  const dispatch = createSigningReadDispatcher({ client, allowedTargets: [target] });
  assert.deepEqual(await dispatch(actor, { method: 'eth_chainId' }), { result: '0x1' });
  assert.deepEqual(await dispatch(actor, { method: 'eth_fillTransaction', params: [{}] }),
    { error: { code: -32601, message: 'Method not found' } });
  assert.deepEqual(seen, ['eth_chainId']);
});

test('forwards only bounded signing reads for the actor and configured targets', async () => {
  const seen: unknown[] = [];
  const client = createPublicClient({ transport: custom({ request: async (request) => {
    seen.push(request); return '0x1234';
  } }) });
  const dispatch = createSigningReadDispatcher({ client, allowedTargets: [target], maxGas: 500000n });
  const call = { from: actor, to: target, data: '0x1234', nonce: '0x2' };
  for (const input of [
    { method: 'eth_getBlockByNumber', params: ['latest', false] },
    { method: 'eth_getTransactionCount', params: [actor, 'pending'] },
    { method: 'eth_gasPrice' }, { method: 'eth_maxPriorityFeePerGas' },
    { method: 'eth_getCode', params: [target, 'latest'] },
    { method: 'eth_call', params: [call, { blockHash: `0x${'12'.repeat(32)}`, requireCanonical: true }] },
    { method: 'eth_estimateGas', params: [call] },
  ]) assert.deepEqual(await dispatch(actor, input), { result: '0x1234' });
  assert.equal((seen[5] as any).params[0].gas, '0x7a120');
  for (const input of [
    { method: 'eth_sendRawTransaction', params: ['0x'] },
    { method: 'eth_getBlockByNumber', params: ['latest', true] },
    { method: 'eth_getTransactionCount', params: [target, 'pending'] },
    { method: 'eth_getCode', params: [actor, 'latest'] },
    { method: 'eth_call', params: [{ ...call, from: target }] },
    { method: 'eth_call', params: [{ ...call, to: actor }] },
    { method: 'eth_call', params: [{ ...call, gas: '0x7a121' }] },
    { method: 'eth_call', params: [call, 'latest', {}] },
    { method: 'eth_call', params: [{ ...call, authorizationList: [] }] },
    [{ method: 'eth_chainId' }],
  ]) assert.ok('error' in await dispatch(actor, input));
  assert.equal(seen.length, 7);
});

test('preserves bounded execution revert data and sanitizes other upstream failures', async () => {
  const failures: unknown[] = [
    { code: 3, message: 'execution reverted: secret', data: '0xdeadbeef' },
    { code: -32000, message: 'execution reverted', data: '0xabcd' },
    { code: -32000, message: 'rate limited at secret endpoint', data: '0xdeadbeef' },
    new Error('secret URL'),
    { code: 3, message: 'execution reverted', data: `0x${'aa'.repeat(131073)}` },
  ];
  const client = createPublicClient({ transport: custom({ retryCount: 0, request: async () => { throw failures.shift(); } }) });
  const dispatch = createSigningReadDispatcher({ client, allowedTargets: [target] });
  const input = { method: 'eth_call', params: [{ from: actor, to: target, data: '0x' }] };
  assert.deepEqual(await dispatch(actor, input), { error: { code: 3, message: 'Execution reverted', data: '0xdeadbeef' } });
  assert.deepEqual(await dispatch(actor, input), { error: { code: 3, message: 'Execution reverted', data: '0xabcd' } });
  for (let i = 0; i < 3; i++) assert.deepEqual(await dispatch(actor, input), { error: { code: -32603, message: 'Upstream request failed' } });
});

test('viem local-account preparation falls back from fill to bounded reads', async () => {
  const { createWalletClient } = await import('viem');
  const { privateKeyToAccount } = await import('viem/accounts');
  const account = privateKeyToAccount(`0x${'01'.repeat(32)}`);
  const methods: string[] = [];
  const upstream = createPublicClient({ transport: custom({ request: async ({ method, params }) => {
    methods.push(method);
    if (method === 'eth_getTransactionCount') return '0x1';
    if (method === 'eth_chainId') return '0x1';
    if (method === 'eth_getBlockByNumber') return { baseFeePerGas: '0x3b9aca00' };
    if (method === 'eth_maxPriorityFeePerGas') return '0x3b9aca00';
    if (method === 'eth_estimateGas') { assert.equal((params as any)[0].nonce, '0x1'); return '0x5208'; }
    throw new Error(`Unexpected method ${method}`);
  } }) });
  const dispatch = createSigningReadDispatcher({ client: upstream, allowedTargets: [target] });
  const wallet = createWalletClient({ account, transport: custom({ retryCount: 0, request: async (input) => {
    const reply = await dispatch(account.address, input);
    if ('error' in reply) throw reply.error;
    return reply.result;
  } }) });
  const prepared = await wallet.prepareTransactionRequest({ account, chain: null, to: target, data: '0x1234' });
  assert.equal(prepared.gas, 21000n);
  assert.deepEqual(methods, ['eth_getTransactionCount', 'eth_chainId', 'eth_getBlockByNumber', 'eth_maxPriorityFeePerGas', 'eth_estimateGas']);
});

test('enforces RPC shape, calldata and gas bounds before contacting the upstream', async () => {
  let calls = 0;
  const client = createPublicClient({ transport: custom({ request: async () => { calls++; return '0x'; } }) });
  const dispatch = createSigningReadDispatcher({ client, allowedTargets: [target] });
  const tx = { from: actor.toUpperCase().replace('0X', '0x'), to: target, data: `0x${'aa'.repeat(131072)}`, gas: '0x1c9c380' };
  assert.deepEqual(await dispatch(actor, { method: 'eth_call', params: [tx, 'finalized'] }), { result: '0x' });
  for (const input of [
    { method: 'eth_call', params: [{ ...tx, data: `${tx.data}00` }] },
    { method: 'eth_call', params: [{ ...tx, gas: '0x1c9c381' }] },
    { method: 'eth_call', params: [{ ...tx, gas: '0x00' }] },
    { method: 'eth_call', params: [{ ...tx, to: null }] },
    { method: 'eth_call', params: [tx, { blockHash: `0x${'12'.repeat(32)}`, requireCanonical: true, extra: true }] },
    { method: 'eth_chainId', id: 1 },
    { method: 'eth_chainId', params: [{}] },
    { method: 'eth_call', params: [{ ...tx, data: '0x1' }] },
  ]) assert.deepEqual(await dispatch(actor, input), { error: { code: -32602, message: 'Invalid parameters' } });
  assert.equal(calls, 1);
});

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createPublicClient, custom, encodeErrorResult, HttpRequestError, parseAbi } from 'viem';
import { AvaSdk, AvaSigningError, avaAbis, type CoreAddresses } from '../src/index.ts';

const addresses = Object.fromEntries(Object.keys(avaAbis).map((name, index) =>
  [name, `0x${(index + 1).toString(16).padStart(40, '0')}`])) as CoreAddresses;
const account = '0x0000000000000000000000000000000000000030' as const;
const sdk = new AvaSdk({ chainId: 31337, addresses });

test('simulation calls the exact intended transaction without signing or sending', async () => {
  const client = createPublicClient({ transport: custom({ request: async ({ method, params }) => {
    assert.equal(method, 'eth_call');
    const [tx] = params as [{ from: string; to: string; data: string; value: string }];
    assert.equal(tx.from.toLowerCase(), account);
    assert.equal(tx.to.toLowerCase(), addresses.requests);
    assert.equal(tx.data, '0x12345678');
    assert.equal(tx.value, '0x2');
    return '0x';
  } }, { retryCount: 0 }) });
  assert.equal(await sdk.simulate(client, account, { to: addresses.requests, data: '0x12345678', value: 2n }), undefined);
});

test('simulation distinguishes application revert from RPC and transport failures', async () => {
  const abi = parseAbi(['error LessonUnavailable(uint256 sessionId)']);
  const cases = [
    { failure: { code: 3, message: 'execution reverted SECRET',
      data: encodeErrorResult({ abi, errorName: 'LessonUnavailable', args: [12n] }) },
      code: 'contract_reverted', errorName: 'LessonUnavailable' },
    { failure: { code: -32602, message: 'SECRET' }, code: 'rpc_error', errorName: undefined },
    { failure: new HttpRequestError({ url: 'https://SECRET.invalid' }), code: 'transport_error', errorName: undefined },
  ] as const;
  for (const item of cases) {
    const client = createPublicClient({ transport: custom({ request: async ({ method }) => {
      assert.equal(method, 'eth_call');
      throw item.failure;
    } }, { retryCount: 0 }) });
    await assert.rejects(sdk.simulate(client, account, { to: addresses.requests, data: '0x12345678' }, abi), error => {
      assert(error instanceof AvaSigningError);
      assert.equal(error.stage, 'simulation');
      assert.equal(error.code, item.code);
      assert.equal(error.errorName, item.errorName);
      assert.equal(error.cause, undefined);
      assert(!JSON.stringify(error).includes('SECRET'));
      return true;
    });
  }
});

test('simulation rejects mutation during the RPC and accepts a later unchanged call', async () => {
  const call = { to: addresses.requests, data: '0x12345678' as `0x${string}`, value: 2n };
  let mutate = true;
  const client = createPublicClient({ transport: custom({ request: async ({ method }) => {
    assert.equal(method, 'eth_call');
    if (mutate) { call.data = '0x87654321'; mutate = false; }
    return '0x';
  } }, { retryCount: 0 }) });
  await assert.rejects(sdk.simulate(client, account, call), error =>
    error instanceof AvaSigningError && error.stage === 'simulation' && error.code === 'intent_mismatch');
  assert.equal(await sdk.simulate(client, account, { to: addresses.requests, data: '0x12345678', value: 2n }), undefined);
});

test('simulation pins numbered and canonical hash points and preserves revert classification', async () => {
  const hash = `0x${'ab'.repeat(32)}` as const;
  const canonical = { blockHash: hash, requireCanonical: true } as const;
  const abi = parseAbi(['error LessonUnavailable(uint256 sessionId)']);
  const call = { to: addresses.requests, data: '0x12345678' as const, value: 2n };
  const expectedPoints = ['0x2a', canonical, canonical];
  let count = 0;
  const client = createPublicClient({ transport: custom({ request: async ({ method, params }) => {
    assert.equal(method, 'eth_call');
    const [tx, point] = params as [{ from: string; to: string; data: string; value: string }, unknown];
    assert.equal(tx.from.toLowerCase(), account);
    assert.equal(tx.to.toLowerCase(), call.to);
    assert.equal(tx.data, call.data);
    assert.equal(tx.value, '0x2');
    assert.deepEqual(point, expectedPoints[count]);
    if (count++ === 1) throw { code: 3, message: 'execution reverted',
      data: encodeErrorResult({ abi, errorName: 'LessonUnavailable', args: [12n] }) };
    return '0x';
  } }, { retryCount: 0 }) });
  await sdk.simulate(client, account, call, abi, 42n);
  await assert.rejects(sdk.simulate(client, account, call, abi, canonical), error =>
    error instanceof AvaSigningError && error.stage === 'simulation' && error.code === 'contract_reverted'
      && error.errorName === 'LessonUnavailable');
  await sdk.simulate(client, account, call, abi, canonical);
  assert.equal(count, 3);
});

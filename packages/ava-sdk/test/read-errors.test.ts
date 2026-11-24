import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createPublicClient, custom, encodeErrorResult, encodeFunctionResult, zeroHash, type Address } from 'viem';
import { AvaSdk, avaAbis, type CoreAddresses } from '../src/index.ts';

const addresses = Object.fromEntries(Object.keys(avaAbis).map((name, i) =>
  [name, `0x${(i + 1).toString(16).padStart(40, '0')}` as Address])) as CoreAddresses;

test('support distinguishes RPC uncertainty from an EVM refusal and recovers without changing the request', async () => {
  let mode: 'fault' | 'refusal' | 'valid' = 'fault';
  const client = createPublicClient({ transport: custom({ request: async ({ method }) => {
    assert.equal(method, 'eth_call');
    if (mode === 'fault') throw { code: -32603, message: 'SYNTHETIC_PRIVATE_PROVIDER_ERROR' };
    if (mode === 'refusal') throw { code: 3, message: 'execution reverted SYNTHETIC_PRIVATE_REASON',
      data: encodeErrorResult({ abi: avaAbis.requests, errorName: 'InvalidState', args: [7n] }) };
    return encodeFunctionResult({ abi: avaAbis.requests, functionName: 'validateCurrentSupport', result: zeroHash });
  } }, { retryCount: 0 }) });
  const sdk = new AvaSdk({ chainId: 31337, addresses });
  await assert.rejects(sdk.support(client, 7n), error => {
    assert(error instanceof Error);
    assert.equal(error.name, 'AvaReadError');
    assert.equal((error as Error & { code: string }).code, 'read_unavailable');
    assert.equal(error.cause, undefined);
    assert(!String(error).includes('SYNTHETIC_PRIVATE'));
    return true;
  });
  mode = 'refusal';
  assert.deepEqual(await sdk.support(client, 7n), { usable: false, reason: 'contract_reverted', errorName: 'InvalidState' });
  mode = 'valid';
  assert.deepEqual(await sdk.support(client, 7n), { usable: true });
});

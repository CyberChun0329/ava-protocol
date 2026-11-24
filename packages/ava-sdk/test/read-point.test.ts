import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createPublicClient, custom, encodeFunctionResult, keccak256, parseAbi, toHex } from 'viem';
import { withCanonicalSnapshot } from '../src/index.ts';

const blockHash = keccak256(toHex('canonical block 42'));
const abi = parseAbi(['function value() view returns (uint256)']);
const address = '0x0000000000000000000000000000000000000001';
function rpc() {
  const state = { canonicalHash: blockHash, failHead: false, failCheck: false };
  const client = createPublicClient({ cacheTime: 0, transport: custom({ request: async ({ method, params }) => {
    if (method === 'eth_getBlockByNumber') {
      const latest = (params as string[])[0] === 'latest';
      if (latest ? state.failHead : state.failCheck) throw new Error('PRIVATE_RPC_SECRET');
      return { hash: latest ? blockHash : state.canonicalHash, number: '0x2a', timestamp: '0x640', transactions: [] };
    }
    assert.equal(method, 'eth_call');
    assert.deepEqual((params as unknown[])[1], { blockHash, requireCanonical: true });
    return encodeFunctionResult({ abi, functionName: 'value', result: 7n });
  } }, { retryCount: 0 }) });
  return { client, state };
}

test('a canonical aggregate shares its hash point and exposes block metadata', async () => {
  const { client } = rpc();
  const result = await withCanonicalSnapshot(client, async ({ point, blockNumber, blockHash: hash, timestamp }) => ({
    blockNumber, hash, timestamp,
    values: await Promise.all([0, 1].map(() => client.readContract({ address, abi, functionName: 'value', ...point }))),
  }));
  assert.deepEqual(result, { blockNumber: 42n, hash: blockHash, timestamp: 1600n, values: [7n, 7n] });
});

test('a reorg refuses the assembled result, then a new canonical aggregate can succeed', async () => {
  const { client, state } = rpc();
  state.canonicalHash = keccak256(toHex('replacement block'));
  await assert.rejects(withCanonicalSnapshot(client, async () => 'must not escape'), { code: 'read_unavailable' });
  state.canonicalHash = blockHash;
  assert.equal(await withCanonicalSnapshot(client, async () => 'recovered'), 'recovered');
});

test('head and completion failures are safe read errors, while callback classifications survive', async () => {
  const { client, state } = rpc();
  for (const field of ['failHead', 'failCheck'] as const) {
    state[field] = true;
    await assert.rejects(withCanonicalSnapshot(client, async () => 7), error => {
      assert(error instanceof Error);
      assert.equal(error.message, 'AVA read unavailable');
      assert.equal(error.cause, undefined);
      return true;
    });
    state[field] = false;
  }
  const classified = Object.assign(new Error('application refusal'), { code: 'not_admissible' });
  await assert.rejects(withCanonicalSnapshot(client, async () => { throw classified; }), error => error === classified);
  assert.equal(await withCanonicalSnapshot(client, async () => 9), 9);
});

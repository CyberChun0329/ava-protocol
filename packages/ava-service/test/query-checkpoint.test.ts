import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { createPublicClient, custom, encodeAbiParameters, encodeEventTopics, parseAbi, toHex, zeroHash } from 'viem';
import { AvaQuery } from '../src/query.js';

const hash = (number: bigint) => toHex(number + 1n, { size: 32 });
const sources = { fixture: { address: toHex(42n, { size: 20 }), abi: parseAbi(['event Empty(uint256 id)']) } };

test('unchanged canonical sync refreshes health in memory and preserves the durable checkpoint', async () => {
  const directory = await mkdtemp(resolve('.tmp/ava-query-checkpoint-'));
  let fail = false;
  const client = createPublicClient({ cacheTime: 0, transport: custom({ request: async ({ method, params }) => {
    if (fail) throw new Error('RPC outage');
    if (method === 'eth_chainId') return '0x7a69';
    if (method === 'eth_blockNumber') return '0x1';
    if (method === 'eth_getLogs') return [];
    if (method === 'eth_getBlockByNumber') {
      const number = BigInt((params as [string])[0]);
      return { number: toHex(number), hash: hash(number), parentHash: number ? hash(number - 1n) : zeroHash,
        timestamp: '0x1', transactions: [] };
    }
    throw new Error(`unexpected RPC method ${method}`);
  } }, { retryCount: 0 }) });
  const options = { client, sources, databasePath: join(directory, 'query.sqlite') };
  let query = new AvaQuery(options);
  try {
    const completed = await query.sync();
    await delay(5);
    const warm = await query.sync();
    assert.equal(warm.status, 'synced');
    assert.equal(warm.indexedBlockHash, completed.indexedBlockHash);
    assert.notEqual(warm.lastSyncAt, completed.lastSyncAt);
    fail = true;
    await assert.rejects(query.sync(), /RPC outage/);
    assert.equal(query.health().status, 'unavailable');
    assert.equal(query.health().lastSyncAt, warm.lastSyncAt);
    query.close();
    query = new AvaQuery(options);
    assert.equal(query.health().status, 'not_synced');
    assert.equal(query.health().lastSyncAt, completed.lastSyncAt);
    fail = false;
    await delay(5);
    const recovered = await query.sync();
    assert.equal(recovered.status, 'synced');
    assert.notEqual(recovered.lastSyncAt, completed.lastSyncAt);
    assert.deepEqual(query.events().items, []);
  } finally { query.close(); await rm(directory, { recursive: true, force: true }); }
});

for (const withPriorSuccess of [false, true]) {
  test(`successful retry persists the completed checkpoint after ${withPriorSuccess ? 'advancing an existing index' : 'a failed first sync'} and restart`, async () => {
    const directory = await mkdtemp(resolve('.tmp/ava-query-partial-'));
    let head = withPriorSuccess ? 1n : 3n;
    let failFinalCheck = false, targetReads = 0;
    const client = createPublicClient({ cacheTime: 0, transport: custom({ request: async ({ method, params }) => {
      if (method === 'eth_chainId') return '0x7a69';
      if (method === 'eth_blockNumber') return toHex(head);
      if (method === 'eth_getLogs') {
        const number = BigInt((params as [{ blockHash: string }])[0].blockHash) - 1n;
        return [{ address: sources.fixture.address, blockNumber: toHex(number), blockHash: hash(number),
          transactionHash: hash(number + 100n), transactionIndex: '0x0', logIndex: '0x0', removed: false,
          topics: encodeEventTopics({ abi: sources.fixture.abi, eventName: 'Empty' }),
          data: encodeAbiParameters([{ type: 'uint256' }], [number]) }];
      }
      if (method === 'eth_getBlockByNumber') {
        const number = BigInt((params as [string])[0]);
        if (failFinalCheck && number === head && ++targetReads === 3) throw new Error('final canonical check outage');
        return { number: toHex(number), hash: hash(number), parentHash: number ? hash(number - 1n) : zeroHash,
          timestamp: '0x1', transactions: [] };
      }
      throw new Error(`unexpected RPC method ${method}`);
    } }, { retryCount: 0 }) });
    const options = { client, sources, databasePath: join(directory, 'query.sqlite'), syncBatchSize: 2 };
    let query = new AvaQuery(options);
    try {
      const prior = withPriorSuccess ? await query.sync() : query.health();
      await delay(5);
      head = 3n;
      failFinalCheck = true;
      await assert.rejects(query.sync(), /final canonical check outage/);
      assert.equal(query.health().status, 'unavailable');
      assert.equal(query.health().indexedBlock, '3');
      assert.equal(query.health().lastSyncAt, prior.lastSyncAt);
      assert.deepEqual(query.events().items.map(event => event.args.id), ['0', '1', '2', '3']);
      query.close();
      query = new AvaQuery(options);
      assert.equal(query.health().lastSyncAt, prior.lastSyncAt);
      assert.equal(query.health().indexedBlock, '3');
      failFinalCheck = false;
      const recovered = await query.sync();
      assert.equal(recovered.status, 'synced');
      assert.ok(recovered.lastSyncAt);
      assert.notEqual(recovered.lastSyncAt, prior.lastSyncAt);
      await delay(5);
      const warm = await query.sync();
      assert.notEqual(warm.lastSyncAt, recovered.lastSyncAt);
      query.close();
      query = new AvaQuery(options);
      assert.equal(query.health().lastSyncAt, recovered.lastSyncAt);
      assert.deepEqual(query.events().items.map(event => event.args.id), ['0', '1', '2', '3']);
    } finally { query.close(); await rm(directory, { recursive: true, force: true }); }
  });
}

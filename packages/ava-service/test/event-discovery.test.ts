import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, rm } from 'node:fs/promises';
import { resolve } from 'node:path';
import { createPublicClient, custom, decodeFunctionData, encodeAbiParameters, encodeEventTopics,
  encodeFunctionResult, parseAbi, toHex, zeroHash, type Abi, type Address, type Hex } from 'viem';
import { AvaSdk, avaAbis, correctionsAbi, executionAbi, type CoreAddresses } from '@ava-protocol/sdk';
import { AvaQuery } from '../src/query.ts';
import { buildAvaService } from '../src/server.ts';

const address = toHex(100n, { size: 20 });
const otherAddress = toHex(101n, { size: 20 });
const manuscript = toHex(700n, { size: 32 });
const abi = parseAbi(['event SubmissionReceived(uint256 indexed submissionId, bytes32 indexed manuscriptId, string label, bool flagged)']);
const sources = { peerJournal: { address, abi }, otherJournal: { address: otherAddress, abi } };
const addresses = Object.fromEntries(Object.keys(avaAbis).map((name, i) =>
  [name, toHex(BigInt(i + 1), { size: 20 })])) as CoreAddresses;
const correctionAddress = toHex(10n, { size: 20 }), executionAddress = toHex(11n, { size: 20 });

// External RPC fixture only: SDK deployment verification, index, SQL and HTTP handlers are real.
function chain() {
  const state = { head: 3n, fork: false, fail: false, logCalls: 0, contractCalls: 0 };
  const hash = (number: bigint): Hex => toHex(number + (state.fork && number >= 2n ? 1000n : 1n), { size: 32 });
  const abis = new Map<string, Abi>(Object.entries(avaAbis).map(([name, value]) =>
    [addresses[name as keyof CoreAddresses], value]));
  abis.set(correctionAddress, correctionsAbi); abis.set(executionAddress, executionAbi);
  const links: Record<string, Address> = { APPLICATION_REGISTRY: addresses.applications,
    IDENTITY_REGISTRY: addresses.identities, AUTHORITY_MATRIX: addresses.authority,
    RULE_PACKAGE_REGISTRY: addresses.packages, EVIDENCE_REGISTRY: addresses.evidence,
    DISCLOSURE_REGISTRY: addresses.disclosure, GOVERNANCE_KERNEL: addresses.kernel,
    REQUEST_ALLOCATION: addresses.requests, CORRECTIONS: correctionAddress, EXECUTION: executionAddress };
  const client = createPublicClient({ cacheTime: 0, transport: custom({ request: async ({ method, params }) => {
    if (state.fail) throw new Error('external RPC unavailable');
    if (method === 'eth_chainId') return '0x7a69';
    if (method === 'eth_getCode') return '0x6000';
    if (method === 'eth_blockNumber') return toHex(state.head);
    if (method === 'eth_getBlockByNumber') {
      const tag = (params as [string])[0];
      const number = tag === 'latest' ? state.head : BigInt(tag);
      return { number: toHex(number), hash: hash(number), parentHash: number ? hash(number - 1n) : zeroHash,
        timestamp: '0x1', transactions: [] };
    }
    if (method === 'eth_getLogs') {
      state.logCalls++;
      const filter = (params as [{ blockHash: Hex; address: Address[] }])[0];
      const number = [0n, 1n, 2n, 3n, 4n].find(n => hash(n) === filter.blockHash)!;
      if (!number) return [];
      return [address, otherAddress].filter(source => filter.address.includes(source)).flatMap(source => [0, 1].map(index => ({
        address: source, blockNumber: toHex(number), blockHash: hash(number),
        transactionHash: toHex(number + 200n, { size: 32 }), transactionIndex: '0x0',
        logIndex: toHex(index + (source === otherAddress ? 2 : 0)), removed: false,
        topics: encodeEventTopics({ abi, eventName: 'SubmissionReceived', args: {
          submissionId: number === 2n && state.fork ? 22n : number, manuscriptId: manuscript } }),
        data: encodeAbiParameters([{ type: 'string' }, { type: 'bool' }], [`submission-${number}-${index}`, index === 0]),
      })));
    }
    if (method === 'eth_call') {
      state.contractCalls++;
      const call = (params as [{ to: Address; data: Hex }])[0];
      const targetAbi = abis.get(call.to.toLowerCase())!;
      const decoded = decodeFunctionData({ abi: targetAbi, data: call.data });
      const result = links[decoded.functionName];
      if (!result) throw new Error(`unexpected contract read ${decoded.functionName}`);
      return encodeFunctionResult({ abi: targetAbi, functionName: decoded.functionName, result });
    }
    throw new Error(`unexpected RPC ${method}`);
  } }, { retryCount: 0 }) });
  return { client, state, hash };
}

test('named-source discovery bounds an ahead index to a canonical snapshot and paginates descending positions', async () => {
  const f = chain();
  const query = new AvaQuery({ client: f.client, sources, databasePath: ':memory:' });
  try {
    await query.sync();
    const filter = { source: 'peerJournal', expectedSourceAddress: address, event: 'SubmissionReceived',
      arg: { name: 'manuscriptId', value: manuscript }, order: 'desc' as const,
      at: { blockNumber: 2n, blockHash: f.hash(2n) }, limit: 1 };
    const first = query.events(filter);
    assert.deepEqual(first.items.map(item => [item.blockNumber, item.logIndex]), [['2', 1]]);
    assert(first.nextCursor);
    const next = query.events({ ...filter, at: { blockNumber: 3n, blockHash: f.hash(3n) }, after: first.nextCursor });
    assert.deepEqual(next.items.map(item => [item.blockNumber, item.logIndex]), [['2', 0]]);
    assert.deepEqual(query.events({ ...filter, before: { blockNumber: 2n, logIndex: 0 }, limit: 10 })
      .items.map(item => [item.blockNumber, item.logIndex]), [['1', 1], ['1', 0]]);
    assert.deepEqual(query.events({ ...filter, arg: { name: 'submissionId', value: '2' }, limit: 10 })
      .items.map(item => item.args.submissionId), ['2', '2']);
    assert.equal(query.events({ ...filter, arg: { name: 'flagged', value: 'true' }, limit: 10 }).items.length, 2);
    assert.equal(query.health().startBlock, '0');
  } finally { query.close(); }
});

test('HTTP discovery validates flat paired filters and configured empty sources without bypassing canonical sync', async () => {
  const f = chain();
  const directory = await mkdtemp(resolve('.tmp/event-discovery-'));
  const service = await buildAvaService({ client: f.client, sdk: new AvaSdk({ chainId: 31337, addresses }),
    databasePath: resolve(directory, 'query.sqlite'), token: 'event-discovery-local-token-at-least-32-chars',
    additionalSources: sources });
  const base = new URLSearchParams({ source: 'peerJournal', expectedSourceAddress: address,
    event: 'SubmissionReceived', argName: 'submissionId', argValue: '2',
    atBlock: '2', atHash: f.hash(2n), order: 'desc' });
  try {
    const response = await service.app.inject(`/v1/events?${base}`);
    assert.equal(response.statusCode, 200);
    assert.deepEqual(response.json().items.map((item: { blockNumber: string; logIndex: number }) =>
      [item.blockNumber, item.logIndex]), [['2', 1], ['2', 0]]);
    assert.equal(response.json().asOf.indexedBlock, '3');
    assert.equal(response.json().asOf.startBlock, '0');
    for (const suffix of ['argName=submissionId', 'argValue=2', 'atBlock=2', `atHash=${f.hash(2n)}`,
      'beforeBlock=2', 'beforeLogIndex=0', 'beforeLogIndex=-1&beforeBlock=2', 'order=sideways',
      'argName=x%27)%20OR%201=1--&argValue=2', 'atBlock=0002&atHash=0x01']) {
      assert.equal((await service.app.inject(`/v1/events?${suffix}`)).statusCode, 400, suffix);
    }
    for (const patch of [{ source: 'missing' }, { expectedSourceAddress: otherAddress },
      { event: 'MissingEvent' }, { argName: 'missingArgument' }]) {
      const params = new URLSearchParams(base);
      for (const [name, value] of Object.entries(patch)) params.set(name, value);
      params.set('fromBlock', '99');
      assert.equal((await service.app.inject(`/v1/events?${params}`)).statusCode, 400, JSON.stringify(patch));
    }
    const logs = f.state.logCalls, reads = f.state.contractCalls;
    assert.equal((await service.app.inject(`/v1/events?${base}`)).statusCode, 200);
    assert.equal(f.state.logCalls, logs, 'unchanged indexed reads fetch no discovery logs');
    assert.equal(f.state.contractCalls, reads, 'indexed discovery performs no record reads');
    f.state.head = 1n;
    assert.equal((await service.app.inject(`/v1/events?${base}`)).statusCode, 503, 'behind the requested block fails closed');
    f.state.head = 3n; f.state.fork = true;
    assert.equal((await service.app.inject(`/v1/events?${base}`)).statusCode, 503, 'orphaned snapshot fails closed');
    base.set('atHash', f.hash(2n)); base.set('argValue', '22');
    assert.equal((await service.app.inject(`/v1/events?${base}`)).json().items.length, 2);
    f.state.fail = true;
    const failed = await service.app.inject(`/v1/events?${base}`);
    assert.equal(failed.statusCode, 503);
    assert.deepEqual(failed.json(), { error: 'chain_or_query_unavailable' });
    f.state.fail = false;
    assert.equal((await service.app.inject(`/v1/events?${base}`)).statusCode, 200);
  } finally { await service.app.close(); await rm(directory, { recursive: true, force: true }); }
});

test('logical filters and canonical cursor identity survive restart and reject changed filters or a reorg', async () => {
  const f = chain();
  const directory = await mkdtemp(resolve('.tmp/event-cursor-'));
  const options = { client: f.client, sources, databasePath: resolve(directory, 'query.sqlite') };
  let query = new AvaQuery(options);
  try {
    await query.sync();
    const filter = { source: 'peerJournal', expectedSourceAddress: address, event: 'SubmissionReceived',
      arg: { name: 'manuscriptId', value: manuscript }, order: 'desc' as const, limit: 1 };
    const first = query.events(filter);
    assert(first.nextCursor);
    assert.throws(() => query.events({ ...filter, order: 'asc', after: first.nextCursor }), /cursor/);
    assert.throws(() => query.events({ ...filter, arg: { name: 'submissionId', value: '3' }, after: first.nextCursor }), /cursor/);
    assert.throws(() => query.events({ ...filter, before: { blockNumber: 4n, logIndex: 0 }, after: first.nextCursor }), /cursor/);
    assert.equal(query.events({ source: 'unknown' }).items.length, 0, 'legacy unconfigured queries retain empty behavior');
    const next = query.events({ ...filter, arg: { value: manuscript, name: 'manuscriptId' }, after: first.nextCursor });
    assert.deepEqual(next.items.map(item => [item.blockNumber, item.logIndex]), [['3', 0]]);
    query.close(); query = new AvaQuery(options); await query.sync();
    assert.deepEqual(query.events({ ...filter, after: first.nextCursor }), next);
    f.state.fork = true; await query.sync();
    assert.throws(() => query.events({ ...filter, after: first.nextCursor }), /cursor/);
  } finally { query.close(); await rm(directory, { recursive: true, force: true }); }
});

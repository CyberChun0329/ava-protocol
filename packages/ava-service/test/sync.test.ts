import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, rm } from 'node:fs/promises';
import { resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { test } from 'node:test';
import { decodeFunctionData, encodeAbiParameters, encodeEventTopics, encodeFunctionResult,
  keccak256, zeroHash, type Abi, type Address, type Hex } from 'viem';
import { AvaServiceClient, AvaServiceError, AvaSdk, avaAbis, correctionsAbi, executionAbi, kernelAbi, localClient, type CoreAddresses } from '@ava-protocol/sdk';
import { privateKeyToAccount } from 'viem/accounts';
import { buildAvaService } from '../src/server.ts';

const token = 'local-test-token-with-at-least-32-characters';
const hash = `0x${'11'.repeat(32)}` as Hex;
const otherApp = `0x${'55'.repeat(32)}` as Hex;
const addresses = Object.fromEntries(Object.keys(avaAbis).map((name, index) =>
  [name, `0x${(index + 1).toString(16).padStart(40, '0')}`])) as CoreAddresses;
const correctionAddress = '0x000000000000000000000000000000000000000a';
const executionAddress = '0x000000000000000000000000000000000000000b';
const object = { id: 1n, appId: hash, workflowKey: hash, packageId: 1n, objectTypeKey: hash,
  objectCommitment: hash, parentObjectId: 0n, subjectId: hash, evidenceReceiptId: 1n,
  disclosurePolicyId: 1n, metadataHash: hash, uri: 'local:fixture', authorityId: hash,
  registeredBy: addresses.kernel, registeredAt: 1n };

function signal() {
  let resolve!: () => void;
  const promise = new Promise<void>(accept => { resolve = accept; });
  return { promise, resolve };
}

// A JSON-RPC boundary fixture: SDK verification, query indexing and HTTP routes are real.
async function fixture(objectCount = 1, options: {
  projectionConcurrency?: number; startBlock?: bigint;
  queryConcurrency?: number; queryQueueLimit?: number;
  recordQueryConcurrency?: number; recordQueryQueueLimit?: number;
} = {}, includeOtherApp = false) {
  const directory = await mkdtemp(resolve(process.env.AVA_TEST_OUTPUT_ROOT ?? '.tmp','transport-sync-'));
  const abis = new Map<string, Abi>(Object.entries(avaAbis).map(([name, abi]) =>
    [addresses[name as keyof CoreAddresses].toLowerCase(), abi]));
  abis.set(correctionAddress, correctionsAbi);
  abis.set(executionAddress, executionAbi);
  const links: Record<string, Address> = { APPLICATION_REGISTRY: addresses.applications,
    IDENTITY_REGISTRY: addresses.identities, AUTHORITY_MATRIX: addresses.authority,
    RULE_PACKAGE_REGISTRY: addresses.packages, EVIDENCE_REGISTRY: addresses.evidence,
    DISCLOSURE_REGISTRY: addresses.disclosure, GOVERNANCE_KERNEL: addresses.kernel,
    REQUEST_ALLOCATION: addresses.requests, CORRECTIONS: correctionAddress, EXECUTION: executionAddress };
  let syncCalls = 0;
  let head = '0x1';
  let canonicalHash = hash;
  let onSync: (() => Promise<void>) | undefined;
  let onObject: ((point: unknown) => Promise<void>) | undefined;
  let onBroadcast: (() => Promise<void>) | undefined;
  let broadcasts = 0;
  const server = createServer(async (request, response) => {
    let body = '';
    for await (const chunk of request) body += chunk;
    const rpc = JSON.parse(body);
    try {
      let result: unknown;
      if (rpc.method === 'eth_chainId') result = '0x7a69';
      else if (rpc.method === 'eth_getCode') result = '0x6000';
      else if (rpc.method === 'eth_blockNumber') { syncCalls++; await onSync?.(); result = head; }
      else if (rpc.method === 'eth_getBlockByNumber') {
        const genesis = rpc.params[0] === '0x0';
        result = { number: genesis ? '0x0' : '0x1', hash: genesis ? zeroHash : canonicalHash,
          parentHash: zeroHash, timestamp: '0x1', transactions: [] };
      } else if (rpc.method === 'eth_getLogs') {
        result = rpc.params[0].blockHash === zeroHash ? [] : Array.from({ length: objectCount + (includeOtherApp ? 1 : 0) }, (_, index) => ({
          address: addresses.kernel, blockNumber: '0x1', blockHash: canonicalHash,
          transactionHash: hash, transactionIndex: '0x0', logIndex: `0x${index.toString(16)}`, removed: false,
          topics: encodeEventTopics({ abi: kernelAbi, eventName: 'GovernedObjectRegistered',
            args: { id: BigInt(index + 1), appId: index < objectCount ? hash : otherApp, objectTypeKey: hash } }),
          data: encodeAbiParameters([{ type: 'bytes32' }, { type: 'uint256' }, { type: 'bytes32' },
            { type: 'uint256' }, { type: 'bytes32' }, { type: 'address' }],
          [hash, 0n, hash, 1n, hash, addresses.kernel]),
        }));
      } else if (rpc.method === 'eth_sendRawTransaction') {
        broadcasts++; await onBroadcast?.(); result = keccak256(rpc.params[0]);
      } else if (rpc.method === 'eth_getTransactionReceipt' || rpc.method === 'eth_getTransactionByHash') result = null;
      else if (rpc.method === 'eth_call') {
        const [call, point] = rpc.params as [{ to: Address; data: Hex }, unknown];
        const abi = abis.get(call.to.toLowerCase())!;
        const decoded = decodeFunctionData({ abi, data: call.data });
        if (decoded.functionName === 'getGovernedObject') await onObject?.(point);
        const value = decoded.functionName === 'getGovernedObject'
          ? { ...object, id: (decoded.args as readonly bigint[])[0],
            appId: (decoded.args as readonly bigint[])[0]! <= BigInt(objectCount) ? hash : otherApp } : links[decoded.functionName];
        if (!value) throw new Error(`Unexpected contract read ${decoded.functionName}`);
        result = encodeFunctionResult({ abi, functionName: decoded.functionName, result: value });
      } else throw new Error(`Unexpected RPC ${rpc.method}`);
      response.setHeader('content-type', 'application/json');
      response.end(JSON.stringify({ jsonrpc: '2.0', id: rpc.id, result }));
    } catch (error) {
      response.end(JSON.stringify({ jsonrpc: '2.0', id: rpc.id,
        error: { code: -32000, message: String(error) } }));
    }
  });
  await new Promise<void>((accept, reject) => {
    server.once('error', reject); server.listen(0, '127.0.0.1', accept);
  });
  const url = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  const settings = { client: localClient(url), sdk: new AvaSdk({ chainId: 31337, addresses }),
    databasePath: resolve(directory, 'query.sqlite'), token, ...options };
  const service = await buildAvaService(settings);
  await service.app.ready();
  return { service, get syncCalls() { return syncCalls; },
    rewind() { head = '0x0'; },
    replaceBranch() { canonicalHash = `0x${'22'.repeat(32)}`; return canonicalHash; },
    delaySync(handler?: () => Promise<void>) { onSync = handler; },
    delayObject(handler?: (point: unknown) => Promise<void>) { onObject = handler; },
    delayBroadcast(handler?: () => Promise<void>) { onBroadcast = handler; },
    get broadcasts() { return broadcasts; },
    restart() { return buildAvaService(settings); },
    async close() {
      await service.app.close();
      server.closeAllConnections();
      await new Promise<void>(accept => server.close(() => accept()));
      await rm(directory, { recursive: true, force: true });
    } };
}

test('configured deployment start excludes earlier events without changing source identity', async () => {
  const f = await fixture(1, { startBlock: 2n });
  try {
    const response = await f.service.app.inject(`/v1/objects?appId=${hash}`);
    assert.equal(response.statusCode, 200);
    assert.equal(response.json().items.length, 0);
    assert.equal(response.json().asOf.indexedBlock, undefined);
  } finally { await f.close(); }
});

test('health redacts provider failures, preserves the checkpoint and clears its error after recovery', async () => {
  const f = await fixture();
  try {
    const before = (await f.service.app.inject('/health')).json();
    f.delaySync(async () => { throw new Error('SYNTHETIC_SECRET https://user:password@provider.invalid/?key=private'); });
    const failed = await f.service.app.inject({ method: 'POST', url: '/v1/sync',
      headers: { authorization: `Bearer ${token}` } });
    assert.equal(failed.statusCode, 503);
    const health = await f.service.app.inject('/health');
    assert.equal(health.statusCode, 200);
    assert.equal(health.json().status, 'unavailable');
    assert.equal(health.json().error, 'chain_or_query_unavailable');
    assert.equal(health.json().indexedBlockHash, before.indexedBlockHash);
    assert.equal(health.json().lastSyncAt, before.lastSyncAt);
    assert(!health.body.includes('SYNTHETIC_SECRET'));
    assert(!health.body.includes('provider.invalid'));
    f.delaySync();
    const recovered = await f.service.app.inject({ method: 'POST', url: '/v1/sync',
      headers: { authorization: `Bearer ${token}` } });
    assert.equal(recovered.statusCode, 200);
    assert.equal(recovered.json().status, 'synced');
    assert.equal(recovered.json().error, undefined);
    assert.equal(recovered.json().indexedBlockHash, before.indexedBlockHash);
  } finally { await f.close(); }
});

test('delayed background and HTTP syncs coalesce before queueing and graceful close drains once', async () => {
  const f = await fixture();
  const entered = signal(), release = signal();
  try {
    const before = f.syncCalls;
    f.delaySync(async () => { entered.resolve(); await release.promise; });
    const active = f.service.sync();
    await entered.promise;
    const polls = Array.from({ length: 50 }, () => f.service.sync());
    const http = f.service.app.inject({ method: 'POST', url: '/v1/sync',
      headers: { authorization: `Bearer ${token}` } });
    await delay(30);
    const closing = f.service.app.close();
    release.resolve();
    const [, , response] = await Promise.all([active, Promise.all(polls), http, closing]);
    assert.equal(response.statusCode, 200);
    assert.equal(response.json().indexedBlockHash, hash);
    assert.equal(f.syncCalls - before, 1, 'close never drains duplicate poll work');
  } finally { release.resolve(); await f.close(); }
});

test('concurrent history GETs share one refresh and retain the same application snapshot', async () => {
  const f = await fixture();
  const entered = signal(), release = signal();
  try {
    const before = f.syncCalls;
    f.delaySync(async () => { entered.resolve(); await release.promise; });
    const responses = Promise.all(Array.from({ length: 50 }, () => f.service.app.inject(
      `/v1/events?appId=${hash}`)));
    await entered.promise;
    await delay(30);
    release.resolve();
    for (const response of await responses) {
      assert.equal(response.statusCode, 200);
      assert.equal(response.json().asOf.indexedBlockHash, hash);
      assert.equal(response.json().items.length, 1);
      assert.equal(response.json().items[0].args.appId, hash);
    }
    assert.equal(f.syncCalls - before, 1, 'one refresh for the concurrent history wave');
  } finally { release.resolve(); await f.close(); }
});

test('cancelling an active history refresh waiter releases admission while other callers keep the refresh', { timeout: 5000 }, async () => {
  const f = await fixture(1, { queryConcurrency: 1, queryQueueLimit: 0 });
  const entered = signal(), release = signal();
  const jobs: Promise<unknown>[] = [];
  try {
    const origin = await f.service.app.listen({ host: '127.0.0.1', port: 0 });
    const remote = new AvaServiceClient(origin);
    const before = f.syncCalls;
    f.delaySync(async () => { entered.resolve(); await release.promise; });
    const controller = new AbortController();
    const cancelled = assert.rejects(remote.events(`appId=${hash}`, { signal: controller.signal }),
      error => error instanceof AvaServiceError && error.kind === 'cancelled');
    jobs.push(cancelled);
    await entered.promise;
    const record = Promise.resolve(f.service.app.inject(`/v1/objects?appId=${hash}`)); jobs.push(record);
    await delay(20);
    controller.abort(); await cancelled; await delay(20);
    const replacement = remote.events(`appId=${hash}`).then(value => ({ value }), error => ({ error }));
    jobs.push(replacement);
    await delay(20);
    const full = await f.service.app.inject(`/v1/events?appId=${hash}`);
    assert.equal(full.statusCode, 429, 'the replacement retains the configured admission limit');
    release.resolve();
    const remaining = await record;
    assert.equal(remaining.statusCode, 200, 'disconnect leaves the shared refresh available to other callers');
    const result = await replacement;
    assert('value' in result, 'cancelled active waiter releases admission before the shared refresh completes');
    assert.equal(result.value.items[0]!.args.appId, hash);
    assert.equal(result.value.asOf.indexedBlockHash, remaining.json().asOf.indexedBlockHash);
    assert.equal(f.syncCalls - before, 1, 'replacement joins the still-running refresh');
  } finally { release.resolve(); await Promise.allSettled(jobs); await f.close(); }
});

test('cancelling a record page during shared refresh frees admission and skips its projection', { timeout: 5000 }, async () => {
  const f = await fixture(1, { recordQueryConcurrency: 1, recordQueryQueueLimit: 0 });
  const entered = signal(), release = signal();
  const jobs: Promise<unknown>[] = [];
  let reads = 0;
  try {
    const origin = await f.service.app.listen({ host: '127.0.0.1', port: 0 });
    const remote = new AvaServiceClient(origin);
    const before = f.syncCalls;
    f.delayObject(async () => { reads++; });
    f.delaySync(async () => { entered.resolve(); await release.promise; });
    const controller = new AbortController();
    const cancelled = assert.rejects(remote.objects(hash, { signal: controller.signal }),
      error => error instanceof AvaServiceError && error.kind === 'cancelled');
    jobs.push(cancelled);
    await entered.promise;
    controller.abort(); await cancelled; await delay(20);
    const replacement = remote.objects(hash).then(value => ({ value }), error => ({ error }));
    jobs.push(replacement);
    await delay(20);
    const full = await f.service.app.inject(`/v1/objects?appId=${hash}`);
    assert.equal(full.statusCode, 429);
    release.resolve();
    const result = await replacement;
    assert('value' in result, 'cancelled refresh waiter releases record admission before refresh completes');
    assert.equal(result.value.items[0]!.id, '1');
    assert.equal(result.value.asOf.indexedBlockHash, hash);
    assert.equal(reads, 1, 'only the replacement page performs a canonical record read');
    assert.equal(f.syncCalls - before, 1, 'replacement record page joins the still-running refresh');
  } finally { release.resolve(); await Promise.allSettled(jobs); await f.close(); }
});

test('failed coalesced sync releases its slot so a later public sync can recover', async () => {
  const f = await fixture();
  const entered = signal(), release = signal();
  try {
    const before = f.syncCalls;
    f.delaySync(async () => { entered.resolve(); await release.promise; throw new Error('delayed RPC failure'); });
    const active = f.service.sync();
    await entered.promise;
    const polls = Array.from({ length: 10 }, () => f.service.sync());
    const results = Promise.allSettled([active, ...polls]);
    release.resolve();
    assert((await results).every(result => result.status === 'rejected'));
    assert.equal(f.syncCalls - before, 1);
    f.delaySync();
    const response = await f.service.app.inject({ method: 'POST', url: '/v1/sync',
      headers: { authorization: `Bearer ${token}` } });
    assert.equal(response.statusCode, 200);
    assert.equal(response.json().status, 'synced');
  } finally { release.resolve(); await f.close(); }
});

test('slow canonical record expansion allows background sync and event reads to progress', async () => {
  const f = await fixture();
  const entered = signal(), release = signal();
  try {
    let reference: unknown;
    f.delayObject(async point => { reference = point; entered.resolve(); await release.promise; });
    const records = f.service.app.inject({ method: 'GET', url: '/v1/objects' });
    await entered.promise;
    const before = f.syncCalls;
    const polls = [f.service.sync(), f.service.sync()];
    await Promise.race([Promise.all(polls), delay(500).then(() => { throw new Error('slow projection blocked index refresh'); })]);
    const events = await f.service.app.inject('/v1/events');
    assert.equal(events.statusCode, 200);
    assert.equal(events.json().asOf.indexedBlockHash, hash);
    release.resolve();
    const response = await records;
    await Promise.all(polls);
    assert.equal(response.statusCode, 200);
    assert.equal(response.json().items[0].objectCommitment, hash);
    assert.deepEqual(reference, { blockHash: response.json().asOf.indexedBlockHash, requireCanonical: true });
    assert.equal(f.syncCalls - before, 2, 'background wave and subsequent event read refresh independently');
  } finally { release.resolve(); await f.close(); }
});

test('HTTP record pages retain canonical full reads and accept only matching event cursors', async () => {
  const f = await fixture(103);
  try {
    const references: unknown[] = [];
    f.delayObject(async point => { references.push(point); });
    let after: string | undefined;
    let firstCursor: string | undefined;
    const ids: string[] = [];
    do {
      const response = await f.service.app.inject({ method: 'GET', url:
        `/v1/objects?appId=${hash}&limit=37${after ? `&after=${after}` : ''}` });
      assert.equal(response.statusCode, 200);
      const page = response.json();
      ids.push(...page.items.map((item: { id: string }) => item.id));
      assert.equal(page.asOf.indexedBlockHash, hash);
      if (!after) {
        assert.equal(page.items.length, 37);
        assert(page.nextCursor, 'the first bounded page must expose continuation');
        firstCursor = page.nextCursor;
        for (const path of [`/v1/objects?appId=${zeroHash}`, '/v1/recognitions', '/v1/requests']) {
          const mismatch = await f.service.app.inject({ method: 'GET', url: `${path}${path.includes('?') ? '&' : '?'}after=${page.nextCursor}` });
          assert.equal(mismatch.statusCode, 400);
          assert.equal(mismatch.json().error, 'invalid_cursor');
        }
      }
      after = page.nextCursor;
    } while (after);
    assert.deepEqual(ids, Array.from({ length: 103 }, (_, index) => String(index + 1)));
    assert.equal(references.length, 103);
    assert(references.every(point => JSON.stringify(point) === JSON.stringify({ blockHash: hash, requireCanonical: true })));
    assert.equal((await f.service.app.inject({ method: 'GET', url: '/v1/objects?limit=101' })).statusCode, 400);
    f.rewind();
    const orphan = await f.service.app.inject({ method: 'GET', url: `/v1/objects?appId=${hash}&after=${firstCursor}` });
    assert.equal(orphan.statusCode, 400);
    assert.equal(orphan.json().error, 'invalid_cursor');
  } finally { await f.close(); }
});


test('concurrent full pages share a bounded projection budget and preserve result order', async () => {
  const f = await fixture(17, { projectionConcurrency: 3 });
  const entered = signal(), release = signal();
  let active = 0, peak = 0;
  try {
    f.delayObject(async point => {
      assert.deepEqual(point, { blockHash: hash, requireCanonical: true });
      active++; peak = Math.max(peak, active);
      if (active === 3) entered.resolve();
      try { await release.promise; } finally { active--; }
    });
    const responses = Promise.all([f.service.app.inject('/v1/objects'), f.service.app.inject('/v1/objects')]);
    await entered.promise;
    await delay(30);
    assert.equal(peak, 3, 'all pages share the configured record budget');
    release.resolve();
    for (const response of await responses) {
      assert.equal(response.statusCode, 200);
      assert.deepEqual(response.json().items.map((item: { id: string }) => item.id),
        ['1','2','3','4','5','6','7','8','9','10','11','12','13','14','15','16','17']);
    }
    assert.equal(active, 0);
  } finally { release.resolve(); await f.close(); }
});

test('a failed projection releases its budget and a later valid page completes', async () => {
  const f = await fixture(17, { projectionConcurrency: 3 });
  try {
    let reads = 0;
    f.delayObject(async () => { reads++; throw new Error('synthetic record outage'); });
    const failed = await f.service.app.inject('/v1/objects');
    assert.equal(failed.statusCode, 503);
    assert(reads <= 3, 'stop scheduling the rest of a failed page');
    f.delayObject();
    const recovered = await f.service.app.inject('/v1/objects');
    assert.equal(recovered.statusCode, 200);
    assert.equal(recovered.json().items.length, 17);
    assert.equal(recovered.json().asOf.indexedBlockHash, hash);
  } finally { await f.close(); }
});


test('reorg during a slow projection rejects its old snapshot and a new branch remains queryable', async () => {
  const f = await fixture();
  const entered = signal(), release = signal();
  try {
    f.delayObject(async () => { entered.resolve(); await release.promise; });
    const old = f.service.app.inject('/v1/objects');
    await entered.promise;
    const replacement = f.replaceBranch();
    await f.service.sync();
    release.resolve();
    assert.equal((await old).statusCode, 503);
    f.delayObject(async point => { assert.deepEqual(point, { blockHash: replacement, requireCanonical: true }); });
    const valid = await f.service.app.inject('/v1/objects');
    assert.equal(valid.statusCode, 200);
    assert.equal(valid.json().asOf.indexedBlockHash, replacement);
    assert.equal(valid.json().items[0].id, '1');
  } finally { release.resolve(); await f.close(); }
});

test('failed shared history refresh rejects the wave and later legal history recovers', async () => {
  const f = await fixture();
  const entered = signal(), release = signal();
  try {
    f.delaySync(async () => { entered.resolve(); await release.promise; throw new Error('synthetic refresh outage'); });
    const before = f.syncCalls;
    const responses = Promise.all(Array.from({ length: 10 }, () => f.service.app.inject('/v1/events')));
    await entered.promise; await delay(30); release.resolve();
    assert((await responses).every(response => response.statusCode === 503));
    assert.equal(f.syncCalls - before, 1);
    f.delaySync();
    const valid = await f.service.app.inject('/v1/events');
    assert.equal(valid.statusCode, 200);
    assert.equal(valid.json().items.length, 1);
  } finally { release.resolve(); await f.close(); }
});

test('HTTP disconnect stops the remaining page and releases capacity for a later valid read', { timeout: 5000 }, async () => {
  const f = await fixture(17, { projectionConcurrency: 3 });
  const entered = signal(), release = signal(), drained = signal();
  let reads = 0, active = 0;
  try {
    const origin = await f.service.app.listen({ host: '127.0.0.1', port: 0 });
    f.delayObject(async () => {
      reads++; active++;
      if (active === 3) entered.resolve();
      try { await release.promise; } finally { if (--active === 0) drained.resolve(); }
    });
    const controller = new AbortController();
    const disconnected = assert.rejects(fetch(`${origin}/v1/objects`, { signal: controller.signal }),
      error => error instanceof Error && error.name === 'AbortError');
    await entered.promise;
    controller.abort();
    await disconnected;
    await delay(20);
    release.resolve();
    await drained.promise;
    f.delayObject();
    const valid = await f.service.app.inject('/v1/objects');
    assert.equal(valid.statusCode, 200);
    assert.equal(valid.json().items.length, 17);
    assert.equal(reads, 3, 'disconnect prevents scheduling the rest of the original page');
  } finally { release.resolve(); await f.close(); }
});


test('HTTP admission rejects an excess page and the same legal query recovers after capacity returns', async () => {
  const f = await fixture(1, { projectionConcurrency: 1, queryConcurrency: 1, queryQueueLimit: 1 });
  const entered = signal(), release = signal();
  const jobs: Promise<unknown>[] = [];
  try {
    f.delayObject(async () => { entered.resolve(); await release.promise; });
    const first = Promise.resolve(f.service.app.inject('/v1/objects')); jobs.push(first);
    await entered.promise;
    const queued = Promise.resolve(f.service.app.inject('/v1/objects')); jobs.push(queued);
    await delay(20);
    const overflow = Promise.resolve(f.service.app.inject('/v1/objects')); jobs.push(overflow);
    const refused = await Promise.race([overflow, delay(200).then(() => { throw new Error('excess page was not rejected'); })]);
    assert.equal(refused.statusCode, 429);
    assert.equal(refused.json().error, 'work_queue_full');
    release.resolve();
    assert.equal((await first).statusCode, 200);
    assert.equal((await queued).statusCode, 200);
    assert.equal((await f.service.app.inject('/v1/objects')).statusCode, 200);
  } finally { release.resolve(); await Promise.allSettled(jobs); await f.close(); }
});


test('queued HTTP disconnect frees page admission and SDK overload remains distinct from business refusal', { timeout: 5000 }, async () => {
  const f = await fixture(1, { projectionConcurrency: 1, queryConcurrency: 1, queryQueueLimit: 1 });
  const entered = signal(), release = signal();
  const jobs: Promise<unknown>[] = [];
  try {
    const origin = await f.service.app.listen({ host: '127.0.0.1', port: 0 });
    const remote = new AvaServiceClient(origin);
    f.delayObject(async () => { entered.resolve(); await release.promise; });
    const active = Promise.resolve(f.service.app.inject('/v1/objects')); jobs.push(active);
    await entered.promise;
    const controller = new AbortController();
    const cancelled = assert.rejects(remote.objects(hash, { signal: controller.signal }),
      error => error instanceof AvaServiceError && error.kind === 'cancelled');
    await delay(20); controller.abort(); await cancelled; await delay(20);
    const replacement = remote.objects(hash).then(value => ({ value }), error => ({ error })); jobs.push(replacement);
    await delay(20);
    await assert.rejects(remote.objects(hash), error => error instanceof AvaServiceError
      && error.kind === 'http' && error.status === 429 && error.code === 'work_queue_full');
    release.resolve();
    assert.equal((await active).statusCode, 200);
    const result = await replacement;
    assert('value' in result, 'cancelled queued page releases its slot before active work finishes');
    assert.equal(result.value.items.length, 1);
    assert.equal((await remote.objects(hash)).items.length, 1);
  } finally { release.resolve(); await Promise.allSettled(jobs); await f.close(); }
});

test('cancelling a page waiting for a projection slot releases its page budget immediately', { timeout: 5000 }, async () => {
  const f = await fixture(1, { projectionConcurrency: 1, queryConcurrency: 2, queryQueueLimit: 0 });
  const entered = signal(), release = signal();
  let first: Promise<Awaited<ReturnType<typeof f.service.app.inject>>> | undefined;
  let replacement: Promise<unknown> | undefined;
  try {
    const origin = await f.service.app.listen({ host: '127.0.0.1', port: 0 });
    const remote = new AvaServiceClient(origin);
    f.delayObject(async () => { entered.resolve(); await release.promise; });
    first = Promise.resolve(f.service.app.inject('/v1/objects'));
    await entered.promise;
    const controller = new AbortController();
    const cancelled = assert.rejects(remote.objects(hash, { signal: controller.signal }),
      error => error instanceof AvaServiceError && error.kind === 'cancelled');
    await delay(30); controller.abort(); await cancelled; await delay(20);
    const next = remote.objects(hash).then(value => ({ value }), error => ({ error }));
    replacement = next;
    await delay(20);
    await assert.rejects(remote.objects(hash), error => error instanceof AvaServiceError && error.status === 429);
    release.resolve();
    assert.equal((await first).statusCode, 200);
    const result = await next;
    assert('value' in result, 'cancelled projection waiter releases heavy-page admission');
    assert.equal(result.value.items.length, 1);
  } finally { release.resolve(); await first; await replacement; await f.close(); }
});


test('HTTP disconnect and graceful close retain an accepted transaction for recovery after restart', { timeout: 5000 }, async () => {
  const f = await fixture();
  const entered = signal(), release = signal();
  let reopened: Awaited<ReturnType<typeof buildAvaService>> | undefined;
  try {
    const origin = await f.service.app.listen({ host: '127.0.0.1', port: 0 });
    const remote = new AvaServiceClient(origin, token);
    const account = privateKeyToAccount('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80');
    const raw = await account.signTransaction({ chainId: 31337, to: addresses.kernel,
      nonce: 0, gas: 21000n, gasPrice: 1n, type: 'legacy' });
    f.delayBroadcast(async () => { entered.resolve(); await release.promise; throw new Error('synthetic lost reply'); });
    const controller = new AbortController();
    const cancelled = assert.rejects(remote.submit('accepted', raw, { signal: controller.signal }),
      error => error instanceof AvaServiceError && error.kind === 'cancelled');
    await entered.promise; controller.abort(); await cancelled;
    let closed = false;
    const closing = f.service.app.close().then(() => { closed = true; });
    await delay(20);
    assert.equal(closed, false, 'database stays open for the accepted broadcast outcome');
    release.resolve(); await closing;
    reopened = await f.restart();
    const observed = await reopened.app.inject('/v1/transactions/accepted');
    assert.equal(observed.statusCode, 200);
    assert.equal(observed.json().hash, keccak256(raw));
    assert.equal(observed.json().status, 'unknown');
    const retry = await reopened.app.inject({ method: 'POST', url: '/v1/transactions',
      headers: { authorization: `Bearer ${token}` }, payload: { key: 'accepted', serializedTransaction: raw } });
    assert.equal(retry.statusCode, 200);
    assert.equal(retry.json().hash, observed.json().hash);
    assert.equal(f.broadcasts, 1);
  } finally { release.resolve(); await reopened?.app.close(); await f.close(); }
});


test('another application indexed query progresses while record admission is full and overload recovers', async () => {
  const f = await fixture(2, { projectionConcurrency: 1, queryConcurrency: 1, queryQueueLimit: 1,
    recordQueryConcurrency: 1, recordQueryQueueLimit: 1 }, true);
  const entered = signal(), release = signal();
  const jobs: Promise<unknown>[] = [];
  try {
    f.delayObject(async () => { entered.resolve(); await release.promise; });
    const url = `/v1/objects?appId=${hash}`;
    const active = Promise.resolve(f.service.app.inject(url)); jobs.push(active);
    await entered.promise;
    const pending = Promise.resolve(f.service.app.inject(url)); jobs.push(pending);
    await delay(20);
    const refused = await f.service.app.inject(url);
    assert.equal(refused.statusCode, 429);
    assert.equal(refused.json().error, 'work_queue_full');
    for (const kind of ['recognitions', 'requests', 'corrections']) {
      const full = await f.service.app.inject(`/v1/${kind}?appId=${hash}`);
      assert.equal(full.statusCode, 429, `${kind} shares the bounded record-page pool`);
    }
    const indexed = await f.service.app.inject(`/v1/events?appId=${otherApp}`);
    assert.equal(indexed.statusCode, 200, 'heavy pages cannot consume indexed-query admission');
    assert.deepEqual(indexed.json().items.map((item: { args: { appId: string } }) => item.args.appId), [otherApp]);
    assert.equal(indexed.json().asOf.indexedBlockHash, hash);
    const synced = await f.service.app.inject({ method: 'POST', url: '/v1/sync',
      headers: { authorization: `Bearer ${token}` } });
    assert.equal(synced.statusCode, 200);
    assert.equal(synced.json().indexedBlockHash, hash);
    release.resolve();
    assert.equal((await active).statusCode, 200);
    assert.equal((await pending).statusCode, 200);
    const recovered = await f.service.app.inject(url);
    assert.equal(recovered.statusCode, 200);
    assert.deepEqual(recovered.json().items.map((item: { appId: string }) => item.appId), [hash, hash]);
  } finally { release.resolve(); await Promise.allSettled(jobs); await f.close(); }
});

test('record concurrency can exceed indexed concurrency without overflowing its projection waiting room', async () => {
  const f = await fixture(3, { projectionConcurrency: 1, queryConcurrency: 1, queryQueueLimit: 0,
    recordQueryConcurrency: 3, recordQueryQueueLimit: 0 }, true);
  const entered = signal(), release = signal();
  const jobs: Promise<Awaited<ReturnType<typeof f.service.app.inject>>>[] = [];
  try {
    f.delayObject(async () => { entered.resolve(); await release.promise; });
    jobs.push(Promise.resolve(f.service.app.inject(`/v1/objects?appId=${hash}`)));
    await entered.promise;
    jobs.push(Promise.resolve(f.service.app.inject(`/v1/objects?appId=${hash}`)),
      Promise.resolve(f.service.app.inject(`/v1/objects?appId=${hash}`)));
    await delay(20);
    const full = await f.service.app.inject(`/v1/objects?appId=${hash}`);
    assert.equal(full.statusCode, 429);
    const indexed = await f.service.app.inject(`/v1/events?appId=${otherApp}`);
    assert.equal(indexed.statusCode, 200);
    release.resolve();
    for (const page of await Promise.all(jobs)) {
      assert.equal(page.statusCode, 200);
      assert.deepEqual(page.json().items.map((item: { id: string }) => item.id), ['1', '2', '3']);
    }
  } finally { release.resolve(); await Promise.allSettled(jobs); await f.close(); }
});

test('indexed admission keeps its limit and queued cancellation while record work shares synchronization', { timeout: 5000 }, async () => {
  const f = await fixture(1, { projectionConcurrency: 1, queryConcurrency: 1, queryQueueLimit: 1,
    recordQueryConcurrency: 1, recordQueryQueueLimit: 0 }, true);
  const entered = signal(), release = signal();
  const jobs: Promise<unknown>[] = [];
  try {
    const origin = await f.service.app.listen({ host: '127.0.0.1', port: 0 });
    const remote = new AvaServiceClient(origin);
    f.delaySync(async () => { entered.resolve(); await release.promise; });
    const before = f.syncCalls;
    const active = Promise.resolve(f.service.app.inject(`/v1/events?appId=${otherApp}`)); jobs.push(active);
    await entered.promise;
    const controller = new AbortController();
    const cancelled = assert.rejects(remote.events(`appId=${otherApp}`, { signal: controller.signal }),
      error => error instanceof AvaServiceError && error.kind === 'cancelled');
    await delay(20); controller.abort(); await cancelled; await delay(20);
    const replacement = remote.events(`appId=${otherApp}`).then(value => ({ value }), error => ({ error }));
    jobs.push(replacement);
    await delay(20);
    const indexFull = await f.service.app.inject(`/v1/events?appId=${otherApp}`);
    assert.equal(indexFull.statusCode, 429);
    assert.equal(indexFull.json().error, 'work_queue_full');
    const record = Promise.resolve(f.service.app.inject(`/v1/objects?appId=${hash}`)); jobs.push(record);
    await delay(20);
    const recordFull = await f.service.app.inject(`/v1/objects?appId=${hash}`);
    assert.equal(recordFull.statusCode, 429);
    assert.equal(f.syncCalls - before, 1, 'both admitted classes join the same in-flight refresh');
    release.resolve();
    const first = await active;
    assert.equal(first.statusCode, 200);
    assert.equal(first.json().items[0].args.appId, otherApp);
    const heavy = await record;
    assert.equal(heavy.statusCode, 200, 'index saturation cannot consume record admission');
    assert.equal(heavy.json().items[0].appId, hash);
    assert.equal(heavy.json().asOf.indexedBlockHash, first.json().asOf.indexedBlockHash);
    const next = await replacement;
    assert('value' in next, 'cancelled indexed waiter promptly releases its waiting room');
    assert.equal(next.value.items[0]!.args.appId, otherApp);
    assert.equal((await remote.events(`appId=${otherApp}`)).items.length, 1);
    assert.equal((await remote.objects(hash)).items.length, 1);
  } finally { release.resolve(); await Promise.allSettled(jobs); await f.close(); }
});

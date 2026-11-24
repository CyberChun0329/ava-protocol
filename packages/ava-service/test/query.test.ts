import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, type ChildProcess } from 'node:child_process';
import { createServer } from 'node:net';
import { mkdtemp, readFile } from 'node:fs/promises';
import { createWriteStream } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { createPublicClient, createWalletClient, custom, http, keccak256, stringToHex, decodeFunctionData, encodeFunctionResult, encodeAbiParameters, encodeEventTopics, parseAbi, zeroHash, type Abi, type Address, type Hex, type PublicClient } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { foundry } from 'viem/chains';
import { correctionsAbi, kernelAbi, requestsAbi } from '@ava-protocol/sdk';
import { AvaQuery } from '../src/query.js';

// Isolated Anvil's public development account, never a user's wallet.
const account = privateKeyToAccount('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80');
let process: ChildProcess;
let client: PublicClient;
let wallet: ReturnType<typeof createWalletClient>;
let address: Address;
let abi: Abi;
let directory: string;
const key = (s: string) => keccak256(stringToHex(s));
const sources = () => ({ applications: { address, abi } });
const options = (file: string) => ({ client, databasePath: resolve(directory, file), sources: sources() });

before(async () => {
  directory = await mkdtemp(resolve('.tmp/query-test-'));
  const port = await new Promise<number>((accept, reject) => {
    const server = createServer();
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const port = (server.address() as { port: number }).port;
      server.close(() => accept(port));
    });
  });
  const log = createWriteStream(resolve(directory, 'anvil.log'));
  process = spawn('anvil', ['--host', '127.0.0.1', '--port', String(port), '--silent']);
  process.stdout!.pipe(log);
  process.stderr!.pipe(log);
  client = createPublicClient({ transport: http(`http://127.0.0.1:${port}`, { retryCount: 0, timeout: 1000 }), cacheTime: 0 });
  wallet = createWalletClient({ account, chain: foundry, transport: http(`http://127.0.0.1:${port}`) });
  let ready = false;
  for (let attempt = 0; attempt < 100; attempt++) {
    try { await client.getChainId(); ready = true; break; } catch { await delay(20); }
  }
  assert(ready, 'isolated Anvil started');
  const artifact = JSON.parse(await readFile('.build/out/AVAApplicationRegistry.sol/AVAApplicationRegistry.json', 'utf8'));
  abi = artifact.abi;
  const hash = await wallet.deployContract({ abi, bytecode: artifact.bytecode.object, args: [account.address], account, chain: foundry });
  address = (await client.waitForTransactionReceipt({ hash })).contractAddress!;
});
after(() => { process?.kill(); });

async function register(name: string) {
  const hash = await wallet.writeContract({ address, abi, functionName: 'registerApplication',
    args: [key(name), key('identity'), key('authority'), account.address, `local:${name}`], account, chain: foundry });
  return client.waitForTransactionReceipt({ hash });
}

test('sync decodes deployed events, persists its cursor, and reopens idempotently', async () => {
  const query = new AvaQuery(options('persistent.sqlite'));
  assert.equal(query.health().status, 'not_synced');
  const receipt = await register('persistent-app');
  const health = await query.sync();
  assert.equal(health.status, 'synced');
  assert.equal(health.chainId, 31337);
  assert.equal(health.indexedBlock, receipt.blockNumber.toString());
  const page = query.events({ event: 'ApplicationRegistered' });
  assert.equal(page.items.length, 1);
  assert.equal(page.items[0].args.appId, key('persistent-app'));
  assert.equal(page.items[0].args.uri, 'local:persistent-app');
  assert.equal(page.items[0].transactionHash, receipt.transactionHash);
  assert.equal(page.items[0].blockHash, receipt.blockHash);
  query.close();
  const reopened = new AvaQuery(options('persistent.sqlite'));
  await reopened.sync();
  assert.deepEqual(reopened.events({ event: 'ApplicationRegistered' }), page);
  reopened.close();
});

test('event configuration preserves history and cursors when a read-only ABI getter is added', async () => {
  const startBlock = await client.getBlockNumber({ cacheTime: 0 }) + 1n;
  await register('getter-compatible-a');
  await register('getter-compatible-b');
  const settings = { ...options('getter-compatible.sqlite'), startBlock };
  const query = new AvaQuery(settings);
  await query.sync();
  const health = query.health();
  const history = query.events();
  const first = query.events({ limit: 1 });
  assert(first.nextCursor);
  const continuation = query.events({ after: first.nextCursor, limit: 1 });
  query.close();
  const extended = [...abi, ...parseAbi(['function configurationVersion() view returns (uint256)'])];
  const reopened = new AvaQuery({ ...settings, sources: { applications: { address, abi: extended } } });
  try {
    assert.equal(reopened.health().indexedBlockHash, health.indexedBlockHash);
    assert.equal(reopened.health().lastSyncAt, health.lastSyncAt);
    assert.deepEqual(reopened.events(), history);
    assert.deepEqual(reopened.events({ limit: 1 }), first);
    assert.deepEqual(reopened.events({ after: first.nextCursor, limit: 1 }), continuation);
    await register('getter-compatible-c');
    await reopened.sync();
    assert.equal(reopened.events({ event: 'ApplicationRegistered' }).items.length, 3);
    assert.deepEqual(reopened.events({ after: first.nextCursor, limit: 1 }), continuation);
  } finally { reopened.close(); }
});

test('event configuration upgrades legacy full ABI metadata only for the same source and event decoder', async () => {
  const startBlock = await client.getBlockNumber({ cacheTime: 0 }) + 1n;
  await register('legacy-config-a');
  await register('legacy-config-b');
  const settings = { ...options('legacy-config.sqlite'), startBlock };
  const query = new AvaQuery(settings);
  await query.sync();
  const health = query.health();
  const history = query.events();
  const first = query.events({ limit: 1 });
  assert(first.nextCursor);
  const continuation = query.events({ after: first.nextCursor, limit: 1 });
  query.close();
  // Migration input: the previous format stored the entire supplied contract ABI.
  const legacy = new DatabaseSync(settings.databasePath);
  legacy.prepare("UPDATE q_meta SET value = ? WHERE key = 'config'").run(JSON.stringify({
    startBlock: startBlock.toString(), confirmations: 1,
    // Non-event fields were never used to decode index history and are discarded.
    sources: { applications: { address: address.toLowerCase(), abi: [...abi, { type: 'function' }] } },
  }));
  legacy.close();
  const changedIndexing = abi.map(item => item.type === 'event' && item.name === 'ApplicationRegistered'
    ? { ...item, inputs: item.inputs.map((input, index) => index === 0 ? { ...input, indexed: !input.indexed } : input) }
    : item);
  const changedParameter = abi.map(item => item.type === 'event' && item.name === 'ApplicationRegistered'
    ? { ...item, inputs: item.inputs.map((input, index) => index === 0 ? { ...input, name: 'differentAppId' } : input) }
    : item);
  const incompatibleSources: Record<string, { address: Address; abi: Abi }>[] = [
    { applications: { address: account.address, abi } },
    { applications: { address, abi: changedIndexing } },
    { applications: { address, abi: changedParameter } },
    { renamed: { address, abi } },
  ];
  for (const sources of incompatibleSources) {
    assert.throws(() => new AvaQuery({ ...settings, sources }), /configuration mismatch/);
  }
  assert.throws(() => new AvaQuery({ ...settings, startBlock: startBlock + 1n }), /configuration mismatch/);
  assert.throws(() => new AvaQuery({ ...settings, confirmations: 2 }), /configuration mismatch/);
  const extended = [...abi, ...parseAbi(['function configurationVersion() view returns (uint256)'])];
  const reopened = new AvaQuery({ ...settings, sources: { applications: { address, abi: extended } } });
  try {
    assert.equal(reopened.health().indexedBlockHash, health.indexedBlockHash);
    assert.equal(reopened.health().lastSyncAt, health.lastSyncAt);
    assert.deepEqual(reopened.events(), history);
    assert.deepEqual(reopened.events({ limit: 1 }), first);
    assert.deepEqual(reopened.events({ after: first.nextCursor, limit: 1 }), continuation);
    await reopened.sync();
    assert.deepEqual(reopened.events(), history);
  } finally { reopened.close(); }
  const again = new AvaQuery(settings);
  try {
    await again.sync();
    assert.deepEqual(again.events({ limit: 1 }), first);
    assert.deepEqual(again.events({ after: first.nextCursor, limit: 1 }), continuation);
  } finally { again.close(); }
});

test('event configuration rejects malformed or unmatched legacy metadata without replacing indexed history', async () => {
  const startBlock = await client.getBlockNumber({ cacheTime: 0 }) + 1n;
  await register('invalid-config');
  const settings = { ...options('invalid-config.sqlite'), startBlock };
  const query = new AvaQuery(settings);
  await query.sync();
  const first = query.events({ limit: 1 });
  assert(first.nextCursor);
  const continuation = query.events({ after: first.nextCursor, limit: 1 });
  query.close();
  const valid = { startBlock: startBlock.toString(), confirmations: 1,
    sources: { applications: { address: address.toLowerCase(), abi } } };
  for (const value of [
    '{', 'null',
    JSON.stringify({ ...valid, sources: { applications: { address: address.toLowerCase(), abi: [{}] } } }),
    JSON.stringify({ ...valid, sources: { applications: { address: address.toLowerCase(), abi: [...abi, { type: 'event' }] } } }),
    JSON.stringify({ ...valid, sources: { applications: { address: address.toLowerCase(), abi: [{ type: 'unknown' }, ...abi] } } }),
    JSON.stringify({ ...valid, unexpected: true }),
  ]) {
    const fixture = new DatabaseSync(settings.databasePath);
    fixture.prepare("UPDATE q_meta SET value = ? WHERE key = 'config'").run(value);
    fixture.close();
    assert.throws(() => new AvaQuery(settings), /configuration mismatch/);
  }
  const restored = new DatabaseSync(settings.databasePath);
  restored.prepare("UPDATE q_meta SET value = ? WHERE key = 'config'").run(JSON.stringify(valid));
  restored.close();
  const reopened = new AvaQuery(settings);
  try {
    await reopened.sync();
    assert.deepEqual(reopened.events({ limit: 1 }), first);
    assert.deepEqual(reopened.events({ after: first.nextCursor, limit: 1 }), continuation);
  } finally { reopened.close(); }
});

test('event filters and pagination preserve deterministic block/log ordering', async () => {
  const startBlock = await client.getBlockNumber({ cacheTime: 0 }) + 1n;
  await register('page-a');
  await register('page-b');
  const query = new AvaQuery({ ...options('pages.sqlite'), startBlock });
  await query.sync();
  const first = query.events({ limit: 1 });
  assert.equal(first.items.length, 1);
  assert.equal(first.items[0].event, 'ApplicationRegistered');
  assert(first.nextCursor);
  const second = query.events({ limit: 1, after: first.nextCursor });
  assert.equal(second.items[0].event, 'ApplicationAdminChanged');
  assert.equal(second.items[0].blockNumber, first.items[0].blockNumber);
  assert(second.items[0].logIndex > first.items[0].logIndex);
  assert.equal(query.events({ source: 'unknown' }).items.length, 0);
  assert.equal(query.events({ event: 'ApplicationRegistered' }).items.length, 2);
  const latest = query.events({ fromBlock: BigInt(second.items[0].blockNumber) + 1n });
  assert.equal(latest.items.length, 2);
  assert.throws(() => query.events({ after: first.nextCursor, event: 'ApplicationRegistered' }), /cursor/);
  assert.throws(() => query.events({ limit: 0 }), /limit/);
  const otherIndex = new AvaQuery({ ...options('other-pages.sqlite'), startBlock });
  await otherIndex.sync();
  assert.throws(() => otherIndex.events({ after: first.nextCursor }), /cursor/);
  otherIndex.close();
  const altered = JSON.parse(Buffer.from(first.nextCursor!, 'base64url').toString());
  altered.l = 9999;
  assert.throws(() => query.events({ after: Buffer.from(JSON.stringify(altered)).toString('base64url') }), /cursor/);
  query.close();
});

test('app-scoped event pages retain their filter and cursor across restart', async () => {
  const startBlock = await client.getBlockNumber({ cacheTime: 0 }) + 1n;
  await register('scoped-page-a');
  await register('scoped-page-b');
  const settings = { ...options('app-pages.sqlite'), startBlock };
  const query = new AvaQuery(settings);
  await query.sync();
  const first = query.events({ appId: key('scoped-page-a'), limit: 1 });
  assert.equal(first.items[0].args.appId, key('scoped-page-a'));
  assert(first.nextCursor);
  assert.throws(() => query.events({ appId: key('scoped-page-b'), after: first.nextCursor }), /cursor/);
  query.close();
  const reopened = new AvaQuery(settings);
  try {
    await reopened.sync();
    const second = reopened.events({ appId: key('scoped-page-a'), after: first.nextCursor, limit: 1 });
    assert.equal(second.items.length, 1);
    assert.equal(second.items[0].args.appId, key('scoped-page-a'));
    assert.equal(second.items[0].event, 'ApplicationAdminChanged');
    assert.equal(second.nextCursor, undefined);
    assert.equal(reopened.events({ appId: key('scoped-page-b') }).items.length, 2);
  } finally { reopened.close(); }
});

test('fixed correction events get canonical app attribution and exclude lookalikes from case pages', async () => {
  const startBlock = await client.getBlockNumber({ cacheTime: 0 }) + 1n;
  const snapshot = await client.request({ method: 'evm_snapshot', params: [] } as never) as string;
  const accepted = [await register('correction-a1'), await register('correction-b1'), await register('correction-a2')];
  const appIds = [key('correction-app-a'), key('correction-app-b'), key('correction-app-a')];
  const lookalike = '0x0000000000000000000000000000000000000abc' as Address;
  const fixture = createPublicClient({ cacheTime: 0, transport: custom({ request: async ({ method, params }) => {
    if (method === 'eth_call') {
      const [call, point] = params as [{ to: Address; data: Hex }, { blockHash: Hex; requireCanonical: boolean }];
      assert.equal(call.to.toLowerCase(), address.toLowerCase());
      const decoded = decodeFunctionData({ abi: correctionsAbi, data: call.data });
      assert.equal(decoded.functionName, 'getCase');
      const id = (decoded.args as readonly bigint[])[0];
      const index = Number(id - 1n);
      assert.deepEqual(point, { blockHash: accepted[index].blockHash, requireCanonical: true });
      return encodeFunctionResult({ abi: correctionsAbi, functionName: 'getCase', result: {
        id, origin: account.address, input: { kind: 1, appId: appIds[index], workflowKey: key('workflow'),
          packageId: 1n, targetPackageId: 1n, sourceStateId: 1n, originCaseId: id, targetId: id,
          originalTargetVersion: 1n, filingEvidenceId: 1n, challengerSubjectId: zeroHash,
          originalActor: account.address, challenger: account.address, affectedActor: account.address },
        acceptedAt: 1n, reviewId: 0n,
      } });
    }
    const result = await client.request({ method, params } as never);
    if (method !== 'eth_getLogs' || !Array.isArray(result)) return result;
    return (result as Record<string, unknown>[]).filter(log => log.logIndex === '0x0').flatMap(log => {
      const index = accepted.findIndex(receipt => receipt.blockHash === log.blockHash);
      if (index < 0) return [];
      const event = { ...log, topics: encodeEventTopics({ abi: correctionsAbi, eventName: 'CaseAccepted',
        args: { caseId: BigInt(index + 1), origin: account.address, originCaseId: BigInt(index + 1) } }),
        data: encodeAbiParameters([{ type: 'uint8' }], [1]),
      };
      return index === 0 ? [event, { ...event, address: lookalike, logIndex: '0x7',
        topics: encodeEventTopics({ abi: correctionsAbi, eventName: 'CaseAccepted',
          args: { caseId: 999n, origin: account.address, originCaseId: 999n } }) }] : [event];
    });
  } }, { retryCount: 0 }) });
  const settings = { client: fixture, startBlock, databasePath: resolve(directory, 'correction-pages.sqlite'),
    sources: { corrections: { address, abi: correctionsAbi }, lookalike: { address: lookalike, abi: correctionsAbi } } };
  const filter = { source: 'corrections', event: 'CaseAccepted', appId: appIds[0], limit: 1 };
  let query = new AvaQuery(settings);
  try {
    await query.sync();
    const first = query.events(filter);
    assert.deepEqual(first.items.map(event => event.args.caseId), ['1']);
    assert(first.nextCursor);
    assert.equal(query.events({ source: 'lookalike', event: 'CaseAccepted' }).items[0].args.appId, undefined);
    assert.throws(() => query.events({ ...filter, appId: appIds[1], after: first.nextCursor }), /cursor/);
    query.close();
    query = new AvaQuery(settings);
    await query.sync();
    const second = query.events({ ...filter, after: first.nextCursor });
    assert.deepEqual(second.items.map(event => event.args.caseId), ['3']);
    assert.equal(second.nextCursor, undefined);
    assert.deepEqual(query.events({ ...filter, appId: appIds[1] }).items.map(event => event.args.caseId), ['2']);
    await client.request({ method: 'evm_revert', params: [snapshot] } as never);
    await query.sync();
    assert.throws(() => query.events({ ...filter, after: first.nextCursor }), /cursor/);
  } finally { query.close(); }
});

test('a shorter reverted chain removes orphan events and rejects their cursors', async () => {
  const query = new AvaQuery(options('reorg.sqlite'));
  await query.sync();
  const snapshot = await client.request({ method: 'evm_snapshot', params: [] } as never) as string;
  const receipt = await register('orphan-a');
  await register('orphan-b');
  await query.sync();
  const orphanPage = query.events({ fromBlock: receipt.blockNumber, limit: 1 });
  assert(orphanPage.nextCursor);
  assert.equal(orphanPage.items[0].args.appId, key('orphan-a'));
  await client.request({ method: 'evm_revert', params: [snapshot] } as never);
  const shortened = await query.sync();
  assert(BigInt(shortened.indexedBlock!) < receipt.blockNumber);
  assert.equal(query.events({ fromBlock: receipt.blockNumber }).items.length, 0);
  assert.throws(() => query.events({ fromBlock: receipt.blockNumber, after: orphanPage.nextCursor }), /cursor/);
  const replacement = await register('replacement');
  await query.sync();
  const events = query.events({ fromBlock: replacement.blockNumber, event: 'ApplicationRegistered' }).items;
  assert.equal(events.length, 1);
  assert.equal(events[0].args.appId, key('replacement'));
  assert.notEqual(events[0].blockHash, receipt.blockHash);
  assert.throws(() => query.events({ fromBlock: receipt.blockNumber, after: orphanPage.nextCursor }), /cursor/);
  query.close();
});

test('confirmation horizon indexes only eligible contiguous blocks', async () => {
  const query = new AvaQuery({ ...options('confirmations.sqlite'), confirmations: 2 });
  const receipt = await register('confirmation-app');
  const first = await query.sync();
  assert.equal(first.indexedBlock, (receipt.blockNumber - 1n).toString());
  assert.equal(query.events({ fromBlock: receipt.blockNumber }).items.length, 0);
  await client.request({ method: 'evm_mine', params: [] } as never);
  const second = await query.sync();
  assert.equal(second.indexedBlock, receipt.blockNumber.toString());
  assert.equal(query.events({ fromBlock: receipt.blockNumber, event: 'ApplicationRegistered' }).items[0].args.appId, key('confirmation-app'));
  query.close();
});

test('persistent chain and configuration identity cannot be silently repointed', async () => {
  const query = new AvaQuery(options('identity.sqlite'));
  await query.sync();
  query.close();
  assert.throws(() => new AvaQuery({ ...options('identity.sqlite'), confirmations: 2 }), /configuration mismatch/);
  assert.throws(() => new AvaQuery({ ...options('identity.sqlite'), startBlock: 1n }), /configuration mismatch/);
  assert.throws(() => new AvaQuery({ ...options('identity.sqlite'), sources: { changed: { address, abi } } }), /configuration mismatch/);
  const reopened = new AvaQuery(options('identity.sqlite'));
  await client.request({ method: 'anvil_setChainId', params: [31338] } as never);
  try {
    await assert.rejects(reopened.sync(), /chain identity mismatch/);
    assert.equal(reopened.health().status, 'unavailable');
  } finally {
    await client.request({ method: 'anvil_setChainId', params: [31337] } as never);
    reopened.close();
  }
});

test('history catch-up prefetches a bounded window and preserves application ordering', async () => {
  const startBlock = await client.getBlockNumber({ cacheTime: 0 }) + 1n;
  for (const name of ['window-a', 'window-b', 'window-c', 'window-d']) await register(name);
  let active = 0, peak = 0;
  const bounded = createPublicClient({ cacheTime: 0, transport: custom({ request: async ({ method, params }) => {
    if (method !== 'eth_getLogs') return client.request({ method, params } as never);
    active++; peak = Math.max(peak, active);
    try { await delay(10); return await client.request({ method, params } as never); }
    finally { active--; }
  } }, { retryCount: 0 }) });
  const query = new AvaQuery({ ...options('window.sqlite'), client: bounded, startBlock, syncBatchSize: 2 });
  try {
    await query.sync();
    assert.equal(peak, 2, 'overlap RPCs without fetching more than the configured window');
    assert.equal(active, 0);
    assert.deepEqual(query.events({ event: 'ApplicationRegistered' }).items.map(event => event.args.appId),
      ['window-a', 'window-b', 'window-c', 'window-d'].map(key));
  } finally { query.close(); }
});

test('a failed catch-up window retains its complete predecessor and recovers without duplicate history', async () => {
  const startBlock = await client.getBlockNumber({ cacheTime: 0 }) + 1n;
  const names = ['checkpoint-a', 'checkpoint-b', 'checkpoint-c', 'checkpoint-d'];
  const receipts: Awaited<ReturnType<typeof register>>[] = [];
  for (const name of names) receipts.push(await register(name));
  let fail = true, active = 0;
  const unstable = createPublicClient({ cacheTime: 0, transport: custom({ request: async ({ method, params }) => {
    if (method !== 'eth_getLogs') return client.request({ method, params } as never);
    active++;
    try {
      await delay(5);
      if (fail && (params as [{ blockHash: Hex }])[0].blockHash === receipts[2]!.blockHash) throw new Error('window outage');
      return await client.request({ method, params } as never);
    } finally { active--; }
  } }, { retryCount: 0 }) });
  const query = new AvaQuery({ ...options('checkpoint.sqlite'), client: unstable, startBlock, syncBatchSize: 2 });
  try {
    await assert.rejects(query.sync(), /window outage/);
    assert.equal(active, 0, 'failed window drains its bounded readers');
    assert.equal(query.health().status, 'unavailable');
    assert.equal(query.health().indexedBlock, receipts[1]!.blockNumber.toString());
    assert.deepEqual(query.events({ event: 'ApplicationRegistered' }).items.map(event => event.args.appId), names.slice(0, 2).map(key));
    fail = false;
    await query.sync();
    assert.deepEqual(query.events({ event: 'ApplicationRegistered' }).items.map(event => event.args.appId), names.map(key));
  } finally { query.close(); }
});

test('RPC log failure retains the prior complete cursor and reports unavailable until recovery', async () => {
  let failLogs = false;
  const unstable = createPublicClient({ cacheTime: 0, transport: custom({ request: async ({ method, params }) => {
    if (failLogs && method === 'eth_getLogs') throw new Error('injected RPC log outage');
    return client.request({ method, params } as never);
  } }, { retryCount: 0 }) });
  const query = new AvaQuery({ ...options('rpc-failure.sqlite'), client: unstable });
  const before = await query.sync();
  const receipt = await register('failure-recovery');
  failLogs = true;
  await assert.rejects(query.sync(), /injected RPC log outage/);
  assert.equal(query.health().status, 'unavailable');
  assert.equal(query.health().indexedBlock, before.indexedBlock);
  assert.equal(query.health().lastSyncAt, before.lastSyncAt);
  assert.equal(query.events({ fromBlock: receipt.blockNumber }).items.length, 0);
  failLogs = false;
  const recovered = await query.sync();
  assert.equal(recovered.status, 'synced');
  assert.equal(recovered.indexedBlock, receipt.blockNumber.toString());
  assert.equal(query.events({ fromBlock: receipt.blockNumber, event: 'ApplicationRegistered' }).items.length, 1);
  query.close();
});

test('replacement at the same height rolls back to the common ancestor', async () => {
  const query = new AvaQuery(options('same-height.sqlite'));
  await query.sync();
  const snapshot = await client.request({ method: 'evm_snapshot', params: [] } as never) as string;
  const orphan = await register('same-height-orphan');
  await query.sync();
  await client.request({ method: 'evm_revert', params: [snapshot] } as never);
  const replacement = await register('same-height-replacement');
  assert.equal(replacement.blockNumber, orphan.blockNumber);
  assert.notEqual(replacement.blockHash, orphan.blockHash);
  await query.sync();
  const page = query.events({ fromBlock: orphan.blockNumber, event: 'ApplicationRegistered' });
  assert.deepEqual(page.items.map(item => item.args.appId), [key('same-height-replacement')]);
  query.close();
});

test('a branch change during log fetching never commits mixed-branch events', async () => {
  let replaceDuringFetch = false;
  let snapshot: string;
  const racing = createPublicClient({ cacheTime: 0, transport: custom({ request: async ({ method, params }) => {
    const result = await client.request({ method, params } as never);
    if (replaceDuringFetch && method === 'eth_getLogs') {
      replaceDuringFetch = false;
      await client.request({ method: 'evm_revert', params: [snapshot] } as never);
      await register('racing-replacement');
    }
    return result;
  } }, { retryCount: 0 }) });
  const query = new AvaQuery({ ...options('racing.sqlite'), client: racing });
  const before = await query.sync();
  snapshot = await client.request({ method: 'evm_snapshot', params: [] } as never) as string;
  const orphan = await register('racing-orphan');
  replaceDuringFetch = true;
  await assert.rejects(query.sync(), /chain changed while fetching logs/);
  assert.equal(query.health().status, 'unavailable');
  assert.equal(query.health().indexedBlock, before.indexedBlock);
  assert.equal(query.events({ fromBlock: orphan.blockNumber }).items.length, 0);
  await query.sync();
  assert.deepEqual(query.events({ fromBlock: orphan.blockNumber, event: 'ApplicationRegistered' }).items.map(item => item.args.appId), [key('racing-replacement')]);
  query.close();
});

test('event pages enforce the maximum size without losing continuation', async () => {
  const startBlock = await client.getBlockNumber({ cacheTime: 0 }) + 1n;
  for (let i = 0; i < 51; i++) await register(`bounded-${i}`);
  const query = new AvaQuery({ ...options('bounded.sqlite'), startBlock });
  await query.sync();
  const first = query.events({ limit: 500 });
  assert.equal(first.items.length, 100);
  assert(first.nextCursor);
  const second = query.events({ limit: 500, after: first.nextCursor });
  assert.equal(second.items.length, 2);
  assert.equal(second.nextCursor, undefined);
  assert.equal(query.events().items.length, 50);
  query.close();
});

test('application events with Core event names cannot invent protocol recognition IDs', async () => {
  const auxiliaryAbi = parseAbi(['event RecognisedStateFormed(uint256 indexed id,uint256 indexed governedObjectId,bytes32 indexed appId,uint256 packageId,uint8 stage,uint8 status,uint256 transitionId,address createdBy)']);
  const auxiliary = createPublicClient({ cacheTime: 0, transport: custom({ request: async ({ method, params }) => {
    const result = await client.request({ method, params } as never);
    if (method !== 'eth_getLogs' || !Array.isArray(result)) return result;
    // An app may emit the same signature as Core. The external RPC fixture supplies its event;
    // only the configured Core emitter is allowed to identify actual protocol records.
    return (result as Record<string, unknown>[]).map(log => ({ ...log,
      topics: encodeEventTopics({ abi: auxiliaryAbi, eventName: 'RecognisedStateFormed',
        args: { id: 999n, governedObjectId: 999n, appId: key('auxiliary-app') } }),
      data: encodeAbiParameters([{ type: 'uint256' }, { type: 'uint8' }, { type: 'uint8' },
        { type: 'uint256' }, { type: 'address' }], [1n, 2, 5, 1n, account.address]),
    }));
  } }, { retryCount: 0 }) });
  await register('auxiliary-event-collision');
  const query = new AvaQuery({ client: auxiliary, databasePath: resolve(directory, 'emitter.sqlite'),
    sources: { auxiliaryApp: { address, abi: auxiliaryAbi } } });
  try {
    await query.sync();
    assert.ok(query.events({ event: 'RecognisedStateFormed' }).items.length > 0);
    assert.deepEqual(query.ids('recognitions', key('auxiliary-app')), []);
  } finally { query.close(); }
});

test('record ID pages enumerate over 100 records of each kind with canonical app-scoped event cursors', async () => {
  const snapshot = await client.request({ method: 'evm_snapshot', params: [] } as never) as string;
  const receipt = await register('record-pages-anchor');
  const appId = key('record-pages-app'), otherApp = key('record-pages-other-app');
  const requestAddress = '0x0000000000000000000000000000000000000123' as Address;
  const kinds = ['objects', 'recognitions', 'requests'] as const;
  const fixture = createPublicClient({ cacheTime: 0, transport: custom({ request: async ({ method, params }) => {
    if (method !== 'eth_getLogs') return client.request({ method, params } as never);
    if ((params as [{ blockHash: Hex }])[0].blockHash !== receipt.blockHash) return [];
    return Array.from({ length: 104 }, (_, index) => {
      const id = BigInt(index + 1), scopedApp = index === 103 ? otherApp : appId;
      const common = { blockHash: receipt.blockHash, blockNumber: `0x${receipt.blockNumber.toString(16)}`,
        transactionHash: receipt.transactionHash, transactionIndex: '0x0', removed: false };
      return [{ ...common, address, logIndex: `0x${(index * 3).toString(16)}`,
        topics: encodeEventTopics({ abi: kernelAbi, eventName: 'GovernedObjectRegistered',
          args: { id, appId: scopedApp, objectTypeKey: key('object') } }),
        data: encodeAbiParameters([{ type: 'bytes32' }, { type: 'uint256' }, { type: 'bytes32' },
          { type: 'uint256' }, { type: 'bytes32' }, { type: 'address' }],
        [key('commitment'), 0n, key('subject'), 1n, key('authority'), account.address]),
      }, { ...common, address, logIndex: `0x${(index * 3 + 1).toString(16)}`,
        topics: encodeEventTopics({ abi: kernelAbi, eventName: 'RecognisedStateFormed',
          args: { id, governedObjectId: id, appId: scopedApp } }),
        data: encodeAbiParameters([{ type: 'uint256' }, { type: 'uint8' }, { type: 'uint8' },
          { type: 'uint256' }, { type: 'address' }], [1n, 2, 5, 1n, account.address]),
      }, { ...common, address: requestAddress, logIndex: `0x${(index * 3 + 2).toString(16)}`,
        topics: encodeEventTopics({ abi: requestsAbi, eventName: 'RequestCreated',
          args: { requestId: id, recognisedStateId: id, appId: scopedApp } }),
        data: encodeAbiParameters([{ type: 'address' }], [account.address]),
      }];
    }).flat();
  } }, { retryCount: 0 }) });
  const settings = { client: fixture, databasePath: resolve(directory, 'record-pages.sqlite'),
    startBlock: receipt.blockNumber,
    sources: { kernel: { address, abi: kernelAbi }, requests: { address: requestAddress, abi: requestsAbi } } };
  let query = new AvaQuery(settings);
  try {
    await query.sync();
    const expected = Array.from({ length: 103 }, (_, index) => String(index + 1));
    for (const kind of kinds) {
      for (let limit = 1; limit <= 100; limit++) {
        const ids: string[] = [];
        let after: string | undefined;
        do {
          const page = query.idsPage(kind, { appId, limit, after });
          assert(page.items.length <= limit);
          ids.push(...page.items); after = page.nextCursor;
        } while (after);
        assert.deepEqual(ids, expected, `${kind}, page size ${limit}`);
      }
      assert.deepEqual(query.ids(kind, appId, 500), expected.slice(0, 100));
      assert.deepEqual(query.ids(kind, appId), expected.slice(0, 50));
      assert.deepEqual(query.idsPage(kind, { appId: otherApp }).items, ['104']);
      const first = query.idsPage(kind, { appId, limit: 1 });
      assert(first.nextCursor);
      assert.throws(() => query.idsPage(kind, { appId: otherApp, after: first.nextCursor }), /cursor/);
      const otherKind = kinds.find(value => value !== kind)!;
      assert.throws(() => query.idsPage(otherKind, { appId, after: first.nextCursor }), /cursor/);
    }
    const first = query.idsPage('objects', { appId, limit: 1 });
    const eventPage = query.events({ source: 'kernel', event: 'GovernedObjectRegistered', appId, limit: 1 });
    assert.equal(first.nextCursor, eventPage.nextCursor, 'the existing event cursor format is reused');
    const cursors = kinds.map(kind => query.idsPage(kind, { appId, limit: 1 }).nextCursor!);
    query.close(); query = new AvaQuery(settings); await query.sync();
    for (const [index, kind] of kinds.entries()) {
      assert.deepEqual(query.idsPage(kind, { appId, after: cursors[index], limit: 1 }).items, ['2']);
    }
    await client.request({ method: 'evm_revert', params: [snapshot] } as never);
    await query.sync();
    for (const [index, kind] of kinds.entries()) {
      assert.throws(() => query.idsPage(kind, { appId, after: cursors[index] }), /cursor/);
    }
  } finally { query.close(); }
});


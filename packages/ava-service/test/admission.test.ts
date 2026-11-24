import assert from 'node:assert/strict';
import { test } from 'node:test';
import { setImmediate, setTimeout as delay } from 'node:timers/promises';
import { createPublicClient, custom, keccak256, type Hex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { AvaTransactions } from '../src/transactions.ts';

const account = privateKeyToAccount('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80');
const target = '0x0000000000000000000000000000000000000020';
const genesis = `0x${'33'.repeat(32)}`, block = `0x${'22'.repeat(32)}`;
function gate() {
  let resolve!: () => void;
  return { promise: new Promise<void>(accept => { resolve = accept; }), resolve: () => resolve() };
}
async function fixture(options: { concurrency: number; maxPending: number }) {
  const raws = await Promise.all([0, 1, 2, 3].map(nonce => account.signTransaction({
    chainId: 31337, to: target, nonce, gas: 21000n, gasPrice: 1n, type: 'legacy' })));
  const entered = gate(), release = gate(), broadcastEntered = gate(), broadcastRelease = gate();
  const state = { holdCode: true, holdBroadcast: false, loseReply: false, codeCalls: 0, active: 0, peak: 0, broadcasts: 0 };
  const client = createPublicClient({ cacheTime: 0, transport: custom({ request: async ({ method, params }) => {
    if (method === 'eth_chainId') return '0x7a69';
    if (method === 'eth_getCode') {
      state.codeCalls++; state.active++; state.peak = Math.max(state.peak, state.active);
      if (state.active === options.concurrency) entered.resolve();
      try { if (state.holdCode) await release.promise; return '0x6000'; }
      finally { state.active--; }
    }
    if (method === 'eth_sendRawTransaction') {
      state.broadcasts++;
      if (state.holdBroadcast) { broadcastEntered.resolve(); await broadcastRelease.promise; }
      if (state.loseReply) throw new Error('synthetic lost broadcast response');
      return keccak256((params as [Hex])[0]);
    }
    if (method === 'eth_blockNumber') return '0x1';
    if (method === 'eth_getBlockByNumber') return { number: (params as [string])[0], hash: (params as [string])[0] === '0x0' ? genesis : block, transactions: [] };
    if (method === 'eth_getTransactionReceipt') return { transactionHash: (params as [Hex])[0],
      blockHash: block, blockNumber: '0x1', from: account.address, to: target, transactionIndex: '0x0',
      contractAddress: null, cumulativeGasUsed: '0x5208', gasUsed: '0x5208', effectiveGasPrice: '0x1',
      logsBloom: `0x${'00'.repeat(256)}`, status: '0x1', type: '0x0', logs: [] };
    throw new Error(`Unexpected RPC ${method}`);
  } }, { retryCount: 0 }) });
  return { tx: new AvaTransactions({ client, databasePath: ':memory:', allowedTargets: [target], ...options }), raws, entered, release, broadcastEntered, broadcastRelease, state };
}

test('transaction admission bounds active and pending work, then permits a rejected request to succeed', async () => {
  const f = await fixture({ concurrency: 2, maxPending: 1 });
  const jobs: Promise<unknown>[] = [];
  try {
    jobs.push(f.tx.submit('a', f.raws[0]!), f.tx.submit('b', f.raws[1]!));
    await f.entered.promise;
    jobs.push(f.tx.submit('c', f.raws[2]!));
    const refused = assert.rejects(f.tx.submit('d', f.raws[3]!), error =>
      error instanceof Error && error.name === 'WorkQueueFullError');
    await Promise.race([refused, delay(200).then(() => { throw new Error('excess work was not rejected'); })]);
    assert.equal(f.state.peak, 2);
    f.state.holdCode = false; f.release.resolve();
    await Promise.all(jobs);
    assert.equal((await f.tx.submit('d', f.raws[3]!)).status, 'confirmed');
    assert.equal(f.state.broadcasts, 4);
  } finally { f.release.resolve(); await Promise.allSettled(jobs); f.tx.close(); }
});

test('queued cancellation releases admission before acceptance and the same bytes can later complete', async () => {
  const f = await fixture({ concurrency: 1, maxPending: 1 });
  const jobs: Promise<unknown>[] = [];
  try {
    jobs.push(f.tx.submit('a', f.raws[0]!));
    await f.entered.promise;
    const controller = new AbortController();
    const queued = f.tx.submit('cancelled', f.raws[1]!, { signal: controller.signal });
    const interrupted = assert.rejects(queued, error => error instanceof Error && error.name === 'AbortError');
    controller.abort();
    await Promise.race([interrupted, delay(200).then(() => { throw new Error('queued cancellation waited for active work'); })]);
    jobs.push(f.tx.submit('replacement', f.raws[2]!));
    f.state.holdCode = false; f.release.resolve();
    await Promise.all(jobs);
    assert.equal(await f.tx.get('cancelled'), undefined, 'no identity persisted before admission started');
    assert.equal((await f.tx.submit('cancelled', f.raws[1]!)).status, 'confirmed');
    assert.equal(f.state.broadcasts, 3);
  } finally { f.release.resolve(); await Promise.allSettled(jobs); f.tx.close(); }
});

test('cancelling a same-hash waiter preserves ordering and leaves other hashes runnable', async () => {
  const f = await fixture({ concurrency: 2, maxPending: 2 });
  const jobs: Promise<unknown>[] = [];
  try {
    jobs.push(f.tx.submit('first', f.raws[0]!));
    await setImmediate();
    const controller = new AbortController();
    const cancelled = assert.rejects(f.tx.submit('cancelled-alias', f.raws[0]!, { signal: controller.signal }),
      error => error instanceof Error && error.name === 'AbortError');
    controller.abort(); await cancelled;
    const alias = f.tx.submit('legal-alias', f.raws[0]!); jobs.push(alias);
    jobs.push(f.tx.submit('other', f.raws[1]!));
    await f.entered.promise;
    assert.equal(f.state.codeCalls, 2, 'same-hash waiters never consume the other runnable slot');
    f.state.holdCode = false; f.release.resolve();
    await Promise.all(jobs);
    assert.equal((await alias).hash, keccak256(f.raws[0]!));
    assert.equal(await f.tx.get('cancelled-alias'), undefined);
    assert.equal(f.state.broadcasts, 2);
  } finally { f.release.resolve(); await Promise.allSettled(jobs); f.tx.close(); }
});

test('disconnect after persistence drains the accepted broadcast and retains unknown identity for recovery', async () => {
  const f = await fixture({ concurrency: 1, maxPending: 1 });
  f.state.holdCode = false; f.state.holdBroadcast = true; f.state.loseReply = true;
  const controller = new AbortController();
  const submitted = f.tx.submit('accepted', f.raws[0]!, { signal: controller.signal });
  try {
    await f.broadcastEntered.promise;
    controller.abort();
    let idle = false;
    const draining = f.tx.drain().then(() => { idle = true; });
    await setImmediate();
    assert.equal(idle, false, 'accepted work is retained until its RPC outcome settles');
    f.broadcastRelease.resolve();
    const unknown = await submitted;
    await draining;
    assert.equal(unknown.status, 'unknown');
    assert.equal(unknown.hash, keccak256(f.raws[0]!));
    assert.equal((await f.tx.get('accepted'))?.status, 'confirmed');
    assert.equal((await f.tx.submit('accepted', f.raws[0]!)).hash, unknown.hash);
    assert.equal(f.state.broadcasts, 1, 'recovery never automatically rebroadcasts accepted bytes');
  } finally { f.broadcastRelease.resolve(); await submitted; f.tx.close(); }
});

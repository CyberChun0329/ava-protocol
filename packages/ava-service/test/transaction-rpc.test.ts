import assert from 'node:assert/strict';
import { setImmediate } from 'node:timers/promises';
import { test } from 'node:test';
import { createPublicClient, custom, keccak256, type Hex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { AvaTransactions, TransactionValidationError } from '../src/transactions.ts';

const target = '0x0000000000000000000000000000000000000020';
const blockHash = `0x${'22'.repeat(32)}`, genesis = `0x${'33'.repeat(32)}`;
const account = privateKeyToAccount('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80');
function signal() {
  let resolve!: () => void;
  const promise = new Promise<void>(accept => { resolve = accept; });
  return { promise, resolve };
}
async function fixture() {
  const raw = await account.signTransaction({ chainId: 31337, to: target, nonce: 0, gas: 21000n, gasPrice: 1n, type: 'legacy' });
  const gate = signal();
  const state = { holdContext: false, holdTip: false, holdCanonical: false, wrongChain: false, failGenesis: false,
    failTip: false, receiptStatus: '0x1' as string | null | undefined, sentBytes: [] as Hex[], chain: 0, genesis: 0, tip: 0, canonical: 0, receipts: 0, broadcasts: 0 };
  const client = createPublicClient({ cacheTime: 0, transport: custom({ request: async ({ method, params }) => {
    if (method === 'eth_chainId') {
      state.chain++;
      if (state.holdContext) await gate.promise;
      return state.wrongChain ? '0x1' : '0x7a69';
    }
    if (method === 'eth_getCode') return '0x6000';
    if (method === 'eth_sendRawTransaction') { state.broadcasts++; state.sentBytes.push((params as [Hex])[0]); return keccak256((params as [Hex])[0]); }
    if (method === 'eth_getTransactionReceipt') {
      state.receipts++;
      return { transactionHash: (params as [Hex])[0], blockHash, blockNumber: '0x1', from: account.address, to: target,
        transactionIndex: '0x0', contractAddress: null, cumulativeGasUsed: '0x5208', gasUsed: '0x5208',
        effectiveGasPrice: '0x1', logsBloom: `0x${'00'.repeat(256)}`,
        ...(state.receiptStatus !== undefined && { status: state.receiptStatus }), type: '0x0', logs: [] };
    }
    if (method === 'eth_blockNumber') {
      state.tip++;
      if (state.holdTip) await gate.promise;
      if (state.failTip) throw { code: -32000, message: 'Synthetic tip outage' };
      return '0x2';
    }
    assert.equal(method, 'eth_getBlockByNumber');
    if ((params as [string])[0] === '0x0') {
      state.genesis++;
      if (state.holdContext) await gate.promise;
      if (state.failGenesis) throw { code: -32000, message: 'Synthetic genesis outage' };
      return { number: '0x0', hash: genesis, transactions: [] };
    }
    state.canonical++;
    if (state.holdCanonical) await gate.promise;
    return { number: '0x1', hash: blockHash, parentHash: genesis, transactions: [] };
  } }, { retryCount: 0 }) });
  return { tx: new AvaTransactions({ client, databasePath: ':memory:', allowedTargets: [target] }), raw, gate, state };
}

test('chain ID and genesis reads both start before either settles', async () => {
  const f = await fixture();
  f.state.holdContext = true;
  const submitted = f.tx.submit('first', f.raw);
  try {
    await setImmediate();
    assert.equal(f.state.chain, 1);
    assert.equal(f.state.genesis, 1);
  } finally { f.gate.resolve(); await submitted; f.tx.close(); }
});

test('explicit recovery during malformed receipt verification resends only the original bytes', async () => {
  const f = await fixture();
  try {
    assert.equal((await f.tx.submit('first', f.raw)).status, 'confirmed');
    f.state.receiptStatus = '0x2';
    const recovered = await f.tx.recover('first', f.raw);
    assert.equal(recovered.status, 'unknown');
    assert.equal(recovered.hash, keccak256(f.raw));
    assert.equal(recovered.nonce, '0');
    assert.equal(recovered.confirmations, 0);
    assert.equal(recovered.blockHash, undefined);
    assert.deepEqual(f.state.sentBytes, [f.raw, f.raw]);
    f.state.receiptStatus = '0x1';
    const confirmed = await f.tx.get('first');
    assert.equal(confirmed?.status, 'confirmed');
    assert.equal(confirmed?.hash, recovered.hash);
    assert.equal((await f.tx.recover('first', f.raw)).status, 'confirmed');
    assert.equal(f.state.broadcasts, 2);
  } finally { f.tx.close(); }
});


test('tip and canonical block reads both start before either settles', async () => {
  const f = await fixture();
  await f.tx.submit('first', f.raw);
  f.state.tip = 0; f.state.canonical = 0;
  f.state.holdTip = true; f.state.holdCanonical = true;
  const observed = f.tx.get('first');
  try {
    await setImmediate();
    assert.equal(f.state.tip, 1);
    assert.equal(f.state.canonical, 1);
  } finally { f.gate.resolve(); await observed; f.tx.close(); }
});

test('wrong chain takes priority over a failed genesis read', async () => {
  const f = await fixture();
  f.state.wrongChain = true;
  f.state.failGenesis = true;
  try {
    await assert.rejects(f.tx.submit('first', f.raw), TransactionValidationError);
    assert.equal(f.state.genesis, 1);
    assert.equal(f.state.broadcasts, 0);
  } finally { f.tx.close(); }
});

test('failed tip waits for its canonical sibling before releasing same-hash work and drain', async () => {
  const f = await fixture();
  await f.tx.submit('first', f.raw);
  f.state.failTip = true;
  f.state.holdCanonical = true;
  f.state.canonical = 0;
  const active = f.tx.get('first');
  let activeDone = false, queuedDone = false, drained = false;
  void active.then(() => { activeDone = true; });
  let queued: ReturnType<typeof f.tx.get> | undefined;
  let drain: Promise<void> | undefined;
  try {
    await setImmediate();
    assert.equal(f.state.canonical, 1);
    const receipts = f.state.receipts;
    queued = f.tx.get('first');
    void queued.then(() => { queuedDone = true; });
    drain = f.tx.drain().then(() => { drained = true; });
    await setImmediate();
    assert.equal(activeDone, false);
    assert.equal(queuedDone, false);
    assert.equal(drained, false);
    assert.equal(f.state.receipts, receipts);
    f.state.failTip = false;
    f.state.holdCanonical = false;
    f.gate.resolve();
    assert.equal((await active)?.status, 'unknown');
    const recovered = await queued;
    assert.equal(recovered?.status, 'confirmed');
    assert.equal(recovered?.hash, keccak256(f.raw));
    await drain;
    assert.equal(f.state.broadcasts, 1);
  } finally {
    f.gate.resolve();
    await Promise.allSettled([active, ...(queued ? [queued] : []), ...(drain ? [drain] : [])]);
    f.tx.close();
  }
});


test('invalid receipt statuses remain uncertain until a valid execution result is observed', async () => {
  for (const receiptStatus of [undefined, null, '0x2']) {
    for (const previouslyConfirmed of [false, true]) {
      const f = await fixture();
      try {
        if (previouslyConfirmed) assert.equal((await f.tx.submit('first', f.raw)).status, 'confirmed');
        f.state.receiptStatus = receiptStatus;
        const uncertain = previouslyConfirmed ? await f.tx.get('first') : await f.tx.submit('first', f.raw);
        assert.ok(uncertain);
        assert.equal(uncertain.status, 'unknown');
        assert.equal(uncertain.hash, keccak256(f.raw));
        assert.equal(uncertain.from, account.address);
        assert.equal(uncertain.to, target);
        assert.equal(uncertain.nonce, '0');
        assert.equal(uncertain.confirmations, 0);
        assert.equal(uncertain.blockHash, undefined);
        assert.equal(uncertain.blockNumber, undefined);
        const repeated = await f.tx.submit('first', f.raw);
        assert.equal(repeated.status, 'unknown');
        assert.equal(repeated.hash, uncertain.hash);
        assert.equal(repeated.confirmations, 0);
        assert.equal(f.state.broadcasts, 1);
        f.state.receiptStatus = previouslyConfirmed ? '0x0' : '0x1';
        const observed = await f.tx.get('first');
        assert.equal(observed?.status, previouslyConfirmed ? 'reverted' : 'confirmed');
        assert.equal(observed?.hash, uncertain.hash);
        assert.equal(observed?.confirmations, 2);
        assert.equal(observed?.blockHash, blockHash);
        assert.equal(f.state.broadcasts, 1);
      } finally { f.tx.close(); }
    }
  }
});

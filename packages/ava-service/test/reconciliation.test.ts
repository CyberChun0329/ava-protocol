import assert from 'node:assert/strict';
import { setImmediate } from 'node:timers/promises';
import { test } from 'node:test';
import { createPublicClient, custom, keccak256, type Hex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { AvaTransactions, TransactionValidationError } from '../src/transactions.ts';
import type { TransactionRecord } from '@ava-protocol/sdk';

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
  const other = await account.signTransaction({ chainId: 31337, to: target, nonce: 1, gas: 21000n, gasPrice: 1n, type: 'legacy' });
  const entered = signal(), release = signal();
  const state = { hold: '' as '' | 'canonical' | 'broadcast', fault: '' as '' | 'receipt' | 'context',
    lostBroadcast: false, wrongChain: false, broadcasts: 0 };
  const client = createPublicClient({ cacheTime: 0, transport: custom({ request: async ({ method, params }) => {
    if (method === 'eth_chainId') {
      if (state.fault === 'context') throw { code: -32000, message: 'Synthetic context outage' };
      return state.wrongChain ? '0x1' : '0x7a69';
    }
    if (method === 'eth_getCode') return '0x6000';
    if (method === 'eth_sendRawTransaction') {
      state.broadcasts++;
      if (state.hold === 'broadcast') { state.hold = ''; entered.resolve(); await release.promise; }
      if (state.lostBroadcast) throw { code: -32000, message: 'Synthetic lost response after acceptance' };
      return keccak256((params as [Hex])[0]);
    }
    if (method === 'eth_getTransactionReceipt') {
      if (state.fault === 'receipt') throw { code: -32000, message: 'Synthetic receipt outage' };
      const second = (params as [Hex])[0] === keccak256(other);
      return { transactionHash: (params as [Hex])[0], blockHash: second ? `0x${'44'.repeat(32)}` : blockHash,
        blockNumber: second ? '0x2' : '0x1', from: account.address, to: target,
        transactionIndex: '0x0', contractAddress: null, cumulativeGasUsed: '0x5208', gasUsed: '0x5208',
        effectiveGasPrice: '0x1', logsBloom: `0x${'00'.repeat(256)}`, status: '0x1', type: '0x0', logs: [] };
    }
    if (method === 'eth_blockNumber') return '0x2';
    assert.equal(method, 'eth_getBlockByNumber');
    if ((params as [string])[0] === '0x0') return { number: '0x0', hash: genesis, transactions: [] };
    const second = (params as [string])[0] === '0x2';
    const sampled = { number: second ? '0x2' : '0x1', hash: second ? `0x${'44'.repeat(32)}` : blockHash,
      parentHash: second ? blockHash : genesis, transactions: [] };
    if (state.hold === 'canonical') { state.hold = ''; entered.resolve(); await release.promise; }
    return sampled;
  } }, { retryCount: 0 }) });
  return { tx: new AvaTransactions({ client, databasePath: ':memory:', allowedTargets: [target] }),
    raw, other, entered, release, state };
}

test('a delayed alias observation cannot overwrite a later outage and the same identity can recover', async () => {
  for (const fault of ['receipt', 'context'] as const) {
    const f = await fixture();
    try {
      await f.tx.submit('first', f.raw);
      await f.tx.submit('alias', f.raw);
      f.state.hold = 'canonical';
      const completed: TransactionRecord[] = [];
      const older = f.tx.get('first').then(record => { completed.push(record!); });
      await f.entered.promise;
      f.state.fault = fault;
      const newer = f.tx.get('alias').then(record => { completed.push(record!); });
      // Give the immediate RPC fixture a full turn; a queued observer may still wait.
      await setImmediate();
      f.release.resolve();
      await Promise.all([older, newer]);
      assert.equal(completed.at(-1)!.status, 'unknown');
      assert.equal(completed.at(-1)!.blockHash, undefined);
      assert.equal(completed.at(-1)!.confirmations, 0);
      f.state.fault = '';
      const recovered = await f.tx.get('alias');
      assert.equal(recovered?.status, 'confirmed');
      assert.equal(recovered?.hash, keccak256(f.raw));
      assert.equal(f.state.broadcasts, 1);
    } finally { f.release.resolve(); f.tx.close(); }
  }
});

test('a delayed lost broadcast response cannot replace an alias observation and never broadcasts twice', async () => {
  const f = await fixture();
  try {
    f.state.hold = 'broadcast';
    const completed: TransactionRecord[] = [];
    const submitted = f.tx.submit('first', f.raw).then(record => { completed.push(record); });
    await f.entered.promise;
    const alias = f.tx.submit('alias', f.raw).then(record => { completed.push(record); });
    await setImmediate();
    f.state.lostBroadcast = true;
    f.release.resolve();
    await Promise.all([submitted, alias]);
    assert.equal(completed.at(-1)!.status, 'confirmed');
    assert.equal(completed.at(-1)!.hash, keccak256(f.raw));
    assert.equal(f.state.broadcasts, 1);
    assert.equal((await f.tx.get('first'))?.hash, (await f.tx.get('alias'))?.hash);
  } finally { f.release.resolve(); f.tx.close(); }
});

test('other hashes progress independently and a rejected observation does not poison later legal reads', async () => {
  const f = await fixture();
  const pending: Promise<unknown>[] = [];
  try {
    await f.tx.submit('first', f.raw);
    await f.tx.submit('other', f.other);
    f.state.hold = 'canonical';
    const active = f.tx.get('first'); pending.push(active);
    await f.entered.promise;
    const other = f.tx.get('other'); pending.push(other);
    const independent = await Promise.race([other, setImmediate().then(() => undefined)]);
    assert.equal(independent?.hash, keccak256(f.other));
    f.state.wrongChain = true;
    const rejected = assert.rejects(f.tx.get('first'), TransactionValidationError); pending.push(rejected);
    f.release.resolve();
    await Promise.all([active, rejected]);
    f.state.wrongChain = false;
    assert.equal((await f.tx.get('first'))?.status, 'confirmed');
    assert.equal(f.state.broadcasts, 2);
  } finally { f.release.resolve(); await Promise.allSettled(pending); f.tx.close(); }
});

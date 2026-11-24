import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { setImmediate } from 'node:timers/promises';
import { createPublicClient, custom, decodeFunctionData, encodeFunctionResult, keccak256, toHex, zeroHash,
  type Abi, type Address, type Hex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { AvaSdk, avaAbis, correctionsAbi, executionAbi, type CoreAddresses } from '@ava-protocol/sdk';
import { AvaTransactions, TransactionConflictError, TransactionValidationError } from '../src/transactions.ts';
import { buildAvaService } from '../src/server.ts';
import { WorkQueueCancelledError, WorkQueueFullError } from '../src/work-queue.ts';

// Anvil's public development key; every transaction and RPC response is synthetic.
const account = privateKeyToAccount('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80');
const target: Address = '0x0000000000000000000000000000000000000020';
const genesis = `0x${'33'.repeat(32)}`, block = `0x${'22'.repeat(32)}`;
const addresses = Object.fromEntries(Object.keys(avaAbis).map((name, index) =>
  [name, toHex(BigInt(index + 1), { size: 20 })])) as CoreAddresses;
const correctionAddress = toHex(10n, { size: 20 }), executionAddress = toHex(11n, { size: 20 });
function gate() {
  let resolve!: () => void;
  return { promise: new Promise<void>(accept => { resolve = accept; }), resolve: () => resolve() };
}
async function fixture() {
  const raw = await account.signTransaction({ type: 'legacy', chainId: 31337, to: target,
    nonce: 0, gas: 21000n, gasPrice: 1n, data: '0x1234' });
  const state = { failBroadcast: true, mined: false, reverted: false, broadcasts: [] as Hex[],
    chainId: '0x7a69', genesis, code: '0x6000', fault: '' as '' | 'context' | 'receipt',
    onReceipt: undefined as (() => Promise<void>) | undefined,
    onBroadcast: undefined as (() => Promise<void>) | undefined };
  const abis = new Map<string, Abi>(Object.entries(avaAbis).map(([name, abi]) =>
    [addresses[name as keyof CoreAddresses], abi]));
  abis.set(correctionAddress, correctionsAbi); abis.set(executionAddress, executionAbi);
  const links: Record<string, Address> = { APPLICATION_REGISTRY: addresses.applications,
    IDENTITY_REGISTRY: addresses.identities, AUTHORITY_MATRIX: addresses.authority,
    RULE_PACKAGE_REGISTRY: addresses.packages, EVIDENCE_REGISTRY: addresses.evidence,
    DISCLOSURE_REGISTRY: addresses.disclosure, GOVERNANCE_KERNEL: addresses.kernel,
    REQUEST_ALLOCATION: addresses.requests, CORRECTIONS: correctionAddress, EXECUTION: executionAddress };
  const client = createPublicClient({ cacheTime: 0, transport: custom({ request: async ({ method, params }) => {
    if (method === 'eth_chainId') {
      if (state.fault === 'context') throw new Error('SYNTHETIC_PRIVATE_PROVIDER context unavailable');
      return state.chainId;
    }
    if (method === 'eth_getCode') return state.code;
    if (method === 'eth_getBlockByNumber') {
      const number = (params as [string])[0] === '0x0' ? '0x0' : '0x1';
      return { number, hash: number === '0x0' ? state.genesis : block,
        parentHash: number === '0x0' ? zeroHash : genesis, transactions: [] };
    }
    if (method === 'eth_blockNumber') return '0x1';
    if (method === 'eth_getLogs') return [];
    if (method === 'eth_call') {
      const call = (params as [{ to: Address; data: Hex }])[0], abi = abis.get(call.to.toLowerCase())!;
      const decoded = decodeFunctionData({ abi, data: call.data });
      const result = links[decoded.functionName];
      assert(result, `expected Core verification call ${decoded.functionName}`);
      return encodeFunctionResult({ abi, functionName: decoded.functionName, result });
    }
    if (method === 'eth_sendRawTransaction') {
      state.broadcasts.push((params as [Hex])[0]);
      await state.onBroadcast?.();
      if (state.failBroadcast) throw new Error(`SYNTHETIC_PRIVATE_PROVIDER rejected ${raw}`);
      state.mined = true;
      return keccak256((params as [Hex])[0]);
    }
    if (method === 'eth_getTransactionReceipt') {
      await state.onReceipt?.();
      if (state.fault === 'receipt') throw new Error('SYNTHETIC_PRIVATE_PROVIDER receipt unavailable');
      return !state.mined ? null : {
        transactionHash: (params as [Hex])[0], blockHash: block, blockNumber: '0x1',
        from: account.address, to: target, transactionIndex: '0x0', contractAddress: null,
        cumulativeGasUsed: '0x5208', gasUsed: '0x5208', effectiveGasPrice: '0x1',
        logsBloom: `0x${'00'.repeat(256)}`, status: state.reverted ? '0x0' : '0x1', type: '0x0', logs: [] };
    }
    if (method === 'eth_getTransactionByHash') return null;
    throw new Error(`Unexpected synthetic RPC ${method}`);
  } }, { retryCount: 0 }) });
  return { raw, state, client };
}

test('only explicit recovery resends original persisted bytes after a failed broadcast and service reopen', async () => {
  const f = await fixture(), directory = await mkdtemp(join(tmpdir(), 'ava-explicit-recovery-'));
  const options = { client: f.client, databasePath: join(directory, 'transactions.sqlite'), allowedTargets: [target] };
  let transactions = new AvaTransactions(options);
  try {
    const original = await transactions.submit('original', f.raw);
    assert.equal(original.status, 'unknown');
    assert.equal(original.error, 'Broadcast outcome unknown');
    assert.equal(original.nonce, '0');
    transactions.close();
    transactions = new AvaTransactions(options);
    assert.equal((await transactions.submit('original', f.raw)).status, 'unknown');
    assert.equal((await transactions.get('original'))?.hash, original.hash);
    assert.equal((await transactions.submit('alias', f.raw)).hash, original.hash);
    assert.deepEqual(f.state.broadcasts, [f.raw], 'ordinary duplicate submit and observation do not resend');
    f.state.failBroadcast = false;
    const recovered = await transactions.recover('original', f.raw);
    assert.equal(recovered.status, 'confirmed');
    assert.equal(recovered.hash, original.hash);
    assert.equal(recovered.nonce, original.nonce);
    assert.equal(recovered.from, original.from);
    assert.equal(recovered.to, original.to);
    assert.equal((await transactions.get('alias'))?.status, 'confirmed');
    assert.deepEqual(f.state.broadcasts, [f.raw, f.raw]);
    assert.doesNotMatch(JSON.stringify(recovered), /SYNTHETIC_PRIVATE_PROVIDER|serializedTransaction/);
  } finally { transactions.close(); await rm(directory, { recursive: true, force: true }); }
});

test('the authenticated local HTTP recovery route completes the existing identity', async () => {
  const f = await fixture(), directory = await mkdtemp(join(tmpdir(), 'ava-recovery-http-'));
  const token = 'synthetic-local-recovery-token-at-least-32-chars';
  const service = await buildAvaService({ client: f.client, sdk: new AvaSdk({ chainId: 31337, addresses }),
    databasePath: join(directory, 'service.sqlite'), token, transactionConcurrency: 1, transactionQueueLimit: 0,
    additionalSources: { synthetic: { address: target, abi: [] } } });
  try {
    const submitted = await service.app.inject({ method: 'POST', url: '/v1/transactions',
      headers: { authorization: `Bearer ${token}` }, payload: { key: 'original', serializedTransaction: f.raw } });
    assert.equal(submitted.statusCode, 200);
    assert.equal(submitted.json().status, 'unknown');
    f.state.failBroadcast = false;
    const recovered = await service.app.inject({ method: 'POST', url: '/v1/transactions/original/recover',
      headers: { authorization: `Bearer ${token}` }, payload: { serializedTransaction: f.raw } });
    assert.equal(recovered.statusCode, 200);
    assert.equal(recovered.json().hash, submitted.json().hash);
    assert.equal(recovered.json().status, 'confirmed');
    assert.deepEqual(f.state.broadcasts, [f.raw, f.raw]);
    for (const [url, headers, payload, status, error] of [
      ['/v1/transactions/original/recover', {}, { serializedTransaction: f.raw }, 401, 'bearer_token_required'],
      ['/v1/transactions/original/recover', { host: 'external.example', authorization: `Bearer ${token}` },
        { serializedTransaction: f.raw }, 403, 'local_host_required'],
      ['/v1/transactions/original/recover', { authorization: `Bearer ${token}` }, {}, 400, 'invalid_request'],
      ['/v1/transactions/original/recover', { authorization: `Bearer ${token}` },
        { serializedTransaction: '0x1' }, 400, 'invalid_transaction'],
      ['/v1/transactions/original/recover', { authorization: `Bearer ${token}` },
        { serializedTransaction: '0x00' }, 409, 'transaction_conflict'],
      ['/v1/transactions/absent/recover', { authorization: `Bearer ${token}` },
        { serializedTransaction: f.raw }, 400, 'invalid_transaction'],
    ] as const) {
      const response = await service.app.inject({ method: 'POST', url, headers, payload });
      assert.equal(response.statusCode, status);
      assert.deepEqual(response.json(), { error });
      assert(!response.body.includes(f.raw));
    }
    const entered = gate(), release = gate();
    f.state.onReceipt = async () => { entered.resolve(); await release.promise; };
    const active = service.transactions.get('original');
    try {
      await entered.promise;
      const full = await service.app.inject({ method: 'POST', url: '/v1/transactions/original/recover',
        headers: { authorization: `Bearer ${token}` }, payload: { serializedTransaction: f.raw } });
      assert.equal(full.statusCode, 429);
      assert.deepEqual(full.json(), { error: 'work_queue_full' });
    } finally { release.resolve(); await active; f.state.onReceipt = undefined; }
    assert.deepEqual(f.state.broadcasts, [f.raw, f.raw]);
  } finally { await service.app.close(); await rm(directory, { recursive: true, force: true }); }
});

test('recovery refuses absent keys, different signed bytes and changed node identity without creating a transaction', async () => {
  const f = await fixture();
  const transactions = new AvaTransactions({ client: f.client, databasePath: ':memory:', allowedTargets: [target] });
  try {
    const original = await transactions.submit('original', f.raw);
    const other = await account.signTransaction({ type: 'legacy', chainId: 31337, to: target,
      nonce: 0, gas: 21000n, gasPrice: 1n, data: '0x5678' });
    await assert.rejects(transactions.recover('absent', f.raw), TransactionValidationError);
    assert.equal(await transactions.get('absent'), undefined);
    await assert.rejects(transactions.recover('original', other), TransactionConflictError);
    f.state.chainId = '0x1';
    await assert.rejects(transactions.recover('original', f.raw), TransactionValidationError);
    f.state.chainId = '0x7a69'; f.state.genesis = zeroHash;
    await assert.rejects(transactions.recover('original', f.raw), TransactionValidationError);
    f.state.genesis = genesis; f.state.code = '0x';
    await assert.rejects(transactions.recover('original', f.raw), TransactionValidationError);
    f.state.code = '0x6000'; f.state.fault = 'context';
    const unavailable = await transactions.recover('original', f.raw);
    assert.equal(unavailable.hash, original.hash);
    assert.equal(unavailable.status, 'unknown');
    assert.equal(unavailable.confirmations, 0);
    assert.equal(unavailable.error, 'Chain verification unavailable');
    assert.deepEqual(f.state.broadcasts, [f.raw]);
    assert.doesNotMatch(JSON.stringify(unavailable), /SYNTHETIC_PRIVATE_PROVIDER/);
  } finally { transactions.close(); }
});

test('failed recovery and receipt outages keep the original outcome unknown until canonical observation succeeds', async () => {
  const f = await fixture();
  const transactions = new AvaTransactions({ client: f.client, databasePath: ':memory:', allowedTargets: [target] });
  try {
    const original = await transactions.submit('original', f.raw);
    const failed = await transactions.recover('original', f.raw);
    assert.equal(failed.hash, original.hash);
    assert.equal(failed.nonce, original.nonce);
    assert.equal(failed.status, 'unknown');
    assert.equal(failed.error, 'Broadcast outcome unknown');
    assert.doesNotMatch(JSON.stringify(failed), /SYNTHETIC_PRIVATE_PROVIDER/);
    f.state.failBroadcast = false; f.state.fault = 'receipt';
    const uncertain = await transactions.recover('original', f.raw);
    assert.equal(uncertain.hash, original.hash);
    assert.equal(uncertain.status, 'unknown');
    assert.equal(uncertain.confirmations, 0);
    assert.equal(uncertain.blockHash, undefined);
    assert.equal(uncertain.error, 'Receipt verification unavailable');
    assert.equal((await transactions.get('original'))?.status, 'unknown');
    assert.equal((await transactions.submit('original', f.raw)).status, 'unknown');
    assert.deepEqual(f.state.broadcasts, [f.raw, f.raw, f.raw]);
    f.state.fault = '';
    assert.equal((await transactions.recover('original', f.raw)).status, 'confirmed');
    assert.deepEqual(f.state.broadcasts, [f.raw, f.raw, f.raw], 'canonical observation completes the original without another resend');
  } finally { transactions.close(); }
});

test('canonical success, reversion and mined transactions awaiting depth are observed without recovery resend', async () => {
  for (const [reverted, confirmations, status] of [[false, 1, 'confirmed'], [true, 1, 'reverted'], [false, 2, 'pending']] as const) {
    const f = await fixture();
    const transactions = new AvaTransactions({ client: f.client, databasePath: ':memory:', allowedTargets: [target], confirmations });
    try {
      const original = await transactions.submit('original', f.raw);
      f.state.mined = true; f.state.reverted = reverted;
      const observed = await transactions.recover('original', f.raw);
      assert.equal(observed.hash, original.hash);
      assert.equal(observed.status, status);
      assert.equal(observed.blockHash, block);
      assert.equal(observed.confirmations, 1);
      assert.deepEqual(f.state.broadcasts, [f.raw]);
    } finally { transactions.close(); }
  }
});

test('recovery shares one hash owner across aliases and does not resend after the first lawful completion', async () => {
  const f = await fixture(), entered = gate(), release = gate();
  const transactions = new AvaTransactions({ client: f.client, databasePath: ':memory:', allowedTargets: [target] });
  const pending: Promise<unknown>[] = [];
  try {
    await transactions.submit('original', f.raw);
    await transactions.submit('alias', f.raw);
    f.state.failBroadcast = false;
    f.state.onBroadcast = async () => { entered.resolve(); await release.promise; };
    const first = transactions.recover('original', f.raw); pending.push(first);
    await entered.promise;
    const alias = transactions.recover('alias', f.raw); pending.push(alias);
    await setImmediate();
    assert.deepEqual(f.state.broadcasts, [f.raw, f.raw]);
    release.resolve();
    assert.equal((await first).status, 'confirmed');
    assert.equal((await alias).status, 'confirmed');
    assert.equal((await transactions.get('original'))?.hash, (await transactions.get('alias'))?.hash);
    assert.deepEqual(f.state.broadcasts, [f.raw, f.raw]);
  } finally { release.resolve(); await Promise.allSettled(pending); transactions.close(); }
});

test('queued recovery can be cancelled or refused at capacity without resending and remains available later', async () => {
  const f = await fixture(), entered = gate(), release = gate();
  const transactions = new AvaTransactions({ client: f.client, databasePath: ':memory:', allowedTargets: [target],
    concurrency: 1, maxPending: 1 });
  const pending: Promise<unknown>[] = [];
  try {
    const original = await transactions.submit('original', f.raw);
    f.state.onReceipt = async () => { entered.resolve(); await release.promise; };
    const active = transactions.get('original'); pending.push(active);
    await entered.promise;
    const controller = new AbortController();
    const cancelled = assert.rejects(transactions.recover('original', f.raw, { signal: controller.signal }), WorkQueueCancelledError);
    pending.push(cancelled);
    await assert.rejects(transactions.recover('original', f.raw), WorkQueueFullError);
    controller.abort(); await cancelled;
    const preAborted = new AbortController(); preAborted.abort();
    await assert.rejects(transactions.recover('original', f.raw, { signal: preAborted.signal }), WorkQueueCancelledError);
    assert.deepEqual(f.state.broadcasts, [f.raw]);
    release.resolve(); await active;
    f.state.onReceipt = undefined; f.state.failBroadcast = false;
    const recovered = await transactions.recover('original', f.raw);
    assert.equal(recovered.hash, original.hash);
    assert.equal(recovered.status, 'confirmed');
    assert.deepEqual(f.state.broadcasts, [f.raw, f.raw]);
  } finally { release.resolve(); await Promise.allSettled(pending); transactions.close(); }
});

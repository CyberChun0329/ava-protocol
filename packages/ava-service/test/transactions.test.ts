import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, type ChildProcess } from 'node:child_process';
import { createServer } from 'node:net';
import { mkdtemp, readFile } from 'node:fs/promises';
import { createWriteStream } from 'node:fs';
import { resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { BaseError, createPublicClient, createTestClient, createWalletClient, custom, encodeFunctionData, http, keccak256,
  parseTransaction, serializeTransaction, stringToHex, toHex,
  type Abi, type Address, type Hex, type PublicClient } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { foundry } from 'viem/chains';
import { AvaTransactions } from '../src/transactions.js';

// Anvil's published development account. No wallet files or private user accounts.
const account = privateKeyToAccount('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80');
let anvil: ChildProcess;
let client: PublicClient;
let chain: ReturnType<typeof createTestClient>;
let address: Address;
let abi: Abi;
let directory: string;
const key = (s: string) => keccak256(stringToHex(s));
const options = (file: string) => ({ client, databasePath: resolve(directory, file), allowedTargets: [address] });

before(async () => {
  directory = await mkdtemp(resolve('.tmp/transactions-test-'));
  const port = await new Promise<number>((accept, reject) => {
    const server = createServer();
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const port = (server.address() as { port: number }).port;
      server.close(() => accept(port));
    });
  });
  const log = createWriteStream(resolve(directory, 'anvil.log'));
  anvil = spawn('anvil', ['--host', '127.0.0.1', '--port', String(port), '--silent']);
  anvil.stdout!.pipe(log);
  anvil.stderr!.pipe(log);
  const transport = http(`http://127.0.0.1:${port}`, { retryCount: 0, timeout: 1000 });
  client = createPublicClient({ transport, cacheTime: 0 });
  chain = createTestClient({ mode: 'anvil', transport });
  let ready = false;
  for (let attempt = 0; attempt < 100; attempt++) {
    try { await client.getChainId(); ready = true; break; } catch { await delay(20); }
  }
  assert(ready, 'isolated Anvil started');
  const artifact = JSON.parse(await readFile('.build/out/AVAApplicationRegistry.sol/AVAApplicationRegistry.json', 'utf8'));
  abi = artifact.abi;
  const wallet = createWalletClient({ account, chain: foundry, transport });
  const hash = await wallet.deployContract({ abi, bytecode: artifact.bytecode.object,
    args: [account.address], account, chain: foundry });
  address = (await client.waitForTransactionReceipt({ hash })).contractAddress!;
});
after(() => { anvil?.kill(); });

async function signed(name: string, overrides: { chainId?: number; nonce?: number; to?: Address; data?: Hex } = {}) {
  const nonce = overrides.nonce ?? await client.getTransactionCount({ address: account.address, blockTag: 'pending' });
  const data = overrides.data ?? encodeFunctionData({ abi, functionName: 'registerApplication',
    args: [key(name), key('identity'), key('authority'), account.address, `local:${name}`] });
  return account.signTransaction({ type: 'eip1559', chainId: overrides.chainId ?? 31337,
    nonce, to: overrides.to ?? address, data, gas: 800_000n,
    maxFeePerGas: 20_000_000_000n, maxPriorityFeePerGas: 1_000_000_000n });
}

test('signed submission is idempotent across aliases and reopening, and conflicts cannot replace it', async () => {
  const opts = options('idempotent.sqlite');
  const manager = new AvaTransactions(opts);
  const before = await client.getTransactionCount({ address: account.address });
  const raw = await signed('idempotent');
  const first = await manager.submit('first', raw);
  assert.equal(first.status, 'confirmed');
  assert.equal(first.from.toLowerCase(), account.address.toLowerCase());
  assert.equal(first.nonce, String(before));
  assert.equal(first.confirmations, 1);
  assert.equal((await manager.submit('first', raw)).hash, first.hash);
  assert.equal((await manager.submit('alias', raw)).hash, first.hash);
  assert.equal((await manager.get('alias'))?.key, 'alias');
  assert.equal(await client.getTransactionCount({ address: account.address }), before + 1);
  await assert.rejects(manager.submit('first', await signed('changed-key')), /idempotency/i);
  await assert.rejects(manager.submit('replacement', await signed('changed-nonce', { nonce: before })), /nonce/i);
  manager.close();
  const reopened = new AvaTransactions(opts);
  assert.equal((await reopened.get('first'))?.hash, first.hash);
  assert.equal((await reopened.submit('first', raw)).status, 'confirmed');
  assert.equal(await client.getTransactionCount({ address: account.address }), before + 1);
  reopened.close();
});

test('canonical success waits for confirmation depth and execution reverts remain distinct', async () => {
  const manager = new AvaTransactions({ ...options('depth.sqlite'), confirmations: 2 });
  const first = await manager.submit('depth', await signed('depth'));
  assert.equal(first.status, 'pending');
  assert.equal(first.confirmations, 1);
  await chain.mine({ blocks: 1 });
  const confirmed = await manager.get('depth');
  assert.equal(confirmed?.status, 'confirmed');
  assert.equal(confirmed.confirmations, 2);
  const duplicate = await manager.submit('revert', await signed('depth'));
  assert.equal(duplicate.status, 'pending');
  assert.match(duplicate.error!, /execution reverted/i);
  await chain.mine({ blocks: 1 });
  const reverted = await manager.get('revert');
  assert.equal(reverted?.status, 'reverted');
  assert.notEqual(reverted.hash, confirmed.hash);
  assert.equal((await client.getTransactionReceipt({ hash: reverted.hash })).status, 'reverted');
  manager.close();
});

test('an accepted transaction whose broadcast response was lost is recoverable after reopening', async () => {
  let lost = false;
  let receiptUnavailable = false;
  const privateDiagnostic = 'endpoint ?token=SYNTHETIC_SECRET private=Alice';
  const opts = options('lost-response.sqlite');
  const boundaryClient = rpcBoundary(async (method, run) => {
    if (receiptUnavailable && method === 'eth_getTransactionReceipt') throw new BaseError(privateDiagnostic);
    if (method === 'eth_sendRawTransaction' && !lost) {
      const reader = new AvaTransactions(opts);
      const durable = await reader.get('uncertain');
      assert.equal(durable?.status, 'unknown', 'identity is visible to another connection before broadcast');
      assert.equal(durable.nonce, String(before));
      assert.equal(await client.getTransactionCount({ address: account.address }), before);
      reader.close();
    }
    const response = await run();
    if (method === 'eth_sendRawTransaction' && !lost) {
      lost = true;
      throw new BaseError(privateDiagnostic);
    }
    return response;
  });
  const manager = new AvaTransactions({ ...opts, client: boundaryClient });
  const raw = await signed('lost-response');
  const before = await client.getTransactionCount({ address: account.address });
  const submitted = await manager.submit('uncertain', raw);
  assert.equal(submitted.status, 'unknown');
  assert.match(submitted.error!, /broadcast outcome unknown/i);
  assert(!JSON.stringify(submitted).includes('SYNTHETIC_SECRET'));
  assert(!JSON.stringify(submitted).includes('Alice'));
  assert.equal(submitted.hash, keccak256(raw));
  assert.equal(await client.getTransactionCount({ address: account.address }), before + 1);
  assert.equal((await client.getTransactionReceipt({ hash: submitted.hash })).status, 'success');
  assert(!JSON.stringify(submitted).includes(raw.slice(0, 120)), 'records do not expose serialized signed bytes');
  manager.close();
  const persisted = await readFile(opts.databasePath);
  assert(!persisted.includes(Buffer.from('SYNTHETIC_SECRET')), 'durable records must not store provider credentials');
  assert(!persisted.includes(Buffer.from('private=Alice')), 'durable records must not store private diagnostics');
  receiptUnavailable = true;
  const reopened = new AvaTransactions({ ...opts, client: boundaryClient });
  const unavailable = await reopened.get('uncertain');
  assert.equal(unavailable?.status, 'unknown');
  assert.equal(unavailable.hash, submitted.hash);
  assert(!JSON.stringify(unavailable).includes('SYNTHETIC_SECRET'));
  assert(!JSON.stringify(unavailable).includes('Alice'));
  receiptUnavailable = false;
  const recovered = await reopened.submit('uncertain', raw);
  assert.equal(recovered.status, 'confirmed');
  assert.equal(recovered.hash, submitted.hash);
  assert.equal(await client.getTransactionCount({ address: account.address }), before + 1);
  reopened.close();
});

test('operator recovers an unaccepted transaction by broadcasting the original signed bytes', async () => {
  const opts = options('manual-recovery.sqlite');
  const balance = await client.getBalance({ address: account.address });
  const nonce = await client.getTransactionCount({ address: account.address });
  const raw = await signed('manual-recovery', { nonce });
  let broadcasts = 0;
  const boundaryClient = rpcBoundary((method, run) => {
    if (method === 'eth_sendRawTransaction') broadcasts++;
    return run();
  });
  const manager = new AvaTransactions({ ...opts, client: boundaryClient });
  try {
    await chain.setBalance({ address: account.address, value: 0n });
    const first = await manager.submit('original', raw);
    assert.equal(first.status, 'unknown');
    assert.equal(first.hash, keccak256(raw));
    assert.equal(broadcasts, 1);
    assert.equal(await client.getTransactionCount({ address: account.address }), nonce);
    assert.equal((await manager.submit('original', raw)).status, 'unknown');
    assert.equal((await manager.submit('alias', raw)).hash, first.hash);
    await assert.rejects(manager.submit('replacement', await signed('different-bytes', { nonce })), /nonce/i);
    assert.equal(broadcasts, 1, 'retries and conflicting bytes do not rebroadcast');
    await chain.setBalance({ address: account.address, value: balance });
    assert.equal(await client.sendRawTransaction({ serializedTransaction: raw }), first.hash);
    await client.waitForTransactionReceipt({ hash: first.hash });
    const recovered = await manager.get('original');
    assert.equal(recovered?.hash, first.hash);
    assert.equal(recovered.status, 'confirmed');
    assert.equal((await manager.get('alias'))?.hash, first.hash);
  } finally {
    await chain.setBalance({ address: account.address, value: balance });
    manager.close();
  }
});

test('receipt disappearance and a stale orphan receipt cannot retain confirmed status after reorg', async () => {
  const opts = options('reorg.sqlite');
  const manager = new AvaTransactions(opts);
  const snapshot = await chain.snapshot();
  const original = await manager.submit('reorg', await signed('orphaned'));
  assert.equal(original.status, 'confirmed');
  const rawRequest = client.transport.request as (args: { method: string; params?: unknown }) => Promise<unknown>;
  const oldReceipt = await rawRequest({ method: 'eth_getTransactionReceipt', params: [original.hash] });
  await chain.revert({ id: snapshot });
  const replacement = await client.sendRawTransaction({ serializedTransaction: await signed('replacement-chain-block') });
  await client.waitForTransactionReceipt({ hash: replacement });
  const orphan = await manager.get('reorg');
  assert.equal(orphan?.hash, original.hash);
  assert.equal(orphan.status, 'unknown');
  assert.equal(orphan.confirmations, 0);
  assert.equal(orphan.blockHash, undefined);
  manager.close();
  const staleClient = rpcBoundary((method, run) => method === 'eth_getTransactionReceipt'
    ? Promise.resolve(oldReceipt) : run());
  const stale = new AvaTransactions({ ...opts, client: staleClient });
  const checked = await stale.get('reorg');
  assert.equal(checked?.status, 'pending');
  assert.equal(checked.confirmations, 0);
  assert.equal(checked.blockHash, undefined);
  assert.match(checked.error!, /canonical chain/i);
  stale.close();
});

test('receipt RPC failure withdraws confirmed status and recovers when verification is available again', async () => {
  let unavailable = false;
  const boundaryClient = rpcBoundary((method, run) => {
    if (unavailable && method === 'eth_getTransactionReceipt') throw new Error('Receipt RPC unavailable');
    return run();
  });
  const manager = new AvaTransactions({ ...options('receipt-outage.sqlite'), client: boundaryClient });
  const original = await manager.submit('receipt-outage', await signed('receipt-outage'));
  assert.equal(original.status, 'confirmed');
  unavailable = true;
  const uncertain = await manager.get('receipt-outage');
  assert.equal(uncertain?.status, 'unknown');
  assert.equal(uncertain.hash, original.hash);
  assert.equal(uncertain.confirmations, 0);
  assert.equal(uncertain.blockNumber, undefined);
  assert.match(uncertain.error!, /verification unavailable/i);
  unavailable = false;
  assert.equal((await manager.get('receipt-outage'))?.status, 'confirmed');
  manager.close();
});

test('unsafe keys, malformed or unsigned payloads, wrong chains, creation and unknown targets are rejected before broadcast', async () => {
  const manager = new AvaTransactions(options('validation.sqlite'));
  const before = await client.getTransactionCount({ address: account.address });
  const good = await signed('invalid-input');
  await assert.rejects(manager.submit('', good), /idempotency/i);
  await assert.rejects(manager.submit('a'.repeat(129), good), /idempotency/i);
  await assert.rejects(manager.submit('bad\nkey', good), /idempotency/i);
  await assert.rejects(manager.submit('invalid', '0x123' as Hex), /invalid/i);
  await assert.rejects(manager.submit('oversize', `0x${'ff'.repeat(128 * 1024 + 1)}`), /128 KiB/i);
  await assert.rejects(manager.submit('wrong-chain', await signed('wrong-chain', { chainId: 1 })), /chain 31337/i);
  const legacy = await account.signTransaction({ type: 'legacy', nonce: before, to: address,
    gas: 100_000n, gasPrice: 2_000_000_000n });
  await assert.rejects(manager.submit('unprotected', legacy), /chain 31337/i);
  const creation = await account.signTransaction({ type: 'eip1559', chainId: 31337, nonce: before,
    data: '0x00', gas: 100_000n, maxFeePerGas: 2_000_000_000n, maxPriorityFeePerGas: 1n });
  await assert.rejects(manager.submit('creation', creation), /creation/i);
  await assert.rejects(manager.submit('unknown-target', await signed('unknown-target', { to: account.address })), /allowedTargets/i);
  const unsigned = serializeTransaction({ type: 'eip1559', chainId: 31337, nonce: before,
    to: address, gas: 100_000n, maxFeePerGas: 2_000_000_000n, maxPriorityFeePerGas: 1n });
  await assert.rejects(manager.submit('unsigned', unsigned), /signature/i);
  assert.equal(await manager.get('wrong-chain'), undefined);
  assert.equal(await client.getTransactionCount({ address: account.address }), before);
  manager.close();
  const eoa = new AvaTransactions({ ...options('eoa.sqlite'), allowedTargets: [account.address] });
  await assert.rejects(eoa.submit('eoa', await signed('eoa', { to: account.address })), /deployed contract/i);
  assert.equal(await eoa.get('eoa'), undefined);
  eoa.close();
});

test('noncanonical high-s signatures are rejected before broadcast', async () => {
  const manager = new AvaTransactions(options('high-s.sqlite'));
  const raw = await signed('high-s');
  const parsed = parseTransaction(raw);
  assert.equal(parsed.type, 'eip1559');
  const highS = toHex(0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n - BigInt(parsed.s!), { size: 32 });
  const malleated = serializeTransaction(parsed, { r: parsed.r!, s: highS, yParity: parsed.yParity! === 0 ? 1 : 0 });
  await assert.rejects(manager.submit('high-s', malleated), /signature/i);
  assert.equal(await manager.get('high-s'), undefined);
  manager.close();
});

test('persisted chain genesis, allowed targets and confirmation policy cannot silently change', async () => {
  const opts = options('context.sqlite');
  const manager = new AvaTransactions(opts);
  await manager.submit('context', await signed('context'));
  manager.close();
  assert.throws(() => new AvaTransactions({ ...opts, confirmations: 2 }), /policy/i);
  assert.throws(() => new AvaTransactions({ ...opts, allowedTargets: [account.address] }), /target set/i);
  const differentGenesis = rpcBoundary(async (method, run) => {
    const result = await run();
    return method === 'eth_getBlockByNumber'
      ? { ...result as object, hash: `0x${'ff'.repeat(32)}` } : result;
  });
  const mismatch = new AvaTransactions({ ...opts, client: differentGenesis });
  await assert.rejects(mismatch.get('context'), /different chain genesis/i);
  mismatch.close();
  const wrongNode = rpcBoundary((method, run) => method === 'eth_chainId' ? Promise.resolve('0x1') : run());
  const wrongChain = new AvaTransactions({ ...options('wrong-node.sqlite'), client: wrongNode });
  await assert.rejects(wrongChain.submit('wrong-node', await signed('wrong-node')), /local chain 31337/i);
  wrongChain.close();
});

test('broadcast errors cannot expose raw signed bytes through returned records', async () => {
  const raw = await signed('error-redaction');
  const boundaryClient = rpcBoundary((method, run) => {
    if (method === 'eth_sendRawTransaction') throw new Error(`Transport rejected ${raw}`);
    return run();
  });
  const manager = new AvaTransactions({ ...options('error-redaction.sqlite'), client: boundaryClient });
  const result = await manager.submit('redacted', raw);
  assert.equal(result.status, 'unknown');
  assert(!JSON.stringify(result).includes(raw.slice(0, 120)), 'error text must omit raw signed payloads');
  manager.close();
});

test('same-key retries during a chain RPC outage preserve identity and withdraw stale confirmation', async () => {
  let unavailable = false;
  const boundaryClient = rpcBoundary((method, run) => {
    if (unavailable && method === 'eth_chainId') throw new BaseError('endpoint ?token=SYNTHETIC_CHAIN_SECRET private=Alice');
    return run();
  });
  const manager = new AvaTransactions({ ...options('chain-outage.sqlite'), client: boundaryClient });
  const raw = await signed('chain-outage');
  const original = await manager.submit('chain-outage', raw);
  assert.equal(original.status, 'confirmed');
  unavailable = true;
  const retried = await manager.submit('chain-outage', raw);
  assert.equal(retried.hash, original.hash);
  assert.equal(retried.status, 'unknown');
  assert.equal(retried.confirmations, 0);
  assert.match(retried.error!, /verification unavailable/i);
  assert(!JSON.stringify(retried).includes('SYNTHETIC_CHAIN_SECRET'));
  assert(!JSON.stringify(retried).includes('Alice'));
  await assert.rejects(manager.submit('chain-outage', await signed('conflicting-outage')), /idempotency/i);
  const observed = await manager.get('chain-outage');
  assert.equal(observed?.status, 'unknown');
  assert(!JSON.stringify(observed).includes('SYNTHETIC_CHAIN_SECRET'));
  assert(!JSON.stringify(observed).includes('Alice'));
  unavailable = false;
  assert.equal((await manager.get('chain-outage'))?.status, 'confirmed');
  manager.close();
});

test('transaction lookup outages expose only a safe diagnostic and recover the original hash after reopening', async () => {
  let unavailable = false;
  const boundaryClient = rpcBoundary((method, run) => {
    if (unavailable && method === 'eth_getTransactionReceipt') return Promise.resolve(null);
    if (unavailable && method === 'eth_getTransactionByHash') {
      throw new BaseError('endpoint ?token=SYNTHETIC_LOOKUP_SECRET private=Alice');
    }
    return run();
  });
  const opts = { ...options('lookup-outage.sqlite'), client: boundaryClient };
  const manager = new AvaTransactions(opts);
  const raw = await signed('lookup-outage');
  const original = await manager.submit('lookup-outage', raw);
  assert.equal(original.status, 'confirmed');
  unavailable = true;
  manager.close();
  const reopened = new AvaTransactions(opts);
  try {
    const observed = await reopened.get('lookup-outage');
    assert.equal(observed?.hash, original.hash);
    assert.equal(observed.status, 'unknown');
    assert.equal(observed.confirmations, 0);
    assert.equal(observed.blockHash, undefined);
    assert.match(observed.error!, /transaction lookup unavailable/i);
    assert(!JSON.stringify(observed).includes('SYNTHETIC_LOOKUP_SECRET'));
    assert(!JSON.stringify(observed).includes('Alice'));
    unavailable = false;
    const recovered = await reopened.submit('lookup-outage', raw);
    assert.equal(recovered.hash, original.hash);
    assert.equal(recovered.nonce, original.nonce);
    assert.equal(recovered.status, 'confirmed');
    assert.equal(recovered.error, undefined);
    assert.equal(await client.getTransactionCount({ address: account.address }), Number(original.nonce) + 1);
  } finally { reopened.close(); }
});

test('protected legacy and EIP-2930 calls retain the caller signature and execute normally', async () => {
  const manager = new AvaTransactions(options('transaction-types.sqlite'));
  for (const type of ['legacy', 'eip2930'] as const) {
    const nonce = await client.getTransactionCount({ address: account.address });
    const transaction = { chainId: 31337, nonce, to: address,
      data: encodeFunctionData({ abi, functionName: 'registerApplication',
        args: [key(type), key('identity'), key('authority'), account.address, `local:${type}`] }),
      gas: 800_000n, gasPrice: 2_000_000_000n };
    const raw = await account.signTransaction(type === 'legacy'
      ? { ...transaction, type: 'legacy' } : { ...transaction, type: 'eip2930', accessList: [] });
    const result = await manager.submit(type, raw);
    assert.equal(result.status, 'confirmed');
    assert.equal((await client.getTransaction({ hash: result.hash })).type, type);
  }
  manager.close();
});

function rpcBoundary(intercept: (method: string, run: () => Promise<unknown>) => Promise<unknown>): PublicClient {
  const request = client.transport.request as (args: { method: string; params?: unknown }) => Promise<unknown>;
  return createPublicClient({ cacheTime: 0, transport: custom({
    request: ({ method, params }) => intercept(method, () => request({ method, params })),
  }, { retryCount: 0 }) });
}

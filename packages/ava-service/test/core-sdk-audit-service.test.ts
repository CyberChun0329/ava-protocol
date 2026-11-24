import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { resolve } from 'node:path';
import { test } from 'node:test';
import { createPublicClient, custom, decodeFunctionData, encodeFunctionResult, keccak256, toHex, zeroHash,
  type Abi, type Address, type Hex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { AvaSdk, avaAbis, correctionsAbi, executionAbi, type CoreAddresses } from '@ava-protocol/sdk';
import { buildAvaService } from '../src/server.ts';

const account = privateKeyToAccount('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80');
const token = 'synthetic-local-audit-token-at-least-32-chars';
const target: Address = '0x0000000000000000000000000000000000000020';
const genesis = `0x${'33'.repeat(32)}` as Hex, block = `0x${'22'.repeat(32)}` as Hex;
const addresses = Object.fromEntries(Object.keys(avaAbis).map((name, index) =>
  [name, toHex(BigInt(index + 1), { size: 20 })])) as CoreAddresses;
const correctionAddress = toHex(10n, { size: 20 }), executionAddress = toHex(11n, { size: 20 });

async function fixture() {
  const directory = await mkdtemp(resolve(process.env.AVA_TEST_OUTPUT_ROOT ?? '.tmp', 'service-audit-'));
  const raw = await account.signTransaction({ type: 'legacy', chainId: 31337, to: target,
    nonce: 0, gas: 21000n, gasPrice: 1n, data: '0x1234' });
  const state = { genesis, broadcasts: [] as Hex[], mined: false,
    onChainId: undefined as (() => Promise<void>) | undefined,
    onGenesis: undefined as (() => Promise<void>) | undefined,
    onHead: undefined as (() => Promise<void>) | undefined };
  const abis = new Map<string, Abi>(Object.entries(avaAbis).map(([name, abi]) =>
    [addresses[name as keyof CoreAddresses].toLowerCase(), abi]));
  abis.set(correctionAddress, correctionsAbi); abis.set(executionAddress, executionAbi);
  const links: Record<string, Address> = { APPLICATION_REGISTRY: addresses.applications,
    IDENTITY_REGISTRY: addresses.identities, AUTHORITY_MATRIX: addresses.authority,
    RULE_PACKAGE_REGISTRY: addresses.packages, EVIDENCE_REGISTRY: addresses.evidence,
    DISCLOSURE_REGISTRY: addresses.disclosure, GOVERNANCE_KERNEL: addresses.kernel,
    REQUEST_ALLOCATION: addresses.requests, CORRECTIONS: correctionAddress, EXECUTION: executionAddress };
  const client = createPublicClient({ cacheTime: 0, transport: custom({ request: async ({ method, params }) => {
    if (method === 'eth_chainId') { await state.onChainId?.(); return '0x7a69'; }
    if (method === 'eth_getCode') return '0x6000';
    if (method === 'eth_getBlockByNumber') {
      const isGenesis = (params as [string])[0] === '0x0';
      if (isGenesis) await state.onGenesis?.();
      return { number: isGenesis ? '0x0' : '0x1', hash: isGenesis ? state.genesis : block,
        parentHash: isGenesis ? zeroHash : state.genesis, transactions: [] };
    }
    if (method === 'eth_blockNumber') { await state.onHead?.(); return '0x1'; }
    if (method === 'eth_getLogs') return [];
    if (method === 'eth_call') {
      const call = (params as [{ to: Address; data: Hex }])[0], abi = abis.get(call.to.toLowerCase())!;
      const decoded = decodeFunctionData({ abi, data: call.data }), result = links[decoded.functionName];
      assert(result); return encodeFunctionResult({ abi, functionName: decoded.functionName, result });
    }
    if (method === 'eth_sendRawTransaction') {
      const bytes = (params as [Hex])[0]; state.broadcasts.push(bytes); state.mined = true; return keccak256(bytes);
    }
    if (method === 'eth_getTransactionReceipt') return !state.mined ? null : {
      transactionHash: (params as [Hex])[0], blockHash: block, blockNumber: '0x1', from: account.address,
      to: target, transactionIndex: '0x0', contractAddress: null, cumulativeGasUsed: '0x5208', gasUsed: '0x5208',
      effectiveGasPrice: '0x1', logsBloom: `0x${'00'.repeat(256)}`, status: '0x1', type: '0x0', logs: [] };
    if (method === 'eth_getTransactionByHash') return null;
    throw new Error(`Unexpected synthetic RPC ${method}`);
  } }, { retryCount: 0 }) });
  const options = { client, sdk: new AvaSdk({ chainId: 31337, addresses }),
    databasePath: resolve(directory, 'service.sqlite'), token, additionalSources: { synthetic: { address: target, abi: [] } } };
  const service = await buildAvaService(options);
  const post = (key: string) => service.app.inject({ method: 'POST', url: '/v1/transactions',
    headers: { authorization: `Bearer ${token}` }, payload: { key, serializedTransaction: raw } });
  return { raw, state, service, options, post, async cleanup() { await service.app.close(); await rm(directory, { recursive: true, force: true }); } };
}

test('relay refuses a different genesis before its first transaction, then accepts the original bytes on its bound chain', async () => {
  const f = await fixture();
  try {
    f.state.genesis = `0x${'44'.repeat(32)}`;
    const refused = await f.post('first'); assert.equal(refused.statusCode, 400, refused.body);
    assert.deepEqual(refused.json(), { error: 'invalid_transaction' });
    assert.equal((await f.service.app.inject('/v1/transactions/first')).statusCode, 404);
    assert.deepEqual(f.state.broadcasts, []);
    f.state.genesis = genesis;
    const accepted = await f.post('first'); assert.equal(accepted.statusCode, 200, accepted.body);
    assert.equal(accepted.json().status, 'confirmed'); assert.equal(accepted.json().hash, keccak256(f.raw));
    assert.deepEqual(f.state.broadcasts, [f.raw]);
    await f.service.app.close();
    f.state.genesis = `0x${'44'.repeat(32)}`;
    await assert.rejects(buildAvaService(f.options), /query database chain identity mismatch/);
    f.state.genesis = genesis;
    const reopened = await buildAvaService(f.options);
    try {
      const duplicate = await reopened.app.inject({ method: 'POST', url: '/v1/transactions',
        headers: { authorization: `Bearer ${token}` }, payload: { key: 'first', serializedTransaction: f.raw } });
      assert.equal(duplicate.statusCode, 200, duplicate.body); assert.equal(duplicate.json().hash, accepted.json().hash);
      assert.equal(duplicate.json().status, 'confirmed'); assert.deepEqual(f.state.broadcasts, [f.raw]);
    } finally { await reopened.app.close(); }
  } finally { await f.cleanup(); }
});

function gate() {
  let resolve!: () => void;
  return { promise: new Promise<void>(accept => { resolve = accept; }), resolve: () => resolve() };
}

test('failed sync drains its sibling RPC reads before releasing shared work and shutdown', { timeout: 5000 }, async () => {
  const f = await fixture(), genesisEntered = gate(), headEntered = gate(), release = gate();
  let chainCalls = 0, settled = false, closingSettled = false;
  f.state.onGenesis = async () => { genesisEntered.resolve(); await release.promise; };
  f.state.onHead = async () => { headEntered.resolve(); await release.promise; };
  f.state.onChainId = async () => {
    chainCalls++; await Promise.all([genesisEntered.promise, headEntered.promise]);
    throw new Error('synthetic chain RPC failure');
  };
  const postSync = () => f.service.app.inject({ method: 'POST', url: '/v1/sync',
    headers: { authorization: `Bearer ${token}` } });
  let second: ReturnType<typeof postSync> | undefined, closing: Promise<void> | undefined;
  const first = postSync().then(response => { settled = true; return response; });
  try {
    try {
      await Promise.all([genesisEntered.promise, headEntered.promise]);
      await new Promise(resolve => setTimeout(resolve, 30));
      second = postSync();
      await new Promise(resolve => setTimeout(resolve, 30));
      closing = f.service.app.close().then(() => { closingSettled = true; });
      await new Promise(resolve => setTimeout(resolve, 30));
      assert.equal(settled, false, 'the failed wave must wait for both started siblings');
      assert.equal(chainCalls, 1, 'another caller must share the failed wave until it drains');
      assert.equal(closingSettled, false, 'shutdown must wait for the started reads');
    } finally {
      release.resolve();
      await Promise.allSettled([first, ...(second ? [second] : []), ...(closing ? [closing] : [])]);
      f.state.onChainId = undefined; f.state.onGenesis = undefined; f.state.onHead = undefined;
    }
    assert.equal((await first).statusCode, 503);
    const reopened = await buildAvaService(f.options);
    try {
      const recovered = await reopened.app.inject({ method: 'POST', url: '/v1/sync',
        headers: { authorization: `Bearer ${token}` } });
      assert.equal(recovered.statusCode, 200, recovered.body); assert.equal(recovered.json().status, 'synced');
    } finally { await reopened.app.close(); }
  } finally { await f.cleanup(); }
});

test('malformed HTTP submissions are definite input refusals and a later valid original succeeds', async () => {
  const f = await fixture();
  try {
    const header = { authorization: `Bearer ${token}` };
    for (const [contentType, payload] of [
      ['application/json', '{"key":"first",'],
      ['application/x-unsupported', 'synthetic'],
      ['application/json', ' '.repeat(150_001)],
    ] as const) {
      const response = await f.service.app.inject({ method: 'POST', url: '/v1/transactions',
        headers: { ...header, 'content-type': contentType }, payload });
      assert.equal(response.statusCode, 400, response.body); assert.deepEqual(response.json(), { error: 'invalid_request' });
      assert.equal((await f.service.app.inject('/v1/transactions/first')).statusCode, 404);
      assert.deepEqual(f.state.broadcasts, []);
    }
    const accepted = await f.post('first'); assert.equal(accepted.statusCode, 200, accepted.body);
    assert.equal(accepted.json().status, 'confirmed'); assert.deepEqual(f.state.broadcasts, [f.raw]);
  } finally { await f.cleanup(); }
});

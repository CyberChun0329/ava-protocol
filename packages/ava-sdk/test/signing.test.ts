import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ContractFunctionRevertedError, createPublicClient, createWalletClient, custom, encodeErrorResult, fromRlp, HttpRequestError, keccak256, parseAbi, parseTransaction, recoverTransactionAddress, serializeTransaction, toHex, toRlp, zeroHash,
  type Address, type Hex, type TransactionSerializable } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { foundry } from 'viem/chains';
import { AvaSdk, AvaSigningError, avaAbis, verifySignedIntent, type CoreAddresses } from '../src/index.ts';

const addresses = Object.fromEntries(Object.keys(avaAbis).map((name, index) =>
  [name, `0x${(index + 1).toString(16).padStart(40, '0')}`])) as CoreAddresses;
// Public Anvil development account only.
const account = privateKeyToAccount('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80');
function signRpc(rpc: Record<string, Hex>, signer = account) {
  const fees = rpc.gasPrice ? { type: 'legacy' as const, gasPrice: BigInt(rpc.gasPrice) }
    : { type: 'eip1559' as const, maxFeePerGas: BigInt(rpc.maxFeePerGas), maxPriorityFeePerGas: BigInt(rpc.maxPriorityFeePerGas) };
  return signer.signTransaction({ ...fees, chainId: Number(rpc.chainId), to: rpc.to,
    data: rpc.data ?? '0x', value: rpc.value ? BigInt(rpc.value) : 0n,
    nonce: Number(rpc.nonce), gas: BigInt(rpc.gas) });
}
function fixture(failure: unknown, failedMethod = 'eth_call', localSigner = false) {
  const transport = custom({ request: async ({ method, params }) => {
    if (method === failedMethod) throw failure;
    if (method === 'eth_chainId') return '0x7a69';
    if (method === 'eth_call') return '0x';
    if (method === 'eth_getTransactionCount') return '0x0';
    if (method === 'eth_estimateGas') return '0x186a0';
    if (method === 'eth_maxPriorityFeePerGas') return '0x1';
    if (method === 'eth_getBlockByNumber') return { number: '0x1', hash: zeroHash, baseFeePerGas: '0x1', transactions: [] };
    if (method === 'eth_signTransaction') {
      const rpc = (params as [Record<string, `0x${string}`>])[0];
      return signRpc(rpc);
    }
    throw new Error(`Unexpected RPC ${method}`);
  } }, { retryCount: 0 });
  return { sdk: new AvaSdk({ chainId: 31337, addresses }),
    client: createPublicClient({ transport }),
    wallet: createWalletClient({ account: localSigner ? { ...account,
      signTransaction: async () => { throw failure; } } : account.address, chain: foundry, transport }) };
}

test('caller-selected transaction nonces preserve exact signed identities for RPC and local wallets', async () => {
  const f = fixture(undefined, 'none');
  const call = f.sdk.allocate(7n, { roleKey: zeroHash, authorityId: zeroHash });
  const local = createWalletClient({ account, chain: foundry,
    transport: custom({ request: args => f.client.request(args as never) }, { retryCount: 0 }) });
  for (const wallet of [f.wallet, local]) {
    const signed = await Promise.all([7, 8].map(nonce => f.sdk.sign(f.client, wallet, call, undefined, { nonce })));
    assert.deepEqual(signed.map(item => parseTransaction(item.serializedTransaction).nonce), [7, 8]);
    assert.notEqual(signed[0].hash, signed[1].hash);
    for (const item of signed) {
      assert.equal(item.hash, keccak256(item.serializedTransaction));
      assert.equal(parseTransaction(item.serializedTransaction).data, call.data);
      assert.equal((await recoverTransactionAddress(item)).toLowerCase(), account.address.toLowerCase());
    }
  }
});

test('caller-selected EIP-1559 fees preserve paired and partial values with nonce zero for RPC and local wallets', async () => {
  const f = fixture(undefined, 'none');
  const call = f.sdk.allocate(7n, { roleKey: zeroHash, authorityId: zeroHash });
  const local = createWalletClient({ account, chain: foundry,
    transport: custom({ request: args => f.client.request(args as never) }, { retryCount: 0 }) });
  for (const wallet of [f.wallet, local]) {
    for (const fees of [
      { maxFeePerGas: 20n, maxPriorityFeePerGas: 2n },
      { maxFeePerGas: 20n },
      { maxPriorityFeePerGas: 2n },
      { maxFeePerGas: 0n, maxPriorityFeePerGas: 0n },
    ]) {
      const signed = await f.sdk.sign(f.client, wallet, call, undefined, { nonce: 0, ...fees });
      const transaction = parseTransaction(signed.serializedTransaction);
      assert.equal(transaction.type, 'eip1559');
      assert.equal(transaction.nonce, 0);
      if (fees.maxFeePerGas !== undefined) assert.equal(transaction.maxFeePerGas ?? 0n, fees.maxFeePerGas);
      if (fees.maxPriorityFeePerGas !== undefined) assert.equal(transaction.maxPriorityFeePerGas ?? 0n, fees.maxPriorityFeePerGas);
      assert((transaction.maxFeePerGas ?? 0n) >= (transaction.maxPriorityFeePerGas ?? 0n));
      assert.equal(transaction.data, call.data);
      assert.equal(signed.hash, keccak256(signed.serializedTransaction));
      assert.equal((await recoverTransactionAddress(signed)).toLowerCase(), account.address.toLowerCase());
    }
  }
});

test('explicit EIP-1559 fees require nonnegative bigints and priority no greater than a supplied cap', async () => {
  const f = fixture(undefined, 'none');
  const call = { to: addresses.requests, data: '0x' } as const;
  const invalid = [-1n, 0, 1, NaN, Infinity, null, '1', {}];
  const cases = [
    ...invalid.map(value => ({ maxFeePerGas: value, maxPriorityFeePerGas: 0n })),
    ...invalid.map(value => ({ maxFeePerGas: 20n, maxPriorityFeePerGas: value })),
    { maxFeePerGas: 1n, maxPriorityFeePerGas: 2n },
  ];
  for (const fees of cases) {
    await assert.rejects(f.sdk.sign(f.client, f.wallet, call, undefined,
      fees as { maxFeePerGas?: bigint; maxPriorityFeePerGas?: bigint }), error =>
      error instanceof AvaSigningError && error.stage === 'preparation' && error.code === 'intent_mismatch'
        && error.cause === undefined);
    const signed = await f.sdk.sign(f.client, f.wallet, call, undefined,
      { nonce: 0, maxFeePerGas: 20n, maxPriorityFeePerGas: 2n });
    assert.equal(parseTransaction(signed.serializedTransaction).maxFeePerGas, 20n);
  }
});

test('an explicit fee cap incompatible with automatic tip estimation fails safely without raising the cap', async () => {
  const f = fixture(undefined, 'none');
  const call = { to: addresses.requests, data: '0x' } as const;
  const wallet = createWalletClient({ account: account.address,
    chain: { ...foundry, fees: { maxPriorityFeePerGas: 2n } },
    transport: custom({ request: args => f.client.request(args as never) }, { retryCount: 0 }) });
  await assert.rejects(f.sdk.sign(f.client, wallet, call, undefined, { maxFeePerGas: 1n }), error =>
    error instanceof AvaSigningError && error.stage === 'preparation' && error.cause === undefined);
  const signed = await f.sdk.sign(f.client, wallet, call, undefined,
    { nonce: 0, maxFeePerGas: 20n, maxPriorityFeePerGas: 2n });
  assert.equal(parseTransaction(signed.serializedTransaction).maxFeePerGas, 20n);
});

test('a completed EIP-1559 tip cannot exceed a zero cap, with or without explicit fee options', async () => {
  const f = fixture(undefined, 'none');
  const call = { to: addresses.requests, data: '0x' } as const;
  let signerInvoked = false;
  const wallet = { ...f.wallet,
    signTransaction: async (request: Parameters<typeof f.wallet.signTransaction>[0]) => {
      signerInvoked = true;
      return f.wallet.signTransaction(request);
    },
  } as typeof f.wallet;
  await assert.rejects(f.sdk.sign(f.client, wallet, call, undefined, { maxFeePerGas: 0n }), error =>
    error instanceof AvaSigningError && error.stage === 'preparation' && error.code === 'intent_mismatch');
  assert.equal(signerInvoked, false);
  const incompatibleDefaults = { ...wallet,
    prepareTransactionRequest: async (request: Parameters<typeof f.wallet.prepareTransactionRequest>[0]) =>
      ({ ...await f.wallet.prepareTransactionRequest(request), type: 'eip1559',
        maxFeePerGas: 0n, maxPriorityFeePerGas: 1n }),
  } as typeof f.wallet;
  await assert.rejects(f.sdk.sign(f.client, incompatibleDefaults, call), error =>
    error instanceof AvaSigningError && error.stage === 'preparation' && error.code === 'intent_mismatch');
  assert.equal(signerInvoked, false);
  const signed = await f.sdk.sign(f.client, wallet, call, undefined,
    { nonce: 0, maxFeePerGas: 20n, maxPriorityFeePerGas: 2n });
  assert.equal(parseTransaction(signed.serializedTransaction).maxFeePerGas, 20n);
  assert.equal(parseTransaction(signed.serializedTransaction).maxPriorityFeePerGas, 2n);
});

test('fee option mutation at every asynchronous stage is rejected including added and removed options', async () => {
  const f = fixture(undefined, 'none');
  const stages = [
    { method: 'eth_chainId', stage: 'chain' },
    { method: 'eth_call', stage: 'simulation' },
    { method: 'eth_estimateGas', stage: 'preparation' },
    { method: 'eth_signTransaction', stage: 'signing' },
  ];
  for (const field of ['maxFeePerGas', 'maxPriorityFeePerGas'] as const) {
    const value = field === 'maxFeePerGas' ? 20n : 2n;
    for (const [before, after] of [[value, value + 1n], [undefined, value], [value, undefined]]) {
      for (const item of stages) {
        const options: { nonce?: number; maxFeePerGas?: bigint; maxPriorityFeePerGas?: bigint } = {
          nonce: 0, maxFeePerGas: 20n, maxPriorityFeePerGas: 2n, [field]: before,
        };
        let mutate = true;
        const transport = custom({ request: async ({ method, params }) => {
          const result = await f.client.request({ method, params } as never);
          if (method === item.method && mutate) { options[field] = after; mutate = false; }
          return result;
        } }, { retryCount: 0 });
        const client = createPublicClient({ transport });
        const wallet = createWalletClient({ account: account.address, chain: foundry, transport });
        const call = { to: addresses.requests, data: '0x' } as const;
        await assert.rejects(f.sdk.sign(client, wallet, call, undefined, options), error =>
          error instanceof AvaSigningError && error.stage === item.stage && error.code === 'intent_mismatch');
        const signed = await f.sdk.sign(client, wallet, call, undefined,
          { nonce: 0, maxFeePerGas: 20n, maxPriorityFeePerGas: 2n });
        assert.equal(parseTransaction(signed.serializedTransaction).maxPriorityFeePerGas, 2n);
      }
    }
  }
});

test('wallet preparation cannot drop or substitute a caller fee cap or priority fee', async () => {
  const f = fixture(undefined, 'none');
  const call = { to: addresses.requests, data: '0x' } as const;
  for (const field of ['maxFeePerGas', 'maxPriorityFeePerGas'] as const) {
    const value = field === 'maxFeePerGas' ? 20n : 2n;
    for (const fees of [{ [field]: value }, { maxFeePerGas: 20n, maxPriorityFeePerGas: 2n },
      { maxFeePerGas: 0n, maxPriorityFeePerGas: 0n }]) {
      for (const replacement of [undefined, value + 1n]) {
        const wallet = { ...f.wallet,
          prepareTransactionRequest: async (request: Parameters<typeof f.wallet.prepareTransactionRequest>[0]) => {
            const prepared = { ...await f.wallet.prepareTransactionRequest(request) };
            if (replacement === undefined) delete prepared[field];
            else prepared[field] = replacement;
            return prepared;
          },
        } as typeof f.wallet;
        await assert.rejects(f.sdk.sign(f.client, wallet, call, undefined, { nonce: 0, ...fees }), error =>
          error instanceof AvaSigningError && error.stage === 'preparation' && error.code === 'intent_mismatch');
        const signed = await f.sdk.sign(f.client, f.wallet, call, undefined,
          { nonce: 0, maxFeePerGas: 20n, maxPriorityFeePerGas: 2n });
        assert.equal(parseTransaction(signed.serializedTransaction).maxFeePerGas, 20n);
      }
    }
  }
});

test('explicit zero fees must be encoded in EIP-1559 rather than shadowing legacy or access-list fees', async t => {
  const f = fixture(undefined, 'none');
  const call = { to: addresses.requests, data: '0x' } as const;
  const base = createWalletClient({ account, chain: foundry,
    transport: custom({ request: args => f.client.request(args as never) }, { retryCount: 0 }) });
  for (const type of ['legacy', 'eip2930'] as const) {
    for (const fees of [{ maxFeePerGas: 0n, maxPriorityFeePerGas: 0n },
      { maxFeePerGas: 0n }, { maxPriorityFeePerGas: 0n }]) {
      await t.test(`${type}: ${Object.keys(fees).join(', ')}`, async () => {
        let signerInvoked = false;
        const wallet = { ...base,
          prepareTransactionRequest: async (request: Parameters<typeof base.prepareTransactionRequest>[0]) => {
            const invocation = { account: request.account, chain: request.chain, to: request.to,
              data: request.data, value: request.value, nonce: request.nonce, gasPrice: 1n };
            const prepared = type === 'legacy'
              ? await base.prepareTransactionRequest({ ...invocation, type: 'legacy' })
              : await base.prepareTransactionRequest({ ...invocation, type: 'eip2930', accessList: [] });
            return { ...prepared, ...fees };
          },
          signTransaction: async (request: Parameters<typeof base.signTransaction>[0]) => {
            signerInvoked = true;
            return base.signTransaction(request);
          },
        } as typeof base;
        await assert.rejects(f.sdk.sign(f.client, wallet, call, undefined, { nonce: 0, ...fees }), error =>
          error instanceof AvaSigningError && error.stage === 'preparation' && error.code === 'intent_mismatch');
        assert.equal(signerInvoked, false, 'incompatible encoded fees are refused before asking the signer');
        const compatibleFees = { ...fees, maxPriorityFeePerGas: fees.maxPriorityFeePerGas ?? 0n };
        const signed = await f.sdk.sign(f.client, base, call, undefined, { nonce: 0, ...compatibleFees });
        const transaction = parseTransaction(signed.serializedTransaction);
        assert.equal(transaction.type, 'eip1559');
        if (fees.maxFeePerGas !== undefined) assert.equal(transaction.maxFeePerGas ?? 0n, 0n);
        if (fees.maxPriorityFeePerGas !== undefined) assert.equal(transaction.maxPriorityFeePerGas ?? 0n, 0n);
        const defaultSigned = await f.sdk.sign(f.client, wallet, call);
        assert.equal(parseTransaction(defaultSigned.serializedTransaction).type, type);
        assert.equal(parseTransaction(defaultSigned.serializedTransaction).gasPrice, 1n);
      });
    }
  }
});

test('explicit nonces must be safe nonnegative integers and a later valid choice remains signable', async () => {
  const f = fixture(undefined, 'none');
  const call = { to: addresses.requests, data: '0x' } as const;
  for (const nonce of [-1, 0.5, Number.MAX_SAFE_INTEGER + 1, NaN, Infinity, null, '7', 7n]) {
    await assert.rejects(f.sdk.sign(f.client, f.wallet, call, undefined, { nonce: nonce as number }), error =>
      error instanceof AvaSigningError && error.stage === 'preparation' && error.code === 'intent_mismatch');
  }
  for (const nonce of [0, Number.MAX_SAFE_INTEGER]) {
    const signed = await f.sdk.sign(f.client, f.wallet, call, undefined, { nonce });
    assert.equal(parseTransaction(signed.serializedTransaction).nonce, nonce);
  }
});

test('nonce option mutation across asynchronous signing stages is refused without poisoning a later call', async () => {
  const f = fixture(undefined, 'none');
  const cases = [
    { method: 'eth_chainId', stage: 'chain', before: 7, after: 8 },
    { method: 'eth_call', stage: 'simulation', before: 7, after: 8 },
    { method: 'eth_estimateGas', stage: 'preparation', before: 7, after: 8 },
    { method: 'eth_signTransaction', stage: 'signing', before: 7, after: 8 },
    { method: 'eth_call', stage: 'simulation', before: undefined, after: 7 },
    { method: 'eth_call', stage: 'simulation', before: 7, after: undefined },
  ];
  for (const item of cases) {
    const options: { nonce?: number } = { nonce: item.before };
    let mutate = true;
    const transport = custom({ request: async ({ method, params }) => {
      const result = await f.client.request({ method, params } as never);
      if (method === item.method && mutate) { options.nonce = item.after; mutate = false; }
      return result;
    } }, { retryCount: 0 });
    const client = createPublicClient({ transport });
    const wallet = createWalletClient({ account: account.address, chain: foundry, transport });
    const call = { to: addresses.requests, data: '0x' } as const;
    await assert.rejects(f.sdk.sign(client, wallet, call, undefined, options), error =>
      error instanceof AvaSigningError && error.stage === item.stage && error.code === 'intent_mismatch');
    const signed = await f.sdk.sign(client, wallet, call, undefined, { nonce: 7 });
    assert.equal(parseTransaction(signed.serializedTransaction).nonce, 7);
  }
});

test('wallet preparation cannot replace an explicit nonce and the caller can still sign a valid request', async () => {
  const f = fixture(undefined, 'none');
  const changed = { ...f.wallet,
    prepareTransactionRequest: async (request: Parameters<typeof f.wallet.prepareTransactionRequest>[0]) => ({
      ...await f.wallet.prepareTransactionRequest(request), nonce: 8,
    }),
  } as typeof f.wallet;
  const call = { to: addresses.requests, data: '0x' } as const;
  await assert.rejects(f.sdk.sign(f.client, changed, call, undefined, { nonce: 7 }), error =>
    error instanceof AvaSigningError && error.stage === 'preparation' && error.code === 'intent_mismatch');
  const signed = await f.sdk.sign(f.client, f.wallet, call, undefined, { nonce: 7 });
  assert.equal(parseTransaction(signed.serializedTransaction).nonce, 7);
});

test('default wallet nonce selection can collide for same-EOA calls signed before submission', async () => {
  const f = fixture(undefined, 'none');
  const first = f.sdk.allocate(7n, { roleKey: zeroHash, authorityId: zeroHash });
  const second = f.sdk.allocate(8n, { roleKey: zeroHash, authorityId: zeroHash });
  const signed = await Promise.all([
    f.sdk.sign(f.client, f.wallet, first),
    f.sdk.sign(f.client, f.wallet, second, undefined, {}),
  ]);
  // Known limit: signing does not reserve a nonce or advance the wallet's pending count.
  assert.deepEqual(signed.map(item => parseTransaction(item.serializedTransaction).nonce), [0, 0]);
  assert.notEqual(signed[0].hash, signed[1].hash);
});

test('simulation reverts expose a known contract error without provider details or raw calldata', async () => {
  const f = fixture({ code: 3, message: 'execution reverted SYNTHETIC_SECRET',
    data: encodeErrorResult({ abi: avaAbis.authority, errorName: 'NotAuthorised', args: [account.address, zeroHash] }) });
  await assert.rejects(f.sdk.sign(f.client, f.wallet, f.sdk.allocate(1n, { roleKey: zeroHash, authorityId: zeroHash })), error => {
    assert(error instanceof Error);
    assert.equal(error.name, 'AvaSigningError');
    const typed = error as Error & { stage: string; code: string; errorName?: string };
    assert.equal(typed.stage, 'simulation');
    assert.equal(typed.code, 'contract_reverted');
    assert.equal(typed.errorName, 'NotAuthorised');
    assert.equal(error.cause, undefined);
    assert(!String(error).includes('SYNTHETIC_SECRET'));
    assert(!JSON.stringify(error).includes(account.address));
    return true;
  });
});

test('chain mismatch, transport and RPC failures keep conservative codes and safe metadata', async () => {
  const cases = [
    { method: 'eth_chainId', failure: new HttpRequestError({ url: 'https://SYNTHETIC_SECRET.invalid' }), stage: 'chain', code: 'transport_error' },
    { method: 'eth_call', failure: { code: -32602, message: 'SYNTHETIC_SECRET' }, stage: 'simulation', code: 'rpc_error' },
    { method: 'eth_estimateGas', failure: new HttpRequestError({ url: 'https://SYNTHETIC_SECRET.invalid' }), stage: 'preparation', code: 'transport_error' },
    { method: 'eth_signTransaction', failure: { code: 4001, message: 'SYNTHETIC_SECRET' }, stage: 'signing', code: 'signer_rejected' },
  ];
  for (const item of cases) {
    const f = fixture(item.failure, item.method);
    await assert.rejects(f.sdk.sign(f.client, f.wallet, { to: addresses.requests, data: '0x' }), error => {
      assert(error instanceof AvaSigningError);
      assert.equal(error.stage, item.stage);
      assert.equal(error.code, item.code);
      assert.equal(error.cause, undefined);
      assert(!JSON.stringify(error).includes('SYNTHETIC_SECRET'));
      return true;
    });
  }
  const f = fixture(undefined, 'none');
  const other = new AvaSdk({ chainId: 84532, addresses });
  await assert.rejects(other.sign(f.client, f.wallet, { to: addresses.requests, data: '0x' }), error =>
    error instanceof AvaSigningError && error.stage === 'chain' && error.code === 'chain_mismatch');
});

test('custom reverts require the supplied ABI and do not expose arbitrary reason arguments', async () => {
  const abi = parseAbi(['error PrivateReason(string text)']);
  const f = fixture({ code: 3, message: 'execution reverted',
    data: encodeErrorResult({ abi, errorName: 'PrivateReason', args: ['SYNTHETIC_SECRET'] }) });
  const call = { to: addresses.requests, data: '0x' } as const;
  for (const supplied of [undefined, abi]) {
    await assert.rejects(f.sdk.sign(f.client, f.wallet, call, supplied), error => {
      assert(error instanceof AvaSigningError);
      assert.equal(error.code, 'contract_reverted');
      assert.equal(error.errorName, supplied ? 'PrivateReason' : undefined);
      assert(!JSON.stringify(error).includes('SYNTHETIC_SECRET'));
      return true;
    });
  }
});

test('a wallet-provided decoded revert still decodes only through the declared error ABI', async () => {
  const data = encodeErrorResult({ abi: avaAbis.authority, errorName: 'NotAuthorised', args: [account.address, zeroHash] });
  const f = fixture(new ContractFunctionRevertedError({ abi: avaAbis.authority, data, functionName: 'approve' }));
  await assert.rejects(f.sdk.sign(f.client, f.wallet, { to: addresses.requests, data: '0x' }), error =>
    error instanceof AvaSigningError && error.code === 'contract_reverted' && error.errorName === 'NotAuthorised');
});

test('unknown signer failures remain unknown and a later legal signature still succeeds', async () => {
  const bad = fixture(new Error('SYNTHETIC_SIGNER_SECRET'), 'none', true);
  const call = { to: addresses.requests, data: '0x' } as const;
  await assert.rejects(bad.sdk.sign(bad.client, bad.wallet, call), error =>
    error instanceof AvaSigningError && error.stage === 'signing' && error.code === 'unknown'
      && !String(error).includes('SYNTHETIC_SIGNER_SECRET'));
  const good = fixture(undefined, 'none');
  const signed = await good.sdk.sign(good.client, good.wallet, call);
  const transaction = parseTransaction(signed.serializedTransaction);
  assert.equal(transaction.chainId, 31337);
  assert.equal(transaction.to?.toLowerCase(), addresses.requests);
});

test('caller mutation during simulation is rejected and a later unchanged call can still be signed', async () => {
  const f = fixture(undefined, 'none');
  const original = f.sdk.allocate(7n, { roleKey: zeroHash, authorityId: zeroHash });
  const replacement = f.sdk.allocate(8n, { roleKey: zeroHash, authorityId: zeroHash });
  let mutate = true;
  const transport = custom({ request: async ({ method, params }) => {
    if (method === 'eth_call' && mutate) { original.data = replacement.data; mutate = false; }
    return f.client.request({ method, params } as never);
  } }, { retryCount: 0 });
  const client = createPublicClient({ transport });
  const wallet = createWalletClient({ account, chain: foundry, transport });
  await assert.rejects(f.sdk.sign(client, wallet, original), error =>
    error instanceof AvaSigningError && error.code === 'intent_mismatch' && error.stage === 'simulation');
  const legal = f.sdk.allocate(7n, { roleKey: zeroHash, authorityId: zeroHash });
  const signed = await f.sdk.sign(client, wallet, legal);
  assert.equal(parseTransaction(signed.serializedTransaction).data, legal.data);
});

test('a signer returning another invocation is refused before exposing bytes, then a legal signature still works', async () => {
  const f = fixture(undefined, 'none');
  const call = f.sdk.allocate(7n, { roleKey: zeroHash, authorityId: zeroHash });
  const switched = createWalletClient({ account: account.address, chain: foundry,
    transport: custom({ request: async ({ method, params }) => {
      if (method === 'eth_signTransaction') {
        const rpc = (params as [Record<string, unknown>])[0];
        return f.client.request({ method, params: [{ ...rpc, data: '0x' }] } as never);
      }
      return f.client.request({ method, params } as never);
    } }, { retryCount: 0 }) });
  await assert.rejects(f.sdk.sign(f.client, switched, call), error =>
    error instanceof AvaSigningError && error.stage === 'signing' && error.code === 'intent_mismatch'
      && error.cause === undefined && !JSON.stringify(error).includes(call.data));
  const wallet = createWalletClient({ account, chain: foundry,
    transport: custom({ request: args => f.client.request(args as never) }, { retryCount: 0 }) });
  const signed = await f.sdk.sign(f.client, wallet, call);
  assert.equal(parseTransaction(signed.serializedTransaction).data, call.data);
});

test('a returned transaction cannot silently replace the prepared nonce and fee envelope', async () => {
  const f = fixture(undefined, 'none');
  let changedField = 'nonce';
  const changed = createWalletClient({ account: account.address, chain: foundry,
    transport: custom({ request: async ({ method, params }) => {
      if (method === 'eth_signTransaction') {
        const rpc = (params as [Record<string, unknown>])[0];
        return f.client.request({ method, params: [{ ...rpc,
          [changedField]: changedField === 'maxPriorityFeePerGas' ? '0x0' : '0xffff' }] } as never);
      }
      return f.client.request({ method, params } as never);
    } }, { retryCount: 0 }) });
  const call = { to: addresses.requests, data: '0x' } as const;
  for (const options of [undefined, { nonce: 7 }, { nonce: 0, maxFeePerGas: 20n, maxPriorityFeePerGas: 2n },
    { maxFeePerGas: 20n }, { maxPriorityFeePerGas: 2n }]) {
    for (const field of ['nonce', 'gas', 'maxFeePerGas', 'maxPriorityFeePerGas']) {
      changedField = field;
      await assert.rejects(f.sdk.sign(f.client, changed, call, undefined, options), error =>
        error instanceof AvaSigningError && error.stage === 'signing' && error.code === 'intent_mismatch');
      const signed = await f.sdk.sign(f.client, f.wallet, call, undefined, options);
      const transaction = parseTransaction(signed.serializedTransaction);
      assert.equal(transaction.nonce, options?.nonce ?? 0);
      if (options?.maxFeePerGas !== undefined) assert.equal(transaction.maxFeePerGas, options.maxFeePerGas);
      if (options?.maxPriorityFeePerGas !== undefined) assert.equal(transaction.maxPriorityFeePerGas, options.maxPriorityFeePerGas);
    }
  }
});

test('changed sender, chain, target, value, data and missing or malformed signatures are rejected', async () => {
  const f = fixture(undefined, 'none'), otherSigner = privateKeyToAccount(`0x${'22'.repeat(32)}`);
  const call = { to: addresses.requests, data: '0x1234', value: 1n } as const;
  for (const variant of ['sender', 'chainId', 'to', 'value', 'data', 'unsigned', 'malformed']) {
    const wallet = createWalletClient({ account: account.address, chain: foundry,
      transport: custom({ request: async ({ method, params }) => {
        if (method !== 'eth_signTransaction') return f.client.request({ method, params } as never);
        const rpc = { ...(params as [Record<string, Hex>])[0] };
        if (variant === 'malformed') return '0x12';
        if (variant === 'unsigned') return serializeTransaction({ chainId: 31337, to: call.to, data: call.data,
          value: call.value, nonce: 0, gas: 100000n, gasPrice: 1n, type: 'legacy' });
        if (variant === 'chainId') rpc.chainId = '0x1';
        if (variant === 'to') rpc.to = addresses.kernel;
        if (variant === 'value') rpc.value = '0x2';
        if (variant === 'data') rpc.data = '0xabcd';
        return signRpc(rpc, variant === 'sender' ? otherSigner : account);
      } }, { retryCount: 0 }) });
    await assert.rejects(f.sdk.sign(f.client, wallet, call), error =>
      error instanceof AvaSigningError && error.code === 'intent_mismatch' && error.cause === undefined);
  }
  assert.equal(parseTransaction((await f.sdk.sign(f.client, f.wallet, call)).serializedTransaction).value, 1n);
});

test('noncanonical integer encodings and reflected high-s signatures cannot pass intent recovery', async () => {
  const f = fixture(undefined, 'none');
  for (const variant of ['rlp', 'high-s']) {
    const wallet = createWalletClient({ account: account.address, chain: foundry,
      transport: custom({ request: async ({ method, params }) => {
        if (method !== 'eth_signTransaction') return f.client.request({ method, params } as never);
        const signed = await f.client.request({ method, params } as never) as Hex;
        assert(signed.startsWith('0x02'));
        if (variant === 'rlp') {
          const fields = fromRlp(`0x${signed.slice(4)}`, 'hex') as Hex[];
          fields[1] = '0x00'; // Integer zero must be encoded as empty, not the byte 00.
          return `0x02${toRlp(fields).slice(2)}`;
        }
        const transaction = parseTransaction(signed);
        assert(transaction.r && transaction.s && transaction.yParity !== undefined);
        const { r, s, v: _v, yParity, ...unsigned } = transaction;
        const order = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
        return serializeTransaction(unsigned as TransactionSerializable, { r,
          s: toHex(order - BigInt(s), { size: 32 }), yParity: yParity === 0 ? 1 : 0 });
      } }, { retryCount: 0 }) });
    await assert.rejects(f.sdk.sign(f.client, wallet, { to: addresses.requests, data: '0x' }), error =>
      error instanceof AvaSigningError && error.code === 'intent_mismatch');
  }
  assert.equal(parseTransaction((await f.sdk.sign(f.client, f.wallet,
    { to: addresses.requests, data: '0x' })).serializedTransaction).nonce, 0);
});

test('supported envelopes with both signature parities preserve the prepared intent', async () => {
  const f = fixture(undefined, 'none');
  const base = createWalletClient({ account, chain: foundry,
    transport: custom({ request: args => f.client.request(args as never) }, { retryCount: 0 }) });
  const accessList = [{ address: addresses.kernel, storageKeys: [zeroHash] }];
  for (const type of ['legacy', 'eip2930', 'eip1559'] as const) {
    const wallet = { ...base, prepareTransactionRequest: (request: Parameters<typeof base.prepareTransactionRequest>[0]) => {
      const invocation = { account: request.account, chain: request.chain, to: request.to,
        data: request.data, value: request.value, nonce: request.nonce };
      if (type === 'legacy') return base.prepareTransactionRequest({ ...invocation, type, gasPrice: 1n });
      if (type === 'eip2930') return base.prepareTransactionRequest({ ...invocation, type, gasPrice: 1n, accessList });
      return base.prepareTransactionRequest({ ...invocation, type });
    } } as typeof base;
    const parities = new Set<number>();
    for (let nonce = 0; nonce < 16 && parities.size < 2; nonce++) {
      const signed = await f.sdk.sign(f.client, wallet, { to: addresses.requests, data: '0x1234' }, undefined, { nonce });
      const transaction = parseTransaction(signed.serializedTransaction);
      assert.equal(transaction.type, type);
      assert.equal(transaction.nonce, nonce);
      assert.equal(transaction.data, '0x1234');
      assert.equal((await recoverTransactionAddress(signed)).toLowerCase(), account.address.toLowerCase());
      if (transaction.type === 'eip2930') assert.deepEqual(transaction.accessList, accessList);
      assert(transaction.yParity !== undefined);
      parities.add(transaction.yParity);
    }
    assert.deepEqual([...parities].sort(), [0, 1], type);
  }
});

test('an unsupported returned envelope is rejected after ordinary preparation and a legal retry works', async () => {
  const f = fixture(undefined, 'none');
  const call = f.sdk.allocate(7n, { roleKey: zeroHash, authorityId: zeroHash });
  const authorization = await account.signAuthorization!({ address: addresses.requests, chainId: 31337, nonce: 0 });
  let returned: Hex | undefined;
  const wallet = { ...f.wallet, signTransaction: async (request: TransactionSerializable) => {
    returned = await account.signTransaction({ ...request, type: 'eip7702', authorizationList: [authorization] } as TransactionSerializable);
    return returned;
  } } as typeof f.wallet;
  await assert.rejects(f.sdk.sign(f.client, wallet, call), error =>
    error instanceof AvaSigningError && error.stage === 'signing' && error.code === 'intent_mismatch');
  assert(returned);
  assert.equal(parseTransaction(returned).type, 'eip7702');
  const signed = await f.sdk.sign(f.client, f.wallet, call);
  assert.equal(parseTransaction(signed.serializedTransaction).data, call.data);
});

test('caller mutation after signing while recovery awaits is rejected and a legal retry works', async () => {
  const f = fixture(undefined, 'none');
  const call = f.sdk.allocate(7n, { roleKey: zeroHash, authorityId: zeroHash });
  const originalData = call.data;
  const replacement = f.sdk.allocate(8n, { roleKey: zeroHash, authorityId: zeroHash });
  let signed = false, scheduled = false;
  const wallet = { ...f.wallet,
    get chain() {
      if (signed && !scheduled) {
        scheduled = true;
        queueMicrotask(() => { call.data = replacement.data; });
      }
      return f.wallet.chain;
    },
    signTransaction: async (request: Parameters<typeof f.wallet.signTransaction>[0]) => {
      const result = await f.wallet.signTransaction(request);
      signed = true;
      return result;
    },
  } as typeof f.wallet;
  await assert.rejects(f.sdk.sign(f.client, wallet, call), error =>
    error instanceof AvaSigningError && error.stage === 'signing' && error.code === 'intent_mismatch');
  assert.equal(scheduled, true);
  assert.equal(call.data, replacement.data);
  call.data = originalData;
  const retry = await f.sdk.sign(f.client, f.wallet, call);
  assert.equal(parseTransaction(retry.serializedTransaction).data, originalData);
});

test('unsupported authorization-list preparation is refused before signing and ordinary intent remains signable', async () => {
  const f = fixture(undefined, 'none');
  const call = f.sdk.allocate(7n, { roleKey: zeroHash, authorityId: zeroHash });
  const authorization = await account.signAuthorization!({ address: addresses.requests, chainId: 31337, nonce: 0 });
  let signatures = 0;
  const wallet = { ...f.wallet,
    prepareTransactionRequest: async (request: Parameters<typeof f.wallet.prepareTransactionRequest>[0]) => ({
      ...await f.wallet.prepareTransactionRequest(request), type: 'eip7702', authorizationList: [authorization],
    }),
    signTransaction: async (request: TransactionSerializable) => {
      signatures++;
      return account.signTransaction(request);
    },
  } as typeof f.wallet;
  await assert.rejects(f.sdk.sign(f.client, wallet, call), error =>
    error instanceof AvaSigningError && error.stage === 'preparation' && error.code === 'intent_mismatch');
  assert.equal(signatures, 0, 'an unsupported envelope must never reach the signer');
  const signed = await f.sdk.sign(f.client, f.wallet, call);
  assert.equal(parseTransaction(signed.serializedTransaction).type, 'eip1559');
  assert.equal((await verifySignedIntent(signed.serializedTransaction,
    { chainId: 31337, account: account.address, call })).hash, signed.hash);
});

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createPublicClient, custom, decodeFunctionData, encodeFunctionResult, keccak256 } from 'viem';
import { localChain } from '../../../examples/shared/local.ts';
import { baseCostQuote, baseFeeOracleAbi, BASE_TRANSACTION_GAS_CAP, transactionSample } from '../../../examples/shared/transaction-cost.ts';

test('cost sampling keeps the actual signed envelope, declared gas and receipt distinct', async () => {
  const chain = await localChain();
  try {
    const hash = await chain.wallets[0].sendTransaction({ to: chain.wallets[1].account.address,
      value: 1n, gas: 30_000n, maxFeePerGas: 2_000_000_000n, maxPriorityFeePerGas: 1_000_000_000n });
    await chain.client.waitForTransactionReceipt({ hash });
    const sample = await transactionSample(chain.client, hash, 'transfer');
    assert.equal(keccak256(sample.rawTransaction), hash);
    assert.equal(sample.gas, 21_000n);
    assert.equal(sample.gasLimit, 30_000n);
    assert.equal(sample.chainId, 31337);
    assert.equal(sample.calldataBytes, 0);
    assert(sample.serializedBytes > 100);
    assert.equal(sample.baseGasCap, 'within');
    await assert.rejects(() => transactionSample({ ...chain.client,
      getRawTransaction: async () => '0x02' }, hash, 'corrupt'), /identity/);
  } finally { await chain.close(); }
});

test('Base projection pins oracle reads and prices full bytes without claiming local chain transactions are Base-valid', async () => {
  const blockHash = `0x${'12'.repeat(32)}` as const;
  const raw = '0x123456' as const;
  const client = createPublicClient({ transport: custom({ request: async ({ method, params }) => {
    if (method === 'eth_chainId') return '0x2105';
    if (method === 'eth_getBlockByNumber') return { number: '0x7', hash: blockHash, baseFeePerGas: '0x5' };
    assert.equal(method, 'eth_call');
    const [call, point] = params as [{ data: `0x${string}` }, unknown];
    assert.deepEqual(point, { blockHash, requireCanonical: true });
    const decoded = decodeFunctionData({ abi: baseFeeOracleAbi, data: call.data });
    if (decoded.functionName === 'getL1Fee') assert.equal(decoded.args[0], raw);
    else assert.equal(decoded.args[0], 21_000n);
    return encodeFunctionResult({ abi: baseFeeOracleAbi, functionName: decoded.functionName,
      result: decoded.functionName === 'getL1Fee' ? 101n : 3n });
  } }, { retryCount: 0 }) });
  const sample = { rawTransaction: raw, gas: 21_000n, gasLimit: BASE_TRANSACTION_GAS_CAP,
    maxFeePerGas: 20n, maxPriorityFeePerGas: 2n, chainId: 31337 };
  const quote = await baseCostQuote(client, [sample]);
  assert.equal(quote.chainId, 8453);
  assert.equal(quote.blockHash, blockHash);
  assert.equal(quote.samples[0].status, 'quoted');
  assert.equal(quote.samples[0].l1DataFeeWei, 101n);
  assert.equal(quote.samples[0].executionFeeWei, 147_000n);
  assert.equal(quote.samples[0].operatorFeeWei, 3n);
  assert.equal(quote.samples[0].projectedFeeWei, 147_104n);
  assert.equal(quote.samples[0].baseGasCap, 'within');
  assert.equal(quote.samples[0].sourceChainId, 31337);
});

test('cap violations and oracle failures cannot become an apparently payable zero-fee quote', async () => {
  const blockHash = `0x${'34'.repeat(32)}` as const;
  let unavailable = false;
  const client = createPublicClient({ transport: custom({ request: async ({ method }) => {
    if (method === 'eth_chainId') return '0x2105';
    if (method === 'eth_getBlockByNumber') return { number: '0x8', hash: blockHash, baseFeePerGas: '0x5' };
    if (unavailable) throw new Error('private RPC URL must not be exposed');
    return `0x${'0'.repeat(64)}`;
  } }, { retryCount: 0 }) });
  const sample = { rawTransaction: '0x12' as const, gas: 21_000n, gasLimit: BASE_TRANSACTION_GAS_CAP + 1n,
    maxFeePerGas: 20n, maxPriorityFeePerGas: 2n, chainId: 31337 };
  const limited = await baseCostQuote(client, [sample, { ...sample, gasLimit: 30_000n, maxFeePerGas: 4n }]);
  assert.equal(limited.samples[0].status, 'above_transaction_cap');
  assert.equal(limited.samples[1].status, 'fee_terms_insufficient');
  for (const quote of limited.samples) assert(!('projectedFeeWei' in quote) || quote.projectedFeeWei === undefined);
  unavailable = true;
  const failed = await baseCostQuote(client, [{ ...sample, gasLimit: 30_000n }]);
  assert.equal(failed.samples[0].status, 'oracle_unavailable');
  assert(!('projectedFeeWei' in failed.samples[0]));
  assert(!JSON.stringify(failed.samples[0], (_, value) => typeof value === 'bigint' ? String(value) : value).includes('private RPC'));
  unavailable = false;
  const recovered = await baseCostQuote(client, [{ ...sample, gasLimit: 30_000n }]);
  assert.equal(recovered.samples[0].status, 'quoted');
});

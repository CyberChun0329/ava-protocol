import { decodeFunctionResult, encodeFunctionData, keccak256, parseAbi, parseTransaction,
  type Hex, type PublicClient } from 'viem';

// Base's documented EIP-7825 per-transaction limit, not its block gas limit.
export const BASE_TRANSACTION_GAS_CAP = 16_777_216n;
export const baseFeeOracleAbi = parseAbi([
  'function getL1Fee(bytes transaction) view returns (uint256)',
  'function getOperatorFee(uint256 gasUsed) view returns (uint256)',
]);
const oracle = '0x420000000000000000000000000000000000000F';
const cap = (gasLimit: bigint) => gasLimit <= BASE_TRANSACTION_GAS_CAP ? 'within' as const : 'above' as const;

/** Capture while the disposable chain still exists; never reconstruct a signature. */
export async function transactionSample(client: Pick<PublicClient, 'getRawTransaction' | 'getTransactionReceipt' | 'getChainId'>,
  hash: Hex, step: string) {
  const [rawTransaction, receipt, chainId] = await Promise.all([
    client.getRawTransaction({ hash }), client.getTransactionReceipt({ hash }), client.getChainId(),
  ]);
  if (keccak256(rawTransaction) !== hash || receipt.transactionHash !== hash) throw new Error('Transaction identity mismatch');
  const tx = parseTransaction(rawTransaction);
  if (tx.chainId !== chainId || tx.gas === undefined || receipt.gasUsed > tx.gas) throw new Error('Transaction envelope/receipt mismatch');
  return { step, hash, status: receipt.status, chainId, blockHash: receipt.blockHash, blockNumber: receipt.blockNumber,
    rawTransaction, to: tx.to, selector: tx.data?.slice(0, 10), gas: receipt.gasUsed, gasLimit: tx.gas,
    calldataBytes: ((tx.data?.length ?? 2) - 2) / 2, serializedBytes: (rawTransaction.length - 2) / 2,
    maxFeePerGas: tx.maxFeePerGas, maxPriorityFeePerGas: tx.maxPriorityFeePerGas, gasPrice: tx.gasPrice,
    localPaidExecutionWei: receipt.gasUsed * receipt.effectiveGasPrice, baseGasCap: cap(tx.gas) };
}
export type TransactionCostSample = Awaited<ReturnType<typeof transactionSample>>;
type FeeInput = Pick<TransactionCostSample, 'rawTransaction' | 'chainId' | 'gas' | 'gasLimit'> &
  Partial<Pick<TransactionCostSample, 'maxFeePerGas' | 'maxPriorityFeePerGas' | 'gasPrice'>>;

/** A fee projection for synthetic samples, never a Base execution or finality claim.
 * L2 gas comes from the local receipt; price uses the original signed fee terms.
 * Oracle calls use the actual signed bytes and a single canonical Base block.
 */
export async function baseCostQuote<T extends FeeInput>(client: Pick<PublicClient, 'getChainId' | 'getBlock' | 'request'>,
  samples: readonly T[]) {
  if (await client.getChainId() !== 8453) throw new Error('Base mainnet read-only quote requires chain 8453');
  const block = await client.getBlock();
  if (!block.hash || block.number === null || block.baseFeePerGas === null) throw new Error('Incomplete Base fee snapshot');
  const baseFee = block.baseFeePerGas;
  const read = async (functionName: 'getL1Fee' | 'getOperatorFee', value: Hex | bigint): Promise<bigint> => {
    const data = functionName === 'getL1Fee'
      ? encodeFunctionData({ abi: baseFeeOracleAbi, functionName, args: [value as Hex] })
      : encodeFunctionData({ abi: baseFeeOracleAbi, functionName, args: [value as bigint] });
    const result = await client.request({ method: 'eth_call', params: [{ to: oracle, data },
      { blockHash: block.hash, requireCanonical: true }] } as never) as Hex;
    const fee = decodeFunctionResult({ abi: baseFeeOracleAbi, functionName, data: result });
    if (typeof fee !== 'bigint') throw new Error('Invalid Base oracle fee');
    return fee;
  };
  const quote = async (sample: T) => {
    const effectiveGasPrice = sample.maxFeePerGas !== undefined
      ? (sample.maxFeePerGas < baseFee + (sample.maxPriorityFeePerGas ?? 0n)
        ? sample.maxFeePerGas : baseFee + (sample.maxPriorityFeePerGas ?? 0n)) : sample.gasPrice;
    const metadata = { sourceChainId: sample.chainId, baseGasCap: cap(sample.gasLimit), effectiveGasPrice };
    try {
      const [l1DataFeeWei, operatorFeeWei] = await Promise.all([
        read('getL1Fee', sample.rawTransaction), read('getOperatorFee', sample.gas),
      ]);
      const executionFeeWei = effectiveGasPrice === undefined ? undefined : sample.gas * effectiveGasPrice;
      const status = metadata.baseGasCap === 'above' ? 'above_transaction_cap' as const
        : effectiveGasPrice === undefined || effectiveGasPrice < baseFee ? 'fee_terms_insufficient' as const : 'quoted' as const;
      return { ...metadata, status, l1DataFeeWei, operatorFeeWei, executionFeeWei,
        projectedFeeWei: status === 'quoted' ? executionFeeWei! + l1DataFeeWei + operatorFeeWei : undefined };
    } catch (error) {
      // A failed oracle request is not a zero fee, and transport details may contain credentials.
      return { ...metadata, status: 'oracle_unavailable' as const,
        errorType: error instanceof Error ? error.name : 'UnknownError' };
    }
  };
  // Keep public RPC load bounded; this is an offline benchmark, not a relay queue.
  const results: Awaited<ReturnType<typeof quote>>[] = new Array(samples.length);
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(4, samples.length) }, async () => {
    while (next < samples.length) { const index = next++; results[index] = await quote(samples[index]); }
  }));
  return { chainId: 8453, blockNumber: block.number, blockHash: block.hash, baseFeePerGas: baseFee,
    oracle, transactionGasCap: BASE_TRANSACTION_GAS_CAP, samples: results,
    limits: 'Projection only: original local signed bytes and fee terms, local gasUsed; no Base execution, inclusion or finality measurement.' };
}

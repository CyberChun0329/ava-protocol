import { BaseError, getCreate2Address, isAddress, keccak256, TransactionNotFoundError,
  TransactionReceiptNotFoundError, type Address, type Hex, type PublicClient } from 'viem';
import type { FoundryBroadcast } from './deployment.js';
import { CanonicalSnapshotChanged, withCanonicalSnapshot } from './read-point.js';
import { AvaReceiptError } from './receipts.js';

// Runtime returned by the creation code in Arachnid's published deployment transaction:
// https://github.com/Arachnid/deterministic-deployment-proxy#deployment-transaction
const create2Proxy = '0x4e59b44847b379578588920ca78fbf26c0b4956c' as Address;
const create2Runtime = '0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf3';
const bytes32 = (value: unknown): value is Hex => typeof value === 'string' && /^0x[0-9a-fA-F]{64}$/.test(value);
const bytes = (value: unknown): value is Hex => typeof value === 'string' && /^0x(?:[0-9a-fA-F]{2})*$/.test(value);
const address = (value: unknown): value is Address => typeof value === 'string' && isAddress(value);
const same = (a: string, b: string) => a.toLowerCase() === b.toLowerCase();
function quantity(value: unknown): bigint | undefined {
  if (typeof value === 'number' && (!Number.isSafeInteger(value) || value < 0)) return undefined;
  if (typeof value !== 'number' && (typeof value !== 'string' || !/^(?:[0-9]+|0x[0-9a-fA-F]+)$/.test(value))) return undefined;
  try { return BigInt(value); } catch { return undefined; }
}

/** Check declarations against one canonical observation. Child names and addresses remain declarations. */
export async function verifyFoundryBroadcasts(runs: readonly FoundryBroadcast[], chainId: number,
  verification: { client: PublicClient; confirmations?: number }): Promise<readonly FoundryBroadcast[]> {
  const required = verification?.confirmations ?? 1;
  if (!verification?.client || !Number.isSafeInteger(chainId) || chainId < 1
      || !Number.isSafeInteger(required) || required < 1 || !Array.isArray(runs)) {
    throw new AvaReceiptError('invalid_request');
  }
  const client = verification.client;
  for (const run of runs) {
    if (!Array.isArray(run?.transactions) || !Array.isArray(run.receipts) || run.pending?.length) {
      throw new AvaReceiptError('invalid_request');
    }
    if (Number(run.chain) !== chainId) throw new AvaReceiptError('chain_mismatch');
  }
  try {
    if (await client.getChainId() !== chainId) throw new AvaReceiptError('chain_mismatch');
    return await withCanonicalSnapshot(client, async ({ blockNumber: head }) => {
      const seen = new Set<string>();
      let previous: { blockNumber: bigint; index: number } | undefined;
      let block: Awaited<ReturnType<PublicClient['getBlock']>> | undefined;
      const verified: FoundryBroadcast[] = [];
      for (const run of runs) {
        const receipts: FoundryBroadcast['receipts'][number][] = [];
        const declaredReceipts = new Set<string>();
        for (const receipt of run.receipts) {
          if (!bytes32(receipt?.transactionHash) || declaredReceipts.has(receipt.transactionHash.toLowerCase())) {
            throw new AvaReceiptError('receipt_mismatch');
          }
          declaredReceipts.add(receipt.transactionHash.toLowerCase());
        }
        for (const declaration of run.transactions) {
          const hash = declaration?.hash;
          const fields = declaration?.transaction;
          if (!fields || !bytes32(hash) || seen.has(hash.toLowerCase()) || !address(fields.from)
              || quantity(fields.nonce) === undefined || quantity(fields.value ?? 0) === undefined
              || !bytes(fields.input) || (declaration.additionalContracts !== undefined
                && !Array.isArray(declaration.additionalContracts))) throw new AvaReceiptError('invalid_request');
          seen.add(hash.toLowerCase());
          if (!declaredReceipts.has(hash.toLowerCase())) {
            throw new AvaReceiptError('receipt_mismatch');
          }
          const [tx, receipt] = await Promise.all([
            client.getTransaction({ hash }), client.getTransactionReceipt({ hash }),
          ]);
          if (tx.blockNumber === null || tx.blockHash === null || tx.transactionIndex === null) {
            throw new AvaReceiptError('not_mined');
          }
          if (!bytes32(receipt.blockHash) || typeof receipt.blockNumber !== 'bigint' || receipt.blockNumber < 0n
              || !Number.isSafeInteger(receipt.transactionIndex) || receipt.transactionIndex < 0
              || (receipt.status !== 'success' && receipt.status !== 'reverted')) throw new AvaReceiptError('invalid_receipt');
          if (receipt.status === 'reverted') throw new AvaReceiptError('reverted');
          if (!same(tx.hash, hash) || !same(receipt.transactionHash, hash) || !same(tx.from, fields.from)
              || !same(receipt.from, tx.from) || BigInt(tx.nonce) !== quantity(fields.nonce)
              || !same(tx.input, fields.input) || tx.value !== quantity(fields.value ?? 0)
              || !same(tx.blockHash, receipt.blockHash) || tx.blockNumber !== receipt.blockNumber
              || tx.transactionIndex !== receipt.transactionIndex
              || (tx.to?.toLowerCase() ?? null) !== (receipt.to?.toLowerCase() ?? null)
              || (tx.chainId !== undefined && tx.chainId !== chainId)
              || (fields.chainId !== undefined && quantity(fields.chainId) !== BigInt(chainId))) {
            throw new AvaReceiptError('receipt_mismatch');
          }
          if (previous && (receipt.blockNumber < previous.blockNumber
              || (receipt.blockNumber === previous.blockNumber && receipt.transactionIndex <= previous.index))) {
            throw new AvaReceiptError('receipt_mismatch');
          }
          previous = { blockNumber: receipt.blockNumber, index: receipt.transactionIndex };
          if (receipt.blockNumber > head || head - receipt.blockNumber + 1n < BigInt(required)) {
            throw new AvaReceiptError('not_confirmed');
          }
          if (block?.number !== receipt.blockNumber) block = await client.getBlock({ blockNumber: receipt.blockNumber });
          if (!bytes32(block.hash) || block.number !== receipt.blockNumber) throw new AvaReceiptError('invalid_receipt');
          if (!same(block.hash, receipt.blockHash)) throw new AvaReceiptError('orphaned');
          const included = block.transactions[receipt.transactionIndex];
          if (!bytes32(included) || !same(included, hash)) throw new AvaReceiptError('receipt_mismatch');
          const point = { blockHash: receipt.blockHash, requireCanonical: true as const };
          const hasCode = async (target: string) => {
            if (!address(target)) throw new AvaReceiptError('invalid_request');
            const code = await client.getCode({ address: target, ...point });
            if (!code || code === '0x') throw new AvaReceiptError('receipt_mismatch');
          };
          if (declaration.transactionType === 'CREATE') {
            if (tx.to !== null || fields.to != null || !address(declaration.contractAddress)
                || !receipt.contractAddress || !same(receipt.contractAddress, declaration.contractAddress)) {
              throw new AvaReceiptError('receipt_mismatch');
            }
            await hasCode(declaration.contractAddress);
          } else if (declaration.transactionType === 'CREATE2') {
            if (receipt.contractAddress !== null || !tx.to || !same(tx.to, create2Proxy)
                || (fields.to != null && !same(fields.to, create2Proxy))
                || !address(declaration.contractAddress) || fields.input.length <= 66) {
              throw new AvaReceiptError('receipt_mismatch');
            }
            const proxyCode = await client.getCode({ address: create2Proxy, ...point });
            if (!proxyCode || !same(proxyCode, create2Runtime)) throw new AvaReceiptError('receipt_mismatch');
            const derived = getCreate2Address({ from: create2Proxy, salt: fields.input.slice(0, 66) as Hex,
              bytecodeHash: keccak256(`0x${fields.input.slice(66)}` as Hex) });
            if (!same(derived, declaration.contractAddress)) throw new AvaReceiptError('receipt_mismatch');
            await hasCode(declaration.contractAddress);
          } else if (declaration.transactionType === 'CALL') {
            const declaredTarget = fields.to ?? declaration.contractAddress;
            if (receipt.contractAddress !== null || !address(declaredTarget) || !tx.to || !same(tx.to, declaredTarget)
                || (declaration.contractAddress != null && !same(declaration.contractAddress, tx.to))) {
              throw new AvaReceiptError('receipt_mismatch');
            }
          } else throw new AvaReceiptError('invalid_request');
          // Code presence verifies neither the creator nor the declared child name.
          for (const child of declaration.additionalContracts ?? []) {
            if (!child) throw new AvaReceiptError('invalid_request');
            if (child.transactionType === 'CREATE' || child.transactionType === 'CREATE2') await hasCode(child.address);
          }
          for (const log of receipt.logs) {
            if (log.removed || !log.blockHash || !same(log.blockHash, receipt.blockHash)
                || log.blockNumber !== receipt.blockNumber || !log.transactionHash || !same(log.transactionHash, hash)
                || log.transactionIndex !== receipt.transactionIndex || !Number.isSafeInteger(log.logIndex)
                || log.logIndex === null || log.logIndex < 0) {
              throw new AvaReceiptError('receipt_mismatch');
            }
          }
          receipts.push({ transactionHash: receipt.transactionHash, status: '0x1', logs: receipt.logs });
        }
        verified.push({ ...run, receipts });
      }
      return verified;
    });
  } catch (error) {
    if (error instanceof AvaReceiptError) throw error;
    if (error instanceof CanonicalSnapshotChanged) throw new AvaReceiptError('orphaned');
    const missing = (item: unknown) => item instanceof TransactionNotFoundError || item instanceof TransactionReceiptNotFoundError;
    if (missing(error) || (error instanceof BaseError && error.walk(missing))) throw new AvaReceiptError('not_mined');
    throw new AvaReceiptError('rpc_unavailable');
  }
}

import { AvaServiceError } from './service-client.js';
import { BaseError, isAddress, TransactionNotFoundError, TransactionReceiptNotFoundError,
  type Address, type Hex, type PublicClient } from 'viem';
import { AvaReceiptError } from './receipts.js';
import { withCanonicalSnapshot } from './read-point.js';

/** A relay rejection describes this attempt only, not global broadcast state. */
export function submissionFailure(error: unknown):
  { status: 'relay-rejected'; code: string } | { status: 'submission-uncertain'; code: 'relay_unavailable' } | undefined {
  if (!(error instanceof AvaServiceError)) return undefined;
  const knownRejectionCodes: Record<number, readonly string[]> = {
    400: ['invalid_request', 'invalid_transaction'],
    409: ['transaction_conflict'],
    401: ['bearer_token_required'],
    403: ['local_host_required'],
    429: ['work_queue_full'],
  };
  if (error.kind === 'http' && error.status !== undefined && knownRejectionCodes[error.status]?.includes(error.code)) {
    return { status: 'relay-rejected', code: error.code };
  }
  return { status: 'submission-uncertain', code: 'relay_unavailable' };
}

function isBytes32Hash(value: unknown): value is Hex {
  return typeof value === 'string' && /^0x[0-9a-fA-F]{64}$/.test(value);
}

/** Prove that a different canonical mined transaction consumed this actor's nonce. */
export async function verifyNonceReplacement(client: PublicClient,
  input: { chainId: number; account: Address; nonce: number; originalHash: Hex; replacementHash: Hex }):
  Promise<{ transactionHash: Hex; from: Address; nonce: number; blockNumber: bigint; blockHash: Hex; status: 'success' | 'reverted' }> {
  let request: typeof input;
  try {
    request = structuredClone(input);
  } catch {
    throw new AvaReceiptError('invalid_request');
  }
  if (!request || !Number.isSafeInteger(request.chainId) || request.chainId < 1 || !isAddress(request.account)) {
    throw new AvaReceiptError('invalid_request');
  }
  if (!Number.isSafeInteger(request.nonce) || request.nonce < 0
      || !isBytes32Hash(request.originalHash) || !isBytes32Hash(request.replacementHash)
      || request.originalHash.toLowerCase() === request.replacementHash.toLowerCase()) {
    throw new AvaReceiptError('invalid_request');
  }
  try {
    if (await client.getChainId() !== request.chainId) throw new AvaReceiptError('chain_mismatch');
    return await withCanonicalSnapshot(client, async ({ blockNumber: snapshotBlockNumber }) => {
      const [receipt, transaction] = await Promise.all([
        client.getTransactionReceipt({ hash: request.replacementHash }),
        client.getTransaction({ hash: request.replacementHash }),
      ]);
      if (transaction.blockNumber === null || transaction.blockHash === null || transaction.transactionIndex === null) {
        throw new AvaReceiptError('not_mined');
      }
      if (!isBytes32Hash(receipt.blockHash) || typeof receipt.blockNumber !== 'bigint' || receipt.blockNumber < 0n
          || !Number.isSafeInteger(receipt.transactionIndex) || receipt.transactionIndex < 0
          || (receipt.status !== 'success' && receipt.status !== 'reverted')) {
        throw new AvaReceiptError('invalid_receipt');
      }

      // Both RPC records must identify the requested replacement and actor/nonce.
      if (transaction.hash.toLowerCase() !== request.replacementHash.toLowerCase()
          || receipt.transactionHash.toLowerCase() !== request.replacementHash.toLowerCase()
          || transaction.from.toLowerCase() !== request.account.toLowerCase()
          || receipt.from.toLowerCase() !== transaction.from.toLowerCase()
          || transaction.nonce !== request.nonce) {
        throw new AvaReceiptError('receipt_mismatch');
      }
      if (transaction.blockHash.toLowerCase() !== receipt.blockHash.toLowerCase()
          || transaction.blockNumber !== receipt.blockNumber || transaction.transactionIndex !== receipt.transactionIndex
          || (transaction.to?.toLowerCase() ?? null) !== (receipt.to?.toLowerCase() ?? null)
          || (transaction.chainId !== undefined && transaction.chainId !== request.chainId)) {
        throw new AvaReceiptError('receipt_mismatch');
      }

      // Confirm this mined location against the captured head and canonical block.
      if (receipt.blockNumber > snapshotBlockNumber) throw new AvaReceiptError('not_confirmed');
      const canonicalBlock = await client.getBlock({ blockNumber: receipt.blockNumber });
      if (!isBytes32Hash(canonicalBlock.hash) || canonicalBlock.number !== receipt.blockNumber) {
        throw new AvaReceiptError('invalid_receipt');
      }
      if (canonicalBlock.hash.toLowerCase() !== receipt.blockHash.toLowerCase()) throw new AvaReceiptError('orphaned');
      const included = canonicalBlock.transactions?.[receipt.transactionIndex];
      if (!isBytes32Hash(included) || included.toLowerCase() !== request.replacementHash.toLowerCase()) {
        throw new AvaReceiptError('receipt_mismatch');
      }
      return { transactionHash: receipt.transactionHash, from: transaction.from, nonce: transaction.nonce,
        blockNumber: receipt.blockNumber, blockHash: receipt.blockHash, status: receipt.status };
    });
  } catch (error) {
    if (error instanceof AvaReceiptError) throw error;
    const isMissingTransaction = (item: unknown) =>
      item instanceof TransactionNotFoundError || item instanceof TransactionReceiptNotFoundError;
    if (isMissingTransaction(error) || (error instanceof BaseError && error.walk(isMissingTransaction))) {
      throw new AvaReceiptError('not_mined');
    }
    throw new AvaReceiptError('rpc_unavailable');
  }
}

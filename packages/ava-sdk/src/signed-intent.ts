import { keccak256, parseTransaction, recoverTransactionAddress, serializeTransaction,
  type Address, type Hex, type TransactionSerialized } from 'viem';
import type { AvaCall } from './index.js';
import { isSupportedTransactionType } from './transaction-envelope.js';
import { AvaSigningError } from './signing-errors.js';

const maximumCanonicalSignatureS = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0n;

/** Verify signed bytes against an expected intent without signing or submitting them. */
export async function verifySignedIntent(serialized: Hex, expected: { chainId: number; account: Address; call: AvaCall }):
  Promise<{ hash: Hex; from: Address; to: Address; nonce: number }> {
  try {
    const expectedChainId = expected.chainId;
    const expectedAccount = expected.account;
    const expectedCall = {
      to: expected.call.to,
      data: expected.call.data,
      value: expected.call.value ?? 0n,
    };
    const transaction = parseTransaction(serialized);

    // Only supported envelopes with a canonical signature may be reserialized.
    if (!isSupportedTransactionType(transaction.type) || !transaction.r || !transaction.s) {
      throw new Error();
    }
    if (BigInt(transaction.s) > maximumCanonicalSignatureS) throw new Error();
    const canonicalTransaction = serializeTransaction(transaction, {
      r: transaction.r,
      s: transaction.s,
      v: transaction.v!,
      yParity: transaction.yParity!,
    });
    if (canonicalTransaction.toLowerCase() !== serialized.toLowerCase()) throw new Error();

    if (transaction.chainId !== expectedChainId
      || transaction.to?.toLowerCase() !== expectedCall.to.toLowerCase()
      || (transaction.data ?? '0x').toLowerCase() !== expectedCall.data.toLowerCase()
      || (transaction.value ?? 0n) !== expectedCall.value
      || !Number.isSafeInteger(transaction.nonce)
      || transaction.nonce! < 0) {
      throw new Error();
    }

    const from = await recoverTransactionAddress({ serializedTransaction: serialized as TransactionSerialized });
    if (from.toLowerCase() !== expectedAccount.toLowerCase()) throw new Error();

    // Recovery yields control: reject changes to the caller's expectations while it was pending.
    if (expected.chainId !== expectedChainId
      || expected.account.toLowerCase() !== expectedAccount.toLowerCase()
      || expected.call.to.toLowerCase() !== expectedCall.to.toLowerCase()
      || expected.call.data.toLowerCase() !== expectedCall.data.toLowerCase()
      || (expected.call.value ?? 0n) !== expectedCall.value) {
      throw new Error();
    }
    return { hash: keccak256(serialized), from, to: transaction.to!, nonce: transaction.nonce! };
  } catch {
    throw new AvaSigningError('signing', 'intent_mismatch');
  }
}

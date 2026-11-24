import { BaseError, ContractFunctionRevertedError } from 'viem';

export class AvaReadError extends Error {
  readonly name = 'AvaReadError';
  readonly code = 'read_unavailable';
  constructor() { super('AVA read unavailable'); }
}

/** Viem also wraps internal RPC failures as reverts. Require a reported EVM
 * revert or ABI-decoded revert data; the wrapper's name/text alone is not proof. */
export function readRejection(error: unknown) {
  if (!(error instanceof BaseError)) return undefined;
  const reverted = error.walk(item => item instanceof ContractFunctionRevertedError);
  if (!(reverted instanceof ContractFunctionRevertedError)) return undefined;
  const reported = error.walk(item => !!item && typeof item === 'object' && 'code' in item && item.code === 3);
  if (!reverted.data && !reported) return undefined;
  return { reason: 'contract_reverted' as const,
    ...(reverted.data ? { errorName: reverted.data.errorName } : {}) };
}

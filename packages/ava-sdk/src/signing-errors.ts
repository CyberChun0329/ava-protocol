import { BaseError, ContractFunctionRevertedError, ExecutionRevertedError, HttpRequestError,
  RpcError, RpcRequestError, TimeoutError, UserRejectedRequestError, decodeErrorResult,
  type Abi, type Hex } from 'viem';

export type SigningStage = 'chain' | 'simulation' | 'preparation' | 'signing';
export type SigningErrorCode = 'chain_mismatch' | 'contract_reverted' | 'transport_error'
  | 'rpc_error' | 'signer_rejected' | 'intent_mismatch' | 'unknown';

/** Safe metadata only. No original cause, provider text, revert arguments or signed bytes. */
export class AvaSigningError extends Error {
  readonly name = 'AvaSigningError';
  constructor(readonly stage: SigningStage, readonly code: SigningErrorCode, readonly errorName?: string) {
    super(`AVA ${stage}: ${code}${errorName ? ` (${errorName})` : ''}`);
  }
}

export async function signingStep<T>(stage: SigningStage, abi: Abi, operation: () => Promise<T>): Promise<T> {
  try { return await operation(); }
  catch (error) {
    if (error instanceof AvaSigningError) throw error;
    const find = (predicate: (item: unknown) => boolean): unknown => error instanceof BaseError
      ? error.walk(predicate) : predicate(error) ? error : undefined;
    const codeIs = (item: unknown, code: number) => !!item && typeof item === 'object' && 'code' in item && item.code === code;
    if (find(item => item instanceof UserRejectedRequestError || codeIs(item, 4001))) {
      throw new AvaSigningError(stage, 'signer_rejected');
    }
    if (find(item => item instanceof ExecutionRevertedError || item instanceof ContractFunctionRevertedError || codeIs(item, 3))) {
      let errorName: string | undefined;
      const withData = find(item => item instanceof ContractFunctionRevertedError
        || !!item && typeof item === 'object' && 'data' in item);
      if (withData && typeof withData === 'object' && 'data' in withData) {
        const raw = withData instanceof ContractFunctionRevertedError ? withData.raw : withData.data;
        const data = raw && typeof raw === 'object' && 'data' in raw ? raw.data : raw;
        if (typeof data === 'string' && /^0x[0-9a-fA-F]+$/.test(data)) {
          try { errorName = decodeErrorResult({ abi, data: data as Hex }).errorName; } catch { /* Unknown selector remains a revert. */ }
        }
      }
      throw new AvaSigningError(stage, 'contract_reverted', errorName);
    }
    if (find(item => item instanceof HttpRequestError || item instanceof TimeoutError)) {
      throw new AvaSigningError(stage, 'transport_error');
    }
    if (find(item => item instanceof RpcError || item instanceof RpcRequestError)) {
      throw new AvaSigningError(stage, 'rpc_error');
    }
    throw new AvaSigningError(stage, 'unknown');
  }
}

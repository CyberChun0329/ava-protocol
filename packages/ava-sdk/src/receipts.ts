import { BaseError, TransactionReceiptNotFoundError, decodeEventLog, isAddress, toEventSelector, zeroAddress,
  type Abi, type AbiEvent, type Address, type Hex, type PublicClient } from 'viem';

export type ReceiptErrorCode = 'invalid_request' | 'chain_mismatch' | 'not_mined' | 'not_confirmed'
  | 'reverted' | 'orphaned' | 'invalid_receipt' | 'receipt_mismatch' | 'helper_mismatch'
  | 'event_missing' | 'event_ambiguous' | 'invalid_id' | 'rpc_unavailable';
export class AvaReceiptError extends Error {
  readonly name = 'AvaReceiptError';
  constructor(readonly code: ReceiptErrorCode) { super(`AVA receipt ${code}`); }
}
export interface CanonicalEventInput {
  chainId: number;
  emitter: Address;
  abi: Abi;
  eventName: string;
  confirmations?: number;
  logIndex?: number;
}
export interface CanonicalEventReceipt {
  chainId: number;
  emitter: Address;
  eventName: string;
  transactionHash: Hex;
  blockHash: Hex;
  blockNumber: bigint;
  logIndex: number;
  confirmations: number;
  args: unknown;
}
export interface CreatedIdEvent { eventName: string; idField: string }
export interface CreatedIdOptions extends CreatedIdEvent {
  chainId: number;
  emitter: Address;
  abi: Abi;
  confirmations?: number;
  /** Only for application event schemas whose identifiers legitimately start at zero. */
  allowZeroId?: boolean;
}
export interface CreatedIdInput extends CreatedIdOptions { idType?: 'uint' }
export interface CreatedBytes32IdInput extends CreatedIdOptions { idType: 'bytes32' }
export interface CreatedIdReceipt<T extends bigint | Hex = bigint> {
  id: T;
  transactionHash: Hex;
  blockHash: Hex;
  blockNumber: bigint;
  emitter: Address;
  eventName: string;
  logIndex: number;
  confirmations: number;
}

function validateEventRequest<T extends CanonicalEventInput>(hash: Hex, input: T) {
  let request: T;
  try {
    if (!input || typeof input !== 'object') throw new Error();
    request = structuredClone(input);
  } catch {
    throw new AvaReceiptError('invalid_request');
  }
  if (!Array.isArray(request.abi)) throw new AvaReceiptError('invalid_request');
  const required = request.confirmations ?? 1;
  if (!Number.isSafeInteger(request.chainId) || request.chainId < 1 || !/^0x[0-9a-fA-F]{64}$/.test(hash)
      || !isAddress(request.emitter) || request.emitter === zeroAddress || !request.eventName
      || !Number.isSafeInteger(required) || required < 1
      || (request.logIndex !== undefined && (!Number.isSafeInteger(request.logIndex) || request.logIndex < 0))) {
    throw new AvaReceiptError('invalid_request');
  }
  const definitions = request.abi.filter(
    (item): item is AbiEvent => item.type === 'event' && item.name === request.eventName,
  );
  if (definitions.length !== 1 || definitions[0].anonymous) throw new AvaReceiptError('invalid_request');
  const definition = definitions[0];
  return { request, required, definition, topic: toEventSelector(definition) };
}

function validateCreatedIdRequest(hash: Hex, input: CreatedIdInput | CreatedBytes32IdInput) {
  const validated = validateEventRequest(hash, input);
  const { request, definition } = validated;
  if (!request.idField || (request.idType !== undefined && request.idType !== 'uint' && request.idType !== 'bytes32')) {
    throw new AvaReceiptError('invalid_request');
  }
  const idType = request.idType ?? 'uint';
  if (idType === 'bytes32') {
    const fields = definition.inputs.filter(item => item.name === request.idField);
    if (fields.length !== 1 || fields[0].type !== 'bytes32') throw new AvaReceiptError('invalid_request');
  }
  return { ...validated, idType };
}

function decodeCreatedId(args: unknown, request: CreatedIdInput | CreatedBytes32IdInput,
  idType: 'uint' | 'bytes32'): bigint | Hex {
  if (!args || typeof args !== 'object' || Array.isArray(args)) throw new AvaReceiptError('invalid_id');
  const value = (args as Record<string, unknown>)[request.idField];
  if (idType === 'bytes32') {
    if (typeof value !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(value)) throw new AvaReceiptError('invalid_id');
    const id = value.toLowerCase() as Hex;
    if (id === `0x${'00'.repeat(32)}` && request.allowZeroId !== true) throw new AvaReceiptError('invalid_id');
    return id;
  }

  const integer = typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? BigInt(value) : value;
  if (typeof integer !== 'bigint' || integer < 0n || (integer === 0n && request.allowZeroId !== true)) {
    throw new AvaReceiptError('invalid_id');
  }
  return integer;
}

/** One current observation, not a waiter or finality promise. No signing or broadcasting. */
export function readCreatedId(client: PublicClient, hash: Hex, input: CreatedBytes32IdInput): Promise<CreatedIdReceipt<Hex>>;
export function readCreatedId(client: PublicClient, hash: Hex, input: CreatedIdInput): Promise<CreatedIdReceipt<bigint>>;
export function readCreatedId(client: PublicClient, hash: Hex,
  input: CreatedIdInput | CreatedBytes32IdInput): Promise<CreatedIdReceipt<bigint | Hex>>;
export async function readCreatedId(client: PublicClient, hash: Hex,
  input: CreatedIdInput | CreatedBytes32IdInput): Promise<CreatedIdReceipt<bigint | Hex>> {
  const [created] = await readCreatedIdEvents(client, hash, input, 1);
  return created;
}

/** Exactly two distinct numeric IDs, in canonical log order. */
export async function readCreatedIdPair(client: PublicClient, hash: Hex,
  input: CreatedIdInput): Promise<[CreatedIdReceipt<bigint>, CreatedIdReceipt<bigint>]> {
  if (input?.idType !== undefined && input.idType !== 'uint') throw new AvaReceiptError('invalid_request');
  const [first, second] = await readCreatedIdEvents(client, hash, input, 2);
  return [first as CreatedIdReceipt<bigint>, second as CreatedIdReceipt<bigint>];
}

async function readCreatedIdEvents(client: PublicClient, hash: Hex,
  input: CreatedIdInput | CreatedBytes32IdInput, count: 1 | 2): Promise<CreatedIdReceipt<bigint | Hex>[]> {
  const validated = validateCreatedIdRequest(hash, input);
  const { request, idType } = validated;
  const { found, receipt, confirmations } = await readEvents(client, hash, validated,
    args => decodeCreatedId(args, request, idType));
  if (found.length < count) throw new AvaReceiptError('event_missing');
  if (found.length > count) throw new AvaReceiptError('event_ambiguous');
  if (count === 2 && (found[0].logIndex === found[1].logIndex || found[0].value === found[1].value)) {
    throw new AvaReceiptError('event_ambiguous');
  }
  if (found.some(log => !Number.isSafeInteger(log.logIndex) || log.logIndex < 0)) {
    throw new AvaReceiptError('receipt_mismatch');
  }
  if (count === 2) found.sort((a, b) => a.logIndex - b.logIndex);
  return found.map(({ value: id, logIndex }) => ({ id, transactionHash: receipt.transactionHash,
    blockHash: receipt.blockHash, blockNumber: receipt.blockNumber,
    emitter: request.emitter, eventName: request.eventName, logIndex, confirmations }));
}

/** Read one canonical event. With a log index, decode and check only that log. */
export async function readCanonicalEvent(client: PublicClient, hash: Hex,
  input: CanonicalEventInput): Promise<CanonicalEventReceipt> {
  const validated = validateEventRequest(hash, input);
  const { request } = validated;
  const { found, receipt, confirmations } = await readEvents(client, hash, validated, args => args, request.logIndex);
  if (found.length === 0) throw new AvaReceiptError('event_missing');
  if (found.length > 1) throw new AvaReceiptError('event_ambiguous');
  const { value: args, logIndex } = found[0];
  if (!Number.isSafeInteger(logIndex) || logIndex < 0) throw new AvaReceiptError('receipt_mismatch');
  return { chainId: request.chainId, emitter: request.emitter, eventName: request.eventName,
    transactionHash: receipt.transactionHash, blockHash: receipt.blockHash, blockNumber: receipt.blockNumber,
    logIndex, confirmations, args };
}

async function readEvents<T>(client: PublicClient, hash: Hex,
  { request, required, definition, topic }: ReturnType<typeof validateEventRequest>,
  transform: (args: unknown) => T, requestedLogIndex?: number) {
  try {
    if (await client.getChainId() !== request.chainId) throw new AvaReceiptError('chain_mismatch');
    const transactionHash = hash.toLowerCase();
    const receipt = await client.getTransactionReceipt({ hash });
    if (receipt.transactionHash.toLowerCase() !== transactionHash) throw new AvaReceiptError('receipt_mismatch');
    if (receipt.status === 'reverted') throw new AvaReceiptError('reverted');
    if (receipt.status !== 'success') throw new AvaReceiptError('invalid_receipt');
    const head = await client.getBlockNumber({ cacheTime: 0 });
    if (head < receipt.blockNumber || head - receipt.blockNumber + 1n < BigInt(required)) {
      throw new AvaReceiptError('not_confirmed');
    }
    const canonical = await client.getBlock({ blockNumber: receipt.blockNumber });
    if (canonical.hash !== receipt.blockHash) throw new AvaReceiptError('orphaned');
    const emitter = request.emitter.toLowerCase();
    const eventAbi = [definition];
    const found: { value: T; logIndex: number }[] = [];
    for (const log of receipt.logs) {
      if (requestedLogIndex !== undefined && log.logIndex !== requestedLogIndex) continue;
      if (log.address.toLowerCase() !== emitter) continue;
      if (log.topics[0]?.toLowerCase() !== topic) continue;
      let decoded;
      try { decoded = decodeEventLog({ abi: eventAbi, data: log.data, topics: log.topics, strict: true }); }
      catch { throw new AvaReceiptError('invalid_receipt'); }
      if (log.removed || log.blockHash !== receipt.blockHash || log.blockNumber !== receipt.blockNumber
          || log.transactionHash?.toLowerCase() !== transactionHash || log.logIndex === null) {
        throw new AvaReceiptError('receipt_mismatch');
      }
      found.push({ value: transform(decoded.args), logIndex: log.logIndex });
    }
    const confirmations = Number(head - receipt.blockNumber + 1n);
    return { found, receipt, confirmations };
  } catch (error) {
    if (error instanceof AvaReceiptError) throw error;
    if (error instanceof TransactionReceiptNotFoundError || (error instanceof BaseError
      && error.walk(item => item instanceof TransactionReceiptNotFoundError) instanceof TransactionReceiptNotFoundError)) {
      throw new AvaReceiptError('not_mined');
    }
    throw new AvaReceiptError('rpc_unavailable');
  }
}

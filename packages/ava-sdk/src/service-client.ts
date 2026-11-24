import { keccak256, type Hex } from 'viem';
import type { QueryHealth, QueryEvent, TransactionRecord, ServicePage, ServicePageOptions, ServiceEventQuery,
  GovernedObjectWire, RecognitionWire, RequestWire, CorrectionCaseWire } from './service-types.js';

export type AvaServiceErrorKind = 'http' | 'transport' | 'malformed_response' | 'cancelled';
export interface ServiceRequestOptions { signal?: AbortSignal }
export interface TransactionObservationOptions extends ServiceRequestOptions {
  timeoutMs?: number;
  pollIntervalMs?: number;
}

/** Safe error metadata; response bodies, signed bytes and credentials are never retained. */
export class AvaServiceError extends Error {
  constructor(readonly kind: AvaServiceErrorKind, readonly code: string, readonly status?: number) {
    super(status === undefined ? `AVA service ${kind}: ${code}` : `AVA service ${status}: ${code}`);
    this.name = 'AvaServiceError';
  }
}

const record = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value);
const decimal = (value: unknown): value is string => typeof value === 'string' && /^(0|[1-9][0-9]{0,77})$/.test(value);
const hash = (value: unknown): value is Hex => typeof value === 'string' && /^0x[0-9a-fA-F]{64}$/.test(value);
function requireTransactionIdentity(value: unknown, key: string, expectedHash: Hex): TransactionRecord {
  if (!record(value) || value.key !== key || typeof value.hash !== 'string'
    || value.hash.toLowerCase() !== expectedHash.toLowerCase()) {
    throw new AvaServiceError('malformed_response', 'transaction_identity_mismatch');
  }
  return value as unknown as TransactionRecord;
}

const serviceErrorCodes = new Set(['local_host_required', 'bearer_token_required', 'invalid_request',
  'invalid_cursor', 'invalid_transaction', 'transaction_conflict', 'transaction_not_found',
  'work_queue_full', 'request_cancelled', 'chain_or_query_unavailable']);

/** Validate only the typed discovery interface; legacy raw query calls retain their wire contract. */
function eventPage(value: unknown, query: ServiceEventQuery): ServicePage<QueryEvent> {
  const invalid = (): never => { throw new AvaServiceError('malformed_response', 'malformed_response'); };
  if (!record(value) || !record(value.asOf) || !Array.isArray(value.items)) return invalid();
  const health = value.asOf;
  if (!['not_synced', 'synced'].includes(String(health.status))
    || !Number.isSafeInteger(health.confirmations) || (health.confirmations as number) < 1
    || (health.chainId !== undefined && (!Number.isSafeInteger(health.chainId) || (health.chainId as number) < 1))
    || (health.genesisHash !== undefined && !hash(health.genesisHash))
    || ['indexedBlock', 'headBlock', 'confirmationTarget', 'startBlock'].some(key => health[key] !== undefined && !decimal(health[key]))
    || (health.indexedBlock !== undefined) !== (health.indexedBlockHash !== undefined)
    || (health.indexedBlockHash !== undefined && !hash(health.indexedBlockHash))
    || ['lastSyncAt', 'error'].some(key => health[key] !== undefined && typeof health[key] !== 'string')
    || (value.nextCursor !== undefined && (typeof value.nextCursor !== 'string' || !value.nextCursor || value.nextCursor.length > 4096))
    || value.items.length > Math.min(query.limit ?? 50, 100)) return invalid();
  const indexed = decimal(health.indexedBlock) ? BigInt(health.indexedBlock) : undefined;
  if (query.at && (health.status !== 'synced' || indexed === undefined || indexed < BigInt(query.at.blockNumber)
    || (indexed === BigInt(query.at.blockNumber) && String(health.indexedBlockHash).toLowerCase() !== query.at.blockHash.toLowerCase()))) return invalid();
  let previous: QueryEvent | undefined;
  for (const item of value.items) {
    if (!record(item) || typeof item.source !== 'string' || !item.source || typeof item.event !== 'string' || !item.event
      || typeof item.address !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(item.address)
      || !record(item.args) || !decimal(item.blockNumber) || !hash(item.blockHash) || !hash(item.parentHash)
      || !hash(item.transactionHash) || !Number.isSafeInteger(item.logIndex) || (item.logIndex as number) < 0) return invalid();
    const block = BigInt(item.blockNumber), logIndex = item.logIndex as number;
    if (indexed === undefined || block > indexed
      || (block === indexed && item.blockHash.toLowerCase() !== String(health.indexedBlockHash).toLowerCase())
      || (health.startBlock !== undefined && block < BigInt(health.startBlock as string))
      || (query.source !== undefined && item.source !== query.source)
      || (query.expectedSourceAddress !== undefined && item.address.toLowerCase() !== query.expectedSourceAddress.toLowerCase())
      || (query.event !== undefined && item.event !== query.event)
      || (query.appId !== undefined && (typeof item.args.appId !== 'string' || item.args.appId.toLowerCase() !== query.appId.toLowerCase()))
      || (query.arg !== undefined && (!['string', 'number', 'boolean'].includes(typeof item.args[query.arg.name])
        || String(item.args[query.arg.name]) !== query.arg.value))
      || (query.fromBlock !== undefined && block < BigInt(query.fromBlock))
      || (query.before !== undefined && (block > BigInt(query.before.blockNumber)
        || (block === BigInt(query.before.blockNumber) && logIndex >= query.before.logIndex)))
      || (query.at !== undefined && (block > BigInt(query.at.blockNumber)
        || (block === BigInt(query.at.blockNumber) && item.blockHash.toLowerCase() !== query.at.blockHash.toLowerCase())))) return invalid();
    if (previous) {
      const priorBlock = BigInt(previous.blockNumber);
      const comparison = block === priorBlock ? Math.sign(logIndex - previous.logIndex) : block < priorBlock ? -1 : 1;
      if ((query.order === 'desc' ? comparison >= 0 : comparison <= 0)
        || (block === priorBlock && item.blockHash.toLowerCase() !== previous.blockHash.toLowerCase())) return invalid();
    }
    previous = item as unknown as QueryEvent;
  }
  return value as unknown as ServicePage<QueryEvent>;
}

export class AvaServiceClient {
  constructor(readonly url: string, private readonly token?: string) {}
  async call(path: string, body?: unknown, options: ServiceRequestOptions = {}): Promise<unknown> {
    const failure = (status?: number) => options.signal?.aborted
      ? new AvaServiceError('cancelled', options.signal.reason instanceof DOMException
          && options.signal.reason.name === 'TimeoutError' ? 'request_timeout' : 'request_cancelled', status)
      : new AvaServiceError('transport', 'transport_error', status);
    if (options.signal?.aborted) throw failure();
    const url = new URL(path, this.url);
    const request = { method: body === undefined ? 'GET' : 'POST', redirect: 'error' as const,
      signal: options.signal,
      headers: { ...(body === undefined ? {} : { 'content-type': 'application/json' }),
        ...(this.token ? { authorization: `Bearer ${this.token}` } : {}) },
      body: body === undefined ? undefined : JSON.stringify(body) };
    let response: Response;
    try { response = await fetch(url, request); }
    catch { throw failure(); }
    let text: string;
    try { text = await response.text(); }
    catch { throw failure(response.status); }
    let result: unknown;
    try { result = JSON.parse(text); }
    catch {
      throw new AvaServiceError(response.ok ? 'malformed_response' : 'http',
        response.ok ? 'malformed_response' : 'http_error', response.status);
    }
    if (!response.ok) {
      const code = record(result) && typeof result.error === 'string' && serviceErrorCodes.has(result.error)
        ? result.error : 'http_error';
      throw new AvaServiceError('http', code, response.status);
    }
    return result;
  }
  async submit(key: string, serializedTransaction: Hex, options: ServiceRequestOptions = {}): Promise<TransactionRecord> {
    const result = await this.call('/v1/transactions', { key, serializedTransaction }, options);
    return requireTransactionIdentity(result, key, keccak256(serializedTransaction));
  }
  /** Explicit recovery of an existing key using its original signed bytes. */
  async recoverSubmit(key: string, serializedTransaction: Hex, options: ServiceRequestOptions = {}): Promise<TransactionRecord> {
    const result = await this.call(`/v1/transactions/${encodeURIComponent(key)}/recover`, { serializedTransaction }, options);
    return requireTransactionIdentity(result, key, keccak256(serializedTransaction));
  }
  async transaction(key: string, options: ServiceRequestOptions = {}): Promise<TransactionRecord> {
    return await this.call(`/v1/transactions/${encodeURIComponent(key)}`, undefined, options) as TransactionRecord;
  }
  /** Observe an existing transaction only; never signs, submits or replaces it. */
  async observeTransaction(identity: Pick<TransactionRecord, 'key' | 'hash'>,
    options: TransactionObservationOptions = {}): Promise<TransactionRecord> {
    const { key, hash } = identity, { pollIntervalMs = 500, timeoutMs = 30_000, signal } = options;
    if (typeof key !== 'string' || !key || typeof hash !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(hash)) {
      throw new TypeError('Invalid transaction observation identity');
    }
    if (!Number.isInteger(timeoutMs) || timeoutMs < 0 || timeoutMs > 2_147_483_647
      || !Number.isInteger(pollIntervalMs) || pollIntervalMs < 1 || pollIntervalMs > 2_147_483_647) {
      throw new RangeError('Invalid transaction observation timing');
    }
    const controller = new AbortController();
    let stopped: 'observation_cancelled' | 'observation_timeout' | undefined;
    const stop = (code: NonNullable<typeof stopped>) => {
      if (!stopped) { stopped = code; controller.abort(); }
    };
    const cancel = () => stop(signal?.reason instanceof DOMException && signal.reason.name === 'TimeoutError'
      ? 'observation_timeout' : 'observation_cancelled');
    if (signal?.aborted) cancel();
    else signal?.addEventListener('abort', cancel, { once: true });
    if (timeoutMs === 0) stop('observation_timeout');
    const deadline = timeoutMs === 0 ? undefined : setTimeout(() => stop('observation_timeout'), timeoutMs);
    try {
      for (;;) {
        if (stopped) throw new AvaServiceError('cancelled', stopped);
        const result = await this.transaction(key, { signal: controller.signal });
        if (stopped) throw new AvaServiceError('cancelled', stopped);
        const record = requireTransactionIdentity(result, key, hash);
        if (![record.from, record.to].every(value => typeof value === 'string' && /^0x[0-9a-fA-F]{40}$/.test(value))
          || typeof record.nonce !== 'string' || !/^\d+$/.test(record.nonce)
          || !Number.isSafeInteger(record.confirmations) || record.confirmations < 0
          || typeof record.updatedAt !== 'string' || !record.updatedAt
          || (record.blockNumber === undefined) !== (record.blockHash === undefined)
          || (record.blockNumber !== undefined && (typeof record.blockNumber !== 'string' || !/^\d+$/.test(record.blockNumber)))
          || (record.blockHash !== undefined && (typeof record.blockHash !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(record.blockHash)))
          || (record.error !== undefined && typeof record.error !== 'string')) {
          throw new AvaServiceError('malformed_response', 'malformed_response');
        }
        if (record.status === 'confirmed' || record.status === 'reverted') {
          if (record.blockNumber === undefined || record.blockHash === undefined || record.confirmations < 1) {
            throw new AvaServiceError('malformed_response', 'malformed_response');
          }
          return record;
        }
        if (record.status !== 'pending' && record.status !== 'unknown') {
          throw new AvaServiceError('malformed_response', 'malformed_response');
        }
        await new Promise<void>(resolve => {
          const done = () => { clearTimeout(timer); controller.signal.removeEventListener('abort', done); resolve(); };
          const timer = setTimeout(done, pollIntervalMs);
          controller.signal.addEventListener('abort', done, { once: true });
          if (controller.signal.aborted) done();
        });
      }
    } catch (error) {
      if (stopped) throw new AvaServiceError('cancelled', stopped);
      throw error;
    } finally { clearTimeout(deadline); signal?.removeEventListener('abort', cancel); }
  }
  async sync(options: ServiceRequestOptions = {}): Promise<QueryHealth> { return await this.call('/v1/sync', {}, options) as QueryHealth; }
  async health(options: ServiceRequestOptions = {}): Promise<QueryHealth> { return await this.call('/health', undefined, options) as QueryHealth; }
  async events(query: string | ServiceEventQuery = '', options: ServiceRequestOptions = {}): Promise<ServicePage<QueryEvent>> {
    if (typeof query === 'string') {
      return await this.call(`/v1/events${query ? `?${query}` : ''}`, undefined, options) as ServicePage<QueryEvent>;
    }
    const captured = { ...query, ...(query.arg ? { arg: { ...query.arg } } : {}),
      ...(query.before ? { before: { ...query.before } } : {}), ...(query.at ? { at: { ...query.at } } : {}) };
    const params = new URLSearchParams();
    for (const name of ['source', 'expectedSourceAddress', 'event', 'appId', 'fromBlock', 'after', 'limit', 'order'] as const) {
      if (captured[name] !== undefined) params.set(name, String(captured[name]));
    }
    if (captured.arg) { params.set('argName', captured.arg.name); params.set('argValue', captured.arg.value); }
    if (captured.before) { params.set('beforeBlock', captured.before.blockNumber); params.set('beforeLogIndex', String(captured.before.logIndex)); }
    if (captured.at) { params.set('atBlock', captured.at.blockNumber); params.set('atHash', captured.at.blockHash); }
    const result = await this.call(`/v1/events?${params}`, undefined, options);
    return eventPage(result, captured);
  }
  objects(appId: Hex, options: ServicePageOptions & ServiceRequestOptions = {}): Promise<ServicePage<GovernedObjectWire>> {
    return this.page('objects', appId, options);
  }
  recognitions(appId: Hex, options: ServicePageOptions & ServiceRequestOptions = {}): Promise<ServicePage<RecognitionWire>> {
    return this.page('recognitions', appId, options);
  }
  requests(appId: Hex, options: ServicePageOptions & ServiceRequestOptions = {}): Promise<ServicePage<RequestWire>> {
    return this.page('requests', appId, options);
  }
  corrections(appId: Hex, options: ServicePageOptions & ServiceRequestOptions = {}): Promise<ServicePage<CorrectionCaseWire>> {
    return this.page('corrections', appId, options);
  }
  private async page<T>(kind: 'objects' | 'recognitions' | 'requests' | 'corrections', appId: Hex,
      options: ServicePageOptions & ServiceRequestOptions): Promise<ServicePage<T>> {
    const query = new URLSearchParams({ appId });
    if (options.limit !== undefined) query.set('limit', String(options.limit));
    if (options.after !== undefined) query.set('after', options.after);
    return await this.call(`/v1/${kind}?${query}`, undefined, options) as ServicePage<T>;
  }
}

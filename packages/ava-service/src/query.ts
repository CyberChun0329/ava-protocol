import { DatabaseSync } from 'node:sqlite';
import { randomUUID } from 'node:crypto';
import { decodeEventLog, keccak256, stringToHex, type Abi, type Address, type Hex, type PublicClient } from 'viem';
import { correctionsAbi } from '@ava-protocol/sdk';

import type { QueryEvent, QueryHealth } from '@ava-protocol/sdk';
export type { QueryEvent, QueryHealth } from '@ava-protocol/sdk';

export interface QueryOptions {
  client: PublicClient;
  databasePath: string;
  /** indexedArgs is startup tuning, excluded from decoder identity; omitting it later retains existing indexes. */
  sources: Record<string, { address: Address; abi: Abi; indexedArgs?: readonly string[] }>;
  startBlock?: bigint;
  confirmations?: number;
  syncBatchSize?: number;
}
export interface EventFilter {
  source?: string;
  expectedSourceAddress?: Address;
  event?: string;
  appId?: Hex;
  fromBlock?: bigint;
  after?: string;
  limit?: number;
  arg?: { name: string; value: string };
  before?: { blockNumber: bigint; logIndex: number };
  order?: 'asc' | 'desc';
  at?: { blockNumber: bigint; blockHash: Hex };
}
export class QueryCursorError extends Error {}
export class QueryFilterError extends Error {}
type Row = Record<string, string | number>;
const json = (value: unknown): string => JSON.stringify(value, (_, v) => typeof v === 'bigint' ? v.toString() : v);
const height = (value: bigint): string => value.toString().padStart(78, '0');
const appIndexSql = "CREATE INDEX IF NOT EXISTS q_events_app_order ON q_events(lower(json_extract(args, '$.appId')), height, log_index)";
const argumentName = /^[A-Za-z_][A-Za-z0-9_]{0,99}$/;
// The identifier is ABI-validated before interpolation; values remain bound parameters.
const scalarSql = (name: string) => `CASE json_type(args, '$.${name}') WHEN 'true' THEN 'true' WHEN 'false' THEN 'false' ELSE CAST(json_extract(args, '$.${name}') AS TEXT) END`;
function requireScalarArgument(abi: Abi | undefined, name: string, event?: string): void {
  const events = abi?.filter(item => item.type === 'event' && (event === undefined || item.name === event));
  const inputs = events?.flatMap(item => item.type === 'event' ? item.inputs.filter(input => input.name === name) : []);
  if (!argumentName.test(name) || !inputs?.length
    || events?.some(item => item.type === 'event' && item.inputs.filter(input => input.name === name).length > 1)
    || (event !== undefined && events?.some(item => item.type === 'event' && item.inputs.filter(input => input.name === name).length !== 1))
    || inputs.some(input => !/^(u?int([0-9]+)?|bytes([0-9]+)?|address|bool|string)$/.test(input.type))
    || new Set(inputs.map(input => input.type)).size !== 1) throw new QueryFilterError('unknown or ambiguous scalar event argument');
}
function stable(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => [k, stable(v)]));
  return value;
}
function pageLimit(value = 50): number {
  if (!Number.isSafeInteger(value) || value < 1) throw new Error('limit must be a positive integer');
  return Math.min(value, 100);
}

/** A local event index; event history never grants live execution authority. */
export class AvaQuery {
  private readonly db: DatabaseSync;
  private readonly client: PublicClient;
  private readonly sources: QueryOptions['sources'];
  private readonly sourcesByAddress: Map<string, [string, QueryOptions['sources'][string]]>;
  private readonly startBlock: bigint;
  private readonly confirmations: number;
  private readonly syncBatchSize: number;
  private readonly argumentIndexSql: string[];
  private status: QueryHealth['status'] = 'not_synced';
  private error?: string;
  private headBlock?: string;
  private targetBlock?: string;
  private lastSyncAt?: string;
  private syncing?: Promise<QueryHealth>;

  constructor(options: QueryOptions) {
    this.client = options.client;
    this.startBlock = options.startBlock ?? 0n;
    this.confirmations = options.confirmations ?? 1;
    this.syncBatchSize = options.syncBatchSize ?? 16;
    if (!Number.isSafeInteger(this.syncBatchSize) || this.syncBatchSize < 1 || this.syncBatchSize > 100) throw new Error('syncBatchSize must be an integer between 1 and 100');
    if (this.startBlock < 0n || !Number.isSafeInteger(this.confirmations) || this.confirmations < 1) throw new Error('invalid startBlock or confirmations');
    this.sources = Object.fromEntries(Object.entries(options.sources).map(([name, source]) => [name, {
      address: source.address.toLowerCase() as Address, abi: source.abi.filter(item => item.type === 'event'),
    }]));
    const addresses = Object.values(this.sources).map(s => s.address);
    if (!addresses.length || new Set(addresses).size !== addresses.length) throw new Error('sources require distinct contract addresses');
    this.sourcesByAddress = new Map(Object.entries(this.sources).map(([name, source]) => [source.address, [name, source]]));
    this.argumentIndexSql = Object.entries(options.sources).flatMap(([name, source]) => [...new Set(source.indexedArgs ?? [])].map(arg => {
      requireScalarArgument(this.sources[name]!.abi, arg);
      const id = keccak256(stringToHex(json([name, arg]))).slice(2);
      return `CREATE INDEX IF NOT EXISTS q_events_arg_${id} ON q_events(${scalarSql(arg)}, height, log_index) WHERE source = '${name.replaceAll("'", "''")}'`;
    }));
    const config = json(stable({ startBlock: this.startBlock.toString(), confirmations: this.confirmations, sources: this.sources }));
    this.db = new DatabaseSync(options.databasePath);
    this.db.exec(`
      PRAGMA journal_mode=WAL;
      CREATE TABLE IF NOT EXISTS q_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS q_blocks (height TEXT PRIMARY KEY, hash TEXT NOT NULL, parent_hash TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS q_events (
        height TEXT NOT NULL, log_index INTEGER NOT NULL, source TEXT NOT NULL, address TEXT NOT NULL,
        event TEXT NOT NULL, args TEXT NOT NULL, transaction_hash TEXT NOT NULL,
        PRIMARY KEY (height, log_index, source)
      );
    `);
    const prior = this.meta('config');
    if (prior !== undefined && prior !== config) {
      let compatible = false;
      try {
        const legacy = JSON.parse(prior);
        // Older metadata included functions and errors, which never decode index events.
        // Retain every other field so a source or decoder change still fails exact equality.
        for (const source of Object.values(legacy.sources) as { abi: Abi }[]) {
          if (!Array.isArray(source.abi) || source.abi.some(item => !item || typeof item !== 'object'
              || !['constructor', 'error', 'event', 'fallback', 'function', 'receive'].includes(item.type))) {
            throw new Error('invalid legacy source ABI');
          }
          source.abi = source.abi.filter(item => item.type === 'event');
        }
        compatible = json(stable(legacy)) === config;
      } catch { /* Malformed metadata must remain a configuration mismatch. */ }
      if (!compatible) {
        this.db.close();
        throw new Error('query database configuration mismatch');
      }
    }
    // Existing history needs the index immediately; bulk-load a fresh index once at sync completion.
    if (this.db.prepare('SELECT 1 FROM q_events LIMIT 1').get()) {
      this.db.exec(appIndexSql);
      for (const sql of this.argumentIndexSql) this.db.exec(sql);
    }
    if (prior !== config) this.setMeta('config', config);
    if (this.meta('indexId') === undefined) this.setMeta('indexId', randomUUID());
    this.lastSyncAt = this.meta('lastSyncAt');
  }

  sync(): Promise<QueryHealth> {
    if (!this.syncing) this.syncing = this.synchronize().finally(() => { this.syncing = undefined; });
    return this.syncing;
  }

  private async synchronize(): Promise<QueryHealth> {
    try {
      const [chainResult, genesisResult, headResult] = await Promise.allSettled([
        this.client.getChainId(), this.client.getBlock({ blockNumber: 0n }), this.client.getBlockNumber({ cacheTime: 0 }),
      ]);
      if (chainResult.status === 'rejected') throw chainResult.reason;
      if (genesisResult.status === 'rejected') throw genesisResult.reason;
      if (headResult.status === 'rejected') throw headResult.reason;
      const chainId = chainResult.value, genesis = genesisResult.value, head = headResult.value;
      if (!genesis.hash) throw new Error('genesis hash unavailable');
      const identity = json({ chainId, genesisHash: genesis.hash });
      const priorIdentity = this.meta('chain');
      if (priorIdentity !== undefined && priorIdentity !== identity) throw new Error('query database chain identity mismatch');
      if (priorIdentity === undefined) this.setMeta('chain', identity);
      this.headBlock = head.toString();
      const target = head - BigInt(this.confirmations - 1);
      this.targetBlock = target >= 0n ? target.toString() : undefined;
      let tip = this.tip();
      let ancestor = tip ? BigInt(String(tip.height)) : this.startBlock - 1n;
      if (ancestor > target) ancestor = target;
      while (ancestor >= this.startBlock) {
        const saved = this.db.prepare('SELECT hash FROM q_blocks WHERE height = ?').get(height(ancestor)) as Row | undefined;
        const canonical = await this.client.getBlock({ blockNumber: ancestor });
        if (saved && saved.hash === canonical.hash) break;
        ancestor--;
      }
      this.transaction(() => {
        this.db.prepare('DELETE FROM q_events WHERE height > ?').run(height(ancestor < 0n ? 0n : ancestor));
        this.db.prepare('DELETE FROM q_blocks WHERE height > ?').run(height(ancestor < 0n ? 0n : ancestor));
        // startBlock zero has no predecessor row to preserve.
        if (ancestor < 0n) { this.db.exec('DELETE FROM q_events; DELETE FROM q_blocks;'); }
      });
      tip = this.tip();
      let previousHash = tip?.hash;
      const insertBlock = this.db.prepare('INSERT INTO q_blocks VALUES (?, ?, ?)');
      const insertEvent = this.db.prepare('INSERT INTO q_events VALUES (?, ?, ?, ?, ?, ?, ?)');
      for (let first = ancestor + 1n > this.startBlock ? ancestor + 1n : this.startBlock; first <= target;) {
        const numbers: bigint[] = [];
        for (let number = first; number <= target && numbers.length < this.syncBatchSize; number++) numbers.push(number);
        // No writes until every read in this bounded window has settled.
        const fetched = await Promise.allSettled(numbers.map(async number => {
          const block = await this.client.getBlock({ blockNumber: number });
          if (!block.hash || block.number !== number) throw new Error('inconsistent RPC block identity');
          const logs = await this.client.getLogs({ address: Object.values(this.sources).map(s => s.address), blockHash: block.hash });
          const decoded: Omit<QueryEvent, 'blockNumber' | 'blockHash' | 'parentHash'>[] = [];
          for (const log of logs) {
            if (log.blockHash !== block.hash || log.blockNumber !== number || log.logIndex === null || !log.transactionHash) throw new Error('inconsistent RPC log identity');
            const [sourceName, source] = this.sourcesByAddress.get(log.address.toLowerCase()) ?? [];
            if (!source) throw new Error('unexpected event source');
            try {
              const result = decodeEventLog({ abi: source.abi, data: log.data, topics: log.topics, strict: true });
              const args = JSON.parse(json(result.args ?? {})) as Record<string, unknown>;
              if (sourceName === 'corrections' && result.eventName === 'CaseAccepted') {
                // This event omits appId. Only the fixed registry may supply case IDs and attribution.
                const caseId = BigInt(String(args.caseId));
                const record = await this.client.readContract({ address: source.address, abi: correctionsAbi,
                  functionName: 'getCase', args: [caseId], blockHash: block.hash, requireCanonical: true });
                if (record.id !== caseId) throw new Error('inconsistent correction case identity');
                args.appId = record.input.appId;
              }
              decoded.push({ source: sourceName!, address: source.address, event: result.eventName!, args, transactionHash: log.transactionHash, logIndex: log.logIndex });
            } catch (error) {
              // ABIs may intentionally omit unrelated public events.
              if (error instanceof Error && error.name === 'AbiEventSignatureNotFoundError') continue;
              throw error;
            }
          }
          return { number, block, decoded };
        }));
        const batch = fetched.map(result => {
          if (result.status === 'rejected') throw result.reason;
          return result.value;
        });
        let parent = previousHash;
        for (const item of batch) {
          if (parent && item.block.parentHash !== parent) throw new Error('chain changed during sync; retry required');
          parent = item.block.hash!;
        }
        const last = batch.at(-1)!;
        // A canonical descendant plus contiguous parent hashes anchors the whole window.
        const checked = await this.client.getBlock({ blockNumber: last.number });
        if (checked.hash !== last.block.hash) throw new Error('chain changed while fetching logs; retry required');
        this.transaction(() => {
          for (const { number, block, decoded } of batch) {
            insertBlock.run(height(number), block.hash!, block.parentHash);
            for (const event of decoded) insertEvent.run(height(number), event.logIndex, event.source, event.address, event.event, json(event.args), event.transactionHash);
          }
        });
        previousHash = parent;
        first = last.number + 1n;
      }
      const indexed = this.tip();
      if (indexed) {
        const checked = await this.client.getBlock({ blockNumber: BigInt(String(indexed.height)) });
        if (checked.hash !== indexed.hash) throw new Error('chain changed before sync completed; retry required');
      }
      this.db.exec(appIndexSql);
      for (const sql of this.argumentIndexSql) this.db.exec(sql);
      const lastSyncAt = new Date().toISOString();
      const checkpoint = json(indexed ? { height: indexed.height, hash: indexed.hash } : null);
      // Partial windows may already be durable after a failed sync. Only a successful
      // completion advances this marker, including the first sync of an older database.
      if (this.meta('lastSyncCheckpoint') !== checkpoint) {
        this.transaction(() => {
          this.setMeta('lastSyncCheckpoint', checkpoint);
          this.setMeta('lastSyncAt', lastSyncAt);
        });
      }
      this.lastSyncAt = lastSyncAt;
      this.status = 'synced';
      this.error = undefined;
      return this.health();
    } catch (error) {
      this.status = 'unavailable';
      this.error = 'chain_or_query_unavailable';
      throw error;
    }
  }

  events(filter: EventFilter = {}): { items: QueryEvent[]; nextCursor?: string } {
    const limit = pageLimit(filter.limit);
    if (filter.fromBlock !== undefined && filter.fromBlock < 0n) throw new Error('fromBlock must be nonnegative');
    const order = filter.order ?? 'asc';
    if (order !== 'asc' && order !== 'desc') throw new QueryFilterError('invalid event order');
    const source = filter.source !== undefined && Object.hasOwn(this.sources, filter.source) ? this.sources[filter.source] : undefined;
    if (filter.expectedSourceAddress !== undefined) {
      if (!/^0x[0-9a-fA-F]{40}$/.test(filter.expectedSourceAddress) || !source
        || source.address !== filter.expectedSourceAddress.toLowerCase()) throw new QueryFilterError('event source mismatch');
      if (filter.event !== undefined && !source.abi.some(item => item.type === 'event' && item.name === filter.event)) {
        throw new QueryFilterError('unknown source event');
      }
    }
    if (filter.arg !== undefined) {
      const arg = filter.arg;
      requireScalarArgument(source?.abi, arg.name, filter.event);
      if (typeof arg.value !== 'string' || arg.value.length > 1024) {
        throw new QueryFilterError('unknown scalar event argument');
      }
    }
    if (filter.before !== undefined && (filter.before.blockNumber < 0n
      || !Number.isSafeInteger(filter.before.logIndex) || filter.before.logIndex < 0)) throw new QueryFilterError('invalid event position');
    if (filter.at !== undefined) {
      const at = filter.at;
      if (at.blockNumber < 0n || !/^0x[0-9a-fA-F]{64}$/.test(at.blockHash)) throw new QueryFilterError('invalid event snapshot');
      const tip = this.tip();
      const block = this.db.prepare('SELECT hash FROM q_blocks WHERE height = ?').get(height(at.blockNumber)) as Row | undefined;
      if (this.status !== 'synced' || !tip || BigInt(String(tip.height)) < at.blockNumber
        || block?.hash !== at.blockHash.toLowerCase()) throw new Error('event snapshot unavailable');
    }
    const appId = filter.appId?.toLowerCase();
    const identity: unknown[] = [filter.source ?? null, filter.event ?? null, appId ?? null, filter.fromBlock?.toString() ?? null];
    // Preserve existing ascending cursor fingerprints. A snapshot is a per-request bound,
    // while the cursor's own canonical hash remains its continuation anchor.
    if (filter.expectedSourceAddress !== undefined || filter.arg !== undefined || filter.before !== undefined || order !== 'asc') {
      identity.push([filter.expectedSourceAddress?.toLowerCase() ?? null, filter.arg ? [filter.arg.name, filter.arg.value] : null,
        filter.before ? [filter.before.blockNumber.toString(), filter.before.logIndex] : null, order]);
    }
    const fingerprint = keccak256(stringToHex(json(identity)));
    const where: string[] = [];
    const values: (string | number)[] = [];
    if (filter.source !== undefined) { where.push('e.source = ?'); values.push(filter.source); }
    if (filter.event !== undefined) { where.push('e.event = ?'); values.push(filter.event); }
    if (appId !== undefined) { where.push("lower(json_extract(e.args, '$.appId')) = ?"); values.push(appId); }
    if (filter.fromBlock !== undefined) { where.push('e.height >= ?'); values.push(height(filter.fromBlock)); }
    if (filter.arg !== undefined) {
      where.push(`${scalarSql(filter.arg.name)} = ?`);
      values.push(filter.arg.value);
    }
    if (filter.before !== undefined) {
      where.push('(e.height < ? OR (e.height = ? AND e.log_index < ?))');
      values.push(height(filter.before.blockNumber), height(filter.before.blockNumber), filter.before.logIndex);
    }
    if (filter.at !== undefined) { where.push('e.height <= ?'); values.push(height(filter.at.blockNumber)); }
    if (filter.after !== undefined) {
      try {
        if (filter.after.length > 4096) throw new Error();
        const cursor = JSON.parse(Buffer.from(filter.after, 'base64url').toString()) as { v: number; b: string; h: string; l: number; f: string; i: string };
        if (cursor.v !== 1 || !/^\d+$/.test(cursor.b) || !Number.isSafeInteger(cursor.l) || cursor.l < 0 || cursor.f !== fingerprint || cursor.i !== this.meta('indexId')) throw new Error();
        const canonical = this.db.prepare('SELECT hash FROM q_blocks WHERE height = ?').get(height(BigInt(cursor.b))) as Row | undefined;
        if (!canonical || canonical.hash !== cursor.h) throw new Error();
        const event = this.db.prepare(`SELECT 1 FROM q_events e WHERE ${where.length ? `${where.join(' AND ')} AND ` : ''}e.height = ? AND e.log_index = ?`).get(...values, height(BigInt(cursor.b)), cursor.l);
        if (!event) throw new Error();
        const compare = order === 'desc' ? '<' : '>';
        where.push(`e.height ${compare}= ?`);
        values.push(height(BigInt(cursor.b)));
        where.push(`(e.height ${compare} ? OR (e.height = ? AND e.log_index ${compare} ?))`);
        values.push(height(BigInt(cursor.b)), height(BigInt(cursor.b)), cursor.l);
      } catch { throw new QueryCursorError('invalid or orphaned event cursor'); }
    }
    const direction = order === 'desc' ? 'DESC' : 'ASC';
    const rows = this.db.prepare(`SELECT e.*, b.hash, b.parent_hash FROM q_events e JOIN q_blocks b ON b.height = e.height ${where.length ? `WHERE ${where.join(' AND ')}` : ''} ORDER BY e.height ${direction}, e.log_index ${direction} LIMIT ?`).all(...values, limit + 1) as Row[];
    const more = rows.length > limit;
    const items: QueryEvent[] = rows.slice(0, limit).map(row => ({ source: String(row.source), address: row.address as Address, event: String(row.event), args: JSON.parse(String(row.args)), blockNumber: BigInt(String(row.height)).toString(), blockHash: row.hash as Hex, parentHash: row.parent_hash as Hex, transactionHash: row.transaction_hash as Hex, logIndex: Number(row.log_index) }));
    const last = items.at(-1);
    return { items, ...(more && last ? { nextCursor: Buffer.from(json({ v: 1, b: last.blockNumber, h: last.blockHash, l: last.logIndex, f: fingerprint, i: this.meta('indexId') })).toString('base64url') } : {}) };
  }

  ids(kind: 'objects' | 'recognitions' | 'requests', appId?: Hex, limit?: number): string[] {
    return this.idsPage(kind, { appId, limit }).items;
  }

  idsPage(kind: 'objects' | 'recognitions' | 'requests', filter: Pick<EventFilter, 'appId' | 'limit' | 'after'> = {}):
    { items: string[]; nextCursor?: string } {
    const selected = { objects: ['GovernedObjectRegistered', 'id'], recognitions: ['RecognisedStateFormed', 'id'], requests: ['RequestCreated', 'requestId'] }[kind];
    if (!selected) throw new Error('unknown id kind');
    const source = kind === 'requests' ? 'requests' : 'kernel';
    const page = this.events({ ...filter, source, event: selected[0] });
    return { items: page.items.map(item => String(item.args[selected[1]!])),
      ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}) };
  }

  health(): QueryHealth {
    const tip = this.tip();
    const chain = this.meta('chain');
    return { status: this.status, ...(chain ? JSON.parse(chain) : {}), confirmations: this.confirmations, startBlock: this.startBlock.toString(),
      ...(tip ? { indexedBlock: BigInt(String(tip.height)).toString(), indexedBlockHash: tip.hash as Hex } : {}),
      ...(this.headBlock !== undefined ? { headBlock: this.headBlock } : {}),
      ...(this.targetBlock !== undefined ? { confirmationTarget: this.targetBlock } : {}),
      ...(this.lastSyncAt ? { lastSyncAt: this.lastSyncAt } : {}),
      ...(this.error ? { error: this.error } : {}),
    };
  }
  close(): void { this.db.close(); }
  private tip(): Row | undefined { return this.db.prepare('SELECT * FROM q_blocks ORDER BY height DESC LIMIT 1').get() as Row | undefined; }
  private meta(key: string): string | undefined { return (this.db.prepare('SELECT value FROM q_meta WHERE key = ?').get(key) as Row | undefined)?.value as string | undefined; }
  private setMeta(key: string, value: string): void { this.db.prepare('INSERT INTO q_meta VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').run(key, value); }
  private transaction(action: () => void): void {
    this.db.exec('BEGIN IMMEDIATE');
    try { action(); this.db.exec('COMMIT'); } catch (error) { this.db.exec('ROLLBACK'); throw error; }
  }
}

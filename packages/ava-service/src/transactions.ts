import { DatabaseSync } from 'node:sqlite';
import { getAddress, isAddress, keccak256, parseTransaction, recoverTransactionAddress, serializeTransaction,
  TransactionNotFoundError, TransactionReceiptNotFoundError, zeroAddress,
  type Address, type Hex, type PublicClient, type TransactionSerialized } from 'viem';

import type { TransactionRecord } from '@ava-protocol/sdk';
import { WorkQueue } from './work-queue.ts';
export type { TransactionRecord } from '@ava-protocol/sdk';

export class TransactionValidationError extends Error {}
export class TransactionConflictError extends Error {}

type StoredTransaction = {
  hash: Hex; raw: Hex; sender: Address; target: Address; nonce: string;
  status: TransactionRecord['status']; block_number: string | null; block_hash: Hex | null;
  confirmations: number; error: string | null; updated_at: string;
};
type Context = { chainId: number; genesisHash: Hex; targets: string[]; confirmations: number };

/** Local-chain relay for caller-signed bytes. It never signs or changes a transaction. */
export class AvaTransactions {
  private readonly client: PublicClient;
  private readonly db: DatabaseSync;
  private readonly targets: string[];
  private readonly requiredConfirmations: number;
  private readonly operations: WorkQueue;

  constructor(options: { client: PublicClient; databasePath: string; allowedTargets: Address[]; confirmations?: number;
    concurrency?: number; maxPending?: number }) {
    this.operations = new WorkQueue(options.concurrency ?? 8, options.maxPending ?? 64);
    this.client = options.client;
    this.requiredConfirmations = options.confirmations ?? 1;
    if (!Number.isSafeInteger(this.requiredConfirmations) || this.requiredConfirmations < 1) {
      throw new TransactionValidationError('confirmations must be a positive safe integer');
    }
    if (!options.allowedTargets.length || options.allowedTargets.some(target =>
      !isAddress(target) || target.toLowerCase() === zeroAddress)) {
      throw new TransactionValidationError('allowedTargets must contain nonzero contract addresses');
    }
    this.targets = [...new Set(options.allowedTargets.map(target => getAddress(target).toLowerCase()))].sort();
    this.db = new DatabaseSync(options.databasePath);
    this.db.exec(`
      PRAGMA busy_timeout = 5000;
      CREATE TABLE IF NOT EXISTS t_meta (id TEXT PRIMARY KEY, value TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS t_transactions (
        hash TEXT PRIMARY KEY, raw TEXT NOT NULL, sender TEXT NOT NULL,
        target TEXT NOT NULL, nonce TEXT NOT NULL, status TEXT NOT NULL,
        block_number TEXT, block_hash TEXT, confirmations INTEGER NOT NULL DEFAULT 0,
        error TEXT, updated_at TEXT NOT NULL, UNIQUE(sender, nonce)
      );
      CREATE TABLE IF NOT EXISTS t_keys (key TEXT PRIMARY KEY, hash TEXT NOT NULL);
    `);
    const context = this.context();
    if (context && (JSON.stringify(context.targets) !== JSON.stringify(this.targets)
      || context.confirmations !== this.requiredConfirmations)) {
      this.db.close();
      throw new TransactionValidationError('Database target set or confirmation policy does not match');
    }
  }

  async submit(idempotencyKey: string, serializedTransaction: Hex, options: { signal?: AbortSignal } = {}): Promise<TransactionRecord> {
    this.validateKey(idempotencyKey);
    const raw = this.signedBytes(serializedTransaction);
    const hash = keccak256(raw);
    return this.forTransaction(hash, () => this.submitSigned(idempotencyKey, raw, hash), options.signal);
  }

  /** Explicitly resend only an existing identity's original signed bytes. */
  async recover(idempotencyKey: string, serializedTransaction: Hex, options: { signal?: AbortSignal } = {}): Promise<TransactionRecord> {
    this.validateKey(idempotencyKey);
    const raw = this.signedBytes(serializedTransaction);
    const hash = keccak256(raw);
    return this.forTransaction(hash, async () => {
      const existing = this.lookup(idempotencyKey);
      if (!existing) throw new TransactionValidationError('Recovery requires an existing transaction key');
      if (existing.raw !== raw || existing.hash !== hash) {
        throw new TransactionConflictError('Recovery requires the original signed bytes and transaction hash');
      }
      try {
        await this.ensureContext();
      } catch (error) {
        if (error instanceof TransactionValidationError) throw error;
        this.uncertain(hash, 'Chain verification unavailable');
        return this.record(idempotencyKey, this.lookup(idempotencyKey)!);
      }
      const observed = await this.refresh(idempotencyKey, existing);
      // pending may already have a canonical receipt below the required confirmation depth.
      // Its blockHash keeps that mined transaction on the observation path without rebroadcast.
      if (observed.status === 'confirmed' || observed.status === 'reverted' || observed.blockHash) return observed;
      const code = await this.client.getCode({ address: existing.target });
      if (!code || code === '0x') throw new TransactionValidationError('Transaction target is not a deployed contract');
      return this.broadcast(idempotencyKey, existing);
    }, options.signal);
  }

  private async submitSigned(idempotencyKey: string, raw: Hex, hash: Hex): Promise<TransactionRecord> {
    const existing = this.lookup(idempotencyKey);
    if (existing && existing.raw !== raw) {
      throw new TransactionConflictError('Idempotency key already belongs to different signed bytes');
    }
    try {
      await this.ensureContext();
    } catch (error) {
      if (!existing || error instanceof TransactionValidationError) throw error;
      this.uncertain(existing.hash, 'Chain verification unavailable');
      return this.record(idempotencyKey, this.lookup(idempotencyKey)!);
    }
    if (existing) {
      return this.refresh(idempotencyKey, existing);
    }
    const same = this.db.prepare('SELECT * FROM t_transactions WHERE hash = ?').get(hash) as StoredTransaction | undefined;
    if (same) {
      this.saveAlias(idempotencyKey, same);
      return this.refresh(idempotencyKey, same);
    }
    let parsed: ReturnType<typeof parseTransaction>;
    let from: Address;
    try {
      parsed = parseTransaction(raw);
      if (!['legacy', 'eip2930', 'eip1559'].includes(parsed.type!)) {
        throw new TransactionValidationError('Only legacy, EIP-2930 and EIP-1559 signed calls are supported');
      }
      // Ethereum requires a low-s signature. Recovery alone also accepts high-s.
      if (!parsed.r || !parsed.s || BigInt(parsed.s) > 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0n
        || serializeTransaction(parsed, { r: parsed.r, s: parsed.s, v: parsed.v!, yParity: parsed.yParity! }).toLowerCase() !== raw) {
        throw new Error('Noncanonical signature or encoding');
      }
      from = await recoverTransactionAddress({ serializedTransaction: raw as TransactionSerialized });
    } catch (error) {
      if (error instanceof TransactionValidationError) throw error;
      throw new TransactionValidationError('Transaction must contain a valid recoverable signature');
    }
    if (parsed.chainId !== 31337) throw new TransactionValidationError('Signed transaction must be protected for local chain 31337');
    if (!parsed.to || !isAddress(parsed.to) || !this.targets.includes(parsed.to.toLowerCase())) {
      throw new TransactionValidationError('Contract creation and targets outside allowedTargets are forbidden');
    }
    if (!Number.isSafeInteger(parsed.nonce) || parsed.nonce! < 0) {
      throw new TransactionValidationError('Transaction nonce is invalid');
    }
    const to = getAddress(parsed.to);
    const code = await this.client.getCode({ address: to });
    if (!code || code === '0x') throw new TransactionValidationError('Transaction target is not a deployed contract');
    const row: StoredTransaction = { hash, raw, sender: getAddress(from), target: to,
      nonce: String(parsed.nonce), status: 'unknown', block_number: null, block_hash: null,
      confirmations: 0, error: null, updated_at: new Date().toISOString() };
    // Commit identity and exact bytes before crossing the uncertain RPC boundary.
    const inserted = this.persist(idempotencyKey, row);
    if (!inserted) return this.refresh(idempotencyKey, this.lookup(idempotencyKey)!);
    return this.broadcast(idempotencyKey, row);
  }

  private async broadcast(idempotencyKey: string, row: StoredTransaction): Promise<TransactionRecord> {
    try {
      const returnedHash = await this.client.sendRawTransaction({ serializedTransaction: row.raw });
      if (returnedHash.toLowerCase() !== row.hash) throw new Error('RPC returned a different transaction hash');
      this.update(row.hash, { status: 'pending', error: null });
    } catch {
      this.update(row.hash, { status: 'unknown', error: 'Broadcast outcome unknown' });
      return this.record(idempotencyKey, this.lookup(idempotencyKey)!);
    }
    return this.refresh(idempotencyKey, this.lookup(idempotencyKey)!);
  }

  async get(idempotencyKey: string, options: { signal?: AbortSignal } = {}): Promise<TransactionRecord | undefined> {
    this.validateKey(idempotencyKey);
    const row = this.lookup(idempotencyKey);
    if (!row) return undefined;
    return this.forTransaction(row.hash, async () => {
      const current = this.lookup(idempotencyKey)!;
      try {
        await this.ensureContext();
      } catch (error) {
        if (error instanceof TransactionValidationError) throw error;
        this.uncertain(current.hash, 'Chain verification unavailable');
        return this.record(idempotencyKey, this.lookup(idempotencyKey)!);
      }
      return this.refresh(idempotencyKey, current);
    }, options.signal);
  }

  /** One owner orders every status write for a hash, including aliases and broadcast replies. */
  private async forTransaction<T>(hash: Hex, operation: () => Promise<T>, signal?: AbortSignal): Promise<T> {
    return this.operations.run(operation, { key: hash, signal });
  }

  drain(): Promise<void> { return this.operations.idle(); }
  close(): void { this.db.close(); }

  private validateKey(key: string): void {
    if (typeof key !== 'string' || !key.trim() || Buffer.byteLength(key) > 128 || /[\x00-\x1f\x7f]/.test(key)) {
      throw new TransactionValidationError('Idempotency key must be nonempty, at most 128 UTF-8 bytes, without control characters');
    }
  }

  private signedBytes(serializedTransaction: Hex): Hex {
    if (typeof serializedTransaction !== 'string' || !/^0x(?:[0-9a-fA-F]{2})+$/.test(serializedTransaction)
      || serializedTransaction.length > 2 + 128 * 1024 * 2) {
      throw new TransactionValidationError('Invalid signed transaction or payload exceeds 128 KiB');
    }
    return serializedTransaction.toLowerCase() as Hex;
  }

  private context(): Context | undefined {
    const row = this.db.prepare("SELECT value FROM t_meta WHERE id = 'context'").get() as { value: string } | undefined;
    return row ? JSON.parse(row.value) as Context : undefined;
  }

  /** Bind the relay to the chain identity already verified by the service index. */
  bindChain(chainId: number, genesisHash: Hex): void {
    if (chainId !== 31337 || !/^0x[0-9a-fA-F]{64}$/.test(genesisHash)) {
      throw new TransactionValidationError('Invalid local chain identity');
    }
    const current: Context = { chainId, genesisHash, targets: this.targets, confirmations: this.requiredConfirmations };
    this.db.prepare("INSERT OR IGNORE INTO t_meta (id, value) VALUES ('context', ?)").run(JSON.stringify(current));
    if (JSON.stringify(this.context()) !== JSON.stringify(current)) {
      throw new TransactionValidationError('Database belongs to a different chain genesis, target set, or confirmation policy');
    }
  }

  private async ensureContext(): Promise<void> {
    const [chainResult, genesisResult] = await Promise.allSettled([
      this.client.getChainId(), this.client.getBlock({ blockNumber: 0n }),
    ]);
    if (chainResult.status === 'rejected') throw chainResult.reason;
    const chainId = chainResult.value;
    if (chainId !== 31337) throw new TransactionValidationError('AvaTransactions only supports local chain 31337');
    if (genesisResult.status === 'rejected') throw genesisResult.reason;
    const genesis = genesisResult.value;
    if (!genesis.hash) throw new TransactionValidationError('Local chain genesis hash is unavailable');
    this.bindChain(chainId, genesis.hash);
  }

  private lookup(key: string): StoredTransaction | undefined {
    return this.db.prepare('SELECT t.* FROM t_transactions t JOIN t_keys k ON t.hash = k.hash WHERE k.key = ?')
      .get(key) as StoredTransaction | undefined;
  }

  private saveAlias(key: string, row: StoredTransaction): void {
    this.db.prepare('INSERT OR IGNORE INTO t_keys (key, hash) VALUES (?, ?)').run(key, row.hash);
    if (this.lookup(key)?.raw !== row.raw) throw new TransactionConflictError('Idempotency key already belongs to different signed bytes');
  }

  private persist(key: string, row: StoredTransaction): boolean {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const existing = this.lookup(key);
      if (existing && existing.raw !== row.raw) throw new TransactionConflictError('Idempotency key already belongs to different signed bytes');
      const sameNonce = this.db.prepare('SELECT * FROM t_transactions WHERE sender = ? AND nonce = ?')
        .get(row.sender, row.nonce) as StoredTransaction | undefined;
      if (sameNonce && sameNonce.raw !== row.raw) throw new TransactionConflictError('Sender nonce already belongs to different signed bytes');
      const inserted = this.db.prepare(`INSERT OR IGNORE INTO t_transactions
        (hash, raw, sender, target, nonce, status, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`)
        .run(row.hash, row.raw, row.sender, row.target, row.nonce, row.status, row.updated_at).changes;
      this.saveAlias(key, row);
      this.db.exec('COMMIT');
      return inserted === 1;
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }

  private async refresh(key: string, row: StoredTransaction): Promise<TransactionRecord> {
    try {
      const receipt = await this.client.getTransactionReceipt({ hash: row.hash });
      if (receipt.status !== 'success' && receipt.status !== 'reverted') {
        throw new Error('Receipt execution status unavailable');
      }
      const [tipResult, canonicalResult] = await Promise.allSettled([
        this.client.getBlockNumber({ cacheTime: 0 }), this.client.getBlock({ blockNumber: receipt.blockNumber }),
      ]);
      if (tipResult.status === 'rejected') throw tipResult.reason;
      if (canonicalResult.status === 'rejected') throw canonicalResult.reason;
      const tip = tipResult.value;
      const canonical = canonicalResult.value;
      if (receipt.transactionHash.toLowerCase() !== row.hash || canonical.hash !== receipt.blockHash || tip < receipt.blockNumber) {
        this.uncertain(row.hash, 'Receipt is not on the current canonical chain', 'pending');
      } else {
        const depth = tip - receipt.blockNumber + 1n;
        const confirmations = Number(depth > BigInt(Number.MAX_SAFE_INTEGER) ? BigInt(Number.MAX_SAFE_INTEGER) : depth);
        const settled = confirmations >= this.requiredConfirmations;
        this.update(row.hash, { status: settled ? (receipt.status === 'success' ? 'confirmed' : 'reverted') : 'pending',
          block_number: receipt.blockNumber.toString(), block_hash: receipt.blockHash, confirmations,
          error: receipt.status === 'reverted' ? 'Transaction execution reverted' : null });
      }
    } catch (error) {
      if (error instanceof TransactionReceiptNotFoundError) {
        try {
          await this.client.getTransaction({ hash: row.hash });
          this.uncertain(row.hash, 'Transaction has no canonical receipt yet', 'pending');
        } catch (transactionError) {
          this.uncertain(row.hash, transactionError instanceof TransactionNotFoundError
            ? 'Transaction is not currently visible to the node'
            : 'Transaction lookup unavailable');
        }
      } else {
        this.uncertain(row.hash, 'Receipt verification unavailable');
      }
    }
    return this.record(key, this.lookup(key)!);
  }

  private uncertain(hash: Hex, error: string, status: 'unknown' | 'pending' = 'unknown'): void {
    this.update(hash, { status, error, block_number: null, block_hash: null, confirmations: 0 });
  }

  private update(hash: Hex, values: Partial<StoredTransaction>): void {
    const entries = Object.entries({ ...values, updated_at: new Date().toISOString() });
    this.db.prepare(`UPDATE t_transactions SET ${entries.map(([key]) => `${key} = ?`).join(', ')} WHERE hash = ?`)
      .run(...entries.map(([, value]) => value), hash);
  }

  private record(key: string, row: StoredTransaction): TransactionRecord {
    return { key, hash: row.hash, from: row.sender, to: row.target, nonce: row.nonce,
      status: row.status, confirmations: row.confirmations, updatedAt: row.updated_at,
      ...(row.block_number !== null && { blockNumber: row.block_number }),
      ...(row.block_hash !== null && { blockHash: row.block_hash }),
      ...(row.error !== null && { error: row.error }) };
  }
}

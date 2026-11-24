import type { Address, Hex } from 'viem';
import type { AvaSdk } from './index.js';
import type { AvaExtensions } from './extensions.js';

/** JSON serialization preserves record shape and writes bigint values as decimal strings. */
export type JsonWire<T> = T extends bigint ? `${bigint}`
  : T extends object ? { [K in keyof T]: JsonWire<T[K]> } : T;

export interface QueryEvent {
  source: string;
  address: Address;
  event: string;
  args: Record<string, unknown>;
  blockNumber: string;
  blockHash: Hex;
  parentHash: Hex;
  transactionHash: Hex;
  logIndex: number;
}
export interface QueryHealth {
  status: 'not_synced' | 'synced' | 'unavailable';
  chainId?: number;
  genesisHash?: Hex;
  indexedBlock?: string;
  indexedBlockHash?: Hex;
  headBlock?: string;
  confirmationTarget?: string;
  confirmations: number;
  startBlock?: string;
  lastSyncAt?: string;
  error?: string;
}
export type TransactionRecord = {
  key: string;
  hash: Hex;
  from: Address;
  to: Address;
  nonce: string;
  status: 'unknown' | 'pending' | 'confirmed' | 'reverted';
  blockNumber?: string;
  blockHash?: Hex;
  confirmations: number;
  error?: string;
  updatedAt: string;
};

/** A page is observed at its own snapshot; an empty index need not have a block head. */
export interface ServicePage<T> {
  asOf: QueryHealth;
  items: T[];
  nextCursor?: string;
}
export interface ServicePageOptions { limit?: number; after?: string }
export interface EventPosition { blockNumber: string; logIndex: number }
/** Filters on indexed events. `at` requires that canonical block and bounds all rows to it. */
export interface ServiceEventQuery extends ServicePageOptions {
  source?: string;
  expectedSourceAddress?: Address;
  event?: string;
  appId?: Hex;
  fromBlock?: string;
  arg?: { name: string; value: string };
  before?: EventPosition;
  order?: 'asc' | 'desc';
  at?: { blockNumber: string; blockHash: Hex };
}

export type GovernedObjectWire = JsonWire<Awaited<ReturnType<AvaSdk['recognition']>>['object']>;
export type RecognitionWire = JsonWire<Awaited<ReturnType<AvaSdk['recognition']>>>;
export type RequestWire = JsonWire<Awaited<ReturnType<AvaSdk['request']>> & {
  support: Awaited<ReturnType<AvaSdk['support']>>;
}>;
export type CorrectionCaseWire = JsonWire<Awaited<ReturnType<AvaSdk['correctionCase']>>
  | Awaited<ReturnType<AvaExtensions['correctionCase']>>>;

import type { Hex, PublicClient } from 'viem';
import type { ReadPoint } from './index.js';
import { AvaReadError } from './read-errors.js';

/** One point per outer aggregate, never a persistent eligibility cache. */
export async function resolveReadPoint(client: PublicClient, point?: ReadPoint): Promise<ReadPoint> {
  if (point !== undefined) return typeof point === 'bigint' ? point : { ...point };
  try {
    const block = await client.getBlock({ blockTag: 'latest' });
    if (!block.hash || block.number === null) throw new AvaReadError();
    return { blockHash: block.hash, requireCanonical: true };
  } catch { throw new AvaReadError(); }
}

export interface CanonicalSnapshot {
  readonly blockNumber: bigint;
  readonly blockHash: Hex;
  readonly timestamp: bigint;
  readonly point: Readonly<{ blockHash: Hex; requireCanonical: true }>;
}

export class CanonicalSnapshotChanged extends AvaReadError {}

/** Pin an aggregate's reads, then refuse its result if that block lost canonicality.
 * Callback failures retain their existing classification. This never caches eligibility. */
export async function withCanonicalSnapshot<T>(client: PublicClient,
  read: (snapshot: CanonicalSnapshot) => Promise<T>): Promise<T> {
  let snapshot: CanonicalSnapshot;
  try {
    const block = await client.getBlock({ blockTag: 'latest' });
    if (!block.hash || block.number === null || typeof block.timestamp !== 'bigint') throw new AvaReadError();
    snapshot = Object.freeze({ blockNumber: block.number, blockHash: block.hash, timestamp: block.timestamp,
      point: Object.freeze({ blockHash: block.hash, requireCanonical: true as const }) });
  } catch { throw new AvaReadError(); }
  const result = await read(snapshot);
  let currentHash: Hex | null;
  try {
    currentHash = (await client.getBlock({ blockNumber: snapshot.blockNumber })).hash;
    if (!currentHash) throw new AvaReadError();
  } catch { throw new AvaReadError(); }
  if (currentHash !== snapshot.blockHash) throw new CanonicalSnapshotChanged();
  return result;
}

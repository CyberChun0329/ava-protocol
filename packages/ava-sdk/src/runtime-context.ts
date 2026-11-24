import type { Hex, PublicClient } from 'viem';
import type { AvaServiceClient } from './service-client.js';

export interface RuntimeCheckpoint { blockNumber: bigint; blockHash: Hex }
export interface RuntimeContext { chainId: number; genesisHash: Hex; checkpoint: RuntimeCheckpoint }
export class AvaRuntimeError extends Error {
  readonly name = 'AvaRuntimeError';
  constructor(readonly code: 'runtime_mismatch' | 'runtime_unavailable') { super(`AVA runtime: ${code}`); }
}
const hash = (value: unknown): value is Hex => typeof value === 'string' && /^0x[0-9a-fA-F]{64}$/.test(value);
const equalHash = (a: Hex, b: Hex) => a.toLowerCase() === b.toLowerCase();

/** Verify RPC and relay agree at the relay's indexed checkpoint. */
export async function readRuntimeContext(client: PublicClient, remote: Pick<AvaServiceClient, 'health' | 'sync'>,
  expected: { chainId: number; genesisHash?: Hex; checkpoint?: RuntimeCheckpoint },
  options: { synchronize?: boolean; signal?: AbortSignal } = {}): Promise<RuntimeContext> {
  try {
    const chainId = expected.chainId, expectedGenesis = expected.genesisHash;
    const checkpoint = expected.checkpoint && { ...expected.checkpoint };
    const mismatch = () => { throw new AvaRuntimeError('runtime_mismatch'); };
    const unavailable = () => { throw new AvaRuntimeError('runtime_unavailable'); };
    if (!Number.isSafeInteger(chainId) || chainId < 1 || (expectedGenesis !== undefined && !hash(expectedGenesis))
      || (checkpoint && (typeof checkpoint.blockNumber !== 'bigint' || checkpoint.blockNumber < 0n || !hash(checkpoint.blockHash)))) return mismatch();
    const [rpcChain, genesis, initialHead, relay] = await Promise.all([
      client.getChainId(), client.getBlock({ blockNumber: 0n }), client.getBlock({ blockTag: 'latest' }),
      options.synchronize === false ? remote.health({ signal: options.signal }) : remote.sync({ signal: options.signal }),
    ]);
    if (rpcChain !== chainId) return mismatch();
    if (!hash(genesis.hash) || genesis.number !== 0n || !hash(initialHead.hash) || initialHead.number === null) return unavailable();
    if (expectedGenesis && !equalHash(genesis.hash, expectedGenesis)) return mismatch();
    const relayValid = relay && relay.status === 'synced' && typeof relay.chainId === 'number' && Number.isSafeInteger(relay.chainId) && hash(relay.genesisHash)
      && typeof relay.indexedBlock === 'string' && /^(0|[1-9][0-9]*)$/.test(relay.indexedBlock)
      && hash(relay.indexedBlockHash)
      ? { chainId: relay.chainId, genesisHash: relay.genesisHash, indexedBlock: relay.indexedBlock, indexedBlockHash: relay.indexedBlockHash }
      : null;
    const indexed = relayValid ? BigInt(relayValid.indexedBlock) : null;
    const retryHead = (checkpoint && checkpoint.blockNumber > initialHead.number)
      || (relayValid && indexed !== null && relayValid.chainId === chainId && equalHash(relayValid.genesisHash, genesis.hash) && indexed > initialHead.number);
    const head = retryHead ? await client.getBlock({ blockTag: 'latest' }) : initialHead;
    if (!hash(head.hash) || head.number === null) return unavailable();
    if (checkpoint && checkpoint.blockNumber > head.number) return mismatch();
    if (!relayValid || indexed === null) return unavailable();
    if (relayValid.chainId !== chainId || !equalHash(relayValid.genesisHash, genesis.hash)) return mismatch();
    if (indexed > head.number) return unavailable();
    const saved = checkpoint ? await client.getBlock({ blockNumber: checkpoint.blockNumber }) : null;
    if (checkpoint) {
      if (!saved || !hash(saved.hash) || saved.number !== checkpoint.blockNumber) return unavailable();
      if (!equalHash(saved.hash, checkpoint.blockHash)) return mismatch();
      if (indexed < checkpoint.blockNumber) return unavailable();
    }
    const block = saved?.number === indexed ? saved : await client.getBlock({ blockNumber: indexed });
    if (!hash(block.hash) || block.number !== indexed) return unavailable();
    if (!equalHash(block.hash, relayValid.indexedBlockHash)) return mismatch();
    return { chainId, genesisHash: genesis.hash, checkpoint: { blockNumber: indexed, blockHash: block.hash } };
  } catch (error) {
    if (error instanceof AvaRuntimeError) throw error;
    throw new AvaRuntimeError('runtime_unavailable');
  }
}

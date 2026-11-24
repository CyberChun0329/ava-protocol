import { spawn, type ChildProcess } from 'node:child_process';
import {createReadStream} from 'node:fs';
import { once } from 'node:events';
import { chmod, readFile, stat, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { createServer } from 'node:net';
import { createWalletClient, http, type Abi, type Hex, type WalletClient, type Transport } from 'viem';
import { mnemonicToAccount } from 'viem/accounts';
import { foundry } from 'viem/chains';
import { localClient } from '@ava-protocol/sdk';
import {inspectAnvilState} from './anvil-state.js';

const artifactSources: Record<string, string> = {
  DefaultAVACorePolicyBundle: 'DefaultAVACoreRuleModules.sol',
  AVARequestCompensation: 'AVARequestAllocation.sol',
};
export async function artifact(name: string, source = artifactSources[name] ?? `${name}.sol`) {
  return JSON.parse(await readFile(resolve(`.build/out/${source}/${name}.json`), 'utf8')) as {
    abi: Abi; bytecode: { object: Hex;
      linkReferences?: Record<string, Record<string, { start: number; length: number }[]>> } };
}
async function availablePort() {
  const server = createServer();
  await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('No local port');
  await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  return address.port;
}
export async function stopProcess(process: ChildProcess) {
  if (process.exitCode !== null || process.signalCode !== null) return;
  const exited = once(process, 'exit');
  process.kill('SIGTERM');
  await exited;
}
export interface LocalChain {
 process: ChildProcess; rpcUrl: string; client: ReturnType<typeof localClient>;
 wallets: WalletClient<Transport,typeof foundry,ReturnType<typeof mnemonicToAccount>>[];
 close: () => Promise<void>;
}
export async function localChain(accountCount = 6, options: { statePath?: string } = {}): Promise<LocalChain> {
  if (!Number.isSafeInteger(accountCount) || accountCount < 6) {
    throw new RangeError('Local chain accountCount must be an integer of at least 6');
  }
  let genesisTimestamp: bigint | undefined;
  let expectedHead: { number: string; hash: Hex } | undefined;
  const checkpointPath = options.statePath && `${options.statePath}.checkpoint.json`;
  if (options.statePath) {
    let exists = false;
    try {
      await stat(options.statePath);exists = true;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }
    if (exists) {
      try {
        const checkpoint = JSON.parse(await readFile(checkpointPath!, 'utf8'));
        if (checkpoint.version !== 1 || checkpoint.status !== 'saved'
          || typeof checkpoint.head?.number !== 'string' || !/^(0|[1-9][0-9]*)$/.test(checkpoint.head.number)
          || !/^0x[0-9a-fA-F]{64}$/.test(checkpoint.head.hash)) throw new Error();
        const state=await inspectAnvilState(createReadStream(options.statePath),BigInt(checkpoint.head.number));
        if(state.genesisTimestamp===undefined||state.sha256!==checkpoint.sha256)throw new Error();
        genesisTimestamp = state.genesisTimestamp;
        expectedHead = checkpoint.head;
      } catch { throw new Error('Invalid persisted Anvil state checkpoint'); }
    } else {
      try { await readFile(checkpointPath!); throw new Error('Missing persisted Anvil state checkpoint data'); }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
    }
    // A crash or failed save leaves this marker. It cannot silently adopt an older checkpoint.
    await writeFile(checkpointPath!, JSON.stringify({ version: 1, status: 'running' }), { mode: 0o600 });
  }
  const port = await availablePort();
  const rpcUrl = `http://127.0.0.1:${port}`;
  const process = spawn('anvil', ['--host', '127.0.0.1', '--port', String(port), '--chain-id', '31337',
    '--accounts', String(accountCount), '--silent', ...(options.statePath
      ? ['--state', options.statePath, '--state-interval', '1', '--preserve-historical-states'] : []),
    // Anvil restores block history but recreates block zero from startup settings.
    ...(genesisTimestamp === undefined ? [] : ['--timestamp', String(genesisTimestamp)])],
    { stdio: ['ignore', 'pipe', 'pipe'] });
  // Runtime output can continue under --silent. Drain it so a longer local flow
  // cannot fill a pipe and block the node's RPC worker.
  process.stdout!.resume();
  let diagnostics = '';
  process.stderr!.on('data', data => { diagnostics = (diagnostics + data.toString()).slice(-4096); });
  process.stderr!.resume();
  const client = localClient(rpcUrl);
  let lastError: unknown;
  for (let i = 0; i < 100; i++) {
    try {
      if (await client.getChainId() === 31337) {
        if (expectedHead) {
          const restored=await client.getBlock({blockNumber:BigInt(expectedHead.number)});
          if(restored.hash!==expectedHead.hash)throw new Error('Persisted Anvil state head mismatch');
          // Loading history does not restore Anvil's clock offset. Preserve genesis/history
          // while keeping subsequent blocks at or beyond the saved head (RPC units: seconds).
          const wall=BigInt(Math.floor(Date.now()/1000)),next=restored.timestamp+1n>wall?restored.timestamp+1n:wall;
          if(!Number.isSafeInteger(Number(next)))throw new Error('Unsupported persisted Anvil timestamp');
          await client.request({method:'evm_setTime',params:[Number(next)]} as never);
        }
        const wallets = Array.from({ length: accountCount }, (_, addressIndex) => createWalletClient({
          account: mnemonicToAccount('test test test test test test test test test test test junk', { addressIndex }),
          chain: foundry, transport: http(rpcUrl, { retryCount: 0 }) }));
        let closing: Promise<void> | undefined;
        const close = () => closing ??= (async () => {
          if (!options.statePath) return stopProcess(process);
          try {
            const head = await client.getBlock({ blockTag: 'latest' });
            if (!head.hash || head.number === null) throw new Error();
            await stopProcess(process);
            if (process.exitCode !== 0) throw new Error(`Anvil exit ${process.exitCode}/${process.signalCode}: ${diagnostics}`);
            const state=await inspectAnvilState(createReadStream(options.statePath),head.number);
            if (state.bestBlockNumber !== head.number || !state.containsHead) throw new Error();
            await chmod(options.statePath, 0o600);
            await writeFile(checkpointPath!, JSON.stringify({ version: 1, status: 'saved',
              sha256: state.sha256,
              head: { number: String(head.number), hash: head.hash } }), { mode: 0o600 });
          } catch (cause) {
            await stopProcess(process);
            throw new Error('Could not save persisted Anvil state checkpoint', { cause });
          }
        })();
        return { process, rpcUrl, client, wallets, close };
      }
    } catch (error) { lastError = error; }
    if (process.exitCode !== null) break;
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  await stopProcess(process);
  throw new Error('Could not start disposable local Anvil', { cause: lastError });
}


import { readFile } from 'node:fs/promises';
import { resolve, relative, sep, isAbsolute } from 'node:path';
import { AvaSdk, AvaExtensions, localClient } from '@ava-protocol/sdk';
import { buildAvaService } from './server.ts';

const file = process.argv[2];
if (!file) throw new Error('Usage: npm run service -- .local/devkit/<run>/deployment.json');
const path = resolve(file);
const fromProject = relative(process.cwd(), path);
if (fromProject === '..' || fromProject.startsWith(`..${sep}`) || isAbsolute(fromProject)) {
  throw new Error('Configuration must be inside this project');
}
const config = JSON.parse(await readFile(path, 'utf8'));
if (config.startBlock !== undefined && (typeof config.startBlock !== 'string' || !/^(0|[1-9][0-9]*)$/.test(config.startBlock))) {
  throw new Error('startBlock must be a nonnegative decimal string');
}
const token = (await readFile(config.tokenPath, 'utf8')).trim();
const sdk = new AvaSdk(config.deployment);
const service = await buildAvaService({ client: localClient(config.rpcUrl), sdk,
  extensions: config.extensions ? new AvaExtensions(sdk, config.extensions) : undefined,
  databasePath: config.databasePath, token, confirmations: config.confirmations,
  startBlock: config.startBlock === undefined ? undefined : BigInt(config.startBlock),
  syncBatchSize: config.syncBatchSize, projectionConcurrency: config.projectionConcurrency,
  queryConcurrency: config.queryConcurrency, queryQueueLimit: config.queryQueueLimit,
  recordQueryConcurrency: config.recordQueryConcurrency, recordQueryQueueLimit: config.recordQueryQueueLimit,
  transactionConcurrency: config.transactionConcurrency, transactionQueueLimit: config.transactionQueueLimit,
  additionalSources: config.additionalSources });
await service.app.listen({ host: '127.0.0.1', port: config.port || 8787 });
console.log(`AVA local service ${service.app.listeningOrigin}; chain 31337; no signer held by service.`);
const timer = setInterval(() => { service.sync().catch(() => {}); }, 2000);
for (const signal of ['SIGINT','SIGTERM'] as const) process.once(signal, async () => {
  clearInterval(timer); await service.app.close(); process.exit(0);
});

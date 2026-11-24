import { open, realpath } from 'node:fs/promises';
import { isAbsolute, relative, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { runCustodyOperator, type CustodyOperatorRequest } from './custody.js';

/** Stopped local maintenance only. No listener, wallet, automatic retry or key output. */
export async function custodyOperatorMain(args: string[]) {
  const [operation, configPath, acknowledgement] = args;
  if (!['prepare', 'activate', 'inspect', 'export-profile', 'install-profile'].includes(operation)
    || !configPath || args.length > 3 || (acknowledgement !== undefined && acknowledgement !== '--stopped')
    || (['prepare', 'activate', 'install-profile'].includes(operation) && acknowledgement !== '--stopped')) {
    throw new Error('Usage: custody-operator <prepare|activate|inspect|export-profile|install-profile> <project-local.json> [--stopped]');
  }
  const rootDirectory = await realpath(process.cwd()), target = await realpath(resolve(configPath));
  const delta = relative(rootDirectory, target);
  if (isAbsolute(delta) || delta === '..' || delta.startsWith('../')) throw new Error('E_CUSTODY');
  const input = await open(target, 'r');
  let value: Record<string, unknown>;
  try {
    const stat = await input.stat();
    if (!stat.isFile() || stat.size > 4 * 1024 * 1024) throw new Error('E_CUSTODY');
    value = JSON.parse(await input.readFile('utf8'));
  } finally { await input.close(); }
  if (!value || typeof value !== 'object' || Array.isArray(value) || typeof value.vaultPath !== 'string'
    || (value.pythonPath !== undefined && typeof value.pythonPath !== 'string')) throw new Error('E_CUSTODY');
  const fields: Record<string, string[]> = { prepare: ['masterKeyFile', 'credentialProfileFile', 'newMasterKeyFile', 'expectedReceipts'],
    activate: ['generationId'], inspect: [], 'export-profile': ['masterKeyFile', 'credentialProfileFile'],
    'install-profile': ['profile', 'activeKeyFile'] };
  if (Object.keys(value).some(key => !['vaultPath', 'pythonPath', ...fields[operation]].includes(key))) throw new Error('E_CUSTODY');
  const { vaultPath, pythonPath, ...parameters } = value;
  return runCustodyOperator({ rootDirectory, vaultPath, pythonPath: pythonPath as string | undefined },
    { ...parameters, operation } as CustodyOperatorRequest);
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  try { console.log(JSON.stringify(await custodyOperatorMain(process.argv.slice(2)))); }
  catch (error) {
    const usage = error instanceof Error && error.message.startsWith('Usage:');
    console.error(usage ? (error as Error).message : 'E_CUSTODY'); process.exitCode = 1;
  }
}

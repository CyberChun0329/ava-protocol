import { createHash } from 'node:crypto';
import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { decodeEventLog, decodeFunctionData, isAddress, keccak256, toHex, zeroAddress,
  type Abi, type Address, type Hex, type PublicClient } from 'viem';
import { avaAbis, correctionsAbi } from './abi.js';
import { verifyFoundryBroadcasts } from './deployment-verification.js';
import type { AvaDeployment } from './index.js';
import { AvaReceiptError } from './receipts.js';

export interface PublicDeploymentApp {
  appId: Hex;
  workflowKey: Hex;
  packageId: string;
  disclosurePolicyId: string;
  modules: { capabilityKey: Hex; module: Address }[];
  requiredSubjects: { account: Address; roleKey: Hex; subjectId: Hex; actionKeys: Hex[] }[];
  correctionOrigins: Address[];
  sourceCorrectionBindings: { requester: Address; guard: Address; hook?: Address }[];
  contracts: Record<string, { address: Address; abi: Abi; artifactSha256: string }>;
}
export interface PublicDeployment {
  schemaVersion: 1;
  deployment: AvaDeployment;
  /** Legacy profile for each app; multiple workflows require an explicit primaryWorkflows selection. */
  apps: Record<string, PublicDeploymentApp>;
  /** All profiles by appId then workflowKey, included when any app has multiple workflows. */
  workflows?: Record<Hex, Record<Hex, PublicDeploymentApp>>;
}
interface BroadcastLog { address: string; topics: readonly Hex[]; data: Hex }
interface BroadcastReceipt { transactionHash: string; status: string | number; logs: readonly BroadcastLog[] }
interface CreatedContract { transactionType: string; contractName: string; address: string }
interface BroadcastTransaction {
  hash: string;
  transactionType: string;
  contractName?: string | null;
  contractAddress?: string | null;
  transaction: { to?: string | null; input: Hex; chainId?: string | number;
    from?: string; nonce?: string | number; value?: string | number };
  additionalContracts?: readonly CreatedContract[];
}
export interface FoundryBroadcast {
  chain: number | string;
  pending?: readonly unknown[];
  transactions: readonly BroadcastTransaction[];
  receipts: readonly BroadcastReceipt[];
}
const coreNames = {
  applications: 'AVAApplicationRegistry', identities: 'AVAIdentityRegistry', authority: 'AVAAuthorityMatrix',
  packages: 'AVACoreRulePackageRegistry', disclosure: 'AVADisclosurePolicyRegistry', evidence: 'AVAEvidenceRegistry',
  kernel: 'AVAGovernanceKernel', requests: 'AVARequestAllocation', challenges: 'AVAChallengeExtension',
} as const;
const sharedNames = new Set<string>([...Object.values(coreNames), 'AVAWorkflowPolicyRouter',
  'AVACorrectionRegistry', 'AVARecognitionDependencies', 'AVAExecutionLifecycle', 'AVARequestSupport',
  'AVAChallengePolicyValidation', 'AVARequestSupportDeployment', 'AVARequestCompensation',
  'AVAGovernedObjectValidation', 'AVACorrectionDeployment']);
// Policy-owned slots in script/AVADefaultBindings.sol; application and allocation are app-specific.
const defaultPolicyCapabilities = {
  DefaultAVACorePolicyBundle: ['attribution', 'verification', 'transition-rule', 'evidence-policy',
    'disclosure-policy', 'challenge-policy', 'authority-policy', 'standing', 'consequence', 'evidence-lifecycle'],
  DefaultAVAExtensionPolicyModule: ['standing-computation', 'standing-credential', 'reward',
    'administrative-priority', 'penalty', 'restoration', 'value-execution'],
} as const;
function publicAddress(value: string): Address {
  if (typeof value !== 'string' || !isAddress(value) || value.toLowerCase() === zeroAddress) {
    throw new Error('Invalid deployment address');
  }
  return value.toLowerCase() as Address;
}

/**
 * Process broadcasts in supplied order. Each disclosure registration must
 * follow its package while that package is the app's only profile awaiting a disclosure policy.
 * Subjects and correction origins describe current app-scoped configuration for every workflow;
 * source correction bindings remain package scoped. Optional verification checks transaction associations
 * and uses canonical RPC receipt logs. Current installation checks remain in verifyInstallation.
 */
export async function exportPublicDeployment({ broadcasts, artifact, authorityContract = coreNames.authority,
  defaultPolicies, primaryWorkflows, allowCoreOnly = false, verification }: {
  broadcasts: FoundryBroadcast | readonly FoundryBroadcast[];
  artifact: (name: string) => Promise<{ abi: Abi }>;
  authorityContract?: string;
  allowCoreOnly?: boolean;
  defaultPolicies?: { corePolicy: Address; extensionPolicy: Address };
  /** Explicit legacy apps[appId] selection; required for every app with multiple workflows. */
  primaryWorkflows?: Record<Hex, Hex>;
  /** Verify the supplied transaction sequence against RPC before deriving the declaration. Default depth is one. */
  verification?: { client: PublicClient; confirmations?: number };
}): Promise<PublicDeployment> {
  const reusedPolicies = new Map<string, Address>();
  if (defaultPolicies !== undefined) {
    if (!defaultPolicies || typeof defaultPolicies !== 'object') throw new Error('Invalid default policies');
    reusedPolicies.set('DefaultAVACorePolicyBundle', publicAddress(defaultPolicies.corePolicy));
    reusedPolicies.set('DefaultAVAExtensionPolicyModule', publicAddress(defaultPolicies.extensionPolicy));
    if (reusedPolicies.get('DefaultAVACorePolicyBundle') === reusedPolicies.get('DefaultAVAExtensionPolicyModule')) {
      throw new Error('Conflicting default policy addresses');
    }
  }
  const configuredCoreNames = { ...coreNames, authority: authorityContract };
  const sharedContractNames = new Set([...sharedNames, authorityContract]);
  const supplied: readonly FoundryBroadcast[] = Array.isArray(broadcasts) ? broadcasts : [broadcasts as FoundryBroadcast];
  if (supplied.length === 0) throw new Error('Deployment broadcasts are required');
  const chainId = Number(supplied[0].chain);
  if (!Number.isSafeInteger(chainId) || chainId < 1) throw new Error('Invalid deployment chain');
  const verified = verification !== undefined;
  if (verified && !verification?.client) throw new AvaReceiptError('invalid_request');
  if (verified && primaryWorkflows) primaryWorkflows = { ...primaryWorkflows };
  const runs = verification ? await verifyFoundryBroadcasts(structuredClone(supplied), chainId, { ...verification }) : supplied;
  const shared = new Map<string, Address>();
  const prepared = runs.map(run => {
    if (Number(run.chain) !== chainId) throw new Error('Conflicting deployment chains');
    if (run.pending?.length) throw new Error('Pending deployment transactions');
    const receipts = new Map(run.receipts.map(receipt => [receipt.transactionHash.toLowerCase(), receipt]));
    const created = new Map<string, Address>();
    const remember = (name: string, value: string) => {
      if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) throw new Error('Invalid contract name');
      const address = publicAddress(value), target = sharedContractNames.has(name) ? shared : created;
      if (reusedPolicies.has(name) && reusedPolicies.get(name) !== address) {
        throw new Error('Conflicting default policy deployment');
      }
      if (target.has(name) && target.get(name) !== address) throw new Error('Conflicting deployment contracts');
      target.set(name, address);
    };
    for (const tx of run.transactions) {
      const receipt = receipts.get(tx.hash.toLowerCase());
      if (!receipt || ![1, '1', '0x1'].includes(receipt.status)) throw new Error('Missing or failed deployment receipt');
      if (tx.transaction.chainId !== undefined && Number(tx.transaction.chainId) !== chainId) {
        throw new Error('Conflicting transaction chain');
      }
      if (tx.transactionType === 'CREATE' || tx.transactionType === 'CREATE2') {
        if (!tx.contractName || !tx.contractAddress) throw new Error('Missing created contract identity');
        remember(tx.contractName, tx.contractAddress);
        for (const child of tx.additionalContracts ?? []) {
          if (child.transactionType !== 'CREATE' && child.transactionType !== 'CREATE2') continue;
          remember(child.contractName, child.address);
        }
      }
    }
    return { run, receipts, created };
  });
  const addresses = {} as AvaDeployment['addresses'];
  for (const [key, name] of Object.entries(configuredCoreNames)) {
    const address = shared.get(name);
    if (!address) throw new Error(`Missing Core deployment: ${name}`);
    addresses[key as keyof typeof coreNames] = address;
  }
  const abis = new Map<string, Abi>(Object.entries(avaAbis).map(([key, abi]) =>
    [addresses[key as keyof typeof coreNames], abi]));
  const corrections = shared.get('AVACorrectionRegistry');
  if (corrections) abis.set(corrections, correctionsAbi);
  const workflows: NonNullable<PublicDeployment['workflows']> = {};
  const configuredApps = new Set<Hex>();
  const packageIds = new Set<string>();
  const policyIds = new Set<string>();
  const subjects = new Map<Hex, { appId: Hex; account: Address; roleKey: Hex; subjectId: Hex }>();
  const permissions = new Map<string, Set<Hex>>();
  const origins = new Map<Hex, Set<Address>>();
  const disabledOrigins = new Set<string>();
  const sourceBindings = new Map<string, Partial<PublicDeploymentApp['sourceCorrectionBindings'][number]>>();
  const allContracts = new Map<string, { address: Address; abi: Abi; artifactSha256: string }>();
  const readContracts = async (created: Map<string, Address>) => {
    const contracts: PublicDeploymentApp['contracts'] = {};
    for (const [name, address] of new Map([...shared, ...created, ...reusedPolicies])) {
      const key = `${name}:${address}`;
      let value = allContracts.get(key);
      if (!value) {
        const source = await artifact(name);
        if (!Array.isArray(source.abi)) throw new Error('Missing contract ABI');
        value = { address, abi: source.abi, artifactSha256: createHash('sha256')
          .update(JSON.stringify(source)).digest('hex') };
        allContracts.set(key, value);
      }
      contracts[name] = value;
    }
    return contracts;
  };
  const eventArgs = (receipt: BroadcastReceipt, address: Address, abi: Abi, eventName: string) => {
    const matches: Record<string, unknown>[] = [];
    for (const log of receipt.logs) {
      if (log.address.toLowerCase() !== address) continue;
      try {
        const event = decodeEventLog({ abi, topics: log.topics as [Hex, ...Hex[]], data: log.data });
        if (event.eventName === eventName) matches.push(event.args as unknown as Record<string, unknown>);
      } catch { /* Other logs in the same receipt are not registration evidence. */ }
    }
    if (matches.length !== 1) throw new Error('Missing or ambiguous deployment registration event');
    return matches[0];
  };
  for (const { run, receipts, created } of prepared) {
    const localProfiles = new Set<PublicDeploymentApp>();
    for (const tx of run.transactions) {
      if (tx.transactionType !== 'CALL') continue;
      const target = (tx.transaction.to ?? tx.contractAddress ?? '').toLowerCase();
      const abi = abis.get(target);
      if (!abi) continue;
      let decoded;
      try { decoded = decodeFunctionData({ abi, data: tx.transaction.input }); }
      catch { throw new Error('Invalid Core deployment calldata'); }
      const args = decoded.args as readonly unknown[];
      const receipt = receipts.get(tx.hash.toLowerCase())!;
      if (target === addresses.applications && decoded.functionName === 'registerApplication') {
        configuredApps.add(args[0] as Hex);
      }
      if (target === addresses.identities && decoded.functionName === 'assignSubject') {
        const [account, appId, roleKey, subjectId] = args as [string, Hex, Hex, Hex];
        configuredApps.add(appId);
        const normalized = publicAddress(account);
        subjects.set(subjectId, { appId, account: normalized, roleKey, subjectId });
      }
      if (target === addresses.identities && decoded.functionName === 'deactivateSubject') subjects.delete(args[0] as Hex);
      if (target === addresses.authority && ['setPermission', 'setPermissions'].includes(decoded.functionName)) {
        const appId = args[0] as Hex;
        configuredApps.add(appId);
        const updates = decoded.functionName === 'setPermissions'
          ? args[1] as readonly { roleKey: Hex; actionKey: Hex; allowed: boolean }[]
          : [{ roleKey: args[1] as Hex, actionKey: args[2] as Hex, allowed: args[3] as boolean }];
        for (const { roleKey, actionKey, allowed } of updates) {
          const key = `${appId}:${roleKey}`, actions = permissions.get(key) ?? new Set<Hex>();
          if (allowed) actions.add(actionKey); else actions.delete(actionKey);
          permissions.set(key, actions);
        }
      }
      if (target === corrections && ['bindRequestOrigin', 'setRequestOriginEnabled'].includes(decoded.functionName)) {
        const [appId, value, enabled] = args as [Hex, string, boolean?];
        configuredApps.add(appId);
        const address = publicAddress(value), active = origins.get(appId) ?? new Set<Address>();
        if (decoded.functionName === 'bindRequestOrigin') {
          // A repeated code pin does not clear a prospective intake disable.
          if (!disabledOrigins.has(`${appId}:${address}`)) active.add(address);
        } else if (enabled === false) {
          active.delete(address);
          disabledOrigins.add(`${appId}:${address}`);
        } else {
          active.add(address);
          disabledOrigins.delete(`${appId}:${address}`);
        }
        origins.set(appId, active);
      }
      if (target === addresses.kernel && ['bindSourceBoundTransitionRequester', 'bindTransitionGuard',
        'bindPostTransitionHook'].includes(decoded.functionName)) {
        const [packageId, value] = args as [bigint, string];
        const binding = sourceBindings.get(packageId.toString()) ?? {};
        const field = decoded.functionName === 'bindSourceBoundTransitionRequester' ? 'requester'
          : decoded.functionName === 'bindTransitionGuard' ? 'guard' : 'hook';
        binding[field] = publicAddress(value);
        sourceBindings.set(packageId.toString(), binding);
      }
      if (target === addresses.packages && decoded.functionName === 'registerRulePackage') {
        const input = args[0] as { appId: Hex; workflowKey: Hex };
        const bindings = args[1] as { capabilityKey: Hex; module: string }[];
        const event = eventArgs(receipt, addresses.packages, abi, 'RulePackageRegistered');
        if (event.appId !== input.appId || event.workflowKey !== input.workflowKey || typeof event.packageId !== 'bigint') {
          throw new Error('Package registration event mismatch');
        }
        const profiles = workflows[input.appId] ??= {};
        if (profiles[input.workflowKey]) throw new Error('Ambiguous application package deployment');
        const packageId = event.packageId.toString();
        if (packageIds.has(packageId)) throw new Error('Duplicate package deployment');
        packageIds.add(packageId);
        if (new Set(bindings.map(binding => binding.capabilityKey)).size !== bindings.length) {
          throw new Error('Duplicate capability binding');
        }
        const profile = profiles[input.workflowKey] = { appId: input.appId, workflowKey: input.workflowKey,
          packageId,
          disclosurePolicyId: '', modules: bindings.map(binding => ({ capabilityKey: binding.capabilityKey,
            module: publicAddress(binding.module) })), requiredSubjects: [], correctionOrigins: [],
          sourceCorrectionBindings: [], contracts: {} };
        localProfiles.add(profile);
      }
      if (target === addresses.disclosure && decoded.functionName === 'registerPolicy') {
        const event = eventArgs(receipt, addresses.disclosure, abi, 'DisclosurePolicyRegistered');
        if (event.appId !== args[0] || event.policyKey !== args[3] || typeof event.policyId !== 'bigint') {
          throw new Error('Disclosure registration event mismatch');
        }
        // Disclosure registrations are app scoped: only one pending profile can identify their workflow.
        const pending = Object.values(workflows[args[0] as Hex] ?? {}).filter(app => !app.disclosurePolicyId);
        if (pending.length !== 1) throw new Error('Ambiguous application disclosure deployment');
        const policyId = event.policyId.toString();
        if (policyIds.has(policyId)) throw new Error('Duplicate disclosure policy deployment');
        policyIds.add(policyId);
        pending[0].disclosurePolicyId = policyId;
      }
    }
    for (const profile of localProfiles) profile.contracts = await readContracts(created);
  }
  const profiles = Object.values(workflows).flatMap(app => Object.values(app));
  if ((!allowCoreOnly && profiles.length === 0) || profiles.some(app => !app.disclosurePolicyId)
    || (profiles.length === 0 && (configuredApps.size > 0 || sourceBindings.size > 0))) {
    throw new Error('Incomplete application deployment');
  }
  for (const app of profiles) {
    for (const [name, address] of reusedPolicies) {
      const keys = defaultPolicyCapabilities[name as keyof typeof defaultPolicyCapabilities]
        .map(capability => keccak256(toHex(`ava.capability.${capability}.v1`)));
      // Preserve custom adapters while requiring each declaration to identify a used default.
      if (!app.modules.some(binding => binding.module === address && keys.includes(binding.capabilityKey))) {
        throw new Error('Default policy binding mismatch');
      }
    }
    app.requiredSubjects = [...subjects.values()].filter(subject => subject.appId === app.appId)
      .map(({ account, roleKey, subjectId }) => ({ account, roleKey, subjectId,
        actionKeys: [...(permissions.get(`${app.appId}:${roleKey}`) ?? [])] }));
    app.correctionOrigins = [...(origins.get(app.appId) ?? [])];
    const binding = sourceBindings.get(app.packageId);
    if (binding) {
      if (!binding.requester || !binding.guard) throw new Error('Incomplete source correction binding');
      app.sourceCorrectionBindings = [{ requester: binding.requester, guard: binding.guard,
        hook: binding.hook ?? zeroAddress }];
    }
  }
  const apps: PublicDeployment['apps'] = {};
  for (const [appId, appWorkflows] of Object.entries(workflows)) {
    const available = Object.values(appWorkflows), selected = primaryWorkflows?.[appId as Hex];
    if (!selected && available.length > 1) throw new Error('Ambiguous application package deployment: primary workflow required');
    const primary = selected ? appWorkflows[selected] : available[0];
    if (!primary) throw new Error('Invalid primary workflow selection');
    apps[appId] = primary;
  }
  if (Object.keys(primaryWorkflows ?? {}).some(appId => !apps[appId])) {
    throw new Error('Invalid primary workflow selection');
  }
  const multipleWorkflows = Object.values(workflows).some(app => Object.keys(app).length > 1);
  return { schemaVersion: 1, deployment: { chainId, addresses }, apps,
    ...(multipleWorkflows ? { workflows } : {}) };
}

/** Load a named contract from an independent Foundry output directory. */
export function foundryArtifactLoader(artifactDirectory: string): (name: string) => Promise<{ abi: Abi; [key: string]: unknown }> {
  return async name => {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) throw new Error('Invalid contract name');
    const matches: string[] = [];
    async function scan(directory: string): Promise<void> {
      for (const entry of await readdir(directory, { withFileTypes: true })) {
        const path = join(directory, entry.name);
        if (entry.isDirectory()) await scan(path);
        else if (entry.isFile() && entry.name === `${name}.json`) matches.push(path);
      }
    }
    await scan(artifactDirectory);
    if (matches.length === 0) throw new Error(`Missing contract artifact: ${name}`);
    if (matches.length > 1) throw new Error(`Ambiguous contract artifact: ${name}`);
    const value: unknown = JSON.parse(await readFile(matches[0], 'utf8'));
    if (!value || typeof value !== 'object' || !Array.isArray((value as { abi?: unknown }).abi)) {
      throw new Error(`Invalid contract artifact: ${name}`);
    }
    return value as { abi: Abi; [key: string]: unknown };
  };
}

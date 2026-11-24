import { BaseError, getContract, keccak256, zeroAddress, zeroHash,
  type Address, type Hex, type PublicClient } from 'viem';
import { ruleGovernanceAbi } from './abi.js';
import type { AvaExtensions } from './extensions.js';
import type { ReadPoint } from './index.js';
import { readRejection } from './read-errors.js';
import { resolveReadPoint } from './read-point.js';

export interface InstallationExpectations {
  appId: Hex;
  workflowKey: Hex;
  /** Must be active; also the default packageId for modules and sourceCorrectionBindings. */
  activePackageId: bigint;
  /** Verify these packages in the same app/workflow without requiring them to be active. */
  historicalPackageIds?: readonly bigint[];
  modules?: readonly { packageId?: bigint; capabilityKey: Hex; module: Address }[];
  requiredSubjects?: readonly { account: Address; roleKey: Hex; subjectId: Hex; actionKeys: readonly Hex[] }[];
  /** Require these account/role/action combinations to be unauthorised in this application. */
  forbiddenPermissions?: readonly { account: Address; roleKey: Hex; actionKey: Hex }[];
  /** Omit fields to skip them. Zero address requires no delegate or actionable nomination. */
  administration?: { root?: Address; application?: Address; pendingRoot?: Address; pendingApplication?: Address };
  correctionOrigins?: readonly Address[];
  /** An omitted hook skips that expectation; zeroAddress explicitly requires no hook. */
  sourceCorrectionBindings?: readonly { packageId?: bigint; requester: Address; guard: Address; hook?: Address }[];
  governanceController?: Address;
}
export interface InstallationFinding {
  check: string;
  status: 'missing' | 'mismatch' | 'unavailable';
  detail: string;
}
export interface InstallationReadiness {
  ready: boolean;
  point: ReadPoint;
  appId: Hex;
  workflowKey: Hex;
  activePackageId: bigint;
  findings: InstallationFinding[];
}

interface ModuleReadGroup {
  capabilityKeys: Hex[];
  modules?: readonly Address[];
  batchReadFailed?: boolean;
  nextModuleIndex: number;
}

function groupRequiredModules(requirements: InstallationExpectations): Map<bigint, ModuleReadGroup> {
  const groups = new Map<bigint, ModuleReadGroup>();
  for (const binding of requirements.modules ?? []) {
    const packageId = binding.packageId ?? requirements.activePackageId;
    let group = groups.get(packageId);
    if (!group) {
      group = { capabilityKeys: [], nextModuleIndex: 0 };
      groups.set(packageId, group);
    }
    group.capabilityKeys.push(binding.capabilityKey);
  }
  return groups;
}

function snapshotInstallationExpectations(expected: InstallationExpectations): InstallationExpectations {
  return {
    ...expected,
    historicalPackageIds: expected.historicalPackageIds?.slice(),
    modules: expected.modules?.map(binding => ({ ...binding })),
    requiredSubjects: expected.requiredSubjects?.map(subject => ({ ...subject, actionKeys: [...subject.actionKeys] })),
    forbiddenPermissions: expected.forbiddenPermissions?.map(permission => ({ ...permission })),
    administration: expected.administration && { ...expected.administration },
    correctionOrigins: expected.correctionOrigins?.slice(),
    sourceCorrectionBindings: expected.sourceCorrectionBindings?.map(binding => ({ ...binding })),
  };
}

function classifyInstallationReadFailure(error: unknown): Pick<InstallationFinding, 'status' | 'detail'> {
  const rejected = readRejection(error);
  const detail = error instanceof Error ? error.message : String(error);
  if (rejected) return { status: 'missing', detail: rejected.errorName ?? rejected.reason };
  if (error instanceof BaseError) return { status: 'unavailable', detail: 'read_unavailable' };
  if (/^No code at /.test(detail)) return { status: 'missing', detail: 'missing_code' };
  if (/mismatch|do not share the configured Core/.test(detail)) {
    return { status: 'mismatch', detail: 'deployment_mismatch' };
  }
  return { status: 'unavailable', detail: 'read_unavailable' };
}

/** Read-only comparison with the caller's declared installation requirements, not a policy certificate. */
export async function verifyInstallation(extensions: AvaExtensions, client: PublicClient,
    expected: InstallationExpectations, point?: ReadPoint): Promise<InstallationReadiness> {
  const requirements = snapshotInstallationExpectations(expected);
  if (requirements.appId === zeroHash || requirements.workflowKey === zeroHash || requirements.activePackageId < 1n) {
    throw new Error('Explicit nonzero application, workflow and active package are required');
  }
  const readPoint = await resolveReadPoint(client, point);
  const at = typeof readPoint === 'bigint' ? { blockNumber: readPoint } : readPoint;
  const sdk = extensions.sdk;
  const contracts = sdk.contracts(client);
  const findings: InstallationFinding[] = [];
  const recordFinding = (check: string, status: InstallationFinding['status'], detail: string) =>
    findings.push({ check, status, detail });
  const compareValue = (check: string, actual: string | bigint, wanted: string | bigint) => {
    const same = typeof actual === 'string' && typeof wanted === 'string'
      ? actual.toLowerCase() === wanted.toLowerCase() : actual === wanted;
    if (!same) recordFinding(check, actual === zeroAddress || actual === zeroHash || actual === 0n
      ? 'missing' : 'mismatch', `Expected ${wanted}; found ${actual}`);
  };
  const inspectRead = async (check: string, read: () => Promise<void>) => {
    try { await read(); }
    catch (error) {
      const failure = classifyInstallationReadFailure(error);
      recordFinding(check, failure.status, failure.detail);
    }
  };

  await inspectRead('deployment', () => extensions.verify(client, readPoint));
  await inspectRead('application', async () => {
    compareValue('application', (await contracts.applications.read.getApplication([requirements.appId], at)).appId, requirements.appId);
  });
  if (requirements.administration) {
    const { root, application, pendingRoot, pendingApplication } = requirements.administration;
    const registry = contracts.applications.read;
    if (root !== undefined) await inspectRead('administration:root', async () => {
      compareValue('administration:root', await registry.ADMIN(at), root);
    });
    if (application !== undefined) await inspectRead('administration:application', async () => {
      compareValue('administration:application', await registry.applicationAdmin([requirements.appId], at), application);
    });
    if (pendingRoot !== undefined) await inspectRead('administration:pendingRoot', async () => {
      compareValue('administration:pendingRoot', await registry.pendingAdmin(at), pendingRoot);
    });
    if (pendingApplication !== undefined) await inspectRead('administration:pendingApplication', async () => {
      let nominee = await registry.pendingApplicationAdmin([requirements.appId], at);
      if (nominee !== zeroAddress) {
        const [nominationVersion, rootVersion] = await Promise.all([
          registry.pendingApplicationAdminVersion([requirements.appId], at), registry.adminVersion(at),
        ]);
        // Root succession invalidates outstanding application nominations from its previous term.
        if (nominationVersion !== rootVersion) nominee = zeroAddress;
      }
      compareValue('administration:pendingApplication', nominee, pendingApplication);
    });
  }
  await inspectRead('activePackage', async () => {
    compareValue('activePackage', await contracts.packages.read.getActivePackageId([
      requirements.appId, requirements.workflowKey], at), requirements.activePackageId);
  });
  const packageIds = new Set([requirements.activePackageId, ...(requirements.historicalPackageIds ?? []),
    ...(requirements.modules ?? []).map(m => m.packageId ?? requirements.activePackageId),
    ...(requirements.sourceCorrectionBindings ?? []).map(b => b.packageId ?? requirements.activePackageId)]);
  for (const id of packageIds) await inspectRead(`package:${id}`, async () => {
    const context = await contracts.packages.read.getVerifiedPackageContext([id], at);
    compareValue(`package:${id}:app`, context.appId, requirements.appId);
    compareValue(`package:${id}:workflow`, context.workflowKey, requirements.workflowKey);
  });
  const groups = groupRequiredModules(requirements);
  for (const binding of requirements.modules ?? []) {
    const packageId = binding.packageId ?? requirements.activePackageId;
    const check = `module:${packageId}:${binding.capabilityKey}`;
    const group = groups.get(packageId)!;
    if (group.capabilityKeys.length > 1 && !group.modules && !group.batchReadFailed) {
      try {
        [, group.modules] = await contracts.packages.read.getVerifiedModulesCompact([packageId, group.capabilityKeys], at);
      } catch {
        group.batchReadFailed = true;
      }
    }
    const moduleIndex = group.nextModuleIndex++;
    await inspectRead(check, async () => {
      const modules = group.modules
        ?? (await contracts.packages.read.getVerifiedModulesCompact([packageId, [binding.capabilityKey]], at))[1];
      compareValue(check, modules[group.modules ? moduleIndex : 0] ?? zeroAddress, binding.module);
    });
  }
  for (const binding of requirements.sourceCorrectionBindings ?? []) {
    const id = binding.packageId ?? requirements.activePackageId, check = `sourceCorrection:${id}`;
    if (binding.requester === zeroAddress || binding.guard === zeroAddress) {
      recordFinding(check, 'missing', 'Required source correction requester and guard must be nonzero');
    }
    await inspectRead(check, async () => {
      compareValue(`${check}:requester`, await contracts.kernel.read.sourceBoundTransitionRequesterByPackage([id], at), binding.requester);
      compareValue(`${check}:guard`, await contracts.kernel.read.transitionGuardByPackage([id], at), binding.guard);
      if (binding.hook !== undefined) {
        compareValue(`${check}:hook`, await contracts.kernel.read.postTransitionHookByPackage([id], at), binding.hook);
      }
    });
    await inspectRead(`${check}:stable`, async () => { await contracts.kernel.read.requireStablePackageBindings([id], at); });
  }
  for (const subject of requirements.requiredSubjects ?? []) {
    const check = `subject:${subject.subjectId}`;
    await inspectRead(check, async () => {
      const record = await contracts.identities.read.getSubjectContext([subject.subjectId], at);
      compareValue(`${check}:app`, record.appId, requirements.appId);
      compareValue(`${check}:account`, record.account, subject.account);
      compareValue(`${check}:role`, record.roleKey, subject.roleKey);
      if (!record.active) recordFinding(`${check}:active`, 'missing', 'Required subject is inactive');
      compareValue(`${check}:canonical`, await contracts.identities.read.subjectOf([
        subject.account, requirements.appId, subject.roleKey], at), subject.subjectId);
    });
    for (const action of subject.actionKeys) await inspectRead(`permission:${subject.subjectId}:${action}`, async () => {
      if (!await contracts.authority.read.isAuthorised([subject.account, requirements.appId, subject.roleKey, action], at)) {
        recordFinding(`permission:${subject.subjectId}:${action}`, 'missing', 'Required action is not currently authorised');
      }
    });
  }
  for (const { account, roleKey, actionKey } of requirements.forbiddenPermissions ?? []) {
    const check = `permission:forbidden:${account}:${roleKey}:${actionKey}`;
    await inspectRead(check, async () => {
      if (await contracts.authority.read.isAuthorised([account, requirements.appId, roleKey, actionKey], at)) {
        recordFinding(check, 'mismatch', 'Forbidden action is currently authorised');
      }
    });
  }
  let correctionRegistry: Awaited<ReturnType<typeof sdk.corrections>> | undefined;
  for (const origin of requirements.correctionOrigins ?? []) {
    const check = `correctionOrigin:${origin}`;
    await inspectRead(check, async () => {
      const registry = correctionRegistry ?? await sdk.corrections(client, readPoint);
      // A block hash keeps the registry binding stable for this check.
      if (typeof readPoint !== 'bigint') correctionRegistry = registry;
      const [pin, disabled, code] = await Promise.all([
        registry.read.requestOriginCodeHash([requirements.appId, origin], at),
        registry.read.requestOriginDisabled([requirements.appId, origin], at),
        client.getCode({ address: origin, ...at }),
      ]);
      if (!code) recordFinding(`${check}:code`, 'missing', 'No code at the required correction origin');
      compareValue(`${check}:codePin`, pin, code ? keccak256(code) : zeroHash);
      if (pin === zeroHash && !code) recordFinding(`${check}:codePin`, 'missing', 'Required origin has no code pin');
      if (disabled) recordFinding(`${check}:enabled`, 'missing', 'Required correction origin is prospectively disabled');
      if (code) compareValue(`${check}:kernel`, await client.readContract({ address: origin,
        abi: ruleGovernanceAbi, functionName: 'GOVERNANCE_KERNEL', ...at }), sdk.deployment.addresses.kernel);
    });
  }
  if (requirements.governanceController) await inspectRead('governanceController', async () => {
    const binding = await contracts.packages.read.getGovernanceBinding([requirements.appId, requirements.workflowKey], at);
    compareValue('governanceController', binding.controller, requirements.governanceController!);
    const controller = getContract({ address: requirements.governanceController!, abi: ruleGovernanceAbi, client });
    if (!await client.getCode({ address: controller.address, ...at })) {
      recordFinding('governanceController:code', 'missing', 'No code at required governance controller');
    }
    compareValue('governanceController:registry', await controller.read.RULE_PACKAGE_REGISTRY(at), sdk.deployment.addresses.packages);
    compareValue('governanceController:kernel', await controller.read.GOVERNANCE_KERNEL(at), sdk.deployment.addresses.kernel);
    compareValue('governanceController:identity', await controller.read.moduleIdentityHash(at), binding.identityHash);
  });
  if (extensions.addresses.governedDisclosure) await inspectRead('governedDisclosure:scope', async () => {
    const disclosure = extensions.governedDisclosure(client);
    compareValue('governedDisclosure:app', await disclosure.read.APP_ID(at), requirements.appId);
    compareValue('governedDisclosure:workflow', await disclosure.read.WORKFLOW_KEY(at), requirements.workflowKey);
  });
  return { ready: findings.length === 0, point: readPoint, appId: requirements.appId, workflowKey: requirements.workflowKey,
    activePackageId: requirements.activePackageId, findings };
}

import { zeroHash, type Address, type Hex, type PublicClient } from 'viem';
import type { Authority, AvaSdk, ReadPoint } from './index.js';
import { AvaReadError } from './read-errors.js';
import { resolveReadPoint } from './read-point.js';

export interface ActorContextQuery {
  account: Address;
  appId: Hex;
  roleKey: Hex;
  actionKeys?: readonly Hex[];
}

export interface ActorContext {
  account: Address;
  appId: Hex;
  roleKey: Hex;
  subjectId: Hex | null;
  authority: Authority | null;
  permissions: readonly { actionKey: Hex; allowed: boolean }[];
  point: ReadPoint;
}

export async function readActorContext(sdk: AvaSdk, client: PublicClient,
  query: ActorContextQuery, point?: ReadPoint): Promise<ActorContext> {
  try {
    const { account, appId, roleKey } = query;
    const actionKeys = [...(query.actionKeys ?? [])];
    const chainId = sdk.deployment.chainId;
    const contracts = sdk.contracts(client);
    const explicitPoint = point === undefined || typeof point === 'bigint' ? point : { ...point };
    if (await client.getChainId() !== chainId) throw new AvaReadError();
    point = await resolveReadPoint(client, explicitPoint);
    const at = typeof point === 'bigint' ? { blockNumber: point } : point;
    const [identityLink, authorityLink] = await Promise.all([
      contracts.kernel.read.IDENTITY_REGISTRY(at), contracts.kernel.read.AUTHORITY_MATRIX(at),
    ]);
    if (identityLink.toLowerCase() !== contracts.identities.address.toLowerCase()
      || authorityLink.toLowerCase() !== contracts.authority.address.toLowerCase()) throw new AvaReadError();
    const subjectId = await contracts.identities.read.subjectOf([account, appId, roleKey], at);
    if (subjectId === zeroHash) return { account, appId, roleKey, subjectId: null, authority: null,
      permissions: actionKeys.map(actionKey => ({ actionKey, allowed: false })), point };
    const context = await contracts.identities.read.getSubjectContext([subjectId], at);
    if (!context.active || context.subjectId.toLowerCase() !== subjectId.toLowerCase()
      || context.account.toLowerCase() !== account.toLowerCase()
      || context.appId.toLowerCase() !== appId.toLowerCase()
      || context.roleKey.toLowerCase() !== roleKey.toLowerCase()) throw new AvaReadError();
    const permissions = await Promise.all(actionKeys.map(async actionKey => ({ actionKey,
      allowed: await contracts.authority.read.isAuthorised([account, appId, roleKey, actionKey], at) })));
    return { account, appId, roleKey, subjectId, authority: { roleKey, authorityId: subjectId },
      permissions, point };
  } catch { throw new AvaReadError(); }
}

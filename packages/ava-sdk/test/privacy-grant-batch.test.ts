import assert from 'node:assert/strict';
import { test } from 'node:test';
import { decodeFunctionData, type Address, type Hex } from 'viem';
import { AvaSdk, AvaExtensions, evidenceBindingsAbi, privacyAbi,
  type Authority, type CoreAddresses, type PrivacyGrantInput } from '../src/index.ts';

const address = (n: number) => `0x${n.toString(16).padStart(40, '0')}` as Address;
const hash = (byte: string) => `0x${byte.repeat(32)}` as Hex;
const addresses = Object.fromEntries(['applications', 'identities', 'authority', 'packages',
  'disclosure', 'evidence', 'kernel', 'requests', 'challenges']
  .map((name, i) => [name, address(i + 1)])) as CoreAddresses;
const sdk = new AvaSdk({ chainId: 31337, addresses });
const privacy = address(20);
const evidenceBindings = address(21);
const extensions = new AvaExtensions(sdk, { privacy, evidenceBindings });
const authority: Authority = { roleKey: hash('11'), authorityId: hash('22') };
const grants: readonly PrivacyGrantInput[] = [
  { resourceId: hash('33'), persona: hash('44'), readerRole: hash('55'), purpose: hash('66'), expiresAt: 1500n },
  { resourceId: hash('77'), persona: hash('88'), readerRole: hash('99'), purpose: hash('aa'), expiresAt: 1600n },
];

test('resource pair encodes two exact commitments under one case and explicit authority', () => {
  const caseId = hash('11');
  const registrations = [
    { resourceId: hash('33'), materialClass: hash('44'), ciphertextHash: hash('55') },
    { resourceId: hash('66'), materialClass: hash('77'), ciphertextHash: hash('88') },
  ] as const;
  const call = extensions.registerPrivateResourcePair(caseId, registrations, authority);
  assert.equal(call.to, privacy);
  assert.equal((call.data.length - 2) / 2, 292);
  assert.deepEqual(decodeFunctionData({ abi: privacyAbi, data: call.data }), {
    functionName: 'registerResourcePair', args: [caseId, registrations, authority.roleKey, authority.authorityId],
  });
});

test('evidence pair encodes two exact bindings under one case and explicit authority', () => {
  const caseId = hash('11');
  const bindings = [{ evidenceId: 1n, resourceId: hash('33') }, { evidenceId: 2n, resourceId: hash('44') }] as const;
  const call = extensions.bindPrivateEvidencePair(caseId, bindings, authority);
  assert.equal(call.to, evidenceBindings);
  assert.equal((call.data.length - 2) / 2, 228);
  assert.deepEqual(decodeFunctionData({ abi: evidenceBindingsAbi, data: call.data }), {
    functionName: 'bindEvidencePair', args: [caseId, bindings, authority.roleKey, authority.authorityId],
  });
});

test('public extension encodes every ordinary grant and the explicit controller authority', () => {
  const call = extensions.grantPrivacyAccessMany(grants, authority);
  assert.equal(call.to, privacy);
  assert.deepEqual(decodeFunctionData({ abi: privacyAbi, data: call.data }), {
    functionName: 'grantAccessMany', args: [grants, authority.roleKey, authority.authorityId],
  });
});

test('batch calls require configured privacy and an explicit controller authority', () => {
  assert.throws(() => new AvaExtensions(sdk, {}).grantPrivacyAccessMany(grants, authority), /privacy.*configured/);
  assert.throws(() => {
    // @ts-expect-error The batch never chooses a controller authority implicitly.
    extensions.grantPrivacyAccessMany(grants);
  });
});

test('single grants remain available and three or four ordinary grants encode less calldata', () => {
  const first = grants[0];
  const call = extensions.grantPrivacyAccess(first.resourceId, first.persona, first.readerRole,
    first.purpose, first.expiresAt, authority);
  assert.deepEqual(decodeFunctionData({ abi: privacyAbi, data: call.data }), {
    functionName: 'grantAccess', args: [first.resourceId, first.persona, first.readerRole,
      first.purpose, first.expiresAt, authority.roleKey, authority.authorityId],
  });
  const three = [grants[0], grants[1], { ...first, resourceId: hash('bb') }];
  const four = [...three, { ...first, resourceId: hash('cc') }];
  assert.equal((extensions.grantPrivacyAccessMany(three, authority).data.length - 2) / 2, 612);
  assert.equal((extensions.grantPrivacyAccessMany(four, authority).data.length - 2) / 2, 772);
  assert.equal((call.data.length - 2) / 2, 228);
});

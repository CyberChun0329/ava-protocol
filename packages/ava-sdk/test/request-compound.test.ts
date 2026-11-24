import assert from 'node:assert/strict';
import { test } from 'node:test';
import { decodeFunctionData, type Address, type Hex } from 'viem';
import { AvaSdk, requestsAbi, type Authority, type CoreAddresses, type RequestInput } from '../src/index.ts';

const addresses = Object.fromEntries(['applications', 'identities', 'authority', 'packages',
  'disclosure', 'evidence', 'kernel', 'requests', 'challenges']
  .map((name, i) => [name, `0x${(i + 1).toString(16).padStart(40, '0')}`])) as CoreAddresses;
const sdk = new AvaSdk({ chainId: 31337, addresses });
const hash = (byte: string) => `0x${byte.repeat(32)}` as Hex;
const creation: Authority = { roleKey: hash('11'), authorityId: hash('22') };
const allocation: Authority = { roleKey: hash('33'), authorityId: hash('44') };
const input: RequestInput = { recognisedStateId: 7n,
  executor: '0x0000000000000000000000000000000000000099' as Address,
  responseClass: hash('55'), parametersHash: hash('66'), burdenHash: hash('77'), validUntil: 1000n };

test('public SDK encodes both explicit authorities in one exact request and Allocation call', () => {
  const call = sdk.createAndApproveRequest(input, creation, allocation);
  assert.equal(call.to, addresses.requests);
  assert.deepEqual(decodeFunctionData({ abi: requestsAbi, data: call.data }), {
    functionName: 'createAndApproveRequest', args: [input, creation.roleKey, creation.authorityId,
      allocation.roleKey, allocation.authorityId],
  });
});

test('compound calls require creation and Allocation authorities without inferring either', () => {
  assert.throws(() => {
    // @ts-expect-error Both authorities are mandatory at the public SDK seam.
    sdk.createAndApproveRequest(input, creation);
  });
  assert.throws(() => {
    // @ts-expect-error A missing creation authority cannot inherit Allocation authority.
    sdk.createAndApproveRequest(input, undefined, allocation);
  });
});

test('separate request and Allocation calls remain available for distinct signers', () => {
  assert.deepEqual(decodeFunctionData({ abi: requestsAbi, data: sdk.createRequest(input, creation).data }),
    { functionName: 'createRequest', args: [input, creation.roleKey, creation.authorityId] });
  assert.deepEqual(decodeFunctionData({ abi: requestsAbi, data: sdk.allocate(8n, allocation).data }),
    { functionName: 'approve', args: [8n, allocation.roleKey, allocation.authorityId] });
  assert.equal((sdk.createAndApproveRequest(input, creation, allocation).data.length - 2) / 2, 324);
  assert.equal((sdk.createRequest(input, creation).data.length + sdk.allocate(8n, allocation).data.length - 4) / 2, 360);
});

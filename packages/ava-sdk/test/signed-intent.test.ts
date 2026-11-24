import assert from 'node:assert/strict';
import { test } from 'node:test';
import { fromRlp, keccak256, parseTransaction, serializeTransaction, toHex, toRlp, type Hex, type TransactionSerializable } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { AvaSigningError } from '../src/signing-errors.ts';
import { verifySignedIntent } from '../src/signed-intent.ts';

// Public Anvil development account, never used on a live chain.
const account = privateKeyToAccount('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80');
const to = '0x0000000000000000000000000000000000000001' as const;
const expected = () => ({ chainId: 31337, account: account.address, call: { to, data: '0x1234' as const, value: 7n } });
const base = { chainId: 31337, to, data: '0x1234' as const, value: 7n, nonce: 4, gas: 100000n };

test('verifies a signed dynamic-fee transaction without submitting it', async () => {
  const raw = await account.signTransaction({ ...base, type: 'eip1559', maxFeePerGas: 10n, maxPriorityFeePerGas: 1n });
  const verified = await verifySignedIntent(raw, expected());
  assert.deepEqual(verified, { hash: keccak256(raw), from: account.address, to, nonce: 4 });
});

test('accepts legacy, access-list and dynamic-fee envelopes', async () => {
  const variants = [
    { ...base, type: 'legacy' as const, gasPrice: 10n },
    { ...base, type: 'eip2930' as const, gasPrice: 10n, accessList: [] },
    { ...base, type: 'eip1559' as const, maxFeePerGas: 10n, maxPriorityFeePerGas: 1n },
  ];
  for (const transaction of variants) {
    const raw = await account.signTransaction(transaction);
    assert.deepEqual(await verifySignedIntent(raw, expected()), { hash: keccak256(raw), from: account.address, to, nonce: 4 });
  }
});

test('refuses mismatched intent and invalid bytes with safe errors, then accepts a valid transaction', async () => {
  const raw = await account.signTransaction({ ...base, type: 'eip1559', maxFeePerGas: 10n, maxPriorityFeePerGas: 1n });
  const other = '0x0000000000000000000000000000000000000002' as const;
  const cases = [
    { raw, intent: { ...expected(), chainId: 1 } },
    { raw, intent: { ...expected(), account: other } },
    { raw, intent: { ...expected(), call: { ...expected().call, to: other } } },
    { raw, intent: { ...expected(), call: { ...expected().call, data: '0xabcd' as const } } },
    { raw, intent: { ...expected(), call: { ...expected().call, value: 8n } } },
    { raw: '0x1234' as Hex, intent: expected() },
    { raw: `${raw}00` as Hex, intent: expected() },
    { raw: `0x04${raw.slice(4)}` as Hex, intent: expected() },
  ];
  for (const item of cases) {
    await assert.rejects(verifySignedIntent(item.raw, item.intent), error => {
      assert(error instanceof AvaSigningError);
      assert.equal(error.stage, 'signing');
      assert.equal(error.code, 'intent_mismatch');
      assert.equal(error.cause, undefined);
      assert(!JSON.stringify(error).includes(raw));
      return true;
    });
  }
  assert.equal((await verifySignedIntent(raw, expected())).nonce, 4);
});

test('rejects noncanonical integer encoding and reflected high-s signatures', async () => {
  const raw = await account.signTransaction({ ...base, nonce: 0, type: 'eip1559', maxFeePerGas: 10n, maxPriorityFeePerGas: 1n });
  const fields = fromRlp(`0x${raw.slice(4)}`, 'hex') as Hex[];
  fields[1] = '0x00';
  const noncanonical = `0x02${toRlp(fields).slice(2)}` as Hex;
  const parsed = parseTransaction(raw);
  assert(parsed.r && parsed.s && parsed.yParity !== undefined);
  const { r, s, v: _v, yParity, ...unsigned } = parsed;
  const order = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
  const highS = serializeTransaction(unsigned as TransactionSerializable, { r,
    s: toHex(order - BigInt(s), { size: 32 }), yParity: yParity === 0 ? 1 : 0 });
  for (const invalid of [noncanonical, highS]) {
    await assert.rejects(verifySignedIntent(invalid, expected()), error =>
      error instanceof AvaSigningError && error.stage === 'signing' && error.code === 'intent_mismatch');
  }
  assert.equal((await verifySignedIntent(raw, expected())).nonce, 0);
});

test('rejects expectation mutation while recovery is pending', async () => {
  const raw = await account.signTransaction({ ...base, type: 'eip1559', maxFeePerGas: 10n, maxPriorityFeePerGas: 1n });
  const intent = expected();
  const pending = verifySignedIntent(raw, intent);
  intent.chainId = 1;
  await assert.rejects(pending, error =>
    error instanceof AvaSigningError && error.stage === 'signing' && error.code === 'intent_mismatch');
  assert.equal((await verifySignedIntent(raw, expected())).nonce, 4);
});

test('rejects a valid authorization-list transaction', async () => {
  const authorization = await account.signAuthorization!({ address: to, chainId: 31337, nonce: 0 });
  const raw = await account.signTransaction({ ...base, type: 'eip7702', maxFeePerGas: 10n,
    maxPriorityFeePerGas: 1n, authorizationList: [authorization] });
  assert.equal(parseTransaction(raw).type, 'eip7702');
  await assert.rejects(verifySignedIntent(raw, expected()), error =>
    error instanceof AvaSigningError && error.stage === 'signing' && error.code === 'intent_mismatch');
});

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { resolve } from 'node:path';

const generator = resolve('scripts/generate_sdk_abi.mjs');
const contracts = ['AVAApplicationRegistry', 'AVAIdentityRegistry', 'AVAAuthorityMatrix',
  'AVACoreRulePackageRegistry', 'AVADisclosurePolicyRegistry', 'AVAEvidenceRegistry',
  'AVAGovernanceKernel', 'AVARequestAllocation', 'AVAChallengeExtension', 'AVACorrectionRegistry',
  'AVAExecutionLifecycle', 'AVADecisionRegistry', 'AVAProcedureAdjudication',
  'AVARecognisedRuleGovernance', 'AVAPrivacyRegistry', 'AVAGovernedDisclosure', 'AVAEvidenceResourceBinding'];

test('ABI check rejects stale source without silently regenerating it', () => {
  const directory = mkdtempSync(resolve('.tmp/release-abi-'));
  try {
    for (const name of contracts) {
      const path = resolve(directory, '.build/out', `${name}.sol`);
      mkdirSync(path, { recursive: true });
      writeFileSync(resolve(path, `${name}.json`), JSON.stringify({ abi: [] }));
    }
    const target = resolve(directory, 'packages/ava-sdk/src/abi.ts');
    mkdirSync(resolve(directory, 'packages/ava-sdk/src'), { recursive: true });
    writeFileSync(target, '// deliberately stale ABI\n');
    const checked = spawnSync(process.execPath, [generator, '--check'], { cwd: directory });
    assert.notEqual(checked.status, 0, 'stale ABI must fail the release');
    assert.equal(readFileSync(target, 'utf8'), '// deliberately stale ABI\n');
    const generated = spawnSync(process.execPath, [generator], { cwd: directory });
    assert.equal(generated.status, 0);
    assert.equal(spawnSync(process.execPath, [generator, '--check'], { cwd: directory }).status, 0);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

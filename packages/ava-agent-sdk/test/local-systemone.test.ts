import assert from 'node:assert/strict';
import test from 'node:test';
import { localSystemOneChoices } from '../src/local-systemone.js';
import type { ChoiceQuestion } from '../src/types.js';

const question: ChoiceQuestion = {
  input: 'Synthetic grant: all four checked prerequisites hold.',
  instructions: 'Pay only when every prerequisite holds.',
  choices: [{ value: '0x01', description: 'Pay the exact grant.' },
    { value: '0x02', description: 'Withhold unsupported payment.' }],
};

test('local System One preserves engine identity and maps the current options without chat generation', async () => {
  const controller = new AbortController();
  const provider = localSystemOneChoices({ id: 'basal-local-mlx', model: 'synthetic-quantized-checkpoint',
    servedModel: 'synthetic-engine-model', systemOne: async (request, signal) => {
      assert.equal(signal, controller.signal);
      assert.deepEqual(request, { state: question.input,
        questions: { ava_option: { type: 'choice', instructions: question.instructions,
          criteria: { '0x01': 'Pay the exact grant.', '0x02': 'Withhold unsupported payment.' } } } });
      return { model: 'synthetic-engine-model', answers: { ava_option: {
        type: 'choice', choice: '0x01', confidence: 0.97, probabilities: { '0x01': 0.97, '0x02': 0.03 },
      } } };
    } });
  assert.equal(provider.id, 'basal-local-mlx');
  assert.equal(provider.model, 'synthetic-quantized-checkpoint');
  assert.deepEqual(await provider.choose(question, controller.signal), {
    kind: 'choice', choice: '0x01', confidence: 0.97, servedModel: 'synthetic-engine-model',
  });
});

test('local engines reject wrong models, invalid choices and cancellation then recover with the same provider', async () => {
  let mode = 'wrong-model';
  let cancel: AbortController | undefined;
  let calls = 0;
  const provider = localSystemOneChoices({ id: 'h2o-local-mlx', model: 'synthetic-q8', servedModel: 'synthetic-base',
    systemOne: async () => {
      calls++;
      if (mode === 'failure') throw new Error('private synthetic provider input');
      cancel?.abort('private synthetic cancellation');
      return { model: mode === 'wrong-model' ? 'another-model' : 'synthetic-base',
        answers: { ava_option: { type: 'choice', choice: mode === 'bad-choice' ? '0xff' : '0x02',
          confidence: mode === 'bad-confidence' ? 1.1 : 0.99 } } };
    } });
  for (mode of ['wrong-model', 'bad-choice', 'bad-confidence', 'failure']) {
    await assert.rejects(provider.choose(question), { message: 'Local System One provider failed' });
  }
  mode = 'valid';
  const pre = new AbortController();
  pre.abort('private synthetic cancellation');
  const before = calls;
  await assert.rejects(provider.choose(question, pre.signal), { message: 'Local System One provider failed' });
  assert.equal(calls, before);
  cancel = new AbortController();
  await assert.rejects(provider.choose(question, cancel.signal), { message: 'Local System One provider failed' });
  cancel = undefined;
  assert.deepEqual(await provider.choose(question), {
    kind: 'choice', choice: '0x02', confidence: 0.99, servedModel: 'synthetic-base',
  });
});

test('local System One exposes sanitised identity and transport error codes', async () => {
  const base = { id: 'local', model: 'model', servedModel: 'expected' };
  assert.throws(() => localSystemOneChoices({ ...base, id: '', systemOne: async () => null }), { code: 'invalid_configuration' });
  assert.throws(() => localSystemOneChoices({ ...base, model: '', systemOne: async () => null }), { code: 'invalid_configuration' });
  const wrong = localSystemOneChoices({ ...base, systemOne: async () => ({ model: 'unexpected' }) });
  await assert.rejects(wrong.choose(question), { code: 'invalid_response', message: 'Local System One provider failed' });
  const failed = localSystemOneChoices({ ...base, systemOne: async () => { throw new Error('secret'); } });
  await assert.rejects(failed.choose(question), { code: 'transport_error', message: 'Local System One provider failed' });
  const controller = new AbortController(); controller.abort('private');
  await assert.rejects(failed.choose(question, controller.signal), { code: 'cancelled', message: 'Local System One provider failed' });
});

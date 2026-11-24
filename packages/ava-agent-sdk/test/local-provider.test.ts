import assert from 'node:assert/strict';
import test from 'node:test';
import { ollamaChoices } from '../src/ollama.js';
import type { ChoiceQuestion } from '../src/types.js';

const question: ChoiceQuestion = {
  input: 'Synthetic authorised input',
  instructions: 'Select one supplied option.',
  choices: [
    { value: '0x01', description: 'Approve' },
    { value: '0x02', description: 'Decline' },
  ],
};

test('the same provider recovers after invalid output, abstention and cancellation', async () => {
  let content = 'not JSON';
  let cancelDuringCall = false;
  const controller = new AbortController();
  const provider = ollamaChoices({
    model: 'explicit-local-model',
    chat: async () => {
      if (cancelDuringCall) controller.abort('synthetic private reason');
      return { done: true, message: { content } };
    },
  });
  await assert.rejects(provider.choose(question), /Ollama provider failed/);
  content = JSON.stringify({ choice: 'abstain' });
  assert.deepEqual(await provider.choose(question), { kind: 'abstain', reason: 'provider_abstained' });
  content = JSON.stringify({ choice: '0x01', confidence: 0.8 });
  cancelDuringCall = true;
  await assert.rejects(provider.choose(question, controller.signal), /Ollama provider failed/);
  cancelDuringCall = false;
  assert.deepEqual(await provider.choose(question, new AbortController().signal), {
    kind: 'choice', choice: '0x01', confidence: 0.8,
  });
});

test('Ollama maps a schema-constrained chat response to the supplied choice', async () => {
  const controller = new AbortController();
  let sent: unknown;
  const provider = ollamaChoices({
    model: 'explicit-local-model',
    chat: async (request, signal) => {
      sent = request;
      assert.equal(signal, controller.signal);
      return {
        model: 'served-local-model',
        done: true,
        message: { content: JSON.stringify({ choice: '0x02', confidence: 0.75 }) },
      };
    },
  });

  assert.equal(provider.id, 'ollama');
  assert.equal(provider.model, 'explicit-local-model');
  assert.deepEqual(await provider.choose(question, controller.signal), {
    kind: 'choice', choice: '0x02', confidence: 0.75, servedModel: 'served-local-model',
  });
  assert.deepEqual(sent, {
    model: 'explicit-local-model',
    messages: [
      { role: 'system', content: 'Select one supplied option. Reply with JSON matching the provided schema.' },
      { role: 'user', content: JSON.stringify({ input: question.input, choices: question.choices }) },
    ],
    stream: false,
    format: {
      type: 'object',
      properties: {
        choice: { type: 'string', enum: ['0x01', '0x02', 'abstain'] },
        confidence: { type: 'number', minimum: 0, maximum: 1 },
      },
      required: ['choice'],
      additionalProperties: false,
    },
  });
});

test('Ollama rejects choices outside the current question', async () => {
  const provider = ollamaChoices({
    model: 'explicit-local-model',
    chat: async () => ({ done: true, message: { content: '{"choice":"0xff"}' } }),
  });
  await assert.rejects(provider.choose(question), /Ollama provider failed/);
});

test('Ollama rejects malformed JSON and unfinished chat responses', async () => {
  for (const response of [
    { done: true, message: { content: 'not-json' } },
    { done: false, message: { content: '{"choice":"0x01"}' } },
  ]) {
    const provider = ollamaChoices({ model: 'explicit-local-model', chat: async () => response });
    await assert.rejects(provider.choose(question), /Ollama provider failed/);
  }
});

test('Ollama respects pre-call and in-flight cancellation', async () => {
  const preAborted = new AbortController();
  preAborted.abort('synthetic private abort reason');
  let called = false;
  const provider = ollamaChoices({
    model: 'explicit-local-model',
    chat: async (_request, signal) => {
      called = true;
      signal?.throwIfAborted();
      return { done: true, message: { content: '{"choice":"0x01"}' } };
    },
  });
  await assert.rejects(provider.choose(question, preAborted.signal), /Ollama provider failed/);
  assert.equal(called, false);

  const duringCall = new AbortController();
  await assert.rejects(ollamaChoices({
    model: 'explicit-local-model',
    chat: async (_request, signal) => {
      assert.equal(signal, duringCall.signal);
      duringCall.abort('synthetic private cancellation');
      return { done: true, message: { content: '{"choice":"0x01"}' } };
    },
  }).choose(question, duringCall.signal), /Ollama provider failed/);
});

test('Ollama hides transport errors, abort details and credentials', async () => {
  const secret = 'synthetic-local-token';
  const provider = ollamaChoices({
    model: 'explicit-local-model',
    chat: async () => { throw new Error(`${secret}: ${question.input}`); },
  });
  await assert.rejects(provider.choose(question), (error: unknown) => {
    assert.ok(error instanceof Error);
    assert.equal(error.message, 'Ollama provider failed');
    assert.equal(error.cause, undefined);
    assert.ok(!String(error).includes(secret));
    assert.ok(!String(error).includes(question.input));
    return true;
  });
});

test('Ollama permits explicit abstention and omits confidence when absent', async () => {
  const abstain = ollamaChoices({
    model: 'explicit-local-model',
    chat: async () => ({ done: true, message: { content: '{"choice":"abstain"}' } }),
  });
  assert.deepEqual(await abstain.choose(question), { kind: 'abstain', reason: 'provider_abstained' });

  const noConfidence = ollamaChoices({
    model: 'explicit-local-model',
    chat: async () => ({ done: true, message: { content: '{"choice":"0x01"}' } }),
  });
  assert.deepEqual(await noConfidence.choose(question), { kind: 'choice', choice: '0x01' });
});

test('Ollama validates confidence only when it is supplied', async () => {
  for (const confidence of [null, '0.5', -0.01, 1.01, Number.NaN, Number.POSITIVE_INFINITY]) {
    const provider = ollamaChoices({
      model: 'explicit-local-model',
      chat: async () => ({ done: true, message: { content: JSON.stringify({ choice: '0x01', confidence }) } }),
    });
    await assert.rejects(provider.choose(question), /Ollama provider failed/);
  }
});

test('Ollama preserves abstention metadata and sanitised error codes', async () => {
  const provider = ollamaChoices({ model: 'local', chat: async () => ({ model: 'served', done: true,
    message: { content: '{"choice":"abstain"}' } }) });
  assert.deepEqual(await provider.choose(question), { kind: 'abstain', reason: 'provider_abstained', servedModel: 'served' });
  const bad = ollamaChoices({ model: 'local', chat: async () => ({ done: true, message: { content: 'bad' } }) });
  await assert.rejects(bad.choose(question), { code: 'invalid_response', message: 'Ollama provider failed' });
  const timeout = ollamaChoices({ model: 'local', chat: async () => { throw new DOMException('secret', 'TimeoutError'); } });
  await assert.rejects(timeout.choose(question), { code: 'timeout', message: 'Ollama provider failed' });
  const controller = new AbortController(); controller.abort('secret');
  await assert.rejects(provider.choose(question, controller.signal), { code: 'cancelled', message: 'Ollama provider failed' });
  assert.throws(() => ollamaChoices({ model: '', chat: async () => null }), { code: 'invalid_configuration' });
});

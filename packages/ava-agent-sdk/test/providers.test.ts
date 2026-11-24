import assert from 'node:assert/strict';
import test from 'node:test';
import { jevChoices, openAIChoices, openAIDecisions } from '../src/providers.js';
import type { ChoiceQuestion } from '../src/types.js';
import { AvaAgentError, type AgentErrorCode } from '../src/errors.js';

test('a JavaScript provider cannot smuggle a private value through a mutated structured error code', async () => {
  const provider = openAIChoices({ model: 'test', create: async () => {
    const error = new AvaAgentError('timeout');
    Object.assign(error, { code: 'SYNTHETIC_PRIVATE_ERROR_CODE' });
    throw error;
  } });
  await assert.rejects(provider.choose(question), error => {
    assert.equal((error as AvaAgentError).code, 'transport_error');
    assert.doesNotMatch(JSON.stringify(error), /SYNTHETIC_PRIVATE_ERROR_CODE/);
    return true;
  });
  assert.equal(new AvaAgentError('SYNTHETIC_PRIVATE_ERROR_CODE' as AgentErrorCode).code, 'transport_error');
});

test('provider errors expose safe codes without leaking transport details', async () => {
  const sdk = await import('../src/index.ts');
  const provider = openAIChoices({ model: 'test', create: async () => {
    throw new DOMException('SYNTHETIC_SECRET_TIMEOUT', 'TimeoutError');
  } });
  await assert.rejects(provider.choose(question), error => {
    assert.equal((error as { code?: string }).code, 'timeout');
    assert(error instanceof sdk.AvaAgentError);
    assert(!String(error).includes('SYNTHETIC_SECRET_TIMEOUT'));
    assert.equal(error.cause, undefined);
    return true;
  });
});

const question: ChoiceQuestion = {
  input: 'Synthetic application-authorised input',
  instructions: 'Choose the supported action.',
  choices: [
    { value: '0x01', description: 'Approve' },
    { value: '0x02', description: 'Decline' },
  ],
};

test('OpenAI sends the exact choices and returns a validated answer with provider metadata', async () => {
  const controller = new AbortController();
  const provider = openAIChoices({
    model: 'explicit-openai-model',
    create: async (request, signal) => {
      assert.deepEqual(request, {
        model: 'explicit-openai-model',
        input: 'Synthetic application-authorised input',
        questions: [{
          type: 'choice',
          name: 'ava_option',
          instructions: 'Choose the supported action.',
          choices: [
            { value: '0x01', description: 'Approve' },
            { value: '0x02', description: 'Decline' },
          ],
        }],
      });
      assert.equal(signal, controller.signal);
      return {
        id: 'decision-synthetic', model: 'served-openai-model',
        answers: [{ type: 'choice', name: 'ava_option', choice: '0x02', confidence: 0.8 }],
      };
    },
  });
  assert.equal(provider.id, 'openai');
  assert.equal(provider.model, 'explicit-openai-model');
  assert.deepEqual(await provider.choose(question, controller.signal), {
    kind: 'choice', choice: '0x02', confidence: 0.8,
    responseId: 'decision-synthetic', servedModel: 'served-openai-model',
  });
});

test('Jev sends literal criteria for all choices and preserves valid optional metadata', async () => {
  const controller = new AbortController();
  const provider = jevChoices({
    model: 'explicit-jev-model',
    systemOne: async (request, signal) => {
      assert.deepEqual(request, {
        model: 'explicit-jev-model',
        state: { input: 'Synthetic application-authorised input' },
        questions: {
          ava_option: {
            type: 'choice', instructions: 'Choose the supported action.',
            criteria: { '0x01': 'Approve', '0x02': 'Decline' },
          },
        },
      });
      assert.equal(signal, controller.signal);
      return {
        id: 'jev-synthetic', model: 'served-jev-model',
        answers: { ava_option: { type: 'choice', choice: '0x01', confidence: 1, probabilities: { '0x01': 1 } } },
      };
    },
  });
  assert.equal(provider.id, 'jev');
  assert.equal(provider.model, 'explicit-jev-model');
  assert.deepEqual(await provider.choose(question, controller.signal), {
    kind: 'choice', choice: '0x01', confidence: 1,
    responseId: 'jev-synthetic', servedModel: 'served-jev-model',
  });
});

test('OpenAI refusal abstains without exposing provider response text', async () => {
  const provider = openAIChoices({
    model: 'explicit-model',
    create: async () => ({
      id: 'refusal-1', model: 'served-model',
      answers: [{ name: 'ava_option', type: 'refusal', reason: 'private refusal details' }],
    }),
  });
  assert.deepEqual(await provider.choose(question), { kind: 'abstain', reason: 'provider_refusal',
    responseId: 'refusal-1', servedModel: 'served-model' });
});

test('OpenAI adapters abstain below two choices without a request or fabricated choices and remain usable', async () => {
  for (const preset of [false, true]) {
    let calls = 0;
    const create = async (request: { questions: { choices: ChoiceQuestion['choices'] }[] }) => {
      calls++;
      assert.deepEqual(request.questions[0].choices, question.choices);
      return { answers: [{ type: 'choice', name: 'ava_option', choice: '0x02', confidence: 0.8 }] };
    };
    const provider = preset ? openAIDecisions({ client: { decisions: { create } } })
      : openAIChoices({ model: 'gpt-6-luna', create });
    for (const choices of [[], question.choices.slice(0, 1)]) {
      const insufficient = { ...question, choices };
      const before = structuredClone(insufficient);
      assert.deepEqual(await provider.choose(insufficient), { kind: 'abstain', reason: 'insufficient_options' });
      assert.deepEqual(insufficient, before);
      assert.equal(calls, 0);
    }
    assert.deepEqual(await provider.choose(question), { kind: 'choice', choice: '0x02', confidence: 0.8 });
    assert.equal(calls, 1);
  }
});

test('OpenAI insufficient-choice abstention does not mask cancellation', async () => {
  const controller = new AbortController();
  controller.abort('private cancellation');
  const provider = openAIDecisions({ client: { decisions: { create: async () => {
    assert.fail('Insufficient choices or cancellation must not send material');
  } } } });
  for (const choices of [[], question.choices.slice(0, 1)]) {
    await assert.rejects(provider.choose({ ...question, choices }, controller.signal), (error: unknown) => {
      assert.ok(error instanceof Error);
      assert.equal(error.message, 'OpenAI provider failed');
      return true;
    });
  }
  assert.deepEqual(await provider.choose({ ...question, choices: question.choices.slice(0, 1) }),
    { kind: 'abstain', reason: 'insufficient_options' });
});

const adapters = [
  {
    name: 'OpenAI',
    make: (call: (signal?: AbortSignal) => Promise<unknown>) => openAIChoices({
      model: 'explicit-model', create: async (_request, signal) => call(signal),
    }),
    response: (answer: unknown) => ({ answers: [answer] }),
    answer: { name: 'ava_option', type: 'choice', choice: '0x01', confidence: 0.6 },
  },
  {
    name: 'Jev',
    make: (call: (signal?: AbortSignal) => Promise<unknown>) => jevChoices({
      model: 'explicit-model', systemOne: async (_request, signal) => call(signal),
    }),
    response: (answer: unknown) => ({ answers: { ava_option: answer } }),
    answer: { type: 'choice', choice: '0x01', confidence: 0.6 },
  },
];

for (const adapter of adapters) {
  test(`${adapter.name} accepts a valid answer without inventing optional metadata`, async () => {
    const provider = adapter.make(async () => adapter.response(adapter.answer));
    assert.deepEqual(await provider.choose(question), { kind: 'choice', choice: '0x01', confidence: 0.6 });
  });

  test(`${adapter.name} rejects out-of-set choices, malformed answer types and confidence`, async () => {
    const invalidAnswers = [
      null, [], 'private raw response',
      { ...adapter.answer, type: 'unknown' },
      { ...adapter.answer, choice: '0x03' },
      { ...adapter.answer, choice: null },
      ...[undefined, null, '0.6', NaN, Infinity, -0.1, 1.1].map((confidence) => ({ ...adapter.answer, confidence })),
    ];
    for (const answer of invalidAnswers) {
      await assert.rejects(adapter.make(async () => adapter.response(answer)).choose(question), new RegExp(adapter.name));
    }
  });

  test(`${adapter.name} validates optional response IDs and served models when supplied`, async () => {
    for (const metadata of [
      { id: 1 }, { id: null }, { id: '' }, { model: false }, { model: null }, { model: '' },
    ]) {
      await assert.rejects(adapter.make(async () => ({
        ...adapter.response(adapter.answer), ...metadata,
      })).choose(question), new RegExp(adapter.name));
    }
  });

  test(`${adapter.name} rejects malformed envelopes without leaking raw response text`, async () => {
    for (const response of [null, [], 'private raw response', {}, { answers: null }, { answers: [] }]) {
      await assert.rejects(adapter.make(async () => response).choose(question), (error: unknown) => {
        assert.ok(error instanceof Error);
        assert.match(error.message, new RegExp(adapter.name));
        assert.ok(!String(error).includes('private raw response'));
        return true;
      });
    }
  });

  test(`${adapter.name} client failure hides private input, credentials and error cause`, async () => {
    const secret = 'synthetic-secret-credential';
    const provider = adapter.make(async () => {
      throw new Error(`${secret}: ${question.input}`, { cause: { body: question.input } });
    });
    await assert.rejects(provider.choose(question), (error: unknown) => {
      assert.ok(error instanceof Error);
      assert.match(error.message, new RegExp(adapter.name));
      assert.ok(!String(error).includes(secret));
      assert.ok(!String(error).includes(question.input));
      assert.equal(error.cause, undefined);
      assert.deepEqual(Object.keys(error), ['code']);
      return true;
    });
  });

  test(`${adapter.name} pre-abort never calls the client and hides the abort reason`, async () => {
    const controller = new AbortController();
    controller.abort('private abort reason');
    let called = false;
    const provider = adapter.make(async () => {
      called = true;
      return adapter.response(adapter.answer);
    });
    await assert.rejects(provider.choose(question, controller.signal), (error: unknown) => {
      assert.ok(error instanceof Error);
      assert.match(error.message, new RegExp(adapter.name));
      assert.ok(!String(error).includes('private abort reason'));
      return true;
    });
    assert.equal(called, false);
  });

  test(`${adapter.name} rejects a successful client result if cancellation happened during the call`, async () => {
    const controller = new AbortController();
    const provider = adapter.make(async (signal) => {
      assert.equal(signal, controller.signal);
      controller.abort('private cancellation');
      return adapter.response(adapter.answer);
    });
    await assert.rejects(provider.choose(question, controller.signal), new RegExp(adapter.name));
  });
}

test('OpenAI rejects the wrong question name, duplicate answers and empty answers', async () => {
  for (const answers of [
    [{ name: 'another_question', type: 'choice', choice: '0x01', confidence: 0.9 }],
    [{ type: 'choice', choice: '0x01', confidence: 0.9 }],
    [{ name: 'ava_option', type: 'refusal' }, { name: 'ava_option', type: 'refusal' }],
    [],
  ]) {
    await assert.rejects(openAIChoices({ model: 'explicit-model', create: async () => ({ answers }) }).choose(question), /OpenAI/);
  }
});

test('Jev rejects wrong question keys, extra answers and undocumented refusal', async () => {
  const answer = { type: 'choice', choice: '0x01', confidence: 0.9 };
  for (const answers of [
    { another_question: answer },
    { ava_option: answer, extra_question: answer },
    { ava_option: { type: 'refusal' } },
    {},
  ]) {
    await assert.rejects(jevChoices({ model: 'explicit-model', systemOne: async () => ({ answers }) }).choose(question), /Jev/);
  }
});

test('Both adapters require an explicit non-empty model', () => {
  for (const model of ['', '  ', undefined as unknown as string]) {
    assert.throws(() => openAIChoices({ model, create: async () => null }), /OpenAI/);
    assert.throws(() => jevChoices({ model, systemOne: async () => null }), /Jev/);
  }
});


test('OpenAI Decisions preset defaults the model and preserves the client receiver and signal', async () => {
  const controller = new AbortController();
  const decisions = { marker: 'bound', async create(request: { model: string }, options?: { signal?: AbortSignal }) {
    assert.equal(this.marker, 'bound');
    assert.equal(request.model, 'gpt-6-luna');
    assert.equal(options?.signal, controller.signal);
    return { answers: [{ type: 'choice', name: 'ava_option', choice: '0x01', confidence: 0.8 }] };
  } };
  const provider = openAIDecisions({ client: { decisions } });
  assert.equal(provider.model, 'gpt-6-luna');
  assert.deepEqual(await provider.choose(question, controller.signal), { kind: 'choice', choice: '0x01', confidence: 0.8 });
});

test('OpenAI Decisions preset accepts an explicit model and validates refusal and invalid answers', async () => {
  let response: unknown = { answers: [{ type: 'refusal', name: 'ava_option', reason: 'private details' }] };
  const client = { decisions: { async create(request: { model: string }) {
    assert.equal(request.model, 'chosen-model');
    return response;
  } } };
  const provider = openAIDecisions({ client, model: 'chosen-model' });
  assert.equal(provider.model, 'chosen-model');
  assert.deepEqual(await provider.choose(question), { kind: 'abstain', reason: 'provider_refusal' });
  response = { answers: [{ type: 'choice', name: 'ava_option', choice: 'outside', confidence: 1 }] };
  await assert.rejects(provider.choose(question), /OpenAI provider failed/);
  assert.throws(() => openAIDecisions({ client, model: '  ' }), /explicit model/);
});

test('OpenAI Decisions preset sanitises client errors', async () => {
  const client = { decisions: { async create() { throw new Error(`secret ${question.input}`); } } };
  await assert.rejects(openAIDecisions({ client }).choose(question), (error: unknown) => {
    assert.ok(error instanceof Error);
    assert.equal(error.message, 'OpenAI provider failed');
    assert.equal(error.cause, undefined);
    return true;
  });
});

test('Decisions preset interoperates with the official OpenAI client without a runtime dependency in the Agent SDK', async () => {
  const { default: OpenAI } = await import('openai');
  const { openAIDecisions } = await import('../src/providers.js');
  let calls = 0;
  const controller = new AbortController();
  const client = new OpenAI({ apiKey: 'sk-synthetic-transport-only', maxRetries: 0, timeout: 1000,
    fetch: async (url, init) => {
      calls++;
      assert.equal(String(url), 'https://api.openai.com/v1/decisions');
      assert.equal(new Headers(init?.headers).get('authorization'), 'Bearer sk-synthetic-transport-only');
      const body = JSON.parse(String(init?.body));
      assert.equal(body.model, 'gpt-6-luna');
      assert.deepEqual(body.questions[0].choices, question.choices);
      return Response.json({ id: 'dec-official-client-fixture', model: 'gpt-6-luna', answers: [
        { type: 'choice', name: 'ava_option', choice: '0x01', confidence: 0.9 },
      ] });
    },
  });
  const answer = await openAIDecisions({ client }).choose(question, controller.signal);
  assert.equal(answer.kind, 'choice');
  if (answer.kind === 'choice') assert.equal(answer.choice, '0x01');
  assert.equal(calls, 1);
});

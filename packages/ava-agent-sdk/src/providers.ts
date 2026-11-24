import type { ChoiceAnswer, ChoiceProvider, ChoiceQuestion } from './types.js';
import { AvaAgentError, providerFailure } from './errors.js';

export interface OpenAIChoiceRequest {
  model: string;
  input: string;
  questions: {
    type: 'choice';
    name: 'ava_option';
    instructions: string;
    choices: ChoiceQuestion['choices'];
  }[];
}

export interface JevChoiceRequest {
  model: string;
  state: { input: string };
  questions: {
    ava_option: {
      type: 'choice';
      instructions: string;
      criteria: Record<string, string>;
    };
  };
}

function invalid(provider: string): never {
  throw new AvaAgentError('invalid_response', `${provider} provider returned an invalid response`);
}

async function sanitised(
  provider: string,
  signal: AbortSignal | undefined,
  call: () => Promise<ChoiceAnswer>,
): Promise<ChoiceAnswer> {
  try {
    if (signal?.aborted) throw new Error('aborted');
    const answer = await call();
    if (signal?.aborted) throw new Error('aborted');
    return answer;
  } catch (error) {
    // Client errors can include request text, credentials or response bodies.
    throw providerFailure(error, signal, `${provider} provider failed`);
  }
}

function object(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function validateMetadata(provider: string, response: Record<string, unknown>): void {
  if ((response.id !== undefined && (typeof response.id !== 'string' || response.id.length === 0))
    || (response.model !== undefined && (typeof response.model !== 'string' || response.model.length === 0))) {
    invalid(provider);
  }
}

function choiceAnswer(
  provider: string,
  response: Record<string, unknown>,
  answer: Record<string, unknown>,
  question: ChoiceQuestion,
): ChoiceAnswer {
  if (answer.type !== 'choice' || typeof answer.choice !== 'string'
    || !question.choices.some(({ value }) => value === answer.choice)
    || typeof answer.confidence !== 'number' || !Number.isFinite(answer.confidence)
    || answer.confidence < 0 || answer.confidence > 1) invalid(provider);
  validateMetadata(provider, response);
  return {
    kind: 'choice', choice: answer.choice, confidence: answer.confidence,
    ...(response.id !== undefined ? { responseId: response.id as string } : {}),
    ...(response.model !== undefined ? { servedModel: response.model as string } : {}),
  };
}

export function openAIChoices({ model, create }: {
  model: string;
  create: (request: OpenAIChoiceRequest, signal?: AbortSignal) => Promise<unknown>;
}): ChoiceProvider {
  if (typeof model !== 'string' || model.trim().length === 0) {
    throw new AvaAgentError('invalid_configuration', 'OpenAI provider requires an explicit model');
  }
  return {
    id: 'openai',
    model,
    async choose(question, signal) {
      return sanitised('OpenAI', signal, async () => {
        // Decisions Choice requires at least two options; legality alone does not justify acting.
        if (question.choices.length < 2) return { kind: 'abstain', reason: 'insufficient_options' };
        const response = await create({
          model,
          input: question.input,
          questions: [{
            type: 'choice', name: 'ava_option', instructions: question.instructions,
            choices: question.choices.map(({ value, description }) => ({ value, description })),
          }],
        }, signal);
        if (!object(response) || !Array.isArray(response.answers) || response.answers.length !== 1) {
          invalid('OpenAI');
        }
        const answer: unknown = response.answers[0];
        if (!object(answer) || answer.name !== 'ava_option') invalid('OpenAI');
        if (answer.type === 'refusal') {
          validateMetadata('OpenAI', response);
          return { kind: 'abstain', reason: 'provider_refusal',
            ...(response.id !== undefined ? { responseId: response.id as string } : {}),
            ...(response.model !== undefined ? { servedModel: response.model as string } : {}) };
        }
        return choiceAnswer('OpenAI', response, answer, question);
      });
    },
  };
}

export function openAIDecisions({ client, model = 'gpt-6-luna' }: {
  client: { decisions: { create: (request: OpenAIChoiceRequest, options?: { signal?: AbortSignal }) => PromiseLike<unknown> } };
  model?: string;
}): ChoiceProvider {
  return openAIChoices({ model, create: async (request, signal) => client.decisions.create(request, { signal }) });
}

export function jevChoices({ model, systemOne }: {
  model: string;
  systemOne: (request: JevChoiceRequest, signal?: AbortSignal) => Promise<unknown>;
}): ChoiceProvider {
  if (typeof model !== 'string' || model.trim().length === 0) {
    throw new AvaAgentError('invalid_configuration', 'Jev provider requires an explicit model');
  }
  return {
    id: 'jev',
    model,
    async choose(question, signal) {
      return sanitised('Jev', signal, async () => {
        const response = await systemOne({
          model,
          state: { input: question.input },
          questions: {
            ava_option: {
              type: 'choice', instructions: question.instructions,
              criteria: Object.fromEntries(question.choices.map(({ value, description }) => [value, description])),
            },
          },
        }, signal);
        if (!object(response) || !object(response.answers)
          || Object.keys(response.answers).length !== 1 || !object(response.answers.ava_option)) {
          invalid('Jev');
        }
        return choiceAnswer('Jev', response, response.answers.ava_option, question);
      });
    },
  };
}

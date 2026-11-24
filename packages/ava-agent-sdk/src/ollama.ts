import type { ChoiceAnswer, ChoiceProvider, ChoiceQuestion } from './types.js';
import { AvaAgentError, providerFailure } from './errors.js';

export interface OllamaChatRequest {
  model: string;
  messages: { role: 'system' | 'user'; content: string }[];
  stream: false;
  format: {
    type: 'object';
    properties: {
      choice: { type: 'string'; enum: string[] };
      confidence: { type: 'number'; minimum: 0; maximum: 1 };
    };
    required: ['choice'];
    additionalProperties: false;
  };
}

function object(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function failed(): never {
  throw new AvaAgentError('invalid_response', 'Ollama provider failed');
}

export function ollamaChoices({ model, chat }: {
  model: string;
  chat: (request: OllamaChatRequest, signal?: AbortSignal) => Promise<unknown>;
}): ChoiceProvider {
  if (typeof model !== 'string' || model.trim().length === 0) {
    throw new AvaAgentError('invalid_configuration', 'Ollama provider requires an explicit model');
  }

  return {
    id: 'ollama',
    model,
    async choose(question: ChoiceQuestion, signal?: AbortSignal): Promise<ChoiceAnswer> {
      try {
        if (signal?.aborted) failed();
        const response = await chat({
          model,
          messages: [
            { role: 'system', content: `${question.instructions} Reply with JSON matching the provided schema.` },
            { role: 'user', content: JSON.stringify({ input: question.input, choices: question.choices }) },
          ],
          stream: false,
          format: {
            type: 'object',
            properties: {
              choice: { type: 'string', enum: [...question.choices.map(({ value }) => value), 'abstain'] },
              confidence: { type: 'number', minimum: 0, maximum: 1 },
            },
            required: ['choice'],
            additionalProperties: false,
          },
        }, signal);
        if (signal?.aborted || !object(response) || response.done !== true
          || !object(response.message) || typeof response.message.content !== 'string'
          || (response.model !== undefined && (typeof response.model !== 'string' || response.model.length === 0))) failed();

        let parsed: unknown;
        try { parsed = JSON.parse(response.message.content); } catch { failed(); }
        if (!object(parsed) || Object.keys(parsed).some((key) => key !== 'choice' && key !== 'confidence')
          || typeof parsed.choice !== 'string') failed();
        if (parsed.confidence !== undefined && (typeof parsed.confidence !== 'number'
          || !Number.isFinite(parsed.confidence) || parsed.confidence < 0 || parsed.confidence > 1)) failed();
        if (parsed.choice === 'abstain') return { kind: 'abstain', reason: 'provider_abstained',
          ...(response.model !== undefined ? { servedModel: response.model } : {}) };
        if (!question.choices.some(({ value }) => value === parsed.choice)) failed();

        return {
          kind: 'choice',
          choice: parsed.choice,
          ...(parsed.confidence !== undefined ? { confidence: parsed.confidence } : {}),
          ...(response.model !== undefined ? { servedModel: response.model } : {}),
        };
      } catch (error) {
        // The transport and abort reason can contain private request or credential data.
        throw providerFailure(error, signal, 'Ollama provider failed');
      }
    },
  };
}

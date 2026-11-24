import { jevChoices, type JevChoiceRequest } from './providers.js';
import type { ChoiceProvider } from './types.js';
import { AvaAgentError, providerFailure } from './errors.js';

/** Local H2O/Basal engines accept plain text state and return the caller's AVA option keys. */
export interface LocalSystemOneRequest {
  state: string;
  questions: JevChoiceRequest['questions'];
}

/** Application-owned transport adapter. Reuses the SDK's typed-choice validation, never a signer. */
export function localSystemOneChoices({ id, model, servedModel, systemOne }: {
  id: string;
  model: string;
  servedModel: string;
  systemOne: (request: LocalSystemOneRequest, signal?: AbortSignal) => Promise<unknown>;
}): ChoiceProvider {
  if (typeof id !== 'string' || !id.trim() || typeof servedModel !== 'string' || !servedModel.trim())
    throw new AvaAgentError('invalid_configuration', 'Local provider requires explicit engine identity');
  if (typeof model !== 'string' || !model.trim())
    throw new AvaAgentError('invalid_configuration', 'Jev provider requires an explicit model');
  const typed = jevChoices({ model, systemOne: async (request, signal) => {
    const response = await systemOne({ state: request.state.input,
      questions: request.questions }, signal);
    if (typeof response !== 'object' || response === null || !('model' in response)
      || response.model !== servedModel) throw new AvaAgentError('invalid_response', 'Unexpected local served model');
    return response;
  } });
  return { id, model, async choose(question, signal) {
    try { return await typed.choose(question, signal); }
    catch (error) { throw providerFailure(error, signal, 'Local System One provider failed'); }
  } };
}

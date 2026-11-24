export type AgentErrorCode = 'cancelled' | 'timeout' | 'transport_error' | 'invalid_response'
  | 'invalid_configuration' | 'invalid_advice';
const codes: readonly AgentErrorCode[] = ['cancelled', 'timeout', 'transport_error', 'invalid_response',
  'invalid_configuration', 'invalid_advice'];

/** Only stable codes and a caller-controlled safe message cross the provider boundary. */
export class AvaAgentError extends Error {
  constructor(readonly code: AgentErrorCode, message = 'Agent provider request failed') {
    super(message);
    // Public JavaScript callbacks are not constrained by TypeScript's union at runtime.
    if (!codes.includes(code)) this.code = 'transport_error';
    Object.defineProperty(this, 'name', { value: 'AvaAgentError' });
  }
}

/** Internal adapter helper: never retain an upstream message, body, stack or cause. */
export function providerFailure(error: unknown, signal?: AbortSignal,
    message = 'Agent provider request failed'): AvaAgentError {
  const name = signal?.aborted ? (signal.reason instanceof Error ? signal.reason.name : '')
    : error instanceof Error ? error.name : '';
  const code = name === 'TimeoutError' || name === 'APIConnectionTimeoutError' ? 'timeout'
    : signal?.aborted || name === 'AbortError' || name === 'APIUserAbortError' ? 'cancelled'
      : error instanceof AvaAgentError ? error.code : error instanceof SyntaxError ? 'invalid_response' : 'transport_error';
  return new AvaAgentError(code, message);
}

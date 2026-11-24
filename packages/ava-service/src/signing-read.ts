import type { Address, Hex, PublicClient } from 'viem';

type Reply = { result: unknown } | { error: { code: number; message: string; data?: Hex } };
const invalid = { error: { code: -32602, message: 'Invalid parameters' } } as const;
const missing = { error: { code: -32601, message: 'Method not found' } } as const;
const address = (value: unknown): value is Address => typeof value === 'string' && /^0x[0-9a-fA-F]{40}$/.test(value);
const quantity = (value: unknown): value is Hex => typeof value === 'string' && /^0x(?:0|[1-9a-fA-F][0-9a-fA-F]{0,63})$/.test(value);
const record = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);
const keys = (value: Record<string, unknown>, allowed: readonly string[]) => Object.keys(value).every(key => allowed.includes(key));
const blockTag = (value: unknown) => quantity(value) || (typeof value === 'string' && ['latest', 'earliest', 'pending', 'safe', 'finalized'].includes(value));
const callBlock = (value: unknown) => blockTag(value) || (record(value) && keys(value, ['blockHash', 'requireCanonical']) &&
  typeof value.blockHash === 'string' && /^0x[0-9a-fA-F]{64}$/.test(value.blockHash) &&
  (value.requireCanonical === undefined || typeof value.requireCanonical === 'boolean'));

export function createSigningReadDispatcher({ client, allowedTargets, maxGas = 30_000_000n }: {
  client: Pick<PublicClient, 'request'>; allowedTargets: readonly Address[]; maxGas?: bigint;
}): (actor: Address, input: unknown) => Promise<Reply> {
  if (maxGas <= 0n || maxGas >= 2n ** 256n || !allowedTargets.every(address)) throw new Error('Invalid signing read configuration');
  const targets = new Set(allowedTargets.map(value => value.toLowerCase()));
  const target = (value: unknown) => address(value) && targets.has(value.toLowerCase());
  return async (actor, input) => {
    if (!record(input) || !keys(input, ['method', 'params']) || typeof input.method !== 'string') return invalid;
    const method = input.method;
    if (!['eth_chainId', 'eth_getBlockByNumber', 'eth_getTransactionCount', 'eth_gasPrice', 'eth_maxPriorityFeePerGas', 'eth_call', 'eth_estimateGas', 'eth_getCode'].includes(method)) return missing;
    if (!address(actor) || (input.params !== undefined && !Array.isArray(input.params))) return invalid;
    const params = (input.params ?? []) as unknown[];
    let forwarded = params;
    if (['eth_chainId', 'eth_gasPrice', 'eth_maxPriorityFeePerGas'].includes(method)) {
      if (params.length !== 0) return invalid;
    } else if (method === 'eth_getBlockByNumber') {
      if (params.length !== 2 || !blockTag(params[0]) || params[1] !== false) return invalid;
    } else if (method === 'eth_getTransactionCount') {
      if (params.length !== 2 || !address(params[0]) || params[0].toLowerCase() !== actor.toLowerCase() || !blockTag(params[1])) return invalid;
    } else if (method === 'eth_getCode') {
      if (params.length !== 2 || !target(params[0]) || !blockTag(params[1])) return invalid;
    } else {
      const tx = params[0];
      if (params.length < 1 || params.length > 2 || !record(tx) || !keys(tx, ['from', 'to', 'data', 'value', 'gas', 'gasPrice', 'maxFeePerGas', 'maxPriorityFeePerGas', 'nonce']) ||
        !address(tx.from) || tx.from.toLowerCase() !== actor.toLowerCase() || !target(tx.to) ||
        (tx.data !== undefined && (typeof tx.data !== 'string' || tx.data.length > 262146 || !/^0x(?:[0-9a-fA-F]{2})*$/.test(tx.data))) ||
        ['value', 'gas', 'gasPrice', 'maxFeePerGas', 'maxPriorityFeePerGas', 'nonce'].some(key => tx[key] !== undefined && !quantity(tx[key])) ||
        (tx.gas !== undefined && BigInt(tx.gas as string) > maxGas) ||
        (params.length === 2 && !(method === 'eth_call' ? callBlock(params[1]) : blockTag(params[1])))) return invalid;
      forwarded = [{ ...tx, gas: tx.gas ?? `0x${maxGas.toString(16)}` }, ...params.slice(1)];
    }
    const request = client.request as (request: { method: string; params: unknown[] }, options: { retryCount: number }) => Promise<unknown>;
    try {
      return { result: await request({ method, params: forwarded }, { retryCount: 0 }) };
    } catch (error) {
      if (method === 'eth_call' || method === 'eth_estimateGas') {
        let cause: unknown = error;
        for (let i = 0; i < 8 && record(cause); i++, cause = cause.cause) {
          if ((cause.code === 3 || (cause.code === -32000 && typeof cause.message === 'string' && /^execution reverted(?:\b|$)/i.test(cause.message))) &&
            typeof cause.data === 'string' && cause.data.length <= 262146 && /^0x(?:[0-9a-fA-F]{2})*$/.test(cause.data)) {
            return { error: { code: 3, message: 'Execution reverted', data: cause.data as Hex } };
          }
        }
      }
      return { error: { code: -32603, message: 'Upstream request failed' } };
    }
  };
}

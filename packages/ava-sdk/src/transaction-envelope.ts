/** Envelopes covered by AVA call simulation and signed-intent verification. */
export function isSupportedTransactionType(type: string | undefined): boolean {
  return type === 'legacy' || type === 'eip2930' || type === 'eip1559';
}

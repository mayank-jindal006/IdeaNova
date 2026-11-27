export function exportAvailability(status) {
  if (status?.eligible === true && /^[0-9a-f]{64}$/.test(status.proposal_digest || '')) return status;
  return { eligible: false, reason: typeof status?.reason === 'string' ? status.reason : 'Export eligibility could not be verified.' };
}

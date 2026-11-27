export function scanDuration(start, finish) {
  if (typeof start !== 'string' || typeof finish !== 'string') return null;
  const from = Date.parse(start), to = Date.parse(finish);
  return Number.isFinite(from) && Number.isFinite(to) && to >= from ? Math.round((to - from) / 1000) : null;
}

export function scanOutcome(status, scanners) {
  if (status === 'failed') return 'failed';
  if (status !== 'done') return 'running';
  const values = [scanners?.secrets?.status, scanners?.dependencies?.status];
  return values.every((value) => value === 'completed' || value === 'empty') ? 'success' : 'partial';
}

export function scanCommit(value) {
  return typeof value === 'string' && /^[a-f0-9]{40}$/i.test(value) ? value.slice(0, 10) : 'Unavailable';
}

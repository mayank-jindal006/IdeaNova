import test from 'node:test';
import assert from 'node:assert/strict';
import { scanCommit, scanDuration, scanOutcome } from './scanPresentation.js';
import { securityApi } from './securityApi.js';
import { exportAvailability } from './exportPresentation.js';

test('scan metadata preserves real values and rejects missing or malformed values', () => {
  assert.equal(scanDuration('2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'), 0);
  assert.equal(scanDuration('bad', '2026-01-01T00:00:00Z'), null);
  assert.equal(scanDuration(null, null), null);
  assert.equal(scanDuration('2026-01-02T00:00:00Z', '2026-01-01T00:00:00Z'), null);
  assert.equal(scanCommit('a'.repeat(40)), 'aaaaaaaaaa');
  assert.equal(scanCommit(null), 'Unavailable');
  assert.equal(scanCommit({}), 'Unavailable');
});

test('scan outcome never promotes incomplete scanner results to full success', () => {
  assert.equal(scanOutcome('failed', {}), 'failed');
  assert.equal(scanOutcome('running', {}), 'running');
  assert.equal(scanOutcome('done', { secrets: { status: 'completed' }, dependencies: { status: 'empty' } }), 'success');
  for (const status of ['fallback', 'unavailable', 'failed', 'skipped', undefined]) {
    assert.equal(scanOutcome('done', { secrets: { status }, dependencies: { status: 'completed' } }), 'partial');
  }
  assert.equal(scanOutcome('done', null), 'partial');
});

function setup(token = 'token') {
  let value = token;
  globalThis.sessionStorage = { getItem: () => value, setItem: (_key, next) => { value = next; }, removeItem: () => { value = null; } };
  let events = 0;
  globalThis.window = { dispatchEvent: () => { events += 1; } };
  return { get token() { return value; }, get events() { return events; } };
}

test('export control requires explicit server eligibility and a valid digest', () => {
  assert.equal(exportAvailability({ eligible: true, proposal_digest: 'a'.repeat(64) }).eligible, true);
  for (const value of [null, {}, { eligible: 'true', proposal_digest: 'a'.repeat(64) }, { eligible: true, proposal_digest: 'invalid' }]) {
    assert.equal(exportAvailability(value).eligible, false);
  }
  assert.equal(exportAvailability({ eligible: false, reason: 'Approval required' }).reason, 'Approval required');
});

test('patch export checks eligibility and downloads the authenticated archive', async () => {
  setup();
  const blob = new Blob(['synthetic-archive'], { type: 'application/zip' });
  globalThis.fetch = async (url, options) => {
    assert.equal(options.headers.Authorization, 'Bearer token');
    if (url.endsWith('/export-status')) return { ok: true, json: async () => ({ eligible: false, reason: 'Approval required' }) };
    assert.equal(url, '/api/fixes/12/export');
    assert.equal(options.method, 'POST');
    return { ok: true, headers: new Headers({ 'content-type': 'application/zip' }), blob: async () => blob };
  };
  assert.equal((await securityApi.patchExportStatus(12)).eligible, false);
  assert.equal(await securityApi.exportPatch(12), blob);
  globalThis.fetch = async () => ({ ok: true, headers: new Headers({ 'content-type': 'application/json' }), blob: async () => blob });
  await assert.rejects(securityApi.exportPatch(12), /invalid archive/);
  globalThis.fetch = async () => ({ ok: false, status: 409, json: async () => ({ error: { message: 'Proposal changed' } }) });
  await assert.rejects(securityApi.exportPatch(12), /Proposal changed/);
});

test('concurrent unauthorized responses clear one session once', async () => {
  const session = setup();
  globalThis.fetch = async () => ({ ok: false, status: 401, json: async () => ({ error: { message: 'Expired' } }) });
  await Promise.allSettled([securityApi.listRepositories(), securityApi.listAuditLogs()]);
  assert.equal(session.token, null);
  assert.equal(session.events, 1);
});

test('login failure and unrelated errors do not expire the active session', async () => {
  const session = setup();
  globalThis.fetch = async () => ({ ok: false, status: 401, json: async () => ({}) });
  await assert.rejects(securityApi.login({}));
  globalThis.fetch = async () => ({ ok: false, status: 500, json: async () => ({}) });
  await assert.rejects(securityApi.listRepositories());
  assert.equal(session.token, 'token');
  assert.equal(session.events, 0);
});

test('successful login returns the session token without expiring the session', async () => {
  const session = setup(null);
  globalThis.fetch = async (url, options) => {
    assert.equal(url, '/api/auth/login');
    assert.equal(options.method, 'POST');
    return { ok: true, json: async () => ({ access_token: 'new-token' }) };
  };
  assert.equal((await securityApi.login({ email: 'test@example.invalid', password: 'synthetic-only' })).access_token, 'new-token');
  assert.equal(session.events, 0);
});

test('a late 401 from an old session does not remove a new session', async () => {
  const session = setup('old-token');
  globalThis.fetch = async () => {
    sessionStorage.setItem('repoguard_access_token', 'new-token');
    return { ok: false, status: 401, json: async () => ({}) };
  };
  await assert.rejects(securityApi.listRepositories());
  assert.equal(session.token, 'new-token');
  assert.equal(session.events, 0);
});

test('finding explanation uses the owned endpoint and surfaces fallback and failures', async () => {
  setup();
  for (const source of ['gemini', 'rule_based_fallback']) {
    globalThis.fetch = async (url, options) => {
      assert.equal(url, '/api/findings/12/explain');
      assert.equal(options.method, 'POST');
      assert.equal(options.headers.Authorization, 'Bearer token');
      return { ok: true, json: async () => ({ explanation: { guidance_source: source } }) };
    };
    assert.equal((await securityApi.explainPersistedFinding(12)).explanation.guidance_source, source);
  }
  globalThis.fetch = async () => ({ ok: false, status: 503, json: async () => ({ error: { message: 'Unavailable' } }) });
  await assert.rejects(securityApi.explainPersistedFinding(12), /Unavailable/);
});

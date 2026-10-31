import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { request, bootstrap, ApiError } from '../src/api.js';
const originalFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = originalFetch; delete globalThis.location; delete globalThis.history; });

test('bootstrap removes URL token before exchange and uses cookie/CSRF after exchange', async () => {
  globalThis.location = { hash: '#token=once-only', pathname: '/', search: '' };
  let removed = false; const calls = [];
  globalThis.history = { replaceState: (_state, _title, url) => { assert.equal(url, '/#home'); removed = true; } };
  globalThis.fetch = async (path, options) => {
    assert.equal(removed, true); calls.push({ path, ...options });
    return new Response(JSON.stringify(path.endsWith('/session') ? { csrf_token: 'csrf-test' } : { role: 'admin' }), { status: 200 });
  };
  await bootstrap(); await request('/config/apply', 'POST', {});
  assert.equal(calls[0].headers.Authorization, 'Bearer once-only');
  assert.equal(calls[1].headers.Authorization, undefined);
  assert.equal(calls[2].headers.Authorization, undefined);
  assert.equal(calls[2].headers['X-CSRF-Token'], 'csrf-test');
  assert.equal(calls[2].credentials, 'same-origin');
  assert.ok(calls[2].headers['X-Request-ID']);
});

test('write version conflicts remain explicit and never automatically retry', async () => {
  let count = 0;
  globalThis.fetch = async () => { count++; return new Response(JSON.stringify({ error: { code: 'version_conflict', message: 'Version conflict' } }), { status: 409 }); };
  await assert.rejects(request('/config', 'PUT', {}), error => error instanceof ApiError && error.status === 409 && error.details.code === 'version_conflict');
  assert.equal(count, 1);
});

test('a timed-out mutation reports uncertainty without resubmitting', async () => {
  let count = 0;
  globalThis.fetch = async (_path, options) => { count++; return new Promise((_resolve, reject) => options.signal.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')))); };
  await assert.rejects(request('/lifecycle/start', 'POST', {}, { timeout: 5 }), error => error instanceof ApiError && error.details.uncertain === true);
  assert.equal(count, 1);
});

test('redacted TOML export is read as text while API errors stay structured', async () => {
  globalThis.fetch = async () => new Response('[core]\nstack="system"\n', { status: 200 });
  assert.equal(await request('/export', 'GET', undefined, { responseType: 'text' }), '[core]\nstack="system"\n');
  globalThis.fetch = async () => new Response(JSON.stringify({ error: { message: 'Not authorized' } }), { status: 403 });
  await assert.rejects(request('/export', 'GET', undefined, { responseType: 'text' }), error => error.message === 'Not authorized');
});

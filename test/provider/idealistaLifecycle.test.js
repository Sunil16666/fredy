/*
 * Copyright (c) 2026 by Christian Kellner.
 * Licensed under Apache-2.0 with Commons Clause and Attribution/Naming Clause
 */

/*
 * Copyright (c) 2026 by Christian Kellner.
 * Licensed under Apache-2.0 with Commons Clause and Attribution/Naming Clause
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { PORTALS } from '../../lib/services/idealista/portal.js';
const store = vi.hoisted(() => ({ settings: {}, getSettings: vi.fn(), upsertSettings: vi.fn() }));
vi.mock('../../lib/services/storage/settingsStorage.js', () => ({
  getSettings: store.getSettings,
  upsertSettings: store.upsertSettings,
}));
const IT = PORTALS['idealista.it'];
const json = (body, init) => new Response(JSON.stringify(body), init);
let api;
let fetchMock;
let instants;
beforeEach(async () => {
  vi.resetModules();
  vi.useFakeTimers();
  vi.setSystemTime(new Date('2026-10-31T12:00:00Z'));
  store.settings = {};
  store.getSettings.mockReset().mockImplementation(async () => store.settings);
  store.upsertSettings.mockReset().mockImplementation((values) => Object.assign(store.settings, values));
  instants = [];
  fetchMock = vi.fn((url) => {
    instants.push(Date.now());
    return Promise.resolve(
      String(url).includes('/oauth/token')
        ? json({ access_token: 'token', expires_in: 120 })
        : json({ elementList: [] }),
    );
  });
  vi.stubGlobal('fetch', fetchMock);
  api = await import('../../lib/services/idealista/mobile-api.js');
});
afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});
async function run() {
  const pending = api.call(IT, '/api/3.5/it/search');
  await vi.runAllTimersAsync();
  return pending;
}
describe('Idealista lifetime behavior', () => {
  it('keeps the device on restart and renews tokens before they expire', async () => {
    await run();
    const id = store.settings.idealista_device_id;
    expect(id).toMatch(/^[a-f0-9]{16}$/);
    await run();
    expect(fetchMock.mock.calls.filter(([url]) => String(url).includes('/oauth/token'))).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(60001);
    await run();
    expect(fetchMock.mock.calls.filter(([url]) => String(url).includes('/oauth/token'))).toHaveLength(2);
    for (let i = 1; i < instants.length; i++) expect(instants[i] - instants[i - 1]).toBeGreaterThanOrEqual(400);
    instants.length = 0;
    vi.resetModules();
    api = await import('../../lib/services/idealista/mobile-api.js');
    await run();
    expect(store.settings.idealista_device_id).toBe(id);
    for (const [url, options] of fetchMock.mock.calls) {
      expect(new URL(url).searchParams.get('t')).toBe(id);
      expect(options.redirect).toBe('error');
      expect(options.signal).toBeInstanceOf(AbortSignal);
    }
    for (let i = 1; i < instants.length; i++) expect(instants[i] - instants[i - 1]).toBeGreaterThanOrEqual(400);
  });
  it('paces a rejected token, its replacement and the retried API request', async () => {
    let grants = 0;
    let calls = 0;
    fetchMock.mockImplementation(async (url) => {
      instants.push(Date.now());
      if (String(url).includes('/oauth/token')) return json({ access_token: `token-${++grants}`, expires_in: 3600 });
      return ++calls === 1 ? new Response('', { status: 401 }) : json({ elementList: [] });
    });
    await run();
    expect(grants).toBe(2);
    expect(calls).toBe(2);
    for (let i = 1; i < instants.length; i++) expect(instants[i] - instants[i - 1]).toBeGreaterThanOrEqual(400);
  });
  it('retains Retry-After and the escalating cooldown across restarts', async () => {
    fetchMock.mockImplementation(async () => new Response('', { status: 429, headers: { 'Retry-After': '3600' } }));
    const refused = expect(api.call(IT, '/api/3.5/it/search')).rejects.toMatchObject({ httpStatus: 429 });
    await vi.runAllTimersAsync();
    await refused;
    const deadline = store.settings.idealista_api_backoff.quietUntil;
    expect(deadline - Date.now()).toBeGreaterThanOrEqual(3600000);
    vi.resetModules();
    api = await import('../../lib/services/idealista/mobile-api.js');
    await expect(api.call(IT, '/api/3.5/it/search')).rejects.toThrow('silent');
    expect(fetchMock).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(3600001);
    fetchMock.mockImplementation(async (url) =>
      String(url).includes('/oauth/token')
        ? json({ access_token: 'new', expires_in: 3600 })
        : json({ elementList: [] }),
    );
    await run();
    expect(store.settings.idealista_api_backoff.quietUntil).toBe(0);
  });
  it('times out a stalled token request instead of holding the lane forever', async () => {
    vi.spyOn(AbortSignal, 'timeout').mockImplementation((ms) => {
      const c = new AbortController();
      setTimeout(() => c.abort(new DOMException('timed out', 'TimeoutError')), ms);
      return c.signal;
    });
    fetchMock.mockImplementationOnce(
      (_url, options) =>
        new Promise((_resolve, reject) =>
          options.signal.addEventListener('abort', () => reject(options.signal.reason)),
        ),
    );
    const pending = expect(api.call(IT, '/api/3.5/it/search')).rejects.toThrow('timed out');
    await vi.runAllTimersAsync();
    await pending;
    expect(Date.now()).toBeGreaterThanOrEqual(Date.parse('2026-10-31T12:00:30Z'));
    await run();
  });
});

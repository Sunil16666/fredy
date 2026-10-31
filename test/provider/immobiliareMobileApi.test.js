/*
 * Copyright (c) 2026 by Christian Kellner.
 * Licensed under Apache-2.0 with Commons Clause and Attribution/Naming Clause
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
const store = vi.hoisted(() => ({ settings: {}, getSettings: vi.fn(), upsertSettings: vi.fn() }));
vi.mock('../../lib/services/storage/settingsStorage.js', () => ({
  getSettings: store.getSettings,
  upsertSettings: store.upsertSettings,
}));
const cookie = 'verified_cookie_for_offline_tests_12345';
const json = (body, init) => new Response(JSON.stringify(body), init);
let api;
let fetchMock;
beforeEach(async () => {
  vi.resetModules();
  vi.useFakeTimers();
  vi.setSystemTime(new Date('2026-10-31T12:00:00Z'));
  store.settings = {};
  store.getSettings.mockReset().mockImplementation(async () => store.settings);
  store.upsertSettings.mockReset().mockImplementation((value) => Object.assign(store.settings, value));
  fetchMock = vi.fn().mockResolvedValue(json({ type: 'search', params: { c: 6737 } }));
  vi.stubGlobal('fetch', fetchMock);
  api = await import('../../lib/services/immobiliare/mobile-api.js');
});
afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

async function callAndAdvance(call) {
  const pending = call();
  await vi.advanceTimersByTimeAsync(501);
  return pending;
}

describe('Immobiliare.it mobile session', () => {
  it('persists one anonymous identity, refreshes its cookie and reuses it across calls', async () => {
    fetchMock.mockResolvedValueOnce(
      json(
        { type: 'search', params: { c: 6737 } },
        { headers: { 'Set-Cookie': `datadome=${cookie}; Secure; HttpOnly` } },
      ),
    );
    await api.resolveSearch('https://www.immobiliare.it/affitto-case/roma/');
    const session = store.settings.immobiliare_session;
    expect(session.deviceId).toMatch(/^[a-f0-9-]{36}$/);
    expect(session.cookie).toBe(cookie);
    await callAndAdvance(() => api.readPage({ c: 6737, t: 'a', px: 600, of: 'price', od: 'a' }, 20));
    const [url, options] = fetchMock.mock.calls[1];
    expect(url.origin).toBe('https://android-imm-v4.ws-app.com');
    expect(Object.fromEntries(url.searchParams)).toMatchObject({
      c: '6737',
      t: 'a',
      px: '600',
      start: '20',
      of: 'd',
      od: 'd',
    });
    expect(options.headers.Cookie).toBe(`datadome=${cookie}`);
    expect(options.headers['immo-id']).toBe(session.deviceId);
    expect(options.redirect).toBe('error');
  });

  it('preserves an existing session across a process/module reload', async () => {
    const existing = {
      deviceId: '12345678-1234-1234-1234-123456789abc',
      userAgent: 'WSCommand3<Furious>|stored-profile',
      cookie,
    };
    store.settings = { immobiliare_session: existing };
    await api.resolveSearch('https://www.immobiliare.it/affitto-case/roma/');
    const headers = fetchMock.mock.calls[0][1].headers;
    expect(headers['User-Agent']).toBe(existing.userAgent);
    expect(headers.Cookie).toBe(`datadome=${cookie}`);
    expect(store.upsertSettings).not.toHaveBeenCalled();
  });

  it('does not persist account cookies', async () => {
    fetchMock.mockResolvedValueOnce(json({}, { headers: { 'Set-Cookie': 'session=private_account_token; Secure' } }));
    await api.resolveSearch('https://www.immobiliare.it/affitto-case/roma/');
    expect(store.settings.immobiliare_session.cookie).toBeNull();
  });

  it('honors the portal clearing an expired cookie', async () => {
    store.settings = {
      immobiliare_session: {
        deviceId: '12345678-1234-1234-1234-123456789abc',
        userAgent: 'WSCommand3<Furious>|stored-profile',
        cookie,
      },
    };
    fetchMock.mockResolvedValueOnce(json({}, { headers: { 'Set-Cookie': 'datadome=; Max-Age=0; Secure' } }));
    await api.resolveSearch('https://www.immobiliare.it/affitto-case/roma/');
    expect(store.settings.immobiliare_session.cookie).toBeNull();
    await callAndAdvance(() => api.readPage({ c: 6737 }, 0));
    expect(fetchMock.mock.calls[1][1].headers.Cookie).toBeUndefined();
  });

  it('does not send an expired cookie after a restart', async () => {
    fetchMock.mockResolvedValueOnce(json({}, { headers: { 'Set-Cookie': `datadome=${cookie}; Max-Age=1` } }));
    await api.resolveSearch('https://www.immobiliare.it/affitto-case/roma/');
    const id = store.settings.immobiliare_session.deviceId;
    await vi.advanceTimersByTimeAsync(1500);
    vi.resetModules();
    api = await import('../../lib/services/immobiliare/mobile-api.js');
    await api.readPage({ c: 6737 }, 0);
    expect(fetchMock.mock.calls[1][1].headers.Cookie).toBeUndefined();
    expect(fetchMock.mock.calls[1][1].headers['immo-id']).toBe(id);
  });

  it('retains a refusal deadline across process restarts', async () => {
    fetchMock.mockResolvedValueOnce(new Response('', { status: 429, headers: { 'Retry-After': '3600' } }));
    await expect(api.readPage({ c: 6737 }, 0)).rejects.toThrow('HTTP 429');
    vi.resetModules();
    api = await import('../../lib/services/immobiliare/mobile-api.js');
    await expect(api.readPage({ c: 6737 }, 0)).rejects.toThrow('cooling down');
    expect(fetchMock).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(3600001);
    await api.readPage({ c: 6737 }, 0);
    expect(store.settings.immobiliare_session.quietUntil).toBe(0);
  });

  it('keeps the in-memory cooldown when persisting a refusal fails', async () => {
    await api.readPage({ c: 6737 }, 0);
    store.upsertSettings.mockImplementationOnce(() => {
      throw new Error('database unavailable');
    });
    fetchMock.mockResolvedValueOnce(new Response('', { status: 429 }));
    await expect(callAndAdvance(() => api.readPage({ c: 6737 }, 0))).rejects.toThrow('database unavailable');
    await expect(api.readPage({ c: 6737 }, 0)).rejects.toThrow('cooling down');
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('does not send an unpersisted identity after storage fails', async () => {
    store.upsertSettings.mockImplementationOnce(() => {
      throw new Error('database unavailable');
    });
    await expect(api.resolveSearch('https://www.immobiliare.it/affitto-case/roma/')).rejects.toThrow(
      'database unavailable',
    );
    expect(fetchMock).not.toHaveBeenCalled();
    await api.resolveSearch('https://www.immobiliare.it/affitto-case/roma/');
    expect(store.settings.immobiliare_session.deviceId).toBe(fetchMock.mock.calls[0][1].headers['immo-id']);
  });

  it('serializes concurrent requests and spaces them apart', async () => {
    const times = [];
    fetchMock.mockImplementation(async () => {
      times.push(Date.now());
      return json({});
    });
    const one = api.readPage({ c: 1 }, 0);
    const two = api.readPage({ c: 2 }, 0);
    await vi.advanceTimersByTimeAsync(1);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(500);
    await Promise.all([one, two]);
    expect(times[1] - times[0]).toBeGreaterThanOrEqual(500);
  });

  it.each([403, 429])('stops requests after HTTP %s and keeps challenge contents out of errors', async (status) => {
    fetchMock.mockResolvedValueOnce(
      new Response('private challenge URL token', { status, headers: { 'Retry-After': '3600' } }),
    );
    await expect(api.readPage({ c: 6737 }, 0)).rejects.toThrow(`HTTP ${status}`);
    await expect(api.readPage({ c: 6737 }, 20)).rejects.toThrow('cooling down');
    expect(fetchMock).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(3600001);
    await api.resolveSearch('https://www.immobiliare.it/affitto-case/roma/');
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('rejects non-scalar filters rather than silently dropping them', async () => {
    await expect(api.readPage({ unknown: { filter: 'value' } }, 0)).rejects.toThrow('unsupported search parameter');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('reports malformed data and HTTP failures without pretending an empty search', async () => {
    fetchMock.mockResolvedValueOnce(new Response('<html>not JSON</html>'));
    await expect(api.readPage({ c: 6737 }, 0)).rejects.toThrow('unreadable JSON');
    fetchMock.mockResolvedValueOnce(new Response('', { status: 500 }));
    await expect(callAndAdvance(() => api.readPage({ c: 6737 }, 0))).rejects.toThrow('HTTP 500');
  });
});

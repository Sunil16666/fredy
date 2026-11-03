/*
 * Copyright (c) 2026 by Christian Kellner.
 * Licensed under Apache-2.0 with Commons Clause and Attribution/Naming Clause
 */

import { randomUUID } from 'node:crypto';
import { getSettings, upsertSettings } from '../storage/settingsStorage.js';
import { sleep } from '../../utils.js';

const ORIGIN = 'https://android-imm-v4.ws-app.com';
const SESSION_SETTING = 'immobiliare_session';
// The 26.18.0 Android client, measured in the emulator. A cookie belongs to its user agent as well
// as its IP, so an existing session keeps the profile it was created with across app updates.
const USER_AGENT =
  'WSCommand3<Furious>|REL|PRD|1080,1920,2.0|26.18.0|ANDROID|Google sdk_gphone64_arm64|14|TAB|2.0-01/09/2016-16:40|0|0';
const REQUEST_GAP_MS = 500;
const REFUSAL_COOLDOWN_MS = 15 * 60_000;
let lane = Promise.resolve();
let session = null;
let lastRequest = 0;

/** @param {unknown} value @returns {boolean} */
function cookieValue(value) {
  return typeof value === 'string' && /^[a-zA-Z0-9~_+/.=-]{20,2048}$/.test(value);
}

/**
 * An installation's anonymous device identity and DataDome cookie. No account or bearer token is
 * required. The settings layer excludes this entire object from HTTP responses.
 * @returns {Promise<{deviceId: string, userAgent: string, cookie: string|null, cookieExpiresAt: number|null, quietUntil: number}>}
 */
async function getSession() {
  if (session != null) return session;
  const stored = (await getSettings())[SESSION_SETTING];
  if (
    stored &&
    typeof stored.deviceId === 'string' &&
    /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(stored.deviceId) &&
    typeof stored.userAgent === 'string' &&
    stored.userAgent.startsWith('WSCommand3<Furious>|') &&
    stored.userAgent.length <= 512 &&
    /^[\x20-\x7e]+$/.test(stored.userAgent)
  ) {
    session = {
      deviceId: stored.deviceId,
      userAgent: stored.userAgent,
      cookie: cookieValue(stored.cookie) ? stored.cookie : null,
      cookieExpiresAt: Number.isFinite(stored.cookieExpiresAt) ? stored.cookieExpiresAt : null,
      quietUntil: Number.isFinite(stored.quietUntil) && stored.quietUntil > 0 ? stored.quietUntil : 0,
    };
  } else {
    const created = {
      deviceId: randomUUID(),
      userAgent: USER_AGENT,
      cookie: null,
      cookieExpiresAt: null,
      quietUntil: 0,
    };
    upsertSettings({ [SESSION_SETTING]: created });
    session = created;
  }
  return session;
}

/**
 * Retain only the portal's DataDome cookie and its refusal deadline. Both survive restarts;
 * anonymous session state never includes account cookies. Commit one response atomically.
 * @param {Response} response
 * @param {Awaited<ReturnType<typeof getSession>>} current
 * @returns {void}
 */
function rememberResponse(response, current) {
  const next = { ...current };
  for (const entry of response.headers.getSetCookie()) {
    const match = /^datadome=([^;]*)/i.exec(entry);
    if (!match) continue;
    const maxAge = /;\s*max-age\s*=\s*(-?\d+)/i.exec(entry);
    const expires = /;\s*expires\s*=\s*([^;]+)/i.exec(entry);
    const deadline = maxAge ? Date.now() + Number(maxAge[1]) * 1000 : expires ? Date.parse(expires[1]) : null;
    const cleared = match[1] === '' || (Number.isFinite(deadline) && deadline <= Date.now());
    if (!cleared && !cookieValue(match[1])) continue;
    next.cookie = cleared ? null : match[1];
    next.cookieExpiresAt = cleared ? null : Number.isFinite(deadline) ? deadline : null;
  }
  if (response.status === 403 || response.status === 429) {
    const retry = response.headers.get('retry-after');
    const seconds = Number(retry);
    const retryAt =
      retry && !Number.isFinite(seconds) ? Date.parse(retry) : Date.now() + Math.max(0, seconds || 0) * 1000;
    next.quietUntil = Math.max(Date.now() + REFUSAL_COOLDOWN_MS, Number.isFinite(retryAt) ? retryAt : 0);
  } else if (response.ok) next.quietUntil = 0;
  if (
    next.cookie !== current.cookie ||
    next.cookieExpiresAt !== current.cookieExpiresAt ||
    next.quietUntil !== current.quietUntil
  ) {
    // Retain a refusal in memory even when storage is temporarily unavailable. Otherwise the
    // failed write would let the next queued request ignore the portal’s cooldown.
    Object.assign(current, next);
    upsertSettings({ [SESSION_SETTING]: next });
  }
}

/**
 * One bounded call to the app's fixed origin. Redirects are refused so a cookie never follows a
 * redirect to another service. A refusal stops subsequent jobs for a quarter hour rather than
 * hammering the challenge endpoint. Do not log response bodies: they can contain session tokens.
 * @param {string} path
 * @param {Record<string, string|number|boolean|null|undefined>} params
 * @returns {Promise<any>}
 */
function request(path, params) {
  const run = lane.then(async () => {
    const current = await getSession();
    if (Date.now() < current.quietUntil)
      throw new Error(
        `Immobiliare.it is cooling down until ${new Date(current.quietUntil).toISOString()} after a verification challenge or rate limit.`,
      );
    const delay = lastRequest + REQUEST_GAP_MS - Date.now();
    if (delay > 0) await sleep(delay);
    const url = new URL(path, ORIGIN);
    for (const [key, value] of Object.entries(params)) {
      if (value == null) continue;
      if (!['string', 'number', 'boolean'].includes(typeof value))
        throw new Error(`Immobiliare.it returned an unsupported search parameter: ${key}.`);
      url.searchParams.set(key, String(value));
    }
    lastRequest = Date.now();
    const response = await fetch(url, {
      redirect: 'error',
      signal: AbortSignal.timeout(30_000),
      headers: {
        'User-Agent': current.userAgent,
        'Accept-Language': 'it-IT',
        'X-Currency': 'EUR',
        'X-Measurement-Unit': 'meters',
        'immo-id': current.deviceId,
        ...(current.cookie && (current.cookieExpiresAt == null || current.cookieExpiresAt > Date.now())
          ? { Cookie: `datadome=${current.cookie}` }
          : {}),
      },
    });
    rememberResponse(response, current);
    if (response.status === 403 || response.status === 429) {
      throw new Error(
        `Immobiliare.it requires verification or is rate limiting this connection (HTTP ${response.status}). No listings were inferred from the refusal.`,
      );
    }
    if (!response.ok) throw new Error(`Immobiliare.it API returned HTTP ${response.status}.`);
    try {
      return await response.json();
    } catch {
      throw new Error('Immobiliare.it API returned unreadable JSON.');
    }
  });
  lane = run.catch(() => {});
  return run;
}

/**
 * Let the portal translate its own website URL. This retains filters Fredy does not know, and
 * avoids guessing geographic IDs or silently widening a search when a local translator is stale.
 * @param {string} url
 * @returns {Promise<any>}
 */
export function resolveSearch(url) {
  return request('/b2c/v1/resolver/url', { url });
}

/** @param {Record<string, any>} params @param {number} offset @returns {Promise<any>} */
export function readPage(params, offset) {
  return request('/b2c/v1/properties', { ...params, start: offset, of: 'd', od: 'd' });
}

/** @param {string} id @returns {Promise<any>} */
export function readDetail(id) {
  if (!/^\d+$/.test(id)) throw new Error('Immobiliare.it requires a numeric advert ID.');
  return request(`/b2c/v1/properties/${id}`, {});
}

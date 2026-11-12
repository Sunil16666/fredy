/*
 * Copyright (c) 2026 by Christian Kellner.
 * Licensed under Apache-2.0 with Commons Clause and Attribution/Naming Clause
 */

/**
 * Explicit live validation, kept separate from offline CI. Each round starts a fresh Node process
 * against the same disposable SQLite database, never the running installation. Reports include
 * counts, timings and booleans only, not cookies, identities, challenge URLs or listing payloads.
 * Usage: node tools/validateImmobiliare.js --output report.json --rounds 2 --interval-ms 60000
 */
import { execFile } from 'node:child_process';
import { promisify, parseArgs } from 'node:util';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';

const { values } = parseArgs({
  options: {
    output: { type: 'string' },
    rounds: { type: 'string', default: '2' },
    'interval-ms': { type: 'string', default: '60000' },
    'worker-state': { type: 'string' },
  },
});

/** Run the real transport and provider with a disposable database. @returns {Promise<void>} */
async function worker() {
  assert.equal(
    await readFile(join(values['worker-state'], '.fredy-validation-state'), 'utf8'),
    'immobiliare-validation-v1',
    'Worker requires a disposable validation directory',
  );
  process.chdir(values['worker-state']);
  // Skip init(), which reads the operator's configured directory. The connection's documented
  // default is db/listings.db relative to this disposable working directory.
  const { default: storage } = await import('../lib/services/storage/SqliteConnection.js');
  const { runMigrations } = await import('../lib/services/storage/migrations/migrate.js');
  const { getSettings } = await import('../lib/services/storage/settingsStorage.js');
  const { config } = await import('../lib/provider/immobiliare.js');
  const api = await import('../lib/services/immobiliare/mobile-api.js');
  const report = { startedAt: new Date().toISOString(), node: process.version, ok: false, requests: [], searches: [] };
  const nativeFetch = globalThis.fetch;
  const devices = new Set();
  let initial;
  globalThis.fetch = async (url, options) => {
    devices.add(options.headers['immo-id']);
    const request = {
      path: new URL(url).pathname.replace(/\/properties\/\d+$/, '/properties/:id'),
      startedAt: Date.now(),
      cookieSent: Boolean(options.headers.Cookie),
    };
    report.requests.push(request);
    try {
      const response = await nativeFetch(url, options);
      request.status = response.status;
      request.durationMs = Date.now() - request.startedAt;
      return response;
    } catch (error) {
      request.networkError = error.name;
      throw error;
    }
  };
  try {
    await runMigrations();
    initial = (await getSettings()).immobiliare_session;
    report.freshSession = initial == null;
    const start = Date.now();
    const rome = (await config.getListings('https://www.immobiliare.it/affitto-case/roma/?prezzoMassimo=600')).map(
      config.normalize,
    );
    assert(rome.length > 0, 'Rome returned no adverts');
    assert(
      rome.every((row) => row.price == null || row.price <= 600),
      'Rome price constraint was lost',
    );
    assert.equal(new Set(rome.map((row) => row.link)).size, rome.length, 'Duplicate Rome links');
    report.searches.push({ name: 'Rome rent, full pagination', count: rome.length, durationMs: Date.now() - start });
    const advert = rome[0];
    const identity = [advert.id, advert.link, advert.price];
    await config.fetchDetails(advert);
    assert(advert.description?.length > 0, 'No detail description');
    assert.deepEqual([advert.id, advert.link, advert.price], identity, 'Detail changed search identity');
    report.detailAvailable = true;

    const matrix = [
      [
        'Milan sale, price/rooms/surface',
        'https://www.immobiliare.it/vendita-case/milano/?prezzoMassimo=200000&localiMinimo=2&superficieMinima=40',
        { t: 'v', px: 200000, lm: 2, sm: 40 },
      ],
      [
        'Turin rent',
        'https://www.immobiliare.it/affitto-case/torino/?prezzoMassimo=500&localiMinimo=3',
        { t: 'a', px: 500, lm: 3 },
      ],
      [
        'English Bologna sale',
        'https://www.immobiliare.it/en/vendita-case/bologna/?prezzoMassimo=80000',
        { t: 'v', px: 80000 },
      ],
      [
        'Generic Rome search',
        'https://www.immobiliare.it/search-list/?idComune=6737&idContratto=2&idCategoria=1&prezzoMassimo=600',
        { t: 'a', px: 600 },
      ],
      [
        'Legitimate empty search',
        'https://www.immobiliare.it/affitto-case/roma/?prezzoMinimo=99999999',
        { t: 'a', pm: 99999999 },
      ],
    ];
    // Concurrent search tasks exercise the shared request lane while keeping every search's
    // filters independent. The transport, not this tool, controls request pacing.
    const results = await Promise.allSettled(
      matrix.map(async ([name, url, expected]) => {
        const resolved = await api.resolveSearch(url);
        assert.equal(resolved.type, 'search', `${name}: unresolved URL`);
        for (const [key, value] of Object.entries(expected))
          assert.equal(String(resolved.params[key]), String(value), `${name}: missing ${key}`);
        const page = await api.readPage(resolved.params, 0);
        assert(Array.isArray(page.list), `${name}: invalid page`);
        if (name === 'Legitimate empty search') assert.equal(page.list.length, 0);
        else assert(page.list.length > 0, `${name}: unexpected empty result`);
        for (const raw of page.list) {
          const row = config.normalize(raw);
          if (row.price != null && expected.px) assert(row.price <= expected.px, `${name}: price exceeds cap`);
          if (row.rooms != null && expected.lm) assert(row.rooms >= expected.lm, `${name}: too few rooms`);
          if (row.size != null && expected.sm) assert(row.size >= expected.sm, `${name}: surface below minimum`);
        }
        report.searches.push({ name, count: page.list.length, total: page.totalActive });
      }),
    );
    const failed = results.find((result) => result.status === 'rejected');
    if (failed) throw failed.reason;
    const final = (await getSettings()).immobiliare_session;
    assert.equal(devices.size, 1, 'Device identity changed within a round');
    assert(devices.has(final.deviceId), 'Device identity was not persisted');
    report.identityReused = initial == null ? null : initial.deviceId === final.deviceId;
    if (initial) assert(report.identityReused, 'Device identity changed on process restart');
    report.cookieStored = Boolean(final.cookie);
    const gaps = report.requests.slice(1).map((request, index) => request.startedAt - report.requests[index].startedAt);
    report.minimumGapMs = gaps.length ? Math.min(...gaps) : null;
    if (gaps.length) assert(report.minimumGapMs >= 490, 'Requests were not paced');
    report.ok = true;
  } catch (error) {
    report.error = error.message;
  } finally {
    report.finishedAt = new Date().toISOString();
    globalThis.fetch = nativeFetch;
    storage.close();
    await writeFile(values.output, JSON.stringify(report, null, 2));
  }
}

/** Start fresh processes and remove their private state even when a round fails. @returns {Promise<void>} */
async function main() {
  const rounds = Number(values.rounds);
  const interval = Number(values['interval-ms']);
  assert(Number.isInteger(rounds) && rounds >= 1 && rounds <= 12, 'rounds must be between 1 and 12');
  assert(Number.isFinite(interval) && interval >= 0, 'interval-ms must be nonnegative');
  const output = resolve(values.output ?? 'immobiliare-validation.json');
  const state = await mkdtemp(join(tmpdir(), 'fredy-immobiliare-'));
  await writeFile(join(state, '.fredy-validation-state'), 'immobiliare-validation-v1');
  const report = { startedAt: new Date().toISOString(), rounds: [] };
  try {
    for (let index = 0; index < rounds; index++) {
      if (index > 0) await new Promise((done) => setTimeout(done, interval));
      const path = join(state, 'round.json');
      await promisify(execFile)(
        process.execPath,
        [fileURLToPath(import.meta.url), '--worker-state', state, '--output', path],
        { timeout: 300000, maxBuffer: 4 * 1024 * 1024 },
      );
      const round = JSON.parse(await readFile(path, 'utf8'));
      report.rounds.push(round);
      // eslint-disable-next-line no-console
      console.log(
        JSON.stringify({
          round: index + 1,
          ok: round.ok,
          requests: round.requests.length,
          identityReused: round.identityReused,
          error: round.error,
        }),
      );
      if (!round.ok) break; // Do not retry a refused connection with another identity.
    }
    report.ok = report.rounds.length === rounds && report.rounds.every((round) => round.ok);
    report.finishedAt = new Date().toISOString();
    await writeFile(output, JSON.stringify(report, null, 2));
    if (!report.ok) process.exitCode = 1;
  } finally {
    await rm(state, { recursive: true, force: true });
  }
}

if (values['worker-state']) await worker();
else await main();

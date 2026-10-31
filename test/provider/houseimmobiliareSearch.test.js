/*
 * Copyright (c) 2026 by Christian Kellner.
 * Licensed under Apache-2.0 with Commons Clause and Attribution/Naming Clause
 */

import { readFile } from 'node:fs/promises';
import * as cheerio from 'cheerio';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const fixture = (name) => readFile(new URL(`../testFixtures/houseimmobiliare${name}.html`, import.meta.url), 'utf8');
const [first, second, empty, detail] = await Promise.all(['', '_page2', '_empty', '_detail'].map(fixture));
const ROOT = 'https://www.houseimmobiliare.info/?s=&property-search=yes&type=affitto&price_max=700';
let provider;
let fetchMock;
const edit = (html, callback) => {
  const $ = cheerio.load(html);
  callback($);
  return $.html();
};
const options = (html, updates) =>
  edit(html, ($) => {
    const list = $('.qodef-property-list');
    list.attr('data-options', JSON.stringify({ ...JSON.parse(list.attr('data-options')), ...updates }));
  });
async function settle(pending) {
  const outcome = Promise.allSettled([pending]);
  await vi.runAllTimersAsync();
  const [result] = await outcome;
  if (result.status === 'rejected') throw result.reason;
  return result.value;
}
beforeEach(async () => {
  vi.resetModules();
  vi.useFakeTimers();
  vi.setSystemTime(new Date('2026-10-31T12:00:00Z'));
  fetchMock = vi.fn(async (url) => new Response(String(url).includes('/page/2/') ? second : first));
  vi.stubGlobal('fetch', fetchMock);
  provider = await import('../../lib/provider/houseimmobiliare.js');
});
afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('House Immobiliare public searches', () => {
  it('walks both pages, starts at the head and preserves array filters on every request', async () => {
    const query =
      '&category%5B%5D=appartamenti&category%5B%5D=mansarde&location%5B%5D=comune-di-citta-di-castello&specification_bedroom=2';
    const rows = await settle(provider.config.getListings(ROOT.replace('/?', '/page/9/?') + query));
    expect(rows).toHaveLength(6);
    expect(new Set(rows.map((row) => row.portalId)).size).toBe(6);
    expect(fetchMock.mock.calls.map(([url]) => url.pathname)).toEqual(['/', '/page/2/']);
    for (const [url, init] of fetchMock.mock.calls) {
      expect(url.searchParams.getAll('category[]')).toEqual(['appartamenti', 'mansarde']);
      expect(url.searchParams.get('specification_bedroom')).toBe('2');
      expect(url.searchParams.get('price_max')).toBe('700');
      expect(init.redirect).toBe('error');
      expect(init.signal).toBeInstanceOf(AbortSignal);
    }
    const listing = provider.config.normalize(rows[0]);
    expect(listing).toMatchObject({
      price: 350,
      size: 45,
      rooms: null,
      address: 'Città di Castello (Perugia)',
      latitude: 43.4574214,
      longitude: 12.2403118,
    });
    expect(listing.images.length).toBeGreaterThan(0);
  });
  it('ignores a separate recommendation widget on archive pages', async () => {
    const html = options(
      edit(first, ($) => {
        const recommendations = $('.qodef-property-list').clone().removeClass('qodef--with-filter');
        recommendations.find('article').attr('data-id', '999999999');
        $('body').append(recommendations);
      }),
      { max_pages_num: 1 },
    );
    fetchMock.mockResolvedValueOnce(new Response(html));
    const rows = await settle(provider.config.getListings(ROOT));
    expect(rows).toHaveLength(3);
    expect(rows.some((row) => row.portalId === '999999999')).toBe(false);
  });
  it('keeps hidden prices unknown and does not call bedrooms total rooms', async () => {
    fetchMock.mockResolvedValue(
      new Response(
        options(
          edit(first, ($) => {
            $('.qodef-e-price-amount').text('Info in agenzia');
            $('.qodef--size .qodef-e-info-item-text').text('75,5 m²');
            $('.qodef--bedrooms .qodef-e-info-item-text').text('3');
          }),
          { max_pages_num: 1 },
        ),
      ),
    );
    const [raw] = await settle(provider.config.getListings(ROOT));
    expect(provider.config.normalize(raw)).toMatchObject({ price: null, size: 75.5, rooms: null });
  });
  it('keeps the canonical link stable when the price hash changes', async () => {
    const [raw] = await settle(provider.config.getListings(ROOT));
    const a = provider.config.normalize(raw);
    const b = provider.config.normalize({ ...raw, price: 400 });
    expect(a.link).toBe(b.link);
    expect(a.id).not.toBe(b.id);
  });
  it('distinguishes an empty search from malformed HTML or a challenge', async () => {
    fetchMock.mockResolvedValueOnce(new Response(empty));
    expect(await settle(provider.config.getListings(ROOT))).toEqual([]);
    fetchMock.mockResolvedValueOnce(new Response('<html>Verify you are human</html>'));
    await expect(settle(provider.config.getListings(ROOT))).rejects.toThrow('results container');
    fetchMock.mockResolvedValueOnce(new Response(edit(empty, ($) => $('.qodef-m-posts-not-found').remove())));
    await expect(settle(provider.config.getListings(ROOT))).rejects.toThrow('neither adverts');
  });
  it('rejects an unexpected sort or pagination schema', async () => {
    fetchMock.mockResolvedValueOnce(new Response(options(first, { orderby: 'price' })));
    await expect(settle(provider.config.getListings(ROOT))).rejects.toThrow('newest-first');
    fetchMock.mockResolvedValueOnce(new Response(options(first, { max_pages_num: 'many' })));
    await expect(settle(provider.config.getListings(ROOT))).rejects.toThrow('pagination');
  });
  it('uses location labels when optional map data is malformed', async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(
        options(
          edit(first, ($) => $('[data-addresses]').attr('data-addresses', '{broken')),
          { max_pages_num: 1 },
        ),
      ),
    );
    const [raw] = await settle(provider.config.getListings(ROOT));
    expect(raw.address).toContain('Città di Castello');
    expect(raw.latitude).toBeUndefined();
  });
  it('keeps earlier pages on failure and stops repeated pages', async () => {
    fetchMock.mockResolvedValueOnce(new Response(first)).mockRejectedValueOnce(new Error('network failure'));
    expect(await settle(provider.config.getListings(ROOT))).toHaveLength(3);
    fetchMock.mockImplementation(async () => new Response(first));
    expect(await settle(provider.config.getListings(ROOT))).toHaveLength(3);
    expect(fetchMock).toHaveBeenCalledTimes(4);
  });
  it('bounds broad searches at thirty pages', async () => {
    fetchMock.mockImplementation(async (url) => {
      const page = Number(url.pathname.match(/page\/(\d+)/)?.[1] ?? 1);
      return new Response(
        options(
          edit(first, ($) =>
            $('article[data-id]').each((index, e) => $(e).attr('data-id', String(page * 1000 + index))),
          ),
          { max_pages_num: 100 },
        ),
      );
    });
    expect(await settle(provider.config.getListings(ROOT))).toHaveLength(90);
    expect(fetchMock).toHaveBeenCalledTimes(30);
  });
  it.each([
    'https://evil.test/?property-search=yes',
    'https://www.houseimmobiliare.info.evil.test/?property-search=yes',
    'http://www.houseimmobiliare.info/?property-search=yes',
    'https://user:pass@www.houseimmobiliare.info/?property-search=yes',
    'https://www.houseimmobiliare.info:444/?property-search=yes',
    'https://www.houseimmobiliare.info/',
    'https://www.houseimmobiliare.info/immobile/anything/',
  ])('rejects an unsupported URL before requesting: %s', async (url) => {
    await expect(settle(provider.config.getListings(url))).rejects.toThrow();
    expect(fetchMock).not.toHaveBeenCalled();
  });
  it('serializes concurrent jobs without leaking URLs or blacklists', async () => {
    const times = [];
    fetchMock.mockImplementation(async () => {
      times.push(Date.now());
      return new Response(options(first, { max_pages_num: 1 }));
    });
    const a = provider.createConfig({ url: ROOT, enabled: true }, ['MONOLOCALE']);
    const b = provider.createConfig({ url: ROOT.replace('affitto', 'vendita'), enabled: true }, []);
    const [arows, brows] = await settle(Promise.all([a.getListings(a.url), b.getListings(b.url)]));
    expect(times[1] - times[0]).toBeGreaterThanOrEqual(500);
    expect(a.filter(a.normalize(arows[0]))).toBe(false);
    expect(b.filter(b.normalize(brows[0]))).toBe(true);
    expect(fetchMock.mock.calls.map(([url]) => url.searchParams.get('type'))).toEqual(['affitto', 'vendita']);
    expect(provider.config.url).toBeNull();
  });
  it('releases the queue after a network failure and refuses redirects', async () => {
    fetchMock.mockRejectedValueOnce(new DOMException('timeout', 'TimeoutError'));
    await expect(settle(provider.config.getListings(ROOT))).rejects.toThrow('timeout');
    expect(await settle(provider.config.getListings(ROOT))).toHaveLength(6);
  });
  it.each([403, 429])('pauses queued requests after HTTP %s and honors Retry-After', async (status) => {
    fetchMock.mockResolvedValueOnce(new Response('private challenge', { status, headers: { 'Retry-After': '3600' } }));
    await expect(settle(provider.config.getListings(ROOT))).rejects.toThrow(`HTTP ${status}`);
    await expect(settle(provider.config.getListings(ROOT))).rejects.toThrow('cooling down');
    expect(fetchMock).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(3600001);
    expect(await settle(provider.config.getListings(ROOT))).toHaveLength(6);
  });
});

describe('House Immobiliare details', () => {
  it('enriches a new card while preserving its search price, link and hash', async () => {
    const [raw] = await settle(provider.config.getListings(ROOT));
    const listing = provider.config.normalize(raw);
    const identity = { id: listing.id, link: listing.link, price: listing.price };
    fetchMock.mockResolvedValueOnce(new Response(detail));
    await settle(provider.config.fetchDetails(listing));
    expect(listing).toMatchObject(identity);
    expect(listing.publishedAt).toBe(Date.parse('2026-10-23T23:00:00+00:00'));
    expect(listing.description).toContain('NO ascensore');
    expect(listing.images.length).toBeGreaterThan(0);
  });
  it('keeps cards intact when detail is refused or names another advert', async () => {
    const [raw] = await settle(provider.config.getListings(ROOT));
    const listing = provider.config.normalize(raw);
    const before = structuredClone(listing);
    fetchMock.mockResolvedValueOnce(new Response(detail.replace('monolocale-arredato-449402', 'different-advert')));
    await settle(provider.config.fetchDetails(listing));
    expect(listing).toEqual(before);
    fetchMock.mockResolvedValueOnce(new Response('', { status: 403 }));
    await settle(provider.config.fetchDetails(listing));
    expect(listing).toEqual(before);
  });
});

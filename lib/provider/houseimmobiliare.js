/*
 * Copyright (c) 2026 by Christian Kellner.
 * Licensed under Apache-2.0 with Commons Clause and Attribution/Naming Clause
 */

import * as cheerio from 'cheerio';
import { buildHash, isOneOf, sleep } from '../utils.js';
import { extractNumber } from '../utils/extract-number.js';
import { publicationDate } from '../utils/publicationDate.js';
import { toListingImages } from '../utils/listingImages.js';
import logger from '../services/logger.js';
/** @import { ParsedListing } from '../types/listing.js' */
/** @import { ProviderConfig } from '../types/providerConfig.js' */

const BASE_URL = 'https://www.houseimmobiliare.info/';
const MAX_PAGES = 30;
// Installation-wide transport state only. Search URLs, documents and blacklists stay per run.
let lane = Promise.resolve();
let lastRequest = 0;
let quietUntil = 0;

/** Validate every search, detail and pagination URL before any network request. @param {string} value @returns {URL} */
function portalUrl(value) {
  const url = new URL(value, BASE_URL);
  if (
    url.protocol !== 'https:' ||
    !['houseimmobiliare.info', 'www.houseimmobiliare.info'].includes(url.hostname) ||
    url.port ||
    url.username ||
    url.password
  )
    throw new Error('House Immobiliare requires an HTTPS URL on houseimmobiliare.info.');
  url.hostname = 'www.houseimmobiliare.info';
  url.hash = '';
  return url;
}

/** Restore the first page while keeping every portal filter, including repeated array parameters. @param {string} value @returns {URL} */
function searchUrl(value) {
  const url = portalUrl(value);
  url.pathname = url.pathname.replace(/\/page\/\d+\/?$/, '/');
  url.searchParams.delete('paged');
  if (
    !(
      (url.pathname === '/' && url.searchParams.get('property-search') === 'yes') ||
      /^\/(?:scelta-immobile|tipologia-immobile|localita-immobile)\/[^/]+\/$/.test(url.pathname) ||
      /^\/immobili-in-(?:vendita|affitto)-[^/]+\/$/.test(url.pathname)
    )
  )
    throw new Error('House Immobiliare requires a finished property search or property archive URL.');
  return url;
}

/**
 * Serialize public HTML requests across jobs. No cookies, credentials, browser or persistent
 * session are needed. A refusal pauses this process, including optional detail requests.
 * @param {URL} url
 * @returns {Promise<string>}
 */
function readHtml(url) {
  const run = lane.then(async () => {
    if (Date.now() < quietUntil)
      throw new Error('House Immobiliare is cooling down after a verification or rate limit.');
    await sleep(Math.max(0, lastRequest + 500 - Date.now()));
    lastRequest = Date.now();
    const response = await fetch(url, {
      redirect: 'error',
      signal: AbortSignal.timeout(30_000),
      headers: { Accept: 'text/html', 'Accept-Language': 'it-IT' },
    });
    if (response.status === 403 || response.status === 429) {
      const retry = response.headers.get('retry-after');
      const seconds = Number(retry);
      const deadline =
        retry && !Number.isFinite(seconds) ? Date.parse(retry) : Date.now() + Math.max(0, seconds || 0) * 1000;
      quietUntil = Math.max(Date.now() + 15 * 60_000, Number.isFinite(deadline) ? deadline : 0);
    }
    if (!response.ok) throw new Error(`House Immobiliare returned HTTP ${response.status}.`);
    return response.text();
  });
  lane = run.catch(() => {});
  return run;
}

/** @param {string} value @returns {number|null} */
function number(value) {
  const parsed = extractNumber(value.replace(/^[^\d-]*/, '').trim());
  return Number.isFinite(parsed) && parsed > 0 ? parsed : null;
}

/** @param {unknown} value @param {number} limit @returns {number|undefined} */
function coordinate(value, limit) {
  if (value == null || String(value).trim() === '') return undefined;
  const parsed = Number(value);
  return Number.isFinite(parsed) && Math.abs(parsed) <= limit ? parsed : undefined;
}

/**
 * Read only the results container, never recommendations or navigation. A recognizable empty
 * result differs from a challenge page. Map entries join by WordPress ID, not by array order.
 * @param {string} html
 * @returns {{listings: any[], pages: number}}
 */
function parseSearch(html) {
  const $ = cheerio.load(html);
  const filtered = $('.qodef-property-list.qodef--with-filter');
  const list = filtered.length ? filtered : $('.qodef-property-list');
  if (list.length !== 1) throw new Error('House Immobiliare returned no unique search results container.');
  const options = JSON.parse(list.attr('data-options') ?? '{}');
  if (options.orderby !== 'date' || String(options.order).toUpperCase() !== 'DESC')
    throw new Error('House Immobiliare did not return a newest-first search.');
  const pages = Number(options.max_pages_num);
  if (!Number.isInteger(pages) || pages < 0) throw new Error('House Immobiliare returned invalid pagination.');
  const markers = new Map();
  for (const element of $('[data-addresses]').toArray()) {
    try {
      const addresses = JSON.parse($(element).attr('data-addresses'))?.addresses;
      for (const entry of Array.isArray(addresses) ? addresses : []) markers.set(String(entry.itemId), entry);
    } catch {
      /* A missing map must not discard readable search cards. */
    }
  }
  const cards = list.find('article.qodef-e[data-id]');
  if (!cards.length && !list.find('.qodef-m-posts-not-found').length)
    throw new Error('House Immobiliare returned neither adverts nor a confirmed empty search.');
  const listings = cards.toArray().map((element) => {
    const card = $(element);
    const portalId = card.attr('data-id');
    const link = portalUrl(card.find('.qodef-e-title-link').attr('href') ?? '').href;
    if (!/^\d+$/.test(portalId) || !/^\/immobile\/[^/]+\/$/.test(new URL(link).pathname))
      throw new Error('House Immobiliare returned an invalid advert identity.');
    const marker = markers.get(portalId);
    const location = card.find('.qodef--location a').last().text().trim();
    const mapAddress = typeof marker?.location?.address === 'string' ? marker.location.address : '';
    const address = mapAddress.replace(/^[\s,]+/, '').trim() || location || null;
    return {
      portalId,
      link,
      title: card.find('.qodef-e-title-link').text().trim() || null,
      price: number(card.find('.qodef-e-price-amount').text()),
      size: number(card.find('.qodef--size .qodef-e-info-item-text').text()),
      address,
      latitude: coordinate(marker?.location?.latitude, 90),
      longitude: coordinate(marker?.location?.longitude, 180),
      description: card.find('.qodef-e-excerpt').text().trim() || undefined,
      images: toListingImages(
        card
          .find('.qodef-e-media-slider img')
          .toArray()
          .map((e) => ({ url: $(e).attr('src'), caption: $(e).attr('alt') })),
      ),
    };
  });
  return { listings, pages };
}

/**
 * Start at the head on every run, preserving the search query on each page. Bound work for broad
 * archives and keep earlier pages if a later request fails. No run history grows in memory.
 * @param {string} value
 * @returns {Promise<any[]>}
 */
async function getListings(value) {
  const root = searchUrl(value);
  const found = new Map();
  const signatures = new Set();
  for (let page = 1; page <= MAX_PAGES; page++) {
    const url = new URL(root);
    if (page > 1) url.pathname = `${root.pathname}page/${page}/`;
    let result;
    try {
      result = parseSearch(await readHtml(url));
    } catch (error) {
      if (page === 1) throw error;
      logger.warn(`House Immobiliare: keeping ${found.size} adverts from an incomplete search (${error.message}).`);
      break;
    }
    if (!result.listings.length) break;
    const signature = JSON.stringify(result.listings.map((entry) => entry.portalId));
    if (signatures.has(signature)) {
      logger.warn('House Immobiliare repeated a page; the search may be incomplete.');
      break;
    }
    signatures.add(signature);
    for (const entry of result.listings) if (!found.has(entry.portalId)) found.set(entry.portalId, entry);
    if (page >= result.pages) break;
    if (page === MAX_PAGES)
      logger.warn('House Immobiliare: stopped after 30 pages. Narrow the search to see the rest.');
  }
  return [...found.values()];
}

/** Convert a search card to Fredy's common listing shape. Bedrooms are not total rooms. @param {any} raw @returns {ParsedListing} */
function normalize(raw) {
  return {
    id: buildHash(raw.portalId, raw.price == null ? null : String(raw.price)),
    link: raw.link,
    title: raw.title,
    price: raw.price,
    size: raw.size,
    rooms: null,
    address: raw.address,
    latitude: raw.latitude,
    longitude: raw.longitude,
    description: raw.description,
    image: raw.images?.[0]?.url ?? null,
    images: raw.images,
  };
}

/** Optional enrichment for new listings; preserve the search card, price and hash on any failure. @param {ParsedListing} listing @returns {Promise<ParsedListing>} */
async function fetchDetails(listing) {
  try {
    const url = portalUrl(listing.link);
    if (!/^\/immobile\/[^/]+\/$/.test(url.pathname)) return listing;
    const $ = cheerio.load(await readHtml(url));
    const canonical = $('link[rel="canonical"]').attr('href');
    if (!canonical || portalUrl(canonical).href !== url.href || !$('.qodef-property-item').length) return listing;
    const description = $('.qodef-m-description-content').first().text().trim();
    if (description) listing.description = description;
    const date = publicationDate($('meta[property="article:published_time"]').attr('content'));
    if (date != null) listing.publishedAt = date;
    const images = toListingImages(
      $('.qodef-custom-gallery a[href], .qodef-property-item a[href]')
        .toArray()
        .map((e) => ({ url: $(e).attr('href'), caption: $(e).find('img').attr('alt') }))
        .filter((e) => /\/wp-content\/uploads\/.*\.(?:jpe?g|png|webp)(?:\?|$)/i.test(e.url)),
    );
    if (images.length) listing.images = images;
  } catch (error) {
    logger.debug(`House Immobiliare: no detail (${error.message}).`);
  }
  return listing;
}

/** @type {ProviderConfig} */
const config = {
  url: null,
  needsBrowser: false,
  requiredFieldNames: ['id', 'title', 'link'],
  crawlContainer: null,
  crawlFields: {},
  priceRangeParams: { min: 'price_min', max: 'price_max' },
  getListings,
  normalize,
  fetchDetails,
};

export const metaInformation = {
  id: 'houseimmobiliare',
  name: 'House Immobiliare',
  baseUrl: BASE_URL,
  countries: ['it'],
};

/** Return an isolated configuration for one job run. @param {{url:string, enabled?:boolean}} sourceConfig @param {string[]} [blacklist] @returns {ProviderConfig} */
export const createConfig = (sourceConfig, blacklist = []) => ({
  ...config,
  url: sourceConfig.url,
  enabled: sourceConfig.enabled,
  filter: (listing) =>
    listing.title != null && !isOneOf(listing.title, blacklist ?? []) && !isOneOf(listing.description, blacklist ?? []),
});
export { config };

/*
 * Copyright (c) 2026 by Christian Kellner.
 * Licensed under Apache-2.0 with Commons Clause and Attribution/Naming Clause
 */

/**
 * Immobiliare.it's Android API. Its URL resolver reads the website's filters and geography;
 * property pages are read as JSON without launching Chromium. See reverse-engineered-immobiliare.md.
 */
import { buildHash, isOneOf } from '../utils.js';
import { sanitize } from '../utils/priceExtractors.js';
import { toListingImages } from '../utils/listingImages.js';
import { resolveSearch, readPage, readDetail } from '../services/immobiliare/mobile-api.js';
import logger from '../services/logger.js';
/** @import { ParsedListing } from '../types/listing.js' */
/** @import { ProviderConfig } from '../types/providerConfig.js' */

const BASE_URL = 'https://www.immobiliare.it/';
const MAX_PAGES = 20;

/** @param {string} url @returns {string} */
function searchUrl(url) {
  const parsed = new URL(url);
  if (
    parsed.protocol !== 'https:' ||
    !['www.immobiliare.it', 'immobiliare.it'].includes(parsed.hostname) ||
    parsed.port ||
    parsed.username ||
    parsed.password ||
    !/^\/(?:en\/|de\/|es\/|fr\/|el\/|pt\/|ru\/)?(?:(?:affitto|vendita|aste)-[^/]+\/|search-list\/?$)/.test(
      parsed.pathname,
    )
  ) {
    throw new Error(
      'Immobiliare.it requires an HTTPS search URL, such as https://www.immobiliare.it/affitto-case/roma/.',
    );
  }
  parsed.hash = '';
  parsed.searchParams.delete('pag');
  return parsed.href;
}

/** @param {any} advert @returns {boolean} */
function isAdvert(advert) {
  return (
    /^\d+$/.test(String(advert?.id ?? '')) &&
    advert.rty === 'ad' &&
    advert.enabled !== false &&
    !(Array.isArray(advert.subProperties) && advert.subProperties.length > 0)
  );
}

/**
 * Read newest first, restarting from offset zero even for a pasted later page. The portal's
 * resolver supplies the filters unchanged. Refuse non-search answers rather than searching Italy
 * without the user's constraints. An interrupted walk keeps its earlier results and says so.
 * @param {string} url
 * @returns {Promise<any[]>}
 */
async function getListings(url) {
  const resolved = await resolveSearch(searchUrl(url));
  if (
    resolved?.type !== 'search' ||
    !resolved.params ||
    typeof resolved.params !== 'object' ||
    Array.isArray(resolved.params) ||
    Object.keys(resolved.params).length === 0
  ) {
    throw new Error('Immobiliare.it could not resolve this URL as a search.');
  }
  const found = new Map();
  const seenPages = new Set();
  let offset = 0;
  for (let page = 1; page <= MAX_PAGES; page++) {
    let data;
    try {
      data = await readPage(resolved.params, offset);
      if (!Array.isArray(data?.list)) throw new Error('The search response has no listing array.');
    } catch (error) {
      if (page === 1) throw error;
      logger.warn(`Immobiliare.it: keeping ${found.size} adverts from an incomplete search (${error.message}).`);
      break;
    }
    if (data.list.length === 0) break;
    const signature = JSON.stringify(data.list.map((entry) => entry?.id));
    if (seenPages.has(signature)) {
      logger.warn('Immobiliare.it repeated a page. The search may be incomplete.');
      break;
    }
    seenPages.add(signature);
    for (const entry of data.list.filter(isAdvert))
      if (!found.has(String(entry.id))) found.set(String(entry.id), entry);
    offset += data.list.length;
    if (Number.isInteger(data.totalActive) && offset >= data.totalActive) break;
    if (page === MAX_PAGES) logger.warn('Immobiliare.it: stopped after 20 pages. Narrow the search to see the rest.');
  }
  return [...found.values()];
}

/** @param {unknown} value @returns {number|undefined} */
function date(value) {
  return typeof value === 'number' && Number.isFinite(value) && value > 0 ? value * 1000 : undefined;
}

/**
 * Native numbers are already machine-formatted, including the decimal surface and price. Hidden
 * prices remain unknown. The same advert keeps its canonical website link across list/detail reads.
 * @param {any} advert
 * @returns {ParsedListing}
 */
function normalize(advert) {
  const geography = advert?.geography;
  const addressParts = [geography?.street, geography?.municipality?.name, geography?.province?.name].filter(
    (part) => typeof part === 'string' && part.trim(),
  );
  const address = [...new Set(addressParts)].join(', ') || null;
  const price = advert?.price?.isHidden ? null : sanitize(advert?.price?.raw);
  const point = geography?.geolocation;
  const pictures = Array.isArray(advert?.media?.images) ? advert.media.images : [];
  return {
    id: buildHash(String(advert?.id ?? ''), price == null ? null : String(price)),
    link: /^\d+$/.test(String(advert?.id ?? '')) ? `${BASE_URL}annunci/${advert.id}/` : null,
    title: typeof advert?.title === 'string' ? [advert.title, address].filter(Boolean).join(' - ') : null,
    price,
    size: sanitize(advert?.topology?.surface?.size),
    rooms: sanitize(advert?.topology?.rooms),
    address,
    latitude:
      typeof point?.latitude === 'number' && Number.isFinite(point.latitude) && Math.abs(point.latitude) <= 90
        ? point.latitude
        : undefined,
    longitude:
      typeof point?.longitude === 'number' && Number.isFinite(point.longitude) && Math.abs(point.longitude) <= 180
        ? point.longitude
        : undefined,
    publishedAt: date(advert?.creationDate) ?? date(advert?.lastModified),
    description: typeof advert?.description?.content === 'string' ? advert.description.content : undefined,
    image: pictures[0]?.hd ?? pictures[0]?.sd ?? null,
    images: toListingImages(pictures.map((picture) => ({ url: picture.hd ?? picture.sd, caption: picture.label }))),
  };
}

/**
 * Only enrich listings Fredy has not stored yet; a blocked detail never discards the search card.
 * Keep the search hash and price together if the advert changes while a run is in progress.
 * @param {ParsedListing} listing
 * @returns {Promise<ParsedListing>}
 */
async function fetchDetails(listing) {
  const id = listing.link?.match(/^https:\/\/www\.immobiliare\.it\/annunci\/(\d+)\/$/)?.[1];
  if (!id) return listing;
  try {
    const raw = await readDetail(id);
    if (String(raw?.id) === id && isAdvert(raw)) {
      const detail = normalize(raw);
      if (detail.description) listing.description = detail.description;
      if (detail.images?.length) listing.images = detail.images;
    }
  } catch (error) {
    logger.debug(`Immobiliare.it: no detail for advert ${id} (${error.message}).`);
  }
  return listing;
}

/** @type {ProviderConfig} */
const config = {
  url: null,
  needsBrowser: false,
  requiredFieldNames: ['id', 'title', 'link', 'price', 'size', 'rooms', 'address'],
  priceRangeParams: { min: 'prezzoMinimo', max: 'prezzoMassimo' },
  crawlContainer: null,
  crawlFields: {},
  getListings,
  normalize,
  fetchDetails,
  // Activity and price probes need separate removed-advert evidence before they can safely ship.
};

export const metaInformation = { id: 'immobiliare', name: 'Immobiliare.it', baseUrl: BASE_URL, countries: ['it'] };

/** @param {{url: string, enabled?: boolean}} sourceConfig @param {string[]} [blacklist] @returns {ProviderConfig} */
export const createConfig = (sourceConfig, blacklist = []) => ({
  ...config,
  enabled: sourceConfig.enabled,
  url: sourceConfig.url,
  filter: (listing) =>
    listing.title != null && !isOneOf(listing.title, blacklist ?? []) && !isOneOf(listing.description, blacklist ?? []),
});

export { config };

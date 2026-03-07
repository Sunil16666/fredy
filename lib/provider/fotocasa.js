/*
 * Copyright (c) 2026 by Christian Kellner.
 * Licensed under Apache-2.0 with Commons Clause and Attribution/Naming Clause
 */

/**
 * Fotocasa provider using the undocumented mobile API.
 *
 * Reverse-engineered from Fotocasa Android app v7.318.1.
 * Authentication: AES-128-CBC request signature (no user OAuth required for public search).
 *
 * API Gateway base URL (CommonRetrofit): https://apps.gw.fotocasa.es
 * Active list endpoint in current app code: GET /v3/placeholders/search
 */

import { createCipheriv, createHash } from 'crypto';
import { buildHash, isOneOf } from '../utils.js';
import checkIfListingIsActive from '../services/listings/listingActiveTester.js';
import logger from '../services/logger.js';

const API_GATEWAY_BASE_URL = 'https://apps.gw.fotocasa.es';
const SEARCH_BASE_URL = 'https://search.gw.fotocasa.es';

// AES passphrase: ConstantsWs.PWD_WS (com.adevinta.realestate.core.constants.ConstantsWs)
const PWD_WS = 'ftcipanuntis2009';

// Media sizes for list view: MediaSizeType.Companion.getList() → [LARGE, EXTRA_SMALL, LARGE_LEGACY]
const MEDIA_SIZES = 'LARGE,EXTRA_SMALL,LARGE_LEGACY';

// Stable device identifier used by our client for signature input and Device-Token header.
const DEVICE_ID = 'c4a3f2e1-b0d9-4e87-a562-f1c3e7d29b40';
const DEVICE_TOKEN = DEVICE_ID;

// UserAgentFotocasaProvider format:
//   <userAgentName>/<appVersion> (<androidRelease>/<sdkInt>; <model>; <product>; <os.version>; <incremental>)
const USER_AGENT = 'AndroidApp/7.318.1 (14/34; Pixel 7; panther; 5.15.0; UP1A.231005.007)';

const DEFAULT_CLIENT_ID = '0';
const DEFAULT_PAGE = '1';
const DEFAULT_PAGE_SIZE = '36';
const DEFAULT_SORT = '0';
const DEFAULT_SAITAMA_CLIENT_VERSION = '7';
const MAX_PAGES_PER_QUERY = 200;

const TRANSLATE_PATH = '/translatesemantic/search';
const SEARCH_V3_PATH = '/v3/placeholders/search';

const LOCATION_PARAM_CANDIDATES = ['locations', 'combinedLocationIds', 'combinedLocationsIds', 'locationCodes'];

const TRANSACTION_SLUG_TO_TYPE = {
  alquiler: 'RENT',
  comprar: 'SALE',
  venta: 'SALE',
  traspaso: 'TRANSFER',
  compartir: 'SHARE',
  'alquiler-con-opcion-a-compra': 'RENT_WITH_OPTION_TO_BUY',
  vacacional: 'HOLIDAY_RENTAL',
  'alquiler-vacacional': 'HOLIDAY_RENTAL',
};

const PROPERTY_SLUG_TO_TYPE = {
  vivienda: 'HOME',
  viviendas: 'HOME',
  piso: 'HOME',
  pisos: 'HOME',
  casa: 'HOME',
  casas: 'HOME',
  habitacion: 'HOME',
  habitaciones: 'HOME',
  garaje: 'GARAGE',
  garajes: 'GARAGE',
  terreno: 'LAND',
  terrenos: 'LAND',
  local: 'COMMERCIAL_PREMISES',
  locales: 'COMMERCIAL_PREMISES',
  'local-comercial': 'COMMERCIAL_PREMISES',
  'locales-comerciales': 'COMMERCIAL_PREMISES',
  oficina: 'OFFICE',
  oficinas: 'OFFICE',
  trastero: 'BOX_ROOM',
  trasteros: 'BOX_ROOM',
  edificio: 'BUILDING',
  edificios: 'BUILDING',
};

let appliedBlackList = [];

/**
 * Computes request signature based on RequestEncryptionApi.java / RequestSignatureApi.java:
 *   key = MD5(PWD_WS), iv = 16x0, input = deviceId + timestamp, output = hex uppercase.
 */
function computeSignature(timestamp) {
  const key = createHash('md5').update(PWD_WS, 'utf8').digest();
  const iv = Buffer.alloc(16, 0);
  const input = Buffer.from(DEVICE_ID + String(timestamp), 'utf8');
  const cipher = createCipheriv('aes-128-cbc', key, iv);
  return Buffer.concat([cipher.update(input), cipher.final()])
    .toString('hex')
    .toUpperCase();
}

function buildHeaders() {
  const timestamp = Date.now();
  return {
    // Authentication-Token is added by the app even when unauthenticated (empty string).
    // Some gateway middleware may reject requests that omit the header entirely.
    'Authentication-Token': '',
    Signature: computeSignature(timestamp),
    'Device-Token': DEVICE_TOKEN,
    Timestamp: String(timestamp),
    'Accept-Language': 'es',
    'X-Source': 'android-fc--app',
    Accept: 'application/json',
    'User-Agent': USER_AGENT,
  };
}

function stringify(value) {
  if (value == null) return null;
  const str = String(value).trim();
  return str.length > 0 ? str : null;
}

function toPositiveInt(value) {
  const str = stringify(value);
  if (str == null) return null;
  const parsed = Number.parseInt(str, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : null;
}

function putIfPresent(target, key, value) {
  const str = stringify(value);
  if (str != null) target[key] = str;
}

function asCsv(value) {
  if (value == null) return null;
  if (Array.isArray(value)) {
    const items = value.map((item) => stringify(item)).filter((item) => item != null);
    return items.length > 0 ? items.join(',') : null;
  }
  return stringify(value);
}

function sanitizeLocations(value) {
  const str = stringify(value);
  if (str == null) return null;
  // Typical format from mobile app is numeric groups separated by commas and/or semicolons.
  return /^[0-9,;.-]+$/.test(str) ? str : null;
}

function buildRequestUrl(baseUrl, path, query = {}, { appendRawMediaSizes = false } = {}) {
  const queryParts = Object.entries(query)
    .filter(([, value]) => value != null && String(value).trim().length > 0)
    .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(String(value))}`);

  if (appendRawMediaSizes) {
    // Retrofit uses @Query(encoded=true) for mediaSizes in app code.
    queryParts.push(`mediaSizes=${MEDIA_SIZES}`);
  }

  const qs = queryParts.length > 0 ? `?${queryParts.join('&')}` : '';
  return `${baseUrl}${path}${qs}`;
}

function isLikelyBlockPage(status, text) {
  if (status !== 403 || typeof text !== 'string') return false;
  const normalized = text.toLowerCase();
  return normalized.includes('pardon our interruption') || normalized.includes('imperva');
}

async function fetchJson(path, query, options = {}) {
  const { appendRawMediaSizes = false, baseUrls = [API_GATEWAY_BASE_URL, SEARCH_BASE_URL] } = options;

  let lastError = null;

  for (const baseUrl of baseUrls) {
    const requestUrl = buildRequestUrl(baseUrl, path, query, { appendRawMediaSizes });
    logger.debug(`Fotocasa: GET ${requestUrl}`);

    const response = await fetch(requestUrl, {
      method: 'GET',
      headers: buildHeaders(),
    });

    if (response.ok) {
      return response.json();
    }

    const text = await response.text();
    const err = new Error(`Fotocasa API error (${response.status}) @ ${baseUrl}: ${text}`);
    lastError = err;

    const hasFallbackHost = baseUrls.length > 1 && baseUrl !== baseUrls[baseUrls.length - 1];
    if (hasFallbackHost && isLikelyBlockPage(response.status, text)) {
      logger.warn(`Fotocasa: blocked on ${baseUrl}, trying fallback mobile backend`);
      continue;
    }

    throw err;
  }

  throw lastError ?? new Error('Fotocasa API request failed');
}

function extractPlaceholders(payload) {
  // v3 returns PlaceholdersSearcherPropertiesListDto directly,
  // legacy searchByUrl wraps it under searcherPlaceholdersListDto.
  const root = payload?.searcherPlaceholdersListDto ?? payload;
  const placeholders = root?.placeholders ?? [];
  return Array.isArray(placeholders) ? placeholders : [];
}

function extractTotalCount(payload) {
  const root = payload?.searcherPlaceholdersListDto ?? payload;
  return toPositiveInt(root?.info?.count);
}

function mapPlaceholdersToListings(placeholders) {
  return placeholders
    .filter(
      (placeholder) =>
        (placeholder.type === 'PROPERTY' || placeholder.type === 'SUPER_TOP') && placeholder.property != null,
    )
    .map((placeholder) => {
      const property = placeholder.property;
      return {
        id: String(property.propertyId),
        price: property.price != null ? String(property.price) : null,
        size: property.surface != null ? `${property.surface} m²` : null,
        title: property.title || property.addressLine || null,
        description: property.comments || null,
        link: property.urlMarketplace || null,
        address: property.addressLine || null,
        image: property.photoLarge || property.photo || null,
        latitude: property.latitude ?? null,
        longitude: property.longitude ?? null,
      };
    });
}

function extractUrlParametersDto(translateResponse) {
  return (
    translateResponse?.urlParametersDto ??
    translateResponse?.data?.urlParametersDto ??
    translateResponse?.data ??
    translateResponse
  );
}

function mapTranslatedUrlParametersToQuery(urlParameters = {}, defaultQuery) {
  const query = { ...defaultQuery };

  putIfPresent(query, 'transactionType', urlParameters.transactionType);
  putIfPresent(query, 'propertyType', urlParameters.propertyType);
  putIfPresent(query, 'purchaseType', urlParameters.purchaseType);
  putIfPresent(
    query,
    'paymentPeriodicityList',
    urlParameters.paymentPeriodicity ?? urlParameters.paymentPeriodicityList,
  );
  putIfPresent(query, 'text', urlParameters.text);
  // Deeplink translator can expose either a resolved location ids string
  // or a human location label. The v3 list endpoint expects "locations".
  putIfPresent(query, 'locations', sanitizeLocations(urlParameters.locations));
  putIfPresent(query, 'priceFrom', urlParameters.priceFrom);
  putIfPresent(query, 'priceTo', urlParameters.priceTo);
  putIfPresent(query, 'surfaceFrom', urlParameters.surfaceFrom);
  putIfPresent(query, 'surfaceTo', urlParameters.surfaceTo);
  putIfPresent(query, 'roomsFrom', urlParameters.roomsFrom ?? urlParameters.rooms);
  putIfPresent(query, 'roomsTo', urlParameters.roomsTo);
  putIfPresent(query, 'bathroomsFrom', urlParameters.bathroomsFrom ?? urlParameters.bathrooms);
  putIfPresent(query, 'bathroomsTo', urlParameters.bathroomsTo);
  putIfPresent(query, 'conservationStates', asCsv(urlParameters.conservationStates));
  putIfPresent(query, 'extras', asCsv(urlParameters.extras));
  putIfPresent(query, 'zipCode', urlParameters.zipCode);
  putIfPresent(query, 'publicationDate', urlParameters.publicationDate);
  putIfPresent(query, 'floorType', asCsv(urlParameters.floorType ?? urlParameters.floorTypes));
  putIfPresent(query, 'orientations', asCsv(urlParameters.orientations));
  putIfPresent(query, 'occupancyStatus', asCsv(urlParameters.occupancyStatus ?? urlParameters.occupancyStatusFilter));
  putIfPresent(query, 'rentalDuration', asCsv(urlParameters.rentalDuration));
  putIfPresent(query, 'contracts', asCsv(urlParameters.contracts));
  putIfPresent(
    query,
    'propertySubTypeList',
    asCsv(urlParameters.propertySubTypeList ?? urlParameters.propertySubtypeList),
  );

  if (urlParameters.hasVideosOrTourVirtual != null) {
    query.hasVideosOrTourVirtual = String(urlParameters.hasVideosOrTourVirtual);
  }
  if (urlParameters.hasPriceDrop != null) {
    query.hasPriceDrop = String(urlParameters.hasPriceDrop);
  }
  if (urlParameters.isBankFlats != null || urlParameters.isBankFlat != null) {
    query.isBankFlat = String(urlParameters.isBankFlats ?? urlParameters.isBankFlat);
  }
  if (urlParameters.hasSubsidies != null) {
    query.hasSubsidies = String(urlParameters.hasSubsidies);
  }

  // Defaults used by app-side request model when absent.
  putIfPresent(query, 'clientId', urlParameters.clientId ?? DEFAULT_CLIENT_ID);
  putIfPresent(query, 'page', urlParameters.page ?? DEFAULT_PAGE);
  putIfPresent(query, 'pageSize', urlParameters.pageSize ?? DEFAULT_PAGE_SIZE);
  putIfPresent(query, 'sort', urlParameters.sort ?? DEFAULT_SORT);
  putIfPresent(
    query,
    'advertisingSaitamaClientVersion',
    urlParameters.advertisingSaitamaClientVersion ?? DEFAULT_SAITAMA_CLIENT_VERSION,
  );

  return query;
}

function parseSearchUrlToQuery(searchUrl) {
  const query = {
    clientId: DEFAULT_CLIENT_ID,
    page: DEFAULT_PAGE,
    pageSize: DEFAULT_PAGE_SIZE,
    sort: DEFAULT_SORT,
    advertisingSaitamaClientVersion: DEFAULT_SAITAMA_CLIENT_VERSION,
  };

  const parsed = new URL(searchUrl);
  const segments = parsed.pathname.split('/').filter(Boolean);
  const start = segments[0] && segments[0].length === 2 ? 1 : 0;

  const transactionSlug = segments[start]?.toLowerCase();
  const propertySlug = segments[start + 1]?.toLowerCase();
  const locationSlug = segments[start + 2]?.toLowerCase();

  putIfPresent(query, 'transactionType', TRANSACTION_SLUG_TO_TYPE[transactionSlug] ?? 'RENT');
  putIfPresent(query, 'propertyType', PROPERTY_SLUG_TO_TYPE[propertySlug] ?? 'HOME');

  // When we only have a semantic location slug, use it as free-text fallback.
  if (locationSlug && locationSlug !== 'todas-las-zonas') {
    putIfPresent(query, 'text', locationSlug.replace(/-/g, ' '));
  }

  for (const key of LOCATION_PARAM_CANDIDATES) {
    const raw = sanitizeLocations(parsed.searchParams.get(key));
    if (raw != null) {
      query.locations = raw;
      break;
    }
  }

  const textCandidates = ['text', 'q', 'query', 'search'];
  for (const key of textCandidates) {
    const value = parsed.searchParams.get(key);
    if (value != null && value.trim().length > 0) {
      query.text = value.trim();
      break;
    }
  }

  const directMappings = [
    ['priceFrom', 'priceFrom'],
    ['priceTo', 'priceTo'],
    ['surfaceFrom', 'surfaceFrom'],
    ['surfaceTo', 'surfaceTo'],
    ['roomsFrom', 'roomsFrom'],
    ['roomsTo', 'roomsTo'],
    ['bathroomsFrom', 'bathroomsFrom'],
    ['bathroomsTo', 'bathroomsTo'],
    ['zipCode', 'zipCode'],
  ];

  for (const [paramKey, queryKey] of directMappings) {
    putIfPresent(query, queryKey, parsed.searchParams.get(paramKey));
  }

  return query;
}

async function tryTranslatedQuery(searchUrl, fallbackQuery) {
  const translatePayload = await fetchJson(TRANSLATE_PATH, { urlValue: searchUrl });
  const urlParameters = extractUrlParametersDto(translatePayload);
  const translatedQuery = mapTranslatedUrlParametersToQuery(urlParameters, fallbackQuery);
  logger.debug(`Fotocasa: translated semantic URL to v3 query keys: ${Object.keys(translatedQuery).join(', ')}`);
  return translatedQuery;
}

async function fetchV3Placeholders(query) {
  const payload = await fetchJson(SEARCH_V3_PATH, query, { appendRawMediaSizes: true });
  const placeholders = extractPlaceholders(payload);
  const totalCount = extractTotalCount(payload);
  logger.debug(
    `Fotocasa: v3 page=${query.page ?? DEFAULT_PAGE} returned ${placeholders.length} placeholder items` +
      (totalCount != null ? ` (count=${totalCount})` : ''),
  );
  return { placeholders, totalCount };
}

async function fetchAllV3Listings(query) {
  const pageSize = toPositiveInt(query.pageSize) ?? toPositiveInt(DEFAULT_PAGE_SIZE) ?? 36;
  const firstPage = toPositiveInt(query.page) ?? toPositiveInt(DEFAULT_PAGE) ?? 1;

  const listings = [];
  const seenListingIds = new Set();
  let totalCount = null;
  let fetchedPages = 0;

  for (let offset = 0; offset < MAX_PAGES_PER_QUERY; offset += 1) {
    const page = firstPage + offset;
    const pagedQuery = { ...query, page: String(page) };
    const { placeholders, totalCount: pageTotalCount } = await fetchV3Placeholders(pagedQuery);
    fetchedPages += 1;

    if (pageTotalCount != null) {
      totalCount = pageTotalCount;
    }

    if (placeholders.length === 0) {
      break;
    }

    for (const listing of mapPlaceholdersToListings(placeholders)) {
      if (!seenListingIds.has(listing.id)) {
        seenListingIds.add(listing.id);
        listings.push(listing);
      }
    }

    if (totalCount != null && listings.length >= totalCount) {
      break;
    }

    if (placeholders.length < pageSize) {
      break;
    }
  }

  if (fetchedPages >= MAX_PAGES_PER_QUERY) {
    logger.warn(`Fotocasa: reached pagination safety cap (${MAX_PAGES_PER_QUERY} pages)`);
  }

  logger.debug(`Fotocasa: aggregated ${listings.length} listing(s) from ${fetchedPages} page(s)`);
  return listings;
}

function uniqueQueries(queries) {
  const seen = new Set();
  const output = [];
  for (const query of queries) {
    if (query == null) continue;
    const key = JSON.stringify(
      Object.keys(query)
        .sort()
        .reduce((acc, current) => {
          acc[current] = query[current];
          return acc;
        }, {}),
    );
    if (!seen.has(key)) {
      seen.add(key);
      output.push(query);
    }
  }
  return output;
}

async function getListings(searchUrl) {
  try {
    const fallbackQuery = parseSearchUrlToQuery(searchUrl);

    let translatedQuery = null;
    try {
      translatedQuery = await tryTranslatedQuery(searchUrl, fallbackQuery);
    } catch (err) {
      logger.warn(`Fotocasa: semantic URL translation failed, using parser fallback (${err.message})`);
    }

    const strippedLocationQuery = { ...fallbackQuery };
    delete strippedLocationQuery.locations;

    const queryAttempts = uniqueQueries([translatedQuery, fallbackQuery, strippedLocationQuery]);
    for (const query of queryAttempts) {
      try {
        const listings = await fetchAllV3Listings(query);
        if (listings.length > 0) {
          return listings;
        }
      } catch (err) {
        logger.warn(`Fotocasa: v3 search failed with query attempt (${err.message})`);
      }
    }
    return [];
  } catch (err) {
    logger.error('Error fetching data from Fotocasa API:', err.message);
    return [];
  }
}

function normalize(o) {
  const id = buildHash(o.id, o.price);
  return Object.assign(o, { id });
}

function applyBlacklist(o) {
  if (o.title == null) return false;
  return !isOneOf(o.title, appliedBlackList) && !isOneOf(o.description, appliedBlackList);
}

const config = {
  url: null,
  sortByDateParam: null,
  crawlFields: {
    id: 'id',
    title: 'title',
    price: 'price',
    size: 'size',
    link: 'link',
    address: 'address',
  },
  normalize,
  filter: applyBlacklist,
  getListings,
  activeTester: checkIfListingIsActive,
};

export const metaInformation = {
  name: 'Fotocasa',
  baseUrl: 'https://www.fotocasa.es/',
  id: 'fotocasa',
};

export const init = (sourceConfig, blacklist) => {
  config.enabled = sourceConfig.enabled;
  config.url = sourceConfig.url;
  appliedBlackList = blacklist || [];
};

export { config };

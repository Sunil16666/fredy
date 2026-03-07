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
import { existsSync, readFileSync } from 'fs';
import { join } from 'path';
import { buildHash, isOneOf } from '../utils.js';
import checkIfListingIsActive from '../services/listings/listingActiveTester.js';
import logger from '../services/logger.js';

const API_GATEWAY_BASE_URL = 'https://apps.gw.fotocasa.es';
const DEFAULT_BASE_URLS = [API_GATEWAY_BASE_URL];

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
const DEFAULT_X_D_TOKEN_FILE_PATH = join(process.cwd(), 'db', 'fotocasa-x-d-token.txt');
const DEFAULT_COOKIE_FILE_CANDIDATES = [
  join(process.cwd(), 'cookies.txt'),
  join(process.cwd(), 'db', 'fotocasa-cookies.txt'),
];

const LOCATION_PARAM_CANDIDATES = ['locations', 'combinedLocationIds', 'combinedLocationsIds', 'locationCodes'];

const TRANSACTION_SLUG_TO_TYPE = {
  alquiler: 'RENT',
  rent: 'RENT',
  rental: 'RENT',
  comprar: 'SALE',
  buy: 'SALE',
  sale: 'SALE',
  venta: 'SALE',
  traspaso: 'TRANSFER',
  transfer: 'TRANSFER',
  compartir: 'SHARE',
  share: 'SHARE',
  'alquiler-con-opcion-a-compra': 'RENT_WITH_OPTION_TO_BUY',
  vacacional: 'HOLIDAY_RENTAL',
  'alquiler-vacacional': 'HOLIDAY_RENTAL',
  holiday: 'HOLIDAY_RENTAL',
  'holiday-rental': 'HOLIDAY_RENTAL',
};

const PROPERTY_SLUG_TO_TYPE = {
  vivienda: 'HOME',
  viviendas: 'HOME',
  home: 'HOME',
  homes: 'HOME',
  piso: 'HOME',
  pisos: 'HOME',
  flat: 'HOME',
  flats: 'HOME',
  apartment: 'HOME',
  apartments: 'HOME',
  casa: 'HOME',
  casas: 'HOME',
  house: 'HOME',
  houses: 'HOME',
  habitacion: 'HOME',
  habitaciones: 'HOME',
  room: 'HOME',
  rooms: 'HOME',
  garaje: 'GARAGE',
  garajes: 'GARAGE',
  garage: 'GARAGE',
  garages: 'GARAGE',
  terreno: 'LAND',
  terrenos: 'LAND',
  land: 'LAND',
  local: 'COMMERCIAL_PREMISES',
  locales: 'COMMERCIAL_PREMISES',
  'local-comercial': 'COMMERCIAL_PREMISES',
  'locales-comerciales': 'COMMERCIAL_PREMISES',
  commercial: 'COMMERCIAL_PREMISES',
  oficina: 'OFFICE',
  oficinas: 'OFFICE',
  office: 'OFFICE',
  offices: 'OFFICE',
  trastero: 'BOX_ROOM',
  trasteros: 'BOX_ROOM',
  storeroom: 'BOX_ROOM',
  storerooms: 'BOX_ROOM',
  edificio: 'BUILDING',
  edificios: 'BUILDING',
  building: 'BUILDING',
  buildings: 'BUILDING',
};

const SORT_TYPE_TO_SORT = {
  publicationDate: '0',
  relevancy: '1',
  relevance: '1',
  priceAsc: '2',
  priceDesc: '3',
  surfaceAsc: '4',
  surfaceDesc: '5',
  roomsAsc: '6',
  roomsDesc: '7',
};

let appliedBlackList = [];
let configuredImpervaToken = null;
let configuredCookieHeader = null;
let configuredImpervaTokenFile = null;
let configuredCookieFile = null;
let hasLoggedMissingCredentialWarning = false;

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
  refreshProtectionHeadersFromFiles();
  const timestamp = Date.now();
  const headers = {
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

  // The mobile app injects this on protected endpoints via Imperva SDK.
  if (configuredImpervaToken != null) {
    headers['X-D-Token'] = configuredImpervaToken;
  }

  // Optional cookie passthrough for users who solve challenges in a browser.
  if (configuredCookieHeader != null) {
    headers.Cookie = configuredCookieHeader;
  }

  return headers;
}

function stringify(value) {
  if (value == null) return null;
  const str = String(value).trim();
  return str.length > 0 ? str : null;
}

function readTextFile(pathLike) {
  const path = stringify(pathLike);
  if (path == null || !existsSync(path)) return null;
  try {
    return stringify(readFileSync(path, 'utf8'));
  } catch (err) {
    logger.warn(`Fotocasa: could not read file "${path}": ${err.message}`);
    return null;
  }
}

function parseCookieFile(rawText) {
  const text = stringify(rawText);
  if (text == null) return null;

  // Netscape cookies.txt format.
  const cookies = text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith('#'))
    .map((line) => line.split('\t'))
    .filter((parts) => parts.length >= 7)
    .map((parts) => `${parts[5]}=${parts[6]}`)
    .filter((entry) => !entry.endsWith('='));

  if (cookies.length > 0) {
    return cookies.join('; ');
  }

  // Plain header value fallback.
  return text.includes('=') ? text : null;
}

function resolveImpervaToken(sourceConfig) {
  const directToken = stringify(sourceConfig?.xDToken ?? sourceConfig?.x_d_token ?? process.env.FOTOCASA_X_D_TOKEN);
  if (directToken != null) return directToken;

  const tokenFile = stringify(
    sourceConfig?.xDTokenFile ??
      sourceConfig?.x_d_token_file ??
      process.env.FOTOCASA_X_D_TOKEN_FILE ??
      DEFAULT_X_D_TOKEN_FILE_PATH,
  );
  configuredImpervaTokenFile = tokenFile;
  return readTextFile(tokenFile);
}

function resolveCookieHeader(sourceConfig) {
  const directCookie = stringify(sourceConfig?.cookie ?? sourceConfig?.cookies ?? process.env.FOTOCASA_COOKIE);
  if (directCookie != null) return directCookie;

  const explicitCookieFile = stringify(
    sourceConfig?.cookieFile ?? sourceConfig?.cookiesFile ?? process.env.FOTOCASA_COOKIE_FILE,
  );
  const candidateFiles = explicitCookieFile != null ? [explicitCookieFile] : DEFAULT_COOKIE_FILE_CANDIDATES;

  for (const cookieFile of candidateFiles) {
    configuredCookieFile = cookieFile;
    const cookieHeader = parseCookieFile(readTextFile(cookieFile));
    if (cookieHeader != null) return cookieHeader;
  }

  return null;
}

function refreshProtectionHeadersFromFiles() {
  if (configuredImpervaToken == null && configuredImpervaTokenFile != null) {
    configuredImpervaToken = readTextFile(configuredImpervaTokenFile);
  }

  if (configuredCookieHeader == null && configuredCookieFile != null) {
    configuredCookieHeader = parseCookieFile(readTextFile(configuredCookieFile));
  }
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

function decodeURIComponentSafe(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function decodeUriComponentRepeated(value, maxDepth = 3) {
  let current = value;
  for (let idx = 0; idx < maxDepth; idx += 1) {
    const decoded = decodeURIComponentSafe(current);
    if (decoded === current) break;
    current = decoded;
  }
  return current;
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
  if ((status !== 403 && status !== 429) || typeof text !== 'string') return false;
  const normalized = text.toLowerCase();
  return (
    normalized.includes('pardon our interruption') ||
    normalized.includes('complete the captcha below') ||
    normalized.includes('relibrary.js') ||
    normalized.includes('imperva')
  );
}

function truncateText(text, maxLength = 320) {
  if (text.length <= maxLength) return text;
  return `${text.slice(0, maxLength)}...`;
}

function summarizeErrorPayload(text) {
  if (typeof text !== 'string') return '<non-text response>';
  const trimmed = text.trim();
  if (trimmed.length === 0) return '<empty body>';

  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    return truncateText(trimmed, 640);
  }

  const normalized = trimmed.replace(/\s+/g, ' ');
  if (normalized.toLowerCase().includes('pardon our interruption')) {
    return 'Pardon Our Interruption challenge page';
  }

  return truncateText(normalized);
}

function createApiError(status, baseUrl, text) {
  const blockedByBotProtection = isLikelyBlockPage(status, text);
  const payloadSummary = summarizeErrorPayload(text);

  const error = new Error(
    blockedByBotProtection
      ? `Fotocasa API blocked (${status}) @ ${baseUrl}: Imperva challenge detected`
      : `Fotocasa API error (${status}) @ ${baseUrl}: ${payloadSummary}`,
  );
  error.status = status;
  error.baseUrl = baseUrl;
  error.isBotBlocked = blockedByBotProtection;
  return error;
}

async function fetchJson(path, query, options = {}) {
  const { appendRawMediaSizes = false, baseUrls = DEFAULT_BASE_URLS } = options;

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
    const err = createApiError(response.status, baseUrl, text);
    lastError = err;

    const hasFallbackHost = baseUrls.length > 1 && baseUrl !== baseUrls[baseUrls.length - 1];
    if (hasFallbackHost && err.isBotBlocked) {
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
  const start = /^[a-z]{2}(?:-[a-z]{2})?$/i.test(segments[0] ?? '') ? 1 : 0;

  const transactionSlug = segments[start]?.toLowerCase();
  const propertySlug = segments[start + 1]?.toLowerCase();
  const locationSlug = segments[start + 2]?.toLowerCase();

  putIfPresent(query, 'transactionType', TRANSACTION_SLUG_TO_TYPE[transactionSlug] ?? 'RENT');
  putIfPresent(query, 'propertyType', PROPERTY_SLUG_TO_TYPE[propertySlug] ?? 'HOME');

  // When we only have a semantic location slug, use it as free-text fallback.
  if (locationSlug && locationSlug !== 'todas-las-zonas' && locationSlug !== 'all-zones') {
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
    ['priceFrom', ['priceFrom', 'minPrice']],
    ['priceTo', ['priceTo', 'maxPrice']],
    ['surfaceFrom', ['surfaceFrom', 'minSurface']],
    ['surfaceTo', ['surfaceTo', 'maxSurface']],
    ['roomsFrom', ['roomsFrom', 'minRooms']],
    ['roomsTo', ['roomsTo', 'maxRooms']],
    ['bathroomsFrom', ['bathroomsFrom', 'minBathrooms']],
    ['bathroomsTo', ['bathroomsTo', 'maxBathrooms']],
    ['zipCode', ['zipCode', 'postalCode']],
    ['propertySubTypeList', ['propertySubTypeList', 'propertySubtypeList', 'propertySubtypeIds', 'propertySubTypeIds']],
  ];

  for (const [queryKey, paramKeys] of directMappings) {
    for (const paramKey of paramKeys) {
      const value = parsed.searchParams.get(paramKey);
      if (value != null && value.trim().length > 0) {
        putIfPresent(query, queryKey, decodeUriComponentRepeated(value));
        break;
      }
    }
  }

  const explicitSort = stringify(parsed.searchParams.get('sort'));
  if (explicitSort != null) {
    query.sort = explicitSort;
  } else {
    const sortType = stringify(parsed.searchParams.get('sortType'));
    if (sortType != null) {
      putIfPresent(query, 'sort', SORT_TYPE_TO_SORT[sortType] ?? SORT_TYPE_TO_SORT[sortType.toLowerCase()]);
    }
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

function validateTranslatedQuery(query, searchUrl) {
  if (query == null || typeof query !== 'object') {
    throw new Error(`Fotocasa: invalid translatesemantic response for "${searchUrl}"`);
  }
  if (stringify(query.transactionType) == null) {
    throw new Error(`Fotocasa: translatesemantic did not provide transactionType for "${searchUrl}"`);
  }
  if (stringify(query.propertyType) == null) {
    throw new Error(`Fotocasa: translatesemantic did not provide propertyType for "${searchUrl}"`);
  }
  if (stringify(query.text) == null && stringify(query.locations) == null) {
    throw new Error(`Fotocasa: translatesemantic did not provide text or locations for "${searchUrl}"`);
  }
}

async function getListings(searchUrl) {
  const fallbackQuery = parseSearchUrlToQuery(searchUrl);
  const translatedQuery = await tryTranslatedQuery(searchUrl, fallbackQuery);
  validateTranslatedQuery(translatedQuery, searchUrl);
  return fetchAllV3Listings(translatedQuery);
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
  const safeSourceConfig = sourceConfig ?? {};
  config.enabled = safeSourceConfig.enabled;
  config.url = safeSourceConfig.url;

  configuredImpervaToken = null;
  configuredCookieHeader = null;
  configuredImpervaTokenFile = null;
  configuredCookieFile = null;

  configuredImpervaToken = resolveImpervaToken(safeSourceConfig);
  configuredCookieHeader = resolveCookieHeader(safeSourceConfig);

  if (configuredImpervaToken != null || configuredCookieHeader != null) {
    logger.debug('Fotocasa: loaded anti-bot credentials for protected mobile endpoint');
  } else {
    if (!hasLoggedMissingCredentialWarning) {
      logger.warn(
        'Fotocasa: no anti-bot credentials found (X-D-Token/cookie); protected requests may fail. Configure xDToken/cookie or FOTOCASA_X_D_TOKEN/FOTOCASA_COOKIE.',
      );
      hasLoggedMissingCredentialWarning = true;
    }
  }

  appliedBlackList = blacklist || [];
};

export { config };

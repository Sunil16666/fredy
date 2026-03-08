/*
 * Copyright (c) 2026 by Christian Kellner.
 * Licensed under Apache-2.0 with Commons Clause and Attribution/Naming Clause
 */

/**
 * Idealista provider using the undocumented mobile API.
 *
 * Reverse-engineered from Idealista Android app v14.3.3.
 * Authentication: OAuth2 client_credentials (no HMAC).
 * All other requests: HMAC-SHA256 signed (Signature + seed headers).
 *
 * Base URL: https://app.idealista.com
 * OAuth:    POST /api/oauth/token
 * Search:   POST /api/3.5/{country}/search  (form-encoded @FieldMap)
 * Locations: GET /api/3/{country}/locations?prefix=...
 */

import { createHmac, randomUUID } from 'crypto';
import { readFileSync, writeFileSync, mkdirSync } from 'fs';
import { join } from 'path';
import { buildHash, isOneOf } from '../utils.js';
import checkIfListingIsActive from '../services/listings/listingActiveTester.js';
import logger from '../services/logger.js';

const BASE_URL = 'https://app.idealista.com';
const API_KEY = '5b85c03c16bbb85d96e232b112ee85dc';
const SECRET_KEY = 'idea;andr01d';
// HMAC key used as raw UTF-8 bytes of this literal string (NOT base64-decoded)
const HMAC_KEY = 'bXBUUW5TODhKdFhENmQyRQ==';
const APP_VERSION = '14.3.3';
const DEVICE_ID = 'deadbeefdeadbeef';

// Token is persisted to disk so it survives process restarts and avoids
// hammering the OAuth endpoint (rate-limited) on every startup.
const TOKEN_CACHE_PATH = join(process.cwd(), 'db', 'idealista-token.json');
const LOCATION_CACHE_PATH = join(process.cwd(), 'db', 'idealista-location-cache.json');

let cachedToken = null;
let tokenExpiry = 0;
let locationCache = {};
let appliedBlackList = [];

function loadPersistedToken() {
  try {
    const raw = readFileSync(TOKEN_CACHE_PATH, 'utf8');
    const { token, expiry } = JSON.parse(raw);
    if (token && expiry > Date.now()) {
      cachedToken = token;
      tokenExpiry = expiry;
      logger.debug('Idealista: loaded OAuth token from disk cache');
    }
  } catch {
    // No cache file yet or unreadable — fine, will fetch fresh token
  }
}

function persistToken(token, expiry) {
  try {
    mkdirSync(join(process.cwd(), 'db'), { recursive: true });
    writeFileSync(TOKEN_CACHE_PATH, JSON.stringify({ token, expiry }), 'utf8');
  } catch (err) {
    logger.warn('Idealista: could not persist OAuth token to disk:', err.message);
  }
}

function loadPersistedLocationCache() {
  try {
    const raw = readFileSync(LOCATION_CACHE_PATH, 'utf8');
    locationCache = JSON.parse(raw);
    logger.debug(`Idealista: loaded ${Object.keys(locationCache).length} location(s) from disk cache`);
  } catch {
    // No cache file yet — fine, will resolve on first request
  }
}

function persistLocationCache() {
  try {
    mkdirSync(join(process.cwd(), 'db'), { recursive: true });
    writeFileSync(LOCATION_CACHE_PATH, JSON.stringify(locationCache), 'utf8');
  } catch (err) {
    logger.warn('Idealista: could not persist location cache to disk:', err.message);
  }
}

loadPersistedToken();
loadPersistedLocationCache();

// Java URLEncoder semantics: spaces → '+'; encodes ! ' ( ) * ~ unlike encodeURIComponent
function javaUrlEncode(s) {
  return encodeURIComponent(String(s))
    .replace(/%20/g, '+')
    .replace(/[!'()*~]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());
}

function buildSortedParamString(params) {
  return Object.entries(params)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${javaUrlEncode(k)}=${javaUrlEncode(v)}`)
    .join('&');
}

// Compute Signature + seed headers for a signed request
// bodyParams: null for GET, object for form-POST
function computeSignature(method, queryParams, bodyParams) {
  const nonce = randomUUID();
  const qStr = buildSortedParamString(queryParams);

  let message;
  if (bodyParams) {
    const bStr = buildSortedParamString(bodyParams);
    // form POST: nonce + METHOD + sortedQuery + sortedBody + ""
    message = nonce + method.toUpperCase() + qStr + bStr;
  } else {
    // GET: nonce + METHOD + sortedQuery
    message = nonce + method.toUpperCase() + qStr;
  }

  const sig = createHmac('sha256', Buffer.from(HMAC_KEY, 'utf8')).update(message, 'utf8').digest('hex');

  return { Signature: sig, seed: nonce };
}

function baseHeaders() {
  return {
    app_version: APP_VERSION,
    device_identifier: DEVICE_ID,
    'User-Agent': `idealista/${APP_VERSION} (Android)`,
    Accept: 'application/json',
  };
}

// fic.java RequestInterceptor always appends k (apikey) and t (device_id) to query
function withApiParams(extraQuery = {}) {
  return { k: API_KEY, t: DEVICE_ID, ...extraQuery };
}

function buildQs(params) {
  return Object.entries(params)
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join('&');
}

async function getOAuthToken() {
  const now = Date.now();
  if (cachedToken && now < tokenExpiry) return cachedToken;

  // x8a.java: Basic base64(URLEncode(consumerKey) + ":" + URLEncode(consumerSecret))
  const credentials = Buffer.from(`${javaUrlEncode(API_KEY)}:${javaUrlEncode(SECRET_KEY)}`, 'utf8').toString('base64');

  const response = await fetch(`${BASE_URL}/api/oauth/token`, {
    method: 'POST',
    headers: {
      ...baseHeaders(),
      Authorization: `Basic ${credentials}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: 'grant_type=client_credentials&scope=write',
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Idealista OAuth failed (${response.status}): ${text}`);
  }

  const data = await response.json();
  cachedToken = data.access_token;
  tokenExpiry = now + (data.expires_in - 60) * 1000;
  persistToken(cachedToken, tokenExpiry);
  return cachedToken;
}

async function apiGet(path, queryParams) {
  const allQuery = withApiParams(queryParams);
  const { Signature, seed } = computeSignature('GET', allQuery, null);
  const token = await getOAuthToken();

  const response = await fetch(`${BASE_URL}${path}?${buildQs(allQuery)}`, {
    method: 'GET',
    headers: {
      ...baseHeaders(),
      Authorization: `Bearer ${token}`,
      Signature,
      seed,
    },
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Idealista GET ${path} failed (${response.status}): ${text}`);
  }
  return response.json();
}

async function apiPost(path, queryParams, bodyParams) {
  const allQuery = withApiParams(queryParams);
  const { Signature, seed } = computeSignature('POST', allQuery, bodyParams);
  const token = await getOAuthToken();

  const bodyStr = Object.entries(bodyParams)
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join('&');

  const response = await fetch(`${BASE_URL}${path}?${buildQs(allQuery)}`, {
    method: 'POST',
    headers: {
      ...baseHeaders(),
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/x-www-form-urlencoded',
      Signature,
      seed,
    },
    body: bodyStr,
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Idealista POST ${path} failed (${response.status}): ${text}`);
  }
  return response.json();
}

// Decode a Google Encoded Polyline string into [[lat, lng], ...] pairs.
function decodePolyline(encoded) {
  const coords = [];
  let index = 0,
    lat = 0,
    lng = 0;
  while (index < encoded.length) {
    let b,
      shift = 0,
      result = 0;
    do {
      b = encoded.charCodeAt(index++) - 63;
      result |= (b & 0x1f) << shift;
      shift += 5;
    } while (b >= 0x20);
    lat += result & 1 ? ~(result >> 1) : result >> 1;
    shift = 0;
    result = 0;
    do {
      b = encoded.charCodeAt(index++) - 63;
      result |= (b & 0x1f) << shift;
      shift += 5;
    } while (b >= 0x20);
    lng += result & 1 ? ~(result >> 1) : result >> 1;
    coords.push([lat / 1e5, lng / 1e5]);
  }
  return coords;
}

// Convert an Idealista shape param (encoded polyline, optionally wrapped in ((...))) to a
// GeoJSON Polygon string that the mobile API's `shape` body parameter accepts.
function polylineToGeoJsonShape(encoded) {
  const clean = encoded.replace(/^\(\(/, '').replace(/\)\)$/, '');
  const coords = decodePolyline(clean);
  return JSON.stringify({ type: 'Polygon', coordinates: [coords.map(([lat, lng]) => [lng, lat])] });
}

// Map URL filter path segments to API body parameter names.
// The path segment format is: con-{key}_{value},{key}_{value},...
const URL_FILTER_MAP = {
  'precio-hasta': 'maxPrice',
  'precio-desde': 'minPrice',
  'metros-cuadrados-mas-de': 'minSize',
  'metros-cuadrados-menos-de': 'maxSize',
  'habitaciones-mas-de': 'minRooms',
  'habitaciones-igual-a': 'minRooms',
  'banos-mas-de': 'minBathrooms',
};

// Keyword-only filter tokens (no _value suffix) → API params
const URL_KEYWORD_FILTERS = {
  'de-un-dormitorio': { minRooms: 1 },
  'de-dos-dormitorios': { minRooms: 2 },
  'de-tres-dormitorios': { minRooms: 3 },
  'de-cuatro-cinco-habitaciones-o-mas': { minRooms: 4 },
  ascensor: { lift: '1' },
  exterior: { exterior: '1' },
  'sin-inquilinos': { noTenants: '1' },
};

function parseFilters(filterSegment) {
  const filters = {};
  if (!filterSegment || !filterSegment.startsWith('con-')) return filters;
  let minRooms = null;
  for (const part of filterSegment.slice(4).split(',')) {
    // Keyword-only tokens
    const kw = URL_KEYWORD_FILTERS[part];
    if (kw) {
      if (kw.minRooms != null) {
        // Multiple room-count keywords → take the minimum (most permissive)
        minRooms = minRooms == null ? kw.minRooms : Math.min(minRooms, kw.minRooms);
      } else {
        Object.assign(filters, kw);
      }
      continue;
    }
    // key_value tokens
    const idx = part.lastIndexOf('_');
    if (idx === -1) continue;
    const apiKey = URL_FILTER_MAP[part.slice(0, idx)];
    if (apiKey) filters[apiKey] = part.slice(idx + 1);
  }
  if (minRooms != null) filters.minRooms = String(minRooms);
  return filters;
}

// Resolve a URL location slug (e.g. "madrid-madrid") to an API locationId.
// Prefers the most geographically specific match (longest locationId).
// Cached per slug to avoid repeated lookups.
async function resolveLocationId(country, slug, operation, propertyType) {
  const cacheKey = `${country}:${slug}`;
  if (locationCache[cacheKey]) return locationCache[cacheKey];

  // Use the last word of the slug as prefix — it tends to be the most specific part.
  // e.g. "madrid-madrid" → "madrid", "valencia-valencia" → "valencia"
  const words = slug.split('-');
  const prefix = words[words.length - 1];
  logger.debug(`Idealista: resolving location slug="${slug}" using prefix="${prefix}"`);

  const data = await apiGet(`/api/3/${country}/locations`, {
    prefix,
    propertyType,
    operation,
  });

  const locations = Array.isArray(data) ? data : data.locations || [];
  if (!locations.length) {
    throw new Error(`Idealista: no locations found for slug "${slug}" (prefix "${prefix}")`);
  }

  // Log raw details of top candidates to aid debugging
  logger.debug(
    `Idealista: ${locations.length} location candidates (raw top-5): ${JSON.stringify(
      locations.slice(0, 5).map((l) => ({
        name: l.name,
        locationId: l.locationId,
        subType: l.subType,
        subTypeText: l.subTypeText,
        divisible: l.divisible,
        total: l.total,
      })),
    )}`,
  );

  // API returns municipality names in "City, Province" format (e.g. "Madrid, Madrid").
  // The URL slug uses hyphens instead: "madrid-madrid".
  // Scoring:
  //   3 = full slug matches after replacing ", " → "-"  (e.g. "Madrid, Madrid" → "madrid-madrid")
  //   2 = city part (before comma) matches full slug   (e.g. "Barcelona" from single-word slug)
  //   1 = city part matches last slug word             (fallback)
  //   0 = no match
  // Ties broken by subTypeText preference (municipality > district > province), then segment count.
  const SUBTYPE_RANK = {
    Municipio: 3,
    Capital: 3,
    Distrito: 2,
    Barrio: 2,
    Comarca: 1,
    Provincia: 0,
    'Comunidad Autónoma': 0,
  };
  const slugFull = slug.toLowerCase();
  const slugLast = words[words.length - 1].toLowerCase();

  const scored = locations
    .map((loc) => {
      const rawName = (loc.name || '').toLowerCase();
      // City part: the portion before the first ", " (if present)
      const cityPart = rawName.split(',')[0].trim().replace(/\s+/g, '-');
      // Full normalized name: replace ", " separator with "-" to match slug format
      const fullNorm = rawName.replace(/,\s*/g, '-').replace(/\s+/g, '-');
      const locId = loc.locationId || '';
      const score = fullNorm === slugFull ? 3 : cityPart === slugFull ? 2 : cityPart === slugLast ? 1 : 0;
      const subtypeRank = SUBTYPE_RANK[loc.subTypeText] ?? 1;
      const segments = locId ? locId.split('-').length : 0;
      return { loc, score, subtypeRank, segments };
    })
    .sort((a, b) => b.score - a.score || b.subtypeRank - a.subtypeRank || b.segments - a.segments);

  const best = scored[0].loc;
  const locationId = best.locationId;
  logger.debug(
    `Idealista: selected locationId="${locationId}" (name="${best.name}", ` +
      `subTypeText="${best.subTypeText}", score=${scored[0].score}, ` +
      `subtypeRank=${scored[0].subtypeRank}, segments=${scored[0].segments})`,
  );
  locationCache[cacheKey] = locationId;
  persistLocationCache();
  return locationId;
}

// Parse an idealista.com web URL into API parameters.
// Handles optional language prefixes (/en/, /fr/, etc.), filter path segments,
// and /areas/ hand-drawn polygon URLs.
// Examples:
//   https://www.idealista.com/alquiler-viviendas/madrid-madrid/
//   https://www.idealista.com/en/venta-viviendas/valencia-valencia/con-precio-hasta_800000,metros-cuadrados-mas-de_60/
//   https://www.idealista.com/en/areas/venta-viviendas/con-ascensor/?shape=%28%28encoded_polyline%29%29
function parseUrl(url) {
  const pathMatch = url.match(/idealista\.[a-z]+(\/[^?#]*)/);
  if (!pathMatch) throw new Error(`Cannot parse idealista URL: ${url}`);

  const segments = pathMatch[1].split('/').filter(Boolean);

  // Find the operation-propertyType segment (starts with "alquiler" or "venta")
  const opIdx = segments.findIndex((s) => /^(alquiler|venta)(-|$)/.test(s));
  if (opIdx === -1) throw new Error(`Cannot find operation segment in URL: ${url}`);

  const operationProperty = segments[opIdx]; // e.g. "venta-viviendas"
  const operation = operationProperty.startsWith('alquiler') ? 'rent' : 'sale';

  // Detect country from TLD (idealista.it → Italy, idealista.pt → Portugal, else Spain)
  const tldMatch = url.match(/idealista\.([a-z]+)/);
  const tld = tldMatch ? tldMatch[1] : 'com';
  const country = tld === 'it' ? 'it' : tld === 'pt' ? 'pt' : 'es';

  // /areas/ URLs: hand-drawn polygon — no location slug, shape in ?shape= query param.
  // e.g. /en/areas/venta-viviendas/con-filters/?shape=((encoded_polyline))
  if (segments[opIdx - 1] === 'areas') {
    const filterSegment = segments[opIdx + 1]; // immediately after the operation
    const filters = parseFilters(filterSegment);
    const shapeMatch = url.match(/[?&]shape=([^&]+)/);
    if (!shapeMatch) throw new Error(`Cannot find shape parameter in areas URL: ${url}`);
    const shapeEncoded = decodeURIComponent(shapeMatch[1]);
    return { country, operation, propertyType: 'homes', shapeEncoded, filters };
  }

  const locationSegment = segments[opIdx + 1]; // slug or comma-separated codes
  const filterSegment = segments[opIdx + 2]; // e.g. "con-precio-hasta_800000,..."

  if (!locationSegment) throw new Error(`Cannot find location segment in URL: ${url}`);

  const filters = parseFilters(filterSegment);

  return { country, operation, propertyType: 'homes', locationSlug: locationSegment, filters };
}

// In-memory detail cache: "country:propertyCode" → detail object (or null if unavailable)
const detailCache = new Map();

async function fetchPropertyDetail(country, propertyCode) {
  const cacheKey = `${country}:${propertyCode}`;
  if (detailCache.has(cacheKey)) return detailCache.get(cacheKey);
  try {
    const data = await apiGet(`/api/3/${country}/detail/${propertyCode}`, {});
    detailCache.set(cacheKey, data);
    return data;
  } catch (err) {
    logger.debug(`Idealista: detail fetch failed for ${propertyCode}: ${err.message}`);
    detailCache.set(cacheKey, null);
    return null;
  }
}

// Run async task factories with bounded concurrency
async function runWithConcurrency(taskFns, limit) {
  const results = new Array(taskFns.length);
  let idx = 0;
  async function worker() {
    while (idx < taskFns.length) {
      const i = idx++;
      results[i] = await taskFns[i]();
    }
  }
  const workers = Array.from({ length: Math.min(limit, taskFns.length) }, worker);
  await Promise.all(workers);
  return results;
}

function buildDescription(item, detail) {
  const mc = detail?.moreCharacteristics ?? {};
  const parts = [];

  // Full agent comment — default language first, then propertyComment fallback
  const agentComment =
    (detail?.comments?.find((c) => c.defaultLanguage) ?? detail?.comments?.[0])?.propertyComment ??
    detail?.propertyComment;
  if (agentComment) {
    parts.push(agentComment.trim());
  }

  // Structured summary line
  const charParts = [];

  // Core: subtitle from search or built from fields
  if (item.suggestedTexts?.subtitle) {
    charParts.push(item.suggestedTexts.subtitle);
  } else {
    const rooms = mc.roomNumber ?? item.rooms;
    const floor = mc.floor ?? item.floor;
    if (rooms != null) charParts.push(`${rooms} hab.`);
    if (item.size != null) charParts.push(`${item.size} m²`);
    if (floor != null) charParts.push(`planta ${floor}`);
  }

  // Usable area (detail-only)
  if (mc.usableArea != null) charParts.push(`${mc.usableArea} m² útiles`);

  // Bathrooms
  const baths = mc.bathNumber ?? item.bathrooms;
  if (baths != null) charParts.push(`${baths} baño${baths !== 1 ? 's' : ''}`);

  // Lift / orientation
  if ((mc.lift ?? item.hasLift) === true) charParts.push('ascensor');
  const exterior = mc.exterior ?? item.exterior;
  if (exterior === true) charParts.push('exterior');
  else if (exterior === false) charParts.push('interior');

  // Property sub-type
  if (mc.isDuplex === true) charParts.push('dúplex');
  if (mc.isPenthouse === true) charParts.push('ático');

  // Features (detail fields take precedence, search fields as fallback)
  const flags = [
    [mc.swimmingPool ?? item.swimmingPool, 'piscina'],
    [mc.garden ?? item.garden, 'jardín'],
    [mc.boxroom, 'trastero'],
    [item.terrace, 'terraza'],
    [item.garage, 'garaje'],
  ];
  for (const [val, label] of flags) {
    if (val === true) charParts.push(label);
  }

  if (item.newDevelopment === true) charParts.push('obra nueva');

  // Furnishing
  const fur = mc.housingFurnitures;
  if (fur && fur !== 'unknown') {
    charParts.push(fur === 'furnished' ? 'amueblado' : fur === 'unfurnished' ? 'sin muebles' : fur);
  }

  // Pets
  if (mc.housingPetsAllowed === true) charParts.push('mascotas OK');

  // Condition / energy cert
  const status = mc.status ?? item.status;
  if (status) charParts.push(status);
  const epc = mc.energyCertificationType;
  if (epc && epc !== 'inProcess') charParts.push(`EPC ${epc}`);

  // Price per m²
  if (item.priceByArea != null) charParts.push(`${item.priceByArea} €/m²`);

  if (charParts.length > 0) parts.push(charParts.join(' · '));

  return parts.length > 0 ? parts.join('\n\n') : null;
}

async function getListings(url) {
  try {
    const { country, operation, propertyType, locationSlug, shapeEncoded, filters } = parseUrl(url);

    let areaParam;
    if (shapeEncoded) {
      areaParam = { shape: polylineToGeoJsonShape(shapeEncoded) };
      logger.debug(
        `Idealista: parsed areas URL → country=${country}, operation=${operation}, filters=${JSON.stringify(filters)}`,
      );
    } else {
      const locationId = await resolveLocationId(country, locationSlug, operation, propertyType);
      areaParam = { locationId };
      logger.debug(
        `Idealista: parsed URL → country=${country}, operation=${operation}, location=${locationSlug}, filters=${JSON.stringify(filters)}`,
      );
    }

    const baseSearchParams = {
      operation,
      propertyType,
      ...areaParam,
      maxItems: '40',
      order: 'publicationDate',
      sort: 'desc',
      ...filters,
    };

    // Fetch up to MAX_PAGES pages to capture all available listings on the first run.
    const MAX_PAGES = 2;
    const allItems = [];
    let page = 1;

    while (page <= MAX_PAGES) {
      const searchParams = { ...baseSearchParams, numPage: String(page) };
      logger.debug(`Idealista: search params page=${page}: ${JSON.stringify(searchParams)}`);

      const data = await apiPost(`/api/3.5/${country}/search`, {}, searchParams);
      const items = data.elementList || [];
      allItems.push(...items);

      const totalPages = data.totalPages ?? 1;
      logger.debug(
        `Idealista: page ${page}/${totalPages}, got ${items.length} items (total so far: ${allItems.length}, API total listings: ${data.total ?? '?'})`,
      );

      if (page >= totalPages || items.length === 0) break;
      page++;
    }

    const DETAIL_CONCURRENCY = 10;
    logger.debug(`Idealista: fetching detail for ${allItems.length} listings (concurrency=${DETAIL_CONCURRENCY})`);
    const details = await runWithConcurrency(
      allItems.map((item) => () => fetchPropertyDetail(country, item.propertyCode)),
      DETAIL_CONCURRENCY,
    );

    return allItems.map((item, i) => ({
      id: String(item.propertyCode),
      price: item.price != null ? String(item.price) : null,
      size: item.size != null ? `${item.size} m²` : null,
      title: item.suggestedTexts?.title || item.address || null,
      description: buildDescription(item, details[i]),
      link: item.url || `https://www.idealista.com/inmueble/${item.propertyCode}/`,
      address: item.address || null,
      image: item.thumbnail || null,
      latitude: item.latitude ?? null,
      longitude: item.longitude ?? null,
    }));
  } catch (err) {
    logger.error('Error fetching data from Idealista API:', err.message);
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
  name: 'Idealista',
  baseUrl: 'https://www.idealista.com/',
  id: 'idealista',
};

export const init = (sourceConfig, blacklist) => {
  config.enabled = sourceConfig.enabled;
  config.url = sourceConfig.url;
  appliedBlackList = blacklist || [];
};

export { config };

/*
 * Copyright (c) 2026 by Christian Kellner.
 * Licensed under Apache-2.0 with Commons Clause and Attribution/Naming Clause
 */

import { expect } from 'chai';
import * as provider from '../../lib/provider/fotocasa.js';
import { providerConfig } from '../utils.js';

const SEARCH_URL = providerConfig.fotocasa.url;
const ENGLISH_SEARCH_URL =
  'https://www.fotocasa.es/en-us/buy/homes/valencia-capital/all-zones/l?maxPrice=800000&minPrice=100000&minSurface=60&propertySubTypeIds=2%253B6%253B7&sortType=publicationDate';

function jsonResponse(payload) {
  return {
    ok: true,
    status: 200,
    json: async () => payload,
    text: async () => JSON.stringify(payload),
  };
}

function errorResponse(status, text) {
  return {
    ok: false,
    status,
    json: async () => ({ reason: text }),
    text: async () => text,
  };
}

function placeholder(propertyId) {
  return {
    type: 'PROPERTY',
    property: {
      propertyId,
      price: 1000 + propertyId,
      surface: 70,
      title: `Listing ${propertyId}`,
      comments: `Description ${propertyId}`,
      addressLine: `Address ${propertyId}`,
      urlMarketplace: `https://www.fotocasa.es/es/alquiler/vivienda/test-${propertyId}`,
      photoLarge: `https://www.fotocasa.es/media/${propertyId}.jpg`,
      latitude: 40.4,
      longitude: -3.7,
    },
  };
}

function adPlaceholder() {
  return {
    type: 'SAITAMA',
    advertisingSaitamaDto: {
      slot: 'list-inline',
    },
  };
}

describe('#fotocasa testsuite()', () => {
  let originalFetch;

  beforeEach(() => {
    originalFetch = global.fetch;
    provider.init(providerConfig.fotocasa, [], []);
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  it('fetches all pages and returns aggregated listings', async () => {
    const requestedPages = [];

    global.fetch = async (url) => {
      const requestUrl = new URL(url);

      if (requestUrl.pathname === '/translatesemantic/search') {
        return jsonResponse({
          urlParametersDto: {
            transactionType: 'RENT',
            propertyType: 'HOME',
            text: 'madrid capital',
            clientId: '0',
            page: '1',
            pageSize: '2',
            sort: '0',
            advertisingSaitamaClientVersion: '7',
          },
        });
      }

      if (requestUrl.pathname === '/v3/placeholders/search') {
        const page = Number.parseInt(requestUrl.searchParams.get('page') ?? '0', 10);
        requestedPages.push(page);

        if (page === 1) {
          return jsonResponse({
            placeholders: [placeholder(1), placeholder(2), adPlaceholder()],
            info: { count: '5' },
          });
        }
        if (page === 2) {
          return jsonResponse({
            placeholders: [placeholder(3), placeholder(4)],
            info: { count: '5' },
          });
        }
        if (page === 3) {
          return jsonResponse({
            placeholders: [placeholder(5)],
            info: { count: '5' },
          });
        }
        return jsonResponse({
          placeholders: [],
          info: { count: '5' },
        });
      }

      throw new Error(`Unexpected endpoint in test: ${requestUrl.pathname}`);
    };

    const listings = await provider.config.getListings(SEARCH_URL);

    expect(requestedPages).to.deep.equal([1, 2, 3]);
    expect(listings).to.be.an('array').with.length(5);
    expect(listings.map((item) => item.id)).to.deep.equal(['1', '2', '3', '4', '5']);
    listings.forEach((listing) => {
      expect(listing.link).to.be.a('string').and.include('https://www.fotocasa.es');
      expect(listing.price).to.be.a('string').and.not.empty;
      expect(listing.title).to.be.a('string').and.not.empty;
    });
  });

  it('fails fast when semantic URL translation is blocked (strict flow)', async () => {
    const v3Requests = [];

    global.fetch = async (url) => {
      const requestUrl = new URL(url);

      if (requestUrl.pathname === '/translatesemantic/search') {
        return errorResponse(403, 'blocked');
      }

      if (requestUrl.pathname === '/v3/placeholders/search') {
        v3Requests.push(requestUrl);
        return jsonResponse({
          placeholders: [placeholder(42)],
          info: { count: '1' },
        });
      }

      throw new Error(`Unexpected endpoint in test: ${requestUrl.pathname}`);
    };

    let thrown = null;
    try {
      await provider.config.getListings(ENGLISH_SEARCH_URL);
    } catch (err) {
      thrown = err;
    }

    expect(thrown).to.be.instanceOf(Error);
    expect(thrown.message).to.include('Fotocasa API error (403)');
    expect(v3Requests).to.have.length(0);
  });

  it('uses apps.gw only by default', async () => {
    const requestedHosts = [];

    global.fetch = async (url) => {
      const requestUrl = new URL(url);
      requestedHosts.push(requestUrl.host);

      if (requestUrl.pathname === '/translatesemantic/search') {
        return jsonResponse({
          urlParametersDto: {
            transactionType: 'RENT',
            propertyType: 'HOME',
            text: 'madrid capital',
            page: '1',
            pageSize: '36',
          },
        });
      }

      if (requestUrl.pathname === '/v3/placeholders/search') {
        return jsonResponse({
          placeholders: [placeholder(77)],
          info: { count: '1' },
        });
      }

      throw new Error(`Unexpected endpoint in test: ${requestUrl.pathname}`);
    };

    const listings = await provider.config.getListings(SEARCH_URL);

    expect(requestedHosts.every((host) => host === 'apps.gw.fotocasa.es')).to.equal(true);
    expect(listings).to.be.an('array').with.length(1);
    expect(listings[0].id).to.equal('77');
  });

  it('fails fast when v3 is blocked by an Imperva challenge page', async () => {
    const v3Requests = [];

    global.fetch = async (url) => {
      const requestUrl = new URL(url);

      if (requestUrl.pathname === '/translatesemantic/search') {
        return jsonResponse({
          urlParametersDto: {
            transactionType: 'SALE',
            propertyType: 'HOME',
            text: 'valencia capital',
            locations: '12345',
            page: '1',
            pageSize: '36',
          },
        });
      }

      if (requestUrl.pathname === '/v3/placeholders/search') {
        v3Requests.push(requestUrl.toString());
        return errorResponse(403, '<html><h1>Pardon Our Interruption</h1></html>');
      }

      throw new Error(`Unexpected endpoint in test: ${requestUrl.pathname}`);
    };

    let thrown = null;
    try {
      await provider.config.getListings(ENGLISH_SEARCH_URL);
    } catch (err) {
      thrown = err;
    }

    expect(thrown).to.be.instanceOf(Error);
    expect(thrown.message).to.include('Imperva challenge detected');
    expect(v3Requests).to.have.length(1);
  });

  it('sends configured X-D-Token and Cookie headers on mobile API calls', async () => {
    provider.init(
      {
        ...providerConfig.fotocasa,
        xDToken: 'x-d-token-value',
        cookie: 'foo=bar; baz=qux',
      },
      [],
      [],
    );

    const capturedHeaders = [];

    global.fetch = async (url, requestInit = {}) => {
      const requestUrl = new URL(url);
      capturedHeaders.push(requestInit.headers ?? {});

      if (requestUrl.pathname === '/translatesemantic/search') {
        return jsonResponse({
          urlParametersDto: {
            transactionType: 'RENT',
            propertyType: 'HOME',
            text: 'madrid capital',
            page: '1',
            pageSize: '36',
          },
        });
      }

      if (requestUrl.pathname === '/v3/placeholders/search') {
        return jsonResponse({
          placeholders: [placeholder(88)],
          info: { count: '1' },
        });
      }

      throw new Error(`Unexpected endpoint in test: ${requestUrl.pathname}`);
    };

    const listings = await provider.config.getListings(SEARCH_URL);
    expect(listings).to.be.an('array').with.length(1);
    expect(capturedHeaders.length).to.be.greaterThan(0);
    capturedHeaders.forEach((headers) => {
      expect(headers['X-D-Token']).to.equal('x-d-token-value');
      expect(headers.Cookie).to.equal('foo=bar; baz=qux');
    });
  });
});

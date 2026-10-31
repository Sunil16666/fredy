/*
 * Copyright (c) 2026 by Christian Kellner.
 * Licensed under Apache-2.0 with Commons Clause and Attribution/Naming Clause
 */

import { beforeAll, describe, expect, it } from 'vitest';
import * as similarityCache from '../../lib/services/similarity-check/similarityCache.js';
import { mockFredy, providerConfig } from '../utils.js';
import * as provider from '../../lib/provider/immobiliare.js';

describe('Immobiliare.it provider pipeline', () => {
  let listings;
  beforeAll(async () => {
    const Fredy = await mockFredy();
    const job = { id: 'immobiliare', notificationAdapter: null, spatialFilter: null, specFilter: null };
    const fredy = new Fredy(provider.createConfig(providerConfig.immobiliare), job, 'immobiliare', similarityCache);
    listings = await fredy.execute();
  }, 180_000);

  it('finds individual adverts with canonical links and readable figures', () => {
    expect(listings.length).toBeGreaterThan(0);
    for (const listing of listings) {
      expect(listing.title).toBeTruthy();
      expect(listing.link).toMatch(/^https:\/\/www\.immobiliare\.it\/annunci\/\d+\/$/);
      for (const field of ['price', 'size', 'rooms']) {
        if (listing[field] != null) expect(listing[field]).toBeGreaterThan(0);
      }
    }
    expect(new Set(listings.map((listing) => listing.link)).size).toBe(listings.length);
  });

  it('declares Italy for geocoding and map bounds', () => {
    expect(provider.metaInformation.countries).toEqual(['it']);
  });
});

/*
 * Copyright (c) 2026 by Christian Kellner.
 * Licensed under Apache-2.0 with Commons Clause and Attribution/Naming Clause
 */

import { beforeAll, describe, expect, it } from 'vitest';
import { mockFredy, providerConfig } from '../utils.js';
import * as provider from '../../lib/provider/houseimmobiliare.js';

describe('House Immobiliare provider pipeline', () => {
  let listings;
  beforeAll(async () => {
    const Fredy = await mockFredy();
    listings = await new Fredy(
      provider.createConfig(providerConfig.houseimmobiliare),
      { id: 'houseimmobiliare', notificationAdapter: null },
      'houseimmobiliare',
      { checkAndAddEntry: () => false },
    ).execute();
  }, 180000);
  it('stores canonical Italian adverts with useful search fields', () => {
    expect(listings.length).toBeGreaterThan(0);
    for (const listing of listings) {
      expect(listing.link).toMatch(/^https:\/\/www\.houseimmobiliare\.info\/immobile\/[^/]+\/$/);
      expect(listing.title).toBeTruthy();
      expect(listing.address).toBeTruthy();
      expect(listing.rooms).toBeNull();
      if (listing.price != null) expect(listing.price).toBeGreaterThan(0);
    }
  });
  it('declares browser-free Italian coverage and no unverified probes', () => {
    expect(provider.metaInformation.countries).toEqual(['it']);
    expect(provider.config.needsBrowser).toBe(false);
    expect(provider.config.activityProbe).toBeUndefined();
    expect(provider.config.priceTracking).toBeUndefined();
  });
});

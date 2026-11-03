/*
 * Copyright (c) 2026 by Christian Kellner.
 * Licensed under Apache-2.0 with Commons Clause and Attribution/Naming Clause
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { mockFredy, providerConfig } from '../utils.js';
import * as mockStore from '../mocks/mockStore.js';
import * as notification from '../mocks/mockNotification.js';
import * as idealista from '../../lib/provider/idealista.js';
import * as immobiliare from '../../lib/provider/immobiliare.js';
import * as houseimmobiliare from '../../lib/provider/houseimmobiliare.js';

// Unlike the general fixture store (whose readers expect listing objects), the production
// deduplication contract returns hashes. Keep that contract and job isolation in this test.
const stored = new Map();
vi.doMock('../../lib/services/storage/listingsStorage.js', () => ({
  ...mockStore,
  getKnownListingHashesForJobAndProvider: (jobId, providerId) =>
    (stored.get(`${jobId}:${providerId}`) ?? []).map((listing) => listing.id),
  storeListings: (jobId, providerId, listings) => {
    const key = `${jobId}:${providerId}`;
    stored.set(key, [...(stored.get(key) ?? []), ...listings]);
  },
}));

beforeEach(() => {
  stored.clear();
  notification.reset();
  mockStore.setUserSettings({ provider_details: ['idealista', 'immobiliare', 'houseimmobiliare'] });
  mockStore.setGeocodeResult(null);
});
afterEach(() => mockStore.setUserSettings(null));

describe.each([
  ['idealista', idealista],
  ['immobiliare', immobiliare],
  ['houseimmobiliare', houseimmobiliare],
])('%s repeated pipeline runs', (id, provider) => {
  it('skips known adverts before details and notifications, without sharing job state', async () => {
    const Fredy = await mockFredy();
    const config = provider.createConfig(providerConfig[id]);
    const details = vi.fn(config.fetchDetails);
    config.fetchDetails = details;
    const run = (jobId) =>
      new Fredy(
        config,
        { id: jobId, userId: 'user1', notificationAdapter: null },
        id,
        { checkAndAddEntry: () => false },
        undefined,
        { maxDetailFetches: Infinity },
      ).execute();

    const first = await run('first-job');
    expect(first.length).toBeGreaterThan(0);
    expect(details).toHaveBeenCalledTimes(first.length);
    expect(notification.get().payload).toBeDefined();

    details.mockClear();
    notification.reset();
    await run('first-job');
    await run('first-job');
    expect(details).not.toHaveBeenCalled();
    expect(notification.get()).toEqual({});
    expect(stored.get(`first-job:${id}`)).toHaveLength(first.length);

    const other = await run('other-job');
    expect(other.map((listing) => listing.id)).toEqual(first.map((listing) => listing.id));
    expect(details).toHaveBeenCalledTimes(other.length);
    expect(notification.get().payload).toBeDefined();
  });
});

/*
 * Copyright (c) 2026 by Christian Kellner.
 * Licensed under Apache-2.0 with Commons Clause and Attribution/Naming Clause
 */

import { beforeEach, describe, expect, it, vi } from 'vitest';
import { config } from '../../lib/provider/idealista.js';
import { call } from '../../lib/services/idealista/mobile-api.js';
import checkIfListingIsActive from '../../lib/services/listings/listingActiveTester.js';
vi.mock('../../lib/services/listings/listingActiveTester.js', () => ({ default: vi.fn() }));
vi.mock('../../lib/services/idealista/mobile-api.js', () => ({
  call: vi.fn(),
  MAX_ITEMS_PER_PAGE: 50,
  searchPath: (portal) => `/api/3.5/${portal.country}/search`,
}));
const LINK = 'https://www.idealista.it/immobile/123456/';
beforeEach(() => {
  vi.resetAllMocks();
  checkIfListingIsActive.mockResolvedValue(-1);
});
describe('Idealista background checks', () => {
  it('checks the advert through its national API', async () => {
    call.mockResolvedValue({ elementList: [{ propertyCode: '123456' }] });
    expect(await config.activityProbe(LINK)).toBe(1);
    expect(call.mock.calls[0][0].country).toBe('it');
    expect(call.mock.calls[0][2].query).toContainEqual(['adIds', '123456']);
    expect(checkIfListingIsActive).not.toHaveBeenCalled();
  });
  it('leaves empty, malformed, mismatched and refused answers unknown', async () => {
    call.mockResolvedValue({ elementList: [] });
    expect(await config.activityProbe(LINK)).toBe(-1);
    call.mockResolvedValueOnce({});
    expect(await config.activityProbe(LINK)).toBe(-1);
    call.mockResolvedValueOnce({ elementList: [{ propertyCode: 'other' }] });
    expect(await config.activityProbe(LINK)).toBe(-1);
    call.mockRejectedValueOnce(new Error('407'));
    expect(await config.activityProbe(LINK)).toBe(-1);
  });
  it.each([1, 0, -1])(
    'uses the established website verdict %s when neither home lookup finds an advert',
    async (verdict) => {
      call.mockResolvedValue({ elementList: [] });
      checkIfListingIsActive.mockResolvedValue(verdict);
      expect(await config.activityProbe(LINK)).toBe(verdict);
      expect(checkIfListingIsActive).toHaveBeenCalledExactlyOnceWith(LINK);
    },
  );
  it('looks up a rental with its own operation after an empty sale lookup', async () => {
    call.mockResolvedValueOnce({ elementList: [] });
    call.mockResolvedValueOnce({ elementList: [{ propertyCode: '123456' }] });
    expect(await config.activityProbe(LINK)).toBe(1);
    expect(call.mock.calls.map(([, , options]) => options.body.find(([key]) => key === 'operation')[1])).toEqual([
      'sale',
      'rent',
    ]);
  });
  it('does not send invalid links to a guessed market', async () => {
    expect(await config.activityProbe('https://example.com/123456/')).toBe(-1);
    expect(call).not.toHaveBeenCalled();
  });
  it('does not fetch another date when the search already supplied one', async () => {
    const listing = { link: LINK, publishedAt: 1793364033000 };
    expect(await config.fetchDetails(listing)).toBe(listing);
    expect(call).not.toHaveBeenCalled();
  });
});

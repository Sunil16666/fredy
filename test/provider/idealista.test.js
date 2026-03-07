/*
 * Copyright (c) 2026 by Christian Kellner.
 * Licensed under Apache-2.0 with Commons Clause and Attribution/Naming Clause
 */

import * as similarityCache from '../../lib/services/similarity-check/similarityCache.js';
import { get } from '../mocks/mockNotification.js';
import { mockFredy, providerConfig } from '../utils.js';
import { expect } from 'chai';
import * as provider from '../../lib/provider/idealista.js';

describe('#idealista testsuite()', () => {
  it('should test idealista provider', async () => {
    const Fredy = await mockFredy();
    provider.init(providerConfig.idealista, [], []);

    const fredy = new Fredy(provider.config, null, provider.metaInformation.id, 'idealista', similarityCache);
    const listing = await fredy.execute();

    expect(listing).to.be.a('array');
    const notificationObj = get();
    expect(notificationObj).to.be.a('object');
    expect(notificationObj.serviceName).to.equal('idealista');
    notificationObj.payload.forEach((notify) => {
      expect(notify.id).to.be.a('string').and.not.empty;
      expect(notify.title).to.be.a('string').and.not.empty;
      expect(notify.link).to.be.a('string').and.include('https://www.idealista.com');
      expect(notify.price).to.be.a('string').and.not.empty;
    });
  });
});

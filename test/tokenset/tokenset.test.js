'use strict';

const expect = require('chai').expect;
const TokenSet = require('../../lib/token_set');
const now = require('../../lib/unix_timestamp');

describe('TokenSet', function () {
  it('sets the expire_at automatically from expires_in', function () {
    const ts = new TokenSet({
      expires_in: 300,
    });

    expect(ts).to.have.property('expires_at', now() + 300);
    expect(ts).to.have.property('expires_in', 300);
    expect(ts.expired()).to.be.false;
  });

  it('expired token sets', function () {
    const ts = new TokenSet({
      expires_in: -30,
    });

    expect(ts).to.have.property('expires_at', now() - 30);
    expect(ts).to.have.property('expires_in', 0);
    expect(ts.expired()).to.be.true;
  });
});

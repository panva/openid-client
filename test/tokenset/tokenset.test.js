const base64url = require('base64url');
const { expect } = require('chai');

const TokenSet = require('../../lib/token_set');
const now = require('../../lib/helpers/unix_timestamp');

describe('TokenSet', function () {
  after(function () {
    if (base64url.decode.restore) base64url.decode.restore();
  });

  it('sets the expire_at automatically from expires_in', function () {
    const ts = new TokenSet({
      expires_in: 300,
    });

    expect(ts).to.have.property('expires_at', now() + 300);
    expect(ts).to.have.property('expires_in', 300);
    expect(ts.expired()).to.be.false;
  });

  it('expired token sets expires_in to 0', function () {
    const ts = new TokenSet({
      expires_in: -30,
    });

    expect(ts).to.have.property('expires_at', now() - 30);
    expect(ts).to.have.property('expires_in', 0);
    expect(ts.expired()).to.be.true;
  });

  it('provides a #claims getter', function () {
    const ts = new TokenSet({
      id_token:
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ',
    });

    expect(ts.claims()).to.eql({ sub: '1234567890', name: 'John Doe', admin: true });
  });

  it('#claims throws if no id_token is present', function () {
    const ts = new TokenSet({});

    expect(function () {
      ts.claims();
    }).to.throw('id_token not present in TokenSet');
  });

  it('#claims does not extend dumped tokenset properties', function () {
    const ts = new TokenSet({
      id_token:
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ',
    });

    expect(JSON.parse(JSON.stringify(ts))).to.eql(ts);
  });

  it('cannot have its prototype methods overloaded', function () {
    let ts = new TokenSet({
      claims: null,
      id_token:
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ',
    });

    expect(ts.claims).to.be.a('function');
    expect(ts.claims()).to.eql({ admin: true, name: 'John Doe', sub: '1234567890' });

    ts = new TokenSet({ expires_in: 'foo' });
    ts.expires_in = 200;
    expect(ts.expires_in).to.be.a('number');
    expect(ts.expired()).to.eql(false);

    const e = new Error();
    class CustomTokenSet extends TokenSet {
      expired() {
        throw e;
      }
    }

    ts = new CustomTokenSet({});
    expect(() => ts.expired()).to.throw(e);
  });
});

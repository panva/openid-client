const { expect } = require('chai');
const nock = require('nock');
const sinon = require('sinon');

const { Issuer, Registry, custom } = require('../../lib');

const fail = () => { throw new Error('expected promise to be rejected'); };

const success = {
  authorization_endpoint: 'https://opemail.example.com/o/oauth2/v2/auth',
  issuer: 'https://opemail.example.com',
  jwks_uri: 'https://opemail.example.com/oauth2/v3/certs',
  token_endpoint: 'https://opemail.example.com/oauth2/v4/token',
  userinfo_endpoint: 'https://opemail.example.com/oauth2/v3/userinfo',
};

describe('Issuer#webfinger()', () => {
  it('must get a string input', function () {
    return Issuer.webfinger().then(fail, (err) => {
      expect(err).to.be.instanceof(TypeError);
      expect(err.message).to.eql('input must be a string');
    });
  });

  it('can discover using the EMAIL syntax', function () {
    const webfinger = nock('https://opemail.example.com')
      .get('/.well-known/webfinger')
      .query(function (query) {
        expect(query).to.have.property('resource', 'acct:joe@opemail.example.com');
        return true;
      })
      .reply(200, {
        subject: 'https://opemail.example.com/joe',
        links: [
          {
            rel: 'http://openid.net/specs/connect/1.0/issuer',
            href: 'https://opemail.example.com',
          },
        ],
      });
    const discovery = nock('https://opemail.example.com')
      .get('/.well-known/openid-configuration')
      .reply(200, success);

    return Issuer.webfinger('joe@opemail.example.com').then(function () {
      expect(webfinger.isDone()).to.be.true;
      expect(discovery.isDone()).to.be.true;
    });
  });

  it('verifies the webfinger responds with an issuer', function () {
    nock('https://opemail.example.com')
      .get('/.well-known/webfinger')
      .query(() => true)
      .reply(200, {
        subject: 'https://opemail.example.com/joe',
        links: [],
      });

    return Issuer.webfinger('joe@opemail.example.com').then(fail, (err) => {
      expect(err).to.have.property('message', 'no issuer found in webfinger response');
    });
  });

  it('verifies the webfinger responds with an issuer which is a valid issuer value (1/2)', function () {
    nock('https://opemail.example.com')
      .get('/.well-known/webfinger')
      .query(() => true)
      .reply(200, {
        subject: 'https://opemail.example.com/joe',
        links: [{
          rel: 'http://openid.net/specs/connect/1.0/issuer',
          href: 'http://opemail.example.com',
        }],
      });

    return Issuer.webfinger('joe@opemail.example.com').then(fail, (err) => {
      expect(err).to.have.property('message', 'invalid issuer location http://opemail.example.com');
    });
  });

  it('verifies the webfinger responds with an issuer which is a valid issuer value (2/2)', function () {
    nock('https://opemail.example.com')
      .get('/.well-known/webfinger')
      .query(() => true)
      .reply(200, {
        subject: 'https://opemail.example.com/joe',
        links: [{
          rel: 'http://openid.net/specs/connect/1.0/issuer',
          href: 1,
        }],
      });

    return Issuer.webfinger('joe@opemail.example.com').then(fail, (err) => {
      expect(err).to.have.property('message', 'invalid issuer location 1');
    });
  });

  it('uses cached issuer if it has one', function () {
    const webfinger = nock('https://opemail.example.com')
      .get('/.well-known/webfinger')
      .query(function (query) {
        expect(query).to.have.property('resource', 'acct:joe@opemail.example.com');
        return true;
      })
      .reply(200, {
        subject: 'https://opemail.example.com/joe',
        links: [
          {
            rel: 'http://openid.net/specs/connect/1.0/issuer',
            href: 'https://opemail.example.com',
          },
        ],
      });

    return Issuer.webfinger('joe@opemail.example.com').then(function () {
      expect(webfinger.isDone()).to.be.true;
    });
  });

  it('validates the discovered issuer is the same as from webfinger', function () {
    Registry.clear();
    const webfinger = nock('https://op.example.com')
      .get('/.well-known/webfinger')
      .query(function (query) {
        expect(query).to.have.property('resource', 'acct:joe@op.example.com');
        return true;
      })
      .reply(200, {
        subject: 'https://op.example.com/joe',
        links: [
          {
            rel: 'http://openid.net/specs/connect/1.0/issuer',
            href: 'https://op.example.com',
          },
        ],
      });
    const discovery = nock('https://op.example.com')
      .get('/.well-known/openid-configuration')
      .reply(200, {
        authorization_endpoint: 'https://op.example.com/o/oauth2/v2/auth',
        issuer: 'https://another.op.example.com',
        jwks_uri: 'https://op.example.com/oauth2/v3/certs',
        token_endpoint: 'https://op.example.com/oauth2/v4/token',
        userinfo_endpoint: 'https://op.example.com/oauth2/v3/userinfo',
      });

    return Issuer.webfinger('joe@op.example.com').then(fail, function (error) {
      expect(webfinger.isDone()).to.be.true;
      expect(discovery.isDone()).to.be.true;
      expect(error.message).to.equal('discovered issuer mismatch, expected https://op.example.com, got: https://another.op.example.com');
      expect(Registry.has('https://another.op.example.com')).to.be.false;
    });
  });

  it('can discover using the URL syntax', function () {
    const webfinger = nock('https://opurl.example.com')
      .get('/.well-known/webfinger')
      .query(function (query) {
        expect(query).to.have.property('resource', 'https://opurl.example.com/joe');
        return true;
      })
      .reply(200, {
        subject: 'https://opurl.example.com/joe',
        links: [
          {
            rel: 'http://openid.net/specs/connect/1.0/issuer',
            href: 'https://opurl.example.com',
          },
        ],
      });
    const discovery = nock('https://opurl.example.com')
      .get('/.well-known/openid-configuration')
      .reply(200, {
        authorization_endpoint: 'https://opurl.example.com/o/oauth2/v2/auth',
        issuer: 'https://opurl.example.com',
        jwks_uri: 'https://opurl.example.com/oauth2/v3/certs',
        token_endpoint: 'https://opurl.example.com/oauth2/v4/token',
        userinfo_endpoint: 'https://opurl.example.com/oauth2/v3/userinfo',
      });

    return Issuer.webfinger('https://opurl.example.com/joe').then(function () {
      expect(webfinger.isDone()).to.be.true;
      expect(discovery.isDone()).to.be.true;
    });
  });

  it('can discover using the Hostname and Port syntax', function () {
    const webfinger = nock('https://ophp.example.com:8080')
      .get('/.well-known/webfinger')
      .query(function (query) {
        expect(query).to.have.property('resource', 'https://ophp.example.com:8080');
        return true;
      })
      .reply(200, {
        subject: 'https://example.com:8080',
        links: [
          {
            rel: 'http://openid.net/specs/connect/1.0/issuer',
            href: 'https://ophp.example.com',
          },
        ],
      });
    const discovery = nock('https://ophp.example.com')
      .get('/.well-known/openid-configuration')
      .reply(200, {
        authorization_endpoint: 'https://ophp.example.com/o/oauth2/v2/auth',
        issuer: 'https://ophp.example.com',
        jwks_uri: 'https://ophp.example.com/oauth2/v3/certs',
        token_endpoint: 'https://ophp.example.com/oauth2/v4/token',
        userinfo_endpoint: 'https://ophp.example.com/oauth2/v3/userinfo',
      });

    return Issuer.webfinger('ophp.example.com:8080').then(function () {
      expect(webfinger.isDone()).to.be.true;
      expect(discovery.isDone()).to.be.true;
    });
  });

  it('can discover using the acct syntax', function () {
    const webfinger = nock('https://opacct.example.com')
      .get('/.well-known/webfinger')
      .query(function (query) {
        expect(query).to.have.property('resource', 'acct:juliet%40capulet.example@opacct.example.com');
        return true;
      })
      .reply(200, {
        subject: 'acct:juliet%40capulet.example@opacct.example.com',
        links: [
          {
            rel: 'http://openid.net/specs/connect/1.0/issuer',
            href: 'https://opacct.example.com',
          },
        ],
      });
    const discovery = nock('https://opacct.example.com')
      .get('/.well-known/openid-configuration')
      .reply(200, {
        authorization_endpoint: 'https://opacct.example.com/o/oauth2/v2/auth',
        issuer: 'https://opacct.example.com',
        jwks_uri: 'https://opacct.example.com/oauth2/v3/certs',
        token_endpoint: 'https://opacct.example.com/oauth2/v4/token',
        userinfo_endpoint: 'https://opacct.example.com/oauth2/v3/userinfo',
      });

    return Issuer.webfinger('acct:juliet%40capulet.example@opacct.example.com').then(function () {
      expect(webfinger.isDone()).to.be.true;
      expect(discovery.isDone()).to.be.true;
    });
  });

  describe('HTTP_OPTIONS', () => {
    afterEach(() => {
      delete Issuer[custom.http_options];
    });

    it('allows for http options to be defined for Issuer.webfinger calls', async () => {
      const httpOptions = sinon.stub().callsFake((opts) => {
        opts.headers.custom = 'foo';
        return opts;
      });
      Issuer[custom.http_options] = httpOptions;

      nock('https://opemail.example.com')
        .get('/.well-known/webfinger')
        .query(function (query) {
          expect(query).to.have.property('resource', 'acct:joe@opemail.example.com');
          return true;
        })
        .matchHeader('custom', 'foo')
        .reply(200, {
          subject: 'https://opemail.example.com/joe',
          links: [
            {
              rel: 'http://openid.net/specs/connect/1.0/issuer',
              href: 'https://opemail.example.com',
            },
          ],
        });

      nock('https://opemail.example.com')
        .get('/.well-known/openid-configuration')
        .matchHeader('custom', 'foo')
        .reply(200, success);

      await Issuer.webfinger('joe@opemail.example.com');

      expect(nock.isDone()).to.be.true;
      sinon.assert.callCount(httpOptions, 2);
    });
  });
});

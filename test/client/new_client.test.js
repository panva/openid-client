const { expect } = require('chai');

const Issuer = require('../../lib/issuer');

describe('new Client()', function () {
  it('requires client_id', function () {
    try {
      const issuer = new Issuer();
      new issuer.Client({}); // eslint-disable-line no-new
      throw new Error();
    } catch (err) {
      expect(err.message).to.equal('client_id is required');
    }
  });

  it('accepts the recognized metadata', function () {
    let client;

    expect(function () {
      const issuer = new Issuer();
      client = new issuer.Client({
        client_id: 'identifier',
        client_secret: 'secure',
      });
    }).not.to.throw();

    expect(client).to.have.property('client_id', 'identifier');
    expect(client).to.have.property('client_secret', 'secure');
  });

  it('assigns defaults to some properties', function () {
    const issuer = new Issuer();
    const client = new issuer.Client({ client_id: 'identifier' });

    expect(client).to.have.property('client_id', 'identifier');
    expect(client).to.have.property('grant_types').eql(['authorization_code']);
    expect(client).to.have.property('id_token_signed_response_alg', 'RS256');
    expect(client).to.have.property('response_types').eql(['code']);
    expect(client).to.have.property('token_endpoint_auth_method', 'client_secret_basic');
  });

  describe('with keystore', function () {
    it('validates it is a keystore', function () {
      const issuer = new Issuer();
      [{}, [], 'not a keystore', 2, true, false].forEach(function (notkeystore) {
        expect(function () {
          new issuer.Client({ client_id: 'identifier' }, notkeystore); // eslint-disable-line no-new
        }).to.throw('jwks must be a JSON Web Key Set formatted object');
      });
    });
  });

  ['introspection', 'revocation'].forEach((endpoint) => {
    it(`autofills ${endpoint}_endpoint_auth_method`, function () {
      const issuer = new Issuer({
        [`${endpoint}_endpoint`]: `https://op.example.com/token/${endpoint}`,
      });
      const client = new issuer.Client({
        client_id: 'identifier',
        token_endpoint_auth_method: 'client_secret_jwt',
        token_endpoint_auth_signing_alg: 'HS512',
      });
      expect(client[`${endpoint}_endpoint_auth_method`]).to.equal('client_secret_jwt');
      expect(client[`${endpoint}_endpoint_auth_signing_alg`]).to.equal('HS512');
    });
  });

  ['token', 'introspection', 'revocation'].forEach((endpoint) => {
    describe(`with ${endpoint}_endpoint_auth_method =~ _jwt`, function () {
      it(`validates the issuer has supported algs announced if ${endpoint}_endpoint_auth_signing_alg is not defined on a client`, function () {
        expect(function () {
          const issuer = new Issuer({
            [`${endpoint}_endpoint`]: 'https://op.example.com/token',
          });
          new issuer.Client({ // eslint-disable-line no-new
            client_id: 'identifier',
            [`${endpoint}_endpoint_auth_method`]: '_jwt',
          });
        }).to.throw(`${endpoint}_endpoint_auth_signing_alg_values_supported must be configured on the issuer if ${endpoint}_endpoint_auth_signing_alg is not defined on a client`);
      });
    });
  });

  it('is able to assign custom or non-recognized properties', function () {
    const issuer = new Issuer();
    const client = new issuer.Client({
      client_id: 'identifier',
      foo: 'bar',
    });
    expect(client).to.have.property('foo', 'bar');
  });

  it('custom properties do not interfere with the prototype', function () {
    const issuer = new Issuer();
    const client = new issuer.Client({
      client_id: 'identifier',
      issuer: 'https://op.example.com',
      userinfo: 'foobar',
      metadata: 'foobar',
    });

    expect(client).to.have.property('userinfo').that.is.a('function'); // not a string
    expect(client).to.have.property('metadata').that.is.an('object'); // not a string
    expect(client.metadata).to.have.property('metadata', 'foobar');
    expect(client.metadata).to.have.property('userinfo', 'foobar');
  });

  describe('common property misuse', function () {
    it('handles redirect_uri', function () {
      const issuer = new Issuer();
      const client = new issuer.Client({
        client_id: 'identifier',
        redirect_uri: 'https://rp.example.com/cb',
      });

      expect(client).not.to.have.property('redirect_uri');
      expect(client).to.have.deep.property('redirect_uris', ['https://rp.example.com/cb']);
      expect(() => new issuer.Client({
        client_id: 'identifier',
        redirect_uri: 'https://rp.example.com/cb',
        redirect_uris: ['https://rp.example.com/cb'],
      })).to.throw(TypeError, 'provide a redirect_uri or redirect_uris, not both');
    });

    it('handles response_type', function () {
      const issuer = new Issuer();
      const client = new issuer.Client({
        client_id: 'identifier',
        response_type: 'code id_token',
      });

      expect(client).not.to.have.property('response_type');
      expect(client).to.have.deep.property('response_types', ['code id_token']);
      expect(() => new issuer.Client({
        client_id: 'identifier',
        response_type: 'code id_token',
        response_types: ['code id_token'],
      })).to.throw(TypeError, 'provide a response_type or response_types, not both');
    });
  });

  describe('dynamic registration defaults not supported by issuer', function () {
    it('token_endpoint_auth_method vs. token_endpoint_auth_methods_supported', function () {
      const issuer = new Issuer({
        issuer: 'https://op.example.com',
        token_endpoint_auth_methods_supported: ['client_secret_post', 'private_key_jwt'],
      });
      const client = new issuer.Client({
        client_id: 'identifier',
      });

      expect(client.token_endpoint_auth_method).to.equal('client_secret_post');
    });
  });
});

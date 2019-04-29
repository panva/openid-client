const { expect } = require('chai');
const nock = require('nock');

const { Issuer } = require('../../lib');

const INPUTS = [
  'https://login.microsoftonline.com/common/v2.0',
  'https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration',
];

const idToken = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJmb28iLCJhdWQiOiJmb28iLCJpYXQiOjEyMzQ1LCJleHAiOjEyMzQ1LCJpc3MiOiJodHRwczovL2xvZ2luLm1pY3Jvc29mdG9ubGluZS5jb20vZm9vL3YyLjAiLCJ0aWQiOiJmb28ifQ';
const fail = () => { throw new Error('expected promise to be rejected'); };

describe('Azure AD multi-tenant applications', () => {
  INPUTS.forEach((input, i) => {
    it(`changes the "iss" validation when Issuer is discovered ${i + 1}/${INPUTS.length}`, () => {
      nock('https://login.microsoftonline.com')
        .get('/common/v2.0/.well-known/openid-configuration')
        .reply(200, {
          issuer: 'https://login.microsoftonline.com/{tenantid}/v2.0',
        });

      return Issuer.discover(input).then((aad) => {
        const client = new aad.Client({ client_id: 'foo' });
        try {
          client.validateIdToken(idToken);
          fail();
        } catch (err) {
          expect(err.message).to.eql('id_token expired');
        }
      });
    });
  });

  it('no changes to "iss" validation when Issuer is constructed', () => {
    const aad = new Issuer({
      issuer: 'https://login.microsoftonline.com/{tenantid}/v2.0',
    });
    const client = new aad.Client({ client_id: 'foo' });
    try {
      client.validateIdToken(idToken);
      fail();
    } catch (err) {
      expect(err.message).to.eql('unexpected iss value');
    }
  });
});

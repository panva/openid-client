const { expect } = require('chai');
const nock = require('nock');

const { Issuer } = require('../../lib');

const INPUTS = {
  common: [
    'https://login.microsoftonline.com/common/v2.0',
    'https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration',
  ],
  consumers: [
    'https://login.microsoftonline.com/consumers/v2.0',
    'https://login.microsoftonline.com/consumers/v2.0/.well-known/openid-configuration',
  ],
  organizations: [
    'https://login.microsoftonline.com/organizations/v2.0',
    'https://login.microsoftonline.com/organizations/v2.0/.well-known/openid-configuration',
  ],
};

const idToken = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJmb28iLCJhdWQiOiJmb28iLCJpYXQiOjEyMzQ1LCJleHAiOjEyMzQ1LCJpc3MiOiJodHRwczovL2xvZ2luLm1pY3Jvc29mdG9ubGluZS5jb20vZm9vL3YyLjAiLCJ0aWQiOiJmb28ifQ.';
const fail = () => { throw new Error('expected promise to be rejected'); };

describe('Azure AD multi-tenant applications', () => {
  Object.entries(INPUTS).forEach(([bucket, inputs]) => {
    inputs.forEach((input) => {
      it(`changes the "iss" validation when Issuer is discovered (${input})`, async () => {
        nock('https://login.microsoftonline.com')
          .get(`/${bucket}/v2.0/.well-known/openid-configuration`)
          .reply(200, {
            issuer: 'https://login.microsoftonline.com/{tenantid}/v2.0',
          });

        const aad = await Issuer.discover(input);
        const client = new aad.Client({ client_id: 'foo' });
        return client.validateIdToken(idToken).then(fail).catch((err) => {
          expect(err.message).to.match(/^JWT expired, now \d+, exp 12345$/);
        });
      });

      it(`changes the "iss" validation when Issuer is discovered with an appid query string (${input})`, async () => {
        nock('https://login.microsoftonline.com')
          .get(`/${bucket}/v2.0/.well-known/openid-configuration?appid=6731de76-14a6-49ae-97bc-6eba6914391e`)
          .reply(200, {
            issuer: 'https://login.microsoftonline.com/{tenantid}/v2.0',
          });

        const aad = await Issuer.discover(`${input}?appid=6731de76-14a6-49ae-97bc-6eba6914391e`);
        const client = new aad.Client({ client_id: 'foo' });
        return client.validateIdToken(idToken).then(fail).catch((err) => {
          expect(err.message).to.match(/^JWT expired, now \d+, exp 12345$/);
        });
      });
    });

    it('no changes to "iss" validation when Issuer is constructed', async () => {
      const aad = new Issuer({
        issuer: 'https://login.microsoftonline.com/{tenantid}/v2.0',
      });
      const client = new aad.Client({ client_id: 'foo' });
      return client.validateIdToken(idToken).then(fail).catch((err) => {
        expect(err.message).to.eql('unexpected iss value, expected https://login.microsoftonline.com/{tenantid}/v2.0, got: https://login.microsoftonline.com/foo/v2.0');
      });
    });
  });
});

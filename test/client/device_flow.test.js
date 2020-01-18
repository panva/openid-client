const querystring = require('querystring');

const { expect } = require('chai');
const nock = require('nock');
const timekeeper = require('timekeeper');

const { Issuer } = require('../../lib');
const DeviceFlowHandle = require('../../lib/device_flow_handle');
const TokenSet = require('../../lib/token_set');
const instance = require('../../lib/helpers/weak_cache');

const fail = () => { throw new Error('expected promise to be rejected'); };

describe('Device Flow features', () => {
  afterEach(timekeeper.reset);
  afterEach(nock.cleanAll);

  before(function () {
    const issuer = new Issuer({
      issuer: 'https://op.example.com',
      device_authorization_endpoint: 'https://op.example.com/auth/device',
      token_endpoint: 'https://op.example.com/token',
    });

    const client = new issuer.Client({
      client_id: 'client',
      token_endpoint_auth_method: 'none',
    });

    Object.assign(this, { issuer, client });
  });

  describe('client.deviceAuthorization()', () => {
    it('returns a handle (without optional response parameters)', async function () {
      nock('https://op.example.com')
        .filteringRequestBody(function (body) {
          expect(querystring.parse(body)).to.eql({
            client_id: 'client',
            scope: 'openid',
            foo: 'bar',
          });
        })
        .post('/auth/device', () => true) // to make sure filteringRequestBody works
        .reply(200, {
          verification_uri: 'https://op.example.com/device',
          user_code: 'AAAA-AAAA',
          device_code: 'foobar',
          expires_in: 300,
        });

      const handle = await this.client.deviceAuthorization({ foo: 'bar' });

      expect(handle).to.be.an.instanceOf(DeviceFlowHandle);

      expect(handle).to.have.property('user_code', 'AAAA-AAAA');
      expect(handle).to.have.property('verification_uri', 'https://op.example.com/device');
      expect(handle).to.have.property('verification_uri_complete', undefined);
      expect(handle).to.have.property('device_code', 'foobar');
      expect(handle).to.have.property('expires_in').that.is.a('number').most(300);
      expect(handle.expired()).to.be.false;
    });

    it('returns a handle (with optional response parameters)', async function () {
      nock('https://op.example.com')
        .post('/auth/device')
        .reply(200, {
          verification_uri: 'https://op.example.com/device',
          verification_uri_complete: 'https://op.example.com/device/AAAA-AAAA',
          user_code: 'AAAA-AAAA',
          device_code: 'foobar',
          expires_in: 300,
          interval: 6,
        });

      const handle = await this.client.deviceAuthorization();

      expect(handle).to.be.an.instanceOf(DeviceFlowHandle);

      expect(handle).to.have.property('user_code', 'AAAA-AAAA');
      expect(handle).to.have.property('verification_uri', 'https://op.example.com/device');
      expect(handle).to.have.property('verification_uri_complete', 'https://op.example.com/device/AAAA-AAAA');
      expect(handle).to.have.property('device_code', 'foobar');
      expect(handle).to.have.property('expires_in').that.is.a('number').most(300);
      expect(handle.expired()).to.be.false;
    });

    it('requires the issuer to have device_authorization_endpoint', () => {
      const issuer = new Issuer({
        issuer: 'https://op.example.com',
        token_endpoint: 'https://op.example.com/token',
      });

      const client = new issuer.Client({
        client_id: 'client',
        token_endpoint_auth_method: 'none',
      });

      return client.deviceAuthorization().then(fail, ({ message }) => {
        expect(message).to.eql('device_authorization_endpoint must be configured on the issuer');
      });
    });

    it('requires the issuer to have token_endpoint', () => {
      const issuer = new Issuer({
        issuer: 'https://op.example.com',
        device_authorization_endpoint: 'https://op.example.com/auth/device',
      });

      const client = new issuer.Client({
        client_id: 'client',
        token_endpoint_auth_method: 'none',
      });

      return client.deviceAuthorization().then(fail, ({ message }) => {
        expect(message).to.eql('token_endpoint must be configured on the issuer');
      });
    });
  });

  describe('DeviceFlowHandle', () => {
    describe('handle.poll()', () => {
      it('calls the token endpoint and returns the tokenset', async function () {
        const handle = new DeviceFlowHandle({
          client: this.client,
          response: {
            verification_uri: 'https://op.example.com/device',
            user_code: 'AAAA-AAAA',
            device_code: 'foobar',
            interval: 5,
            expires_in: 300,
          },
        });

        nock('https://op.example.com')
          .filteringRequestBody(function (body) {
            expect(querystring.parse(body)).to.eql({
              client_id: 'client',
              grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
              device_code: 'foobar',
            });
          })
          .post('/token', () => true) // to make sure filteringRequestBody works
          .reply(200, {
            expires_in: 300,
            access_token: 'at',
          });

        instance(handle).interval = 5;

        const tokenset = await handle.poll();

        expect(tokenset).to.be.instanceOf(TokenSet);
      });

      it('continues to poll when slow_down is received and increases the interval by 5000', async function () {
        this.timeout(6000);
        const handle = new DeviceFlowHandle({
          client: this.client,
          response: {
            verification_uri: 'https://op.example.com/device',
            user_code: 'AAAA-AAAA',
            device_code: 'foobar',
            interval: 5,
            expires_in: 300,
          },
        });

        nock('https://op.example.com')
          .filteringRequestBody(function (body) {
            expect(querystring.parse(body)).to.eql({
              client_id: 'client',
              grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
              device_code: 'foobar',
            });
          })
          .post('/token', () => true) // to make sure filteringRequestBody works
          .reply(400, { error: 'slow_down' })
          .post('/token')
          .reply(200, {
            expires_in: 300,
            access_token: 'at',
          });

        instance(handle).interval = 5;

        const tokenset = await handle.poll();

        expect(instance(handle).interval).to.eql(5005);

        expect(tokenset).to.be.instanceOf(TokenSet);
      });

      it('continues to poll when authorization_pending is received with the same interval', async function () {
        const handle = new DeviceFlowHandle({
          client: this.client,
          response: {
            verification_uri: 'https://op.example.com/device',
            user_code: 'AAAA-AAAA',
            device_code: 'foobar',
            interval: 5,
            expires_in: 300,
          },
        });

        nock('https://op.example.com')
          .filteringRequestBody(function (body) {
            expect(querystring.parse(body)).to.eql({
              client_id: 'client',
              grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
              device_code: 'foobar',
            });
          })
          .post('/token', () => true) // to make sure filteringRequestBody works
          .reply(400, { error: 'authorization_pending' })
          .post('/token')
          .reply(200, {
            expires_in: 300,
            access_token: 'at',
          });

        instance(handle).interval = 5;

        const tokenset = await handle.poll();

        expect(instance(handle).interval).to.eql(5);

        expect(tokenset).to.be.instanceOf(TokenSet);
      });

      it('validates the id token when there is one returned', async function () {
        const handle = new DeviceFlowHandle({
          client: this.client,
          response: {
            verification_uri: 'https://op.example.com/device',
            user_code: 'AAAA-AAAA',
            device_code: 'foobar',
            interval: 5,
            expires_in: 300,
          },
        });

        nock('https://op.example.com')
          .post('/token')
          .reply(200, {
            id_token: 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJzdWJqZWN0In0.',
            refresh_token: 'bar',
            access_token: 'tokenValue',
          });

        instance(handle).interval = 5;

        return handle.poll().then(fail, (err) => {
          expect(err.name).to.eql('RPError');
          expect(err.message).to.eql('unexpected JWT alg received, expected RS256, got: none');
        });
      });

      it('stops polling on other errors and rejects', async function () {
        const handle = new DeviceFlowHandle({
          client: this.client,
          response: {
            verification_uri: 'https://op.example.com/device',
            user_code: 'AAAA-AAAA',
            device_code: 'foobar',
            interval: 5,
            expires_in: 300,
          },
        });

        nock('https://op.example.com')
          .filteringRequestBody(function (body) {
            expect(querystring.parse(body)).to.eql({
              client_id: 'client',
              grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
              device_code: 'foobar',
            });
          })
          .post('/token', () => true) // to make sure filteringRequestBody works
          .reply(400, { error: 'authorization_pending' })
          .post('/token')
          .reply(400, {
            error: 'server_error',
            error_description: 'bad things are happening',
          });

        instance(handle).interval = 5;

        return handle.poll().then(fail, (err) => {
          expect(err.name).to.equal('OPError');
          expect(err).to.have.property('error', 'server_error');
          expect(err).to.have.property('error_description', 'bad things are happening');
        });
      });

      it('stops polling when expired', async function () {
        const handle = new DeviceFlowHandle({
          client: this.client,
          response: {
            verification_uri: 'https://op.example.com/device',
            user_code: 'AAAA-AAAA',
            device_code: 'foobar',
            interval: 5,
            expires_in: 300,
          },
        });

        instance(handle).interval = 5;
        instance(handle).expires_at = Math.floor(Date.now() / 1000);

        return handle.poll().then(fail, (err) => {
          expect(err.name).to.equal('RPError');
          expect(err.message).to.equal('the device code "foobar" has expired and the device authorization session has concluded');
        });
      });
    });

    it('the handle tracks expiration of the device code', () => {
      const handle = new DeviceFlowHandle({
        response: {
          verification_uri: 'https://op.example.com/device',
          user_code: 'AAAA-AAAA',
          device_code: 'foobar',
          expires_in: 300,
        },
      });

      expect(handle.expired()).to.be.false;
      timekeeper.travel(new Date(Date.now() + 100 * 1000));
      expect(handle.expired()).to.be.false;
      timekeeper.travel(new Date(Date.now() + 200 * 1000));
      expect(handle.expired()).to.be.true;
    });

    ['verification_uri', 'user_code', 'device_code'].forEach((prop) => {
      it(`validates ${prop}`, function () {
        nock('https://op.example.com')
          .post('/auth/device')
          .reply(200, {
            verification_uri: 'https://op.example.com/device',
            user_code: 'AAAA-AAAA',
            device_code: 'foobar',
            expires_in: 300,
            [prop]: '',
          });

        return this.client.deviceAuthorization().then(fail, ({ message }) => {
          expect(message).to.eql(`expected ${prop} string to be returned by Device Authorization Response, got ""`);
        });
      });
    });

    it('validates expires_in', function () {
      nock('https://op.example.com')
        .post('/auth/device')
        .reply(200, {
          verification_uri: 'https://op.example.com/device',
          user_code: 'AAAA-AAAA',
          device_code: 'foobar',
        });

      return this.client.deviceAuthorization().then(fail, ({ message }) => {
        expect(message).to.eql('expected expires_in number to be returned by Device Authorization Response, got undefined');
      });
    });
  });
});

const http = require('http');

const sinon = require('sinon');
const MockRequest = require('readable-mock-req');
const { expect } = require('chai');

const { Issuer, Strategy } = require('../../lib');

['useGot', 'useRequest'].forEach((httpProvider) => {
  describe(`OpenIDConnectStrategy - using ${httpProvider.substring(3).toLowerCase()}`, function () {
    before(function () {
      Issuer[httpProvider]();
    });

    before(function () {
      this.origIncomingMessage = http.IncomingMessage;
      http.IncomingMessage = MockRequest;
    });

    after(function () {
      http.IncomingMessage = this.origIncomingMessage;
    });

    beforeEach(function () {
      this.issuer = new Issuer({
        issuer: 'https://op.example.com',
        authorization_endpoint: 'https://op.example.com/auth',
        jwks_uri: 'https://op.example.com/jwks',
        token_endpoint: 'https://op.example.com/token',
        userinfo_endpoint: 'https://op.example.com/userinfo',
        code_challenge_methods_supported: ['plain', 'S256'],
      });

      this.client = new this.issuer.Client({
        client_id: 'foo',
        client_secret: 'barbaz',
        respose_types: ['code'],
        redirect_uris: ['http://rp.example.com/cb'],
      });
    });

    it('checks for session presence', function (next) {
      const strategy = new Strategy({ client: this.client }, () => {});

      const req = new MockRequest('GET', '/login/oidc');

      strategy.error = (error) => {
        try {
          expect(error).to.be.an.instanceof(Error);
          expect(error.message).to.match(/session/);
          next();
        } catch (err) {
          next(err);
        }
      };
      strategy.authenticate(req);
    });

    describe('initate', function () {
      it('starts authentication requests for GETs', function () {
        const strategy = new Strategy({ client: this.client }, () => {});

        const req = new MockRequest('GET', '/login/oidc');
        req.session = {};

        strategy.redirect = sinon.spy();
        strategy.authenticate(req);

        expect(strategy.redirect.calledOnce).to.be.true;
        const target = strategy.redirect.firstCall.args[0];
        expect(target).to.include('redirect_uri=');
        expect(target).to.include('scope=');
        expect(req.session).to.have.property('oidc:op.example.com');
        expect(req.session['oidc:op.example.com']).to.have.keys('state', 'response_type');
      });

      it('starts authentication requests for POSTs', function () {
        const strategy = new Strategy({ client: this.client }, () => {});

        const req = new MockRequest('POST', '/login/oidc');
        req.session = {};
        req.body = {};

        strategy.redirect = sinon.spy();
        strategy.authenticate(req);

        expect(strategy.redirect.calledOnce).to.be.true;
        const target = strategy.redirect.firstCall.args[0];
        expect(target).to.include('redirect_uri=');
        expect(target).to.include('scope=');
        expect(req.session).to.have.property('oidc:op.example.com');
        expect(req.session['oidc:op.example.com']).to.have.keys('state', 'response_type');
      });

      it('can have redirect_uri and scope specified', function () {
        const strategy = new Strategy({
          client: this.client,
          params: {
            redirect_uri: 'https://example.com/cb',
            scope: 'openid profile',
          },
        }, () => {});

        const req = new MockRequest('GET', '/login/oidc');
        req.session = {};

        strategy.redirect = sinon.spy();
        strategy.authenticate(req);

        expect(strategy.redirect.calledOnce).to.be.true;
        const target = strategy.redirect.firstCall.args[0];
        expect(target).to.include(`redirect_uri=${encodeURIComponent('https://example.com/cb')}`);
        expect(target).to.include('scope=openid%20profile');
      });

      it('automatically includes nonce for where it applies', function () {
        const strategy = new Strategy({
          client: this.client,
          params: {
            response_type: 'code id_token token',
            response_mode: 'form_post',
          },
        }, () => {});

        const req = new MockRequest('GET', '/login/oidc');
        req.session = {};

        strategy.redirect = sinon.spy();
        strategy.authenticate(req);

        expect(strategy.redirect.calledOnce).to.be.true;
        const target = strategy.redirect.firstCall.args[0];
        expect(target).to.include('redirect_uri=');
        expect(target).to.include('scope=');
        expect(target).to.include('nonce=');
        expect(target).to.include('response_mode=form_post');
        expect(req.session).to.have.property('oidc:op.example.com');
        expect(req.session['oidc:op.example.com']).to.have.keys('state', 'nonce', 'response_type');
      });

      describe('use pkce', () => {
        it('can be set to use PKCE with boolean', function () {
          this.issuer.metadata.code_challenge_methods_supported = ['S256', 'plain'];
          const s256 = new Strategy({ // eslint-disable-line no-new
            client: this.client,
            usePKCE: true,
          }, () => {});
          expect(s256).to.have.property('_usePKCE', 'S256');

          this.issuer.metadata.code_challenge_methods_supported = ['plain'];
          const plain = new Strategy({ // eslint-disable-line no-new
            client: this.client,
            usePKCE: true,
          }, () => {});
          expect(plain).to.have.property('_usePKCE', 'plain');

          ['foobar', undefined, false].forEach((invalidDiscoveryValue) => {
            this.issuer.metadata.code_challenge_methods_supported = invalidDiscoveryValue;
            expect(() => {
              new Strategy({ // eslint-disable-line no-new
                client: this.client,
                usePKCE: true,
              }, () => {});
            }).to.throw('code_challenge_methods_supported is not properly set on issuer');
          });

          this.issuer.metadata.code_challenge_methods_supported = [];
          expect(() => {
            new Strategy({ // eslint-disable-line no-new
              client: this.client,
              usePKCE: true,
            }, () => {});
          }).to.throw('issuer code_challenge_methods_supported is empty');

          this.issuer.metadata.code_challenge_methods_supported = ['not supported'];
          expect(() => {
            new Strategy({ // eslint-disable-line no-new
              client: this.client,
              usePKCE: true,
            }, () => {});
          }).to.throw('neither S256 or plain code_challenge_method is supported by the issuer');
        });

        it('will throw when explictly provided value is not supported', function () {
          expect(() => {
            new Strategy({ // eslint-disable-line no-new
              client: this.client,
              usePKCE: 'foobar',
            }, () => {});
          }).to.throw('foobar is not valid/implemented PKCE code_challenge_method');
        });

        it('can be set to use PKCE (S256)', function () {
          const strategy = new Strategy({
            client: this.client,
            usePKCE: 'S256',
          }, () => {});

          const req = new MockRequest('GET', '/login/oidc');
          req.session = {};

          strategy.redirect = sinon.spy();
          strategy.authenticate(req);

          expect(strategy.redirect.calledOnce).to.be.true;
          const target = strategy.redirect.firstCall.args[0];
          expect(target).to.include('code_challenge_method=S256');
          expect(target).to.include('code_challenge=');
          expect(req.session).to.have.property('oidc:op.example.com');
          expect(req.session['oidc:op.example.com']).to.have.property('code_verifier');
        });

        it('can be set to use PKCE (plain)', function () {
          const strategy = new Strategy({
            client: this.client,
            usePKCE: 'plain',
          }, () => {});

          const req = new MockRequest('GET', '/login/oidc');
          req.session = {};

          strategy.redirect = sinon.spy();
          strategy.authenticate(req);

          expect(strategy.redirect.calledOnce).to.be.true;
          const target = strategy.redirect.firstCall.args[0];
          expect(target).not.to.include('code_challenge_method');
          expect(target).to.include('code_challenge=');
          expect(req.session).to.have.property('oidc:op.example.com');
          expect(req.session['oidc:op.example.com']).to.have.property('code_verifier');
        });
      });

      it('can have session key specifed', function () {
        const strategy = new Strategy({
          client: this.client,
          sessionKey: 'oidc:op.example.com:foo',
        }, () => {});

        const req = new MockRequest('GET', '/login/oidc');
        req.session = {};

        strategy.redirect = sinon.spy();
        strategy.authenticate(req);

        expect(req.session).to.have.property('oidc:op.example.com:foo');
        expect(req.session['oidc:op.example.com:foo']).to.have.keys('state', 'response_type');
      });
    });

    describe('callback', function () {
      it('triggers the verify function and then the success one', function (next) {
        const ts = { foo: 'bar' };
        sinon.stub(this.client, 'authorizationCallback').callsFake(function () {
          return Promise.resolve(ts);
        });

        const strategy = new Strategy({ client: this.client }, (tokenset, done) => {
          expect(tokenset).to.equal(ts);
          done(null, tokenset);
        });

        strategy.success = () => { next(); };

        const req = new MockRequest('GET', '/login/oidc/callback?code=foobar&state=state');
        req.session = {
          'oidc:op.example.com': {
            nonce: 'nonce',
            state: 'state',
            response_type: 'code',
          },
        };

        strategy.authenticate(req);
      });

      it('triggers the error function when server_error is encountered', function (next) {
        const strategy = new Strategy({ client: this.client }, () => {});

        const req = new MockRequest('GET', '/login/oidc/callback?error=server_error&state=state');
        req.session = {
          'oidc:op.example.com': {
            nonce: 'nonce',
            state: 'state',
            response_type: 'code',
          },
        };

        strategy.error = (error) => {
          try {
            expect(error.error).to.equal('server_error');
            next();
          } catch (err) {
            next(err);
          }
        };

        strategy.authenticate(req);
      });

      it('lets the dev know when most common problems with session occur', function (next) {
        const strategy = new Strategy({ client: this.client }, () => {});

        const req = new MockRequest('GET', '/login/oidc/callback?code=code&state=foo');
        req.session = {};

        strategy.error = (error) => {
          try {
            expect(error.message).to.eql('did not find expected authorization request details in session, req.session["oidc:op.example.com"] is undefined');
            next();
          } catch (err) {
            next(err);
          }
        };

        strategy.authenticate(req);
      });

      it('triggers the error function when non oidc error is encountered', function (next) {
        const strategy = new Strategy({ client: this.client }, () => {});

        sinon.stub(this.client, 'authorizationCallback').callsFake(function () {
          return Promise.reject(new Error('callback error'));
        });

        const req = new MockRequest('GET', '/login/oidc/callback?code=code&state=state');
        req.session = {
          'oidc:op.example.com': {
            nonce: 'nonce',
            state: 'state',
            response_type: 'code',
          },
        };

        strategy.error = (error) => {
          try {
            expect(error.message).to.equal('callback error');
            next();
          } catch (err) {
            next(err);
          }
        };

        strategy.authenticate(req);
      });

      it('triggers the fail function when oidc error is encountered', function (next) {
        const strategy = new Strategy({ client: this.client }, () => {});

        const req = new MockRequest('GET', '/login/oidc/callback?error=login_required&state=state');
        req.session = {
          'oidc:op.example.com': {
            nonce: 'nonce',
            state: 'state',
            response_type: 'code',
          },
        };

        strategy.fail = (error) => {
          try {
            expect(error.error).to.equal('login_required');
            next();
          } catch (err) {
            next(err);
          }
        };

        strategy.authenticate(req);
      });

      it('triggers the error function for errors during verify', function (next) {
        const strategy = new Strategy({ client: this.client }, (tokenset, done) => {
          done(new Error('user find error'));
        });

        const ts = { foo: 'bar' };
        sinon.stub(this.client, 'authorizationCallback').callsFake(function () {
          return Promise.resolve(ts);
        });

        const req = new MockRequest('GET', '/login/oidc/callback?code=foo&state=state');
        req.session = {
          'oidc:op.example.com': {
            nonce: 'nonce',
            state: 'state',
            response_type: 'code',
          },
        };

        strategy.error = (error) => {
          try {
            expect(error.message).to.equal('user find error');
            next();
          } catch (err) {
            next(err);
          }
        };

        strategy.authenticate(req);
      });

      it('triggers the fail function when verify yields no account', function (next) {
        const strategy = new Strategy({ client: this.client }, (tokenset, done) => {
          done();
        });

        const ts = { foo: 'bar' };
        sinon.stub(this.client, 'authorizationCallback').callsFake(function () {
          return Promise.resolve(ts);
        });

        const req = new MockRequest('GET', '/login/oidc/callback?code=foo&state=state');
        req.session = {
          'oidc:op.example.com': {
            nonce: 'nonce',
            response_type: 'code',
            state: 'state',
          },
        };

        strategy.fail = () => {
          next();
        };

        strategy.authenticate(req);
      });

      it('does userinfo request too if part of verify arity and resulting tokenset', function (next) {
        const strategy = new Strategy({ client: this.client }, (tokenset, userinfo, done) => {
          try {
            expect(tokenset).to.be.ok;
            expect(userinfo).to.be.ok;
            done(null, { sub: 'foobar' });
          } catch (err) {
            next(err);
          }
        });

        const ts = { access_token: 'foo' };
        const ui = { sub: 'bar' };
        sinon.stub(this.client, 'authorizationCallback').callsFake(function () {
          return Promise.resolve(ts);
        });
        sinon.stub(this.client, 'userinfo').callsFake(function () {
          return Promise.resolve(ui);
        });

        const req = new MockRequest('GET', '/login/oidc/callback?code=foo&state=state');
        req.session = {
          'oidc:op.example.com': {
            nonce: 'nonce',
            response_type: 'code',
            state: 'state',
          },
        };

        strategy.success = () => {
          next();
        };

        strategy.authenticate(req);
      });

      it('skips userinfo request too if no tokenset but arity', function (next) {
        const strategy = new Strategy({ client: this.client }, (tokenset, userinfo, done) => {
          try {
            expect(tokenset).to.be.ok;
            expect(userinfo).to.be.undefined;
            done(null, { sub: 'foobar' });
          } catch (err) {
            next(err);
          }
        });

        const ts = { id_token: 'foo' };
        sinon.stub(this.client, 'authorizationCallback').callsFake(function () {
          return Promise.resolve(ts);
        });

        const req = new MockRequest('GET', '/login/oidc/callback?code=foo&state=state');
        req.session = {
          'oidc:op.example.com': {
            nonce: 'nonce',
            response_type: 'code',
            state: 'state',
          },
        };

        strategy.success = () => {
          next();
        };

        strategy.authenticate(req);
      });

      it('receives a request as the first parameter if passReqToCallback is set', function (next) {
        const strategy = new Strategy({
          client: this.client,
          passReqToCallback: true,
        }, (req, tokenset, done) => {
          try {
            expect(req).to.be.an.instanceof(MockRequest);
            expect(tokenset).to.be.ok;
            done(null, { sub: 'foobar' });
          } catch (err) {
            next(err);
          }
        });

        const ts = { id_token: 'foo' };
        sinon.stub(this.client, 'authorizationCallback').callsFake(function () {
          return Promise.resolve(ts);
        });

        const req = new MockRequest('GET', '/login/oidc/callback?code=foo&state=state');
        req.session = {
          'oidc:op.example.com': {
            nonce: 'nonce',
            response_type: 'code',
            state: 'state',
          },
        };

        strategy.success = () => {
          next();
        };

        strategy.authenticate(req);
      });

      it('receives a request and userinfo with passReqToCallback: true and userinfo', function (next) {
        const strategy = new Strategy({
          client: this.client,
          passReqToCallback: true,
        }, (req, tokenset, userinfo, done) => {
          try {
            expect(req).to.be.an.instanceof(MockRequest);
            expect(tokenset).to.be.ok;
            expect(userinfo).to.be.ok;
            done(null, { sub: 'foobar' });
          } catch (err) {
            next(err);
          }
        });

        const ts = { access_token: 'foo' };
        const ui = { sub: 'bar' };
        sinon.stub(this.client, 'authorizationCallback').callsFake(function () {
          return Promise.resolve(ts);
        });
        sinon.stub(this.client, 'userinfo').callsFake(function () {
          return Promise.resolve(ui);
        });

        const req = new MockRequest('GET', '/login/oidc/callback?code=foo&state=state');
        req.session = {
          'oidc:op.example.com': {
            nonce: 'nonce',
            response_type: 'code',
            state: 'state',
          },
        };

        strategy.success = () => {
          next();
        };

        strategy.authenticate(req);
      });

      it('skips userinfo request too if no tokenset but arity (even with passReqToCallback)', function (next) {
        const strategy = new Strategy({
          client: this.client,
          passReqToCallback: true,
        }, (req, tokenset, userinfo, done) => {
          try {
            expect(req).to.be.an.instanceof(MockRequest);
            expect(tokenset).to.be.ok;
            expect(userinfo).to.be.undefined;
            done(null, { sub: 'foobar' });
          } catch (err) {
            next(err);
          }
        });

        const ts = { id_token: 'foo' };
        sinon.stub(this.client, 'authorizationCallback').callsFake(function () {
          return Promise.resolve(ts);
        });

        const req = new MockRequest('GET', '/login/oidc/callback?code=foo&state=state');
        req.session = {
          'oidc:op.example.com': {
            nonce: 'nonce',
            response_type: 'code',
            state: 'state',
          },
        };

        strategy.success = () => {
          next();
        };

        strategy.authenticate(req);
      });
    });
  });
});

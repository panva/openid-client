'use strict';

/* eslint-disable import/no-extraneous-dependencies, func-names */

const _ = require('lodash');
const decode = require('base64url').decode;
const koa = require('koa');
const crypto = require('crypto');
const url = require('url');
const uuid = require('uuid');
const jose = require('node-jose');
const path = require('path');
const Router = require('koa-router');
const body = require('koa-body');
const session = require('koa-session');
const render = require('koa-ejs');

const PRESETS = require('./presets');

module.exports = (issuer) => {
  const app = koa();

  if (process.env.NODE_ENV === 'production') {
    app.proxy = true;

    app.use(function* (next) {
      if (this.secure) {
        yield next;
      } else {
        this.redirect(this.href.replace(/^http:\/\//i, 'https://'));
      }
    });
  }

  app.keys = ['some secret hurr'];
  app.use(session(app));

  const CLIENTS = new Map();
  const TOKENS = new Map();

  render(app, {
    cache: false,
    layout: '_layout',
    root: path.join(__dirname, 'views'),
  });

  app.use(function* (next) {
    this.session.id = this.session.id || uuid();
    yield next;
  });

  app.use(function* (next) {
    try {
      yield next;
    } catch (error) {
      yield this.render('error', { issuer, error, session: this.session });
    }
  });

  app.use(function* (next) {
    if (!CLIENTS.has(this.session.id) && !this.path.startsWith('/setup')) {
      this.redirect('/setup');
    }
    yield next;
  });

  const router = new Router();

  router.get('/', function* () {
    yield this.render('index', { session: this.session, issuer });
  });

  router.get('/rpframe', function* () {
    const clientId = CLIENTS.get(this.session.id).client_id;
    const sessionState = TOKENS.get(this.session.id).session_state;
    yield this.render('rp_frame', { session: this.session, layout: false, issuer, clientId, sessionState });
  });

  router.get('/setup', function* () {
    yield this.render('setup', { session: this.session, presets: PRESETS, issuer });
  });

  router.post('/setup/:preset', function* () {
    let keystore;
    const preset = PRESETS[this.params.preset];
    this.session.loggedIn = false;

    if (preset.keystore) {
      keystore = jose.JWK.createKeyStore();
      yield keystore.generate.apply(keystore, preset.keystore);
    }

    const metadata = Object.assign({
      post_logout_redirect_uris: [url.resolve(this.href, '/')],
      redirect_uris: [url.resolve(this.href, '/cb')],
    }, preset.registration);

    const client = yield issuer.Client.register(metadata, keystore);
    client.CLOCK_TOLERANCE = 5;
    CLIENTS.set(this.session.id, client);
    this.session.authorization_params = preset.authorization_params;

    this.redirect('/client');
  });

  router.get('/issuer', function* () {
    yield this.render('issuer', {
      issuer,
      keystore: (yield issuer.keystore()),
      session: this.session,
    });
  });

  router.get('/client', function* () {
    yield this.render('client', { client: CLIENTS.get(this.session.id), session: this.session, issuer });
  });

  router.get('/logout', function* () {
    const id = this.session.id;
    this.session.loggedIn = false;

    if (!TOKENS.has(id)) {
      return this.redirect('/');
    }

    const tokens = TOKENS.get(id);
    TOKENS.delete(id);

    try {
      yield CLIENTS.get(id).revoke(tokens.access_token);
    } catch (err) {}

    return this.redirect(url.format(Object.assign(url.parse(issuer.end_session_endpoint), {
      search: null,
      query: {
        id_token_hint: tokens.id_token,
        post_logout_redirect_uri: url.resolve(this.href, '/'),
      },
    })));
  });

  router.get('/login', function* (next) {
    this.session.state = crypto.randomBytes(16).toString('hex');
    this.session.nonce = crypto.randomBytes(16).toString('hex');

    const authorizationRequest = Object.assign({
      claims: {
        id_token: { email_verified: null },
        userinfo: { sub: null, email: null },
      },
      redirect_uri: url.resolve(this.href, 'cb'),
      scope: 'openid',
      state: this.session.state,
      nonce: this.session.nonce,
    }, this.session.authorization_params);

    const authz = CLIENTS.get(this.session.id).authorizationUrl(authorizationRequest);

    this.redirect(authz);
    yield next;
  });

  router.get('/refresh', function* (next) {
    if (!TOKENS.has(this.session.id)) {
      this.session = null;
      this.redirect('/');
    } else {
      const tokens = TOKENS.get(this.session.id);
      const client = CLIENTS.get(this.session.id);

      const refreshed = yield client.refresh(tokens);
      refreshed.session_state = tokens.session_state;

      TOKENS.set(this.session.id, refreshed);

      this.redirect('/user');
    }


    yield next;
  });

  router.get('/cb', function* () {
    const state = this.session.state;
    delete this.session.state;
    const nonce = this.session.nonce;
    delete this.session.nonce;
    const client = CLIENTS.get(this.session.id);
    const params = client.callbackParams(this.request.req);

    TOKENS.set(this.session.id,
      yield client.authorizationCallback(url.resolve(this.href, 'cb'), params, { nonce, state }));

    this.session.loggedIn = true;

    this.redirect('/user');
  });

  router.post('/cb', body({ patchNode: true }), function* () {
    const state = this.session.state;
    delete this.session.state;
    const nonce = this.session.nonce;
    delete this.session.nonce;
    const client = CLIENTS.get(this.session.id);
    const params = client.callbackParams(this.request.req);

    TOKENS.set(this.session.id,
      yield client.authorizationCallback(url.resolve(this.href, 'cb'), params, { nonce, state }));

    this.session.loggedIn = true;

    this.redirect('/user');
  });

  function rejectionHandler(error) {
    if (error.name === 'OpenIdConnectError') {
      return error;
    }

    throw error;
  }

  router.get('/user', function* () {
    if (!TOKENS.has(this.session.id)) {
      this.session.loggedIn = false;
      return this.redirect('/client');
    }
    const tokens = TOKENS.get(this.session.id);
    const client = CLIENTS.get(this.session.id);

    const context = {
      tokens,
      userinfo: undefined,
      id_token: tokens.id_token ? _.map(tokens.id_token.split('.'), (part) => {
        try {
          return JSON.parse(decode(part));
        } catch (err) {
          return part;
        }
      }) : undefined,
      session: this.session,
      introspections: {},
      issuer,
    };

    const promises = {};

    _.forEach(tokens, (value, key) => {
      if (key.endsWith('token') && key !== 'id_token') {
        promises[key] = client.introspect(value, key).catch(rejectionHandler);
      }
      return undefined;
    });

    if (tokens.access_token) {
      promises.userinfo = client.userinfo(tokens)
        .then(userinfo => client.fetchDistributedClaims(userinfo))
        .then(userinfo => client.unpackAggregatedClaims(userinfo))
        .catch(rejectionHandler);
    }

    const results = yield promises;

    _.forEach(results, (result, key) => {
      if (key === 'userinfo') {
        context.userinfo = result;
      } else {
        context.introspections[key] = result;
      }
    });

    return yield this.render('user', context);
  });

  app.use(router.routes());
  app.use(router.allowedMethods());

  return app;
};

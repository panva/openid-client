/* eslint-disable import/no-extraneous-dependencies, func-names */
'use strict';

const _ = require('lodash');
const decode = require('base64url').decode;
const koa = require('koa');
const crypto = require('crypto');
const url = require('url');
const uuid = require('node-uuid').v4;
const jose = require('node-jose');
const path = require('path');
const Router = require('koa-router');
const session = require('koa-session');
const render = require('koa-ejs');

module.exports = issuer => {
  const app = koa();

  if (process.env.HEROKU) {
    app.proxy = true;

    app.use(function * (next) {
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

  app.use(function * (next) {
    this.session.id = this.session.id || uuid();
    yield next;
  });

  app.use(function * (next) {
    try {
      yield next;
    } catch (error) {
      yield this.render('error', { error, session: this.session });
    }
  });

  app.use(function * (next) {
    if (!CLIENTS.has(this.session.id)) {
      const keystore = jose.JWK.createKeyStore();
      yield keystore.generate.apply(keystore,
        _.sample([['RSA', 2048], ['EC', _.sample(['P-256', 'P-384', 'P-521'])]]));

      const client = yield issuer.Client.register({
        grant_types: ['authorization_code', 'refresh_token'],
        post_logout_redirect_uris: [url.resolve(this.href, '/')],
        redirect_uris: [url.resolve(this.href, 'cb')],
        response_types: ['code'],

        token_endpoint_auth_method: 'private_key_jwt',
        // token_endpoint_auth_method: 'client_secret_jwt',

        // id_token_encrypted_response_alg: 'RSA1_5',
        // userinfo_encrypted_response_alg: 'RSA1_5',
      // });
      }, keystore);
      CLIENTS.set(this.session.id, client);
    }
    yield next;
  });

  const router = new Router();

  router.get('/', function * () {
    yield this.render('index', { session: this.session });
  });

  router.get('/issuer', function * () {
    yield this.render('issuer', {
      issuer,
      keystore: (yield issuer.keystore()),
      session: this.session,
    });
  });

  router.get('/client', function * () {
    yield this.render('client', { client: CLIENTS.get(this.session.id), session: this.session });
  });

  router.get('/logout', function * () {
    const id = this.session.id;
    this.session = null;

    if (!TOKENS.has(id)) {
      return this.redirect('/');
    }

    const tokens = TOKENS.get(id);

    yield CLIENTS.get(id).revoke(tokens.access_token);

    return this.redirect(url.format(Object.assign(url.parse(issuer.end_session_endpoint), {
      search: null,
      query: {
        id_token_hint: tokens.id_token,
        post_logout_redirect_uri: url.resolve(this.href, '/'),
      },
    })));
  });

  router.get('/login', function * (next) {
    this.session.state = crypto.randomBytes(16).toString('hex');
    this.session.nonce = crypto.randomBytes(16).toString('hex');
    const authz = CLIENTS.get(this.session.id).authorizationUrl({
      claims: {
        id_token: { email_verified: null },
        userinfo: { sub: null, email: null },
      },
      redirect_uri: url.resolve(this.href, 'cb'),
      scope: 'openid',

      // scope: 'openid offline_access',
      // prompt: 'consent',

      state: this.session.state,
      nonce: this.session.nonce,
    });

    this.redirect(authz);
    yield next;
  });

  router.get('/refresh', function * (next) {
    if (!TOKENS.has(this.session.id)) {
      this.session = null;
      this.redirect('/');
    } else {
      const tokens = TOKENS.get(this.session.id);
      const client = CLIENTS.get(this.session.id);

      TOKENS.set(
        this.session.id,
        yield client.refresh(tokens)
      );

      this.redirect('/user');
    }


    yield next;
  });

  router.get('/cb', function * () {
    const state = this.session.state;
    delete this.session.state;
    const nonce = this.session.nonce;
    delete this.session.nonce;

    TOKENS.set(
      this.session.id,
      yield CLIENTS.get(this.session.id)
        .authorizationCallback(url.resolve(this.href, 'cb'), this.query, { nonce, state }));

    this.session.loggedIn = true;

    this.redirect('/user');
  });

  router.get('/user', function * () {
    if (!TOKENS.has(this.session.id)) {
      this.session = null;
      return this.redirect('/');
    }
    const tokens = TOKENS.get(this.session.id);
    const client = CLIENTS.get(this.session.id);

    const context = {
      tokens,
      userinfo: (yield client.userinfo(tokens).catch(() => {})),
      id_token: tokens.id_token ? _.map(tokens.id_token.split('.'), part => {
        try {
          return JSON.parse(decode(part));
        } catch (err) {
          return part;
        }
      }) : undefined,
      session: this.session,
      introspections: {},
    };

    const introspections = _.map(tokens, (value, key) => {
      if (key.endsWith('token') && key !== 'id_token') {
        return client.introspect(value).then((response) => {
          context.introspections[key] = response;
        });
      }
      return undefined;
    });

    yield Promise.all(introspections);

    return yield this.render('user', context);
  });

  app.use(router.routes());
  app.use(router.allowedMethods());

  return app;
};

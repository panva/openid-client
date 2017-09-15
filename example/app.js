'use strict';

/* eslint-disable import/no-extraneous-dependencies */

const _ = require('lodash');
const Koa = require('koa');
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
  const app = new Koa();

  if (process.env.NODE_ENV === 'production') {
    app.proxy = true;

    app.use(async (ctx, next) => {
      if (ctx.secure) {
        await next();
      } else {
        ctx.redirect(ctx.href.replace(/^http:\/\//i, 'https://'));
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

  app.use(async (ctx, next) => {
    ctx.session.id = ctx.session.id || uuid();
    await next();
  });

  app.use(async (ctx, next) => {
    try {
      await next();
    } catch (error) {
      await ctx.render('error', { issuer, error, session: ctx.session });
    }
  });

  app.use(async (ctx, next) => {
    if (!CLIENTS.has(ctx.session.id) && !ctx.path.startsWith('/setup')) {
      ctx.redirect('/setup');
    }
    await next();
  });

  const router = new Router();

  router.get('/', async (ctx, next) => {
    await ctx.render('index', { session: ctx.session, issuer });
    return next();
  });

  router.get('/rpframe', async (ctx, next) => {
    const clientId = CLIENTS.get(ctx.session.id).client_id;
    const sessionState = TOKENS.get(ctx.session.id).session_state;
    await ctx.render('rp_frame', {
      session: ctx.session, layout: false, issuer, clientId, sessionState,
    });
    return next();
  });

  router.get('/setup', async (ctx, next) => {
    await ctx.render('setup', { session: ctx.session, presets: PRESETS, issuer });
    return next();
  });

  router.post('/setup/:preset', async (ctx, next) => {
    let keystore;
    const preset = PRESETS[ctx.params.preset];
    ctx.session.loggedIn = false;

    if (preset.keystore) {
      keystore = jose.JWK.createKeyStore();
      await keystore.generate.apply(keystore, preset.keystore);
    }

    const metadata = Object.assign({
      post_logout_redirect_uris: [url.resolve(ctx.href, '/')],
      redirect_uris: [url.resolve(ctx.href, '/cb')],
    }, preset.registration);

    const client = await issuer.Client.register(metadata, keystore);
    client.CLOCK_TOLERANCE = 5;
    CLIENTS.set(ctx.session.id, client);
    ctx.session.authorization_params = preset.authorization_params;

    ctx.redirect('/client');
    return next();
  });

  router.get('/issuer', async (ctx, next) => {
    await ctx.render('issuer', {
      issuer,
      keystore: (await issuer.keystore()),
      session: ctx.session,
    });
    return next();
  });

  router.get('/client', async (ctx, next) => {
    await ctx.render('client', { client: CLIENTS.get(ctx.session.id), session: ctx.session, issuer });
    return next();
  });

  router.get('/logout', async (ctx, next) => {
    const id = ctx.session.id;
    ctx.session.loggedIn = false;

    if (!TOKENS.has(id)) {
      return ctx.redirect('/');
    }

    const tokens = TOKENS.get(id);
    TOKENS.delete(id);

    const client = CLIENTS.get(id);

    try {
      await Promise.all([
        tokens.access_token ? client.revoke(tokens.access_token, 'access_token') : undefined,
        tokens.refresh_token ? client.revoke(tokens.refresh_token, 'refresh_token') : undefined,
      ]);
    } catch (err) {}

    ctx.redirect(url.format(Object.assign(url.parse(issuer.end_session_endpoint), {
      search: null,
      query: {
        id_token_hint: tokens.id_token,
        post_logout_redirect_uri: url.resolve(ctx.href, '/'),
      },
    })));

    return next();
  });

  router.get('/login', async (ctx, next) => {
    ctx.session.state = crypto.randomBytes(16).toString('hex');
    ctx.session.nonce = crypto.randomBytes(16).toString('hex');

    const authorizationRequest = Object.assign({
      claims: {
        id_token: { email_verified: null },
        userinfo: { sub: null, email: null },
      },
      redirect_uri: url.resolve(ctx.href, 'cb'),
      scope: 'openid',
      state: ctx.session.state,
      nonce: ctx.session.nonce,
    }, ctx.session.authorization_params);

    const authz = CLIENTS.get(ctx.session.id).authorizationUrl(authorizationRequest);

    ctx.redirect(authz);
    return next();
  });

  router.get('/refresh', async (ctx, next) => {
    if (!TOKENS.has(ctx.session.id)) {
      ctx.session = null;
      ctx.redirect('/');
    } else {
      const tokens = TOKENS.get(ctx.session.id);
      const client = CLIENTS.get(ctx.session.id);

      const refreshed = await client.refresh(tokens);
      refreshed.session_state = tokens.session_state;

      TOKENS.set(ctx.session.id, refreshed);

      ctx.redirect('/user');
    }

    return next();
  });

  router.get('/cb', async (ctx, next) => {
    const state = ctx.session.state;
    delete ctx.session.state;
    const nonce = ctx.session.nonce;
    delete ctx.session.nonce;
    const client = CLIENTS.get(ctx.session.id);
    const params = client.callbackParams(ctx.request.req);

    TOKENS.set(
      ctx.session.id,
      await client.authorizationCallback(url.resolve(ctx.href, 'cb'), params, { nonce, state })
    );

    ctx.session.loggedIn = true;

    ctx.redirect('/user');

    return next();
  });

  router.post('/cb', body({ patchNode: true }), async (ctx, next) => {
    const state = ctx.session.state;
    delete ctx.session.state;
    const nonce = ctx.session.nonce;
    delete ctx.session.nonce;
    const client = CLIENTS.get(ctx.session.id);
    const params = client.callbackParams(ctx.request.req);

    TOKENS.set(
      ctx.session.id,
      await client.authorizationCallback(url.resolve(ctx.href, 'cb'), params, { nonce, state })
    );

    ctx.session.loggedIn = true;

    ctx.redirect('/user');

    return next();
  });

  function rejectionHandler(error) {
    if (error.name === 'OpenIdConnectError') {
      return error;
    }

    throw error;
  }

  router.get('/user', async (ctx, next) => {
    if (!TOKENS.has(ctx.session.id)) {
      ctx.session.loggedIn = false;
      return ctx.redirect('/client');
    }
    const tokens = TOKENS.get(ctx.session.id);
    const client = CLIENTS.get(ctx.session.id);

    const context = {
      tokens,
      userinfo: undefined,
      id_token: tokens.id_token ? tokens.claims : undefined,
      session: ctx.session,
      introspections: {},
      issuer,
    };

    const promises = [];

    _.forEach(tokens, (value, key) => {
      if (key.endsWith('token') && key !== 'id_token') {
        const p = client.introspect(value, key)
          .then((result) => {
            context.introspections[key] = result;
          })
          .catch(rejectionHandler);
        promises.push(p);
      }
      return undefined;
    });

    if (tokens.access_token) {
      const p = client.userinfo(tokens)
        .then(userinfo => client.fetchDistributedClaims(userinfo))
        .then(userinfo => client.unpackAggregatedClaims(userinfo))
        .then((result) => {
          context.userinfo = result;
        })
        .catch(rejectionHandler);
      promises.push(p);
    }

    await Promise.all(promises);
    await ctx.render('user', context);

    return next();
  });

  app.use(router.routes());
  app.use(router.allowedMethods());

  return app;
};

/* eslint-disable import/no-extraneous-dependencies */

const crypto = require('crypto');
const url = require('url');
const path = require('path');

const _ = require('lodash');
const Koa = require('koa');
const jose = require('node-jose');
const Router = require('koa-router');
const body = require('koa-body');
const session = require('koa-session');
const render = require('koa-ejs');
const LRU = require('lru-cache')();

const PRESETS = require('./presets');

const SESSION_KEY = 'rp:sess';

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
  app.use(session({
    key: SESSION_KEY,
    store: {
      get(key) {
        return LRU.get(key);
      },
      set(key, sess, maxAge) {
        LRU.set(key, sess, maxAge);
      },
      destroy(key) {
        LRU.del(key);
      },
    },
  }, app));
  app.use((ctx, next) => {
    ctx.session.save(); // save this session no matter whether it is populated
    return next();
  });

  render(app, {
    cache: true,
    layout: '_layout',
    root: path.join(__dirname, 'views'),
  });

  app.use(async (ctx, next) => {
    try {
      await next();
    } catch (error) {
      await ctx.render('error', { issuer, error, session: ctx.session });
    }
  });

  app.use(async (ctx, next) => {
    if (!ctx.session.client && !ctx.path.startsWith('/setup') && !ctx.path.endsWith('/jwks.json')) {
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
    const clientId = ctx.session.client.client_id;
    const sessionState = ctx.session.tokenset.session_state;
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
    const metadata = {};

    if (preset.keystore) {
      keystore = jose.JWK.createKeyStore();
      await keystore.generate(...preset.keystore);
      ctx.session.keystore = keystore;
      if (process.env.NODE_ENV === 'production') {
        Object.assign(metadata, {
          jwks_uri: url.resolve(ctx.href, router.url('jwks', { session_id: ctx.cookies.get(SESSION_KEY) })),
        });
      }
    } else {
      ctx.session.keystore = undefined;
    }

    Object.assign(metadata, {
      post_logout_redirect_uris: [url.resolve(ctx.href, '/')],
      redirect_uris: [url.resolve(ctx.href, '/cb')],
    }, preset.registration);

    const client = await issuer.Client.register(metadata, { keystore });
    client.CLOCK_TOLERANCE = 5;
    ctx.session.tokenset = undefined;
    ctx.session.client = client;
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
    await ctx.render('client', { client: ctx.session.client, session: ctx.session, issuer });
    return next();
  });

  router.get('/logout', async (ctx, next) => {
    const { client, tokenset: tokens } = ctx.session;

    if (tokens) {
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
    } else {
      ctx.redirect('/');
    }
    ctx.session = null;

    return next();
  });

  router.get('/login', async (ctx, next) => {
    ctx.session.state = crypto.randomBytes(16).toString('hex');
    ctx.session.nonce = crypto.randomBytes(16).toString('hex');

    const { client } = ctx.session;

    const authorizationRequest = Object.assign({
      redirect_uri: url.resolve(ctx.href, 'cb'),
      scope: 'openid profile email address phone',
      state: ctx.session.state,
      nonce: ctx.session.nonce,
      response_type: client.response_types[0],
    }, ctx.session.authorization_params);

    ctx.redirect(client.authorizationUrl(authorizationRequest));
    return next();
  });

  router.get('/refresh', async (ctx, next) => {
    if (!ctx.session.tokenset) {
      ctx.session = null;
      ctx.redirect('/');
    } else {
      const tokens = ctx.session.tokenset;
      const { client } = ctx.session;

      const refreshed = await client.refresh(tokens);
      refreshed.session_state = tokens.session_state;

      ctx.session.tokenset = refreshed;

      ctx.redirect('/user');
    }

    return next();
  });

  router.get('/cb', async (ctx, next) => {
    const { client } = ctx.session;
    const params = client.callbackParams(ctx.request.req);

    if (_.isEmpty(params)) { // probably a fragment response
      return ctx.render('repost', { layout: false });
    }

    const { state, nonce } = ctx.session;
    delete ctx.session.state;
    delete ctx.session.nonce;

    ctx.session.tokenset = await client.authorizationCallback(url.resolve(ctx.href, 'cb'), params, { nonce, state });

    ctx.redirect('/user');

    return next();
  });

  router.post('/cb', body({ patchNode: true }), async (ctx, next) => {
    const { state, nonce } = ctx.session;
    delete ctx.session.state;
    delete ctx.session.nonce;
    const { client } = ctx.session;
    const params = client.callbackParams(ctx.request.req);

    ctx.session.tokenset = await client.authorizationCallback(url.resolve(ctx.href, 'cb'), params, { nonce, state });

    ctx.redirect('/user');

    return next();
  });

  router.get('jwks', '/:session_id/jwks.json', async (ctx) => {
    const { keystore } = LRU.get(ctx.params.session_id) || {};
    if (keystore) {
      ctx.body = keystore.toJSON();
    } else {
      ctx.status = 404;
      ctx.body = {
        error: 'invalid_request',
        error_description: 'jwks for this client not found',
      };
    }
  });

  function rejectionHandler(error) {
    if (error.name === 'OpenIdConnectError') {
      return error;
    }

    throw error;
  }

  router.get('/user', async (ctx, next) => {
    const tokens = ctx.session.tokenset;
    if (!tokens) {
      return ctx.redirect('/client');
    }
    const { client } = ctx.session;

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

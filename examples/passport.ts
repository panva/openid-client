import * as client from 'openid-client'
import {
  Strategy,
  type VerifyFunction,
  type StrategyOptions,
  type AuthenticateOptions,
} from 'openid-client/passport'

import express from 'express'
import cookieParser from 'cookie-parser'
import session from 'express-session'
import passport from 'passport'
import { ensureLoggedIn, ensureLoggedOut } from 'connect-ensure-login'

// Prerequisites

let app!: express.Application
let server!: URL // Authorization server's Issuer Identifier URL
/**
 * In this example it is expected your application's origin + '/login' is
 * registered as an allowed redirect URL at the Authorization server
 */
let callbackURL!: URL
let clientId!: string // Client identifier at the Authorization Server
let clientSecret!: string // Client Secret
let scope = 'openid email'
let sessionSecret!: string // Secret to sign session cookies with

// End of prerequisites

declare global {
  namespace Express {
    interface User {
      sub: string
      email?: string
    }
  }
}

let config = await client.discovery(server, clientId, clientSecret)

app.use(cookieParser())
app.use(
  session({
    saveUninitialized: false,
    resave: true,
    secret: sessionSecret,
  }),
)
app.use(passport.authenticate('session'))

let verify: VerifyFunction = (tokens, verified) => {
  verified(null, tokens.claims())
}

let options: StrategyOptions = {
  config,
  scope,
  callbackURL,
}

passport.use('openid', new Strategy(options, verify))

passport.serializeUser((user: Express.User, cb) => {
  cb(null, user)
})

passport.deserializeUser((user: Express.User, cb) => {
  return cb(null, user)
})

app.get('/', ensureLoggedIn('/login'), (req, res) => {
  res.send(`Welcome ${req.user?.email || req.user?.sub}`)
})

app.get(
  '/login',
  ensureLoggedOut('/logout'),
  passport.authenticate('openid', {
    successRedirect: '/',
  } as AuthenticateOptions),
)

app.get('/logout', (req, res) => {
  req.logout(() => {
    res.redirect(
      client.buildEndSessionUrl(config, {
        post_logout_redirect_uri: `${req.protocol}://${req.host}`,
      }).href,
    )
  })
})

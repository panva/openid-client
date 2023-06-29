(async () => {
  const express = require('express')
  const { Issuer, Strategy: OpenIDConnectStrategy } = await import('openid-client')
  const passport = require('passport')
  const session = require('express-session')
  const https = require('node:https')
  const fs = require('node:fs')
  const app = express()
  const port = 3001

  const oidcIssuer = await Issuer.discover('https://localhost:3000')
  console.log('Discovered issuer %s %O', oidcIssuer.issuer, oidcIssuer.metadata)

  const client = new oidcIssuer.Client({
    client_id: 'oidcCLIENT',
    redirect_uris: ['https://localhost:3001/cb'],
    response_types: ['id_token'],
    // id_token_signed_response_alg (default "RS256")
  }) // => Client

  passport.use(new OpenIDConnectStrategy({
      client,
      params: { response_mode: 'form_post' }
    },
    function(tokenset, done) {
      return done(null, tokenset.claims())
    }
  ))

  app.use(express.urlencoded({ extended: false }))
  app.use(session({
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: true }
  }))
  app.use(passport.initialize())
  app.use(passport.session())

  passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, {
        email: user.sub
      })
    })
  })
  
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user)
    })
  })

  app.get('/', (req, res) => {
    res.send('Hello World!')
  })

  app.get('/login', passport.authenticate('localhost'))

  app.post('/cb',
    passport.authenticate('localhost', { failureRedirect: '/login', failureMessage: true }),
    function(req, res) {
      res.redirect('/')
    })

  // app.listen(port, () => {
  //   console.log(`Example app listening on port ${port}`)
  // })
  const options = {
    key: fs.readFileSync('localhost-key.pem'),
    cert: fs.readFileSync('localhost.pem'),
  }
  server = https.createServer(options, app)
  server.listen(port)
})()

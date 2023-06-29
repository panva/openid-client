(async () => {
  const express = require('express')
  const { Issuer, Strategy: OpenIDConnectStrategy } = await import('openid-client')
  const passport = require('passport')
  const app = express()
  const port = 3001

  const oidcIssuer = await Issuer.discover('http://localhost:3000')
  console.log('Discovered issuer %s %O', oidcIssuer.issuer, oidcIssuer.metadata)

  const client = new oidcIssuer.Client({
    client_id: 'oidcCLIENT',
    redirect_uris: ['http://localhost:3001/cb'],
    response_types: ['id_token'],
    // id_token_signed_response_alg (default "RS256")
  }) // => Client

  passport.use(new OpenIDConnectStrategy({
      client
    },
    function(tokenset, done) {
      return done(null, tokenset.claims())
    }
  ))

  app.get('/', (req, res) => {
    res.send('Hello World!')
  })

  app.get('/login', passport.authenticate('localhost'))

  app.get('/cb',
    passport.authenticate('localhost', { failureRedirect: '/login', failureMessage: true }),
    function(req, res) {
      res.redirect('/')
    })

  app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
  })
})()

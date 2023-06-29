(async () => {
  const express = require('express')
  const { Issuer } = await import('openid-client')
  const app = express()
  const port = 3001

  const oidcIssuer = await Issuer.discover('http://localhost:3000')
  console.log('Discovered issuer %s %O', oidcIssuer.issuer, oidcIssuer.metadata)

  app.get('/', (req, res) => {
    res.send('Hello World!')
  })

  app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
  })
})()

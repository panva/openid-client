'use strict';

const Issuer = require('..').Issuer;

const ISSUER = process.env.ISSUER || 'https://guarded-cliffs-8635.herokuapp.com';
const port = process.env.PORT || 3001;

const appFactory = require('./app');

Issuer.discover(ISSUER).then((issuer) => {
  const app = appFactory(issuer);
  app.listen(port);
}).catch(() => process.exit(1));

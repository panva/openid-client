'use strict';

const { Issuer } = require('..');

const {
  ISSUER = 'https://guarded-cliffs-8635.herokuapp.com',
  PORT = 3001,
} = process.env;

const appFactory = require('./app');

Issuer.discover(ISSUER).then((issuer) => {
  const app = appFactory(issuer);
  app.listen(PORT);
}).catch((err) => {
  console.error(err); // eslint-disable-line no-console
  process.exit(1);
});

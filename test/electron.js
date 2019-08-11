/* eslint-disable */

const { app } = require('electron');

const { Base } = require('mocha/lib/reporters');

const orig = Base.prototype.epilogue;

Base.prototype.epilogue = function epilogue() {
  orig.call(this);
  const { stats: { failures } } = this;

  app.exit(failures ? 1 : 0);
}

require('../node_modules/.bin/mocha');

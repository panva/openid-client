/* eslint-disable */

const { app } = require('electron');

const { Base } = require('mocha/lib/reporters');

const orig = Base.prototype.epilogue;

Base.prototype.epilogue = function epilogue() {
  orig.call(this);
  const { stats: { failures, passes } } = this;

  app.exit(failures || passes === 0 ? 1 : 0);
}

require('mocha/bin/mocha');

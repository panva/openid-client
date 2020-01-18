const url = require('url');
const { strict: assert } = require('assert');

module.exports = (target) => {
  try {
    const { protocol } = new url.URL(target);
    assert(protocol.match(/^(https?:)$/));
    return true;
  } catch (err) {
    throw new TypeError('only valid absolute URLs can be requested');
  }
};

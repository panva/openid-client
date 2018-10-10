const got = require('got');

const httpClient = (issuer) => {
  /*
 * url {String}
 * options {Object}
 * options.headers {Object}
 * options.body {String|Object}
 * options.form {Boolean}
 * options.query {Object}
 * options.timeout {Number}
 * options.retries {Number}
 * options.followRedirect {Boolean}
 */
  const get = function get(url, options) {
    issuer.logger({ message: 'SSO OpenId Client GET', url, options });
    return got.get(url, options);
  };

  const post = function post(url, options) {
    issuer.logger({ message: 'SSO OpenId Client POST', url, options });
    return got.post(url, options);
  };

  return {
    HTTPError: got.HTTPError,
    get,
    post,
  };
};
module.exports = httpClient;

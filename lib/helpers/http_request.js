const http = require('http');

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

class HTTPError extends Error {
  constructor(response) {
    const statusMessage = http.STATUS_CODES[response.statusCode];
    super(`Response code ${response.statusCode} (${statusMessage})`, {});
    this.name = 'HTTPError';
    this.statusCode = response.statusCode;
    this.statusMessage = statusMessage;
    this.headers = response.headers;
    this.response = response;
  }
}

module.exports = function requestWrapper() {
  const request = require('request'); // eslint-disable-line import/no-extraneous-dependencies, global-require

  function requestWrap(method, url, options) {
    if (options.form) {
      options.form = options.body;
      options.body = undefined;
    }
    return new Promise((resolve, reject) => {
      request({
        method,
        url,
        headers: options.headers,
        qs: options.query,
        body: options.body,
        form: options.form,
        followRedirect: options.followRedirect,
        timeout: options.timeout,
      }, (error, response, body) => {
        if (error) {
          reject(error);
        } else {
          response.body = body;
          const { statusCode } = response;
          const limitStatusCode = options.followRedirect ? 299 : 399;

          if (statusCode !== 304 && (statusCode < 200 || statusCode > limitStatusCode)) {
            reject(new HTTPError(response));
            return;
          }

          resolve(response);
        }
      });
    });
  }

  return {
    HTTPError,
    get(url, options) {
      return requestWrap('GET', url, options);
    },
    post(url, options) {
      return requestWrap('POST', url, options);
    },
  };
};

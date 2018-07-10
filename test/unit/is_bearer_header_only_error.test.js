const { expect } = require('chai');

const checkIfBearerHeaderOnlyError = require('../../lib/helpers/is_bearer_header_only_error');

describe('isBearerHeaderOnlyError', function () {
  it('ignores the header when scheme is not Bearer', function () {
    const err = new Error('foo');
    err.response = {
      headers: {
        'www-authenticate': 'Basic realm="foo"',
      },
    };

    expect(checkIfBearerHeaderOnlyError.call({
      httpClient: {
        HTTPError: Error,
      },
    }, err)).to.eql([false]);
  });
});

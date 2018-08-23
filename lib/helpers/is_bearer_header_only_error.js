const REGEXP = /(\w+)=("[^"]*")/g;
const NOPE = [false];

module.exports = function isBearerHeaderOnlyError(error) {
  if (error instanceof this.httpClient.HTTPError) {
    try {
      const body = {};
      if (!error.response.headers['www-authenticate'].startsWith('Bearer ')) {
        return NOPE;
      }

      while ((REGEXP.exec(error.response.headers['www-authenticate'])) !== null) {
        if (RegExp.$1 && RegExp.$2) {
          body[RegExp.$1] = RegExp.$2.slice(1, -1);
        }
      }

      return [!!body.error, body];
    } catch (err) {}
  }

  return NOPE;
};

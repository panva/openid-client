module.exports = function isStandardBodyError(error) {
  if (error instanceof this.httpClient.HTTPError) {
    try {
      error.response.body = JSON.parse(error.response.body);
      return typeof error.response.body.error === 'string' && error.response.body.error.length;
    } catch (err) {}
  }

  return false;
};

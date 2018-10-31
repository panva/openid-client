module.exports = function pick(object, ...paths) {
  const obj = {};
  for (const path of paths) { // eslint-disable-line no-restricted-syntax
    if (object[path]) {
      obj[path] = object[path];
    }
  }
  return obj;
};

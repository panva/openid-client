module.exports = (object, callback) => {
  Object.keys(object).forEach((key) => {
    callback(object[key], key, object);
  });
};

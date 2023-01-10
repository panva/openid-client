const { serialize, deserialize } = require('node:v8');

module.exports = globalThis.structuredClone || ((obj) => deserialize(serialize(obj)));

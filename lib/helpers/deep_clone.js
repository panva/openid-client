const { serialize, deserialize } = require('v8');

module.exports = globalThis.structuredClone || ((obj) => deserialize(serialize(obj)));

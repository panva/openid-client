module.exports = globalThis.structuredClone || JSON.parse(JSON.stringify(obj));

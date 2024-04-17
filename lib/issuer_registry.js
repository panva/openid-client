const LRU = require('lru-cache');

module.exports = new LRU.LRUCache({ max: 100 });

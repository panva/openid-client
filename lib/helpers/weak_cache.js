const privateProps = new WeakMap();

module.exports = (ctx) => {
  if (!privateProps.has(ctx)) {
    privateProps.set(ctx, new Map([['metadata', new Map()]]));
  }
  return privateProps.get(ctx);
};

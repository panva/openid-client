export default {
  extensions: {
    ts: 'module',
    mjs: true,
  },
  files: ['test/**/*.ts'],
  workerThreads: false,
  nodeArguments: ['--enable-source-maps'],
}

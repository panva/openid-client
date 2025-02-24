const { execSync } = require('child_process')
const { readFileSync, writeFileSync } = require('fs')
const { version, dependencies } = require('./package.json')

const updates = [
  [
    './src/index.ts',
    /const VERSION = 'v\d+\.\d+\.\d+'/gm,
    `const VERSION = 'v${version}'`,
  ],
  [
    './build/index.js',
    /const VERSION = 'v\d+\.\d+\.\d+'/gm,
    `const VERSION = 'v${version}'`,
    false,
  ],
]

for (const [path, regex, replace, gitAdd = true] of updates) {
  writeFileSync(
    path,
    readFileSync(path, { encoding: 'utf-8' }).replace(regex, replace),
  )
  if (gitAdd) execSync(`git add ${path}`, { stdio: 'inherit' })
}

const jsr = require('./jsr.json')
jsr.imports = {}
jsr.version = version

for (const [dependency, semver] of Object.entries(dependencies)) {
  switch (dependency) {
    case 'jose':
    case 'oauth4webapi':
      jsr.imports[dependency] = `jsr:@panva/${dependency}@${semver}`
      break
    default:
      throw new Error('unhandled jsr dependency')
  }
}
writeFileSync('./jsr.json', JSON.stringify(jsr, null, 4) + '\n')
execSync(`git add ./jsr.json`, { stdio: 'inherit' })

execSync('git add build/* -f', { stdio: 'inherit' })

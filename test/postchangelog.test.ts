import { createRequire } from 'node:module'

import test from 'ava'

const require = createRequire(import.meta.url)
const { formatChangelog } = require('../.postchangelog.cjs') as {
  formatChangelog(changelog: string): string
}

test('postchangelog separates second-level headings', (t) => {
  for (const newline of ['\n', '\r\n']) {
    const input = [
      '# Changelog',
      '',
      '### [2.0.0](new)',
      '',
      '### Fixes',
      '',
      '* fix',
      '## [1.0.0](old)',
      '',
      'details',
      '## Notes',
    ].join(newline)
    const expected = [
      '# Changelog',
      '',
      '## [2.0.0](new)',
      '',
      '### Fixes',
      '',
      '* fix',
      '',
      '## [1.0.0](old)',
      '',
      'details',
      '',
      '## Notes',
    ].join(newline)

    t.is(formatChangelog(input), expected)
    t.is(formatChangelog(expected), expected)
  }
})

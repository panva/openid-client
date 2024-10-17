import { rejects } from './run.js'

rejects(
  import.meta.url,
  { code: 'OAUTH_JWT_CLAIM_COMPARISON_FAILED' },
  { message: /"s_hash"/ },
  { useState: true },
)

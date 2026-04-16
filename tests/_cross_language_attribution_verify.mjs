// Read JSON {primitive, publicKey} from stdin and verify via TS SDK.
// Called from tests/test_attribution_primitive.py::test_cross_language_python_to_ts.

import {
  verifyAttributionPrimitive,
} from '../../agent-passport-system/src/index.js'

let raw = ''
process.stdin.setEncoding('utf8')
process.stdin.on('data', (chunk) => { raw += chunk })
process.stdin.on('end', () => {
  try {
    const { primitive, publicKey } = JSON.parse(raw)
    const res = verifyAttributionPrimitive(primitive, publicKey)
    if (res.valid) {
      process.stdout.write('VALID')
    } else {
      process.stdout.write(`INVALID:${res.reason || 'unknown'}`)
    }
  } catch (e) {
    process.stdout.write(`ERROR:${e?.message || String(e)}`)
    process.exit(1)
  }
})

// 1.0.2: the other common encodings, and --deep for a secret split into pieces.
// The values here are made up and match no provider's key shape.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { scanText, mask } from '../src/index.js'
import { forms, pieces } from '../src/scan.js'

const value = 'tok_a1B2c3D4e5F6g7H8i9J0k1L2m3/x+y'
const secrets = [{ name: 'API_TOKEN', value, source: '.env' }]

test('hex, URL-encoded and escaped forms are found and named, the report masks the real value', () => {
  const hex = Buffer.from(value).toString('hex')
  const lines = [
    `a="${hex}"`,
    `b="${hex.toUpperCase()}"`,
    `c="${encodeURIComponent(value)}"`,
    `d="${value.split('/').join('\\/')}"`,
    `e="${value.split('/').join('\\u002f')}"`,
  ]
  const found = scanText(lines.join('\n'), secrets)
  assert.deepEqual(found.map((f) => `${f.line} ${f.what}`).sort(), [
    '1 API_TOKEN from .env, hex',
    '2 API_TOKEN from .env, hex',
    '3 API_TOKEN from .env, URL-encoded',
    '4 API_TOKEN from .env, escaped',
    '5 API_TOKEN from .env, escaped',
  ])
  assert.ok(found.every((f) => f.sample === mask(value)))
  assert.ok(forms('no-slash-or-symbols-here').every((f) => !f.how.includes('escaped')), 'escaped forms only when there is a "/"')
})

test('--deep: a secret split into pieces is found, but only with --deep and only from two pieces', () => {
  const split = `var k=["${value.slice(0, 22)}","${value.slice(22)}"].join("")`
  assert.equal(scanText(split, secrets).length, 0, 'off by default')
  const deep = scanText(split, secrets, { deep: true })
  assert.equal(deep.length, 1)
  assert.equal(deep[0].kind, 'pieces')
  // The split at 22 cuts through the third piece, so two of three are found, which is enough.
  assert.match(deep[0].what, /^API_TOKEN from \.env, in pieces \(2 of 3 found\)$/)

  // One piece alone is not enough, and a whole match is reported once, as the value.
  assert.equal(scanText(`var k="${value.slice(0, 12)}"`, secrets, { deep: true }).length, 0)
  const whole = scanText(`var k="${value}"`, secrets, { deep: true })
  assert.deepEqual(whole.map((f) => f.kind), ['value'])
})

test('--deep never uses a common start or a short value as a piece', () => {
  assert.deepEqual(pieces('short-value-123'), [])
  // "https://ap" and "i.example." have no digit, so only random-looking pieces count.
  assert.ok(pieces('https://api.example.com/v1?key=Zq81Lm03Xa77Bc').every((p) => /\d/.test(p) && /[A-Za-z]/.test(p)))
  // A bundle full of other random strings does not set it off.
  const noise = Array.from({ length: 200 }, (_, i) => `"${(i * 7919).toString(36)}Xq${i}Zr${i * 31}"`).join(',')
  assert.equal(scanText(noise, secrets, { deep: true }).length, 0)
})

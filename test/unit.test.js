// Fake keys are built at run time, so nothing secret-shaped is ever committed.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { randomBytes } from 'node:crypto'
import { findShapes, loadSecrets, mask, parseDotenv, riskyNames, scanProject, scanText } from '../src/index.js'

const rnd = (n) => randomBytes(n).toString('base64').replace(/[^A-Za-z0-9]/g, 'x').slice(0, n)
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url')
const jwt = (role) => `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64({ iss: 'supabase', role, ref: 'abcdefgh' })}.${rnd(43)}`
export const fake = {
  stripe: 'sk_' + 'test_' + rnd(30),
  stripePublishable: 'pk_' + 'test_' + rnd(30),
  serviceRole: jwt('service_role'),
  anon: jwt('anon'),
  openai: 'sk-' + 'proj-' + rnd(48),
  anthropic: 'sk-' + 'ant-api03-' + rnd(80),
  aws: 'AKIA' + rnd(16).toUpperCase().replace(/[^A-Z0-9]/g, 'Q'),
  github: 'ghp' + '_' + rnd(36),
  google: 'AIza' + rnd(35),
  db: 'postgres' + '://app:' + rnd(16) + '@db.example.com:5432/main',
}

test('parses dotenv: quotes, export, comments and shipped-ok', () => {
  const vars = parseDotenv('# comment\nexport A="x y"\nB=\'z\'\nC=plain # note\nVITE_D=pub # shipped-ok\n')
  assert.deepEqual(vars.map((v) => [v.name, v.value, v.ok]), [['A', 'x y', false], ['B', 'z', false], ['C', 'plain', false], ['VITE_D', 'pub', true]])
})

test('only server values are secrets: public names, shared values, short values and safe names are left out', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ss-'))
  writeFileSync(join(dir, '.env'), [
    `STRIPE_SECRET_KEY=${fake.stripe}`,
    `VITE_STRIPE_PUBLISHABLE_KEY=${fake.stripePublishable}`,
    `SUPABASE_URL=https://abcdefgh.supabase.co`,
    `VITE_SUPABASE_URL=https://abcdefgh.supabase.co`,
    `SUPABASE_ANON_KEY=${fake.anon}`,
    `VITE_SUPABASE_ANON_KEY=${fake.anon}`,
    `PORT=3000`,
    `DATABASE_URL=${fake.db}`,
  ].join('\n'))
  writeFileSync(join(dir, '.env.example'), `STRIPE_SECRET_KEY=${'sk_' + 'test_' + 'replace-me-with-yours-000'}`)
  const { secrets } = loadSecrets(dir, { env: { PATH: '/usr/bin:/bin:/usr/local/bin', CI_DEPLOY_TOKEN: 'ci-' + rnd(30), NODE_ENV: 'production' } })
  assert.deepEqual(secrets.map((s) => s.name).sort(), ['CI_DEPLOY_TOKEN', 'DATABASE_URL', 'STRIPE_SECRET_KEY'])
})

test('risky names: a public prefix on a secret-sounding name, unless it is a known public key or marked shipped-ok', () => {
  const all = parseDotenv('VITE_STRIPE_SECRET=x\nNEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=x\nVITE_SUPABASE_ANON_KEY=x\nNEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=x\nVITE_PADDLE_CLIENT_TOKEN=x\nEXPO_PUBLIC_API_TOKEN=x # shipped-ok\nPUBLIC_DATABASE_URL=x\n')
  assert.deepEqual(riskyNames(all).map((v) => v.name), ['VITE_STRIPE_SECRET', 'NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY', 'PUBLIC_DATABASE_URL'])
})

test('key shapes: every server key is found, publishable and anon keys are not', () => {
  const text = Object.values(fake).join('\n')
  const ids = findShapes(text).map((f) => f.shape.id).sort()
  assert.deepEqual(ids, ['anthropic', 'aws-access-key', 'database-url', 'github-token', 'google-api-key', 'openai', 'stripe-secret', 'supabase-service-role'])
})

test('a Supabase anon key is never reported, a service_role key always is', () => {
  assert.equal(findShapes(fake.anon).length, 0)
  assert.equal(findShapes(fake.serviceRole)[0].shape.id, 'supabase-service-role')
})

test('secrets are masked in output', () => {
  const m = mask(fake.stripe)
  assert.ok(!m.includes(fake.stripe.slice(4, -2)) && m.startsWith('sk_t') && m.includes('chars'))
})

test('a value found by name is not reported again as a shape', () => {
  const found = scanText(`const k="${fake.stripe}"`, [{ name: 'STRIPE_SECRET_KEY', value: fake.stripe, source: '.env' }])
  assert.equal(found.length, 1)
  assert.equal(found[0].kind, 'value')
})

test('a project scan reads browser output, skips server output, reads Next.js prerendered pages and flags source maps', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ss-'))
  writeFileSync(join(dir, '.env'), `STRIPE_SECRET_KEY=${fake.stripe}\nVITE_STRIPE_SECRET=${fake.stripe}\n`)
  mkdirSync(join(dir, '.next/static/chunks'), { recursive: true })
  mkdirSync(join(dir, '.next/server/app'), { recursive: true })
  writeFileSync(join(dir, '.next/static/chunks/main.js'), `var a=1;\nvar k="${fake.stripe}";`)
  writeFileSync(join(dir, '.next/static/chunks/main.js.map'), '{"version":3}')
  writeFileSync(join(dir, '.next/server/app/page.js'), `const server="${fake.stripe}"`) // server code: never shipped
  writeFileSync(join(dir, '.next/server/app/index.html'), `<p>${fake.serviceRole}</p>`) // prerendered page: shipped
  const r = scanProject(dir, { env: {} })
  const sum = r.findings.map((f) => `${f.level} ${f.kind} ${f.file.replace(/\\/g, '/')}${f.line ? ':' + f.line : ''}`).sort()
  assert.deepEqual(sum, [
    'error shape .next/server/app/index.html:1',
    'error value .next/static/chunks/main.js:2',
    'warn name .env:2',
    'warn sourcemap .next/static',
  ])
})

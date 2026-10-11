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
  // --verify needs the full key on each finding, hidden from JSON.
  const shaped = r.findings.find((f) => f.kind === 'shape')
  assert.ok(shaped.shapeId === 'supabase-service-role' && typeof shaped.key === 'string' && !JSON.stringify(r).includes(shaped.key))
})

test('git history: a key committed then deleted is found, so is a server secret in any .env ever committed, a public build switch and .env.example are not', async () => {
  const { execFileSync } = await import('node:child_process')
  const { rmSync } = await import('node:fs')
  const { scanHistory } = await import('../src/index.js')
  const dir = mkdtempSync(join(tmpdir(), 'ss-git-'))
  const git = (...a) => execFileSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.com', '-c', 'commit.gpgsign=false', '-c', 'core.autocrlf=false', ...a], { cwd: dir, stdio: 'pipe' })
  git('init', '-q')
  writeFileSync(join(dir, '.env'), `VITE_EDITION=web\nGITHUB_TOKEN=${fake.github}\n`)
  writeFileSync(join(dir, '.env.example'), 'STRIPE_SECRET_KEY=\n')
  writeFileSync(join(dir, 'config.js'), `export const stripe = "${fake.stripe}"\n`)
  git('add', '-A')
  git('commit', '-qm', 'first')
  rmSync(join(dir, '.env'))
  writeFileSync(join(dir, 'config.js'), 'export const stripe = process.env.STRIPE_SECRET_KEY\n')
  git('add', '-A')
  git('commit', '-qm', 'remove the keys')
  // Today the key lives only in an ignored .env.local, as it should.
  writeFileSync(join(dir, '.gitignore'), '.env.local\n')
  writeFileSync(join(dir, '.env.local'), `STRIPE_SECRET_KEY=${fake.stripe}\n`)
  const { secrets } = loadSecrets(dir, { env: {} })
  const r = await scanHistory(dir, secrets)
  assert.equal(r.commits, 2)
  const sum = r.findings.map((f) => `${f.kind} ${f.file}${f.line ? ':' + f.line : ''}`).sort()
  assert.deepEqual(sum, ['history-env .env:2', 'history-value config.js:1'])
  assert.ok(r.findings.every((f) => f.commit && f.date))
  assert.ok(!JSON.stringify(r).includes(fake.stripe) && !JSON.stringify(r).includes(fake.github), 'full keys never in JSON')
  assert.equal(await scanHistory(mkdtempSync(join(tmpdir(), 'ss-nogit-'))), null)
})

test('verify: asks only the key\'s own provider, live on 200, dead on 401, unknown when it cannot ask', async () => {
  const { verifyFindings } = await import('../src/index.js')
  const asked = []
  const fetch = async (url, init) => {
    asked.push(new URL(url).host)
    if (url.includes('stripe')) return new Response('{}', { status: 200 })
    if (url.includes('github')) return new Response('{}', { status: 401 })
    if (url.includes('abcdefgh.supabase.co')) return new Response('{}', { status: 200 })
    throw new Error('offline')
  }
  const text = [fake.stripe, fake.github, fake.openai, fake.aws, fake.serviceRole].join('\n')
  const findings = scanText(text, [])
  await verifyFindings(findings, fetch)
  const by = Object.fromEntries(findings.map((f) => [f.shapeId, f.verified]))
  assert.deepEqual(by, { 'stripe-secret': 'live', 'github-token': 'dead', openai: 'unknown', 'aws-access-key': 'unknown', 'supabase-service-role': 'live' })
  assert.deepEqual(asked.sort(), ['abcdefgh.supabase.co', 'api.github.com', 'api.openai.com', 'api.stripe.com'])
  const { report } = await import('../src/index.js')
  const out = report({ findings, files: 1, verified: true })
  assert.ok(out.includes('LIVE, rotate now') && out.includes('2 keys still work'))
  assert.ok(!out.includes(fake.stripe) && !JSON.stringify(findings).includes(fake.stripe))
})

test('base64: a secret put through btoa or base64url on its way into the bundle is still found, and named as such', async () => {
  const { forms } = await import('../src/scan.js')
  // ">>>" and "???" encode to "Pj4+" and "Pz8/", so both the + and / of standard base64 appear.
  const value = 'tok_' + rnd(20) + '>>>???'
  const secrets = [{ name: 'API_TOKEN', value, source: '.env' }]
  const b64 = Buffer.from(value).toString('base64')
  const url = Buffer.from(value).toString('base64url')
  assert.ok(b64.includes('+') && b64.includes('/'), 'the test value must exercise + and /')
  assert.deepEqual(forms(value).map((f) => f.how).slice(0, 3), ['', ', base64', ', base64url'])
  const found = scanText(`var a="${b64}";\nvar b="${url}";\nvar c="${b64.replace(/=+$/, '')}x"`, secrets)
  assert.deepEqual(found.map((f) => `${f.line} ${f.what}`), ['1 API_TOKEN from .env, base64', '3 API_TOKEN from .env, base64', '2 API_TOKEN from .env, base64url'])
  assert.ok(found.every((f) => f.sample === mask(value)), 'the report masks the real value, not the encoded one')
  assert.equal(scanText(`var a="${Buffer.from('something else entirely').toString('base64')}"`, secrets).length, 0)
})

test('base64 in git history: a key committed in base64 form is found', async () => {
  const { execFileSync } = await import('node:child_process')
  const { scanHistory } = await import('../src/index.js')
  const dir = mkdtempSync(join(tmpdir(), 'ss-git64-'))
  const git = (...a) => execFileSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.com', '-c', 'commit.gpgsign=false', '-c', 'core.autocrlf=false', ...a], { cwd: dir, stdio: 'pipe' })
  const value = 'tok_' + rnd(26)
  git('init', '-q')
  writeFileSync(join(dir, 'config.js'), `export const t = atob("${Buffer.from(value).toString('base64')}")\n`)
  git('add', '-A')
  git('commit', '-qm', 'hide it, badly')
  const r = await scanHistory(dir, [{ name: 'API_TOKEN', value, source: '.env' }])
  assert.equal(r.findings.length, 1)
  assert.match(r.findings[0].what, /^API_TOKEN \(base64\) was committed in config\.js/)
})

// Builds a real Vite app and a real Next.js app with planted fake keys, then checks
// that shipped-secrets finds exactly the ones that ship and nothing that stays on the
// server. Also scans the Vite build by URL, and builds once with the Vite plugin.
// Needs network the first time (npm install). Run: npm run test:apps
import { execSync } from 'node:child_process'
import { mkdirSync, rmSync, writeFileSync, existsSync, readFileSync } from 'node:fs'
import { createServer } from 'node:http'
import { tmpdir } from 'node:os'
import { join, extname } from 'node:path'
import { randomBytes } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { scanProject, scanUrl, loadSecrets } from '../../src/index.js'

const here = fileURLToPath(new URL('.', import.meta.url))
const pkgRoot = join(here, '..', '..')
const work = join(tmpdir(), 'shipped-secrets-apps')
mkdirSync(work, { recursive: true })

const rnd = (n) => randomBytes(n).toString('base64').replace(/[^A-Za-z0-9]/g, 'x').slice(0, n)
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url')
const jwt = (role) => `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64({ iss: 'supabase', role, ref: 'abcdefgh' })}.${rnd(43)}`
const sh = (cmd, cwd) => execSync(cmd, { cwd, stdio: ['ignore', 'pipe', 'pipe'], encoding: 'utf8' })

let fails = 0
const check = (ok, msg) => {
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${msg}`)
  if (!ok) fails++
}
const summary = (r) => r.findings.map((f) => `${f.level} ${f.kind}${f.what ? ' ' + f.what.split(' ')[0] : ''}`)

// ---------- Vite ----------
{
  const app = join(work, 'vite-app')
  const stripe = 'sk_' + 'test_' + rnd(30)
  const anon = jwt('anon')
  const serverOnly = 'srv_' + rnd(40)
  const pasted = 'sk-' + 'proj-' + rnd(48) // pasted straight into the code, the way keys end up in source maps
  mkdirSync(join(app, 'src'), { recursive: true })
  if (!existsSync(join(app, 'node_modules/vite'))) {
    writeFileSync(join(app, 'package.json'), JSON.stringify({ name: 'vite-app', private: true, type: 'module' }))
    sh('npm install --no-audit --no-fund vite@7', app)
  }
  writeFileSync(join(app, '.env'), [
    `VITE_STRIPE_SECRET=${stripe}`, // the classic slip: a server key with the public prefix
    `VITE_SUPABASE_ANON_KEY=${anon}`, // meant for browsers
    `VITE_SUPABASE_URL=https://abcdefgh.supabase.co`,
    `PAYMENTS_TOKEN=${serverOnly}`, // server only, never used in browser code
  ].join('\n'))
  writeFileSync(join(app, 'index.html'), '<!doctype html><html><body><div id="app"></div><script type="module" src="/src/main.js"></script></body></html>')
  writeFileSync(join(app, 'src/main.js'), `document.getElementById('app').textContent = [import.meta.env.VITE_STRIPE_SECRET, import.meta.env.VITE_SUPABASE_ANON_KEY, import.meta.env.VITE_SUPABASE_URL].join(' ')\nconst later = () => import('./later.js')\nlater()\n`)
  writeFileSync(join(app, 'src/later.js'), `// TODO move to the server\nexport const x = ${JSON.stringify(pasted)}\n`)
  writeFileSync(join(app, 'vite.config.js'), "export default { build: { sourcemap: true } }\n")
  rmSync(join(app, 'dist'), { recursive: true, force: true })
  sh('npx vite build', app)

  const r = scanProject(app, { env: {} })
  const s = summary(r)
  if (process.env.DEBUG_APPS) for (const f of r.findings) console.log('   ', f.level, f.kind, f.file, f.line, f.what.slice(0, 40))
  check(s.some((x) => x.startsWith('error value VITE_STRIPE_SECRET')), 'Vite: the Stripe key behind VITE_ is found in the bundle by its real value')
  check(s.filter((x) => x.startsWith('error')).length >= 1 && !r.findings.some((f) => f.level === 'error' && f.kind === 'shape' && /Supabase/.test(f.what)), 'Vite: the Supabase anon key is not reported')
  check(r.findings.some((f) => f.kind === 'name' && f.what.startsWith('VITE_STRIPE_SECRET')), 'Vite: VITE_STRIPE_SECRET is flagged as a risky name')
  check(!r.findings.some((f) => /PAYMENTS_TOKEN/.test(f.what)), 'Vite: the server-only token is not reported (it never shipped)')
  check(r.findings.some((f) => f.kind === 'sourcemap'), 'Vite: shipped source maps are flagged')
  check(r.findings.some((f) => f.kind === 'shape' && /OpenAI/.test(f.what) && f.file.endsWith('.map')), 'Vite: a key pasted into the code is found inside the source map too')

  // The same build, scanned by URL like a stranger would.
  const dist = join(app, 'dist')
  const types = { '.html': 'text/html', '.js': 'text/javascript', '.map': 'application/json', '.css': 'text/css' }
  const server = createServer((req, res) => {
    const path = join(dist, req.url === '/' ? 'index.html' : decodeURIComponent(req.url.split('?')[0]))
    if (!path.startsWith(dist) || !existsSync(path)) return res.writeHead(404).end()
    res.writeHead(200, { 'content-type': types[extname(path)] ?? 'application/octet-stream' }).end(readFileSync(path))
  })
  await new Promise((ok) => server.listen(0, ok))
  const url = `http://127.0.0.1:${server.address().port}/`
  const byUrlWithValues = await scanUrl(url, loadSecrets(app, { env: {} }).secrets)
  const byUrlShapesOnly = await scanUrl(url, [])
  server.close()
  check(byUrlWithValues.findings.some((f) => f.kind === 'value'), `URL scan with local .env values: the key is found on the live site (${byUrlWithValues.files} files fetched)`)
  check(byUrlShapesOnly.findings.some((f) => f.kind === 'shape' && /Stripe/.test(f.what)), 'URL scan with no local values: the key is still found by its shape')
  check(byUrlShapesOnly.findings.some((f) => f.kind === 'sourcemap'), 'URL scan: downloadable source maps are flagged')

  // The Vite plugin must stop the build.
  writeFileSync(join(app, 'vite.config.js'), `import shippedSecrets from ${JSON.stringify(join(pkgRoot, 'src/vite.js').replace(/\\/g, '/'))}\nexport default { build: { sourcemap: true }, plugins: [shippedSecrets()] }\n`)
  let stopped = false
  try {
    sh('npx vite build', app)
  } catch (e) {
    stopped = /shipped-secrets stopped the build/.test(String(e.stdout) + String(e.stderr))
  }
  check(stopped, 'Vite plugin: the build fails with the report')

  // With the slip fixed (no secret behind VITE_), the plugin lets it through.
  writeFileSync(join(app, '.env'), [`VITE_SUPABASE_ANON_KEY=${anon}`, `VITE_SUPABASE_URL=https://abcdefgh.supabase.co`, `PAYMENTS_TOKEN=${serverOnly}`].join('\n'))
  writeFileSync(join(app, 'src/main.js'), `document.getElementById('app').textContent = [import.meta.env.VITE_SUPABASE_ANON_KEY, import.meta.env.VITE_SUPABASE_URL].join(' ')\n`)
  writeFileSync(join(app, 'vite.config.js'), `import shippedSecrets from ${JSON.stringify(join(pkgRoot, 'src/vite.js').replace(/\\/g, '/'))}\nexport default { plugins: [shippedSecrets()] }\n`)
  let passed = true
  try {
    sh('npx vite build', app)
  } catch {
    passed = false
  }
  check(passed, 'Vite plugin: a clean build passes')
}

// ---------- Next.js ----------
{
  const app = join(work, 'next-app')
  const serviceRole = jwt('service_role')
  const anon = jwt('anon')
  const serverSecret = 'srv_' + rnd(40)
  const printed = 'sk_' + 'test_' + rnd(30)
  mkdirSync(join(app, 'app'), { recursive: true })
  if (!existsSync(join(app, 'node_modules/next'))) {
    writeFileSync(join(app, 'package.json'), JSON.stringify({ name: 'next-app', private: true }))
    sh('npm install --no-audit --no-fund next@15 react@19 react-dom@19', app)
  }
  writeFileSync(join(app, '.env.local'), [
    `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=${serviceRole}`, // the classic: service key with the public prefix
    `NEXT_PUBLIC_SUPABASE_ANON_KEY=${anon}`,
    `INTERNAL_API_SECRET=${serverSecret}`, // used on the server only
    `STRIPE_SECRET_KEY=${printed}`, // printed into a page by a server component: ships in the HTML
  ].join('\n'))
  writeFileSync(join(app, 'next.config.mjs'), 'export default {}\n')
  writeFileSync(join(app, 'app/layout.js'), 'export default function Layout({ children }) { return <html><body>{children}</body></html> }\n')
  writeFileSync(join(app, 'app/client.js'), "'use client'\nexport default function Client() { return <p>{process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY} {process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY}</p> }\n")
  writeFileSync(join(app, 'app/page.js'), "import Client from './client'\nexport default function Page() { const ok = process.env.INTERNAL_API_SECRET ? 'yes' : 'no'; return <main><p>{ok}</p><p>{process.env.STRIPE_SECRET_KEY}</p><Client /></main> }\n")
  rmSync(join(app, '.next'), { recursive: true, force: true })
  sh('npx next build', app)

  const r = scanProject(app, { env: {} })
  check(r.dirs.some((d) => d.replace(/\\/g, '/') === '.next/static'), 'Next.js: finds .next/static by itself')
  check(r.findings.some((f) => f.level === 'error' && f.kind === 'value' && f.what.startsWith('NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY')), 'Next.js: the service_role key behind NEXT_PUBLIC_ is found in the client bundle')
  check(r.findings.some((f) => f.level === 'error' && f.what.startsWith('STRIPE_SECRET_KEY') && /\.next[\\/]server[\\/]app/.test(f.file)), 'Next.js: a secret printed into a prerendered page is found in the HTML')
  check(!r.findings.some((f) => /INTERNAL_API_SECRET/.test(f.what)), 'Next.js: the server-only secret is not reported (it stays in server code)')
  const valueSpots = new Set(r.findings.filter((f) => f.kind === 'value').map((f) => `${f.file}:${f.line}`))
  check(!r.findings.some((f) => f.kind === 'shape' && valueSpots.has(`${f.file}:${f.line}`)), 'Next.js: a key found by its value is not reported again as a shape')
  check(r.findings.some((f) => f.kind === 'name' && f.what.startsWith('NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY')), 'Next.js: the risky name is flagged')
  check(!r.findings.some((f) => f.kind === 'name' && /ANON_KEY/.test(f.what)), 'Next.js: the anon key name is not flagged')
}

console.log(fails ? `\n${fails} FAILED` : '\nall good')
process.exit(fails ? 1 : 0)

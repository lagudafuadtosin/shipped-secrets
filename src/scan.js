// Finds what a site ships to the browser and looks through it for secrets.

import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { extname, join, relative, sep } from 'node:path'
import { findShapes, withKey } from './shapes.js'
import { loadSecrets, mask, riskyNames } from './env.js'

// Where each framework puts what the browser downloads, most specific first.
const OUTPUT_DIRS = [
  '.next/static', // Next.js (.next/server is server code and is never scanned)
  'out', // Next.js static export
  '.output/public', // Nuxt, Nitro
  '.svelte-kit/output/client', // SvelteKit
  '.vercel/output/static', // Vercel build output
  'dist/client', // Vite and Astro with a server build next to it
  'dist',
  'build/client', // React Router, Remix
  'build',
  'storybook-static',
]
// Server-side output inside an otherwise browser folder.
const SERVER_PARTS = new Set(['server', 'ssr', '.server'])
const TEXT = new Set(['.js', '.mjs', '.cjs', '.css', '.html', '.htm', '.map', '.json', '.txt', '.xml', '.webmanifest', '.svg'])

/** The folders of browser output found under the project folder. */
export function findOutputDirs(root) {
  const found = []
  for (const d of OUTPUT_DIRS) {
    const p = join(root, d)
    if (!existsSync(p) || !statSync(p).isDirectory()) continue
    // dist and build are skipped when their client half was already taken.
    if (found.some((f) => p.startsWith(f + sep) || f.startsWith(p + sep))) continue
    found.push(p)
  }
  return found
}

function walk(dir, out = [], exts = TEXT) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    const st = statSync(p)
    if (st.isDirectory()) {
      if (!SERVER_PARTS.has(name) && name !== 'node_modules') walk(p, out, exts)
    } else if (exts.has(extname(name).toLowerCase()) && st.size < 20 * 1024 * 1024) out.push(p)
  }
  return out
}

// Next.js keeps prerendered pages under .next/server, and they go straight to
// visitors: the HTML and the RSC payload. Only those are read there, never the
// server's own JavaScript.
const NEXT_PAGES = ['.next/server/app', '.next/server/pages']
const PAGE_FILES = new Set(['.html', '.rsc', '.body', '.meta'])
function nextPages(root) {
  const out = []
  for (const d of NEXT_PAGES) {
    const p = join(root, d)
    if (existsSync(p)) walk(p, out, PAGE_FILES)
  }
  return out
}

const lineAt = (text, index) => text.slice(0, index).split('\n').length

/**
 * Scans text that a browser receives. Returns findings without the file name.
 * @param {string} text
 * @param {{ name: string, value: string, source: string }[]} secrets
 */
/** A secret value that has a known shape can be checked by --verify too. */
export function keyOf(finding, value) {
  const shape = findShapes(value)[0]
  return shape && shape.match === value ? withKey(Object.assign(finding, { shapeId: shape.shape.id }), value) : finding
}

/**
 * The value as written and the common ways it gets encoded on its way into a
 * bundle: base64 (padding dropped, so it matches with or without the "="), hex,
 * URL-encoded, and with "/" escaped the way some JSON and RSC payloads write it.
 * Each is an exact transform of the real value, so none of them can raise a
 * false alarm.
 */
export function forms(value) {
  const out = [{ text: value, how: '' }]
  const add = (text, how) => { if (text !== value && !out.some((f) => f.text === text)) out.push({ text, how }) }
  const buf = Buffer.from(value, 'utf8')
  const b64 = buf.toString('base64').replace(/=+$/, '')
  add(b64, ', base64')
  add(b64.replace(/\+/g, '-').replace(/\//g, '_'), ', base64url')
  add(buf.toString('hex'), ', hex')
  add(buf.toString('hex').toUpperCase(), ', hex')
  add(encodeURIComponent(value), ', URL-encoded')
  if (value.includes('/')) {
    add(value.replace(/\//g, '\\/'), ', escaped')
    add(value.replace(/\//g, '\\u002f'), ', escaped')
  }
  return out
}

const PIECE = 10

/**
 * For --deep: pieces of the value, to find a secret split up so that the whole
 * of it never appears. Only from values long enough to have a random part, and
 * only pieces that look random (a digit, a letter, eight different characters),
 * so a common start like "sk_live_" or "https://" is never one of them.
 */
export function pieces(value) {
  if (value.length < 24) return []
  const out = []
  for (let i = 0; i + PIECE <= value.length; i += PIECE) {
    const p = value.slice(i, i + PIECE)
    if (/\d/.test(p) && /[A-Za-z]/.test(p) && new Set(p).size >= 8) out.push(p)
  }
  return out
}

/**
 * @param {string} text
 * @param {{ name: string, value: string, source: string }[]} secrets
 * @param {{ deep?: boolean }} [opts]
 */
export function scanText(text, secrets, opts = {}) {
  const found = []
  for (const s of secrets) {
    const from = s.source.split(/[\\/]/).pop()
    let whole = false
    for (const { text: form, how } of forms(s.value)) {
      let at = text.indexOf(form)
      while (at !== -1) {
        whole = true
        found.push(keyOf({ level: 'error', kind: 'value', what: `${s.name} from ${from}${how}`, sample: mask(s.value), line: lineAt(text, at) }, s.value))
        at = text.indexOf(form, at + form.length)
        if (found.length > 50) break
      }
    }
    // Two or more random pieces of one secret in the same file, and never the
    // whole of it: split on purpose. A single piece is left alone.
    if (opts.deep && !whole) {
      const all = pieces(s.value)
      const hits = all.map((p) => text.indexOf(p)).filter((at) => at !== -1)
      if (hits.length >= 2) {
        found.push(keyOf({ level: 'error', kind: 'pieces', what: `${s.name} from ${from}, in pieces (${hits.length} of ${all.length} found)`, sample: mask(s.value), line: lineAt(text, Math.min(...hits)) }, s.value))
      }
    }
  }
  for (const f of findShapes(text)) {
    // A value already reported by name is not reported twice as a shape.
    if (secrets.some((s) => f.match.includes(s.value) || s.value.includes(f.match))) continue
    found.push(withKey({ level: f.shape.level, kind: 'shape', what: f.shape.name, sample: mask(f.match), line: lineAt(text, f.index), shapeId: f.shape.id }, f.match))
  }
  return found
}

/**
 * Scans a project folder: its env files for risky names, and its browser output
 * for real secret values and known key shapes.
 * @param {string} root
 * @param {{ dirs?: string[], allow?: string[], env?: Record<string, string | undefined>, envFiles?: string[], deep?: boolean }} [opts]
 */
export function scanProject(root, opts = {}) {
  const { secrets, all } = loadSecrets(root, { env: opts.env ?? process.env, files: opts.envFiles, allow: opts.allow })
  const findings = []
  for (const v of riskyNames(all, opts.allow)) {
    findings.push({
      level: 'warn', kind: 'name', file: relative(root, v.source) || v.source, line: v.line,
      what: `${v.name} has a public prefix, so its value goes to every visitor. If it is a secret, drop the prefix and use it on the server only. If it is meant to be public, add "# shipped-ok" to the line.`,
    })
  }
  const dirs = (opts.dirs ?? findOutputDirs(root)).map((d) => (d.startsWith(root) ? d : join(root, d)))
  let files = 0
  let maps = 0
  const lists = dirs.map((d) => walk(d))
  if (!opts.dirs) lists.push(nextPages(root))
  for (const list of lists) {
    for (const file of list) {
      files++
      if (file.endsWith('.map')) maps++
      const text = readFileSync(file, 'utf8')
      for (const f of scanText(text, secrets, { deep: opts.deep })) findings.push(Object.assign(f, { file: relative(root, file) }))
    }
  }
  if (maps) {
    findings.push({
      level: 'warn', kind: 'sourcemap', file: dirs.map((d) => relative(root, d)).join(', '), line: 0,
      what: `${maps} source map${maps === 1 ? '' : 's'} ship to the public. Anyone can read your original source code from them. Turn them off for production or keep them off the public server.`,
    })
  }
  return { findings, dirs: dirs.map((d) => relative(root, d) || '.'), files, secretsChecked: secrets.length }
}

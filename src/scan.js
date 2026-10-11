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
 * The value as written, and base64 of it, so a key put through btoa() or
 * Buffer.toString('base64') on its way into the bundle is still found. The
 * padding is dropped, so it matches with or without the trailing "=".
 */
export function forms(value) {
  const b64 = Buffer.from(value, 'utf8').toString('base64').replace(/=+$/, '')
  const url = b64.replace(/\+/g, '-').replace(/\//g, '_')
  return [{ text: value, how: '' }, { text: b64, how: ', base64' }, ...(url !== b64 ? [{ text: url, how: ', base64url' }] : [])]
}

export function scanText(text, secrets) {
  const found = []
  for (const s of secrets) {
    for (const { text: form, how } of forms(s.value)) {
      let at = text.indexOf(form)
      while (at !== -1) {
        found.push(keyOf({ level: 'error', kind: 'value', what: `${s.name} from ${s.source.split(/[\\/]/).pop()}${how}`, sample: mask(s.value), line: lineAt(text, at) }, s.value))
        at = text.indexOf(form, at + form.length)
        if (found.length > 50) break
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
 * @param {{ dirs?: string[], allow?: string[], env?: Record<string, string | undefined>, envFiles?: string[] }} [opts]
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
      for (const f of scanText(text, secrets)) findings.push(Object.assign(f, { file: relative(root, file) }))
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

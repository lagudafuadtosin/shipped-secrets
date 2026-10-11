// Reads the secret values the project actually has, so the scan can look for the
// real thing in what ships, not just for shapes.
//
// Sources: every .env* file in the project folder (not the .example / .sample /
// .template ones) and Cloudflare's .dev.vars, plus, for CI, environment
// variables whose names look secret. A value counts as a secret only if its
// name has no public prefix. Values that are also given to a public-prefixed
// name are public on purpose and left out.

import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

export const PUBLIC_PREFIXES = ['VITE_', 'NEXT_PUBLIC_', 'REACT_APP_', 'EXPO_PUBLIC_', 'PUBLIC_', 'NUXT_PUBLIC_', 'GATSBY_', 'STORYBOOK_']
export const isPublicName = (name) => PUBLIC_PREFIXES.some((p) => name.startsWith(p))
const stripPrefix = (name) => {
  const p = PUBLIC_PREFIXES.find((x) => name.startsWith(x))
  return p ? name.slice(p.length) : name
}

const SECRET_WORDS = /(SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE|API_?KEY|ACCESS_?KEY|SERVICE_?ROLE|DATABASE_URL|DB_URL|CONNECTION_STRING|CREDENTIAL|AUTH_KEY|WEBHOOK)/
// Names that look secret but are meant for browsers.
const SAFE_WORDS = /(ANON_?KEY|PUBLISHABLE|PUBLIC_?KEY|SITE_?KEY|MEASUREMENT_ID|CLIENT_?ID|CLIENT_?TOKEN|APP_?ID)/

export const looksSecretName = (name) => SECRET_WORDS.test(name) && !SAFE_WORDS.test(name)
export const looksSafeName = (name) => SAFE_WORDS.test(name)

/** Parses dotenv text. Returns [{ name, value, line, ok }] where ok = a "shipped-ok" comment on the line. */
export function parseDotenv(text) {
  const out = []
  text.split(/\r?\n/).forEach((raw, i) => {
    const line = raw.trim()
    if (!line || line.startsWith('#')) return
    const m = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(line)
    if (!m) return
    let value = m[2]
    let ok = /#.*shipped-ok/.test(value)
    if (/^"/.test(value)) value = (/^"((?:[^"\\]|\\.)*)"/.exec(value) || [, ''])[1].replace(/\\n/g, '\n')
    else if (/^'/.test(value)) value = (/^'([^']*)'/.exec(value) || [, ''])[1]
    else value = value.replace(/\s+#.*$/, '').trim()
    out.push({ name: m[1], value, line: i + 1, ok })
  })
  return out
}

const SKIP_FILES = /\.(example|sample|template|dist|defaults)$/i

/** Every env file in dir that holds real values. */
export function envFiles(dir) {
  const names = existsSync(dir) ? readdirSync(dir) : []
  return names.filter((n) => (n === '.dev.vars' || n === '.env' || n.startsWith('.env.')) && !SKIP_FILES.test(n)).map((n) => join(dir, n))
}

// Too short, or a value that is fine to be public whatever its name.
function trivial(value) {
  if (value.length < 12) return true
  if (/^(true|false|null|undefined|production|development|test)$/i.test(value)) return true
  if (/^\d+(\.\d+)?$/.test(value)) return true
  // A URL is only a secret if it carries a password or a token in it.
  if (/^https?:\/\/[^\s]+$/i.test(value) && !/:\/\/[^/@\s]+:[^/@\s]+@/.test(value) && !/[?&](key|token|secret|sig|signature|password)=/i.test(value)) return true
  return false
}

/**
 * The secrets to look for: { name, value, source, ok }.
 * @param {string} dir the project folder
 * @param {{ env?: Record<string, string | undefined>, files?: string[], allow?: string[] }} [opts]
 */
export function loadSecrets(dir, opts = {}) {
  const allow = new Set(opts.allow ?? [])
  const files = opts.files ?? envFiles(dir)
  const all = []
  for (const file of files) for (const v of parseDotenv(readFileSync(file, 'utf8'))) all.push({ ...v, source: file })
  // CI: secrets usually arrive as environment variables, not files. Only take
  // the ones whose names look secret, so PATH and friends are never searched for.
  for (const [name, value] of Object.entries(opts.env ?? {})) {
    if (value && looksSecretName(name) && !isPublicName(name)) all.push({ name, value, line: 0, ok: false, source: 'environment' })
  }
  // A value given to a public name is public on purpose, unless that public name
  // itself sounds secret (VITE_STRIPE_SECRET): then it is the leak, not the proof.
  const risky = (v) => isPublicName(v.name) && looksSecretName(stripPrefix(v.name))
  const publicValues = new Set(all.filter((v) => isPublicName(v.name) && (v.ok || !risky(v))).map((v) => v.value))
  const seen = new Set()
  const secrets = []
  for (const v of all) {
    if (v.ok || allow.has(v.name)) continue
    if (isPublicName(v.name) ? !risky(v) : looksSafeName(v.name)) continue
    if (trivial(v.value) || publicValues.has(v.value) || seen.has(v.value)) continue
    seen.add(v.value)
    secrets.push(v)
  }
  return { secrets, all }
}

/** Public-prefixed names that look secret: { name, source, line }. */
export function riskyNames(all, allow = []) {
  const allowed = new Set(allow)
  return all.filter((v) => isPublicName(v.name) && !v.ok && !allowed.has(v.name) && looksSecretName(stripPrefix(v.name)))
}

/** Shows enough of a secret to recognise it, never the whole thing. */
export function mask(value) {
  return value.length <= 8 ? '****' : `${value.slice(0, 4)}…${value.slice(-2)} (${value.length} chars)`
}

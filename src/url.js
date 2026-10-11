// Scans a live site the way a stranger would: the page, the scripts it loads,
// the chunks those scripts load, and any source maps they point to.

import { scanText } from './scan.js'

const MAX_FILES = 200

async function get(url) {
  try {
    const res = await fetch(url, { redirect: 'follow', headers: { 'user-agent': 'shipped-secrets' } })
    if (!res.ok) return null
    const type = res.headers.get('content-type') || ''
    if (!/text|javascript|json|html|xml|svg/.test(type) && !/\.(m?js|map|json|css|html?)(\?|$)/.test(url)) return null
    return await res.text()
  } catch {
    return null
  }
}

function assetsIn(text, base, isHtml) {
  const urls = new Set()
  const add = (u) => {
    try {
      const abs = new URL(u, base)
      if (abs.origin === new URL(base).origin) urls.add(abs.href.split('#')[0])
    } catch {
      /* not a URL */
    }
  }
  if (isHtml) {
    for (const m of text.matchAll(/<script[^>]*\bsrc=["']([^"']+)["']/gi)) add(m[1])
    for (const m of text.matchAll(/<link[^>]*\brel=["'](?:modulepreload|preload|stylesheet)["'][^>]*\bhref=["']([^"']+)["']/gi)) add(m[1])
    for (const m of text.matchAll(/<link[^>]*\bhref=["']([^"']+)["'][^>]*\brel=["'](?:modulepreload|preload|stylesheet)["']/gi)) add(m[1])
  } else {
    // Chunks a bundle loads later, and its source map.
    for (const m of text.matchAll(/["'`]((?:\.{0,2}\/)?[\w./-]+\.(?:m?js|css))["'`]/g)) add(m[1])
    for (const m of text.matchAll(/\/[/*]# sourceMappingURL=([^\s*]+)/g)) if (!m[1].startsWith('data:')) add(m[1])
  }
  return urls
}

/**
 * Scans a deployed site by URL. Only files on the same site are fetched.
 * @param {string} url
 * @param {{ name: string, value: string, source: string }[]} [secrets] local values to look for too
 */
export async function scanUrl(url, secrets = []) {
  const findings = []
  const seen = new Set()
  const queue = [url]
  let maps = 0
  while (queue.length && seen.size < MAX_FILES) {
    const u = queue.shift()
    if (seen.has(u)) continue
    seen.add(u)
    const text = await get(u)
    if (text === null) continue
    const isHtml = u === url || /<html|<!doctype/i.test(text.slice(0, 500))
    if (/\.map(\?|$)/.test(u)) maps++
    for (const f of scanText(text, secrets)) findings.push(Object.assign(f, { file: u }))
    for (const next of assetsIn(text, u, isHtml)) if (!seen.has(next)) queue.push(next)
  }
  if (maps) {
    findings.push({ level: 'warn', kind: 'sourcemap', file: url, line: 0, what: `${maps} source map${maps === 1 ? '' : 's'} can be downloaded from this site. Anyone can read your original source code from them.` })
  }
  return { findings, files: seen.size }
}

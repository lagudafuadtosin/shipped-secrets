// shipped-secrets: find secrets that ship to the browser.
export { scanProject, scanText, findOutputDirs } from './scan.js'
export { scanUrl } from './url.js'
export { loadSecrets, riskyNames, parseDotenv, envFiles, mask, PUBLIC_PREFIXES } from './env.js'
export { SHAPES, findShapes } from './shapes.js'

const ORDER = { error: 0, warn: 1 }

/** Plain-text report, worst first. Secrets are always masked. */
export function report(result) {
  const lines = []
  const findings = [...result.findings].sort((a, b) => ORDER[a.level] - ORDER[b.level] || String(a.file).localeCompare(String(b.file)) || a.line - b.line)
  // The same secret twice on one line is one line of output.
  const counts = new Map()
  for (const f of findings) {
    const key = `${f.level}|${f.file}|${f.line}|${f.what}|${f.sample ?? ''}`
    counts.set(key, (counts.get(key) ?? 0) + 1)
  }
  for (const [key, n] of counts) {
    const [level, file, line, what, sample] = key.split('|')
    const where = line !== '0' ? `${file}:${line}` : file
    lines.push(`${level === 'error' ? 'ERROR' : 'warn '} ${where}  ${what}${sample ? `  [${sample}]` : ''}${n > 1 ? `  (${n} times)` : ''}`)
  }
  const errors = findings.filter((f) => f.level === 'error')
  const distinct = new Set(errors.map((f) => `${f.what}|${f.sample}`)).size
  const places = new Set(errors.map((f) => `${f.file}:${f.line}`)).size
  const warns = findings.length - errors.length
  lines.push('')
  lines.push(
    distinct
      ? `${distinct} secret${distinct === 1 ? '' : 's'} shipped to the browser, in ${places} place${places === 1 ? '' : 's'}. Rotate ${distinct === 1 ? 'it' : 'them'}: deleting a key from the code does not take it back from anyone who already downloaded it.`
      : 'No secrets found in what ships to the browser.',
  )
  if (warns) lines.push(`${warns} warning${warns === 1 ? '' : 's'} to check.`)
  return lines.join('\n')
}

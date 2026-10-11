// shipped-secrets: find secrets that ship to the browser, or sit in git history.
export { scanProject, scanText, findOutputDirs } from './scan.js'
export { scanUrl } from './url.js'
export { scanHistory } from './history.js'
export { verifyKey, verifyFindings, VERIFIABLE } from './verify.js'
export { loadSecrets, riskyNames, parseDotenv, envFiles, mask, PUBLIC_PREFIXES } from './env.js'
export { SHAPES, findShapes } from './shapes.js'

const ORDER = { error: 0, warn: 1 }
const VERDICT = { live: 'LIVE, rotate now', dead: 'dead', unknown: 'not checked' }

/** Plain-text report, worst first. Secrets are always masked. */
export function report(result) {
  const lines = []
  const live = (f) => (f.verified === 'live' ? 0 : 1)
  const findings = [...result.findings].sort((a, b) => ORDER[a.level] - ORDER[b.level] || live(a) - live(b) || String(a.file).localeCompare(String(b.file)) || a.line - b.line)
  // The same secret twice on one line is one line of output.
  const counts = new Map()
  for (const f of findings) {
    const key = `${f.level}|${f.file}|${f.line}|${f.what}|${f.sample ?? ''}|${f.verified ?? ''}`
    counts.set(key, (counts.get(key) ?? 0) + 1)
  }
  for (const [key, n] of counts) {
    const [level, file, line, what, sample, verified] = key.split('|')
    const where = line !== '0' ? `${file}:${line}` : file
    lines.push(`${level === 'error' ? 'ERROR' : 'warn '} ${where}  ${what}${sample ? `  [${sample}]` : ''}${verified ? `  (${VERDICT[verified]})` : ''}${n > 1 ? `  (${n} times)` : ''}`)
  }
  const errors = findings.filter((f) => f.level === 'error')
  const history = errors.filter((f) => f.kind.startsWith('history'))
  const shipped = errors.filter((f) => !f.kind.startsWith('history'))
  const distinct = (list) => new Set(list.map((f) => `${f.what}|${f.sample}`)).size
  const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`
  const warns = findings.length - errors.length
  lines.push('')
  if (shipped.length) {
    const n = distinct(shipped)
    const places = new Set(shipped.map((f) => `${f.file}:${f.line}`)).size
    lines.push(`${plural(n, 'secret')} shipped to the browser, in ${plural(places, 'place')}. Rotate ${n === 1 ? 'it' : 'them'}: deleting a key from the code does not take it back from anyone who already downloaded it.`)
  } else if (result.dirs?.length || result.files) lines.push('No secrets found in what ships to the browser.')
  if (history.length) {
    lines.push(`${plural(new Set(history.map((f) => f.sample ?? f.file)).size, 'secret')} in git history. Rotate ${history.length === 1 ? 'it' : 'them'}: every clone of the repository has ${history.length === 1 ? 'it' : 'them'}, even after a delete.`)
  } else if (result.commits != null) lines.push(`No secrets found in ${plural(result.commits, 'commit')} of git history.`)
  const liveCount = new Set(errors.filter((f) => f.verified === 'live').map((f) => f.sample)).size
  if (result.verified && errors.some((f) => f.verified)) lines.push(liveCount ? `${plural(liveCount, 'key')} still work${liveCount === 1 ? 's' : ''}: rotate ${liveCount === 1 ? 'it' : 'them'} first.` : 'None of the keys that could be checked still work.')
  if (warns) lines.push(`${plural(warns, 'warning')} to check.`)
  return lines.join('\n')
}

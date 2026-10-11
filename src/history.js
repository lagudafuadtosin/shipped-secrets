// Searches every commit in the repository: lines that were ever added, for known
// key shapes and for the project's current secret values, and every .env file
// that was ever committed with a server secret in it, even if it was deleted later. A secret that was
// committed once is in every clone of the repository, deleted or not.

import { spawn } from 'node:child_process'
import { createInterface } from 'node:readline'
import { findShapes, withKey } from './shapes.js'
import { isSecretLine, mask, parseDotenv } from './env.js'
import { forms, keyOf } from './scan.js'

const ENV_FILE = /(^|\/)(\.env(\.[^/]*)?|\.dev\.vars)$/
const SAFE_ENV = /\.(example|sample|template|dist|defaults)$/i

/**
 * @param {string} root a folder inside the repository
 * @param {{ name: string, value: string }[]} secrets current values to look for
 * @returns {Promise<{ findings: object[], commits: number } | null>} null when root is not a git repository
 */
export function scanHistory(root, secrets = []) {
  return new Promise((resolve) => {
    // Every commit on every branch, oldest last, with the added lines of each diff.
    const git = spawn('git', ['log', '--all', '-p', '--no-color', '--no-ext-diff', '--unified=0', '--format=@@commit %H %ad', '--date=short'], { cwd: root })
    const findings = []
    const reported = new Set()
    let commits = 0
    let commit = ''
    let date = ''
    let file = ''
    let line = 0
    let envFile = false
    let failed = false
    git.on('error', () => {
      failed = true
    })
    git.stderr.on('data', (d) => {
      if (/not a git repository/i.test(String(d))) failed = true
    })
    const add = (f) => {
      const key = `${f.kind}|${f.sample}|${f.file}`
      if (reported.has(key)) return // the same secret in the same file: report the newest commit only
      reported.add(key)
      findings.push(f)
    }
    createInterface({ input: git.stdout, crlfDelay: Infinity }).on('line', (text) => {
      if (text.startsWith('@@commit ')) {
        ;[, commit, date] = text.split(' ')
        commits++
        return
      }
      if (text.startsWith('+++ b/')) {
        file = text.slice(6)
        envFile = ENV_FILE.test(file) && !SAFE_ENV.test(file)
        return
      }
      const hunk = /^@@ -\d+(?:,\d+)? \+(\d+)/.exec(text)
      if (hunk) {
        line = Number(hunk[1])
        return
      }
      if (!text.startsWith('+') || text.startsWith('+++')) return
      const added = text.slice(1)
      // A committed .env file counts only for the server secrets it held, not for VITE_EDITION=web.
      if (envFile) {
        for (const v of parseDotenv(added)) {
          if (!isSecretLine(v)) continue
          add(keyOf({ level: 'error', kind: 'history-env', file, line, commit: commit.slice(0, 8), date, what: `${v.name} was committed in ${file} (${commit.slice(0, 8)}, ${date}). Every clone has it, even if the file was deleted later.`, sample: mask(v.value) }, v.value))
        }
        line++
        return
      }
      for (const s of secrets) {
        for (const { text: form, how } of forms(s.value)) {
          if (added.includes(form)) {
            add(keyOf({ level: 'error', kind: 'history-value', file, line, commit: commit.slice(0, 8), date, what: `${s.name}${how ? ` (${how.slice(2)})` : ''} was committed in ${file} (${commit.slice(0, 8)}, ${date})`, sample: mask(s.value) }, s.value))
          }
        }
      }
      for (const f of findShapes(added)) {
        if (secrets.some((s) => f.match.includes(s.value) || s.value.includes(f.match))) continue
        add(withKey({ level: f.shape.level, kind: 'history-shape', file, line, commit: commit.slice(0, 8), date, what: `${f.shape.name} was committed in ${file} (${commit.slice(0, 8)}, ${date})`, sample: mask(f.match), shapeId: f.shape.id }, f.match))
      }
      line++
    })
    git.on('close', () => resolve(failed ? null : { findings, commits }))
  })
}

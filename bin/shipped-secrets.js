#!/usr/bin/env node
// shipped-secrets [folder or URL] [--dir <path>] [--allow NAME] [--history] [--verify] [--deep] [--all] [--strict] [--json]
//
// With no argument: finds the browser output in this project (dist, .next/static,
// build, out, ...), reads this project's .env files, and looks for your real
// secret values and known key shapes in what ships. With a URL: scans the live
// site the way a stranger would, using this folder's .env values too.
// --history searches every commit, --verify asks each key's provider if it still works.
// Exit code 1 when a secret is found, or a warning with --strict.

import { resolve } from 'node:path'
import { loadSecrets, report, scanHistory, scanProject, scanUrl, verifyFindings } from '../src/index.js'

const args = process.argv.slice(2)
const flag = (name) => args.includes(name)
const values = (name) => args.flatMap((a, i) => (a === name && args[i + 1] ? [args[i + 1]] : []))
const positional = args.filter((a, i) => !a.startsWith('--') && !['--dir', '--allow'].includes(args[i - 1]))

if (flag('--help') || flag('-h')) {
  console.log(`Usage: shipped-secrets [folder | https://your.site] [options]

Finds secrets that ship to the browser: your real .env values, known key shapes
(Stripe, Supabase service_role, OpenAI, Anthropic, AWS, GitHub, ...), public-prefixed
names that look secret, and source maps left public.

  --history       also search every commit in git history, and flag any .env file ever committed
  --verify        ask each found key's own provider whether it still works (sends the key to that provider only)
  --deep          also look for a secret split into pieces (two or more long random pieces of it in one file)
  --all           --history and --verify
  --dir <path>    scan this folder instead of finding the build output (repeatable)
  --allow NAME    a variable that is fine to ship (repeatable). Or add "# shipped-ok" to its .env line
  --strict        warnings fail too
  --json          machine-readable output (full keys are never included)`)
  process.exit(0)
}

const target = positional[0] ?? '.'
const allow = values('--allow')
const history = flag('--history') || flag('--all')
const verify = flag('--verify') || flag('--all')
const deep = flag('--deep')
let result
if (/^https?:\/\//.test(target)) {
  const { secrets } = loadSecrets(process.cwd(), { env: process.env, allow })
  result = await scanUrl(target, secrets, { deep })
} else {
  const root = resolve(target)
  const dirs = values('--dir')
  result = scanProject(root, { dirs: dirs.length ? dirs.map((d) => resolve(root, d)) : undefined, allow, deep })
  if (!dirs.length && !result.dirs.length && !history) {
    console.error('No build output found (dist, build, out, .next/static, ...). Build first, pass --dir <path>, or use --history.')
    process.exit(2)
  }
  if (history) {
    const { secrets } = loadSecrets(root, { env: {}, allow })
    const past = await scanHistory(root, secrets)
    if (!past) console.error(`${root} is not in a git repository, so history was not searched.`)
    else {
      result.findings.push(...past.findings)
      result.commits = past.commits
    }
  }
}

if (verify) {
  await verifyFindings(result.findings)
  result.verified = true
}

if (flag('--json')) console.log(JSON.stringify(result, null, 2))
else console.log(report(result))
const errors = result.findings.some((f) => f.level === 'error')
process.exit(errors || (flag('--strict') && result.findings.length) ? 1 : 0)

#!/usr/bin/env node
// shipped-secrets [folder or URL] [--dir <path>] [--allow NAME] [--strict] [--json]
//
// With no argument: finds the browser output in this project (dist, .next/static,
// build, out, ...), reads this project's .env files, and looks for your real
// secret values and known key shapes in what ships. With a URL: scans the live
// site the way a stranger would, using this folder's .env values too.
// Exit code 1 when a secret is found, or a warning with --strict.

import { resolve } from 'node:path'
import { loadSecrets, report, scanProject, scanUrl } from '../src/index.js'

const args = process.argv.slice(2)
const flag = (name) => args.includes(name)
const values = (name) => args.flatMap((a, i) => (a === name && args[i + 1] ? [args[i + 1]] : []))
const positional = args.filter((a, i) => !a.startsWith('--') && !['--dir', '--allow'].includes(args[i - 1]))

if (flag('--help') || flag('-h')) {
  console.log(`Usage: shipped-secrets [folder | https://your.site] [--dir <path>] [--allow NAME] [--strict] [--json]

Finds secrets that ship to the browser: your real .env values, known key shapes
(Stripe, Supabase service_role, OpenAI, Anthropic, AWS, GitHub, ...), public-prefixed
names that look secret, and source maps left public.

  --dir <path>    scan this folder instead of finding the build output (repeatable)
  --allow NAME    a variable that is fine to ship (repeatable). Or add "# shipped-ok" to its .env line
  --strict        warnings fail too
  --json          machine-readable output`)
  process.exit(0)
}

const target = positional[0] ?? '.'
const allow = values('--allow')
let result
if (/^https?:\/\//.test(target)) {
  const { secrets } = loadSecrets(process.cwd(), { env: process.env, allow })
  result = await scanUrl(target, secrets)
} else {
  const root = resolve(target)
  const dirs = values('--dir')
  result = scanProject(root, { dirs: dirs.length ? dirs.map((d) => resolve(root, d)) : undefined, allow })
  if (!dirs.length && !result.dirs.length) {
    console.error('No build output found (dist, build, out, .next/static, ...). Build first, or pass --dir <path>.')
    process.exit(2)
  }
}

if (flag('--json')) console.log(JSON.stringify(result, null, 2))
else console.log(report(result))
const errors = result.findings.some((f) => f.level === 'error')
process.exit(errors || (flag('--strict') && result.findings.length) ? 1 : 0)

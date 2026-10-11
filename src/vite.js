// Vite plugin: after every production build, scan what was built and fail the
// build if a secret is in it. Warnings are printed and do not fail the build.
//
//   import shippedSecrets from 'shipped-secrets/vite'
//   export default { plugins: [shippedSecrets()] }

import { report, scanProject } from './index.js'

/**
 * @param {{ allow?: string[], failOnWarn?: boolean, deep?: boolean }} [opts]
 */
export default function shippedSecrets(opts = {}) {
  let root = process.cwd()
  let outDir = 'dist'
  let isBuild = false
  return {
    name: 'shipped-secrets',
    apply: 'build',
    configResolved(config) {
      root = config.root
      outDir = config.build.outDir
      isBuild = config.command === 'build' && !config.build.ssr
    },
    closeBundle() {
      if (!isBuild) return
      const result = scanProject(root, { dirs: [outDir], allow: opts.allow, deep: opts.deep })
      if (!result.findings.length) return
      const text = report(result)
      const fail = result.findings.some((f) => f.level === 'error') || (opts.failOnWarn && result.findings.length)
      if (fail) throw new Error(`shipped-secrets stopped the build:\n${text}`)
      console.warn(`shipped-secrets:\n${text}`)
    },
  }
}

// Checks whether a found key still works, by asking its own provider with a
// harmless read-only call, the way TruffleHog does. Opt-in (--verify): the key
// goes only to the provider that issued it, over HTTPS, and nowhere else.
//
// Answers: 'live' (the provider accepted it: rotate it now), 'dead' (refused:
// revoked or never real), 'unknown' (no safe way to check, or the provider did
// not answer).

const b64url = (s) => Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8')

// shape id -> how to ask. Each returns the Response, or null when it cannot ask.
const CHECKS = {
  'stripe-secret': (key, f) => f('https://api.stripe.com/v1/balance', { headers: { authorization: `Bearer ${key}` } }),
  openai: (key, f) => f('https://api.openai.com/v1/models', { headers: { authorization: `Bearer ${key}` } }),
  anthropic: (key, f) => f('https://api.anthropic.com/v1/models', { headers: { 'x-api-key': key, 'anthropic-version': '2023-06-01' } }),
  'github-token': (key, f) => f('https://api.github.com/user', { headers: { authorization: `Bearer ${key}`, 'user-agent': 'shipped-secrets' } }),
  sendgrid: (key, f) => f('https://api.sendgrid.com/v3/scopes', { headers: { authorization: `Bearer ${key}` } }),
  resend: (key, f) => f('https://api.resend.com/domains', { headers: { authorization: `Bearer ${key}` } }),
  mailgun: (key, f) => f('https://api.mailgun.net/v3/domains', { headers: { authorization: `Basic ${Buffer.from(`api:${key}`).toString('base64')}` } }),
  'slack-token': (key, f) => f('https://slack.com/api/auth.test', { method: 'POST', headers: { authorization: `Bearer ${key}` } }),
  // A Supabase key carries its project ref, so the project's own API can be asked.
  'supabase-service-role': (key, f) => {
    try {
      const ref = JSON.parse(b64url(key.split('.')[1])).ref
      if (!/^[a-z0-9]{8,40}$/.test(ref ?? '')) return null
      return f(`https://${ref}.supabase.co/rest/v1/`, { headers: { apikey: key, authorization: `Bearer ${key}` } })
    } catch {
      return null
    }
  },
}

/** Which shape ids can be verified. */
export const VERIFIABLE = Object.keys(CHECKS)

/**
 * @param {string} shapeId
 * @param {string} key
 * @param {typeof fetch} [f]
 * @returns {Promise<'live' | 'dead' | 'unknown'>}
 */
export async function verifyKey(shapeId, key, f = globalThis.fetch) {
  const ask = CHECKS[shapeId]
  if (!ask) return 'unknown'
  try {
    const res = await ask(key, (url, init) => f(url, { ...init, signal: AbortSignal.timeout(10_000) }))
    if (!res) return 'unknown'
    if (shapeId === 'slack-token') return (await res.json()).ok ? 'live' : 'dead'
    if (res.status === 200) return 'live'
    if (res.status === 401 || res.status === 403) return 'dead'
    return 'unknown'
  } catch {
    return 'unknown'
  }
}

/**
 * Adds a verdict to every shape finding that carries its full key.
 * @param {{ shapeId?: string, key?: string, what: string }[]} findings
 */
export async function verifyFindings(findings, f = globalThis.fetch) {
  const asked = new Map()
  for (const finding of findings) {
    if (!finding.shapeId || !finding.key) continue
    const id = `${finding.shapeId}|${finding.key}`
    if (!asked.has(id)) asked.set(id, verifyKey(finding.shapeId, finding.key, f))
    finding.verified = await asked.get(id)
  }
  return findings
}

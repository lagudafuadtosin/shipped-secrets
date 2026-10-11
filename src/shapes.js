// What known secret keys look like. Publishable keys that are meant for browsers
// (Stripe pk_, Supabase anon and sb_publishable_) are never reported.
// level: error = a server secret, warn = often fine in a browser, check it.

const b64url = (s) => Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8')

export const SHAPES = [
  { id: 'stripe-secret', name: 'Stripe secret or restricted key', level: 'error', re: /\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{20,}\b/g },
  { id: 'supabase-secret', name: 'Supabase secret key', level: 'error', re: /\bsb_secret_[0-9A-Za-z_-]{20,}\b/g },
  {
    id: 'supabase-service-role', name: 'Supabase service_role key (bypasses row level security)', level: 'error',
    re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
    // A Supabase key is a JWT. Only the service_role one is a secret; the anon one is meant for browsers.
    check(match) {
      try {
        const payload = JSON.parse(b64url(match.split('.')[1]))
        return payload && payload.role === 'service_role'
      } catch {
        return false
      }
    },
  },
  { id: 'anthropic', name: 'Anthropic API key', level: 'error', re: /\bsk-ant-(?:api|admin)\d{2}-[0-9A-Za-z_-]{20,}\b/g },
  { id: 'openai', name: 'OpenAI API key', level: 'error', re: /\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[0-9A-Za-z_-]{32,}\b/g },
  { id: 'aws-access-key', name: 'AWS access key ID', level: 'error', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { id: 'github-token', name: 'GitHub token', level: 'error', re: /\b(?:gh[pousr]_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{60,})\b/g },
  { id: 'sendgrid', name: 'SendGrid API key', level: 'error', re: /\bSG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}\b/g },
  { id: 'mailgun', name: 'Mailgun API key', level: 'error', re: /\bkey-[0-9a-f]{32}\b/g },
  { id: 'resend', name: 'Resend API key', level: 'error', re: /\bre_[0-9A-Za-z]{8}_[0-9A-Za-z]{20,}\b/g },
  { id: 'twilio-api-key', name: 'Twilio API key', level: 'error', re: /\bSK[0-9a-f]{32}\b/g },
  { id: 'slack-token', name: 'Slack token', level: 'error', re: /\bxox[abprs]-[0-9A-Za-z-]{10,}\b/g },
  { id: 'private-key', name: 'Private key', level: 'error', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/g },
  { id: 'database-url', name: 'Database URL with a password', level: 'error', re: /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss):\/\/[^\s:'"`/@]+:[^\s'"`@]+@[^\s'"`]+/g },
  // Google browser keys (Maps, Firebase) are usually meant to be public and locked by referrer.
  { id: 'google-api-key', name: 'Google API key (often public by design: check it is restricted)', level: 'warn', re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
]

/** Every known secret shape in text: [{ shape, match, index }]. */
export function findShapes(text) {
  const out = []
  for (const shape of SHAPES) {
    shape.re.lastIndex = 0
    let m
    while ((m = shape.re.exec(text))) {
      if (shape.check && !shape.check(m[0])) continue
      out.push({ shape, match: m[0], index: m.index })
    }
  }
  return out
}

# shipped-secrets

Find secrets that ship to the browser, or sit in your git history, and check whether they still work.

Every frontend framework has a prefix that puts a setting into the JavaScript every visitor downloads: `VITE_`, `NEXT_PUBLIC_`, `REACT_APP_`, `EXPO_PUBLIC_`, `PUBLIC_`. Give a server key that prefix by mistake, or paste a key into client code, and it is public. The build works, the site works, and nobody notices until a bill or a breach. One Vite user lost about €800 when bots scraped a `VITE_GEMINI_API_KEY` from the bundle.

`shipped-secrets` looks at what your build actually ships and tells you, before you deploy.

```sh
npx shipped-secrets
```

```
ERROR .next/static/chunks/app/page-5fb8.js:1  NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY from .env.local  [eyJh…sM (157 chars)]
ERROR .next/server/app/index.html:1  STRIPE_SECRET_KEY from .env.local  [sk_t…H5 (38 chars)]  (2 times)
warn  .env.local:1  NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY has a public prefix, so its value goes to every visitor. ...

2 secrets shipped to the browser, in 3 places. Rotate them: deleting a key from the code does not take it back from anyone who already downloaded it.
```

Secrets are always masked in the output. Nothing is sent anywhere unless you ask for `--verify`.

## What it checks

1. **Your real secret values.** It reads your `.env*` files (not `.env.example`), Cloudflare's `.dev.vars`, and in CI the environment variables whose names look secret. Then it searches every file the browser gets, source maps included, for each server value. This catches any secret, whatever it looks like, including your own tokens that no pattern knows.
2. **Known key shapes**, for keys that are not in your local files: Stripe secret and restricted keys, Supabase service_role keys and `sb_secret_` keys, OpenAI, Anthropic, AWS, GitHub, SendGrid, Mailgun, Resend, Twilio, Slack, private keys, and database URLs with a password. Google API keys are a warning, because Maps and Firebase browser keys are meant to be public.
3. **Supabase keys are decoded.** The anon key and the service_role key look the same. `shipped-secrets` reads the role inside the key, so the anon key is never reported and the service_role key always is.
4. **Risky names.** A public prefix on a name that sounds secret (`VITE_STRIPE_SECRET`, `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY`) is a warning. Names meant for browsers (anon key, publishable key, client ID, client token, site key) are not.
5. **Source maps left public.** A warning, because anyone can read your original code from them, and a key pasted into the code is in there too.

## Where it looks

It finds the browser output by itself and never reads server code:

| framework | folder |
|---|---|
| Next.js | `.next/static`, plus prerendered pages in `.next/server/app` (`.html`, `.rsc`), which go straight to visitors |
| Next.js static export | `out` |
| Vite, Astro | `dist`, or `dist/client` when there is a server build |
| Create React App, React Router, Remix | `build`, or `build/client` |
| SvelteKit | `.svelte-kit/output/client` |
| Nuxt, Nitro | `.output/public` |
| Vercel output | `.vercel/output/static` |
| Storybook | `storybook-static` |

Folders named `server` or `ssr` inside them are skipped. Point it anywhere else with `--dir`.

## A live site

```sh
npx shipped-secrets https://your.site
```

It loads the page the way a stranger would, follows its scripts, the chunks they load and their source maps, and looks for key shapes. Run it from your project folder and it also looks for your own `.env` values on the live site. Only files on the same site are fetched.

## In your build

Vite plugin, which fails the build when a secret ships:

```js
// vite.config.js
import shippedSecrets from 'shipped-secrets/vite'

export default { plugins: [shippedSecrets()] }
```

Any framework, after the build in CI:

```sh
npm run build && npx shipped-secrets
```

It exits with code 1 when a secret is found, so CI stops. Warnings do not fail it unless you add `--strict`.

## When something is meant to be public

Add `# shipped-ok` to the line in your `.env` file:

```
NEXT_PUBLIC_MAPS_KEY=AIza...   # shipped-ok, restricted to our domain
```

or pass `--allow NAME`. `--json` gives the findings as JSON, masked like the text output.

## Git history

```sh
npx shipped-secrets --history
```

A key that was committed once is in every clone of the repository, even after you delete it. `--history` reads every commit on every branch and reports:

- known key shapes in any line ever added
- your current `.env` secret values in any file ever committed, so a key you moved out of the code is still caught where it used to be
- any `.env` file ever committed with a server secret in it. A public build switch like `VITE_EDITION=web` is not reported.

Each finding names the file, line, commit and date. Run it without a build and it searches history only.

## Is the key still live?

```sh
npx shipped-secrets --verify
```

For each key it finds, it asks that key's own provider, with a read-only call, whether the key still works:

```
ERROR dist/assets/index-3f9a.js:1  Stripe secret or restricted key  [sk_l…x2 (107 chars)]  (LIVE, rotate now)
ERROR dist/assets/index-3f9a.js:1  GitHub token  [ghp_…9Q (40 chars)]  (dead)
```

Checked: Stripe (`/v1/balance`), OpenAI and Anthropic (list models), GitHub (`/user`), SendGrid, Mailgun, Resend, Slack (`auth.test`), and Supabase service_role keys (your project's own API, read from the key). Others are marked "not checked". The key goes to its own provider over HTTPS and nowhere else, and only when you pass `--verify`. Live keys are listed first.

`--all` is `--history` and `--verify` together.

## What it does not do

- It does not fix anything. A shipped or committed secret must be rotated at the provider: deleting it from the code, or rewriting history, does not take it back from anyone who already has it.
- `--verify` does not check AWS, Twilio, private keys or database URLs: checking those safely needs more than one harmless call.

## Tested

`npm test` runs the unit tests. `npm run test:apps` builds a real Vite app and a real Next.js app with planted fake keys, and checks that:

- a Stripe key behind `VITE_` is found by its real value, and a key pasted into code is found in the source map too
- the Supabase anon key and a server-only token are not reported
- a Supabase service_role key behind `NEXT_PUBLIC_` is found in the Next.js client bundle
- a secret printed into a page by a server component is found in the prerendered HTML and RSC payload
- a server-only secret in Next.js server code is not reported
- the same build served locally is caught by URL, with and without local `.env` values
- the Vite plugin stops a build with a secret and passes a clean one

The unit tests also build a git repository with a key committed and then deleted and check `--history` finds it, and check `--verify` against a stand-in provider (live, dead and unreachable). Full keys are never in the JSON output.

Fake keys are made while the tests run, so nothing secret-shaped is ever committed.

## Licence

MIT. By Fuad Laguda.

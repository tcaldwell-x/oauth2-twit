# Login with X — OAuth 2.0 Sample

A minimal [Next.js](https://nextjs.org) app that implements the **X API OAuth 2.0
Authorization Code flow with PKCE** ("Login with X") and then displays the
signed-in user's account info by calling
[`GET /2/users/me`](https://docs.x.com/x-api/users/user-lookup-me).

The OAuth **authorize** step uses the `twitter.com` host; the token exchange and
API calls use `api.twitter.com`.

## How it works

| Route | Purpose |
|---|---|
| `GET /api/auth/login` | Generates a PKCE verifier/challenge + state, sets them in httpOnly cookies, and redirects to `https://twitter.com/i/oauth2/authorize`. |
| `GET /api/auth/callback` | Validates `state`, exchanges the `code` for an access token at `https://api.twitter.com/2/oauth2/token`, and stores the token in an httpOnly cookie. |
| `POST /api/auth/logout` | Clears the access-token cookie. |
| `/` (home) | If a token cookie exists, calls `GET /2/users/me` and renders the profile; otherwise shows the "Sign in with X" button. |

PKCE logic lives in [`lib/oauth.ts`](lib/oauth.ts).

## 1. Create an X app

1. Go to the [X Developer Portal](https://developer.x.com) → your Project → app
   settings → **User authentication settings**.
2. Enable **OAuth 2.0**.
3. **Type of App**:
   - **Web App** = confidential client → you get a Client ID **and** Client Secret.
   - **Native App / SPA** = public client → Client ID only (no secret).
4. **Callback URI / Redirect URL** — add both:
   - `http://127.0.0.1:3000/api/auth/callback` (local dev)
   - `https://<your-app>.vercel.app/api/auth/callback` (production)
5. Copy the **Client ID** (and **Client Secret** if you have one).

> The callback URL must match _exactly_ what the app sends. This sample derives
> it from the request origin, or you can pin it with `X_REDIRECT_URI`.

## 2. Run locally

```bash
npm install
cp .env.example .env.local   # then fill in X_CLIENT_ID (and X_CLIENT_SECRET)
npm run dev
```

Open http://127.0.0.1:3000

> Use `127.0.0.1` (not `localhost`) so it matches the registered callback URL.

## 3. Deploy to Vercel

1. Commit and push to GitHub:
   ```bash
   git add .
   git commit -m "Login with X OAuth 2.0 sample"
   git push
   ```
2. In [Vercel](https://vercel.com/new), **Import** the GitHub repo. Next.js is
   auto-detected — no build config needed.
3. Add **Environment Variables** in the Vercel project settings:
   - `X_CLIENT_ID` — required
   - `X_CLIENT_SECRET` — only for confidential (Web App) clients
   - `X_REDIRECT_URI` — optional; set to
     `https://<your-app>.vercel.app/api/auth/callback` to pin it
4. Deploy. Then make sure your production callback URL is registered in the X
   developer portal (step 1.4).

## Environment variables

| Variable | Required | Notes |
|---|---|---|
| `X_CLIENT_ID` | Yes | OAuth 2.0 Client ID |
| `X_CLIENT_SECRET` | No | Only for confidential "Web App" clients |
| `X_REDIRECT_URI` | No | Pins the callback URL; otherwise derived from the request origin |

## Scopes

`tweet.read`, `users.read`, `offline.access` — the minimum needed to log in and
read the authenticated user's profile.

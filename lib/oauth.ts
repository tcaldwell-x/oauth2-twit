import crypto from "crypto";

/**
 * X (Twitter) OAuth 2.0 Authorization Code Flow with PKCE.
 *
 * Per the user's requirement, the user-facing authorize step uses the
 * `twitter.com` host instead of `x.com`. The token + API hosts use
 * `api.twitter.com`.
 */
export const X_AUTHORIZE_URL = "https://twitter.com/i/oauth2/authorize";
export const X_TOKEN_URL = "https://api.twitter.com/2/oauth2/token";
export const X_USERS_ME_URL = "https://api.twitter.com/2/users/me";

// Scopes needed to log in and read the authenticated user's profile.
// `offline.access` is included so a refresh token is returned.
export const X_SCOPES = ["tweet.read", "users.read", "offline.access"];

export const COOKIE_VERIFIER = "x_oauth_code_verifier";
export const COOKIE_STATE = "x_oauth_state";
export const COOKIE_ACCESS_TOKEN = "x_access_token";

function base64UrlEncode(buf: Buffer): string {
  return buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/** Generate a high-entropy PKCE code verifier (RFC 7636). */
export function generateCodeVerifier(): string {
  return base64UrlEncode(crypto.randomBytes(32));
}

/** Derive the S256 code challenge from a verifier. */
export function generateCodeChallenge(verifier: string): string {
  return base64UrlEncode(
    crypto.createHash("sha256").update(verifier).digest()
  );
}

/** Random opaque value used for CSRF protection on the callback. */
export function generateState(): string {
  return base64UrlEncode(crypto.randomBytes(16));
}

export function getClientId(): string {
  const clientId = process.env.X_CLIENT_ID;
  if (!clientId) {
    throw new Error("Missing X_CLIENT_ID environment variable");
  }
  return clientId;
}

/**
 * Resolve the redirect URI registered in the X developer portal.
 *
 * If X_REDIRECT_URI is set it wins; otherwise we derive it from the incoming
 * request origin so the same code works on localhost, Vercel previews, and
 * production. Whatever value is used here must be registered as a callback URL
 * for your app in the X developer portal.
 */
export function getRedirectUri(requestUrl: string): string {
  if (process.env.X_REDIRECT_URI) {
    return process.env.X_REDIRECT_URI;
  }
  const origin = new URL(requestUrl).origin;
  return `${origin}/api/auth/callback`;
}

/**
 * Build the Authorization header / body params for the token endpoint.
 *
 * - Confidential clients (a client secret is configured) authenticate with
 *   HTTP Basic auth.
 * - Public clients send only the client_id in the request body.
 */
export function buildTokenAuth(): {
  headers: Record<string, string>;
  includeClientIdInBody: boolean;
} {
  const clientId = getClientId();
  const clientSecret = process.env.X_CLIENT_SECRET;

  const headers: Record<string, string> = {
    "Content-Type": "application/x-www-form-urlencoded",
  };

  if (clientSecret) {
    const basic = Buffer.from(`${clientId}:${clientSecret}`).toString("base64");
    headers["Authorization"] = `Basic ${basic}`;
    return { headers, includeClientIdInBody: false };
  }

  return { headers, includeClientIdInBody: true };
}

export interface TokenResponse {
  token_type: string;
  expires_in: number;
  access_token: string;
  scope: string;
  refresh_token?: string;
}

/** Exchange an authorization code for an access token. */
export async function exchangeCodeForToken(params: {
  code: string;
  codeVerifier: string;
  redirectUri: string;
}): Promise<TokenResponse> {
  const { headers, includeClientIdInBody } = buildTokenAuth();

  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: params.code,
    redirect_uri: params.redirectUri,
    code_verifier: params.codeVerifier,
  });
  if (includeClientIdInBody) {
    body.set("client_id", getClientId());
  }

  const res = await fetch(X_TOKEN_URL, {
    method: "POST",
    headers,
    body: body.toString(),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Token exchange failed (${res.status}): ${text}`);
  }

  return (await res.json()) as TokenResponse;
}

export interface XUser {
  id: string;
  name: string;
  username: string;
  profile_image_url?: string;
  description?: string;
  created_at?: string;
  verified?: boolean;
  public_metrics?: {
    followers_count: number;
    following_count: number;
    tweet_count: number;
    listed_count: number;
  };
}

/** Fetch the authenticated user's profile via GET /2/users/me. */
export async function fetchMe(accessToken: string): Promise<XUser> {
  const url = new URL(X_USERS_ME_URL);
  url.searchParams.set(
    "user.fields",
    "profile_image_url,description,created_at,verified,public_metrics"
  );

  const res = await fetch(url.toString(), {
    headers: { Authorization: `Bearer ${accessToken}` },
    cache: "no-store",
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`/2/users/me failed (${res.status}): ${text}`);
  }

  const json = (await res.json()) as { data: XUser };
  return json.data;
}

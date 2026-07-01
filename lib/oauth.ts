import crypto from "crypto";

/**
 * X (Twitter) OAuth 2.0 Authorization Code Flow with PKCE.
 *
 * Per the user's requirement, the user-facing authorize step uses the
 * `twitter.com` host instead of `x.com`. The token + API hosts use
 * `api.twitter.com`.
 *
 * Every outbound request to X includes `X-B3-Flags: 1` so the platform
 * records a full distributed trace. On failure we surface the response's
 * `x-transaction-id` plus the full error body and HTTP status in the UI.
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
/** Short-lived cookie used to pass a failed-request trace to the UI. */
export const COOKIE_TRACE = "x_oauth_trace";

/** Sent on every outbound X API / OAuth request to enable full tracing. */
export const TRACE_REQUEST_HEADERS = {
  "X-B3-Flags": "1",
} as const;

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
    ...TRACE_REQUEST_HEADERS,
  };

  if (clientSecret) {
    const basic = Buffer.from(`${clientId}:${clientSecret}`).toString("base64");
    headers["Authorization"] = `Basic ${basic}`;
    return { headers, includeClientIdInBody: false };
  }

  return { headers, includeClientIdInBody: true };
}

/** Trace payload for a single outbound request, shown in the UI on failure. */
export interface RequestTrace {
  /** Human label for the step (e.g. "Token exchange", "GET /2/users/me"). */
  label: string;
  method: string;
  url: string;
  /** Request headers we always send for tracing. */
  requestHeaders: { "X-B3-Flags": string };
  /** HTTP status from the response, if we got one. */
  status: number | null;
  /** Value of the `x-transaction-id` response header (support debugging). */
  transactionId: string | null;
  /** Full response body text on failure. */
  errorBody: string | null;
  /** Parsed error code when the body is JSON with `error` / `errors`. */
  errorCode: string | null;
  /** Parsed error message when available. */
  errorMessage: string | null;
}

/**
 * Error thrown when an outbound X request fails. Carries a full
 * {@link RequestTrace} so the UI can render transaction id + body + status.
 */
export class TracedRequestError extends Error {
  readonly trace: RequestTrace;

  constructor(trace: RequestTrace) {
    const parts = [
      trace.label,
      trace.status != null ? `HTTP ${trace.status}` : "no response",
      trace.errorCode,
      trace.errorMessage ?? trace.errorBody,
      trace.transactionId ? `x-transaction-id=${trace.transactionId}` : null,
    ].filter(Boolean);
    super(parts.join(" — "));
    this.name = "TracedRequestError";
    this.trace = trace;
  }
}

function getHeaderIgnoreCase(
  headers: Headers,
  name: string
): string | null {
  // Headers.get is case-insensitive, but we also try the common variants.
  return (
    headers.get(name) ??
    headers.get(name.toLowerCase()) ??
    headers.get(name.toUpperCase())
  );
}

/** Pull a useful error code + message out of a typical X API error body. */
function parseErrorBody(text: string): {
  errorCode: string | null;
  errorMessage: string | null;
} {
  if (!text) return { errorCode: null, errorMessage: null };
  try {
    const json = JSON.parse(text) as Record<string, unknown>;
    // OAuth token errors: { error: "invalid_grant", error_description: "..." }
    if (typeof json.error === "string") {
      return {
        errorCode: json.error,
        errorMessage:
          typeof json.error_description === "string"
            ? json.error_description
            : typeof json.message === "string"
              ? json.message
              : text,
      };
    }
    // X API v2 errors: { errors: [{ code, message }], title, detail }
    if (Array.isArray(json.errors) && json.errors.length > 0) {
      const first = json.errors[0] as Record<string, unknown>;
      return {
        errorCode:
          first.code != null
            ? String(first.code)
            : typeof json.title === "string"
              ? json.title
              : null,
        errorMessage:
          typeof first.message === "string"
            ? first.message
            : typeof json.detail === "string"
              ? json.detail
              : text,
      };
    }
    if (typeof json.title === "string" || typeof json.detail === "string") {
      return {
        errorCode: typeof json.title === "string" ? json.title : null,
        errorMessage:
          typeof json.detail === "string"
            ? json.detail
            : typeof json.message === "string"
              ? json.message
              : text,
      };
    }
  } catch {
    // not JSON
  }
  return { errorCode: null, errorMessage: text };
}

/** Build a failure trace from a Response (or lack thereof). */
async function buildFailureTrace(
  label: string,
  method: string,
  url: string,
  res: Response | null,
  networkError?: unknown
): Promise<RequestTrace> {
  if (!res) {
    const msg =
      networkError instanceof Error
        ? networkError.message
        : String(networkError ?? "Network error");
    return {
      label,
      method,
      url,
      requestHeaders: { "X-B3-Flags": "1" },
      status: null,
      transactionId: null,
      errorBody: msg,
      errorCode: "network_error",
      errorMessage: msg,
    };
  }

  const text = await res.text();
  const { errorCode, errorMessage } = parseErrorBody(text);
  const transactionId =
    getHeaderIgnoreCase(res.headers, "x-transaction-id") ??
    getHeaderIgnoreCase(res.headers, "X-Transaction-Id");

  return {
    label,
    method,
    url,
    requestHeaders: { "X-B3-Flags": "1" },
    status: res.status,
    transactionId,
    errorBody: text || null,
    errorCode,
    errorMessage,
  };
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

  let res: Response;
  try {
    res = await fetch(X_TOKEN_URL, {
      method: "POST",
      headers,
      body: body.toString(),
    });
  } catch (e) {
    throw new TracedRequestError(
      await buildFailureTrace(
        "Token exchange (POST /2/oauth2/token)",
        "POST",
        X_TOKEN_URL,
        null,
        e
      )
    );
  }

  if (!res.ok) {
    throw new TracedRequestError(
      await buildFailureTrace(
        "Token exchange (POST /2/oauth2/token)",
        "POST",
        X_TOKEN_URL,
        res
      )
    );
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

  const requestUrl = url.toString();
  let res: Response;
  try {
    res = await fetch(requestUrl, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        ...TRACE_REQUEST_HEADERS,
      },
      cache: "no-store",
    });
  } catch (e) {
    throw new TracedRequestError(
      await buildFailureTrace(
        "GET /2/users/me",
        "GET",
        requestUrl,
        null,
        e
      )
    );
  }

  if (!res.ok) {
    throw new TracedRequestError(
      await buildFailureTrace("GET /2/users/me", "GET", requestUrl, res)
    );
  }

  const json = (await res.json()) as { data: XUser };
  return json.data;
}

/** Serialize a trace for the short-lived cookie (URL-safe base64 JSON). */
export function encodeTraceCookie(trace: RequestTrace): string {
  return base64UrlEncode(Buffer.from(JSON.stringify(trace), "utf8"));
}

/** Decode a trace cookie value; returns null if malformed. */
export function decodeTraceCookie(value: string): RequestTrace | null {
  try {
    const padded = value.replace(/-/g, "+").replace(/_/g, "/");
    const json = Buffer.from(padded, "base64").toString("utf8");
    return JSON.parse(json) as RequestTrace;
  } catch {
    return null;
  }
}

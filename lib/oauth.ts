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
// Token + user lookup on the current API host (api.x.com). Authorize stays on
// twitter.com per product requirement.
export const X_TOKEN_URL = "https://api.x.com/2/oauth2/token";
export const X_USERS_ME_URL = "https://api.x.com/2/users/me";

// Scopes needed to log in and read the authenticated user's profile.
// `offline.access` is included so a refresh token is returned.
export const X_SCOPES = ["tweet.read", "users.read", "offline.access"];

export const COOKIE_VERIFIER = "x_oauth_code_verifier";
export const COOKIE_STATE = "x_oauth_state";
export const COOKIE_ACCESS_TOKEN = "x_access_token";
/** Scope string returned by the token endpoint (for debugging 401s). */
export const COOKIE_TOKEN_META = "x_token_meta";
/** Short-lived cookie used to pass a failed-request trace to the UI. */
export const COOKIE_TRACE = "x_oauth_trace";

/** Encode access token for safe cookie storage (avoids `;` `,` truncation). */
export function encodeAccessTokenCookie(token: string): string {
  return encodeURIComponent(token.trim());
}

/** Decode access token from cookie; tolerates legacy unencoded values. */
export function decodeAccessTokenCookie(value: string): string {
  try {
    return decodeURIComponent(value).trim();
  } catch {
    return value.trim();
  }
}

export interface TokenMeta {
  token_type: string;
  scope: string;
  expires_in: number;
}

export function encodeTokenMetaCookie(meta: TokenMeta): string {
  return encodeURIComponent(JSON.stringify(meta));
}

export function decodeTokenMetaCookie(value: string): TokenMeta | null {
  try {
    return JSON.parse(decodeURIComponent(value)) as TokenMeta;
  } catch {
    return null;
  }
}

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
  /** All response headers (lower-cased names) for debugging missing txn ids. */
  responseHeaders: Record<string, string> | null;
  /** Full response body text on failure. */
  errorBody: string | null;
  /** Parsed error code when the body is JSON with `error` / `errors`. */
  errorCode: string | null;
  /** Parsed error message when available. */
  errorMessage: string | null;
  /** Non-sensitive token diagnostics when auth failed (length / prefix only). */
  tokenDebug?: string | null;
  /** Scope / token_type from the token endpoint, when known. */
  tokenMeta?: TokenMeta | null;
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

/**
 * Snapshot every response header the runtime exposes.
 * Names are lower-cased; multi-value headers are joined with ", ".
 *
 * Note: Node/undici `fetch` only gives us what `Headers` enumerates — if X
 * never sent `x-transaction-id` on this response (common on some 401 paths),
 * or an intermediary stripped it, it will not appear here.
 */
function snapshotHeaders(headers: Headers): Record<string, string> {
  const out: Record<string, string> = {};
  // forEach + entries cover the same set; use entries for multi-value joins.
  for (const [key, value] of headers.entries()) {
    const k = key.toLowerCase();
    out[k] = out[k] ? `${out[k]}, ${value}` : value;
  }
  // Also walk forEach in case a runtime only implements one iterator.
  headers.forEach((value, key) => {
    const k = key.toLowerCase();
    if (!(k in out)) out[k] = value;
  });
  return out;
}

/** Prefer x-transaction-id; fall back to any header whose name mentions transaction. */
function extractTransactionId(
  headers: Headers,
  snapshot: Record<string, string>
): string | null {
  const direct =
    headers.get("x-transaction-id") ??
    snapshot["x-transaction-id"] ??
    snapshot["x-transactionid"];
  if (direct) return direct;

  for (const [key, value] of Object.entries(snapshot)) {
    if (key.includes("transaction") && value) return value;
  }
  return null;
}

/** Safe token summary for the UI (never the full secret). */
export function tokenDebugSummary(accessToken: string | undefined | null): string {
  if (!accessToken) return "missing";
  const t = accessToken.trim();
  if (!t) return "empty";
  const prefix = t.slice(0, 8);
  const suffix = t.length > 12 ? t.slice(-4) : "";
  return `len=${t.length} prefix=${prefix}…${suffix}`;
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
  networkError?: unknown,
  extras?: { tokenDebug?: string | null; tokenMeta?: TokenMeta | null }
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
      responseHeaders: null,
      errorBody: msg,
      errorCode: "network_error",
      errorMessage: msg,
      tokenDebug: extras?.tokenDebug ?? null,
      tokenMeta: extras?.tokenMeta ?? null,
    };
  }

  const text = await res.text();
  const { errorCode, errorMessage } = parseErrorBody(text);
  const responseHeaders = snapshotHeaders(res.headers);
  const transactionId = extractTransactionId(res.headers, responseHeaders);

  return {
    label,
    method,
    url,
    requestHeaders: { "X-B3-Flags": "1" },
    status: res.status,
    transactionId,
    responseHeaders,
    errorBody: text || null,
    errorCode,
    errorMessage,
    tokenDebug: extras?.tokenDebug ?? null,
    tokenMeta: extras?.tokenMeta ?? null,
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

/**
 * Fetch the authenticated user's profile via GET /2/users/me.
 *
 * Uses the user-context OAuth 2.0 access token from the PKCE flow
 * (not an app-only bearer token from the developer portal).
 */
export async function fetchMe(
  accessToken: string,
  tokenMeta?: TokenMeta | null
): Promise<XUser> {
  // Guard against cookie whitespace / encoding artifacts.
  const token = accessToken.trim();
  const tokenDebug = tokenDebugSummary(token);
  const extras = { tokenDebug, tokenMeta: tokenMeta ?? null };

  const url = new URL(X_USERS_ME_URL);
  url.searchParams.set(
    "user.fields",
    "profile_image_url,description,created_at,verified,public_metrics"
  );

  const requestUrl = url.toString();
  const headers: Record<string, string> = {
    Authorization: `Bearer ${token}`,
    Accept: "application/json",
    ...TRACE_REQUEST_HEADERS,
  };

  let res: Response;
  try {
    res = await fetch(requestUrl, {
      method: "GET",
      headers,
      cache: "no-store",
      redirect: "manual",
    });
  } catch (e) {
    throw new TracedRequestError(
      await buildFailureTrace(
        "GET /2/users/me",
        "GET",
        requestUrl,
        null,
        e,
        extras
      )
    );
  }

  if (!res.ok) {
    // If user.fields triggered a tier/permission issue, retry without them so
    // the user at least gets the default id/name/username payload.
    if (res.status === 401 || res.status === 403) {
      const retryUrl = X_USERS_ME_URL;
      let retry: Response | null = null;
      try {
        retry = await fetch(retryUrl, {
          method: "GET",
          headers,
          cache: "no-store",
          redirect: "manual",
        });
        if (retry.ok) {
          const json = (await retry.json()) as { data: XUser };
          return json.data;
        }
      } catch {
        // fall through to original failure
      }
      // Prefer the retry response for the trace when it also failed (cleaner URL).
      if (retry && !retry.ok) {
        throw new TracedRequestError(
          await buildFailureTrace(
            "GET /2/users/me",
            "GET",
            retryUrl,
            retry,
            undefined,
            extras
          )
        );
      }
    }

    throw new TracedRequestError(
      await buildFailureTrace(
        "GET /2/users/me",
        "GET",
        requestUrl,
        res,
        undefined,
        extras
      )
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

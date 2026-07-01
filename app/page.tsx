import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import {
  COOKIE_ACCESS_TOKEN,
  COOKIE_TRACE,
  TracedRequestError,
  decodeTraceCookie,
  encodeTraceCookie,
  fetchMe,
  type RequestTrace,
  type XUser,
} from "@/lib/oauth";

export const dynamic = "force-dynamic";

const ERROR_MESSAGES: Record<string, string> = {
  access_denied: "You declined the authorization request.",
  state_mismatch: "Security check failed (state mismatch). Please try again.",
  missing_oauth_params: "The login response was missing required parameters.",
  token_exchange_failed:
    "Could not exchange the authorization code for a token. Check your app credentials and callback URL.",
  users_me_failed:
    "Signed in, but GET /2/users/me returned Unauthorized (401). The access token is missing user context, expired, corrupted in the cookie, or the app is missing the users.read + tweet.read scopes. Sign in again after checking credentials in the X developer portal.",
};

function formatNumber(n: number): string {
  return new Intl.NumberFormat("en-US", { notation: "compact" }).format(n);
}

/** Renders the outbound request trace for a failed X API / OAuth call. */
function TracePanel({ trace }: { trace: RequestTrace }) {
  const headerEntries = trace.responseHeaders
    ? Object.entries(trace.responseHeaders).sort(([a], [b]) =>
        a.localeCompare(b)
      )
    : [];

  return (
    <div className="trace" role="region" aria-label="Request trace">
      <p className="trace-title">Request trace</p>
      <dl className="trace-grid">
        <dt>Step</dt>
        <dd>{trace.label}</dd>
        <dt>Request</dt>
        <dd>
          <code>
            {trace.method} {trace.url}
          </code>
        </dd>
        <dt>Request header</dt>
        <dd>
          <code>X-B3-Flags: {trace.requestHeaders["X-B3-Flags"]}</code>
        </dd>
        <dt>HTTP status</dt>
        <dd>
          <code>{trace.status != null ? String(trace.status) : "—"}</code>
        </dd>
        <dt>Error code</dt>
        <dd>
          <code>{trace.errorCode ?? "—"}</code>
        </dd>
        {trace.tokenDebug && (
          <>
            <dt>Token (debug)</dt>
            <dd>
              <code>{trace.tokenDebug}</code>
            </dd>
          </>
        )}
        <dt>Error message</dt>
        <dd className="trace-msg">
          {trace.errorMessage ?? trace.errorBody ?? "—"}
        </dd>
      </dl>

      <p className="trace-title" style={{ marginTop: 16 }}>
        Response headers ({headerEntries.length})
      </p>
      {headerEntries.length === 0 ? (
        <p className="trace-msg" style={{ color: "var(--muted)", margin: 0 }}>
          No response headers were exposed by the runtime (x-transaction-id was
          not among them). This often happens when the API never set the header
          on this failure path, or the server fetch layer did not surface it.
        </p>
      ) : (
        <pre className="trace-headers">
          {headerEntries.map(([k, v]) => `${k}: ${v}`).join("\n")}
        </pre>
      )}

      {trace.errorBody && (
        <>
          <p className="trace-title" style={{ marginTop: 16 }}>
            Full error response body
          </p>
          <pre className="trace-headers">{trace.errorBody}</pre>
        </>
      )}
    </div>
  );
}

function LoginView({
  error,
  trace,
}: {
  error?: string;
  trace?: RequestTrace | null;
}) {
  return (
    <div className="card card-wide">
      <h1 className="title">Login with X</h1>
      <p className="subtitle">
        This sample demonstrates the X API OAuth 2.0 Authorization Code flow
        with PKCE. Sign in to view your account info from{" "}
        <code>GET /2/users/me</code>. Every outbound request sends{" "}
        <code>X-B3-Flags: 1</code>; failures show the response{" "}
        <code>x-transaction-id</code>, status, and full error body below.
      </p>
      {error && (
        <div className="error">
          {ERROR_MESSAGES[error] ?? `Login error: ${error}`}
        </div>
      )}
      {trace && <TracePanel trace={trace} />}
      <a className="btn btn-primary" href="/api/auth/login">
        Sign in with X
      </a>
      <p className="foot">
        OAuth authorize host: <code>twitter.com</code>
      </p>
    </div>
  );
}

function ProfileView({ user }: { user: XUser }) {
  const avatar = user.profile_image_url?.replace("_normal", "_400x400");
  return (
    <div className="card">
      <div className="profile-header">
        {avatar && (
          // eslint-disable-next-line @next/next/no-img-element
          <img className="avatar" src={avatar} alt={user.name} />
        )}
        <div>
          <p className="name">
            {user.name}
            {user.verified && <span className="verified">✓</span>}
          </p>
          <p className="username">@{user.username}</p>
        </div>
      </div>

      {user.description && <p className="bio">{user.description}</p>}

      {user.public_metrics && (
        <div className="metrics">
          <div>
            <span className="metric-value">
              {formatNumber(user.public_metrics.following_count)}
            </span>{" "}
            <span className="metric-label">Following</span>
          </div>
          <div>
            <span className="metric-value">
              {formatNumber(user.public_metrics.followers_count)}
            </span>{" "}
            <span className="metric-label">Followers</span>
          </div>
          <div>
            <span className="metric-value">
              {formatNumber(user.public_metrics.tweet_count)}
            </span>{" "}
            <span className="metric-label">Posts</span>
          </div>
        </div>
      )}

      <p className="foot" style={{ textAlign: "left", marginTop: 0 }}>
        User ID: <code>{user.id}</code>
      </p>

      <form action="/api/auth/logout" method="post">
        <button className="btn btn-secondary" type="submit">
          Log out
        </button>
      </form>
    </div>
  );
}

export default async function Home({
  searchParams,
}: {
  searchParams: Promise<{ error?: string }>;
}) {
  const { error } = await searchParams;
  const cookieStore = await cookies();
  const accessToken = cookieStore.get(COOKIE_ACCESS_TOKEN)?.value;
  const traceCookie = cookieStore.get(COOKIE_TRACE)?.value;
  const cookieTrace = traceCookie ? decodeTraceCookie(traceCookie) : null;

  let content;
  if (accessToken) {
    try {
      const user = await fetchMe(accessToken);
      content = <ProfileView user={user} />;
    } catch (e) {
      console.error(e);
      // Server Components can't set cookies — bounce through /api/auth/fail to
      // clear the bad access token, stash the request trace, and show the UI.
      const trace =
        e instanceof TracedRequestError ? e.trace : cookieTrace;
      if (trace) {
        redirect(
          `/api/auth/fail?error=users_me_failed&trace=${encodeURIComponent(encodeTraceCookie(trace))}`
        );
      }
      redirect("/api/auth/logout?error=users_me_failed");
    }
  } else {
    // Only surface the cookie-backed trace when we actually failed an OAuth step
    // (avoids showing a stale trace on a normal visit).
    const showTrace =
      error === "token_exchange_failed" || error === "users_me_failed"
        ? cookieTrace
        : null;
    content = <LoginView error={error} trace={showTrace} />;
  }

  return <main className="container">{content}</main>;
}

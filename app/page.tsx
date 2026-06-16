import { cookies } from "next/headers";
import { COOKIE_ACCESS_TOKEN, fetchMe, type XUser } from "@/lib/oauth";

export const dynamic = "force-dynamic";

const ERROR_MESSAGES: Record<string, string> = {
  access_denied: "You declined the authorization request.",
  state_mismatch: "Security check failed (state mismatch). Please try again.",
  missing_oauth_params: "The login response was missing required parameters.",
  token_exchange_failed:
    "Could not exchange the authorization code for a token. Check your app credentials and callback URL.",
};

function formatNumber(n: number): string {
  return new Intl.NumberFormat("en-US", { notation: "compact" }).format(n);
}

function LoginView({ error }: { error?: string }) {
  return (
    <div className="card">
      <h1 className="title">Login with X</h1>
      <p className="subtitle">
        This sample demonstrates the X API OAuth 2.0 Authorization Code flow
        with PKCE. Sign in to view your account info from{" "}
        <code>GET /2/users/me</code>.
      </p>
      {error && (
        <div className="error">
          {ERROR_MESSAGES[error] ?? `Login error: ${error}`}
        </div>
      )}
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

  let content;
  if (accessToken) {
    try {
      const user = await fetchMe(accessToken);
      content = <ProfileView user={user} />;
    } catch (e) {
      console.error(e);
      // Token is likely expired/invalid — fall back to the login view.
      content = <LoginView error="token_exchange_failed" />;
    }
  } else {
    content = <LoginView error={error} />;
  }

  return <main className="container">{content}</main>;
}

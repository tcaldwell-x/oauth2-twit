import { NextResponse } from "next/server";
import {
  COOKIE_STATE,
  COOKIE_VERIFIER,
  X_AUTHORIZE_URL,
  X_SCOPES,
  generateCodeChallenge,
  generateCodeVerifier,
  generateState,
  getClientId,
  getRedirectUri,
} from "@/lib/oauth";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);
  const state = generateState();
  const redirectUri = getRedirectUri(request.url);

  const authorizeUrl = new URL(X_AUTHORIZE_URL);
  authorizeUrl.searchParams.set("response_type", "code");
  authorizeUrl.searchParams.set("client_id", getClientId());
  authorizeUrl.searchParams.set("redirect_uri", redirectUri);
  authorizeUrl.searchParams.set("scope", X_SCOPES.join(" "));
  authorizeUrl.searchParams.set("state", state);
  authorizeUrl.searchParams.set("code_challenge", codeChallenge);
  authorizeUrl.searchParams.set("code_challenge_method", "S256");

  const response = NextResponse.redirect(authorizeUrl.toString());

  // Short-lived, httpOnly cookies hold the PKCE verifier + CSRF state until
  // the callback completes.
  const cookieOpts = {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax" as const,
    path: "/",
    maxAge: 60 * 10, // 10 minutes
  };
  response.cookies.set(COOKIE_VERIFIER, codeVerifier, cookieOpts);
  response.cookies.set(COOKIE_STATE, state, cookieOpts);

  return response;
}

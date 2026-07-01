import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import {
  COOKIE_ACCESS_TOKEN,
  COOKIE_STATE,
  COOKIE_TRACE,
  COOKIE_VERIFIER,
  TracedRequestError,
  encodeTraceCookie,
  exchangeCodeForToken,
  getRedirectUri,
} from "@/lib/oauth";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const error = url.searchParams.get("error");

  const home = new URL("/", url.origin);

  if (error) {
    home.searchParams.set("error", error);
    return NextResponse.redirect(home.toString());
  }

  const cookieStore = await cookies();
  const storedState = cookieStore.get(COOKIE_STATE)?.value;
  const codeVerifier = cookieStore.get(COOKIE_VERIFIER)?.value;

  if (!code || !state || !storedState || !codeVerifier) {
    home.searchParams.set("error", "missing_oauth_params");
    return NextResponse.redirect(home.toString());
  }

  if (state !== storedState) {
    home.searchParams.set("error", "state_mismatch");
    return NextResponse.redirect(home.toString());
  }

  try {
    const token = await exchangeCodeForToken({
      code,
      codeVerifier,
      redirectUri: getRedirectUri(request.url),
    });

    const response = NextResponse.redirect(home.toString());

    // Persist the access token in an httpOnly cookie. Clear the temporary
    // PKCE/state cookies now that the exchange succeeded.
    // Store the raw token; Next cookie serialization handles safe characters.
    // Trim in case the token endpoint ever returns surrounding whitespace.
    const accessToken = token.access_token.trim();
    response.cookies.set(COOKIE_ACCESS_TOKEN, accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/",
      maxAge: token.expires_in ?? 60 * 60 * 2,
    });
    response.cookies.delete(COOKIE_VERIFIER);
    response.cookies.delete(COOKIE_STATE);
    response.cookies.delete(COOKIE_TRACE);

    return response;
  } catch (e) {
    console.error(e);
    home.searchParams.set("error", "token_exchange_failed");
    const response = NextResponse.redirect(home.toString());

    // Pass the full request trace (incl. x-transaction-id + body + status)
    // to the home page via a short-lived cookie so the UI can display it.
    if (e instanceof TracedRequestError) {
      response.cookies.set(COOKIE_TRACE, encodeTraceCookie(e.trace), {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        path: "/",
        maxAge: 60 * 5, // 5 minutes — long enough to render once
      });
    }

    response.cookies.delete(COOKIE_VERIFIER);
    response.cookies.delete(COOKIE_STATE);
    return response;
  }
}

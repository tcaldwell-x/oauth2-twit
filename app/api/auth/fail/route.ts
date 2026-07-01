import { NextResponse } from "next/server";
import {
  COOKIE_ACCESS_TOKEN,
  COOKIE_TRACE,
  decodeTraceCookie,
} from "@/lib/oauth";

export const dynamic = "force-dynamic";

/**
 * Clears a bad access-token cookie, stores the request trace for the UI, and
 * redirects home with an error code. Used when GET /2/users/me fails after
 * a successful token exchange.
 */
export async function GET(request: Request) {
  const url = new URL(request.url);
  const error = url.searchParams.get("error") ?? "users_me_failed";
  const traceParam = url.searchParams.get("trace");

  const home = new URL("/", url.origin);
  home.searchParams.set("error", error);

  const response = NextResponse.redirect(home.toString(), { status: 303 });
  response.cookies.delete(COOKIE_ACCESS_TOKEN);

  if (traceParam && decodeTraceCookie(traceParam)) {
    response.cookies.set(COOKIE_TRACE, traceParam, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/",
      maxAge: 60 * 5,
    });
  }

  return response;
}

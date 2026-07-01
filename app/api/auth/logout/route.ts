import { NextResponse } from "next/server";
import {
  COOKIE_ACCESS_TOKEN,
  COOKIE_TRACE,
} from "@/lib/oauth";

export const dynamic = "force-dynamic";

function clearAndRedirect(request: Request) {
  const url = new URL(request.url);
  const home = new URL("/", url.origin);
  const error = url.searchParams.get("error");
  if (error) {
    home.searchParams.set("error", error);
  }

  const response = NextResponse.redirect(home.toString(), { status: 303 });
  response.cookies.delete(COOKIE_ACCESS_TOKEN);
  // Keep COOKIE_TRACE if present so the UI can still render the failure panel.
  return response;
}

export async function POST(request: Request) {
  return clearAndRedirect(request);
}

/** Allow GET so the home page can bounce here to clear a bad token cookie. */
export async function GET(request: Request) {
  return clearAndRedirect(request);
}

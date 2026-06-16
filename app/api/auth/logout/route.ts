import { NextResponse } from "next/server";
import { COOKIE_ACCESS_TOKEN } from "@/lib/oauth";

export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  const response = NextResponse.redirect(new URL("/", request.url), {
    status: 303,
  });
  response.cookies.delete(COOKIE_ACCESS_TOKEN);
  return response;
}

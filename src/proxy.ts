import { NextResponse, type NextRequest } from "next/server";
import { verifyAccessToken, AUTH_COOKIE_NAME } from "@/lib/auth";

const PUBLIC_ROUTES = ["/login"];

export function proxy(request: NextRequest) {
  const { pathname } = request.nextUrl;
  if (pathname.startsWith("/_next") || pathname.startsWith("/api/auth") || pathname.startsWith("/static")) {
    return NextResponse.next();
  }
  const token = request.cookies.get(AUTH_COOKIE_NAME)?.value;
  const payload = token ? verifyAccessToken(token) : null;
  if (PUBLIC_ROUTES.includes(pathname)) {
    if (payload) return NextResponse.redirect(new URL("/dashboard", request.url));
    return NextResponse.next();
  }
  if (!payload) {
    const loginUrl = new URL("/login", request.url);
    loginUrl.searchParams.set("redirect", pathname);
    return NextResponse.redirect(loginUrl);
  }
  const headers = new Headers(request.headers);
  headers.set("x-user-id", String(payload.sub));
  headers.set("x-user-username", payload.username);
  headers.set("x-user-role", payload.role);
  return NextResponse.next({ request: { headers } });
}

export const config = { matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"] };

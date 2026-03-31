import { NextRequest, NextResponse } from "next/server";

const protectedPrefixes = ["/products", "/settings"];
const authPages = ["/login", "/signup"];

export async function proxy(request: NextRequest) {
  const { pathname } = request.nextUrl;

  const isProtected = protectedPrefixes.some((p) => pathname.startsWith(p));
  const isAuthPage = authPages.some((p) => pathname.startsWith(p));
  const sessionCookie = request.cookies.get("better-auth.session_token")?.value;

  if (isProtected && !sessionCookie) {
    return NextResponse.redirect(new URL("/login", request.url));
  }

  if (isAuthPage && sessionCookie) {
    return NextResponse.redirect(new URL("/products", request.url));
  }

  if (pathname === "/" && !sessionCookie) {
    return NextResponse.redirect(new URL("/login", request.url));
  }

  return NextResponse.next();
}

export const config = {
  matcher: [
    "/((?!api|_next/static|_next/image|favicon.ico).*)",
  ],
};

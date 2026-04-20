import { NextRequest, NextResponse } from "next/server";

export function proxy(req: NextRequest) {
  const auth = req.cookies.get("auth");
  const { pathname } = req.nextUrl;

  if (
    pathname.startsWith("/login") ||
    pathname.startsWith("/api/auth") ||
    pathname.startsWith("/api/virustotal")
  ) {
    return NextResponse.next();
  }

  if (auth?.value === "1") {
    return NextResponse.next();
  }

  return NextResponse.redirect(new URL("/login", req.url));
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
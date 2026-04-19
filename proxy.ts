import { NextRequest, NextResponse } from "next/server";

export const runtime = "edge";

export function proxy(req: NextRequest) {
  const authHeader = req.headers.get("authorization");

  if (authHeader && authHeader.startsWith("Basic ")) {
    const base64 = authHeader.slice(6);
    const decoded = atob(base64);
    const colonIndex = decoded.indexOf(":");
    const user = decoded.slice(0, colonIndex);
    const pass = decoded.slice(colonIndex + 1);

    const validUser = process.env.BASIC_AUTH_USER;
    const validPass = process.env.BASIC_AUTH_PASS;

    if (user === validUser && pass === validPass) {
      return NextResponse.next();
    }
  }

  return new NextResponse("Authentication required", {
    status: 401,
    headers: {
      "WWW-Authenticate": 'Basic realm="SOC Access Only"',
    },
  });
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
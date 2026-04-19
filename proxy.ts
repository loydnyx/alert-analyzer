import { NextRequest, NextResponse } from "next/server";

export function proxy(req: NextRequest) {
  const authHeader = req.headers.get("authorization");

  if (authHeader && authHeader.startsWith("Basic ")) {
    const base64 = authHeader.slice(6);
    const decoded = Buffer.from(base64, "base64").toString("utf-8");
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
      "WWW-Authenticate": 'Basic realm="SOC Access Only", charset="UTF-8"',
      "Content-Type": "text/plain",
    },
  });
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
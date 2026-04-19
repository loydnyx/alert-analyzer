import { NextRequest, NextResponse } from "next/server";

export function middleware(req: NextRequest) {
  const authHeader = req.headers.get("authorization");

  if (authHeader) {
    const base64 = authHeader.split(" ")[1];
    const decoded = Buffer.from(base64, "base64").toString("utf-8");
    const [user, pass] = decoded.split(":");

    const validUser = process.env.BASIC_AUTH_USER;
    const validPass = process.env.BASIC_AUTH_PASS;

    if (user === validUser && pass === validPass) {
      return NextResponse.next();
    }
  }

  return new NextResponse("Unauthorized", {
    status: 401,
    headers: {
      "WWW-Authenticate": 'Basic realm="Alert Analyzer – SOC Access Only"',
    },
  });
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
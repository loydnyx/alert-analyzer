import { NextRequest, NextResponse } from "next/server";
import { cookies } from "next/headers";

export async function POST(req: NextRequest) {
  const { user, pass } = await req.json();

  const validUser = process.env.BASIC_AUTH_USER;
  const validPass = process.env.BASIC_AUTH_PASS;

  if (user === validUser && pass === validPass) {
    const cookieStore = await cookies();
    cookieStore.set("auth", "1", {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      maxAge: 60 * 30, // 30 minutes
      path: "/",
    });
    return NextResponse.json({ ok: true });
  }

  return NextResponse.json({ ok: false }, { status: 401 });
}

// Logout
export async function DELETE() {
  const cookieStore = await cookies();
  cookieStore.set("auth", "", {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 0,
    path: "/",
  });
  return NextResponse.json({ ok: true });
}
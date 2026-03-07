import { NextRequest, NextResponse } from "next/server";

async function sha256(text: string): Promise<string> {
  const data = new TextEncoder().encode(text);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export async function GET(req: NextRequest) {
  const password = process.env.ACCESS_PASSWORD;
  if (!password) return NextResponse.json({ required: false });

  const cookie = req.cookies.get("fwh_access")?.value;
  const hash = await sha256(password);
  return NextResponse.json({
    required: true,
    authenticated: cookie === hash,
  });
}

export async function POST(req: NextRequest) {
  const password = process.env.ACCESS_PASSWORD;
  if (!password) return NextResponse.json({ ok: true });

  const { password: input } = await req.json();
  if (input !== password) {
    return NextResponse.json({ error: "密码错误" }, { status: 401 });
  }

  const hash = await sha256(password);
  const res = NextResponse.json({ ok: true });
  res.cookies.set("fwh_access", hash, {
    httpOnly: true,
    secure: req.nextUrl.protocol === "https:",
    sameSite: "lax",
    maxAge: 60 * 60 * 24 * 365,
    path: "/",
  });
  return res;
}

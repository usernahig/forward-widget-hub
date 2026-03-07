import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

async function sha256(text: string): Promise<string> {
  const data = new TextEncoder().encode(text);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export async function middleware(request: NextRequest) {
  const password = process.env.ACCESS_PASSWORD;
  if (!password) return NextResponse.next();

  const cookie = request.cookies.get("fwh_access")?.value;
  const hash = await sha256(password);
  if (cookie === hash) return NextResponse.next();

  return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
}

export const config = {
  matcher: ["/api/upload", "/api/manage"],
};

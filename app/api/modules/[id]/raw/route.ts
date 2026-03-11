import { NextRequest, NextResponse } from "next/server";
import { getBackendDb, getBackendStore } from "@/lib/backend";

interface ModuleRow { id: string; collection_id: string; filename: string; is_encrypted: number; }

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const ua = request.headers.get("user-agent") || "";
  if (!ua.includes("Forward")) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  const { id } = await params;
  const db = await getBackendDb();
  const mod = await db.prepare("SELECT id, collection_id, filename, is_encrypted FROM modules WHERE id = ?").get(id) as ModuleRow | undefined;
  if (!mod) return NextResponse.json({ error: "Not found" }, { status: 404 });

  const store = await getBackendStore();

  // If store supports CDN URLs, redirect there
  const cdnUrl = store.getUrl?.(mod.collection_id, mod.filename);
  if (cdnUrl) {
    return NextResponse.redirect(cdnUrl, 302);
  }

  const content = await store.read(mod.collection_id, mod.filename);
  if (!content) return NextResponse.json({ error: "File not found" }, { status: 404 });

  const contentType = mod.is_encrypted ? "application/octet-stream" : "application/javascript; charset=utf-8";

  return new NextResponse(new Uint8Array(content), {
    headers: {
      "Content-Type": contentType,
      "Content-Disposition": `inline; filename="${encodeURIComponent(mod.filename)}"; filename*=UTF-8''${encodeURIComponent(mod.filename)}`,
      "Cache-Control": "public, max-age=3600",
      "Vary": "User-Agent",
    },
  });
}

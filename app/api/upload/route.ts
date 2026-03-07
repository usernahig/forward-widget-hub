import { NextRequest, NextResponse } from "next/server";
import { nanoid } from "nanoid";
import { getDb } from "@/lib/db";
import { generateToken, hashToken, getTokenPrefix } from "@/lib/auth";
import { parseWidgetMetadata, isEncrypted } from "@/lib/parser";
import { saveModule } from "@/lib/storage";

const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB

export async function POST(request: NextRequest) {
  try {
    const formData = await request.formData();
    const files = formData.getAll("files") as File[];
    const token = formData.get("token") as string | null;
    const collectionTitle = (formData.get("title") as string) || "My Widgets";
    const collectionDesc = (formData.get("description") as string) || "";

    if (!files.length) {
      return NextResponse.json({ error: "No files provided" }, { status: 400 });
    }

    for (const file of files) {
      if (file.size > MAX_FILE_SIZE) {
        return NextResponse.json({ error: `File ${file.name} exceeds 5MB limit` }, { status: 413 });
      }
      if (!file.name.endsWith(".js")) {
        return NextResponse.json({ error: `File ${file.name} is not a .js file` }, { status: 400 });
      }
    }

    const db = getDb();
    let userId: string;
    let rawToken: string;
    let isNewUser = false;

    if (token) {
      const hash = hashToken(token);
      const user = db.prepare("SELECT id FROM users WHERE token_hash = ?").get(hash) as { id: string } | undefined;
      if (!user) {
        return NextResponse.json({ error: "Invalid token" }, { status: 401 });
      }
      userId = user.id;
      rawToken = token;
    } else {
      userId = nanoid();
      rawToken = generateToken();
      const hash = hashToken(rawToken);
      const prefix = getTokenPrefix(rawToken);
      db.prepare("INSERT INTO users (id, token_hash, token_prefix) VALUES (?, ?, ?)").run(userId, hash, prefix);
      isNewUser = true;
    }

    let collectionId: string;
    let slug: string;

    const existingCollection = formData.get("collection_id") as string | null;
    if (existingCollection) {
      const col = db.prepare("SELECT id, slug FROM collections WHERE id = ? AND user_id = ?").get(existingCollection, userId) as { id: string; slug: string } | undefined;
      if (!col) {
        return NextResponse.json({ error: "Collection not found or not owned" }, { status: 404 });
      }
      collectionId = col.id;
      slug = col.slug;
    } else {
      collectionId = nanoid();
      slug = nanoid(10);
      db.prepare("INSERT INTO collections (id, user_id, slug, title, description) VALUES (?, ?, ?, ?, ?)").run(collectionId, userId, slug, collectionTitle, collectionDesc);
    }

    const savedModules = [];
    for (const file of files) {
      const buffer = Buffer.from(await file.arrayBuffer());
      const encrypted = isEncrypted(buffer);
      const content = buffer.toString("utf8");
      const meta = encrypted ? null : parseWidgetMetadata(content);

      const moduleId = nanoid();
      const filename = file.name;

      db.prepare(
        `INSERT INTO modules (id, collection_id, filename, widget_id, title, description, version, author, file_size, is_encrypted)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).run(moduleId, collectionId, filename, meta?.id || null, meta?.title || filename.replace(".js", ""), meta?.description || "", meta?.version || null, meta?.author || null, file.size, encrypted ? 1 : 0);

      saveModule(collectionId, filename, buffer);

      savedModules.push({
        id: moduleId, filename, title: meta?.title || filename, version: meta?.version, encrypted,
      });
    }

    const siteUrl = process.env.SITE_URL || request.nextUrl.origin;

    return NextResponse.json({
      ...(isNewUser ? { token: rawToken } : {}),
      manageUrl: `${siteUrl}/manage/${rawToken}`,
      collection: {
        id: collectionId, slug,
        fwdUrl: `${siteUrl}/api/collections/${slug}/fwd`,
        pageUrl: `${siteUrl}/c/${slug}`,
      },
      modules: savedModules,
    });
  } catch (error) {
    console.error("Upload error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

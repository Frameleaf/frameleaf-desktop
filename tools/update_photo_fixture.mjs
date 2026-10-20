// Synthetic API qualification only; credentials stay in memory and requests stay on loopback.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { setTimeout } from "node:timers/promises";
import { crc32 } from "node:zlib";

const original = Buffer.from("iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAIAAAD8GO2jAAAAKklEQVR4nGNQaEigKWIYtWDUglELRi0YtWDUglELRi0YtWDUglELhooFAHfgAD2FaRhWAAAAAElFTkSuQmCC", "base64");
const hash = bytes => createHash("sha256").update(bytes).digest("hex");

export async function qualifyUpdatePhoto(base, password, proof) {
  const origin = new URL(base);
  assert.ok(origin.protocol === "http:" && origin.hostname === "127.0.0.1" && origin.port &&
    !origin.username && !origin.password && origin.pathname === "/" && !origin.search && !origin.hash,
  "photo_fixture_origin_invalid");
  const request = async (path, options = {}) => fetch(`${origin.origin}/api/${path}`, {
    ...options, redirect: "error", signal: AbortSignal.timeout(15000),
  });
  const credentials = { email: "native-update-photo@example.invalid", password };
  const authenticate = body => ({ method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  if (!proof) {
    const response = await request("auth/admin-sign-up", authenticate({ ...credentials, name: "Synthetic update qualification" }));
    assert.equal(response.status, 201, "synthetic account creation failed");
  }
  const login = await request("auth/login", authenticate(credentials));
  assert.equal(login.status, 201, "persisted account login failed");
  const { accessToken } = await login.json();
  assert.equal(typeof accessToken, "string");
  const headers = { authorization: `Bearer ${accessToken}` };
  const download = async (id, kind) => {
    const deadline = Date.now() + 120000;
    while (true) {
      const response = await request(`assets/${id}/${kind}`, { headers });
      if (response.ok) {
        assert.match(response.headers.get("content-type") ?? "", /^image\//);
        const bytes = Buffer.from(await response.arrayBuffer());
        assert.ok(bytes.length > 0);
        return bytes;
      }
      assert.ok(kind === "thumbnail" && response.status === 404 && Date.now() < deadline,
        "synthetic media unavailable");
      await response.arrayBuffer();
      await setTimeout(2000);
    }
  };
  const upload = async (bytes, name) => {
    const form = new FormData();
    form.set("fileCreatedAt", "2026-01-01T00:00:00.000Z");
    form.set("fileModifiedAt", "2026-01-01T00:00:00.000Z");
    form.set("assetData", new Blob([bytes], { type: "image/png" }), name);
    const response = await request("assets", { method: "POST", headers, body: form });
    assert.equal(response.status, 201, "synthetic photo upload failed");
    const result = await response.json();
    assert.equal(result.status, "created");
    assert.match(result.id, /^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/);
    assert.deepEqual(await download(result.id, "original"), bytes);
    const thumbnail = await download(result.id, "thumbnail");
    assert.notDeepEqual(thumbnail, bytes);
    return { id: result.id, name, originalSha256: hash(bytes), thumbnailSha256: hash(thumbnail) };
  };
  if (!proof) return upload(original, "synthetic-before-update.png");
  assert.match(proof.id, /^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/);
  const metadata = await request(`assets/${proof.id}`, { headers });
  assert.equal(metadata.status, 200);
  const value = await metadata.json();
  assert.equal(value.id, proof.id);
  assert.equal(value.originalFileName, proof.name);
  assert.equal(hash(await download(proof.id, "original")), proof.originalSha256);
  assert.equal(hash(await download(proof.id, "thumbnail")), proof.thumbnailSha256);
  // A valid PNG text chunk makes the new upload's checksum distinct without another fixture.
  const text = Buffer.from("tEXtFrameleaf\0after-update");
  const size = Buffer.alloc(4), checksum = Buffer.alloc(4);
  size.writeUInt32BE(text.length - 4);
  checksum.writeUInt32BE(crc32(text));
  const next = Buffer.concat([original.subarray(0, -12), size, text, checksum, original.subarray(-12)]);
  const uploaded = await upload(next, "synthetic-after-update.png");
  assert.notEqual(uploaded.id, proof.id);
  return { originalBytes: true, thumbnailBytes: true, newUpload: true };
}

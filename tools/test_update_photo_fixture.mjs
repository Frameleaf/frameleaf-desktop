import assert from "node:assert/strict";
import { createServer } from "node:http";
import { Readable } from "node:stream";
import { test } from "node:test";

async function fixture(t) {
  const assets = new Map();
  let damage;
  const server = createServer(async (request, response) => {
    try {
      const path = new URL(request.url, "http://127.0.0.1").pathname;
      const json = (value, status = 200) => {
        response.writeHead(status, { "content-type": "application/json" });
        response.end(JSON.stringify(value));
      };
      if (path.startsWith("/api/auth/")) {
        let body = "";
        for await (const chunk of request) body += chunk;
        assert.equal(JSON.parse(body).password, "synthetic photo password");
        return json(path.endsWith("login") ? { accessToken: "synthetic-token" } : {}, 201);
      }
      assert.equal(request.headers.authorization, "Bearer synthetic-token");
      if (path === "/api/assets" && request.method === "POST") {
        const form = await new Request("http://127.0.0.1/api/assets", {
          method: "POST", headers: request.headers,
          body: Readable.toWeb(request), duplex: "half",
        }).formData();
        const file = form.get("assetData");
        const id = `11111111-1111-4111-8111-${String(assets.size + 1).padStart(12, "0")}`;
        assets.set(id, { bytes: Buffer.from(await file.arrayBuffer()), name: file.name });
        return json({ id, status: "created" }, 201);
      }
      const [, id, kind] = path.match(/^\/api\/assets\/([^/]+)(?:\/(original|thumbnail))?$/) ?? [];
      const asset = assets.get(id);
      assert.ok(asset, "requested an unknown synthetic asset");
      if (!kind) return json({ id, originalFileName: asset.name });
      response.writeHead(200, { "content-type": "image/png" });
      response.end(damage === kind ? Buffer.from("changed") : kind === "original" ? asset.bytes : Buffer.from(`thumbnail:${id}`));
    } catch {
      response.writeHead(500); response.end();
    }
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  return { base: `http://127.0.0.1:${server.address().port}`, assets, damage: value => { damage = value; } };
}

async function helper() {
  const module = await import("./update_photo_fixture.mjs").catch(() => ({}));
  assert.equal(typeof module.qualifyUpdatePhoto, "function", "photo preservation helper is missing");
  return module.qualifyUpdatePhoto;
}

test("photo qualification verifies retained bytes and uploads distinct media after update", async t => {
  const qualify = await helper();
  const f = await fixture(t);
  const proof = await qualify(f.base, "synthetic photo password");
  const result = await qualify(f.base, "synthetic photo password", proof);
  assert.deepEqual(result, { originalBytes: true, thumbnailBytes: true, newUpload: true });
  assert.equal(f.assets.size, 2);
  const [before, after] = [...f.assets.values()];
  assert.notDeepEqual(before.bytes, after.bytes);
  assert.notEqual(before.name, after.name);
  assert.equal(JSON.stringify(proof).includes("password"), false);
});

test("photo qualification rejects changed original or thumbnail bytes", async t => {
  const qualify = await helper();
  for (const kind of ["original", "thumbnail"]) {
    const f = await fixture(t);
    const proof = await qualify(f.base, "synthetic photo password");
    f.damage(kind);
    await assert.rejects(qualify(f.base, "synthetic photo password", proof));
    assert.equal(f.assets.size, 1);
  }
});

test("photo fixture refuses non-loopback destinations before sending credentials", async () => {
  const qualify = await helper();
  for (const base of ["https://example.invalid", "http://127.0.0.1@localhost:8080", "http://127.0.0.1:8080/foreign"]) {
    await assert.rejects(qualify(base, "synthetic photo password"), /photo_fixture_origin_invalid/);
  }
});

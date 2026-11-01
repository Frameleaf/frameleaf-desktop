import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const source = await readFile(new URL("seed_host_restore_fixture.mjs", import.meta.url), "utf8");
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
// Exercise the actual finalizer without starting a server or accessing a credential store.
const cleanup = new AsyncFunction("adapter", "store", "initialized", "command", "database", "stopDatabase", "assert",
  source.match(/  } finally {\n([\s\S]*)\n  }\n}\s*$/)[1]);

for (const failure of ["none", "owner", "store", "status", "shutdown"]) {
  test(`fixture cleanup still joins every resource after ${failure} failure`, async () => {
    const calls = [];
    const expected = Error(failure);
    const action = name => {
      calls.push(name);
      if (failure === name) throw expected;
    };
    const work = cleanup({ stop: async () => action("owner") }, { close: () => action("store") }, true,
      async () => action("status"), "synthetic-database", async () => action("shutdown"), assert);
    if (failure === "none") await work;
    else await assert.rejects(work);
    assert.deepEqual(calls, failure === "status" ? ["owner", "store", "status"] : ["owner", "store", "status", "shutdown"]);
  });
}

test("fixture accepts only PostgreSQL's confirmed not-running status", async () => {
  const calls = [];
  await cleanup({ stop: async () => {} }, { close: () => calls.push("store") }, true,
    async () => { throw Object.assign(Error("not running"), { code: 3 }); }, "synthetic-database",
    async () => assert.fail("must not stop an already stopped database"), assert);
  assert.deepEqual(calls, ["store"]);
});

test("fixture skips PostgreSQL commands before initialization even after owner failure", async () => {
  let closed = false;
  await assert.rejects(cleanup({ stop: async () => { throw Error("owner failed"); } },
    { close: () => { closed = true; } }, false, async () => assert.fail("no database exists"), "synthetic-database",
    async () => assert.fail("no database exists"), assert), /owner failed/);
  assert.equal(closed, true);
});

const inspectRows = new AsyncFunction("mode", "sql", "console", "assert", "startDatabase", "stopDatabase", "database",
  source.slice(source.indexOf('if (mode === "selected") {'), source.indexOf('\n} else {', source.indexOf('if (mode === "selected") {'))) + '\n}');
for (const mode of ["selected", "original"]) {
  test(`${mode} fixture mode requires unchanged seeded content`, async () => {
    const literal = mode === "selected"
      ? source.match(/VALUES\('native-owner-qualification','([^']+)'\)/)[1]
      : source.match(/UPDATE system_metadata SET value='([^']+)'/)[1];
    const row = JSON.parse(literal);
    assert.equal(row.fixtureRow, "original-seeded-row");
    const inspect = value => inspectRows(mode, async query => {
      const field = query.match(/value->>'([^']+)'/)[1];
      return value[field] ?? "";
    }, { log() {} }, assert, async () => {}, async () => {}, "synthetic-database");
    await inspect(row);
    await assert.rejects(inspect({ label: row.label }), /original-seeded-row/);
    await assert.rejects(inspect({ ...row, fixtureRow: "replaced" }), /original-seeded-row/);
  });
}

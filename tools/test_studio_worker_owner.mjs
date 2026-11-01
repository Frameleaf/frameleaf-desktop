import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { Writable } from "node:stream";
import { test } from "node:test";
import { ownStudioWorker } from "../runtime/host-agent.mjs";

const engine = "a".repeat(40);
const ready = () => ({
  protocolVersion: 1,
  state: "ready",
  engineDigest: engine,
  expiresAt: new Date(Date.now() + 60 * 60_000).toISOString(),
});
const fixture = () => {
  const child = new EventEmitter();
  child.connected = true;
  child.exitCode = null;
  child.stdout = new EventEmitter();
  const input = [],
    kills = [];
  child.stdin = new Writable({
    write(chunk, _encoding, done) {
      input.push(chunk.toString());
      done();
    },
  });
  const exit = (code = 0) => {
    child.connected = false;
    child.exitCode = code;
    child.emit("disconnect");
    child.emit("exit", code, null);
  };
  const close = () => child.emit("close", child.exitCode, null);
  child.kill = (signal) => {
    kills.push(signal);
    exit(1);
    close();
    return true;
  };
  return {
    child,
    input,
    kills,
    exit,
    close,
    owner: ownStudioWorker(child, engine),
  };
};

test("Studio owner trusts only valid IPC and clears readiness on requalification", async () => {
  const f = fixture();
  try {
    assert.equal(f.owner.check(), false);
    f.child.stdout.emit("data", Buffer.from(JSON.stringify(ready())));
    assert.equal(f.owner.check(), false);
    f.child.emit("message", ready());
    assert.equal(f.owner.check(), true);
    f.child.emit("message", { protocolVersion: 1, state: "qualifying" });
    assert.equal(f.owner.check(), false);
    f.child.emit("message", ready());
    assert.equal(f.owner.check(), true);
  } finally {
    f.exit();
    f.close();
    await f.owner.stop();
  }
});

test("Studio owner invalidates ready status on disconnect, exit or protocol failure", async () => {
  for (const event of ["disconnect", "exit", "error", "bad-message"]) {
    const f = fixture();
    try {
      f.child.emit("message", ready());
      assert.equal(f.owner.check(), true);
      if (event === "bad-message")
        f.child.emit("message", {
          ...ready(),
          sessionToken: "synthetic-secret",
        });
      else f.child.emit(event);
      assert.throws(() => f.owner.check(), /host_studio_/);
      f.child.emit("message", ready());
      assert.throws(() => f.owner.check(), /host_studio_/);
    } finally {
      f.exit();
      f.close();
      await f.owner.stop();
    }
  }
});

test("Studio owner bounds qualification and expires readiness at renewal", async (t) => {
  const now = Date.parse("2026-10-16T12:00:00.000Z");
  t.mock.timers.enable({ apis: ["Date"], now });
  const initial = fixture();
  try {
    t.mock.timers.setTime(now + 10 * 60_000);
    assert.throws(() => initial.owner.check(), /host_studio_not_ready/);
    initial.child.emit("message", ready());
    assert.throws(() => initial.owner.check(), /host_studio_not_ready/);
  } finally {
    initial.exit();
    initial.close();
    await initial.owner.stop();
  }
  const admitted = fixture();
  try {
    admitted.child.emit("message", ready());
    assert.equal(admitted.owner.check(), true);
    t.mock.timers.setTime(now + 60 * 60_000);
    assert.equal(admitted.owner.check(), false);
    t.mock.timers.setTime(now + 70 * 60_000);
    assert.throws(() => admitted.owner.check(), /host_studio_not_ready/);
  } finally {
    admitted.exit();
    admitted.close();
    await admitted.owner.stop();
  }
});

test("Studio drain writes one stop command and joins pipe close, not just process exit", async () => {
  const f = fixture();
  f.child.emit("message", ready());
  let settled = false;
  const drain = f.owner.stop();
  drain.then(
    () => {
      settled = true;
    },
    () => {
      settled = true;
    },
  );
  try {
    assert.equal(f.owner.stop(), drain);
    assert.equal(f.owner.check(), false);
    assert.deepEqual(f.input, ["stop\n"]);
    f.exit();
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(settled, false);
    f.close();
    await drain;
    assert.deepEqual(f.kills, []);
    assert.deepEqual(f.input, ["stop\n"]);
  } finally {
    f.exit();
    f.close();
    await drain;
  }
});

test("a broken stop pipe forces and joins the child before reporting drain failure", async () => {
  const f = fixture();
  f.child.stdin.end = () => {
    throw new Error("synthetic broken pipe");
  };
  await assert.rejects(f.owner.stop(), /host_studio_drain_failed/);
  assert.deepEqual(f.kills, ["SIGKILL"]);
  assert.equal(f.owner.check(), false);
});

test("a Studio worker missing its graceful deadline is forced and reported as failed", async (t) => {
  t.mock.timers.enable({ apis: ["Date", "setTimeout"], now: 1000 });
  const f = fixture();
  const stopping = assert.rejects(f.owner.stop(), /host_studio_drain_failed/);
  t.mock.timers.tick(35_000);
  await stopping;
  assert.deepEqual(f.kills, ["SIGKILL"]);
});

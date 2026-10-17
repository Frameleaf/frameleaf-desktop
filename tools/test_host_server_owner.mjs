import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { test } from "node:test";
import { ownHostServer } from "../runtime/host-agent.mjs";

const fixture = () => {
  const child = new EventEmitter();
  const sent = [],
    kills = [];
  child.connected = true;
  child.exitCode = null;
  child.stdout = new EventEmitter();
  child.send = (value, callback) => {
    sent.push(value);
    callback(null);
    return true;
  };
  const exit = (code = 0) => {
    child.exitCode = code;
    child.connected = false;
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
  return { child, sent, kills, exit, close, owner: ownHostServer(child) };
};

test("server ownership requires its private acknowledgement, not a stdout marker", async () => {
  const f = fixture();
  try {
    assert.equal(f.owner.check(), false);
    f.child.stdout.emit("data", "frameleaf:owner-ready:v1\n");
    assert.equal(f.owner.check(), false);
    f.child.emit("message", "frameleaf:owner-ready:v1");
    assert.equal(f.owner.check(), true);
    f.child.emit("disconnect");
    assert.throws(() => f.owner.check(), /host_server_disconnected/);
  } finally {
    f.exit();
    f.close();
    await f.owner.stop();
  }
});

test("invalid ownership messages cannot be cleared by a later acknowledgement", async () => {
  const f = fixture();
  try {
    f.child.emit("message", { ready: true, sessionToken: "synthetic-secret" });
    f.child.emit("message", "frameleaf:owner-ready:v1");
    assert.throws(() => f.owner.check(), /host_server_protocol_invalid/);
  } finally {
    f.exit();
    f.close();
    await f.owner.stop();
  }
});

test("server drain sends once and joins every captured pipe before returning", async () => {
  const f = fixture();
  let settled = false;
  const stopping = f.owner.stop();
  stopping.then(
    () => {
      settled = true;
    },
    () => {
      settled = true;
    },
  );
  try {
    assert.equal(f.owner.stop(), stopping);
    assert.equal(f.owner.check(), false);
    assert.deepEqual(f.sent, ["frameleaf:stop"]);
    f.exit();
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(settled, false);
    f.close();
    await stopping;
    assert.deepEqual(f.kills, []);
  } finally {
    f.exit();
    f.close();
    await stopping;
  }
});

test("server control failure is reported only after the process and pipes close", async () => {
  const f = fixture();
  f.child.send = (_value, callback) => {
    callback(new Error("synthetic IPC failure"));
    return false;
  };
  const stopping = assert.rejects(f.owner.stop(), /host_server_drain_failed/);
  f.exit();
  f.close();
  await stopping;
});

test("a server missing its graceful deadline is forced and reported as failed", async (t) => {
  t.mock.timers.enable({ apis: ["Date", "setTimeout"], now: 1000 });
  const f = fixture();
  const stopping = assert.rejects(f.owner.stop(), /host_server_drain_failed/);
  t.mock.timers.tick(40_000);
  await stopping;
  assert.deepEqual(f.kills, ["SIGKILL"]);
});

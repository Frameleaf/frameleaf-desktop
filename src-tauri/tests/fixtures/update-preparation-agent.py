import base64, json, os, sys, uuid

source = base64.b64decode(sys.stdin.readline().strip(), validate=True)
assert b"host_update_preparation_failed" in source
assert max(map(len, sys.argv)) < 8000
request = json.loads(sys.stdin.readline())
c, update = request["configuration"], request["update"]
assert c["mode"] == "restore-prepare"
assert c["password"] == "synthetic existing database password"
os.fstat(int(os.environ["FRAMELEAF_MANAGER_PROFILE_FD"]))
os.fstat(int(os.environ["FRAMELEAF_CODE_LEASE_FD"]))

def record(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(value)

def identity(path):
    s = os.stat(path)
    return str(s.st_dev) + ":" + str(s.st_ino)

if "prepared" in request:
    receipt = request["prepared"]
    assert receipt["state"] == "update-prepared" and receipt["update"] == update
    state = c["state"]
    with os.fdopen(os.open(os.path.join(state, "update-verification-started"), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600), "wb") as f:
        f.write(b"v")
    target = os.path.join(state, "restore-targets", receipt["binding"]["operationId"], receipt["attemptId"])
    with open(os.path.join(target, "restore-result.json")) as f:
        assert json.load(f) == receipt
    assert identity(os.path.join(target, "database")) == receipt["databaseIdentity"]
    with open(os.path.join(state, "host-state.json")) as f:
        assert json.load(f)["manifestSha256"] == c["manifestSha256"]
    if MODE == "verification-failed":
        sys.exit(1)
    if MODE == "verification-hang":
        assert sys.stdin.readline() == "stop\n"
        record(os.path.join(state, "update-verification-stop"), "stopped")
        sys.exit(0)
    if MODE == "verification-profile":
        with open(os.path.join(os.path.splitext(state)[0] + ".manager", ".host-profile"), "w") as f:
            f.write("0" * 64)
    if MODE == "verification-source":
        with open(os.path.join(state, "host-state.json"), "w") as f:
            f.write("{}")
    if MODE == "verification-dump":
        with open(os.path.join(state, "restore-input", receipt["binding"]["operationId"], "input", "database.dump"), "w") as f:
            f.write("changed after fresh checks")
    if MODE == "verification-original":
        os.rename(os.path.join(state, "database"), os.path.join(state, "retained-original"))
        os.mkdir(os.path.join(state, "database"), 0o700)
    if MODE == "verification-foreign":
        receipt["attemptId"] = str(uuid.uuid4())
    print(json.dumps({"state": "update-verified", "prepared": receipt, "offlineChecksums": MODE != "verification-unchecked", "schemaValidated": MODE != "verification-unschemed"}), flush=True)
    sys.exit(0)

if MODE == "nonzero":
    sys.exit(1)
state = c["state"]
binding = update["restore"]
attempt = str(uuid.uuid4())
root = os.path.join(state, "restore-targets")
operation = os.path.join(root, binding["operationId"])
target = os.path.join(operation, attempt)
database = os.path.join(target, "database")
for directory in [root, operation, target, database]:
    try:
        os.mkdir(directory, 0o700)
    except FileExistsError:
        assert directory == root
record(os.path.join(database, "PG_VERSION"), "19\n")
marker = {"schemaVersion": 1, "manifestSha256": c["manifestSha256"], "sourceRevision": c["sourceRevision"], "postgresMajor": "19"}
record(os.path.join(target, "host-state.json"), json.dumps(marker))
intent = {"schemaVersion": 1, "binding": binding, "attemptId": attempt, "profileIdentity": identity(state), "targetIdentity": identity(target), "update": update}
record(os.path.join(target, "restore-target.json"), json.dumps(intent))
receipt = {**intent, "state": "update-prepared", "databaseIdentity": identity(database), "validation": {"postgresMajor": 19, "vectorVersion": "0.8.7", "canonical": True, "executionStateReconstructed": True}}
on_disk = dict(receipt)
if MODE == "record":
    on_disk["targetIdentity"] = "0:0"
record(os.path.join(target, "restore-result.json"), json.dumps(on_disk))
if MODE == "pid":
    record(os.path.join(database, "postmaster.pid"), str(os.getpid()))
if MODE == "state":
    receipt["state"] = "restore-prepared"
if MODE == "binding":
    receipt["update"]["sourceEpoch"] = 999
if MODE == "source-marker":
    with open(os.path.join(state, "host-state.json"), "w") as f:
        f.write(json.dumps(marker))
if MODE == "hang":
    record(os.path.join(state, "update-child-started"), "ready")
    assert sys.stdin.readline() == "stop\n"
    record(os.path.join(state, "update-stop-received"), "stopped")
    sys.exit(0)
proof = {"state": "update-verified", "prepared": receipt, "offlineChecksums": True, "schemaValidated": True}
if MODE == "proof-state":
    proof["state"] = "restore-verified"
if MODE == "unchecked":
    proof["offlineChecksums"] = False
if MODE == "unschemed":
    proof["schemaValidated"] = False
if MODE == "proof-extra":
    proof["path"] = "/outside"
if MODE == "unverified":
    proof = receipt
print(json.dumps(proof), flush=True)
if MODE == "extra":
    print("extra frame", flush=True)

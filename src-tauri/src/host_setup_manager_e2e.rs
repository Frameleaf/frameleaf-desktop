//! Opt-in end-to-end run against an installed companion and its real Manager, photo server and
//! database. Never part of an ordinary test run: every test here is ignored, and refuses to
//! start outside the disposable machine `tools/manager_e2e/run.sh` builds. Each test owns one
//! account's library, started and stopped through the same calls the interface makes.
use super::*;
use crate::manager::{Action, Command};
use crate::manager_local::{Features, Ports};
use crate::manager_tls::TlsIdentity;
use std::{
    io::{Read, Write},
    path::PathBuf,
    time::Instant,
};

const DAY: i64 = 24 * 60 * 60;
/// How often an operation is asked about. Manager allows one address 120 paired requests in
/// ten minutes, and refuses the rest of those ten minutes once that is spent.
const POLL: Duration = Duration::from_secs(5);
fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}
fn fingerprint(pem: &str) -> String {
    crate::manager::certificate_fingerprint(pem).unwrap()
}
/// Whether Manager's reply names this port's listener as the photo server.
async fn pong(port: u16) -> bool {
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    // The photo server is local: plain HTTP on loopback.
    match client
        .get(format!("http://127.0.0.1:{port}/api/server/ping"))
        .timeout(Duration::from_secs(10))
        .send()
        .await
    {
        Ok(reply) => reply.text().await.is_ok_and(|body| body.contains("pong")),
        Err(_) => false,
    }
}

/// What another program on a loopback port does with a connection.
#[derive(Clone, Copy)]
enum Answer {
    /// Answers in plain text: not TLS, so provably not this library's Manager.
    Plain,
    /// Accepts and says nothing: proves nothing.
    Silent,
}
/// Another program holding a loopback port until dropped.
struct Other {
    done: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
fn other(port: u16, answer: Answer) -> Other {
    let listener = std::net::TcpListener::bind(("127.0.0.1", port))
        .unwrap_or_else(|error| panic!("port {port} must be free for another program: {error}"));
    listener.set_nonblocking(true).unwrap();
    let done = Arc::new(AtomicBool::new(false));
    let stop = done.clone();
    let thread = std::thread::spawn(move || {
        let mut held = Vec::new();
        while !stop.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.set_nonblocking(false);
                    match answer {
                        Answer::Plain => {
                            let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
                            let _ = stream.read(&mut [0u8; 64]);
                            let _ = stream.write_all(
                                b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n",
                            );
                        }
                        Answer::Silent => held.push(stream),
                    }
                }
                Err(_) => std::thread::sleep(Duration::from_millis(10)),
            }
        }
    });
    Other {
        done,
        thread: Some(thread),
    }
}
impl Drop for Other {
    fn drop(&mut self) {
        self.done.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// What Manager reported about its controller, and what opening Photos answered just after.
type Sample = (String, Result<String, String>);
/// One account's library on the installed package named by the environment.
struct Lab {
    setup: HostSetup,
    manifest: String,
    state: PathBuf,
    data: PathBuf,
    password: zeroize::Zeroizing<String>,
    bound: std::sync::OnceLock<(String, String)>,
}
/// What the keystore holds for a profile's TLS identity, as stored.
struct Identities {
    current: Option<serde_json::Value>,
    pending: Option<serde_json::Value>,
}
impl Identities {
    fn certificate(value: &Option<serde_json::Value>) -> Option<String> {
        value
            .as_ref()
            .map(|value| value["certificatePem"].as_str().unwrap().to_owned())
    }
    fn current_certificate(&self) -> Option<String> {
        Self::certificate(&self.current)
    }
}
impl Lab {
    fn new() -> Self {
        Self::on(&std::env::var("FRAMELEAF_MANAGER_E2E_MANIFEST").expect("the installed package"))
    }
    fn on(manifest: &str) -> Self {
        assert_eq!(
            std::env::var("FRAMELEAF_MANAGER_E2E").as_deref(),
            Ok("disposable"),
            "only inside the machine tools/manager_e2e/run.sh builds"
        );
        assert_ne!(unsafe { libc::geteuid() }, 0, "an unprivileged account");
        let profile = crate::host_install::account_profile();
        Self {
            setup: HostSetup::default(),
            manifest: manifest.into(),
            state: profile.join("state"),
            data: profile.join("manager"),
            // The same in every process of one account, so a later one can authorize again.
            password: zeroize::Zeroizing::new(format!(
                "Synthetic-manager-{}-end-to-end!",
                unsafe { libc::geteuid() }
            )),
            bound: std::sync::OnceLock::new(),
        }
    }
    /// The keystore binding a start uses for this profile, and the library's installation
    /// identity, from the same configuration `launch` derives. First read while Manager is
    /// stopped; neither changes afterwards.
    fn bound(&self) -> &(String, String) {
        self.bound.get_or_init(|| {
            let record = Installation::read(&self.manifest).expect("the installed package");
            let (layout, runtime) = verified(&record).expect("the package verifies");
            let uid = unsafe { libc::geteuid() };
            let recorded = crate::manager_local::recorded(&self.data).unwrap();
            let mut settings = configuration(
                &record,
                &layout,
                &runtime,
                &uid,
                self.state.clone(),
                self.data.clone(),
                recorded.ports,
            )
            .unwrap();
            if let Some(marker) = crate::host_state::Owner::peek(&self.state).unwrap() {
                settings.installation_id = marker.installation_id;
            }
            let binding = crate::manager_profile::Profile::from_keystore(
                &settings,
                &layout.runtime,
                runtime.manifest_sha256(),
            )
            .unwrap()
            .binding()
            .to_owned();
            (binding, settings.installation_id)
        })
    }
    fn features(&self) -> Features {
        let record = Installation::read(&self.manifest).expect("the installed package");
        Features::of_package(&record.layout().unwrap().runtime)
    }
    fn identities(&self) -> Identities {
        let binding = &self.bound().0;
        Identities {
            current: crate::credentials::load(&format!("native-manager-tls-{binding}")).unwrap(),
            pending: crate::credentials::load(&format!("native-manager-tls-next-{binding}"))
                .unwrap(),
        }
    }
    /// Put the keystore in a state an earlier start, or a crash, would have left.
    fn save_identities(
        &self,
        current: Option<&serde_json::Value>,
        pending: Option<&serde_json::Value>,
    ) {
        let binding = &self.bound().0;
        if let Some(current) = current {
            crate::credentials::save(&format!("native-manager-tls-{binding}"), current).unwrap();
        }
        let account = format!("native-manager-tls-next-{binding}");
        match pending {
            Some(identity) => crate::credentials::save(
                &account,
                &serde_json::json!({
                    "schemaVersion": 1,
                    "operationId": uuid::Uuid::new_v4(),
                    "identity": identity,
                }),
            )
            .unwrap(),
            None => crate::credentials::delete(&account).unwrap(),
        }
    }
    /// An identity for this library issued `age` seconds ago; identities last 365 days.
    fn issued(&self, age: i64) -> serde_json::Value {
        let origin = self.record().ports.origin();
        serde_json::to_value(TlsIdentity::issued_at(&self.bound().1, &origin, now() - age).unwrap())
            .unwrap()
    }
    async fn start(&self) -> Result<View, String> {
        let started = Instant::now();
        let result = self.setup.start(self.manifest.clone()).await;
        println!(
            "start: {:?} in {:.1}s",
            result.as_ref().map(|view| view.state.clone()),
            started.elapsed().as_secs_f32()
        );
        result
    }
    /// The last attempt `start` makes after a renewed identity failed: no renewal.
    async fn start_without_renewing(&self) -> Result<(), String> {
        let record = Installation::read(&self.manifest)?;
        let cancel = Arc::new(AtomicBool::new(false));
        let mut running = {
            let (record, cancel) = (record.clone(), cancel.clone());
            tauri::async_runtime::spawn_blocking(move || {
                launch(
                    &record,
                    &cancel,
                    None,
                    &std::sync::atomic::AtomicUsize::new(0),
                )
            })
            .await
            .map_err(|_| "native_host_setup_failed".to_string())??
        };
        running
            .manager
            .wait_ready(Duration::from_secs(20), &cancel)
            .await?;
        settle_identity(&mut running);
        let mut owner = self.setup.owner.lock().await;
        self.setup.adopt(&mut owner, running);
        self.setup.set("manager-ready", None, Some(record));
        Ok(())
    }
    async fn stop(&self) {
        self.setup.stop().await.expect("Manager stops");
    }
    async fn ports(&self) -> Ports {
        let mut owner = self.setup.owner.lock().await;
        owner
            .as_mut()
            .expect("running")
            .configuration
            .ports()
            .unwrap()
    }
    /// The certificate the running Manager was started with.
    async fn served(&self) -> String {
        let mut owner = self.setup.owner.lock().await;
        owner
            .as_mut()
            .expect("running")
            .manager
            .certificate()
            .to_owned()
    }
    fn record(&self) -> crate::manager_local::Record {
        crate::manager_local::recorded(&self.data).unwrap()
    }
    fn grant(&self) -> crate::manager::SavedManager {
        crate::credentials::load(crate::manager::CREDENTIAL)
            .unwrap()
            .expect("this computer is paired")
    }
    async fn authorize(&self) {
        let view = self
            .setup
            .authorize(self.password.clone(), false)
            .await
            .expect("this computer pairs with its own Manager");
        println!("paired with {} ({})", view.origin, view.installation_id);
    }
    async fn ask(&self, command: Command) -> Result<serde_json::Value, String> {
        crate::manager::send(&self.grant(), &crate::credentials::identity()?, command).await
    }
    /// A command Manager accepts only shortly after its password was entered: when that has
    /// lapsed, the password is entered again, as the interface asks a person to.
    async fn ask_recent(&self, command: impl Fn() -> Command) -> Result<serde_json::Value, String> {
        match self.ask(command()).await {
            Err(code) if code == "manager_recent_auth_required" => {
                self.authorize().await;
                self.ask(command()).await
            }
            other => other,
        }
    }
    async fn runtime(&self) -> Result<serde_json::Value, String> {
        self.ask(Command::Runtime {
            nonce: uuid::Uuid::new_v4(),
        })
        .await
    }
    /// What Manager says its controller is doing, as `state` or `state:code`.
    async fn photo_server(&self) -> String {
        let reply = self
            .runtime()
            .await
            .expect("Manager answers the runtime route");
        let server = &reply["photoServer"];
        match server["code"].as_str() {
            Some(code) => format!("{}:{code}", server["state"].as_str().unwrap()),
            None => server["state"].as_str().unwrap().to_owned(),
        }
    }
    async fn photos(&self) -> Result<String, String> {
        self.setup.photos_url().await.map(String::from)
    }
    /// Run one Manager operation to its end.
    async fn control(&self, action: Action) -> Result<(), String> {
        self.follow(action, false).await.map(drop)
    }
    /// The same, sampling while it runs what Manager reports about its controller and, each
    /// time that changes, whether Photos would open.
    async fn control_sampled(&self, action: Action) -> Result<Vec<Sample>, String> {
        self.follow(action, true).await
    }
    async fn follow(&self, action: Action, sample: bool) -> Result<Vec<Sample>, String> {
        let name = serde_json::to_string(&action).unwrap();
        let started = Instant::now();
        let key = uuid::Uuid::new_v4();
        let accepted = self.ask_recent(|| Command::Control { action, key }).await?;
        let id = uuid::Uuid::parse_str(accepted["id"].as_str().unwrap()).unwrap();
        let mut seen: Vec<Sample> = Vec::new();
        loop {
            if sample {
                let state = self.photo_server().await;
                if seen.last().is_none_or(|(last, _)| *last != state) {
                    seen.push((state, self.photos().await));
                }
            }
            let operation = self.ask(Command::Operation { id }).await?;
            match operation["state"].as_str() {
                Some("complete") => break,
                Some("running") => {}
                _ => return Err(format!("{name} ended as {operation}")),
            }
            if started.elapsed() > Duration::from_secs(20 * 60) {
                return Err(format!("{name} did not finish"));
            }
            tokio::time::sleep(POLL).await;
        }
        println!(
            "{name}: complete in {:.1}s; seen while it ran: {seen:?}",
            started.elapsed().as_secs_f32()
        );
        Ok(seen)
    }
    /// The update gate, against this account's real library.
    fn update_gate(&self) -> Result<(), String> {
        self.setup
            .lock_for_update_at(Some(Hosted {
                state: &self.state,
                data: &self.data,
                listener: &|| crate::manager_local::recorded_manager_listener(&self.data),
                process: &crate::process_tree::ProcessIdentity::lookup,
            }))
            .map(drop)
    }
}
/// Every sample taken while an operation ran: Photos opened only while Manager said `running`.
fn opened_only_while_running(seen: &[Sample]) {
    for (state, opened) in seen {
        match (state.as_str(), opened) {
            // The two are separate requests; a state that changed in between is not a fault.
            (_, Err(code)) => assert!(
                [
                    "local_photos_starting",
                    "local_photos_maintenance",
                    "local_photos_not_running"
                ]
                .contains(&code.as_str()),
                "{state}: refused with {code}"
            ),
            (state, Ok(_)) => assert!(
                state == "running" || state == "starting",
                "Photos opened while Manager reported {state}"
            ),
        }
    }
}

/// (d) A Manager that declares nothing: no route is asked, no port is moved, no identity is
/// renewed, and a busy port refuses the start with the port named.
#[tokio::test]
#[ignore = "end-to-end: run tools/manager_e2e/run.sh"]
async fn a_manager_that_declares_nothing_is_started_exactly_as_before() {
    let lab = Lab::new();
    assert_eq!(lab.features(), Features::default());
    // An identity in its last 30 days, as a library started eleven months ago holds.
    let due = lab.issued(340 * DAY);
    lab.save_identities(Some(&due), None);
    let due = Identities::certificate(&Some(due)).unwrap();

    let view = lab.start().await.expect("the released Manager starts");
    assert_eq!(view.state, "manager-ready");
    assert_eq!(lab.served().await, due, "the saved identity, not a renewal");
    let identities = lab.identities();
    assert_eq!(identities.current_certificate().as_deref(), Some(&*due));
    assert!(identities.pending.is_none(), "nothing was renewed");
    assert_eq!(view.certificate_expires_in_days, Some(25));
    assert!(!view.certificate_renewable);
    assert_eq!(lab.ports().await, Ports::default());
    assert_eq!(lab.record().ports, Ports::default());
    lab.authorize().await;
    assert_eq!(lab.photos().await.unwrap_err(), "local_photos_not_running");
    // This Manager has no runtime route: had Desktop asked, opening Photos below would fail.
    println!("runtime route on this Manager: {:?}", lab.runtime().await);
    assert!(lab.runtime().await.is_err());
    lab.control(Action::Start).await.unwrap();
    assert_eq!(lab.photos().await.unwrap(), "http://127.0.0.1:2283/");
    assert!(pong(2283).await);
    assert_eq!(lab.update_gate().unwrap_err(), "update_host_active");
    lab.control(Action::Stop).await.unwrap();
    assert_eq!(lab.photos().await.unwrap_err(), "local_photos_not_running");
    lab.stop().await;
    lab.update_gate()
        .expect("a stopped library does not block an update");

    for port in [2283, 54329, 9443] {
        let _held = other(port, Answer::Plain);
        assert_eq!(
            lab.start().await.unwrap_err(),
            format!("local_port_in_use_{port}")
        );
        assert_eq!(lab.record().ports, Ports::default(), "nothing moved");
    }
    lab.start()
        .await
        .expect("starts again once the ports are free");
    assert_eq!(lab.ports().await, Ports::default());
    assert_eq!(lab.served().await, due);
    lab.stop().await;
}

/// (a) Photos open only while Manager says its own controller is serving them.
#[tokio::test]
#[ignore = "end-to-end: run tools/manager_e2e/run.sh"]
async fn photos_open_only_while_manager_reports_its_controller_serving_them() {
    let lab = Lab::new();
    assert!(lab.features().runtime_status);
    lab.start().await.expect("Manager starts");
    lab.authorize().await;

    let reply = lab.runtime().await.unwrap();
    println!("runtime: {reply}");
    // A Manager that has not started its controller yet has nothing to report about it.
    assert_eq!(
        lab.photo_server().await,
        "unknown:native_owner_not_attached"
    );
    assert_eq!(reply["ports"]["manager"], 9443);
    assert_eq!(reply["ports"]["api"], 2283);
    assert_eq!(reply["ports"]["database"], 54329);
    assert_eq!(
        reply["capabilities"],
        serde_json::json!(["runtime-status", "ports", "tls-rotation"])
    );
    assert_eq!(lab.photos().await.unwrap_err(), "local_photos_not_running");
    {
        // Another program answers on the photo port while this library's server is stopped.
        let _held = other(2283, Answer::Plain);
        assert_eq!(lab.photos().await.unwrap_err(), "local_photos_not_running");
    }

    let seen = lab.control_sampled(Action::Start).await.unwrap();
    opened_only_while_running(&seen);
    assert_eq!(lab.photo_server().await, "running");
    assert_eq!(lab.photos().await.unwrap(), "http://127.0.0.1:2283/");
    assert!(pong(2283).await, "the photo server answers there");

    // A backup takes the controller out of photo-serving mode.
    let seen = lab.control_sampled(Action::Backup).await.unwrap();
    opened_only_while_running(&seen);
    let after = lab.photo_server().await;
    println!("after the backup Manager reports {after}");
    if after == "running" {
        assert!(lab.photos().await.is_ok());
    } else {
        assert!(lab.photos().await.is_err());
        lab.control(Action::Start).await.unwrap();
    }

    lab.control(Action::Stop).await.unwrap();
    assert_eq!(lab.photo_server().await, "stopped");
    assert_eq!(lab.photos().await.unwrap_err(), "local_photos_not_running");

    // A backup of a stopped library runs its controller with the database alone. The
    // controller holds the journal then, but it is not serving photos.
    let seen = lab.control_sampled(Action::Backup).await.unwrap();
    opened_only_while_running(&seen);
    assert!(
        seen.iter().any(|(state, opened)| {
            state == "unknown:native_database_maintenance"
                && matches!(opened, Err(code) if code == "local_photos_maintenance")
        }),
        "maintenance was not seen: {seen:?}"
    );
    assert_eq!(lab.photos().await.unwrap_err(), "local_photos_not_running");
    lab.stop().await;
}

/// (b) Each of the three ports moves off a port another program holds, the library stays on
/// its ports afterwards, and everything that names a port reads the saved one.
#[tokio::test]
#[ignore = "end-to-end: run tools/manager_e2e/run.sh"]
async fn each_busy_port_moves_and_every_consumer_follows_the_saved_port() {
    let lab = Lab::new();
    assert!(lab.features().ports && lab.features().runtime_status);
    let defaults = Ports::default();
    lab.bound();
    // A library that has run on the default ports, so Manager holds a descriptor naming them.
    lab.start().await.expect("first start");
    lab.authorize().await;
    lab.control(Action::Start).await.unwrap();
    assert!(pong(defaults.api).await);
    lab.control(Action::Stop).await.unwrap();
    lab.stop().await;
    let paired = lab.grant().view();
    assert_eq!(paired.origin, defaults.origin());

    // The photo port.
    let photo = other(defaults.api, Answer::Plain);
    lab.start().await.expect("starts beside a busy photo port");
    let moved = Ports {
        api: defaults.api + 1,
        ..defaults
    };
    assert_eq!(lab.ports().await, moved);
    assert_eq!(
        lab.record().ports,
        moved,
        "saved before Manager was started"
    );
    let reply = lab.runtime().await.unwrap();
    assert_eq!(
        reply["ports"]["api"], moved.api,
        "Manager was given the port"
    );
    lab.control(Action::Start).await.unwrap();
    assert_eq!(
        lab.photos().await.unwrap(),
        format!("http://127.0.0.1:{}/", moved.api)
    );
    assert!(
        pong(moved.api).await,
        "the photo server listens on the moved port"
    );
    assert!(
        !pong(defaults.api).await,
        "the other program still holds the default"
    );
    lab.control(Action::Stop).await.unwrap();
    lab.stop().await;
    drop(photo);
    // Once moved, a library stays where it is.
    lab.start().await.expect("starts again");
    assert_eq!(lab.ports().await, moved);
    lab.stop().await;

    // The database port.
    let database = other(defaults.database, Answer::Silent);
    lab.start()
        .await
        .expect("starts beside a busy database port");
    let moved = Ports {
        database: defaults.database + 1,
        ..moved
    };
    assert_eq!(lab.ports().await, moved);
    assert_eq!(lab.record().ports, moved);
    assert_eq!(
        lab.runtime().await.unwrap()["ports"]["database"],
        moved.database
    );
    lab.control(Action::Start).await.unwrap();
    assert_eq!(
        crate::manager_host::listener(moved.database),
        Evidence::Running,
        "the database listens on the moved port"
    );
    assert!(pong(moved.api).await);
    lab.control(Action::Stop).await.unwrap();
    lab.stop().await;
    drop(database);

    // Manager's own port: only from a listener proven to be another program's.
    {
        let _silent = other(defaults.manager, Answer::Silent);
        assert_eq!(
            lab.start().await.unwrap_err(),
            format!("local_port_in_use_{}", defaults.manager),
            "a listener that proves nothing is not moved away from"
        );
        assert_eq!(lab.record().ports, moved);
    }
    let manager = other(defaults.manager, Answer::Plain);
    lab.start()
        .await
        .expect("starts beside a busy Manager port");
    let moved = Ports {
        manager: defaults.manager + 1,
        ..moved
    };
    assert_eq!(lab.ports().await, moved);
    assert_eq!(lab.record().ports, moved);
    // This computer's grant followed its own Manager: no new pairing, same grant.
    let followed = lab.grant().view();
    assert_eq!(followed.origin, moved.origin());
    assert_eq!(followed.manager_id, paired.manager_id);
    assert_eq!(followed.certificate_sha256, paired.certificate_sha256);
    lab.ask(Command::Status {})
        .await
        .expect("Manager kept the grant across its own port change");
    assert_eq!(
        lab.runtime().await.unwrap()["ports"]["manager"],
        moved.manager
    );
    // The saved TLS identity follows the port too.
    assert_eq!(
        lab.identities().current.unwrap()["origin"],
        moved.origin().as_str()
    );
    lab.control(Action::Start).await.unwrap();
    assert_eq!(
        lab.photos().await.unwrap(),
        format!("http://127.0.0.1:{}/", moved.api)
    );
    assert!(pong(moved.api).await);
    // The update gate reads the saved port: this library's Manager is there, not on 9443.
    assert_eq!(lab.update_gate().unwrap_err(), "update_host_active");
    lab.control(Action::Stop).await.unwrap();
    lab.stop().await;
    lab.update_gate()
        .expect("the other program on the default Manager port does not block an update");
    {
        // On the saved port, what cannot be identified blocks; what is proven foreign does not.
        let _silent = other(moved.manager, Answer::Silent);
        assert_eq!(lab.update_gate().unwrap_err(), "update_library_not_idle");
    }
    {
        let _plain = other(moved.manager, Answer::Plain);
        lab.update_gate()
            .expect("another program's listener is not this library's Manager");
    }
    drop(manager);

    lab.start()
        .await
        .expect("starts with every default port free again");
    assert_eq!(lab.ports().await, moved, "the library stays on its ports");
    lab.control(Action::Start).await.unwrap();
    assert!(pong(moved.api).await);
    lab.control(Action::Stop).await.unwrap();
    lab.stop().await;
}

/// (c) Renewal, re-pinning, the grace period, a handover Manager refuses, and identities that
/// ran out. `FRAMELEAF_MANAGER_E2E_SHORT` is how many seconds a short-lived identity lasts.
#[tokio::test]
#[ignore = "end-to-end: run tools/manager_e2e/run.sh"]
async fn the_tls_identity_is_renewed_and_no_refused_handover_leaves_the_library_stopped() {
    let lab = Lab::new();
    assert!(lab.features().tls_rotation);
    let short: i64 = std::env::var("FRAMELEAF_MANAGER_E2E_SHORT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(150);
    let certificate =
        |value: &serde_json::Value| value["certificatePem"].as_str().unwrap().to_owned();
    let pinned = |lab: &Lab| lab.grant().view().certificate_sha256.unwrap();

    // 1. A due identity and a Manager with no store: it refuses the handover (there is nothing
    //    to hand over from), and the start goes on with the identity it would have replaced.
    let first = lab.issued(340 * DAY);
    lab.save_identities(Some(&first), None);
    let view = lab
        .start()
        .await
        .expect("a refused handover does not stop the library");
    assert_eq!(lab.served().await, certificate(&first));
    assert_eq!(lab.identities().current, Some(first.clone()));
    assert!(
        lab.identities().pending.is_none(),
        "the waiting identity was dropped"
    );
    assert_eq!(view.certificate_expires_in_days, Some(25));
    assert!(view.certificate_renewable);
    lab.authorize().await;
    assert_eq!(pinned(&lab), fingerprint(&certificate(&first)));
    lab.stop().await;

    // 2. The normal renewal: Manager holds the due identity and accepts its successor.
    let view = lab.start().await.expect("renewal");
    let second = lab.identities().current.unwrap();
    assert_ne!(second, first);
    assert_eq!(lab.served().await, certificate(&second));
    assert!(lab.identities().pending.is_none(), "promoted");
    assert_eq!(view.certificate_expires_in_days, None);
    assert_eq!(
        pinned(&lab),
        fingerprint(&certificate(&second)),
        "the grant was re-pinned"
    );
    lab.ask(Command::Status {})
        .await
        .expect("the paired channel works over the renewed certificate");
    lab.stop().await;

    // 3. The grace period: Manager accepted the renewal, Desktop did not see it succeed and
    //    goes back to the identity it replaced. The keystore is as it was before promotion.
    lab.save_identities(Some(&first), Some(&second));
    lab.start_without_renewing()
        .await
        .expect("Manager takes the replaced identity back within its grace period");
    assert_eq!(lab.served().await, certificate(&first));
    assert_eq!(lab.identities().current, Some(first.clone()));
    assert!(
        lab.identities().pending.is_none(),
        "the waiting identity was dropped"
    );
    assert_eq!(
        pinned(&lab),
        fingerprint(&certificate(&first)),
        "the grant went back with it"
    );
    lab.ask(Command::Status {})
        .await
        .expect("paired over the earlier certificate");
    lab.stop().await;
    //    And forward again from there: the identity is still due.
    lab.start().await.expect("renewal after a roll back");
    let third = lab.identities().current.unwrap();
    assert!(third != first && third != second);
    assert_eq!(lab.served().await, certificate(&third));
    assert_eq!(pinned(&lab), fingerprint(&certificate(&third)));
    lab.ask(Command::Status {})
        .await
        .expect("paired over the new certificate");
    lab.stop().await;

    // 4. An identity Manager was never given: every attempt is refused, the first failure is
    //    reported, and no key is discarded. With the right identity back, the library starts.
    let stranger = lab.issued(340 * DAY);
    lab.save_identities(Some(&stranger), None);
    let refused = lab.start().await.unwrap_err();
    println!("an identity Manager never held: {refused}");
    assert_eq!(lab.identities().current, Some(stranger.clone()), "kept");
    assert!(
        lab.identities().pending.is_some(),
        "the renewal is kept for the next start"
    );
    println!(
        "update gate after the refused start: {:?}",
        lab.update_gate()
    );
    lab.save_identities(Some(&third), None);
    lab.start()
        .await
        .expect("Manager's store was not changed by the refusals");
    assert_eq!(lab.served().await, certificate(&third));
    lab.ask(Command::Status {}).await.expect("still paired");
    lab.stop().await;

    // 5. A renewal that ran out while it was waiting, after Manager had accepted it.
    let brief = lab.issued(365 * DAY - short);
    lab.save_identities(None, Some(&brief));
    let expires = Instant::now() + Duration::from_secs(short as u64);
    lab.start()
        .await
        .expect("Manager accepts the short-lived renewal");
    assert_eq!(lab.served().await, certificate(&brief));
    assert_eq!(pinned(&lab), fingerprint(&certificate(&brief)));
    lab.stop().await;
    //    As a crash before promotion leaves it: the earlier identity saved, this one waiting.
    lab.save_identities(Some(&third), Some(&brief));
    tokio::time::sleep(expires.saturating_duration_since(Instant::now()) + Duration::from_secs(2))
        .await;
    lab.start()
        .await
        .expect("a renewal signed by the expired waiting identity is accepted");
    let fourth = lab.identities().current.unwrap();
    assert!(fourth != third && fourth != brief);
    assert_eq!(lab.served().await, certificate(&fourth));
    assert!(lab.identities().pending.is_none());
    assert_eq!(
        pinned(&lab),
        fingerprint(&certificate(&fourth)),
        "re-pinned from the expired one"
    );
    lab.ask(Command::Status {})
        .await
        .expect("paired over the new certificate");
    lab.stop().await;

    // 6. The same with a waiting identity Manager never saw: the saved one signs.
    let unseen = lab.issued(365 * DAY - 3);
    lab.save_identities(None, Some(&unseen));
    tokio::time::sleep(Duration::from_secs(5)).await;
    lab.start().await.expect("renewed from the saved identity");
    let fifth = lab.identities().current.unwrap();
    assert!(fifth != fourth && fifth != unseen);
    assert_eq!(lab.served().await, certificate(&fifth));
    assert_eq!(pinned(&lab), fingerprint(&certificate(&fifth)));
    lab.stop().await;

    // 7. The saved identity itself expired while Manager held it.
    let last = lab.issued(365 * DAY - short);
    lab.save_identities(None, Some(&last));
    let expires = Instant::now() + Duration::from_secs(short as u64);
    lab.start()
        .await
        .expect("Manager accepts the short-lived identity");
    assert_eq!(lab.identities().current, Some(last.clone()));
    lab.stop().await;
    tokio::time::sleep(expires.saturating_duration_since(Instant::now()) + Duration::from_secs(2))
        .await;
    lab.start()
        .await
        .expect("an expired identity is renewed, not a reason to refuse the library");
    let renewed = lab.identities().current.unwrap();
    assert_ne!(renewed, last);
    assert_eq!(lab.served().await, certificate(&renewed));
    assert_eq!(pinned(&lab), fingerprint(&certificate(&renewed)));
    lab.ask(Command::Status {})
        .await
        .expect("paired over the new certificate");
    lab.control(Action::Start).await.unwrap();
    assert!(pong(2283).await, "and the library itself still runs");
    lab.control(Action::Stop).await.unwrap();
    lab.stop().await;
}

/// A library started with the released companion, then moved to the one whose Manager
/// declares the capabilities: the package move and a moved port in the same start.
#[tokio::test]
#[ignore = "end-to-end: run tools/manager_e2e/run.sh"]
async fn a_library_moved_from_the_released_companion_uses_what_the_new_manager_declares() {
    let released = Lab::on(&std::env::var("FRAMELEAF_MANAGER_E2E_RELEASED").expect("released"));
    assert_eq!(released.features(), Features::default());
    released.start().await.expect("the released Manager starts");
    released.authorize().await;
    released.control(Action::Start).await.unwrap();
    assert!(pong(2283).await);
    released.control(Action::Stop).await.unwrap();
    released.stop().await;
    let paired = released.grant().view();
    let certificate = released.identities().current_certificate().unwrap();
    drop(released);

    let lab = Lab::new();
    assert!(lab.features().ports && lab.features().runtime_status);
    let held = other(2283, Answer::Plain);
    lab.start()
        .await
        .expect("the library moves to the new package beside a busy port");
    let moved = Ports {
        api: 2284,
        ..Ports::default()
    };
    assert_eq!(lab.ports().await, moved);
    assert_eq!(
        lab.served().await,
        certificate,
        "the paired certificate moved with it"
    );
    assert_eq!(lab.grant().view().manager_id, paired.manager_id);
    lab.ask(Command::Status {})
        .await
        .expect("still paired, no new approval");
    assert_eq!(lab.photos().await.unwrap_err(), "local_photos_not_running");
    lab.control(Action::Start).await.unwrap();
    assert_eq!(lab.photos().await.unwrap(), "http://127.0.0.1:2284/");
    assert!(pong(2284).await);
    lab.control(Action::Stop).await.unwrap();
    lab.stop().await;
    drop(held);
    // The applied package move is sent again on every start; it does not block a later one.
    lab.start().await.expect("starts again");
    assert_eq!(lab.ports().await, moved);
    lab.stop().await;
}

impl Lab {
    /// Leave Manager holding an operation that failed: a backup whose destination cannot be
    /// written. Manager keeps such an operation until it is resumed, and admits no changed
    /// port or package while it does.
    async fn fail_a_backup(&self) -> uuid::Uuid {
        use std::os::unix::fs::PermissionsExt;
        let backups = self.data.join("backups");
        std::fs::create_dir_all(&backups).unwrap();
        let before = std::fs::metadata(&backups).unwrap().permissions();
        std::fs::set_permissions(&backups, std::fs::Permissions::from_mode(0o500)).unwrap();
        let key = uuid::Uuid::new_v4();
        let accepted = self
            .ask_recent(|| Command::Control {
                action: Action::Backup,
                key,
            })
            .await
            .unwrap();
        let id = uuid::Uuid::parse_str(accepted["id"].as_str().unwrap()).unwrap();
        let started = Instant::now();
        loop {
            let operation = self.ask(Command::Operation { id }).await.unwrap();
            if operation["state"] != "running" {
                println!("the backup ended as {operation}");
                assert_eq!(operation["state"], "failed");
                break;
            }
            assert!(started.elapsed() < Duration::from_secs(20 * 60));
            tokio::time::sleep(POLL).await;
        }
        std::fs::set_permissions(&backups, before).unwrap();
        id
    }
    async fn resume_backup(&self, id: uuid::Uuid) {
        self.ask_recent(|| Command::Resume {
            action: Action::Backup,
            id,
        })
        .await
        .expect("the failed backup can be resumed");
        let started = Instant::now();
        loop {
            let operation = self.ask(Command::Operation { id }).await.unwrap();
            match operation["state"].as_str() {
                Some("complete") => break,
                Some("running") => {}
                _ => panic!("the resumed backup ended as {operation}"),
            }
            assert!(started.elapsed() < Duration::from_secs(20 * 60));
            tokio::time::sleep(POLL).await;
        }
    }
}

/// Manager admits no changed port while an operation is unfinished. A port moved for a start
/// Manager then refuses must not stay moved: the library has to start again, on the ports
/// Manager knows, as soon as they are free, or its operation could never be resumed.
#[tokio::test]
#[ignore = "end-to-end: run tools/manager_e2e/run.sh"]
async fn a_port_moved_for_a_start_manager_refuses_does_not_stay_moved() {
    let lab = Lab::new();
    assert!(lab.features().ports);
    let defaults = Ports::default();
    lab.start().await.expect("first start");
    lab.authorize().await;
    lab.control(Action::Start).await.unwrap();
    lab.control(Action::Stop).await.unwrap();
    let unfinished = lab.fail_a_backup().await;
    lab.stop().await;

    {
        let _held = other(defaults.api, Answer::Plain);
        // Manager refuses the moved port. The answer is the one a busy port always had.
        assert_eq!(
            lab.start().await.unwrap_err(),
            format!("local_port_in_use_{}", defaults.api)
        );
        // And again: the refused move was not kept as where the library lives.
        assert_eq!(
            lab.start().await.unwrap_err(),
            format!("local_port_in_use_{}", defaults.api)
        );
    }
    lab.start()
        .await
        .expect("with the port free the library starts where Manager knows it");
    assert_eq!(lab.ports().await, defaults);
    assert_eq!(lab.record().ports, defaults);
    lab.resume_backup(unfinished).await;
    if lab.photo_server().await == "running" {
        lab.control(Action::Stop).await.unwrap();
    }
    lab.stop().await;

    // With nothing unfinished the same busy port is moved away from, and that is kept.
    let held = other(defaults.api, Answer::Plain);
    lab.start().await.expect("starts beside the busy port");
    let moved = Ports {
        api: defaults.api + 1,
        ..defaults
    };
    assert_eq!(lab.ports().await, moved);
    lab.stop().await;
    drop(held);
    lab.start().await.expect("starts again");
    assert_eq!(lab.ports().await, moved, "a move Manager accepted is kept");
    lab.stop().await;
}

/// The TLS identity beside an unfinished operation: a due one still starts the library, and
/// an expired one is still renewed, because nothing else could ever start it again.
#[tokio::test]
#[ignore = "end-to-end: run tools/manager_e2e/run.sh"]
async fn an_unfinished_operation_does_not_stop_an_identity_from_being_renewed() {
    let lab = Lab::new();
    assert!(lab.features().tls_rotation);
    let short: i64 = std::env::var("FRAMELEAF_MANAGER_E2E_SHORT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(150);
    let certificate =
        |value: &serde_json::Value| value["certificatePem"].as_str().unwrap().to_owned();
    lab.start().await.expect("first start");
    lab.authorize().await;
    lab.control(Action::Start).await.unwrap();
    lab.control(Action::Stop).await.unwrap();
    lab.stop().await;
    // Manager comes to hold an identity that runs out shortly.
    let brief = lab.issued(365 * DAY - short);
    lab.save_identities(None, Some(&brief));
    let expires = Instant::now() + Duration::from_secs(short as u64);
    lab.start()
        .await
        .expect("Manager accepts the short-lived identity");
    assert_eq!(lab.served().await, certificate(&brief));
    let unfinished = lab.fail_a_backup().await;
    lab.stop().await;

    // Due, not expired: whatever Manager does with the renewal, the library starts.
    lab.start()
        .await
        .expect("a due identity beside an unfinished operation");
    let kept = lab.served().await == certificate(&brief);
    println!("beside an unfinished operation the due identity was kept: {kept}");
    lab.stop().await;
    let held = lab.identities().current.unwrap();

    tokio::time::sleep(expires.saturating_duration_since(Instant::now()) + Duration::from_secs(2))
        .await;
    lab.start()
        .await
        .expect("an expired identity beside an unfinished operation is renewed");
    assert_ne!(lab.identities().current.unwrap(), held);
    lab.ask(Command::Status {})
        .await
        .expect("paired over the new certificate");
    lab.resume_backup(unfinished).await;
    if lab.photo_server().await == "running" {
        lab.control(Action::Stop).await.unwrap();
    }
    lab.stop().await;
}

/// First half of a crash: Manager is started on a moved port, and this process then ends
/// without stopping it, as the app does when it crashes. Run before the test below, in the
/// same login session.
#[tokio::test]
#[ignore = "end-to-end: run tools/manager_e2e/run.sh"]
async fn a_crash_leaves_manager_running_on_its_moved_port() {
    let lab = Lab::new();
    assert!(lab.features().ports);
    let _held = other(Ports::default().manager, Answer::Plain);
    lab.start()
        .await
        .expect("starts beside a busy Manager port");
    assert_eq!(lab.ports().await.manager, Ports::default().manager + 1);
    lab.authorize().await;
    println!("ending without stopping Manager");
    // No destructor runs, so the Manager this process owns is not ended with it.
    std::process::exit(0);
}

/// Second half: the next run finds the Manager the crash left, on the port it was moved to,
/// stops exactly that process and starts the library again where it was.
#[tokio::test]
#[ignore = "end-to-end: run tools/manager_e2e/run.sh"]
async fn the_next_run_finds_the_manager_a_crash_left_on_its_moved_port() {
    let lab = Lab::new();
    let moved = Ports {
        manager: Ports::default().manager + 1,
        ..Ports::default()
    };
    assert_eq!(lab.record().ports, moved);
    // It is still there, presenting this library's certificate on the saved port.
    assert_eq!(
        crate::manager_local::recorded_manager_listener(&lab.data),
        Evidence::Running
    );
    assert_eq!(lab.update_gate().unwrap_err(), "update_library_not_idle");
    lab.start()
        .await
        .expect("the Manager the crash left is stopped and the library starts again");
    assert_eq!(
        lab.ports().await,
        moved,
        "it stays on its port though 9443 is free now"
    );
    lab.ask(Command::Status {}).await.expect("still paired");
    lab.control(Action::Start).await.unwrap();
    assert!(pong(moved.api).await);
    lab.control(Action::Stop).await.unwrap();
    lab.stop().await;
    lab.update_gate()
        .expect("a stopped library does not block an update");
}

//! Only installed identities cross IPC; code, state paths and secrets stay native.
use crate::{
    host_install::Installation,
    manager_host::{Configuration, Evidence, NativeManager},
};
use serde::Serialize;
#[cfg(any(target_os = "macos", target_os = "linux", windows))]
use sha2::{Digest, Sha256};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct View {
    state: String,
    code: Option<String>,
    installation: Option<Installation>,
    origin: Option<String>,
    pub background_active: bool,
    /// A stop for quitting failed and Manager is still running, so quitting without stopping
    /// it may be chosen. The interface offers that only while this says so.
    leave_available: bool,
    /// Days until the running Manager's TLS identity expires, once that is near.
    certificate_expires_in_days: Option<u32>,
    /// That identity is renewed the next time local management starts.
    certificate_renewable: bool,
    profile_setup_available: bool,
    profile_requires_authorization: bool,
    companion_platform: Option<&'static str>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Compatibility {
    Verified,
    Unknown,
    Refused,
    /// Correctly signed, but built for a different version of this app: update the companion.
    Outdated,
}
impl Compatibility {
    fn from_check(result: Result<(), String>) -> Self {
        match result.as_ref().map_err(String::as_str) {
            Ok(()) => Self::Verified,
            Err("host_manifest_incompatible") => Self::Outdated,
            Err(
                "host_install_record_invalid"
                | "host_install_controller_changed"
                | "host_install_runtime_changed"
                | "host_signature_invalid"
                | "host_manifest_invalid"
                | "host_component_missing"
                | "host_package_state_invalid"
                | "native_manager_unprotected"
                | "runtime_store_file_invalid"
                | "runtime_path_invalid"
                | "runtime_root_invalid"
                | "runtime_link_forbidden"
                | "runtime_size_invalid"
                | "runtime_artifact_invalid"
                | "runtime_inventory_mismatch"
                | "runtime_artifact_changed",
            ) => Self::Refused,
            Err(_) => Self::Unknown,
        }
    }
}

impl Default for View {
    fn default() -> Self {
        Self {
            state: "idle".into(),
            code: None,
            installation: None,
            origin: None,
            background_active: false,
            leave_available: false,
            certificate_expires_in_days: None,
            certificate_renewable: false,
            profile_setup_available: cfg!(any(target_os = "linux", windows)),
            profile_requires_authorization: cfg!(target_os = "linux"),
            companion_platform: match (std::env::consts::OS, std::env::consts::ARCH) {
                ("macos", "aarch64") => Some("mac"),
                ("windows", "x86_64") => Some("windows"),
                ("linux", "x86_64") => Some("linux"),
                _ => None,
            },
        }
    }
}
struct Running {
    manager: NativeManager,
    configuration: Configuration,
    installation: Installation,
    /// What this package's Manager declares; none for the first released Manager.
    features: crate::manager_local::Features,
}
/// Whether an owned Manager, or anything it started, is still alive.
fn live(owner: &mut Option<Running>) -> bool {
    owner
        .as_mut()
        .is_some_and(|running| !matches!(running.manager.tree_exited(), Ok(true)))
}
/// Whether this app's record names the owned Manager, writing it again if it is missing. Without
/// it a later launch cannot find a Manager that was left running.
fn recorded(running: &mut Running) -> bool {
    #[cfg(unix)]
    {
        let (data, pid) = (&running.configuration.data, running.manager.process_id());
        crate::manager_host::owned_process_recorded(data, pid)
            || (crate::manager_host::record_owned_process(data, pid).is_ok()
                && crate::manager_host::owned_process_recorded(data, pid))
    }
    #[cfg(not(unix))]
    {
        let _ = running;
        false
    }
}
/// The existing stop proof, read-only: no controller holds the journal, its last stop was clean
/// and no database process file remains. Anything short of that is not proof.
struct Library {
    state: std::path::PathBuf,
    installation_id: String,
    manifest_sha256: String,
}
/// Read a failed idle proof: a held lease is something running, anything else is not proof.
fn idle_evidence(proof: Result<(), String>) -> Evidence {
    match proof.as_ref().map_err(String::as_str) {
        Ok(()) => Evidence::Clear,
        Err("host_controller_already_owned" | "host_already_owned") => Evidence::Running,
        Err(_) => Evidence::Unknown,
    }
}
impl Library {
    fn idle(&self) -> Evidence {
        idle_evidence(
            crate::host_state::Owner::acquire(&self.state, false).and_then(|mut proof| {
                proof.admit_idle(&self.installation_id, &self.manifest_sha256)
            }),
        )
    }
}
/// Where this account's library lives on disk, and how to ask what may be running from it.
#[cfg_attr(not(unix), allow(dead_code))]
#[derive(Clone, Copy)]
struct Hosted<'a> {
    /// The controller's state directory.
    state: &'a std::path::Path,
    /// Manager's data directory, which holds this app's record of the Manager it started.
    data: &'a std::path::Path,
    /// Whether this library's Manager may be answering on the port this library records for
    /// it. A listener proven to be another program's is `Clear`.
    listener: &'a dyn Fn() -> Evidence,
    /// What holds a PID right now.
    #[cfg(unix)]
    process: &'a dyn Fn(u32) -> crate::process_tree::Presence,
}
/// From disk alone: `Clear` when no library was ever hosted at `state`, or when its journal
/// proves it idle and nothing that could be its Manager answers on Manager's port. The port
/// covers a Manager that left no usable record.
#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn hosted_library(state: &std::path::Path, listener: &dyn Fn() -> Evidence) -> Evidence {
    match std::fs::symlink_metadata(state) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Evidence::Clear,
        Err(_) => Evidence::Unknown,
        Ok(_) => match idle_evidence(crate::host_state::Owner::package_idle(state)) {
            Evidence::Clear => listener(),
            journal => journal,
        },
    }
}
#[derive(Default)]
pub(crate) struct HostSetup {
    owner: tokio::sync::Mutex<Option<Running>>,
    /// The library a Manager was started for in this run. It outlives `owner`: stopping or
    /// losing Manager does not prove its controller and database stopped.
    library: Mutex<Option<Library>>,
    cancel: Arc<AtomicBool>,
    active: AtomicBool,
    /// A stop for quitting failed, so quitting without stopping may be chosen.
    exit_stop_failed: AtomicBool,
    /// The person chose to quit and leave Manager running for the next launch to stop.
    left_for_exit: AtomicBool,
    /// When the owned Manager's TLS identity expires, in Unix seconds; 0 with none owned.
    certificate_expires_at: std::sync::atomic::AtomicI64,
    /// Whether the owned Manager accepts a renewed identity at its next start.
    certificate_renewable: AtomicBool,
    /// Manager's origin for this library when it is not the default.
    origin: Mutex<Option<String>>,
    view: Mutex<View>,
}
impl HostSetup {
    /// Whether a local operation is in flight or an owned Manager is alive. Operations hold the
    /// owner for their whole duration and keep the flag themselves; whenever the owner is free
    /// the flag is re-derived from the owned process, so a Manager that exited cannot hold it.
    pub(crate) fn background_active(&self) -> bool {
        if self.left_for_exit.load(Ordering::Acquire) {
            return false;
        }
        if let Ok(mut owner) = self.owner.try_lock() {
            self.active.store(live(&mut owner), Ordering::Release);
        }
        self.active.load(Ordering::Acquire)
    }
    pub(crate) fn lock_for_update(&self) -> Result<impl Drop + '_, String> {
        // Unit tests never consult the library really hosted on the machine that runs them.
        #[cfg(all(unix, not(test)))]
        {
            let profile = crate::host_install::account_profile();
            let (state, data) = (profile.join("state"), profile.join("manager"));
            self.lock_for_update_at(Some(Hosted {
                state: &state,
                data: &data,
                listener: &|| crate::manager_local::recorded_manager_listener(&data),
                process: &crate::process_tree::ProcessIdentity::lookup,
            }))
        }
        #[cfg(not(all(unix, not(test))))]
        {
            self.lock_for_update_at(None)
        }
    }
    /// Every way something of this library could run, or be started, during an update, and
    /// the evidence that must be `Clear` for it. Evidence that is missing, unreadable or
    /// could be racing is `Unknown`, and `Unknown` blocks exactly as `Running` does.
    /// - An operation of this app in flight: it holds the owner, which this takes and keeps.
    /// - A Manager this run owns (on Windows, anything left in its job): `live`.
    /// - A controller or database outliving a Manager this run stopped, lost or left: the
    ///   remembered library's journal must prove a clean stop.
    /// - The same after a restart of this app (Stop and quit, Quit anyway, a crash): the
    ///   journal found on disk must prove it, with no controller holding it.
    /// - A Manager left by an earlier run (Quit anyway, a crash), which could start the
    ///   controller: this app's record of it. The record is written before Manager is
    ///   spawned, so it exists even for a Manager that has not bound its port; until it names
    ///   a process that is seen to be gone, it blocks.
    /// - Any Manager with no usable record: the port this library records for its Manager
    ///   must definitely refuse, or what answers there must be proven to be another program
    ///   (it presents a certificate that is not this library's, or does not speak TLS). A
    ///   record of that port that cannot be read blocks.
    ///
    /// With all of that proven and the owner held, nothing is left that could start one.
    /// On Windows the controller and database die with this app's job, so a new run there
    /// has nothing on disk to check.
    fn lock_for_update_at(&self, hosted: Option<Hosted<'_>>) -> Result<impl Drop + '_, String> {
        let mut owner = self.owner.try_lock().map_err(|_| "update_host_active")?;
        // Holding the owner proves no operation is in flight. A live Manager blocks, and a
        // Manager whose state cannot be read counts as live.
        if live(&mut owner) {
            return Err("update_host_active".into());
        }
        // Outside Windows the controller and database are not this app's children: they can
        // outlive Manager, and this app.
        let session = self
            .library
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_ref()
            .map_or(Evidence::Clear, Library::idle);
        #[cfg(any(target_os = "macos", target_os = "linux", test))]
        let journal = hosted.map_or(Evidence::Clear, |hosted| {
            hosted_library(hosted.state, hosted.listener)
        });
        #[cfg(not(any(target_os = "macos", target_os = "linux", test)))]
        let journal = Evidence::Clear;
        #[cfg(unix)]
        let manager = hosted.map_or(Evidence::Clear, |hosted| {
            crate::manager_host::recorded_manager(hosted.data, hosted.process)
        });
        #[cfg(not(unix))]
        let manager = Evidence::Clear;
        #[cfg(not(any(unix, test)))]
        let _ = hosted;
        if [session, journal, manager] != [Evidence::Clear; 3] {
            return Err("update_library_not_idle".into());
        }
        Ok(owner)
    }
    /// Own a started Manager and remember its library for the update gate.
    fn adopt(&self, owner: &mut Option<Running>, running: Running) {
        // A failed stop of an earlier Manager says nothing about this one.
        self.exit_stop_failed.store(false, Ordering::Release);
        self.certificate_expires_at.store(
            running.manager.certificate_expires_at().unwrap_or(0),
            Ordering::Release,
        );
        self.certificate_renewable
            .store(running.features.tls_rotation, Ordering::Release);
        *self
            .origin
            .lock()
            .unwrap_or_else(|error| error.into_inner()) =
            Some(running.configuration.origin.clone());
        *self
            .library
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(Library {
            state: running.configuration.state.clone(),
            installation_id: running.configuration.installation_id.clone(),
            manifest_sha256: running.installation.manifest_sha256.clone(),
        });
        *owner = Some(running);
    }
    /// Quit without stopping, allowed only after a stop for quitting failed and only while this
    /// app's record names the live Manager, so the next launch can attempt to stop it. Not on
    /// Windows: leaving there ends Manager's job and would kill a running database.
    pub(crate) fn leave_for_exit(&self, leave: bool) -> Result<(), String> {
        if leave {
            if cfg!(not(unix)) || !self.exit_stop_failed.load(Ordering::Acquire) {
                return Err("native_manager_shutdown_unconfirmed".into());
            }
            let mut owner = self.owner.try_lock().map_err(|_| "native_host_busy")?;
            if owner.as_mut().is_some_and(|running| !recorded(running)) {
                return Err("native_manager_record_unavailable".into());
            }
        }
        self.left_for_exit.store(leave, Ordering::Release);
        Ok(())
    }
    fn set(&self, state: &str, code: Option<String>, installation: Option<Installation>) {
        *self.view.lock().unwrap_or_else(|error| error.into_inner()) = View {
            state: state.into(),
            code,
            origin: installation.as_ref().map(|_| {
                self.origin
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .clone()
                    .unwrap_or_else(|| crate::manager_local::Ports::default().origin())
            }),
            installation,
            ..View::default()
        };
    }
    fn snapshot(&self) -> View {
        let mut view = self
            .view
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone();
        view.background_active = self.background_active();
        view.leave_available =
            cfg!(unix) && view.background_active && self.exit_stop_failed.load(Ordering::Acquire);
        // Only for a Manager that is running now; a clock that cannot be read says nothing.
        view.certificate_expires_in_days = match self.certificate_expires_at.load(Ordering::Acquire)
        {
            expires if expires != 0 && view.background_active => crate::manager::clock()
                .ok()
                .and_then(|now| i64::try_from(now / 1000).ok())
                .and_then(|now| crate::manager_tls::expiry_notice_days(expires, now)),
            _ => None,
        };
        view.certificate_renewable = view.certificate_expires_in_days.is_some()
            && self.certificate_renewable.load(Ordering::Acquire);
        view
    }
    pub(crate) fn require_management_origin(&self, origin: &str) -> Result<(), String> {
        let view = self.snapshot();
        if view.origin.as_deref() == Some(origin)
            && matches!(
                view.state.as_str(),
                "starting" | "stopping" | "provisioning"
            )
        {
            return Err("native_host_busy".into());
        }
        Ok(())
    }
    pub(crate) fn cancel(&self) {
        self.cancel.store(true, Ordering::Release);
    }
    pub(crate) async fn status(&self) -> Result<View, String> {
        if let Ok(mut owner) = self.owner.try_lock() {
            if let Some(running) = owner.as_mut() {
                if running.manager.has_exited()? {
                    let record = Some(running.installation.clone());
                    self.set(
                        "needs-attention",
                        Some("native_manager_exited".into()),
                        record,
                    );
                }
            }
        }
        Ok(self.snapshot())
    }
    /// Inspect only the selected installed package. Profile and runtime startup remain separate.
    pub(crate) async fn compatibility(
        &self,
        manifest: String,
        controller: String,
    ) -> Compatibility {
        let Ok(_owner) = self.owner.try_lock() else {
            return Compatibility::Unknown;
        };
        let result = tauri::async_runtime::spawn_blocking(move || {
            #[cfg(any(target_os = "macos", target_os = "linux", windows))]
            {
                let record = Installation::read(&manifest)?;
                if record.controller_sha256 != controller {
                    return Err("host_package_selection_changed".into());
                }
                verify_installed_package(&record)
            }
            #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
            {
                let _ = (manifest, controller);
                Err("host_install_platform_unsupported".into())
            }
        })
        .await
        .unwrap_or_else(|_| Err("host_package_check_unavailable".into()));
        Compatibility::from_check(result)
    }

    pub(crate) async fn provision(&self, manifest: String) -> Result<View, String> {
        #[cfg(target_os = "linux")]
        {
            let record = Installation::read(&manifest)?;
            self.provision_record(record, crate::profile_elevation::provision)
                .await
        }
        #[cfg(windows)]
        {
            let record = Installation::read(&manifest)?;
            self.provision_record(record, |record| {
                verify_installed_package(record)?;
                crate::windows_host_profile::prepare(record)
            })
            .await
        }
        #[cfg(not(any(target_os = "linux", windows)))]
        {
            let _ = manifest;
            Err("host_install_platform_unsupported".into())
        }
    }
    #[cfg(any(target_os = "linux", windows, test))]
    async fn provision_record<F>(
        &self,
        installation: Installation,
        provision: F,
    ) -> Result<View, String>
    where
        F: FnOnce(&Installation) -> Result<(), String> + Send + 'static,
    {
        let owner = self.owner.try_lock().map_err(|_| "native_host_busy")?;
        if owner.is_some() {
            return Err("native_host_stop_required".into());
        }
        self.active.store(true, Ordering::Release);
        self.set("provisioning", None, Some(installation.clone()));
        let record = installation.clone();
        let result = tauri::async_runtime::spawn_blocking(move || provision(&record))
            .await
            .map_err(|_| "host_profile_prepare_failed".to_string())
            .and_then(|result| result);
        self.active.store(false, Ordering::Release);
        self.set(
            if result.is_ok() {
                "profile-ready"
            } else {
                "needs-attention"
            },
            result.as_ref().err().cloned(),
            Some(installation),
        );
        result?;
        Ok(self.snapshot())
    }
    pub(crate) async fn start(&self, manifest: String) -> Result<View, String> {
        let mut owner = self.owner.try_lock().map_err(|_| "native_host_busy")?;
        if let Some(running) = owner.as_mut() {
            if !running.manager.has_exited()? {
                return Err("native_manager_already_running".into());
            }
        }
        if !cfg!(any(target_os = "macos", target_os = "linux", windows)) {
            return Err("host_install_platform_unsupported".into());
        }
        // Validate the fixed identity before changing lifecycle state.
        let installation = Installation::read(&manifest)?;
        if owner
            .as_ref()
            .is_some_and(|running| running.installation != installation)
        {
            return Err("native_host_stop_required".into());
        }
        let attempted = installation.clone();
        self.cancel.store(false, Ordering::Release);
        self.active.store(true, Ordering::Release);
        // Unit tests never consult the library really hosted on the machine that runs them.
        #[cfg(not(test))]
        {
            *self
                .origin
                .lock()
                .unwrap_or_else(|error| error.into_inner()) = profile_data()
                .and_then(|data| crate::manager_local::recorded(&data).ok())
                .map(|record| record.ports.origin());
        }
        self.set("starting", None, Some(installation.clone()));
        let result = started_with_renewal(
            |renew, renewing| {
                let (installation, cancel) = (installation.clone(), self.cancel.clone());
                async move {
                    let mut running = tauri::async_runtime::spawn_blocking(move || {
                        launch(&installation, &cancel, renew, &renewing)
                    })
                    .await
                    .map_err(|_| "native_host_setup_failed".to_string())
                    .and_then(|value| value)?;
                    running
                        .manager
                        .wait_ready(Duration::from_secs(20), &self.cancel)
                        .await?;
                    Ok(running)
                }
            },
            &self.cancel,
        )
        .await
        .map(|mut running| {
            settle_identity(&mut running);
            running
        });
        match result {
            Ok(running) => {
                self.adopt(&mut owner, running);
                self.set("manager-ready", None, self.snapshot().installation);
            }
            Err(error) => {
                self.startup_failed(
                    owner.as_ref().map(|running| running.installation.clone()),
                    attempted,
                    error.clone(),
                );
                return Err(error);
            }
        }
        Ok(self.snapshot())
    }
    fn startup_failed(
        &self,
        retained: Option<Installation>,
        attempted: Installation,
        error: String,
    ) {
        self.active.store(retained.is_some(), Ordering::Release);
        self.set("needs-attention", Some(error), retained.or(Some(attempted)));
    }
    pub(crate) async fn authorize(
        &self,
        password: zeroize::Zeroizing<String>,
        allow_recovery: bool,
    ) -> Result<crate::manager::View, String> {
        require_password(&password)?;
        let mut owner = self.owner.try_lock().map_err(|_| "native_host_busy")?;
        let running = owner.as_mut().ok_or("native_manager_not_ready")?;
        running
            .manager
            .management_identity(&running.configuration)?;
        let identity = crate::credentials::identity()?;
        let existing =
            crate::credentials::load::<crate::manager::SavedManager>(crate::manager::CREDENTIAL)?;
        // Confirm secure writes before claiming an administrator or issuing a grant.
        crate::credentials::save("manager-pairing-check", &true)?;
        crate::credentials::delete("manager-pairing-check")?;
        authorize_owner(
            &mut running.manager,
            &running.configuration,
            &identity,
            password,
            allow_recovery,
            existing,
            |saved| crate::credentials::save(crate::manager::CREDENTIAL, saved),
        )
        .await
    }
    pub(crate) async fn photos_url(&self) -> Result<url::Url, String> {
        let mut owner = self.owner.try_lock().map_err(|_| "native_host_busy")?;
        let running = owner.as_mut().ok_or("native_manager_not_ready")?;
        running
            .manager
            .management_identity(&running.configuration)?;
        let saved =
            crate::credentials::load::<crate::manager::SavedManager>(crate::manager::CREDENTIAL)?
                .ok_or("manager_pairing_required")?;
        let address = photos_owner(
            &mut running.manager,
            &running.configuration,
            &crate::credentials::identity()?,
            &saved,
        )
        .await?;
        let identity = crate::credentials::identity()?;
        photo_server_proof(
            running.features,
            |command| crate::manager::send(&saved, &identity, command),
            running.configuration.api_port,
        )
        .await?;
        running
            .manager
            .management_identity(&running.configuration)?;
        owned_photo_listener(&running.configuration.state, running.configuration.api_port)?;
        Ok(address)
    }
    pub(crate) async fn stop(&self) -> Result<View, String> {
        self.stop_proven(false).await
    }
    /// Stop Manager, only on the journal's proof that the database is closed. With `in_order`,
    /// a controller that still holds the journal is first closed in order through Manager; the
    /// same proof is then required before Manager is touched.
    async fn stop_proven(&self, in_order: bool) -> Result<View, String> {
        let mut owner = self.owner.try_lock().map_err(|_| "native_host_busy")?;
        let Some(running) = owner.as_mut() else {
            return Ok(self.snapshot());
        };
        let record = Some(running.installation.clone());
        self.set("stopping", None, record.clone());
        // Once Manager and everything under it has exited there is nothing to stop or to prove
        // idle; an interrupted journal must not keep a dead Manager owned.
        let result = if matches!(running.manager.tree_exited(), Ok(true)) {
            Ok(())
        } else {
            async {
                let Running {
                    manager,
                    configuration,
                    installation,
                    ..
                } = running;
                let prove = || {
                    let mut proof = crate::host_state::Owner::acquire(&configuration.state, true)?;
                    proof.admit_idle(
                        &configuration.installation_id,
                        &installation.manifest_sha256,
                    )?;
                    Ok::<_, String>(proof)
                };
                let proof = if in_order {
                    orderly_stop_proof(
                        prove,
                        stop_photo_server(&mut *manager, configuration, ORDERLY_STOP),
                        Duration::from_secs(10),
                    )
                    .await?
                } else {
                    prove()?
                };
                manager.shutdown(Duration::from_secs(10)).await?;
                drop(proof);
                Ok::<(), String>(())
            }
            .await
        };
        if let Err(error) = result {
            self.set("needs-attention", Some(error.clone()), record);
            return Err(error);
        }
        self.stopped(&mut owner, record);
        Ok(self.snapshot())
    }
    fn stopped(&self, owner: &mut Option<Running>, record: Option<Installation>) {
        #[cfg(unix)]
        if let Some(running) = owner.as_ref() {
            crate::manager_host::forget_owned_process(&running.configuration.data);
        }
        *owner = None;
        self.active.store(false, Ordering::Release);
        self.certificate_expires_at.store(0, Ordering::Release);
        self.exit_stop_failed.store(false, Ordering::Release);
        self.left_for_exit.store(false, Ordering::Release);
        self.set("idle", None, record);
    }
    /// The quit path. Unix asks Manager to exit even while the photo server runs: its controller
    /// then closes the database in order, and finishes on its own if this app exits first.
    /// Windows keeps the idle proof, because ending Manager's job there would kill the database;
    /// a photo server that is still running is first closed in order through Manager.
    /// The quit path as one decision. `exit_refused` is the code of whatever else would refuse
    /// the exit that follows: with one, nothing is stopped or left, because the app would
    /// stay open with its library stopped for nothing.
    pub(crate) async fn quit(
        &self,
        exit_refused: Option<&'static str>,
        leave_running: bool,
    ) -> Result<(), String> {
        if let Some(code) = exit_refused {
            return Err(code.into());
        }
        if leave_running {
            self.leave_for_exit(true)
        } else {
            self.stop_for_exit().await.map(|_| ())
        }
    }
    pub(crate) async fn stop_for_exit(&self) -> Result<View, String> {
        self.stop_for_exit_within(Duration::from_secs(10)).await
    }
    async fn stop_for_exit_within(&self, timeout: Duration) -> Result<View, String> {
        #[cfg(unix)]
        {
            let mut owner = self.owner.try_lock().map_err(|_| "native_host_busy")?;
            let Some(running) = owner.as_mut() else {
                return Ok(self.snapshot());
            };
            let record = Some(running.installation.clone());
            self.set("stopping", None, record.clone());
            if let Err(error) = running.manager.shutdown(timeout).await {
                // Manager did not exit in time. Quitting without stopping is offered only if
                // its record is in place, so the next launch can find it and attempt the stop.
                let error = if recorded(running) {
                    self.exit_stop_failed.store(true, Ordering::Release);
                    error
                } else {
                    "native_manager_record_unavailable".to_string()
                };
                self.set("needs-attention", Some(error.clone()), record);
                return Err(error);
            }
            self.stopped(&mut owner, record);
            Ok(self.snapshot())
        }
        #[cfg(not(unix))]
        {
            let _ = timeout;
            self.stop_proven(true).await
        }
    }
    /// Windows is ending the session and ends this app, and with it Manager's job, when this
    /// returns. Close the photo server and database in order first. Whatever this cannot do
    /// (an operation in flight, no saved grant, a stop that fails) is left to the job's
    /// kill-on-close, which the next start recovers from.
    #[cfg(windows)]
    pub(crate) fn stop_for_session_end(&self) {
        let _ = tauri::async_runtime::block_on(self.stop_proven(true));
    }
}
/// How long Manager may take to close the photo server and database in order. Manager gives its
/// own controller 170 seconds before it gives up.
const ORDERLY_STOP: Duration = Duration::from_secs(180);
/// The proof that the database is closed, for a stop that would otherwise kill it. Only a
/// controller known to hold the journal is worth asking to stop; any other failed proof
/// (unreadable, interrupted, bound to something else) is refused as it is. Whatever `ask`
/// reports, only the journal's own proof is returned: the controller may take a moment after
/// Manager's answer to release the journal, so the proof is read again for up to `settle`.
async fn orderly_stop_proof<P>(
    prove: impl Fn() -> Result<P, String>,
    ask: impl std::future::Future<Output = Result<(), String>>,
    settle: Duration,
) -> Result<P, String> {
    let held = |proof: &Result<P, String>| {
        proof
            .as_ref()
            .is_err_and(|code| idle_evidence(Err(code.clone())) == Evidence::Running)
    };
    let first = prove();
    if !held(&first) {
        return first;
    }
    ask.await?;
    let deadline = std::time::Instant::now() + settle;
    loop {
        let proof = prove();
        if !held(&proof) || std::time::Instant::now() >= deadline {
            return proof;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
/// Ask the owned Manager to stop the photo server and database in order, with the grant this
/// computer saved when it was authorized for exactly this Manager.
async fn stop_photo_server(
    manager: &mut NativeManager,
    configuration: &Configuration,
    timeout: Duration,
) -> Result<(), String> {
    let certificate = manager.management_identity(configuration)?;
    let identity = crate::credentials::identity()?;
    let saved =
        crate::credentials::load::<crate::manager::SavedManager>(crate::manager::CREDENTIAL)?
            .ok_or("manager_pairing_required")?;
    local_grant(&saved, &identity, configuration, &certificate.sha256)?;
    manager_stop(
        |command| crate::manager::send(&saved, &identity, command),
        timeout,
    )
    .await
}
/// Manager's stop operation, followed until Manager reports it complete. Anything else it
/// reports, an answer that cannot be read and running out of time are all failures.
async fn manager_stop<F>(
    send: impl Fn(crate::manager::Command) -> F,
    timeout: Duration,
) -> Result<(), String>
where
    F: std::future::Future<Output = Result<serde_json::Value, String>>,
{
    use crate::manager::{Action, Command};
    let deadline = std::time::Instant::now() + timeout;
    let accepted = send(Command::Control {
        action: Action::Stop,
        key: uuid::Uuid::new_v4(),
    })
    .await?;
    let id = accepted["id"]
        .as_str()
        .and_then(|id| uuid::Uuid::parse_str(id).ok())
        .ok_or("manager_response_invalid")?;
    loop {
        let operation = send(Command::Operation { id }).await?;
        match operation["state"].as_str() {
            Some("complete") => return Ok(()),
            Some("running") => {}
            Some("failed" | "interrupted") => {
                return Err(operation["error"]
                    .as_str()
                    .unwrap_or("manager_operation_failed")
                    .into())
            }
            _ => return Err("manager_response_invalid".into()),
        }
        if std::time::Instant::now() >= deadline {
            return Err("native_manager_shutdown_unconfirmed".into());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}
/// Start local management, renewing Manager's TLS identity when that is due. `attempt` is
/// given whether it may renew, and a flag it sets once it presents a renewed identity. If
/// such an attempt fails, one more is made with the identity the renewal would have replaced:
/// a Manager that had already accepted the new one takes the old one back during its grace
/// period, so the library starts either way. If that also fails, the first failure is the
/// one reported, and the renewed identity stays saved for the next start.
async fn started_with_renewal<T, F>(
    attempt: impl Fn(bool, Arc<AtomicBool>) -> F,
    cancel: &AtomicBool,
) -> Result<T, String>
where
    F: std::future::Future<Output = Result<T, String>>,
{
    let renewing = Arc::new(AtomicBool::new(false));
    match attempt(true, renewing.clone()).await {
        Err(error) if renewing.load(Ordering::Acquire) && !cancel.load(Ordering::Acquire) => {
            attempt(false, Arc::new(AtomicBool::new(false)))
                .await
                .map_err(|_| error)
        }
        result => result,
    }
}
/// After Manager is verified ready: let this computer's saved grant follow it to a moved port
/// or a renewed certificate, then settle its TLS identity in the keystore. Each step is
/// retried by the next start if it fails here, so a failure never stops a running library.
fn settle_identity(running: &mut Running) {
    if running.features.ports || running.features.tls_rotation {
        // The grant first: if this app stops between the two, the next start presents the
        // renewed identity again and finds the grant already pinned to it.
        let replaced = running.manager.replaced_certificate().map(str::to_owned);
        let _ = follow_grant(running, replaced.as_deref());
    }
    let _ = running.manager.settle_identity();
}
fn follow_grant(running: &Running, replaced: Option<&str>) -> Result<(), String> {
    {
        let Some(mut saved) =
            crate::credentials::load::<crate::manager::SavedManager>(crate::manager::CREDENTIAL)?
        else {
            return Ok(());
        };
        if saved.follow_local(
            &running.configuration.installation_id,
            &running.configuration.origin,
            running.manager.certificate(),
            replaced,
        ) {
            crate::credentials::save(crate::manager::CREDENTIAL, &saved)?;
        }
        Ok(())
    }
}
/// For a Manager that declares `runtime-status`: Manager says, over the pinned channel and
/// bound to this request, what its own controller is doing, and Photos opens only while that
/// is serving photos on `port`. A Manager that does not declare it is not asked, and the
/// journal-lease check that follows is all there is, as before.
async fn photo_server_proof<F>(
    features: crate::manager_local::Features,
    send: impl FnOnce(crate::manager::Command) -> F,
    port: u16,
) -> Result<(), String>
where
    F: std::future::Future<Output = Result<serde_json::Value, String>>,
{
    if !features.runtime_status {
        return Ok(());
    }
    let reply = send(crate::manager::Command::Runtime {
        nonce: uuid::Uuid::new_v4(),
    })
    .await?;
    photo_server_running(&reply, port)
}
/// Whether Manager reports its controller serving photos on `port`. Only `running` opens the
/// address; every other state, and a reply that does not say, refuses with what it means.
fn photo_server_running(reply: &serde_json::Value, port: u16) -> Result<(), String> {
    let server = &reply["photoServer"];
    let maintenance = server["code"]
        .as_str()
        .is_some_and(|code| code.ends_with("_maintenance"));
    match server["state"].as_str() {
        Some("running") if reply["ports"]["api"].as_u64() == Some(port.into()) => Ok(()),
        Some("starting") => Err("local_photos_starting".into()),
        Some("unknown") if maintenance => Err("local_photos_maintenance".into()),
        Some("stopping" | "stopped" | "unknown") => Err("local_photos_not_running".into()),
        _ => Err("manager_response_invalid".into()),
    }
}
/// This account's Manager data directory, where the library's own records are kept.
#[cfg(not(test))]
fn profile_data() -> Option<std::path::PathBuf> {
    #[cfg(unix)]
    {
        Some(crate::host_install::account_profile().join("manager"))
    }
    #[cfg(windows)]
    {
        crate::windows_host_profile::paths()
            .ok()
            .map(|paths| paths.1)
    }
    #[cfg(not(any(unix, windows)))]
    {
        None
    }
}
fn local_photos_origin(port: u16) -> Result<url::Url, String> {
    if port == 0 {
        return Err("native_host_config_invalid".into());
    }
    url::Url::parse(&format!("http://127.0.0.1:{port}/"))
        .map_err(|_| "native_host_config_invalid".into())
}
pub(crate) async fn photos_owner(
    manager: &mut NativeManager,
    configuration: &Configuration,
    identity: &crate::connection::DeviceIdentity,
    saved: &crate::manager::SavedManager,
) -> Result<url::Url, String> {
    let certificate = manager.management_identity(configuration)?;
    local_grant(saved, identity, configuration, &certificate.sha256)?;
    crate::manager::send(saved, identity, crate::manager::Command::Status {}).await?;
    manager.management_identity(configuration)?;
    // This selects the owned server address; only the photo UI can establish account readiness.
    local_photos_origin(configuration.api_port)
}
/// The photo address is opened only while this library's controller holds its journal lease.
/// Without that controller, whatever answers on the port is another program.
fn owned_photo_listener(state: &std::path::Path, port: u16) -> Result<(), String> {
    photo_listener(
        crate::host_state::Owner::controller_running(state),
        port,
        &|| crate::manager_host::listener(port),
    )
}
/// `controller` is whether this library's controller holds its journal lease; a lease that
/// cannot be read refuses. `listener` is asked only to name what is wrong: no answer from it
/// opens the address.
fn photo_listener(
    controller: Result<bool, String>,
    port: u16,
    listener: &dyn Fn() -> Evidence,
) -> Result<(), String> {
    if controller? {
        return Ok(());
    }
    Err(match listener() {
        Evidence::Running => format!("local_port_in_use_{port}"),
        Evidence::Clear | Evidence::Unknown => "local_photos_not_running".into(),
    })
}
fn require_password(password: &str) -> Result<(), String> {
    if password.chars().count() < 14
        || password.len() > 256
        || password.contains(['\r', '\n', '\0'])
    {
        return Err("manager_login_details_invalid".into());
    }
    Ok(())
}
fn claim_proof(path: &std::path::Path) -> Result<zeroize::Zeroizing<String>, String> {
    use std::io::Read;
    let directory = cap_std::fs::Dir::from_std_file(crate::host_storage::directory(path)?);
    let file = directory
        .open_with("claim-key", &crate::host_state::options(false))
        .map_err(|_| "manager_claim_proof_changed")?
        .into_std();
    crate::host_state::valid_file(&file).map_err(|_| "manager_claim_proof_changed")?;
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    file.take(65)
        .read_to_end(&mut bytes)
        .map_err(|_| "manager_claim_proof_changed")?;
    let text = std::str::from_utf8(&bytes).map_err(|_| "manager_claim_proof_changed")?;
    if !crate::native_runtime::digest_valid(text, 64) {
        return Err("manager_claim_proof_changed".into());
    }
    Ok(zeroize::Zeroizing::new(text.to_owned()))
}
fn local_grant(
    saved: &crate::manager::SavedManager,
    identity: &crate::connection::DeviceIdentity,
    configuration: &Configuration,
    certificate: &str,
) -> Result<crate::manager::View, String> {
    saved.require_device(identity)?;
    let view = saved.view();
    if view.origin != configuration.origin
        || view.installation_id != configuration.installation_id
        || view.certificate_sha256.as_deref() != Some(certificate)
    {
        return Err("manager_already_paired".into());
    }
    if view.expires_at <= crate::manager::clock()? {
        return Err("manager_pairing_expired".into());
    }
    Ok(view)
}
pub(crate) async fn authorize_owner(
    manager: &mut NativeManager,
    configuration: &Configuration,
    identity: &crate::connection::DeviceIdentity,
    password: zeroize::Zeroizing<String>,
    allow_recovery: bool,
    existing: Option<crate::manager::SavedManager>,
    persist: impl FnOnce(&crate::manager::SavedManager) -> Result<(), String>,
) -> Result<crate::manager::View, String> {
    require_password(&password)?;
    let certificate = manager.management_identity(configuration)?;
    if let Some(saved) = existing {
        let view = local_grant(&saved, identity, configuration, &certificate.sha256)?;
        if allow_recovery && !view.scopes.contains(&crate::manager::Scope::Restore) {
            return Err("manager_recovery_approval_required".into());
        }
        crate::manager::reauthenticate(&saved, password.to_string()).await?;
        crate::manager::send(&saved, identity, crate::manager::Command::Status {}).await?;
        manager.management_identity(configuration)?;
        return Ok(view);
    }
    if !manager.claimed().await? {
        let proof = claim_proof(&configuration.data)?;
        manager.claim_local(&password, &proof).await?;
    }
    let fingerprint = certificate.sha256.clone();
    crate::manager::pair(
        identity,
        &configuration.origin,
        password.to_string(),
        Some(certificate),
        allow_recovery,
        |saved| {
            manager.management_identity(configuration)?;
            local_grant(saved, identity, configuration, &fingerprint)?;
            persist(saved)
        },
    )
    .await
}

#[cfg(any(target_os = "macos", target_os = "linux", windows, all(test, unix)))]
pub(crate) fn require_leaf(path: &std::path::Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let required = if cfg!(target_os = "linux") {
            "host_install_linux_profile_required"
        } else {
            "host_install_profile_required"
        };
        let info = std::fs::symlink_metadata(path).map_err(|_| required.to_string())?;
        if !info.is_dir()
            || info.uid() != unsafe { libc::geteuid() }
            || info.mode() & 0o7777 != 0o700
        {
            return Err(required.into());
        }
        #[cfg(target_os = "macos")]
        crate::manager_host::no_acl(path)?;
        Ok(())
    }
    #[cfg(windows)]
    {
        crate::windows_protection::require_private_directory(path)
            .map_err(|_| "host_install_windows_profile_required".into())
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Err("host_install_platform_unsupported".into())
    }
}
#[cfg(any(target_os = "macos", target_os = "linux", windows, test))]
fn native_release(version: &str, revision: &str) -> Result<String, String> {
    if version.split('.').count() != 3
        || !version.split('.').all(|part| {
            !part.is_empty() && part.len() <= 5 && part.bytes().all(|b| b.is_ascii_digit())
        })
        || !crate::native_runtime::digest_valid(revision, 40)
    {
        return Err("native_host_version_invalid".into());
    }
    Ok(format!("frameleaf-v{version}-native.{}-1", &revision[..12]))
}
#[cfg(windows)]
fn pin_profile_leaf(path: &std::path::Path) -> Result<Vec<std::fs::File>, String> {
    crate::windows_protection::pin_private_directory(path)
        .map_err(|_| "host_install_windows_profile_required".into())
}

/// Re-read an installed package record and verify its controller and signed runtime.
#[cfg(any(target_os = "macos", target_os = "linux", windows))]
fn verified(
    record: &Installation,
) -> Result<
    (
        crate::host_install::Layout,
        crate::host_runtime::VerifiedHostRuntime,
    ),
    String,
> {
    let current = Installation::read(&record.manifest_sha256)?;
    if &current != record {
        return Err("host_install_record_invalid".into());
    }
    let layout = record.layout()?;
    let controller = crate::runtime_store::read_bounded(&layout.controller, 256 * 1024 * 1024)?;
    if format!("{:x}", Sha256::digest(controller)) != record.controller_sha256 {
        return Err("host_install_controller_changed".into());
    }
    let raw = crate::runtime_store::read_bounded(
        &layout.runtime.join("manifest.json"),
        16 * 1024 * 1024,
    )?;
    let signature: [u8; 64] =
        crate::runtime_store::read_bounded(&layout.runtime.join("manifest.sig"), 64)?
            .try_into()
            .map_err(|_| "host_signature_invalid")?;
    let runtime = crate::release_policy::verify_host_runtime(
        &layout.runtime.join("payload"),
        &raw,
        &signature,
    )?;
    if runtime.manifest_sha256() != record.manifest_sha256 {
        return Err("host_install_runtime_changed".into());
    }
    Ok((layout, runtime))
}

#[cfg(any(target_os = "macos", target_os = "linux", windows))]
fn verify_installed_package(record: &Installation) -> Result<(), String> {
    let layout = record.layout()?;
    let _lease = crate::package_lease::CodeLease::acquire_existing(&layout.runtime)?;
    let (_, runtime) = verified(record)?;
    runtime.manager_programs()?;
    Ok(())
}

/// The Manager configuration for a verified package and this account's profile paths.
#[cfg(any(target_os = "macos", target_os = "linux", windows))]
fn configuration<U: Serialize>(
    record: &Installation,
    layout: &crate::host_install::Layout,
    runtime: &crate::host_runtime::VerifiedHostRuntime,
    uid: &U,
    state: std::path::PathBuf,
    data: std::path::PathBuf,
    ports: crate::manager_local::Ports,
) -> Result<Configuration, String> {
    let package: serde_json::Value = serde_json::from_slice(&crate::runtime_store::read_bounded(
        &layout.runtime.join("payload/server/package.json"),
        64 * 1024,
    )?)
    .map_err(|_| "native_host_version_invalid")?;
    let release = native_release(
        package["version"]
            .as_str()
            .ok_or("native_host_version_invalid")?,
        runtime.source_revision(),
    )?;
    let identity = serde_json::to_vec(&(record, uid)).map_err(|_| "native_host_setup_failed")?;
    Ok(Configuration {
        installation_id: format!("{:x}", Sha256::digest(identity))[..12].into(),
        name: "My Frameleaf library".into(),
        release,
        controller: layout.controller.clone(),
        state,
        data,
        origin: ports.origin(),
        database_port: ports.database,
        api_port: ports.api,
    })
}

/// Why the package a library last ran with cannot be the start of a move. A package that is
/// correctly signed but built for another version of this app is named as that: the selected
/// package is not what is wrong, and installing it again would not help. Such a move is not
/// made, because its pins include the database version and nothing here migrates a database.
#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn previous_package_refusal(code: String) -> String {
    if code == "host_manifest_incompatible" {
        "host_upgrade_previous_package_incompatible".into()
    } else {
        code
    }
}

/// A library keeps its first installation identity. Moving it to a newer signed package copies its
/// saved secrets and repoints its journals while it is cleanly stopped; downgrades are refused.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn carry_forward(
    record: &Installation,
    runtime: &crate::host_runtime::VerifiedHostRuntime,
    next: &mut Configuration,
    uid: u32,
) -> Result<(), String> {
    let Some(marker) = crate::host_state::Owner::peek(&next.state)? else {
        return Ok(());
    };
    next.installation_id = marker.installation_id.clone();
    if marker.manifest_sha256 == record.manifest_sha256 {
        return Ok(());
    }
    let previous_record = Installation::read(&marker.manifest_sha256)
        .map_err(|_| "host_upgrade_previous_package_missing")?;
    let (previous_layout, previous_runtime) =
        verified(&previous_record).map_err(previous_package_refusal)?;
    if runtime.epoch() <= previous_runtime.epoch() {
        return Err("host_upgrade_downgrade_refused".into());
    }
    let mut previous = configuration(
        &previous_record,
        &previous_layout,
        &previous_runtime,
        &uid,
        next.state.clone(),
        next.data.clone(),
        // The ports Manager last ran with: its descriptor, and so the transition, names them.
        next.ports()?,
    )?;
    previous.installation_id = marker.installation_id.clone();
    let layout = record.layout()?;
    // Hold the previous package and the journal for the whole move.
    let _code = crate::package_lease::CodeLease::acquire(&previous_layout.runtime)?;
    let owner = crate::host_state::Owner::acquire(&next.state, true)?;
    // Manager accepts the new package only from the exact descriptor it last ran with.
    let old_binding = crate::manager_profile::Profile::binding_for(
        &previous,
        &previous_layout.runtime,
        &marker.manifest_sha256,
    )?;
    let transition = crate::manager_tls::TlsIdentity::saved_certificate(&old_binding)?
        .map(|certificate| -> Result<_, String> {
            Ok(crate::manager_host::Transition {
                operation_id: uuid::Uuid::new_v4(),
                from_fingerprint: crate::manager_host::descriptor_fingerprint(
                    &previous,
                    &previous_layout.runtime,
                    &previous_runtime,
                    &previous_record.controller_sha256,
                    &certificate,
                )?,
            })
        })
        .transpose()?;
    move_library(
        owner,
        Package {
            config: &previous,
            candidate: &previous_layout.runtime,
            manifest: &marker.manifest_sha256,
            revision: previous_runtime.source_revision(),
        },
        Package {
            config: next,
            candidate: &layout.runtime,
            manifest: &record.manifest_sha256,
            revision: runtime.source_revision(),
        },
        |previous, next| crate::manager_profile::Profile::carry_forward(previous, next, transition),
        crate::manager_tls::TlsIdentity::carry_forward,
    )
}

/// One side of a library move: the package's configuration, location and identity.
#[cfg(unix)]
struct Package<'a> {
    config: &'a Configuration,
    candidate: &'a std::path::Path,
    manifest: &'a str,
    revision: &'a str,
}

/// Every check runs before the first change; the journal write last commits the move.
#[cfg(unix)]
fn move_library(
    mut owner: crate::host_state::Owner,
    previous: Package,
    next: Package,
    profile: impl FnOnce(
        (&Configuration, &std::path::Path, &str),
        (&Configuration, &std::path::Path, &str),
    ) -> Result<(String, String), String>,
    tls: impl FnOnce(&str, &str) -> Result<(), String>,
) -> Result<(), String> {
    let id = &previous.config.installation_id;
    owner.check_movable(id, previous.manifest)?;
    host_state_package(
        &next.config.state,
        (previous.manifest, previous.revision),
        (next.manifest, next.revision),
    )?;
    let (old, new) = profile(
        (previous.config, previous.candidate, previous.manifest),
        (next.config, next.candidate, next.manifest),
    )?;
    tls(&old, &new)?;
    carry_host_state(
        &next.config.state,
        (previous.manifest, previous.revision),
        (next.manifest, next.revision),
    )?;
    owner.carry_forward(id, previous.manifest, next.manifest)
}

/// The exact bytes the host agent writes for a package's marker.
#[cfg(unix)]
fn host_state_marker((manifest, revision): (&str, &str)) -> Result<String, String> {
    if !crate::native_runtime::digest_valid(manifest, 64)
        || !crate::native_runtime::digest_valid(revision, 40)
    {
        return Err("host_state_invalid".into());
    }
    Ok(format!(
        r#"{{"schemaVersion":1,"manifestSha256":"{manifest}","sourceRevision":"{revision}","postgresMajor":"19"}}"#
    ))
}

#[cfg(unix)]
#[derive(Debug, PartialEq)]
enum HostStatePackage {
    /// The host never created its database; the agent starts it fresh for any package.
    Unclaimed,
    Previous,
    Next,
}

/// Read-only: which package the host agent's marker names.
#[cfg(unix)]
fn host_state_package(
    state: &std::path::Path,
    previous: (&str, &str),
    next: (&str, &str),
) -> Result<HostStatePackage, String> {
    use std::io::Read;
    let (previous, next) = (host_state_marker(previous)?, host_state_marker(next)?);
    let root = cap_std::fs::Dir::from_std_file(crate::host_storage::directory(state)?);
    let mut file = match root.open_with("host-state.json", &crate::host_state::options(false)) {
        Ok(file) => file.into_std(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            for entry in root.entries().map_err(|_| "host_state_invalid")? {
                let name = entry.map_err(|_| "host_state_invalid")?.file_name();
                if !["lease.lock", "agent.log", "controller-state.json"]
                    .iter()
                    .any(|allowed| name == std::ffi::OsStr::new(allowed))
                {
                    return Err("host_update_requires_manager".into());
                }
            }
            return Ok(HostStatePackage::Unclaimed);
        }
        Err(_) => return Err("host_state_invalid".into()),
    };
    crate::host_state::valid_file(&file).map_err(|_| "host_state_invalid")?;
    let mut current = String::new();
    Read::by_ref(&mut file)
        .take(4097)
        .read_to_string(&mut current)
        .map_err(|_| "host_state_invalid")?;
    if current == next {
        Ok(HostStatePackage::Next)
    } else if current == previous {
        Ok(HostStatePackage::Previous)
    } else {
        Err("host_update_requires_manager".into())
    }
}

/// The host agent's package marker names the package that last ran this database.
#[cfg(unix)]
fn carry_host_state(
    state: &std::path::Path,
    previous: (&str, &str),
    next: (&str, &str),
) -> Result<(), String> {
    use std::io::Write;
    if host_state_package(state, previous, next)? != HostStatePackage::Previous {
        return Ok(());
    }
    let marker = host_state_marker(next)?;
    let root = cap_std::fs::Dir::from_std_file(crate::host_storage::directory(state)?);
    // A fixed name lets a retry replace what an interrupted move left behind.
    let temp = ".host-state.json.carry.tmp";
    match root.remove_file(temp) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
            return Err("host_state_invalid".into())
        }
        _ => {}
    }
    let result = (|| -> Result<(), String> {
        let mut options = crate::host_state::options(true);
        options.create_new(true);
        let mut output = root
            .open_with(temp, &options)
            .map_err(|_| "host_state_invalid")?
            .into_std();
        output
            .write_all(marker.as_bytes())
            .and_then(|_| output.sync_all())
            .map_err(|_| "host_state_invalid")?;
        drop(output);
        root.rename(temp, &root, "host-state.json")
            .map_err(|_| "host_state_invalid")?;
        crate::host_storage::directory(state)?
            .sync_all()
            .map_err(|_| "host_state_invalid".to_string())
    })();
    if result.is_err() {
        let _ = root.remove_file(temp);
    }
    result
}

/// The Library version a package carries, for display only.
pub(crate) fn package_version(record: &Installation) -> Option<String> {
    let layout = record.layout().ok()?;
    let raw = crate::runtime_store::read_bounded(
        &layout.runtime.join("payload/server/package.json"),
        64 * 1024,
    )
    .ok()?;
    let version = serde_json::from_slice::<serde_json::Value>(&raw).ok()?["version"]
        .as_str()?
        .to_owned();
    (version.split('.').count() == 3
        && version.split('.').all(|part| {
            !part.is_empty() && part.len() <= 5 && part.bytes().all(|b| b.is_ascii_digit())
        }))
    .then_some(version)
}

/// The package this account's library last ran with, for display only.
pub(crate) fn library_package(records: &[Installation]) -> Option<String> {
    #[cfg(unix)]
    let state = {
        records.first()?;
        crate::host_install::account_profile().join("state")
    };
    #[cfg(windows)]
    let state = {
        records.first()?;
        crate::windows_host_profile::paths().ok()?.0
    };
    crate::host_state::Owner::peek(&state)
        .ok()
        .flatten()
        .map(|marker| marker.manifest_sha256)
}

fn launch(
    record: &Installation,
    cancel: &AtomicBool,
    renew_identity: bool,
    renewing: &AtomicBool,
) -> Result<Running, String> {
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        let _ = (record, cancel, renew_identity, renewing);
        Err("host_install_platform_unsupported".into())
    }
    #[cfg(any(target_os = "macos", target_os = "linux", windows))]
    {
        let (layout, runtime) = verified(record)?;
        #[cfg(unix)]
        let uid = {
            let uid = unsafe { libc::geteuid() };
            let minimum_uid = if cfg!(target_os = "linux") { 1 } else { 501 };
            if uid < minimum_uid || unsafe { libc::getuid() } != uid {
                return Err("host_install_profile_required".into());
            }
            uid
        };
        #[cfg(windows)]
        let uid = crate::windows_protection::process_user_sid()?;
        #[cfg(unix)]
        let profile = layout.profiles.join(uid.to_string());
        #[cfg(unix)]
        let state = profile.join("state");
        #[cfg(unix)]
        let data = profile.join("manager");
        #[cfg(windows)]
        let (state, data) = crate::windows_host_profile::paths()?;
        // Downstream shared setup helpers may create missing leaves; keep both existing objects pinned.
        #[cfg(windows)]
        let _profiles = [pin_profile_leaf(&state)?, pin_profile_leaf(&data)?];
        require_leaf(&state)?;
        require_leaf(&data)?;
        // Where this library last listened. A record that cannot be read refuses the start.
        let recorded = crate::manager_local::recorded(&data)?;
        // A Manager left running by a crashed run of this app still holds this library. Stop
        // that exact process, then give its controller time to finish closing the database.
        #[cfg(unix)]
        if crate::manager_host::stop_orphaned_manager(
            &data,
            Duration::from_secs(15),
            cancel,
            &|| crate::manager_local::recorded_manager_listener(&data),
        )? {
            let deadline = std::time::Instant::now() + Duration::from_secs(60);
            while crate::host_state::Owner::controller_running(&state) == Ok(true)
                && std::time::Instant::now() < deadline
                && !cancel.load(Ordering::Acquire)
            {
                std::thread::sleep(Duration::from_millis(100));
            }
        }
        #[allow(unused_mut)]
        let mut configuration =
            configuration(record, &layout, &runtime, &uid, state, data, recorded.ports)?;
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        carry_forward(record, &runtime, &mut configuration, uid)?;
        if cancel.load(Ordering::Acquire) {
            return Err("native_manager_start_cancelled".into());
        }
        let programs = runtime.manager_programs()?;
        if cancel.load(Ordering::Acquire) {
            return Err("native_manager_start_cancelled".into());
        }
        // Only what this package's Manager declares is used: anything else stays as it was.
        let features = crate::manager_local::Features::of_package(&layout.runtime);
        // Records its launch before spawning, and the spawned process after.
        let manager = programs.start_from_keystore(
            &mut configuration,
            &crate::manager_host::LocalStart {
                features,
                renew_identity,
                renewing,
            },
        )?;
        Ok(Running {
            manager,
            configuration,
            installation: record.clone(),
            features,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn photos_ask_manager_for_its_state_only_when_it_declares_that_and_open_only_on_running()
    {
        use crate::manager::Command;
        use crate::manager_local::Features;
        use serde_json::json;
        // Today's released Manager declares nothing: it is not asked, and nothing changes.
        for features in [
            Features::default(),
            Features {
                ports: true,
                tls_rotation: true,
                runtime_status: false,
            },
        ] {
            let never = |_: Command| async { panic!("a Manager that does not declare it") };
            assert_eq!(photo_server_proof(features, never, 2283).await, Ok(()));
        }
        let capable = Features {
            runtime_status: true,
            ..Features::default()
        };
        let asked = |reply: Result<serde_json::Value, String>| async move {
            photo_server_proof(
                capable,
                |command| {
                    assert!(matches!(command, Command::Runtime { nonce } if !nonce.is_nil()));
                    async move { reply }
                },
                2283,
            )
            .await
        };
        let state = |server: serde_json::Value| json!({"ports":{"manager":9443,"api":2283,"database":54329},"photoServer":server});
        assert_eq!(asked(Ok(state(json!({"state":"running"})))).await, Ok(()));
        for (server, code) in [
            (json!({"state":"starting"}), "local_photos_starting"),
            (json!({"state":"stopping"}), "local_photos_not_running"),
            (json!({"state":"stopped"}), "local_photos_not_running"),
            // A backup or restore holds the controller: whatever answers on the port is not
            // this library's photo server.
            (
                json!({"state":"unknown","code":"native_database_maintenance"}),
                "local_photos_maintenance",
            ),
            (
                json!({"state":"unknown","code":"native_restore_maintenance"}),
                "local_photos_maintenance",
            ),
            (
                json!({"state":"unknown","code":"native_checkpoint_cleanup_maintenance"}),
                "local_photos_maintenance",
            ),
            (
                json!({"state":"unknown","code":"native_owner_not_attached"}),
                "local_photos_not_running",
            ),
            (json!({"state":"unknown"}), "local_photos_not_running"),
            (json!({"state":"serving"}), "manager_response_invalid"),
            (json!({}), "manager_response_invalid"),
            (json!(null), "manager_response_invalid"),
        ] {
            assert_eq!(asked(Ok(state(server))).await, Err(code.to_string()));
        }
        // Running, but not on the port this library's photos are opened on.
        for reply in [
            json!({"ports":{"manager":9443,"api":2284,"database":54329},"photoServer":{"state":"running"}}),
            json!({"photoServer":{"state":"running"}}),
        ] {
            assert_eq!(
                asked(Ok(reply)).await,
                Err("manager_response_invalid".to_string())
            );
        }
        // No answer, or one that could not be read, never opens the address.
        for failure in [
            "manager_unreachable_or_certificate_invalid",
            "manager_response_invalid",
            "desktop_route_unavailable",
        ] {
            assert_eq!(asked(Err(failure.into())).await, Err(failure.to_string()));
        }
    }

    #[test]
    fn a_failed_renewal_is_retried_once_with_the_identity_it_would_have_replaced() {
        use std::cell::RefCell;
        let cancel = AtomicBool::new(false);
        // What each attempt did: (may renew, presented a renewed identity, outcome).
        let run =
            |renews: bool, outcomes: Vec<Result<&'static str, String>>, cancel: &AtomicBool| {
                let attempts = RefCell::new(Vec::new());
                let outcomes = RefCell::new(outcomes.into_iter());
                let result = tauri::async_runtime::block_on(started_with_renewal(
                    |renew, renewing| {
                        attempts.borrow_mut().push(renew);
                        if renew && renews {
                            renewing.store(true, Ordering::Release);
                        }
                        let outcome = outcomes.borrow_mut().next().expect("no further attempt");
                        async move { outcome }
                    },
                    cancel,
                ));
                (result, attempts.into_inner())
            };
        // Nothing to renew: one attempt, whatever it returns.
        assert_eq!(
            run(false, vec![Ok("started")], &cancel),
            (Ok("started"), vec![true])
        );
        assert_eq!(
            run(false, vec![Err("local_port_in_use_2283".into())], &cancel),
            (Err("local_port_in_use_2283".into()), vec![true])
        );
        // A renewal that succeeds needs no second attempt.
        assert_eq!(
            run(true, vec![Ok("renewed")], &cancel),
            (Ok("renewed"), vec![true])
        );
        // A renewal that fails: the earlier identity is tried, without renewing.
        assert_eq!(
            run(
                true,
                vec![Err("native_manager_exited".into()), Ok("rolled back")],
                &cancel
            ),
            (Ok("rolled back"), vec![true, false])
        );
        // If that fails too, the first failure is the one that is reported.
        assert_eq!(
            run(
                true,
                vec![
                    Err("native_manager_exited".into()),
                    Err("native_tls_identity_expired".into())
                ],
                &cancel
            ),
            (Err("native_manager_exited".into()), vec![true, false])
        );
        // A start the person cancelled is not started again.
        cancel.store(true, Ordering::Release);
        assert_eq!(
            run(
                true,
                vec![Err("native_manager_start_cancelled".into())],
                &cancel
            ),
            (Err("native_manager_start_cancelled".into()), vec![true])
        );
    }

    /// Deny replacement of the executable and of its path while either Desktop launch is possible.
    #[cfg(windows)]
    fn pin_watcher_executable(path: &std::path::Path) -> (Vec<std::fs::File>, std::fs::File) {
        use std::{
            fs::OpenOptions,
            os::windows::fs::{MetadataExt, OpenOptionsExt},
        };
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
            FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE,
        };

        let ancestors: Vec<_> = path.ancestors().skip(1).collect();
        let pins = ancestors
            .into_iter()
            .rev()
            .map(|ancestor| {
                let pin = OpenOptions::new()
                    .access_mode(FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES)
                    .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                    .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                    .open(ancestor)
                    .expect("could not pin the installed Desktop directory");
                let info = pin.metadata().unwrap();
                assert!(
                    info.is_dir() && info.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0
                );
                pin
            })
            .collect();
        let file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .expect("could not pin the installed Desktop executable");
        let info = file.metadata().unwrap();
        assert!(info.is_file() && info.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0);
        (pins, file)
    }

    /// Run the released app as a client of a separate disposable signed Library.
    #[cfg(windows)]
    #[test]
    #[ignore = "requires an installed Desktop and signed companion on a fresh Windows runner"]
    fn disposable_runner_installed_desktop_watches_while_hidden() {
        use std::{
            io::{Read, Write},
            net::TcpListener,
            path::PathBuf,
            process::{Command, Stdio},
            time::Instant,
        };
        use zeroize::Zeroizing;

        assert_eq!(std::env::var("GITHUB_ACTIONS").as_deref(), Ok("true"));
        assert_eq!(
            std::env::var("RUNNER_ENVIRONMENT").as_deref(),
            Ok("github-hosted")
        );
        let runner = PathBuf::from(std::env::var_os("RUNNER_TEMP").unwrap())
            .canonicalize()
            .unwrap();
        let executable = PathBuf::from(std::env::var_os("FRAMELEAF_WATCH_DESKTOP_EXE").unwrap());
        let physical = executable.canonicalize().unwrap();
        assert!(executable.is_absolute() && physical.starts_with(&runner) && physical.is_file());
        assert_eq!(physical.file_name().unwrap(), "frameleaf-desktop.exe");
        // Start-Process needs the physical DOS path, with no user-controlled alias or reparse point.
        let launch_path = physical
            .to_str()
            .and_then(|path| path.strip_prefix(r"\\?\"))
            .unwrap();
        assert!(std::path::Path::new(launch_path).is_absolute());
        let (directories, mut executable_file) = pin_watcher_executable(&physical);
        assert_eq!(
            std::path::Path::new(launch_path).canonicalize().unwrap(),
            physical
        );
        let expected = std::env::var("FRAMELEAF_WATCH_DESKTOP_SHA256").unwrap();
        let limit = 256 * 1024 * 1024;
        let mut bytes = Vec::new();
        (&mut executable_file)
            .take(limit + 1)
            .read_to_end(&mut bytes)
            .unwrap();
        assert!(bytes.len() as u64 <= limit);
        assert_eq!(format!("{:x}", Sha256::digest(bytes)), expected);

        let (state, _) = crate::windows_host_profile::paths().unwrap();
        assert!(
            !state.parent().unwrap().exists(),
            "requires a fresh native profile"
        );
        let local_data = crate::host_install::windows_local_app_data().unwrap();
        assert!(
            !local_data.join("app.frameleaf.desktop").exists(),
            "requires a fresh Desktop app data directory"
        );
        for account in [
            "connection",
            "installation",
            crate::manager::CREDENTIAL,
            crate::source_consent::CREDENTIAL,
        ] {
            assert!(
                crate::credentials::load::<serde_json::Value>(account)
                    .unwrap()
                    .is_none(),
                "requires a fresh Desktop credential store"
            );
        }
        let listener = TcpListener::bind(("127.0.0.1", 2283)).unwrap();
        let database = TcpListener::bind(("127.0.0.1", 54329)).unwrap();
        let manifest = std::env::var("FRAMELEAF_INSTALLED_HOST_MANIFEST").unwrap();
        let record =
            Installation::read(&manifest).expect("expected the approved installed companion");
        let (layout, runtime) = verified(&record).expect("installed companion verification failed");

        let scratch = crate::runtime_store::Staging::create(
            runner.join(format!("frameleaf-watch-library-{}", uuid::Uuid::new_v4())),
        )
        .unwrap();
        let source = crate::runtime_store::Staging::create(
            PathBuf::from(std::env::var_os("USERPROFILE").unwrap())
                .join(format!("frameleaf-watch-source-{}", uuid::Uuid::new_v4())),
        )
        .unwrap();
        let database_password = Zeroizing::new(format!("Synthetic-db-{}!", uuid::Uuid::new_v4()));
        let photo_password = Zeroizing::new(format!("Synthetic-photo-{}!", uuid::Uuid::new_v4()));
        drop((listener, database));
        let mut host = runtime
            .start(
                scratch.path(),
                &database_password,
                54329,
                2283,
                &layout.controller,
            )
            .expect("disposable signed Library did not start");
        host.wait_ready(Duration::from_secs(240)).unwrap();

        let tools = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../tools");
        let mut command = Command::new("powershell.exe");
        command
            .args(["-NoProfile", "-File"])
            .arg(tools.join("qualify_windows_welcome.ps1"))
            .arg("-Executable")
            .arg(launch_path)
            .arg("-WatchedFolder")
            .arg(source.path())
            .stdin(Stdio::piped())
            .env(
                "FRAMELEAF_SYNTHETIC_PHOTO_PASSWORD",
                photo_password.as_str(),
            );
        let mut smoke = command
            .spawn()
            .expect("Windows UI Automation could not start");
        let tree = crate::process_tree::ProcessTree::attach(&smoke).unwrap_or_else(|_| {
            let _ = smoke.kill();
            let _ = smoke.wait();
            panic!("could not own the Windows acceptance process tree");
        });
        let handshake_sent = smoke
            .stdin
            .take()
            .is_some_and(|mut stdin| stdin.write_all(b"frameleaf-watch-smoke\r\n").is_ok());
        let deadline = Instant::now() + Duration::from_secs(900);
        let result = handshake_sent
            && loop {
                match smoke.try_wait() {
                    Ok(Some(status)) => break status.success(),
                    Ok(None) if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(250))
                    }
                    _ => break false,
                }
            };
        let terminated = tree.terminate_confirmed(Duration::from_secs(20));
        drop((executable_file, directories));
        let stopped = host.stop();
        terminated.expect("Windows acceptance process cleanup failed");
        assert!(handshake_sent, "Windows acceptance handshake failed");
        assert!(result, "installed Desktop watcher acceptance failed");
        stopped.expect("disposable Library shutdown failed");
    }

    /// Exercise an installed watcher in a fresh graphical account with a synthetic Library.
    #[cfg(any(
        all(target_os = "macos", target_arch = "aarch64"),
        all(target_os = "linux", target_arch = "x86_64")
    ))]
    #[test]
    #[ignore = "requires an interactive disposable account with approved installed packages"]
    fn disposable_unix_installed_desktop_watch_and_resume() {
        use std::{io::IsTerminal, net::TcpListener, path::PathBuf, process::Command};
        use zeroize::Zeroizing;

        assert_eq!(
            std::env::var("FRAMELEAF_WATCH_DISPOSABLE").as_deref(),
            Ok("1")
        );
        assert!(std::io::stdin().is_terminal() && std::io::stderr().is_terminal());
        assert_ne!(
            unsafe { libc::geteuid() },
            0,
            "requires an unprivileged account"
        );
        let security = crate::credential_lock::directory().unwrap();
        let home = security.parent().unwrap().canonicalize().unwrap();
        assert!(
            !security.exists(),
            "requires a fresh Desktop installation identity"
        );
        let data = if cfg!(target_os = "macos") {
            home.join("Library/Application Support")
        } else {
            std::env::var_os("XDG_DATA_HOME")
                .filter(|value| !value.is_empty())
                .map(PathBuf::from)
                .unwrap_or_else(|| home.join(".local/share"))
        };
        assert!(data.is_absolute() && !data.join("app.frameleaf.desktop").exists());
        for account in [
            "connection",
            "installation",
            crate::manager::CREDENTIAL,
            crate::source_consent::CREDENTIAL,
        ] {
            assert!(
                crate::credentials::load::<serde_json::Value>(account)
                    .unwrap()
                    .is_none(),
                "requires a fresh Desktop credential store"
            );
        }

        let executable = PathBuf::from(std::env::var_os("FRAMELEAF_WATCH_DESKTOP_EXE").unwrap());
        assert!(executable.is_absolute() && executable.is_file());
        assert_eq!(executable.canonicalize().unwrap(), executable);
        assert_eq!(executable.file_name().unwrap(), "frameleaf-desktop");
        let expected = std::env::var("FRAMELEAF_WATCH_DESKTOP_SHA256").unwrap();
        assert!(crate::native_runtime::digest_valid(&expected, 64));

        let listener = TcpListener::bind(("127.0.0.1", 2283)).unwrap();
        let database = TcpListener::bind(("127.0.0.1", 54329)).unwrap();
        let manifest = std::env::var("FRAMELEAF_INSTALLED_HOST_MANIFEST").unwrap();
        let record =
            Installation::read(&manifest).expect("expected the approved installed companion");
        let (_, runtime) = verified(&record).expect("installed companion verification failed");
        // Both the database and watcher require admitted local filesystems. /tmp can be tmpfs.
        let scratch = crate::runtime_store::Staging::create(
            home.join(format!("frameleaf-watch-library-{}", uuid::Uuid::new_v4())),
        )
        .unwrap();
        let source = crate::runtime_store::Staging::create(
            home.join(format!("frameleaf-watch-source-{}", uuid::Uuid::new_v4())),
        )
        .unwrap();
        let database_password = Zeroizing::new(format!("Synthetic-db-{}!", uuid::Uuid::new_v4()));
        let photo_password = Zeroizing::new(format!("Synthetic-photo-{}!", uuid::Uuid::new_v4()));
        drop((listener, database));
        let mut host = runtime
            .start(scratch.path(), &database_password, 54329, 2283)
            .expect("disposable signed Library did not start");
        host.wait_ready(Duration::from_secs(240)).unwrap();

        let tools = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../tools");
        let result = Command::new("node")
            .arg(tools.join("qualify_installed_photo.mjs"))
            .arg("watch-interactive")
            .arg(source.path())
            .arg(&executable)
            .arg(&expected)
            .env(
                "FRAMELEAF_SYNTHETIC_PHOTO_PASSWORD",
                photo_password.as_str(),
            )
            .status();
        host.stop().expect("disposable Library shutdown failed");
        assert!(
            result.is_ok_and(|status| status.success()),
            "installed Desktop watcher acceptance failed"
        );
        println!("Installed watcher acceptance executable SHA-256: {expected}; companion manifest: {manifest}");
    }

    #[cfg(windows)]
    #[tokio::test]
    #[ignore = "requires an installed companion on a disposable hosted runner"]
    async fn disposable_runner_diagnoses_installed_manager_start() {
        assert_eq!(std::env::var("GITHUB_ACTIONS").as_deref(), Ok("true"));
        assert_eq!(
            std::env::var("RUNNER_ENVIRONMENT").as_deref(),
            Ok("github-hosted")
        );
        let manifest = std::env::var("FRAMELEAF_INSTALLED_HOST_MANIFEST")
            .expect("expected the reviewed installed companion identity");
        let setup = HostSetup::default();
        let view = setup
            .start(manifest)
            .await
            .expect("installed Manager startup refused");
        assert_eq!(view.state, "manager-ready");
        setup
            .stop()
            .await
            .expect("installed Manager shutdown failed");
    }

    #[cfg(unix)]
    #[test]
    fn host_package_marker_moves_forward_once_and_refuses_unknown_packages() {
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("frameleaf-host-marker-{}", uuid::Uuid::new_v4()));
        crate::runtime_store::private_directory(&root).unwrap();
        let path = root.join("host-state.json");
        let marker = |m: &str, r: &str| {
            format!(
                r#"{{"schemaVersion":1,"manifestSha256":"{m}","sourceRevision":"{r}","postgresMajor":"19"}}"#
            )
        };
        let (a, b, c) = ("a".repeat(64), "b".repeat(64), "c".repeat(64));
        let (ra, rb) = ("1".repeat(40), "2".repeat(40));
        let write = |text: &str| {
            use std::os::unix::fs::OpenOptionsExt;
            let _ = std::fs::remove_file(&path);
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .unwrap();
            std::fs::write(&path, text).unwrap();
        };
        write(&marker(&a, &ra));
        carry_host_state(&root, (&a, &ra), (&b, &rb)).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), marker(&b, &rb));
        carry_host_state(&root, (&a, &ra), (&b, &rb)).unwrap();
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
        write(&marker(&c, &ra));
        assert_eq!(
            carry_host_state(&root, (&a, &ra), (&b, &rb)).unwrap_err(),
            "host_update_requires_manager"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), marker(&c, &ra));
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn library_move_checks_everything_before_its_first_change() {
        use crate::host_state::Owner;
        let (a, b, c) = ("a".repeat(64), "b".repeat(64), "c".repeat(64));
        let (ra, rb) = ("1".repeat(40), "2".repeat(40));
        let id = "aaaaaaaaaaaa";
        let setup = |active: bool, marker: Option<&str>, pending: bool| {
            let root = std::env::temp_dir()
                .canonicalize()
                .unwrap()
                .join(format!("frameleaf-library-move-{}", uuid::Uuid::new_v4()));
            let state = root.join("state");
            crate::runtime_store::private_directory(&root).unwrap();
            let mut owner = Owner::acquire(&state, true).unwrap();
            owner
                .activate(id, &a, crate::host_runtime::HostMode::Server)
                .unwrap();
            if !active {
                owner.clean_stop().unwrap();
            }
            drop(owner);
            if let Some(text) = marker {
                use std::os::unix::fs::OpenOptionsExt;
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(state.join("host-state.json"))
                    .unwrap();
                std::io::Write::write_all(&mut file, text.as_bytes()).unwrap();
            }
            if pending {
                crate::runtime_store::private_directory(&state.join("checkpoints")).unwrap();
                crate::runtime_store::private_directory(&state.join("checkpoints/op")).unwrap();
            }
            (root, state)
        };
        let config = |state: &std::path::Path| Configuration {
            installation_id: id.into(),
            name: "Synthetic".into(),
            release: "frameleaf-v3.0.0-1".into(),
            controller: "/bin/echo".into(),
            state: state.into(),
            data: state.with_file_name("manager"),
            origin: "https://127.0.0.1:9443".into(),
            database_port: 54329,
            api_port: 2283,
        };
        let run = |state: &std::path::Path| {
            let config = config(state);
            let calls = std::cell::Cell::new(0);
            let owner = Owner::acquire(state, true);
            let result = owner.and_then(|owner| {
                move_library(
                    owner,
                    Package {
                        config: &config,
                        candidate: std::path::Path::new("/runtime/a"),
                        manifest: &a,
                        revision: &ra,
                    },
                    Package {
                        config: &config,
                        candidate: std::path::Path::new("/runtime/b"),
                        manifest: &b,
                        revision: &rb,
                    },
                    |_, _| {
                        calls.set(calls.get() + 1);
                        Ok(("d".repeat(64), "e".repeat(64)))
                    },
                    |_, _| Ok(()),
                )
            });
            (result, calls.get())
        };
        let previous = host_state_marker((&a, &ra)).unwrap();
        for (active, marker, pending, code) in [
            (
                true,
                Some(previous.clone()),
                false,
                "host_recovery_requires_manager",
            ),
            (
                false,
                Some(previous.clone()),
                true,
                "host_upgrade_operation_pending",
            ),
            (
                false,
                Some(host_state_marker((&c, &ra)).unwrap()),
                false,
                "host_update_requires_manager",
            ),
        ] {
            let (root, state) = setup(active, marker.as_deref(), pending);
            let before = std::fs::read(state.join("host-state.json")).unwrap();
            let (result, calls) = run(&state);
            assert_eq!(result.unwrap_err(), code);
            assert_eq!(calls, 0, "nothing changes before every check passes");
            assert_eq!(
                std::fs::read(state.join("host-state.json")).unwrap(),
                before
            );
            std::fs::remove_dir_all(root).unwrap();
        }
        let (root, state) = setup(false, Some(&previous), false);
        let (result, calls) = run(&state);
        result.unwrap();
        assert_eq!(calls, 1);
        assert_eq!(
            std::fs::read_to_string(state.join("host-state.json")).unwrap(),
            host_state_marker((&b, &rb)).unwrap()
        );
        assert_eq!(Owner::peek(&state).unwrap().unwrap().manifest_sha256, b);
        assert_eq!(
            run(&state).0.unwrap_err(),
            "host_controller_binding_changed"
        );
        std::fs::remove_dir_all(root).unwrap();
        // A host that never created its database moves without a marker to rewrite.
        let (root, state) = setup(false, None, false);
        run(&state).0.unwrap();
        assert!(!state.join("host-state.json").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn update_excludes_local_host_operations() {
        let setup = HostSetup::default();
        let update = setup.lock_for_update().unwrap();
        assert!(setup.owner.try_lock().is_err());
        assert!(setup.lock_for_update().is_err());
        drop(update);
        // A live Manager's exclusion is covered where a Manager is owned; a stale flag alone
        // can no longer block an update.
        setup.active.store(true, Ordering::Release);
        assert!(setup.lock_for_update().is_ok());
    }

    #[cfg(windows)]
    #[test]
    fn pinned_profile_leaf_cannot_disappear_during_shared_startup_helpers() {
        let root =
            std::env::temp_dir().join(format!("frameleaf-setup-pin-{}", uuid::Uuid::new_v4()));
        crate::runtime_store::private_directory(&root).unwrap();
        let pin = pin_profile_leaf(&root).unwrap();
        assert!(std::fs::remove_dir(&root).is_err());
        assert!(std::fs::rename(&root, root.with_extension("moved")).is_err());
        require_leaf(&root).unwrap();
        crate::runtime_store::private_directory(&root).unwrap();
        drop(pin);
        std::fs::remove_dir(root).unwrap();
    }
    #[tokio::test]
    async fn uninstalled_identity_never_starts_a_manager_or_reads_credentials() {
        let setup = HostSetup::default();
        assert_eq!(
            setup.start("../escape".into()).await.err().unwrap(),
            "host_install_identity_invalid"
        );
        assert!(setup.owner.lock().await.is_none());
        assert!(!setup.background_active());
        assert_eq!(setup.snapshot().state, "idle");
    }
    #[cfg(windows)]
    #[test]
    fn windows_setup_never_creates_missing_or_adopts_inherited_profile_leaves() {
        let root = std::env::temp_dir().join(format!("frameleaf-setup-{}", uuid::Uuid::new_v4()));
        assert_eq!(
            require_leaf(&root).unwrap_err(),
            "host_install_windows_profile_required"
        );
        assert!(!root.exists());
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("retained"), b"synthetic only").unwrap();
        assert!(require_leaf(&root).is_err());
        assert_eq!(
            std::fs::read(root.join("retained")).unwrap(),
            b"synthetic only"
        );
        std::fs::remove_dir_all(&root).unwrap();
        crate::runtime_store::private_directory(&root).unwrap();
        require_leaf(&root).unwrap();
        std::fs::remove_dir(root).unwrap();
    }
    #[test]
    fn compatibility_reports_unknown_without_positive_evidence() {
        assert_eq!(Compatibility::from_check(Ok(())), Compatibility::Verified);
        // A signed package pinned to another app version needs a companion update, not a refusal.
        assert_eq!(
            Compatibility::from_check(Err("host_manifest_incompatible".into())),
            Compatibility::Outdated
        );
        for code in [
            "host_signature_invalid",
            "runtime_artifact_changed",
            "native_manager_unprotected",
        ] {
            assert_eq!(
                Compatibility::from_check(Err(code.into())),
                Compatibility::Refused
            );
        }
        for code in [
            "host_package_selection_changed",
            "host_package_busy",
            "host_package_maintenance",
            "runtime_store_read_failed",
        ] {
            assert_eq!(
                Compatibility::from_check(Err(code.into())),
                Compatibility::Unknown
            );
        }
    }

    #[test]
    fn profile_setup_capability_survives_lifecycle_transitions() {
        let setup = HostSetup::default();
        for state in ["idle", "provisioning", "profile-ready", "needs-attention"] {
            setup.set(state, None, None);
            let view = serde_json::to_value(setup.snapshot()).unwrap();
            assert_eq!(
                view["profileSetupAvailable"],
                cfg!(any(target_os = "linux", windows))
            );
            assert_eq!(view["state"], state);
        }
    }
    #[tokio::test]
    async fn local_photos_requires_an_owned_manager_before_reading_credentials() {
        assert_eq!(
            HostSetup::default().photos_url().await.unwrap_err(),
            "native_manager_not_ready"
        );
    }
    #[test]
    fn local_photos_origin_is_only_the_configured_loopback_port() {
        let url = local_photos_origin(2283).unwrap();
        assert_eq!(url.as_str(), "http://127.0.0.1:2283/");
        assert!(local_photos_origin(0).is_err());
        for other in [
            "http://localhost:2283/",
            "https://127.0.0.1:2283/",
            "http://127.0.0.1:9443/",
            "https://nas.example/",
        ] {
            assert_ne!(url.origin(), url::Url::parse(other).unwrap().origin());
        }
        assert_eq!(url.origin(), url.join("auth/register").unwrap().origin());
    }
    #[test]
    fn native_prerelease_label_preserves_real_version_and_source_identity() {
        assert_eq!(
            native_release("3.2.0", &"a".repeat(40)).unwrap(),
            "frameleaf-v3.2.0-native.aaaaaaaaaaaa-1"
        );
        for version in ["", "3.2", "3.2.0/escape", "3.2.0.1", "3..0"] {
            assert!(native_release(version, &"a".repeat(40)).is_err());
        }
        assert!(native_release("3.2.0", "main").is_err());
    }
    #[test]
    fn lifecycle_management_gate_only_blocks_the_owned_origin_during_transitions() {
        let setup = HostSetup::default();
        let record: Installation = serde_json::from_value(serde_json::json!({"schemaVersion":1,"manifestSha256":"a".repeat(64),"controllerSha256":"b".repeat(64)})).unwrap();
        // A lifecycle operation holds the owner for as long as the flag is its to keep.
        let _operation = setup.owner.try_lock().unwrap();
        setup.active.store(true, Ordering::Release);
        setup.set("starting", None, Some(record.clone()));
        assert!(setup
            .require_management_origin("https://127.0.0.1:9443")
            .is_err());
        assert!(setup
            .require_management_origin("https://nas.example")
            .is_ok());
        setup.set("provisioning", None, Some(record.clone()));
        assert!(setup
            .require_management_origin("https://127.0.0.1:9443")
            .is_err());
        setup.cancel();
        assert!(setup.cancel.load(Ordering::Acquire));
        setup.set("manager-ready", None, Some(record));
        assert!(setup
            .require_management_origin("https://127.0.0.1:9443")
            .is_ok());
        assert!(setup.snapshot().background_active);
    }
    #[tokio::test]
    async fn profile_setup_serializes_authorization_and_never_starts_a_manager() {
        let setup = Arc::new(HostSetup::default());
        let record: Installation = serde_json::from_value(serde_json::json!({"schemaVersion":1,"manifestSha256":"a".repeat(64),"controllerSha256":"b".repeat(64)})).unwrap();
        let inspect = setup.clone();
        let view = setup
            .provision_record(record.clone(), move |_| {
                assert!(inspect.background_active());
                assert_eq!(inspect.snapshot().state, "provisioning");
                assert!(inspect.owner.try_lock().is_err());
                assert!(inspect
                    .require_management_origin("https://127.0.0.1:9443")
                    .is_err());
                Ok(())
            })
            .await
            .unwrap();
        assert_eq!(view.state, "profile-ready");
        assert_eq!(view.installation, Some(record.clone()));
        assert!(!view.background_active);
        assert!(setup.owner.lock().await.is_none());
        let held = setup.owner.lock().await;
        assert_eq!(
            setup
                .provision_record(record.clone(), |_| panic!(
                    "busy setup must not request authorization"
                ))
                .await
                .err()
                .unwrap(),
            "native_host_busy"
        );
        drop(held);
        assert_eq!(
            setup
                .provision_record(record.clone(), |_| Err(
                    "host_profile_authorization_cancelled".into()
                ))
                .await
                .err()
                .unwrap(),
            "host_profile_authorization_cancelled"
        );
        let view = setup.snapshot();
        assert_eq!(view.state, "needs-attention");
        assert_eq!(view.installation, Some(record));
        assert!(!view.background_active);
        assert!(setup.owner.lock().await.is_none());
    }
    #[cfg(unix)]
    #[test]
    fn setup_never_adopts_a_shared_or_linked_profile_leaf() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("frameleaf-setup-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(require_leaf(&root).is_err());
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        require_leaf(&root).unwrap();
        let alias = root.with_extension("alias");
        symlink(&root, &alias).unwrap();
        assert!(require_leaf(&alias).is_err());
        std::fs::remove_file(alias).unwrap();
        std::fs::remove_dir(root).unwrap();
    }
    #[cfg(unix)]
    struct OwnedFixture(std::path::PathBuf);
    #[cfg(unix)]
    impl OwnedFixture {
        fn new() -> Self {
            let root = std::env::temp_dir()
                .canonicalize()
                .unwrap()
                .join(format!("frameleaf-host-setup-{}", uuid::Uuid::new_v4()));
            crate::runtime_store::private_directory(&root).unwrap();
            for leaf in ["state", "data"] {
                crate::runtime_store::private_directory(&root.join(leaf)).unwrap();
            }
            Self(root)
        }
        fn state(&self) -> std::path::PathBuf {
            self.0.join("state")
        }
        /// A setup that owns `program` as its Manager, as a completed start leaves it.
        fn own(&self, program: &str, arguments: &[&str]) -> HostSetup {
            let installation: Installation = serde_json::from_value(serde_json::json!({"schemaVersion":1,"manifestSha256":"a".repeat(64),"controllerSha256":"b".repeat(64)})).unwrap();
            let mut command = std::process::Command::new(program);
            command.args(arguments);
            self.own_command(command, installation)
        }
        fn own_command(
            &self,
            mut command: std::process::Command,
            installation: Installation,
        ) -> HostSetup {
            let setup = HostSetup::default();
            let running = Running {
                manager: NativeManager::test_child(&mut command),
                configuration: Configuration {
                    installation_id: "aaaaaaaaaaaa".into(),
                    name: "My Frameleaf library".into(),
                    release: "frameleaf-v1.2.3-native.aaaaaaaaaaaa-1".into(),
                    controller: "/bin/echo".into(),
                    state: self.state(),
                    data: self.0.join("data"),
                    origin: "https://127.0.0.1:9443".into(),
                    database_port: 54329,
                    api_port: 2283,
                },
                installation,
                features: Default::default(),
            };
            setup.adopt(&mut setup.owner.try_lock().unwrap(), running);
            setup.active.store(true, Ordering::Release);
            setup
        }
    }
    #[cfg(unix)]
    impl Drop for OwnedFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn background_activity_follows_the_owned_manager_and_ends_with_stop() {
        let fixture = OwnedFixture::new();
        let setup = fixture.own("/bin/sleep", &["30"]);
        assert!(setup.background_active());
        assert!(setup.lock_for_update().is_err());
        let view = setup.stop().await.unwrap();
        assert_eq!(view.state, "idle");
        assert!(!view.background_active);
        assert!(!setup.background_active());
        assert!(setup.owner.try_lock().unwrap().is_none());
        assert!(setup.lock_for_update().is_ok());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn exited_manager_never_keeps_the_app_unquittable_even_with_an_interrupted_journal() {
        let fixture = OwnedFixture::new();
        let setup = fixture.own("/bin/sleep", &["0.2"]);
        // The library's last controller died without a clean stop.
        let mut journal = crate::host_state::Owner::acquire(&fixture.state(), true).unwrap();
        journal
            .activate(
                "aaaaaaaaaaaa",
                &"a".repeat(64),
                crate::host_runtime::HostMode::Server,
            )
            .unwrap();
        drop(journal);
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while setup.background_active() {
            assert!(std::time::Instant::now() < deadline, "Manager did not exit");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            setup.status().await.unwrap().code.as_deref(),
            Some("native_manager_exited")
        );
        let view = setup.stop().await.unwrap();
        assert_eq!(view.state, "idle");
        assert!(!view.background_active);
        // Quitting is free again, but nothing proved the database stopped: no update yet.
        assert!(setup.owner.try_lock().unwrap().is_none());
        assert!(setup.lock_for_update().is_err());
        // The library is started again, recovers, and this time stops cleanly.
        let mut journal = crate::host_state::Owner::acquire(&fixture.state(), true).unwrap();
        journal
            .activate(
                "aaaaaaaaaaaa",
                &"a".repeat(64),
                crate::host_runtime::HostMode::Server,
            )
            .unwrap();
        journal.clean_stop().unwrap();
        drop(journal);
        assert!(setup.lock_for_update().is_ok());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stopping_an_exited_manager_keeps_updates_closed_while_its_controller_runs() {
        let fixture = OwnedFixture::new();
        let setup = fixture.own("/bin/sleep", &["0.2"]);
        // Manager exits while its controller still holds the journal and runs the database.
        let mut controller = crate::host_state::Owner::acquire(&fixture.state(), true).unwrap();
        controller
            .activate(
                "aaaaaaaaaaaa",
                &"a".repeat(64),
                crate::host_runtime::HostMode::Server,
            )
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while setup.background_active() {
            assert!(std::time::Instant::now() < deadline, "Manager did not exit");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // Stopping the dead Manager needs no proof and clears the owner...
        assert_eq!(setup.stop().await.unwrap().state, "idle");
        assert!(setup.owner.try_lock().unwrap().is_none());
        // ...but that must not open the update gate.
        assert!(setup.lock_for_update().is_err());
        controller.clean_stop().unwrap();
        // Stopped cleanly, yet the controller process has not released the journal.
        assert!(setup.lock_for_update().is_err());
        drop(controller);
        assert!(setup.lock_for_update().is_ok());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn quitting_stops_manager_while_the_photo_server_runs_but_stop_still_needs_idle_proof() {
        let fixture = OwnedFixture::new();
        let setup = fixture.own("/bin/sleep", &["30"]);
        // A live controller holds the journal lease for as long as the photo server runs.
        let controller = crate::host_state::Owner::acquire(&fixture.state(), true).unwrap();
        assert_eq!(
            setup.stop().await.err().unwrap(),
            "host_controller_already_owned"
        );
        assert!(setup.background_active());
        let view = setup.stop_for_exit().await.unwrap();
        assert_eq!(view.state, "idle");
        assert!(!view.background_active);
        assert!(!setup.background_active());
        // The controller was left to close the database itself; until it has, no update.
        assert!(setup.lock_for_update().is_err());
        drop(controller);
        assert!(setup.lock_for_update().is_ok());
    }

    /// The Windows exit stop, whose Manager job holds the database: the decision runs on every OS.
    #[tokio::test]
    async fn an_orderly_stop_asks_manager_only_for_a_running_controller_and_trusts_only_the_journal(
    ) {
        use std::cell::Cell;
        async fn never() -> Result<(), String> {
            panic!("Manager is not asked")
        }
        let no_wait = Duration::ZERO;
        // Already proven idle: Manager is not asked and the proof is handed on.
        assert_eq!(
            orderly_stop_proof(|| Ok("proof"), never(), no_wait).await,
            Ok("proof")
        );
        // A proof that failed for any reason other than a running controller is refused as it
        // is: unreadable, interrupted or changed evidence is never something to stop through.
        for unknown in [
            "host_recovery_requires_manager",
            "host_controller_state_invalid",
            "host_controller_binding_changed",
            "host_process_state_requires_review",
            "host_state_not_private",
            "host_profile_identity_changed",
        ] {
            assert_eq!(
                orderly_stop_proof(|| Err::<(), _>(unknown.to_string()), never(), no_wait).await,
                Err(unknown.to_string())
            );
        }
        for held in ["host_controller_already_owned", "host_already_owned"] {
            let asked = Cell::new(false);
            // What the journal says: a controller holds it until Manager has stopped it.
            let journal = || {
                if asked.get() {
                    Ok("proof")
                } else {
                    Err(held.to_string())
                }
            };
            // Manager could not stop it: nothing is proven, so nothing may be ended.
            assert_eq!(
                orderly_stop_proof(
                    journal,
                    async { Err("native_shutdown_unconfirmed".to_string()) },
                    no_wait
                )
                .await,
                Err("native_shutdown_unconfirmed".to_string())
            );
            // Manager stopped it and the journal now proves it.
            assert_eq!(
                orderly_stop_proof(
                    journal,
                    async {
                        asked.set(true);
                        Ok(())
                    },
                    no_wait
                )
                .await,
                Ok("proof")
            );
            // Manager says stopped but the controller still holds the journal: Manager's word
            // is not the proof.
            assert_eq!(
                orderly_stop_proof(|| Err::<(), _>(held.to_string()), async { Ok(()) }, no_wait)
                    .await,
                Err(held.to_string())
            );
        }
        // The controller lets go a moment after Manager answers: the proof is read again.
        let reads = Cell::new(0);
        assert_eq!(
            orderly_stop_proof(
                || {
                    reads.set(reads.get() + 1);
                    if reads.get() < 4 {
                        Err("host_controller_already_owned".to_string())
                    } else {
                        Ok("proof")
                    }
                },
                async { Ok(()) },
                Duration::from_secs(30)
            )
            .await,
            Ok("proof")
        );
        // After Manager's stop the journal turns out interrupted: refused, never retried into.
        let reads = Cell::new(0);
        assert_eq!(
            orderly_stop_proof(
                || {
                    reads.set(reads.get() + 1);
                    Err::<(), _>(
                        if reads.get() == 1 {
                            "host_controller_already_owned"
                        } else {
                            "host_recovery_requires_manager"
                        }
                        .to_string(),
                    )
                },
                async { Ok(()) },
                Duration::from_secs(30)
            )
            .await,
            Err("host_recovery_requires_manager".to_string())
        );
        assert_eq!(reads.get(), 2);
    }

    #[tokio::test]
    async fn a_manager_stop_is_done_only_when_manager_reports_it_complete() {
        use crate::manager::{Action, Command};
        use serde_json::json;
        use std::cell::RefCell;
        let id = uuid::Uuid::new_v4();
        // Manager's answers to the stop request and then to each look at its operation.
        let run = |accepted: Result<serde_json::Value, String>,
                   states: Vec<serde_json::Value>,
                   timeout: Duration| async move {
            let states = RefCell::new(states.into_iter());
            let accepted = RefCell::new(Some(accepted));
            manager_stop(
                |command| {
                    let reply = match command {
                        Command::Control {
                            action: Action::Stop,
                            key,
                        } if !key.is_nil() => accepted.borrow_mut().take().expect("asked once"),
                        Command::Operation { id: asked } if asked == id => Ok(states
                            .borrow_mut()
                            .next()
                            .expect("not asked again after an answer that ends it")),
                        _ => panic!("only a stop and its own operation are sent"),
                    };
                    async move { reply }
                },
                timeout,
            )
            .await
        };
        let accepted = || Ok(json!({ "id": id.to_string() }));
        let long = Duration::from_secs(60);
        assert_eq!(
            run(
                accepted(),
                vec![
                    json!({"state":"running"}),
                    json!({"state":"running"}),
                    json!({"state":"complete"})
                ],
                long
            )
            .await,
            Ok(())
        );
        for (answer, code) in [
            (
                json!({"state":"failed","error":"native_shutdown_unconfirmed"}),
                "native_shutdown_unconfirmed",
            ),
            (
                json!({"state":"interrupted","error":null}),
                "manager_operation_failed",
            ),
            (json!({"state":"stopped"}), "manager_response_invalid"),
            (json!({}), "manager_response_invalid"),
        ] {
            assert_eq!(
                run(accepted(), vec![answer], long).await,
                Err(code.to_string())
            );
        }
        // Still running when time is up is not a stop.
        assert_eq!(
            run(accepted(), vec![json!({"state":"running"})], Duration::ZERO).await,
            Err("native_manager_shutdown_unconfirmed".to_string())
        );
        // A refused request, or an acceptance naming no operation, asks nothing further.
        assert_eq!(
            run(Err("manager_scope_denied".into()), vec![], long).await,
            Err("manager_scope_denied".to_string())
        );
        assert_eq!(
            run(Ok(json!({"id":"not-an-operation"})), vec![], long).await,
            Err("manager_response_invalid".to_string())
        );
    }

    #[test]
    fn a_library_whose_last_package_was_built_for_another_version_is_named_as_that() {
        // Not "this companion does not match": the selected package is the right one.
        assert_eq!(
            previous_package_refusal("host_manifest_incompatible".into()),
            "host_upgrade_previous_package_incompatible"
        );
        assert_ne!(
            Compatibility::from_check(Err(previous_package_refusal(
                "host_manifest_incompatible".into()
            ))),
            Compatibility::Outdated
        );
        // Every other refusal of the previous package keeps its own meaning.
        for code in [
            "host_signature_invalid",
            "host_manifest_invalid",
            "host_install_runtime_changed",
            "runtime_artifact_changed",
        ] {
            assert_eq!(previous_package_refusal(code.into()), code);
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_running_managers_certificate_expiry_is_reported_only_when_near_and_only_while_it_runs(
    ) {
        const DAY: i64 = 24 * 60 * 60;
        let fixture = OwnedFixture::new();
        let setup = fixture.own("/bin/sleep", &["30"]);
        cleanly_stopped(&fixture.state());
        let now = i64::try_from(crate::manager::clock().unwrap() / 1000).unwrap();
        // The stand-in was given no identity.
        assert_eq!(setup.snapshot().certificate_expires_in_days, None);
        for (expires, days) in [
            (now + 200 * DAY, None),
            (now + 10 * DAY - 60, Some(10)),
            (now - DAY, None),
        ] {
            setup
                .certificate_expires_at
                .store(expires, Ordering::Release);
            assert_eq!(setup.snapshot().certificate_expires_in_days, days);
        }
        setup
            .certificate_expires_at
            .store(now + 10 * DAY - 60, Ordering::Release);
        setup.stop().await.unwrap();
        assert_eq!(setup.snapshot().certificate_expires_in_days, None);
    }

    /// The Windows quit path on a stand-in Manager: with a controller holding the journal and no
    /// way to ask Manager to stop it, Manager is left running and the app stays protected.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_orderly_stop_that_cannot_ask_manager_ends_nothing() {
        let fixture = OwnedFixture::new();
        let setup = fixture.own("/bin/sleep", &["30"]);
        let controller = crate::host_state::Owner::acquire(&fixture.state(), true).unwrap();
        // The stand-in never became a verified Manager, so there is nothing to ask.
        assert_eq!(
            setup.stop_proven(true).await.err().unwrap(),
            "native_manager_not_ready"
        );
        assert!(setup.background_active());
        assert!(live(&mut setup.owner.try_lock().unwrap()));
        // Once the journal proves a clean stop, the same path stops Manager without asking.
        drop(controller);
        cleanly_stopped(&fixture.state());
        let view = setup.stop_proven(true).await.unwrap();
        assert_eq!(view.state, "idle");
        assert!(!setup.background_active());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_new_run_keeps_updates_closed_until_the_hosted_library_is_proven_idle() {
        use crate::host_runtime::HostMode;
        let fixture = OwnedFixture::new();
        let state = fixture.state();
        let data = fixture.0.join("data");
        let hosted = on_disk(&state, &data, &|| Evidence::Clear);
        // An account that never hosted a library has nothing to wait for, whatever answers
        // on the port.
        let never = fixture.0.join("never-hosted");
        assert!(HostSetup::default()
            .lock_for_update_at(Some(on_disk(&never, &never, &|| Evidence::Running)))
            .is_ok());
        let setup = fixture.own("/bin/sleep", &["30"]);
        let mut controller = crate::host_state::Owner::acquire(&state, true).unwrap();
        controller
            .activate("aaaaaaaaaaaa", &"a".repeat(64), HostMode::Server)
            .unwrap();
        // Stop and quit: Manager is gone, its controller is still closing the database.
        setup.stop_for_exit().await.unwrap();
        drop(setup);
        // The next run of the app remembers no Manager and no library.
        let restarted = HostSetup::default();
        assert!(restarted.owner.try_lock().unwrap().is_none());
        assert_eq!(
            restarted.lock_for_update_at(Some(hosted)).err().unwrap(),
            "update_library_not_idle"
        );
        controller.clean_stop().unwrap();
        assert!(
            restarted.lock_for_update_at(Some(hosted)).is_err(),
            "the controller still holds the journal"
        );
        drop(controller);
        assert!(restarted.lock_for_update_at(Some(hosted)).is_ok());
        // A controller that died without a clean stop keeps a later run closed too.
        let mut controller = crate::host_state::Owner::acquire(&state, true).unwrap();
        controller
            .activate("aaaaaaaaaaaa", &"a".repeat(64), HostMode::Server)
            .unwrap();
        drop(controller);
        assert_eq!(
            HostSetup::default()
                .lock_for_update_at(Some(hosted))
                .err()
                .unwrap(),
            "update_library_not_idle"
        );
    }

    /// The gate's view of a library on disk, with real process lookups.
    #[cfg(unix)]
    fn on_disk<'a>(
        state: &'a std::path::Path,
        data: &'a std::path::Path,
        listener: &'a dyn Fn() -> Evidence,
    ) -> Hosted<'a> {
        Hosted {
            state,
            data,
            listener,
            process: &crate::process_tree::ProcessIdentity::lookup,
        }
    }
    /// A library whose journal records a clean stop and is held by nobody.
    #[cfg(unix)]
    fn cleanly_stopped(state: &std::path::Path) {
        let mut journal = crate::host_state::Owner::acquire(state, true).unwrap();
        journal
            .activate(
                "aaaaaaaaaaaa",
                &"a".repeat(64),
                crate::host_runtime::HostMode::Server,
            )
            .unwrap();
        journal.clean_stop().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_new_run_keeps_updates_closed_for_a_launch_that_left_no_process_and_no_listener() {
        let fixture = OwnedFixture::new();
        let (state, data) = (fixture.state(), fixture.0.join("data"));
        cleanly_stopped(&state);
        let hosted = on_disk(&state, &data, &|| Evidence::Clear);
        let restarted = HostSetup::default();
        assert!(restarted.lock_for_update_at(Some(hosted)).is_ok());
        // This app crashed after starting a Manager launch: the Manager was spawned but has
        // not bound its port, and no process was recorded for it.
        crate::manager_host::record_launch_intent(&data).unwrap();
        assert_eq!(
            restarted.lock_for_update_at(Some(hosted)).err().unwrap(),
            "update_library_not_idle"
        );
        // Only a record completed with a process that is seen to be gone opens it again.
        let mut manager = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        crate::manager_host::record_owned_process(&data, manager.id()).unwrap();
        assert!(restarted.lock_for_update_at(Some(hosted)).is_err());
        manager.kill().unwrap();
        manager.wait().unwrap();
        assert!(restarted.lock_for_update_at(Some(hosted)).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn evidence_that_cannot_be_read_never_opens_the_update_gate() {
        use crate::process_tree::Presence;
        let fixture = OwnedFixture::new();
        let (state, data) = (fixture.state(), fixture.0.join("data"));
        cleanly_stopped(&state);
        let restarted = HostSetup::default();
        let mut manager = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        crate::manager_host::record_owned_process(&data, manager.id()).unwrap();
        manager.kill().unwrap();
        manager.wait().unwrap();
        // The recorded Manager has exited, and a readable lookup says so.
        assert!(restarted
            .lock_for_update_at(Some(on_disk(&state, &data, &|| Evidence::Clear)))
            .is_ok());
        // A lookup of the recorded process that fails is not an exit.
        let unreadable = Hosted {
            process: &|_| Presence::Unknown,
            ..on_disk(&state, &data, &|| Evidence::Clear)
        };
        assert_eq!(
            restarted
                .lock_for_update_at(Some(unreadable))
                .err()
                .unwrap(),
            "update_library_not_idle"
        );
        // A port probe that times out is not a refusal.
        let timed_out =
            || crate::manager_host::listener_evidence(Err(std::io::ErrorKind::TimedOut.into()));
        assert_eq!(timed_out(), Evidence::Unknown);
        assert_eq!(
            restarted
                .lock_for_update_at(Some(on_disk(&state, &data, &timed_out)))
                .err()
                .unwrap(),
            "update_library_not_idle"
        );
        for kind in [
            std::io::ErrorKind::PermissionDenied,
            std::io::ErrorKind::ConnectionReset,
            std::io::ErrorKind::Other,
        ] {
            assert_eq!(
                crate::manager_host::listener_evidence(Err(kind.into())),
                Evidence::Unknown
            );
        }
        assert_eq!(
            crate::manager_host::listener_evidence(Err(
                std::io::ErrorKind::ConnectionRefused.into()
            )),
            Evidence::Clear
        );
        // A state directory that cannot be examined is not "never hosted".
        let blocked = state.join("controller-state.json").join("below-a-file");
        assert!(restarted
            .lock_for_update_at(Some(on_disk(&blocked, &data, &|| Evidence::Clear)))
            .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_new_run_keeps_updates_closed_while_a_manager_left_running_is_alive() {
        use std::os::unix::fs::OpenOptionsExt;
        let fixture = OwnedFixture::new();
        let (state, data) = (fixture.state(), fixture.0.join("data"));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let probe = move || crate::manager_host::listener(port);
        let hosted = on_disk(&state, &data, &probe);
        // The library stopped cleanly: its journal alone would allow an update.
        cleanly_stopped(&state);
        assert!(HostSetup::default()
            .lock_for_update_at(Some(hosted))
            .is_ok());

        // Quit anyway, or a crash, left the recorded Manager running; it could start the
        // controller while an update installs.
        let mut manager = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        crate::manager_host::record_owned_process(&data, manager.id()).unwrap();
        let restarted = HostSetup::default();
        assert!(restarted.owner.try_lock().unwrap().is_none());
        assert_eq!(
            restarted.lock_for_update_at(Some(hosted)).err().unwrap(),
            "update_library_not_idle"
        );
        manager.kill().unwrap();
        manager.wait().unwrap();
        assert!(restarted.lock_for_update_at(Some(hosted)).is_ok());

        // A record that cannot be read proves nothing.
        let record = data.join("desktop-manager-process.json");
        std::fs::remove_file(&record).unwrap();
        std::io::Write::write_all(
            &mut std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&record)
                .unwrap(),
            b"not a record",
        )
        .unwrap();
        assert!(restarted.lock_for_update_at(Some(hosted)).is_err());
        std::fs::remove_file(&record).unwrap();
        assert!(restarted.lock_for_update_at(Some(hosted)).is_ok());

        // A Manager that was never recorded still answers on its port.
        let unrecorded = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
        assert!(restarted.lock_for_update_at(Some(hosted)).is_err());
        drop(unrecorded);
        assert!(restarted.lock_for_update_at(Some(hosted)).is_ok());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stop_and_quit_stops_nothing_when_the_exit_would_be_refused() {
        let fixture = OwnedFixture::new();
        let setup = fixture.own("/bin/sleep", &["30"]);
        setup.set("manager-ready", None, setup.snapshot().installation);
        assert!(!setup.snapshot().leave_available);
        // A media copy is running: the exit that follows would be refused.
        assert_eq!(
            setup
                .quit(Some("media_copy_exit_blocked"), false)
                .await
                .unwrap_err(),
            "media_copy_exit_blocked"
        );
        let view = setup.snapshot();
        assert_eq!(view.state, "manager-ready", "Manager was not asked to stop");
        assert!(view.background_active);
        assert!(setup.owner.try_lock().unwrap().is_some());
        // With nothing refusing the exit, the same request stops it.
        setup.quit(None, false).await.unwrap();
        let view = setup.snapshot();
        assert_eq!(view.state, "idle");
        assert!(!view.background_active && !view.leave_available);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn leaving_is_offered_only_for_the_manager_whose_stop_failed() {
        let fixture = OwnedFixture::new();
        let mut command = std::process::Command::new("/bin/sleep");
        command.arg("30");
        unsafe {
            use std::os::unix::process::CommandExt;
            command.pre_exec(|| {
                libc::signal(libc::SIGTERM, libc::SIG_IGN);
                Ok(())
            });
        }
        let installation: Installation = serde_json::from_value(serde_json::json!({"schemaVersion":1,"manifestSha256":"a".repeat(64),"controllerSha256":"b".repeat(64)})).unwrap();
        let setup = fixture.own_command(command, installation.clone());
        assert!(setup
            .stop_for_exit_within(Duration::from_millis(300))
            .await
            .is_err());
        assert!(setup.snapshot().leave_available);
        // A later Manager in the same run starts with no such offer.
        let mut next = std::process::Command::new("/bin/sleep");
        next.arg("30");
        let running = Running {
            manager: NativeManager::test_child(&mut next),
            configuration: setup
                .owner
                .try_lock()
                .unwrap()
                .take()
                .map(|running| running.configuration)
                .unwrap(),
            installation,
            features: Default::default(),
        };
        setup.adopt(&mut setup.owner.try_lock().unwrap(), running);
        assert!(setup.background_active());
        assert!(!setup.snapshot().leave_available);
        assert_eq!(
            setup.leave_for_exit(true).unwrap_err(),
            "native_manager_shutdown_unconfirmed"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn quitting_without_stopping_is_refused_when_manager_cannot_be_recorded() {
        let fixture = OwnedFixture::new();
        let mut command = std::process::Command::new("/bin/sleep");
        command.arg("30");
        unsafe {
            use std::os::unix::process::CommandExt;
            command.pre_exec(|| {
                libc::signal(libc::SIGTERM, libc::SIG_IGN);
                Ok(())
            });
        }
        let installation: Installation = serde_json::from_value(serde_json::json!({"schemaVersion":1,"manifestSha256":"a".repeat(64),"controllerSha256":"b".repeat(64)})).unwrap();
        let setup = fixture.own_command(command, installation);
        // The record was never written and cannot be: its directory is gone.
        let data = fixture.0.join("data");
        std::fs::remove_dir(&data).unwrap();
        assert_eq!(
            setup
                .stop_for_exit_within(Duration::from_millis(300))
                .await
                .err()
                .unwrap(),
            "native_manager_record_unavailable"
        );
        assert_eq!(
            setup.leave_for_exit(true).unwrap_err(),
            "native_manager_shutdown_unconfirmed",
            "leaving was never offered"
        );
        assert!(setup.background_active());
        // Once the record can be written, the failed stop offers leaving and the record is there.
        crate::runtime_store::private_directory(&data).unwrap();
        assert_eq!(
            setup
                .stop_for_exit_within(Duration::from_millis(300))
                .await
                .err()
                .unwrap(),
            "native_manager_shutdown_unconfirmed"
        );
        assert!(data.join("desktop-manager-process.json").exists());
        // Losing the record again after the offer still refuses the quit.
        std::fs::remove_dir_all(&data).unwrap();
        assert_eq!(
            setup.leave_for_exit(true).unwrap_err(),
            "native_manager_record_unavailable"
        );
        assert!(setup.background_active(), "the app stays open");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_manager_that_ignores_the_stop_can_still_be_left_running_to_quit() {
        let fixture = OwnedFixture::new();
        // An ignored signal stays ignored across exec: this Manager never honours the request.
        let mut command = std::process::Command::new("/bin/sleep");
        command.arg("30");
        unsafe {
            use std::os::unix::process::CommandExt;
            command.pre_exec(|| {
                libc::signal(libc::SIGTERM, libc::SIG_IGN);
                Ok(())
            });
        }
        let installation: Installation = serde_json::from_value(serde_json::json!({"schemaVersion":1,"manifestSha256":"a".repeat(64),"controllerSha256":"b".repeat(64)})).unwrap();
        let setup = fixture.own_command(command, installation);
        let data = fixture.0.join("data");
        let pid = setup
            .owner
            .try_lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .manager
            .process_id();
        crate::manager_host::record_owned_process(&data, pid).unwrap();
        // Leaving is not offered before a stop has been tried and has failed.
        assert_eq!(
            setup.leave_for_exit(true).unwrap_err(),
            "native_manager_shutdown_unconfirmed"
        );
        assert_eq!(
            setup
                .stop_for_exit_within(Duration::from_millis(300))
                .await
                .err()
                .unwrap(),
            "native_manager_shutdown_unconfirmed"
        );
        assert_eq!(setup.snapshot().state, "needs-attention");
        assert!(setup.background_active(), "exit stays protected by default");
        // The interface offers leaving exactly while the backend allows it.
        assert!(setup.snapshot().leave_available);
        // Something else would refuse the exit: Manager is neither left nor stopped.
        assert_eq!(
            setup
                .quit(Some("media_copy_exit_blocked"), true)
                .await
                .unwrap_err(),
            "media_copy_exit_blocked"
        );
        assert!(setup.background_active());
        setup.leave_for_exit(true).unwrap();
        assert!(!setup.background_active(), "the chosen quit is not blocked");
        assert!(
            data.join("desktop-manager-process.json").exists(),
            "the next launch must still be able to find this Manager"
        );
        assert!(
            setup.lock_for_update().is_err(),
            "leaving never unlocks updates"
        );
        // An exit that something else prevented restores the protection.
        setup.leave_for_exit(false).unwrap();
        assert!(setup.background_active());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn update_waits_for_proof_that_an_exited_managers_controller_and_database_stopped() {
        let fixture = OwnedFixture::new();
        let setup = fixture.own("/bin/sleep", &["0.2"]);
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while setup.background_active() {
            assert!(std::time::Instant::now() < deadline, "Manager did not exit");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // No journal yet: nothing proves the library idle.
        assert!(setup.lock_for_update().is_err());
        // Manager is gone but its controller still runs the photo server.
        let mut controller = crate::host_state::Owner::acquire(&fixture.state(), true).unwrap();
        controller
            .activate(
                "aaaaaaaaaaaa",
                &"a".repeat(64),
                crate::host_runtime::HostMode::Server,
            )
            .unwrap();
        assert!(setup.lock_for_update().is_err());
        // The controller died without a clean stop: still no proof.
        drop(controller);
        assert!(setup.lock_for_update().is_err());
        // A clean stop that left a database process file is not proof either.
        let mut controller = crate::host_state::Owner::acquire(&fixture.state(), true).unwrap();
        controller
            .activate(
                "aaaaaaaaaaaa",
                &"a".repeat(64),
                crate::host_runtime::HostMode::Server,
            )
            .unwrap();
        controller.clean_stop().unwrap();
        drop(controller);
        let database = fixture.state().join("database");
        crate::runtime_store::private_directory(&database).unwrap();
        std::fs::write(database.join("postmaster.pid"), b"synthetic").unwrap();
        assert!(setup.lock_for_update().is_err());
        std::fs::remove_file(database.join("postmaster.pid")).unwrap();
        assert!(setup.lock_for_update().is_ok());
    }

    #[test]
    fn photos_open_only_on_this_librarys_own_listener() {
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("frameleaf-photo-listener-{}", uuid::Uuid::new_v4()));
        crate::runtime_store::private_directory(&root).unwrap();
        // The port stays bound for the whole test, so no other test can be given it and every
        // probe of it has one answer.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let in_use = format!("local_port_in_use_{port}");
        // No controller of this library runs, so the program on its port is someone else's.
        assert_eq!(owned_photo_listener(&root, port).unwrap_err(), in_use);
        assert_eq!(
            crate::manager_host::foreign_listener(&[port]).unwrap_err(),
            in_use
        );
        let controller = crate::host_state::Owner::acquire(&root, true).unwrap();
        owned_photo_listener(&root, port).unwrap();
        drop(controller);
        // The controller is gone and the port still answers: someone else's again.
        assert_eq!(owned_photo_listener(&root, port).unwrap_err(), in_use);
        // Nothing listening, or a probe with no answer: the photo server is not running. The
        // probe is supplied here because a port this test released could be bound by another.
        for silent in [Evidence::Clear, Evidence::Unknown] {
            assert_eq!(
                photo_listener(
                    crate::host_state::Owner::controller_running(&root),
                    port,
                    &|| silent
                )
                .unwrap_err(),
                "local_photos_not_running"
            );
        }
        // A lease that cannot be read never opens the address, whatever answers on the port.
        for answer in [Evidence::Clear, Evidence::Running, Evidence::Unknown] {
            assert_eq!(
                photo_listener(Err("host_state_not_private".into()), port, &|| answer).unwrap_err(),
                "host_state_not_private"
            );
        }
        // A held lease opens it without asking the port.
        photo_listener(Ok(true), port, &|| panic!("the port is not asked")).unwrap();
        drop(listener);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn failed_or_cancelled_restart_keeps_the_previous_installation_without_a_live_manager() {
        let setup = HostSetup::default();
        let previous: Installation=serde_json::from_value(serde_json::json!({"schemaVersion":1,"manifestSha256":"a".repeat(64),"controllerSha256":"b".repeat(64)})).unwrap();
        let attempted: Installation=serde_json::from_value(serde_json::json!({"schemaVersion":1,"manifestSha256":"c".repeat(64),"controllerSha256":"d".repeat(64)})).unwrap();
        setup.startup_failed(
            Some(previous.clone()),
            attempted.clone(),
            "native_manager_start_cancelled".into(),
        );
        // Exit protection now follows the owned process: with none alive there is none to keep.
        assert!(!setup.background_active());
        assert_eq!(setup.snapshot().installation, Some(previous));
        setup.startup_failed(None, attempted.clone(), "native_host_setup_failed".into());
        assert!(!setup.background_active());
        assert_eq!(setup.snapshot().installation, Some(attempted));
    }
    #[test]
    fn local_authorization_password_is_bounded_before_credentials_or_network() {
        for password in [
            "",
            "short",
            "1234567890123",
            &"x".repeat(257),
            "long-password\ncontrol",
        ] {
            assert!(require_password(password).is_err());
        }
        require_password("12345678901234").unwrap();
    }
    #[test]
    fn local_claim_proof_is_private_bounded_and_never_follows_links() {
        use std::io::Write;
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("frameleaf-claim-proof-{}", uuid::Uuid::new_v4()));
        crate::runtime_store::private_directory(&root).unwrap();
        let dir = cap_std::fs::Dir::from_std_file(crate::host_storage::directory(&root).unwrap());
        for value in [
            "a".repeat(64),
            "a".repeat(65),
            "A".repeat(64),
            "short".into(),
        ] {
            let mut file = dir
                .open_with("claim-key", &crate::host_state::options(true))
                .unwrap();
            file.write_all(value.as_bytes()).unwrap();
            drop(file);
            assert_eq!(claim_proof(&root).is_ok(), value == "a".repeat(64));
            dir.remove_file("claim-key").unwrap();
        }
        let mut file = dir
            .open_with("original", &crate::host_state::options(true))
            .unwrap();
        file.write_all("a".repeat(64).as_bytes()).unwrap();
        drop(file);
        std::fs::hard_link(root.join("original"), root.join("claim-key")).unwrap();
        assert!(claim_proof(&root).is_err());
        std::fs::remove_file(root.join("claim-key")).unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(root.join("original"), root.join("claim-key")).unwrap();
            assert!(claim_proof(&root).is_err());
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}

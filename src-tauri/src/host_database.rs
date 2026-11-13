//! Physical database references retain prepared and original folders in place.

use cap_std::fs::Dir;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Component, Path, PathBuf};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Reference {
    operation_id: String,
    attempt_id: String,
    identities: [String; 5],
}
impl Reference {
    fn paths(profile: &Path, operation: &str, attempt: &str) -> Result<[PathBuf; 5], String> {
        if !profile.is_absolute()
            || profile
                .components()
                .any(|part| matches!(part, Component::ParentDir))
            || !crate::host_runtime::checkpoint_operation_id(operation)
            || !crate::host_runtime::checkpoint_operation_id(attempt)
        {
            return Err("host_database_reference_invalid".into());
        }
        let root = profile.join("restore-targets");
        let operation_root = root.join(operation);
        let target = operation_root.join(attempt);
        Ok([
            profile.into(),
            root,
            operation_root,
            target.clone(),
            target.join("database"),
        ])
    }
    fn identities(paths: &[PathBuf; 5]) -> Result<[String; 5], String> {
        let mut result = Vec::new();
        for path in paths {
            crate::native_runtime::absolute_directory(path)?;
            let directory = Dir::from_std_file(crate::host_storage::directory(path)?);
            #[cfg(unix)]
            {
                use cap_std::fs::MetadataExt;
                if directory
                    .dir_metadata()
                    .map_err(|_| "host_database_reference_invalid")?
                    .mode()
                    & 0o077
                    != 0
                {
                    return Err("host_database_reference_invalid".into());
                }
            }
            let identity = crate::copy_source::root_identity(&directory)?;
            result.push(format!("{:x}", Sha256::digest(identity.as_bytes())));
        }
        result
            .try_into()
            .map_err(|_| "host_database_reference_invalid".into())
    }
    /// A locator only: checksum/canonical validation and the controller lease still gate activation.
    pub(crate) fn capture(profile: &Path, operation: &str, attempt: &str) -> Result<Self, String> {
        let paths = Self::paths(profile, operation, attempt)?;
        let reference = Self {
            operation_id: operation.into(),
            attempt_id: attempt.into(),
            identities: Self::identities(&paths).map_err(|_| "host_database_reference_invalid")?,
        };
        // Never adopt a PID or infer that a database with an existing marker is stopped.
        match std::fs::symlink_metadata(paths[4].join("postmaster.pid")) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err("host_database_reference_invalid".into()),
        }
        reference.resolve(profile)?;
        Ok(reference)
    }
    /// The operation whose restore target this names.
    #[cfg(unix)]
    pub(crate) fn operation_id(&self) -> &str {
        &self.operation_id
    }
    pub(crate) fn binds_restore(
        &self,
        operation: &str,
        attempt: &str,
        identities: [&str; 3],
    ) -> bool {
        self.operation_id == operation
            && self.attempt_id == attempt
            && self.matches_node_identities(identities)
    }
    pub(crate) fn matches_node_identities(&self, values: [&str; 3]) -> bool {
        values.into_iter().zip([0, 3, 4]).all(|(value, index)| {
            #[cfg(windows)]
            let value = {
                let Some((volume, inode)) = value.split_once(':') else {
                    return false;
                };
                let Ok(inode) = inode.parse::<u64>() else {
                    return false;
                };
                format!("{volume}:{}:{}", inode >> 32, inode & 0xffff_ffff)
            };
            format!("{:x}", Sha256::digest(value.as_bytes())) == self.identities[index]
        })
    }
    pub(crate) fn target_directory(&self, profile: &Path) -> Result<Dir, String> {
        let database = self.resolve(profile)?;
        let root = Dir::from_std_file(crate::host_storage::directory(
            database.parent().ok_or("host_database_reference_invalid")?,
        )?);
        let id = crate::copy_source::root_identity(&root)?;
        if format!("{:x}", Sha256::digest(id.as_bytes())) != self.identities[3] {
            return Err("host_database_reference_invalid".into());
        }
        Ok(root)
    }
    pub(crate) fn resolve(&self, profile: &Path) -> Result<PathBuf, String> {
        let paths = Self::paths(profile, &self.operation_id, &self.attempt_id)?;
        if self
            .identities
            .iter()
            .any(|value| !crate::native_runtime::digest_valid(value, 64))
            || Self::identities(&paths).map_err(|_| "host_database_reference_invalid")?
                != self.identities
        {
            return Err("host_database_reference_invalid".into());
        }
        Ok(paths[4].clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::PathBuf};
    const OP: &str = "11111111-1111-4111-8111-111111111111";
    const ATTEMPT: &str = "22222222-2222-4222-8222-222222222222";
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir()
                .canonicalize()
                .unwrap()
                .join(format!("frameleaf-db-reference-{}", uuid::Uuid::new_v4()));
            for path in [
                root.clone(),
                root.join("database"),
                root.join("restore-targets"),
                root.join("restore-targets").join(OP),
                root.join("restore-targets").join(OP).join(ATTEMPT),
                root.join("restore-targets")
                    .join(OP)
                    .join(ATTEMPT)
                    .join("database"),
            ] {
                crate::runtime_store::private_directory(&path).unwrap();
            }
            fs::write(root.join("database/sentinel"), b"original").unwrap();
            let fixture = Self(root);
            fs::write(fixture.database().join("sentinel"), b"prepared").unwrap();
            fixture
        }
        fn database(&self) -> PathBuf {
            self.0
                .join("restore-targets")
                .join(OP)
                .join(ATTEMPT)
                .join("database")
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn reference_roundtrip_resolves_fixed_target_and_never_moves_either_database() {
        let f = Fixture::new();
        let reference = Reference::capture(&f.0, OP, ATTEMPT).unwrap();
        let raw = serde_json::to_vec(&reference).unwrap();
        let decoded: Reference = serde_json::from_slice(&raw).unwrap();
        assert_eq!(decoded, reference);
        assert_eq!(decoded.resolve(&f.0).unwrap(), f.database());
        assert_eq!(
            fs::read(f.0.join("database/sentinel")).unwrap(),
            b"original"
        );
        assert_eq!(
            fs::read(f.database().join("sentinel")).unwrap(),
            b"prepared"
        );
        assert!(!String::from_utf8(raw)
            .unwrap()
            .contains(f.0.to_str().unwrap()));
    }
    #[test]
    fn node_owner_resolves_the_same_reference_in_the_native_identity_namespace() {
        use std::io::Write;
        use std::process::{Command, Stdio};
        let f = Fixture::new();
        let reference = Reference::capture(&f.0, OP, ATTEMPT).unwrap();
        let module = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../runtime/host-agent.mjs")
            .canonicalize()
            .unwrap();
        let module = url::Url::from_file_path(module).unwrap();
        let script = format!("import fs from 'node:fs'; import {{readHostDatabase}} from '{}'; const c=JSON.parse(fs.readFileSync(0,'utf8')); console.log(JSON.stringify(await readHostDatabase(c.profile,c.reference)));", module);
        let mut child = Command::new("node")
            .args(["--input-type=module", "--eval", &script])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(
                &serde_json::to_vec(&serde_json::json!({"profile":f.0,"reference":reference}))
                    .unwrap(),
            )
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let selected: PathBuf = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(selected, f.database());
    }

    #[test]
    fn references_refuse_path_authority_live_capture_and_changed_directory_identities() {
        for value in [
            "../outside",
            "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA",
            "00000000-0000-0000-0000-000000000000",
        ] {
            let f = Fixture::new();
            assert!(Reference::capture(&f.0, value, ATTEMPT).is_err());
            assert!(Reference::capture(&f.0, OP, value).is_err());
        }
        let f = Fixture::new();
        fs::write(f.database().join("postmaster.pid"), b"not adopted").unwrap();
        assert!(Reference::capture(&f.0, OP, ATTEMPT).is_err());
        fs::remove_file(f.database().join("postmaster.pid")).unwrap();
        let reference = Reference::capture(&f.0, OP, ATTEMPT).unwrap();
        let previous = f.database().with_file_name("retained");
        fs::rename(f.database(), &previous).unwrap();
        crate::runtime_store::private_directory(&f.database()).unwrap();
        assert!(reference.resolve(&f.0).is_err());
        assert_eq!(fs::read(previous.join("sentinel")).unwrap(), b"prepared");
        let mut unknown = serde_json::to_value(reference).unwrap();
        unknown["path"] = serde_json::json!("/outside");
        assert!(serde_json::from_value::<Reference>(unknown).is_err());
    }
    #[test]
    fn reparenting_the_same_database_does_not_preserve_reference_authority() {
        let f = Fixture::new();
        let reference = Reference::capture(&f.0, OP, ATTEMPT).unwrap();
        let target = f.database().parent().unwrap().to_owned();
        let previous = target.with_file_name("retained-attempt");
        fs::rename(&target, &previous).unwrap();
        crate::runtime_store::private_directory(&target).unwrap();
        fs::rename(previous.join("database"), f.database()).unwrap();
        assert!(reference.resolve(&f.0).is_err());
        assert_eq!(
            fs::read(f.database().join("sentinel")).unwrap(),
            b"prepared"
        );
    }
    #[cfg(unix)]
    #[test]
    fn reference_refuses_links_and_nonprivate_directories() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let f = Fixture::new();
        let reference = Reference::capture(&f.0, OP, ATTEMPT).unwrap();
        fs::set_permissions(f.database(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(reference.resolve(&f.0).is_err());
        fs::set_permissions(f.database(), fs::Permissions::from_mode(0o700)).unwrap();
        let previous = f.database().with_file_name("retained");
        fs::rename(f.database(), &previous).unwrap();
        symlink(previous, f.database()).unwrap();
        assert!(reference.resolve(&f.0).is_err());
    }
}

use super::{digest_valid, HostManifest, VerifyingKey};
use serde::Serialize;
use sha2::{Digest, Sha256};

// Display data only: this type cannot start a process or admit a host epoch.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PackageMetadata {
    version: String,
    epoch: u64,
    source_revision: String,
}
pub(crate) fn package_metadata(
    raw: &[u8],
    signature: &[u8; 64],
    trusted: &[VerifyingKey],
    minimum_epoch: u64,
    expected_manifest: &str,
    package: &[u8],
) -> Result<PackageMetadata, String> {
    let manifest = HostManifest::verify(raw, signature, trusted, minimum_epoch)?;
    if !digest_valid(expected_manifest, 64)
        || format!("{:x}", Sha256::digest(raw)) != expected_manifest
    {
        return Err("host_install_runtime_changed".into());
    }
    if package.len() > 64 * 1024 || manifest.epoch > 9_007_199_254_740_991 {
        return Err("host_package_metadata_invalid".into());
    }
    let artifact = manifest
        .files
        .get("server/package.json")
        .ok_or("host_component_missing")?;
    if artifact.bytes != package.len() as u64
        || artifact.sha256 != format!("{:x}", Sha256::digest(package))
    {
        return Err("host_package_metadata_invalid".into());
    }
    let package: serde_json::Value =
        serde_json::from_slice(package).map_err(|_| "host_package_metadata_invalid")?;
    let version = package["version"]
        .as_str()
        .ok_or("native_host_version_invalid")?;
    crate::host_setup::native_release(version, &manifest.source_revision)?;
    Ok(PackageMetadata {
        version: version.into(),
        epoch: manifest.epoch,
        source_revision: manifest.source_revision,
    })
}

#[cfg(test)]
mod tests {
    use crate::host_epochs::host_fixture::Fixture;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;
    use sha2::{Digest, Sha256};

    fn fixture(package: &[u8]) -> Fixture {
        let mut fixture = Fixture::new();
        std::fs::write(fixture.0.join("server/package.json"), package).unwrap();
        fixture.1["files"]["server/package.json"] =
            json!({"bytes":package.len(),"sha256":format!("{:x}",Sha256::digest(package))});
        fixture
    }
    fn metadata(fixture: &Fixture, package: &[u8]) -> Result<super::PackageMetadata, String> {
        let raw = serde_json::to_vec(&fixture.1).unwrap();
        let key = SigningKey::from_bytes(&[42; 32]);
        super::package_metadata(
            &raw,
            &key.sign(&raw).to_bytes(),
            &[key.verifying_key()],
            1,
            &format!("{:x}", Sha256::digest(&raw)),
            package,
        )
    }
    #[test]
    fn package_metadata_reports_signed_version_without_authorizing_payload_execution() {
        let package = br#"{"version":"3.1.0"}"#;
        let fixture = fixture(package);
        let result = metadata(&fixture, package).unwrap();
        assert_eq!(
            serde_json::to_value(result).unwrap(),
            json!({"version":"3.1.0","epoch":1,"sourceRevision":"a".repeat(40)})
        );
        assert!(fixture.verify().is_ok());
        std::fs::write(fixture.0.join("node"), b"changed executable").unwrap();
        assert!(metadata(&fixture, package).is_ok());
        assert!(
            fixture.verify().is_err(),
            "display metadata must not replace full execution verification"
        );
        assert!(metadata(&fixture, br#"{"version":"9.9.9"}"#).is_err());
    }
    #[test]
    fn package_metadata_refuses_signature_identity_and_floor_mismatch() {
        let package = br#"{"version":"3.1.0"}"#;
        let fixture = fixture(package);
        let raw = serde_json::to_vec(&fixture.1).unwrap();
        let key = SigningKey::from_bytes(&[42; 32]);
        let sig = key.sign(&raw).to_bytes();
        let digest = format!("{:x}", Sha256::digest(&raw));
        let other = SigningKey::from_bytes(&[43; 32]);
        assert!(
            super::package_metadata(&raw, &sig, &[other.verifying_key()], 1, &digest, package)
                .is_err()
        );
        assert!(
            super::package_metadata(&raw, &sig, &[key.verifying_key()], 2, &digest, package)
                .is_err()
        );
        assert!(super::package_metadata(
            &raw,
            &sig,
            &[key.verifying_key()],
            1,
            &"f".repeat(64),
            package
        )
        .is_err());
        let mut altered = raw.clone();
        altered.push(b' ');
        assert!(super::package_metadata(
            &altered,
            &sig,
            &[key.verifying_key()],
            1,
            &digest,
            package
        )
        .is_err());
    }
    #[test]
    fn package_metadata_refuses_incompatible_manifests_and_unbounded_or_invalid_versions() {
        for (field, value) in [
            ("schemaVersion", json!(9)),
            ("protocolVersion", json!(9)),
            ("epoch", json!(9007199254740992u64)),
            ("platform", json!("foreign")),
            ("sourceRevision", json!("main")),
        ] {
            let package = br#"{"version":"3.1.0"}"#;
            let mut fixture = fixture(package);
            fixture.1[field] = value;
            assert!(metadata(&fixture, package).is_err(), "{field}");
        }
        for package in [
            br#"{"version":"3.1.0-preview"}"#.as_slice(),
            br#"{"version":123}"#.as_slice(),
            br#"{"version":"3.1.0\n"}"#.as_slice(),
            b"not JSON".as_slice(),
            vec![b' '; 65537].as_slice(),
        ] {
            let fixture = fixture(package);
            assert!(metadata(&fixture, package).is_err());
        }
    }
}

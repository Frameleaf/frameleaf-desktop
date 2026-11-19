//! One link in the signed history of backups that Frameleaf Cloud keeps: which stored object is the
//! backup, its exact version and the hash of its bytes, and the link before it. The machine that made the
//! backup signs it with its Ed25519 identity, so the history can be withheld but never forged, reordered
//! or rolled back.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{invalid, Result};

/// The field order is the published contract; never reorder it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotDescriptor {
    pub version: u32,
    pub instance_id: String,
    pub vault_id: String,
    pub snapshot_id: String,
    /// Starts at 1 and goes up by one.
    pub sequence: u64,
    /// The digest of the record before this one; None for the first.
    pub previous_digest: Option<String>,
    pub created_at: String,
    pub manifest: Manifest,
    pub signer_kid: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    pub format: String,
    pub format_version: u32,
    pub key_version: u32,
    pub object_key: String,
    pub version_id: String,
    pub ciphertext_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Ed25519Jwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub kid: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotSignature {
    /// Ed25519 over the signing input, unpadded base64url.
    pub signature: String,
    /// SHA-256 of the signing input, hex. The next record names it as `previousDigest`.
    pub digest: String,
    pub signer_jwk: Ed25519Jwk,
}

/// RFC 7638 thumbprint of an Ed25519 public key (`x` is unpadded base64url).
pub fn ed25519_thumbprint(x: &str) -> String {
    let canonical = format!(
        r#"{{"crv":"Ed25519","kty":"OKP","x":{}}}"#,
        serde_json::to_string(x).expect("a string")
    );
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical))
}

/// The public JWK of a key, with its thumbprint as `kid`.
pub fn public_jwk(key: &VerifyingKey) -> Ed25519Jwk {
    let x = URL_SAFE_NO_PAD.encode(key.as_bytes());
    Ed25519Jwk {
        kty: "OKP".into(),
        crv: "Ed25519".into(),
        kid: ed25519_thumbprint(&x),
        x,
    }
}

/// The exact bytes that are signed: a label, a newline, then the descriptor's JSON in its fixed order.
pub fn snapshot_signing_input(descriptor: &SnapshotDescriptor) -> Vec<u8> {
    let mut bytes = b"frameleaf-backup-snapshot-v2\n".to_vec();
    bytes.extend(serde_json::to_vec(descriptor).expect("a descriptor serialises"));
    bytes
}

pub fn snapshot_digest(descriptor: &SnapshotDescriptor) -> String {
    hex::encode(Sha256::digest(snapshot_signing_input(descriptor)))
}

/// Signs a descriptor with the key it names.
pub fn sign_snapshot_descriptor(
    descriptor: &SnapshotDescriptor,
    key: &SigningKey,
) -> Result<SnapshotSignature> {
    let signer_jwk = public_jwk(&key.verifying_key());
    if descriptor.signer_kid != signer_jwk.kid {
        return Err(invalid(
            "Backup requires the current instance signing identity",
        ));
    }
    let bytes = snapshot_signing_input(descriptor);
    Ok(SnapshotSignature {
        signature: URL_SAFE_NO_PAD.encode(key.sign(&bytes).to_bytes()),
        digest: hex::encode(Sha256::digest(&bytes)),
        signer_jwk,
    })
}

/// Whether a record was signed by `pinned`, a key the caller already trusts, and says so truthfully about itself.
pub fn snapshot_signature_holds(
    descriptor: &SnapshotDescriptor,
    record: &SnapshotSignature,
    pinned: Option<&Ed25519Jwk>,
) -> bool {
    let Some(pinned) = pinned else { return false };
    if pinned.kid != descriptor.signer_kid
        || pinned.x != record.signer_jwk.x
        || ed25519_thumbprint(&pinned.x) != pinned.kid
        || record.signer_jwk.kid != pinned.kid
    {
        return false;
    }
    let bytes = snapshot_signing_input(descriptor);
    if hex::encode(Sha256::digest(&bytes)) != record.digest {
        return false;
    }
    let key = URL_SAFE_NO_PAD
        .decode(&pinned.x)
        .ok()
        .and_then(|x| <[u8; 32]>::try_from(x).ok());
    let signature = URL_SAFE_NO_PAD
        .decode(&record.signature)
        .ok()
        .and_then(|s| <[u8; 64]>::try_from(s).ok());
    match (
        key.and_then(|key| VerifyingKey::from_bytes(&key).ok()),
        signature,
    ) {
        (Some(key), Some(signature)) => key
            .verify(&bytes, &Signature::from_bytes(&signature))
            .is_ok(),
        _ => false,
    }
}

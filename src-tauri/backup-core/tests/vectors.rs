//! Golden values: the TypeScript engine's pinned vectors, and more exported from it (tools/export_fixtures.mjs).

mod common;

use std::time::{Duration, UNIX_EPOCH};

use common::{fixtures, noise, CHUNKER};
use ed25519_dalek::SigningKey;
use frameleaf_backup_core::escrow::{
    scrypt_derive, unwrap_bucket_key, wrap_bucket_key, KeyEscrowBlob,
};
use frameleaf_backup_core::s3::{sign_s3_request, S3Credentials, SignRequest};
use frameleaf_backup_core::snapshot_record::{
    public_jwk, sign_snapshot_descriptor, snapshot_signature_holds, snapshot_signing_input,
    SnapshotDescriptor,
};
use frameleaf_backup_core::{
    blob_id, chunks, derive_keys, gear_table, parse_recovery_code, recovery_code,
    server_backup_vault_id, ChunkerParams,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn vectors() -> Value {
    serde_json::from_slice(&std::fs::read(fixtures().join("vectors.json")).unwrap()).unwrap()
}

fn cuts(data: &[u8], key: &[u8], params: ChunkerParams, step: usize) -> Vec<usize> {
    let gear = gear_table(key);
    // Handed over `step` bytes at a time, as a stream would.
    struct Steps<'a>(&'a [u8], usize);
    impl std::io::Read for Steps<'_> {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            let take = self.0.len().min(self.1).min(out.len());
            out[..take].copy_from_slice(&self.0[..take]);
            self.0 = &self.0[take..];
            Ok(take)
        }
    }
    chunks(Steps(data, step), params, &gear)
        .map(|chunk| chunk.unwrap().len())
        .collect()
}

#[test]
fn matches_the_pinned_vectors() {
    let keys = derive_keys(&[1; 32], "00000000-0000-4000-8000-000000000000").unwrap();
    assert_eq!(
        hex::encode(keys.id),
        "2dea066050be60054b2d154c58e6a55ad8c19b60767f25e8dea028f772292897"
    );
    assert_eq!(
        hex::encode(keys.cut),
        "023c077490b2650e26f330a1bbc7227baf29922afde58c3df983ee917c7bccdf"
    );
    assert_eq!(
        gear_table(&keys.cut)[..4],
        [1_285_107_895, 1_290_597_550, 3_046_091_720, 4_054_664_066]
    );
    assert_eq!(
        hex::encode(blob_id(&keys, b"frameleaf")),
        "7a846dc5b149eaf4ade5871532800c13423818c647f94bebbddd42d7b9e6430f"
    );
    assert_eq!(
        cuts(&noise(100_000, 42), &keys.cut, CHUNKER, 7000),
        [
            2513, 4710, 5595, 7257, 4552, 4568, 6708, 4478, 2803, 5209, 1073, 5284, 6510, 4440,
            4717, 4238, 4905, 3219, 7723, 4148, 4220, 1130
        ]
    );
}

#[test]
fn matches_the_exported_vectors() {
    let vectors = vectors();
    let keys = derive_keys(&[1; 32], "00000000-0000-4000-8000-000000000000").unwrap();
    for (name, value) in [
        ("id", keys.id),
        ("blob", keys.blob),
        ("cut", keys.cut),
        ("meta", keys.meta),
    ] {
        assert_eq!(
            hex::encode(value),
            vectors["keys"][name].as_str().unwrap(),
            "{name}"
        );
    }
    let gear: Vec<u8> = gear_table(&keys.cut)
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect();
    assert_eq!(hex::encode(Sha256::digest(gear)), vectors["gearSha256"]);
    let small = ChunkerParams {
        min: 64,
        avg: 256,
        max: 1024,
    };
    let want: Vec<usize> = serde_json::from_value(vectors["cutsSmall"].clone()).unwrap();
    for step in [1, 333, 7000, 1 << 20] {
        assert_eq!(
            cuts(&noise(30_000, 7), &keys.cut, small, step),
            want,
            "arriving {step} bytes at a time"
        );
    }
    let default: Vec<usize> = serde_json::from_value(vectors["cutsDefault"].clone()).unwrap();
    assert_eq!(cuts(&noise(100_000, 42), &keys.cut, CHUNKER, 1), default);
}

#[test]
fn chunks_differently_under_another_key_and_survives_an_insertion() {
    let data = noise(200_000, 1);
    let sizes = cuts(&data, &[7; 32], CHUNKER, 7000);
    assert_eq!(sizes.iter().sum::<usize>(), data.len());
    assert!(sizes[..sizes.len() - 1]
        .iter()
        .all(|size| *size > CHUNKER.min && *size <= CHUNKER.max));
    assert_ne!(cuts(&data, &[8; 32], CHUNKER, 7000), sizes);

    let hashes = |input: &[u8]| -> std::collections::HashSet<Vec<u8>> {
        let gear = gear_table(&[7; 32]);
        chunks(input, CHUNKER, &gear)
            .map(|chunk| Sha256::digest(chunk.unwrap()).to_vec())
            .collect()
    };
    let before = hashes(&data);
    let after = hashes(&[&data[..500], b"a few new bytes", &data[500..]].concat());
    assert!(
        after.iter().filter(|hash| before.contains(*hash)).count() as f64
            > after.len() as f64 * 0.8
    );
}

#[test]
fn prints_and_reads_the_recovery_code() {
    let key: Vec<u8> = (0..32u32)
        .map(|index| ((index * 37 + 11) & 0xff) as u8)
        .collect();
    let code = recovery_code(&key);
    assert_eq!(code, vectors()["recoveryCode"]);
    assert_eq!(code.split('-').count(), 14);
    assert_eq!(parse_recovery_code(&code).unwrap().to_vec(), key);
    assert_eq!(
        parse_recovery_code(&code.to_lowercase().replace('-', " "))
            .unwrap()
            .to_vec(),
        key
    );
    assert_eq!(
        parse_recovery_code(&code.replace('0', "O").replace('1', "l"))
            .unwrap()
            .to_vec(),
        key
    );
    let other = recovery_code(&[9; 32]);
    assert_eq!(parse_recovery_code(&other[..other.len() - 5]), None);
    assert_eq!(
        parse_recovery_code(&format!("{}U", &other[..other.len() - 1])),
        None
    );
    assert_eq!(server_backup_vault_id(&[7; 32]), vectors()["vaultId"]);
}

#[test]
fn signs_s3_requests_as_aws_and_the_typescript_engine_do() {
    let doc = sign_s3_request(&SignRequest {
        method: "GET",
        host: "examplebucket.s3.amazonaws.com",
        canonical_uri: "/test.txt",
        query: "",
        headers: &[("Range", "bytes=0-9")],
        body: None,
        region: "us-east-1",
        credentials: &S3Credentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            session_token: None,
        },
        now: UNIX_EPOCH + Duration::from_secs(1_369_353_600),
    });
    assert_eq!(
        doc["authorization"],
        "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
    );
    assert!(!doc.contains_key("host"));

    let ours = sign_s3_request(&SignRequest {
        method: "PUT",
        host: "localhost:9000",
        canonical_uri: "/bucket/r/v1/vault/p/%C3%BC%20x",
        query: "partNumber=2&uploadId=a%2Fb",
        headers: &[("Content-Type", " application/octet-stream ")],
        body: Some(b"hello"),
        region: "us-east-1",
        credentials: &S3Credentials {
            access_key_id: "AKIDEXAMPLE".into(),
            secret_access_key: "secret".into(),
            session_token: Some("token".into()),
        },
        now: time::OffsetDateTime::parse(
            "2026-11-18T12:34:56.789Z",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap()
        .into(),
    });
    let theirs: std::collections::BTreeMap<String, String> =
        serde_json::from_value(vectors()["signedS3"].clone()).unwrap();
    assert_eq!(ours, theirs);
}

#[test]
fn derives_escrow_keys_as_rfc_7914_and_opens_what_the_typescript_engine_wrapped() {
    let derived = scrypt_derive("pleaseletmein", b"SodiumChloride", 16_384, 8, 1, 64).unwrap();
    assert_eq!(
        hex::encode(derived),
        "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887"
    );
    let theirs: KeyEscrowBlob = serde_json::from_value(vectors()["escrow"].clone()).unwrap();
    let ours = wrap_bucket_key(
        &[7; 32],
        "correct horse battery staple",
        Some(([3; 16], [4; 12])),
    )
    .unwrap();
    assert_eq!(ours, theirs, "the same salt and nonce give the same bytes");
    assert_eq!(serde_json::to_value(&ours).unwrap(), vectors()["escrow"]);
    assert_eq!(
        unwrap_bucket_key(&theirs, "correct horse battery staple").unwrap(),
        [7; 32]
    );
    assert!(unwrap_bucket_key(&theirs, "correct horse battery stapler")
        .unwrap_err()
        .to_string()
        .contains("does not open"));
    assert!(wrap_bucket_key(&[7; 32], "too short", None)
        .unwrap_err()
        .to_string()
        .contains("at least 12"));
    let random = wrap_bucket_key(&[7; 32], "correct horse battery staple", None).unwrap();
    assert_eq!(
        unwrap_bucket_key(&random, "correct horse battery staple").unwrap(),
        [7; 32]
    );
}

#[test]
fn signs_the_record_of_a_backup_over_the_same_bytes() {
    let vectors = vectors();
    let descriptor: SnapshotDescriptor =
        serde_json::from_value(vectors["descriptor"].clone()).unwrap();
    let bytes = snapshot_signing_input(&descriptor);
    assert_eq!(
        hex::encode(Sha256::digest(&bytes)),
        vectors["signingInputSha256"]
    );
    assert!(bytes.starts_with(b"frameleaf-backup-snapshot-v2\n{\"version\":2,\"instanceId\":"));

    let key = SigningKey::from_bytes(&[11; 32]);
    let pinned = public_jwk(&key.verifying_key());
    let mine = SnapshotDescriptor {
        signer_kid: pinned.kid.clone(),
        previous_digest: None,
        ..descriptor
    };
    let signed = sign_snapshot_descriptor(&mine, &key).unwrap();
    assert!(snapshot_signature_holds(&mine, &signed, Some(&pinned)));
    assert!(!snapshot_signature_holds(&mine, &signed, None));
    let other = public_jwk(&SigningKey::from_bytes(&[12; 32]).verifying_key());
    assert!(!snapshot_signature_holds(&mine, &signed, Some(&other)));
    assert!(!snapshot_signature_holds(
        &SnapshotDescriptor {
            sequence: 8,
            ..mine.clone()
        },
        &signed,
        Some(&pinned)
    ));
    let elsewhere = SnapshotDescriptor {
        signer_kid: "someone-else".into(),
        ..mine
    };
    assert!(sign_snapshot_descriptor(&elsewhere, &key)
        .unwrap_err()
        .to_string()
        .contains("signing identity"));
}

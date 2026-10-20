use super::super::{validate_report, QualifiedRuntime, VerifiedRuntime};
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::PathBuf,
    time::{Duration, Instant},
};

#[test]
#[ignore = "requires owned signed CoreML runtime and archived real three-role qualifications; real GPU preparation"]
fn archived_three_role_qualifications_share_one_real_gpu_process() {
    let root = PathBuf::from(
        std::env::var_os("FRAMELEAF_TEST_COREML_GROUP").expect("owned fixture required"),
    );
    let input: Value = serde_json::from_slice(&fs::read(root.join("input.json")).unwrap()).unwrap();
    let cache = PathBuf::from(input["cache"].as_str().unwrap());
    let candidate = root.join("candidate");
    let signature: [u8; 64] = fs::read(candidate.join("manifest.sig"))
        .unwrap()
        .try_into()
        .unwrap();
    let runtime = VerifiedRuntime::verify(
        &candidate.join("payload"),
        &fs::read(candidate.join("manifest.json")).unwrap(),
        &signature,
        &[SigningKey::from_bytes(&[71; 32]).verifying_key()],
        1,
    )
    .unwrap();
    let mut qualified = Vec::new();
    let mut cases = Vec::new();
    for role in input["roles"].as_array().unwrap() {
        let role = PathBuf::from(role.as_str().unwrap());
        let raw = fs::read(role.join("spec.json")).unwrap();
        let spec: Value = serde_json::from_slice(&raw).unwrap();
        let fixture = fs::read(role.join(spec["fixtureFile"].as_str().unwrap())).unwrap();
        let profile = crate::model_catalogue::approved_profile(
            "ViT-B-16-SigLIP-384__webli",
            &spec["entries"],
            runtime.source_revision(),
            runtime.provider(),
        )
        .unwrap()
        .unwrap();
        let filename = PathBuf::from(spec["fixtureFile"].as_str().unwrap());
        let (expected_spec, expected_fixture) = profile
            .challenge(filename.file_stem().unwrap().to_str().unwrap())
            .unwrap();
        assert_eq!(raw, expected_spec);
        assert_eq!(fixture, expected_fixture);
        let report: Value =
            serde_json::from_slice(&fs::read(role.join("qualified-report.json")).unwrap()).unwrap();
        let receipt: Value =
            serde_json::from_slice(&fs::read(role.join("nas-validation-result.json")).unwrap())
                .unwrap();
        assert_eq!(receipt["receiptValidated"], true);
        assert_eq!(receipt["manifestSha256"], runtime.manifest_sha256());
        assert_eq!(
            receipt["reportSha256"],
            format!(
                "{:x}",
                Sha256::digest(serde_json_canonicalizer::to_vec(&report).unwrap())
            )
        );
        validate_report(
            &report,
            &spec,
            &format!("{:x}", Sha256::digest(&raw)),
            super::collector_hash(&runtime.manifest),
        )
        .unwrap();
        // Archived fixtures enter this private test only; production still obtains this type through qualify.
        qualified.push(QualifiedRuntime {
            spec: raw,
            report,
            manifest_sha256: runtime.manifest_sha256().into(),
        });
        cases.push((spec, fixture));
    }
    assert_eq!(qualified.len(), 3);
    assert!(qualified
        .iter()
        .all(|item| item.report()["runtimeFingerprint"]
            == qualified[0].report()["runtimeFingerprint"]));
    let work = root.join(format!("owned-work-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&work).unwrap();
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let refs: Vec<_> = qualified.iter().collect();
    let mut sidecar = runtime
        .start_bound_sidecar(&refs, &cache, &work, port)
        .unwrap();
    let scratch = sidecar.working_dir().to_path_buf();
    let engine = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let result=engine.block_on(async {
        let client=reqwest::Client::builder().no_proxy().pool_max_idle_per_host(0).timeout(Duration::from_secs(5)).build().unwrap();
        let base=format!("http://127.0.0.1:{port}");
        let budget=cases.iter().map(|(spec,_)|spec["deadlineSeconds"].as_u64().unwrap()).sum::<u64>()+15;
        let start=Instant::now();let end=start+Duration::from_secs(budget);
        loop {
            if client.get(format!("{base}/ping")).bearer_auth(sidecar.authorization()).send().await.is_ok_and(|r|r.status().is_success()) {break;}
            assert!(sidecar.is_running().unwrap(),"grouped sidecar exited");assert!(Instant::now()<end,"grouped preparation deadline");tokio::time::sleep(Duration::from_millis(250)).await;
        }
        let preparation_ms=start.elapsed().as_secs_f64()*1000.0;
        assert_eq!(client.get(format!("{base}/ping")).send().await.unwrap().status(),reqwest::StatusCode::UNAUTHORIZED);
        let mut outputs=Vec::new();
        for index in [0,1,2,2,1,0] {
            let (spec,fixture)=&cases[index];
            let form=reqwest::multipart::Form::new().text("entries",serde_json::to_string(&spec["entries"]).unwrap());
            let form=if spec["fixtureKind"]=="text" {form.text("text",String::from_utf8(fixture.clone()).unwrap())} else {form.part("image",reqwest::multipart::Part::bytes(fixture.clone()).file_name("input").mime_str("application/octet-stream").unwrap())};
            let response=client.post(format!("{base}/predict")).bearer_auth(sidecar.authorization()).multipart(form).send().await.unwrap();
            assert!(response.status().is_success(),"role{index}: {}",response.status());
            let value:Value=response.json().await.unwrap();let actual:Vec<f64>=serde_json::from_str(value["clip"].as_str().unwrap()).unwrap();let expected:Vec<f64>=serde_json::from_str(spec["expectedOutput"]["clip"].as_str().unwrap()).unwrap();assert_eq!(actual.len(),expected.len());
            let mut max=0.0_f64;
            for (a,e) in actual.iter().zip(&expected) {let d=(a-e).abs();assert!(a.is_finite()&&d<=1e-4_f64.max(1e-3*a.abs().max(e.abs())));max=max.max(d);}
            outputs.push(json!({"role":index,"dimensions":actual.len(),"maxAbsoluteDifference":max}));
        }
        let mut unbound=cases[0].0["entries"].clone();unbound["clip"]["textual"]["options"]["language"]=json!("fr");
        let form=reqwest::multipart::Form::new().text("entries",unbound.to_string()).text("text","fixture");
        assert_eq!(client.post(format!("{base}/predict")).bearer_auth(sidecar.authorization()).multipart(form).send().await.unwrap().status(),reqwest::StatusCode::CONFLICT);
        json!({"fixtureOnly":true,"archivedQualificationsReplayedOnlyInTest":true,"realFreshQualificationRun":false,"runtimeSignatureVerified":true,"roles":3,"predictions":outputs,"preparationMilliseconds":preparation_ms,"startupBudgetSeconds":budget,"unauthorizedRefused":true,"unboundConfigurationRefused":true,"releaseAuthorityUsed":false})
    });
    sidecar.stop().unwrap();
    drop(sidecar);
    assert!(!scratch.exists());
    fs::remove_dir(&work).unwrap();
    fs::write(
        root.join("RESULT-process.json"),
        serde_json::to_vec_pretty(&result).unwrap(),
    )
    .unwrap();
}

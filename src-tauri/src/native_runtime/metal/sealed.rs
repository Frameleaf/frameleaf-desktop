use super::super::VerifiedRuntime;
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

#[test]
#[ignore = "requires the explicitly owned complete CoreML fixture; real GPU model preparation"]
fn sealed_coreml_runtime_qualifies_and_predicts_the_approved_reference() {
    let root = PathBuf::from(
        std::env::var_os("FRAMELEAF_TEST_COREML_FIXTURE").expect("owned fixture root required"),
    );
    let input: Value = serde_json::from_slice(&fs::read(root.join("input.json")).unwrap()).unwrap();
    let cache = PathBuf::from(input["cache"].as_str().unwrap());
    let candidate = root.join("candidate");
    let signature: [u8; 64] = fs::read(candidate.join("manifest.sig"))
        .unwrap()
        .try_into()
        .unwrap();
    let key = SigningKey::from_bytes(&[71; 32]).verifying_key();
    let runtime = VerifiedRuntime::verify(
        &candidate.join("payload"),
        &fs::read(candidate.join("manifest.json")).unwrap(),
        &signature,
        &[key],
        1,
    )
    .unwrap();
    let raw = fs::read(root.join("spec.json")).unwrap();
    let spec: Value = serde_json::from_slice(&raw).unwrap();
    let fixture = fs::read(root.join(spec["fixtureFile"].as_str().unwrap())).unwrap();
    let work = root.join(format!("owned-work-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&work).unwrap();
    let qualified = runtime
        .qualify(&cache, &work, &raw, &fixture, &AtomicBool::new(false))
        .expect("sealed real CoreML qualification");
    assert_eq!(qualified.report()["state"], "ready-mixed");
    fs::write(
        root.join("qualified-report.json"),
        serde_json::to_vec_pretty(qualified.report()).unwrap(),
    )
    .unwrap();
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let mut sidecar = runtime
        .start_qualified_sidecar(&qualified, &cache, &work, port)
        .unwrap();
    let scratch = sidecar.working_dir().to_path_buf();
    let engine = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let result=engine.block_on(async {
        let client=reqwest::Client::builder().pool_max_idle_per_host(0).timeout(Duration::from_secs(5)).build().unwrap();
        let base=format!("http://127.0.0.1:{port}");
        let deadline=Instant::now()+Duration::from_secs(spec["deadlineSeconds"].as_u64().unwrap_or(120)+15);
        loop {
            if client.get(format!("{base}/ping")).bearer_auth(sidecar.authorization()).send().await.is_ok_and(|response|response.status().is_success()) { break; }
            assert!(sidecar.is_running().unwrap(),"owned sidecar exited during preparation");
            assert!(Instant::now()<deadline,"owned sidecar preparation deadline");
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        assert_eq!(client.get(format!("{base}/ping")).send().await.unwrap().status(),reqwest::StatusCode::UNAUTHORIZED);
        let form=reqwest::multipart::Form::new().text("entries",serde_json::to_string(&spec["entries"]).unwrap());
        let form=match spec["fixtureKind"].as_str().unwrap() {
            "text" => form.text("text",String::from_utf8(fixture.clone()).unwrap()),
            "image" => form.part("image",reqwest::multipart::Part::bytes(fixture.clone()).file_name("input").mime_str("application/octet-stream").unwrap()),
            kind => panic!("unsupported fixture kind: {kind}"),
        };
        let response=client.post(format!("{base}/predict")).bearer_auth(sidecar.authorization()).multipart(form).send().await.unwrap();
        assert!(response.status().is_success(),"bound prediction refused: {}",response.status());
        let value:Value=response.json().await.unwrap();
        let actual:Vec<f64>=serde_json::from_str(value["clip"].as_str().unwrap()).unwrap();
        let expected:Vec<f64>=serde_json::from_str(spec["expectedOutput"]["clip"].as_str().unwrap()).unwrap();
        assert_eq!(actual.len(),expected.len());
        let mut difference=0.0_f64;
        for (actual,expected) in actual.iter().zip(&expected) {
            let delta=(actual-expected).abs();assert!(actual.is_finite()&&delta<=1e-4_f64.max(1e-3*actual.abs().max(expected.abs())));difference=difference.max(delta);
        }
        json!({"fixtureOnly":true,"runtimeSignatureVerified":true,"state":"ready-mixed","authenticatedBoundPrediction":true,"fixtureKind":spec["fixtureKind"],"referenceDimensions":actual.len(),"maxAbsoluteDifference":difference,"releaseAuthorityUsed":false})
    });
    sidecar.stop().unwrap();
    drop(sidecar);
    assert!(!scratch.exists());
    fs::remove_dir(&work).unwrap();
    fs::write(
        root.join("prediction-result.json"),
        serde_json::to_vec_pretty(&result).unwrap(),
    )
    .unwrap();
}

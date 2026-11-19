//! The S3 store against a small S3 stand-in on 127.0.0.1: paths, ranges, paging, multipart, retries,
//! renewed credentials, and a backup restored through Range GETs.

mod common;

use std::collections::{BTreeMap, VecDeque};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{manifest, noise, CHUNKER, PACK_TARGET, ROOT_KEY};
use frameleaf_backup_core::s3::{S3Credentials, S3Options, S3Store};
use frameleaf_backup_core::{
    backup, fs_source, restore, BackupOptions, ByteRange, Error, Repository, Store,
};

#[derive(Clone, Debug)]
struct Seen {
    method: String,
    path: String,
    query: String,
    range: Option<String>,
    token: Option<String>,
}

#[derive(Default)]
struct State {
    objects: BTreeMap<String, Vec<u8>>,
    uploads: BTreeMap<String, BTreeMap<u32, Vec<u8>>>,
    seen: Vec<Seen>,
    /// Answers given before the real one: (status, S3 error code).
    failures: VecDeque<(u16, &'static str)>,
    /// Parts from this number on are refused.
    refuse_parts_from: Option<u32>,
}

fn decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'%' {
            out.push(u8::from_str_radix(&text[at + 1..at + 3], 16).unwrap());
            at += 3;
        } else {
            out.push(bytes[at]);
            at += 1;
        }
    }
    String::from_utf8(out).unwrap()
}

fn answer(
    state: &mut State,
    method: &str,
    path: &str,
    query: &BTreeMap<String, String>,
    headers: &BTreeMap<String, String>,
    body: Vec<u8>,
) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let error = |status: u16, code: &str| {
        (
            status,
            vec![],
            format!("<Error><Code>{code}</Code></Error>").into_bytes(),
        )
    };
    if !headers
        .get("authorization")
        .is_some_and(|value| value.starts_with("AWS4-HMAC-SHA256 Credential="))
    {
        return error(403, "AccessDenied");
    }
    if let Some((status, code)) = state.failures.pop_front() {
        return error(status, code);
    }
    let key = path
        .strip_prefix("/bucket/")
        .map(decode)
        .unwrap_or_default();
    match (method, query.contains_key("uploads"), query.get("uploadId")) {
        ("GET", _, _) if key.is_empty() => {
            let prefix = query.get("prefix").cloned().unwrap_or_default();
            let keys: Vec<_> = state
                .objects
                .iter()
                .filter(|(name, _)| name.starts_with(&prefix))
                .collect();
            let start: usize = query
                .get("continuation-token")
                .map_or(0, |token| token.parse().unwrap());
            let page = &keys[start..keys.len().min(start + 2)];
            let truncated = start + 2 < keys.len();
            let mut xml = String::from("<ListBucketResult>");
            for (name, body) in page {
                xml += &format!("<Contents><Key>{name}</Key><LastModified>2026-01-01T00:00:00.000Z</LastModified><Size>{}</Size></Contents>", body.len());
            }
            xml += &format!("<IsTruncated>{truncated}</IsTruncated>");
            if truncated {
                xml += &format!(
                    "<NextContinuationToken>{}</NextContinuationToken>",
                    start + 2
                );
            }
            (200, vec![], (xml + "</ListBucketResult>").into_bytes())
        }
        ("GET", _, _) => {
            let Some(object) = state.objects.get(&key) else {
                return error(404, "NoSuchKey");
            };
            match headers.get("range") {
                Some(range) => {
                    let spec = range.strip_prefix("bytes=").unwrap();
                    let (start, end) = match spec.split_once('-').unwrap() {
                        ("", suffix) => (
                            object.len().saturating_sub(suffix.parse().unwrap()),
                            object.len(),
                        ),
                        (start, end) => (
                            start.parse().unwrap(),
                            (end.parse::<usize>().unwrap() + 1).min(object.len()),
                        ),
                    };
                    (206, vec![], object[start..end].to_vec())
                }
                None => (200, vec![], object.clone()),
            }
        }
        ("POST", true, _) => {
            let id = format!("upload-{}", state.uploads.len() + 1);
            state.uploads.insert(id.clone(), BTreeMap::new());
            (200, vec![], format!("<InitiateMultipartUploadResult><UploadId>{id}</UploadId></InitiateMultipartUploadResult>").into_bytes())
        }
        ("PUT", _, Some(upload)) => {
            let number: u32 = query["partNumber"].parse().unwrap();
            if state.refuse_parts_from.is_some_and(|from| number >= from) {
                return error(400, "InvalidPart");
            }
            state.uploads.get_mut(upload).unwrap().insert(number, body);
            (
                200,
                vec![("etag".into(), format!("\"etag-{number}\""))],
                vec![],
            )
        }
        ("POST", _, Some(upload)) => {
            let parts = state.uploads.remove(upload).unwrap();
            assert!(String::from_utf8(body)
                .unwrap()
                .contains(&format!("<PartNumber>{}</PartNumber>", parts.len())));
            state
                .objects
                .insert(key, parts.into_values().flatten().collect());
            (
                200,
                vec![("x-amz-version-id".into(), "v-multipart".into())],
                b"<CompleteMultipartUploadResult/>".to_vec(),
            )
        }
        ("DELETE", _, Some(upload)) => {
            state.uploads.remove(upload);
            (204, vec![], vec![])
        }
        ("PUT", _, _) => {
            state.objects.insert(key, body);
            (
                200,
                vec![
                    ("etag".into(), "\"e\"".into()),
                    ("x-amz-version-id".into(), "null".into()),
                ],
                vec![],
            )
        }
        ("DELETE", _, _) => {
            state.objects.remove(&key);
            (204, vec![], vec![])
        }
        _ => error(400, "BadRequest"),
    }
}

/// Starts the stand-in; returns its address and its state.
fn stand_in() -> (String, Arc<Mutex<State>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = format!("http://{}", listener.local_addr().unwrap());
    let state = Arc::new(Mutex::new(State::default()));
    let shared = state.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let state = shared.clone();
            std::thread::spawn(move || {
                let mut stream = stream.unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        return;
                    }
                    let mut parts = line.split_whitespace();
                    let (method, target) = (
                        parts.next().unwrap().to_string(),
                        parts.next().unwrap().to_string(),
                    );
                    let mut headers = BTreeMap::new();
                    loop {
                        let mut header = String::new();
                        reader.read_line(&mut header).unwrap();
                        let header = header.trim_end();
                        if header.is_empty() {
                            break;
                        }
                        let (name, value) = header.split_once(':').unwrap();
                        headers.insert(name.to_lowercase(), value.trim().to_string());
                    }
                    let mut body = vec![
                        0u8;
                        headers
                            .get("content-length")
                            .map_or(0, |length| length.parse().unwrap())
                    ];
                    reader.read_exact(&mut body).unwrap();
                    let (path, query_text) = target.split_once('?').unwrap_or((&target, ""));
                    let query: BTreeMap<String, String> = query_text
                        .split('&')
                        .filter(|pair| !pair.is_empty())
                        .map(|pair| {
                            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
                            (decode(name), decode(value))
                        })
                        .collect();
                    let (status, extra, reply) = {
                        let mut state = state.lock().unwrap();
                        state.seen.push(Seen {
                            method: method.clone(),
                            path: decode(path),
                            query: query_text.to_string(),
                            range: headers.get("range").cloned(),
                            token: headers.get("x-amz-security-token").cloned(),
                        });
                        answer(&mut state, &method, path, &query, &headers, body)
                    };
                    let mut response =
                        format!("HTTP/1.1 {status} X\r\ncontent-length: {}\r\n", reply.len());
                    for (name, value) in extra {
                        response += &format!("{name}: {value}\r\n");
                    }
                    response += "\r\n";
                    stream.write_all(response.as_bytes()).unwrap();
                    stream.write_all(&reply).unwrap();
                }
            });
        }
    });
    (address, state)
}

fn open(address: &str, renewals: Arc<AtomicUsize>) -> S3Store {
    let mut options = S3Options::new(
        address,
        "us-east-1",
        "bucket",
        Box::new(move |renew| {
            if renew {
                renewals.fetch_add(1, Ordering::SeqCst);
            }
            Ok(S3Credentials {
                access_key_id: "AKID".into(),
                secret_access_key: "secret".into(),
                session_token: Some(if renew { "fresh" } else { "stale" }.into()),
            })
        }),
    );
    options.prefix = "r/v1/vault/".into();
    options.retry_delays = vec![Duration::from_millis(1), Duration::from_millis(1)];
    options.part_size = 2048;
    S3Store::new(options).unwrap()
}

#[test]
fn puts_reads_whole_and_in_part_lists_across_pages_and_deletes_under_its_prefix() {
    let (address, state) = stand_in();
    let store = open(&address, Arc::default());
    let body = noise(5000, 1);
    for key in [
        "p/aa",
        "p/bb",
        "p/cc",
        "i/dd",
        "s/000000000001-abcdef0123456789",
    ] {
        let content = if key == "p/aa" {
            body.clone()
        } else {
            key.as_bytes().to_vec()
        };
        store.put(key, &content).unwrap();
    }
    assert!(state
        .lock()
        .unwrap()
        .objects
        .keys()
        .all(|key| key.starts_with("r/v1/vault/")));
    assert_eq!(store.get("p/aa", None).unwrap(), body);
    assert_eq!(
        store
            .get("p/aa", Some(ByteRange::Span { start: 10, end: 20 }))
            .unwrap(),
        &body[10..20]
    );
    assert_eq!(
        store.get("p/aa", Some(ByteRange::Suffix(12))).unwrap(),
        &body[4988..]
    );
    assert!(store
        .get("p/aa", Some(ByteRange::Span { start: 5, end: 5 }))
        .unwrap()
        .is_empty());
    let listed = store.list("p/").unwrap();
    assert_eq!(
        listed
            .iter()
            .map(|object| object.key.as_str())
            .collect::<Vec<_>>(),
        ["p/aa", "p/bb", "p/cc"]
    );
    assert_eq!(listed[0].size, 5000);
    let expected: std::time::SystemTime = time::OffsetDateTime::parse(
        "2026-01-01T00:00:00Z",
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap()
    .into();
    assert_eq!(listed[0].modified, expected);
    assert_eq!(
        state
            .lock()
            .unwrap()
            .seen
            .iter()
            .filter(|call| call.query.contains("continuation-token"))
            .count(),
        1
    );
    store.delete("p/bb").unwrap();
    assert_eq!(store.list("p/").unwrap().len(), 2);
    // The multipart upload: 5000 bytes in 2048-byte parts.
    assert_eq!(state.lock().unwrap().objects["r/v1/vault/p/aa"], body);
    assert_eq!(
        state
            .lock()
            .unwrap()
            .seen
            .iter()
            .filter(|call| call.query.contains("partNumber"))
            .count(),
        3
    );
}

#[test]
fn tries_again_after_a_server_error_and_asks_for_fresh_credentials_once_they_expire() {
    let (address, state) = stand_in();
    let renewals = Arc::new(AtomicUsize::new(0));
    let store = open(&address, renewals.clone());
    state
        .lock()
        .unwrap()
        .failures
        .extend([(500, "InternalError"), (503, "SlowDown")]);
    store.put("p/aa", b"eventually").unwrap();
    assert_eq!(
        state.lock().unwrap().objects["r/v1/vault/p/aa"],
        b"eventually"
    );

    state
        .lock()
        .unwrap()
        .failures
        .push_back((400, "ExpiredToken"));
    assert_eq!(store.get("p/aa", None).unwrap(), b"eventually");
    assert_eq!(renewals.load(Ordering::SeqCst), 1);
    assert_eq!(
        state.lock().unwrap().seen.last().unwrap().token.as_deref(),
        Some("fresh")
    );

    state.lock().unwrap().failures.extend([
        (500, "InternalError"),
        (500, "InternalError"),
        (500, "InternalError"),
    ]);
    match store.get("p/aa", None) {
        Err(Error::S3 {
            status: Some(500),
            code: Some(code),
            message,
        }) => {
            assert_eq!(code, "InternalError");
            assert!(message.contains("500 InternalError"));
        }
        other => panic!("{other:?}"),
    }
    match store.get("p/missing", None) {
        Err(Error::S3 {
            status: Some(404), ..
        }) => {}
        other => panic!("{other:?}"),
    }
}

#[test]
fn removes_the_parts_of_an_upload_that_fails() {
    let (address, state) = stand_in();
    let store = open(&address, Arc::default());
    state.lock().unwrap().refuse_parts_from = Some(2);
    assert!(store.put("p/big", &noise(6000, 2)).is_err());
    let state = state.lock().unwrap();
    assert!(
        state.uploads.is_empty(),
        "the unfinished upload was removed"
    );
    assert!(state
        .seen
        .iter()
        .any(|call| call.method == "DELETE" && call.query.contains("uploadId")));
    assert!(!state.objects.contains_key("r/v1/vault/p/big"));
}

#[test]
fn backs_up_to_a_bucket_and_restores_through_range_reads() {
    let (address, state) = stand_in();
    let store: Arc<dyn Store> = Arc::new(open(&address, Arc::default()));
    let work = tempfile::tempdir().unwrap();
    let library = work.path().join("library");
    std::fs::create_dir_all(library.join("Documents")).unwrap();
    std::fs::write(
        library.join("Documents/notes.txt"),
        "remember the milk\n".repeat(400),
    )
    .unwrap();
    std::fs::write(library.join("big.bin"), noise(150_000, 3)).unwrap();
    let mut repository = Repository::init(store.clone(), &ROOT_KEY, None, Some(CHUNKER)).unwrap();
    let result = backup(
        &mut repository,
        &fs_source(&library),
        &BackupOptions {
            pack_target: Some(PACK_TARGET),
            ..Default::default()
        },
    )
    .unwrap();

    let before = state.lock().unwrap().seen.len();
    let mut reopened = Repository::open(store, &ROOT_KEY).unwrap();
    reopened.load_index().unwrap();
    let snapshot = reopened.read_snapshot(&result.key).unwrap();
    restore(&reopened, &snapshot, &[], &work.path().join("out"), None).unwrap();
    assert_eq!(manifest(&work.path().join("out")), manifest(&library));
    let state = state.lock().unwrap();
    let reads: Vec<&Seen> = state.seen[before..]
        .iter()
        .filter(|call| call.method == "GET" && call.path.contains("/p/"))
        .collect();
    assert!(!reads.is_empty());
    assert!(
        reads.iter().all(|call| call.range.is_some()),
        "packs are only ever read by range"
    );
}

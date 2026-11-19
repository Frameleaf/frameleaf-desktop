//! A repository in an S3 bucket (Wasabi through Frameleaf Cloud, or a bucket the owner brings), signed
//! with AWS Signature Version 4. Restores read blobs by Range GET.

use std::collections::BTreeMap;
use std::io::{self, Read};
use std::sync::Arc;
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime};

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::store::{ByteRange, Store, StoredObject};
use crate::{Error, Result};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct S3Credentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
}

pub struct S3Options {
    /// The provider's address, used path-style: `<endpoint>/<bucket>/<key>`.
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    /// Put in front of every object name, for example `r/v1/<vault>/`.
    pub prefix: String,
    /// Asked before every request, so credentials that last minutes serve runs that last days. The flag is
    /// true when the provider has just said the last ones expired.
    pub credentials: Box<dyn Fn(bool) -> Result<S3Credentials> + Send + Sync>,
    /// Bytes per second to send at most, or None for no limit. Read as the upload goes.
    pub upload_limit: Option<UploadLimit>,
    /// Waits between tries after a network error, 429 or 5xx.
    pub retry_delays: Vec<Duration>,
    /// Objects larger than this are sent as multipart uploads in parts of this size.
    pub part_size: usize,
}

impl S3Options {
    pub fn new(
        endpoint: &str,
        region: &str,
        bucket: &str,
        credentials: Box<dyn Fn(bool) -> Result<S3Credentials> + Send + Sync>,
    ) -> Self {
        S3Options {
            endpoint: endpoint.into(),
            region: region.into(),
            bucket: bucket.into(),
            prefix: String::new(),
            credentials,
            upload_limit: None,
            retry_delays: vec![Duration::from_secs(1), Duration::from_secs(4)],
            part_size: 8 * 1024 * 1024,
        }
    }
}

pub type UploadLimit = Arc<dyn Fn() -> Option<u64> + Send + Sync>;

const SLICE: usize = 64 * 1024;
const EXPIRED: [&str; 4] = [
    "ExpiredToken",
    "InvalidToken",
    "RequestExpired",
    "InvalidAccessKeyId",
];

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn hmac(key: &[u8], data: &str) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("any key length");
    mac.update(data.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

/// `encodeURIComponent`, then `!'()*` as well: everything but `A-Z a-z 0-9 - _ . ~` is percent-encoded.
pub fn uri_encode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.~".contains(&byte) {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn tag(xml: &str, name: &str) -> Option<String> {
    let open = format!("<{name}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find('<')? + start;
    (xml[end..].starts_with(&format!("</{name}>"))).then(|| xml[start..end].to_string())
}

/// `YYYYMMDDTHHMMSSZ`.
fn amz_date(now: SystemTime) -> String {
    let time = time::OffsetDateTime::from(now);
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        time.year(),
        u8::from(time.month()),
        time.day(),
        time.hour(),
        time.minute(),
        time.second()
    )
}

pub struct SignRequest<'a> {
    pub method: &'a str,
    pub host: &'a str,
    pub canonical_uri: &'a str,
    pub query: &'a str,
    pub headers: &'a [(&'a str, &'a str)],
    pub body: Option<&'a [u8]>,
    pub region: &'a str,
    pub credentials: &'a S3Credentials,
    pub now: SystemTime,
}

/// AWS Signature Version 4 for S3: the headers to send, without `host` (which the sender sets from the
/// address it signed for). Every header given is signed.
pub fn sign_s3_request(request: &SignRequest) -> BTreeMap<String, String> {
    let amz_date = amz_date(request.now);
    let date_stamp = &amz_date[..8];
    let payload_hash = sha256_hex(request.body.unwrap_or_default());
    // Sorted by name in byte order, which for these lower-case ASCII names is the code-unit order.
    let mut headers: BTreeMap<String, String> = request
        .headers
        .iter()
        .map(|(name, value)| (name.to_lowercase(), value.to_string()))
        .collect();
    headers.insert("host".into(), request.host.into());
    headers.insert("x-amz-content-sha256".into(), payload_hash.clone());
    headers.insert("x-amz-date".into(), amz_date.clone());
    if let Some(token) = &request.credentials.session_token {
        headers.insert("x-amz-security-token".into(), token.clone());
    }
    let signed_names = headers.keys().cloned().collect::<Vec<_>>().join(";");
    let canonical_headers: String = headers
        .iter()
        .map(|(name, value)| format!("{name}:{}\n", value.trim()))
        .collect();
    let canonical_request = [
        request.method,
        request.canonical_uri,
        request.query,
        &canonical_headers,
        &signed_names,
        &payload_hash,
    ]
    .join("\n");
    let scope = format!("{date_stamp}/{}/s3/aws4_request", request.region);
    let string_to_sign = [
        "AWS4-HMAC-SHA256",
        &amz_date,
        &scope,
        &sha256_hex(canonical_request.as_bytes()),
    ]
    .join("\n");
    let key = hmac(
        &hmac(
            &hmac(
                &hmac(
                    format!("AWS4{}", request.credentials.secret_access_key).as_bytes(),
                    date_stamp,
                ),
                request.region,
            ),
            "s3",
        ),
        "aws4_request",
    );
    let signature = hex::encode(hmac(&key, &string_to_sign));
    headers.remove("host");
    headers.insert(
        "authorization".into(),
        format!("AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_names}, Signature={signature}", request.credentials.access_key_id),
    );
    headers
}

struct Answer {
    status: u16,
    version_id: Option<String>,
    etag: Option<String>,
    body: Vec<u8>,
}

pub struct S3Store {
    options: S3Options,
    origin: String,
    host: String,
    base_path: String,
    client: reqwest::blocking::Client,
}

impl S3Store {
    pub fn new(options: S3Options) -> Result<Self> {
        let endpoint = url::Url::parse(&options.endpoint)
            .map_err(|_| crate::invalid("Not a storage address"))?;
        let host = match endpoint.port() {
            Some(port) => format!("{}:{port}", endpoint.host_str().unwrap_or_default()),
            None => endpoint.host_str().unwrap_or_default().to_string(),
        };
        // ponytail: no idle timeout, only a connect timeout; a total timeout would cut off a slow 64 MiB pack.
        let client = reqwest::blocking::Client::builder()
            .timeout(None)
            .connect_timeout(Duration::from_secs(30))
            .build()
            .map_err(|error| crate::invalid(error.to_string()))?;
        Ok(S3Store {
            origin: endpoint.origin().ascii_serialization(),
            base_path: endpoint.path().trim_end_matches('/').to_string(),
            host,
            client,
            options,
        })
    }

    fn send_once(
        &self,
        renew: bool,
        method: &str,
        key: Option<&str>,
        query: &[(&str, &str)],
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Result<Answer> {
        let object_path = key.map_or(String::new(), |key| {
            format!(
                "/{}",
                format!("{}{key}", self.options.prefix)
                    .split('/')
                    .map(uri_encode)
                    .collect::<Vec<_>>()
                    .join("/")
            )
        });
        let canonical_uri = format!(
            "{}/{}{}",
            self.base_path,
            uri_encode(&self.options.bucket),
            if object_path.is_empty() {
                "/"
            } else {
                &object_path
            }
        );
        let mut pairs: Vec<(String, String)> = query
            .iter()
            .map(|(name, value)| (uri_encode(name), uri_encode(value)))
            .collect();
        pairs.sort();
        let query_string = pairs
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("&");
        let credentials = (self.options.credentials)(renew)?;
        let signed = sign_s3_request(&SignRequest {
            method,
            host: &self.host,
            canonical_uri: &canonical_uri,
            query: &query_string,
            headers,
            body,
            region: &self.options.region,
            credentials: &credentials,
            now: SystemTime::now(),
        });
        let what = format!("{method} {}", key.unwrap_or("the bucket"));
        let url = format!(
            "{}{canonical_uri}{}",
            self.origin,
            if query_string.is_empty() {
                String::new()
            } else {
                format!("?{query_string}")
            }
        );
        let mut request = self.client.request(method.parse().expect("a method"), url);
        for (name, value) in &signed {
            request = request.header(name, value);
        }
        if let Some(body) = body {
            let reader = Throttled {
                body: body.to_vec(),
                at: 0,
                started: Instant::now(),
                allowance: Duration::ZERO,
                limit: self.options.upload_limit.clone(),
            };
            request = request.body(reqwest::blocking::Body::sized(reader, body.len() as u64));
        }
        let unreachable = || Error::S3 {
            message: format!("The storage provider could not be reached ({what})"),
            status: None,
            code: None,
        };
        let response = request.send().map_err(|_| unreachable())?;
        let status = response.status().as_u16();
        let header = |name: &str| {
            response
                .headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string)
        };
        let version_id = header("x-amz-version-id").filter(|value| value != "null");
        let etag = header("etag");
        let body = response.bytes().map_err(|_| unreachable())?.to_vec();
        if !(200..300).contains(&status) {
            let code = tag(&String::from_utf8_lossy(&body), "Code");
            // Never a header and never a key: only the status and the provider's short code.
            let shown = code.as_deref().map(|code| {
                format!(
                    " {}",
                    code.chars()
                        .filter(|c| c.is_alphanumeric() || "_.-".contains(*c))
                        .collect::<String>()
                )
            });
            return Err(Error::S3 {
                message: format!(
                    "The storage provider refused {what}: {status}{}",
                    shown.unwrap_or_default()
                ),
                status: Some(status),
                code,
            });
        }
        Ok(Answer {
            status,
            version_id,
            etag,
            body,
        })
    }

    fn send(
        &self,
        method: &str,
        key: Option<&str>,
        query: &[(&str, &str)],
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Result<Answer> {
        let mut renewed = false;
        let mut attempt = 0;
        loop {
            match self.send_once(renewed, method, key, query, headers, body) {
                Ok(answer) => return Ok(answer),
                // Expired credentials are asked for again once; that doesn't count as a retry.
                Err(Error::S3 {
                    code: Some(code), ..
                }) if EXPIRED.contains(&code.as_str()) && !renewed => renewed = true,
                Err(Error::S3 {
                    status,
                    message,
                    code,
                }) => {
                    let transient = status.is_none_or(|status| status == 429 || status >= 500);
                    if !transient || attempt >= self.options.retry_delays.len() {
                        return Err(Error::S3 {
                            status,
                            message,
                            code,
                        });
                    }
                    sleep(self.options.retry_delays[attempt]);
                    attempt += 1;
                }
                Err(error) => return Err(error),
            }
        }
    }
}

/// A body sent in slices, held back to the speed limit. Owned, as `reqwest` wants a `'static` body.
struct Throttled {
    body: Vec<u8>,
    at: usize,
    started: Instant,
    allowance: Duration,
    limit: Option<UploadLimit>,
}

impl Read for Throttled {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let slice = (self.body.len() - self.at).min(SLICE).min(out.len());
        out[..slice].copy_from_slice(&self.body[self.at..self.at + slice]);
        self.at += slice;
        match self
            .limit
            .as_ref()
            .and_then(|limit| limit())
            .filter(|limit| *limit > 0)
        {
            // Each slice earns the time it should have taken; sleeping off the surplus holds the average.
            Some(limit) => {
                self.allowance += Duration::from_secs_f64(slice as f64 / limit as f64);
                if let Some(ahead) =
                    (self.started + self.allowance).checked_duration_since(Instant::now())
                {
                    sleep(ahead);
                }
            }
            None => self.allowance = self.started.elapsed(),
        }
        Ok(slice)
    }
}

impl Store for S3Store {
    fn put(&self, key: &str, body: &[u8]) -> Result<Option<String>> {
        if body.len() <= self.options.part_size {
            return Ok(self
                .send("PUT", Some(key), &[], &[], Some(body))?
                .version_id);
        }
        let started = self.send("POST", Some(key), &[("uploads", "")], &[], None)?;
        let upload_id =
            tag(&String::from_utf8_lossy(&started.body), "UploadId").ok_or_else(|| Error::S3 {
                message: "The storage provider did not start an upload".into(),
                status: None,
                code: None,
            })?;
        let finished = (|| -> Result<Option<String>> {
            let mut parts = Vec::new();
            for (index, part) in body.chunks(self.options.part_size).enumerate() {
                let number = (index + 1).to_string();
                let answer = self.send(
                    "PUT",
                    Some(key),
                    &[("partNumber", &number), ("uploadId", &upload_id)],
                    &[],
                    Some(part),
                )?;
                parts.push(answer.etag.ok_or_else(|| Error::S3 {
                    message: "The storage provider did not confirm an upload".into(),
                    status: Some(answer.status),
                    code: None,
                })?);
            }
            let list: String = parts
                .iter()
                .enumerate()
                .map(|(index, etag)| {
                    format!(
                        "<Part><PartNumber>{}</PartNumber><ETag>{etag}</ETag></Part>",
                        index + 1
                    )
                })
                .collect();
            let done = self.send(
                "POST",
                Some(key),
                &[("uploadId", &upload_id)],
                &[],
                Some(
                    format!("<CompleteMultipartUpload>{list}</CompleteMultipartUpload>").as_bytes(),
                ),
            )?;
            // S3 can answer 200 and still report a failure in the body.
            if let Some(code) = tag(&String::from_utf8_lossy(&done.body), "Code") {
                return Err(Error::S3 {
                    message: "The storage provider could not finish an upload".into(),
                    status: Some(done.status),
                    code: Some(code),
                });
            }
            Ok(done.version_id)
        })();
        if finished.is_err() {
            // Parts of an upload that never finishes are billed until removed.
            let _ = self.send("DELETE", Some(key), &[("uploadId", &upload_id)], &[], None);
        }
        finished
    }

    fn get(&self, key: &str, range: Option<ByteRange>) -> Result<Vec<u8>> {
        let header = match range {
            Some(ByteRange::Span { start, end }) if end <= start => return Ok(Vec::new()),
            Some(ByteRange::Span { start, end }) => Some(format!("bytes={start}-{}", end - 1)),
            Some(ByteRange::Suffix(suffix)) => Some(format!("bytes=-{suffix}")),
            None => None,
        };
        let headers: Vec<(&str, &str)> = header
            .iter()
            .map(|value| ("range", value.as_str()))
            .collect();
        Ok(self.send("GET", Some(key), &[], &headers, None)?.body)
    }

    fn list(&self, list_prefix: &str) -> Result<Vec<StoredObject>> {
        let prefix = &self.options.prefix;
        let full = format!("{prefix}{list_prefix}");
        let mut found = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let mut query = vec![("list-type", "2"), ("prefix", full.as_str())];
            if let Some(token) = &token {
                query.push(("continuation-token", token));
            }
            let xml = String::from_utf8_lossy(&self.send("GET", None, &query, &[], None)?.body)
                .into_owned();
            // Object names here are letters, digits, `-`, `_` and `/`, so nothing in them needs XML decoding.
            for item in xml.split("<Contents>").skip(1) {
                let item = item.split("</Contents>").next().unwrap_or_default();
                if let Some(key) = tag(item, "Key").filter(|key| key.starts_with(prefix.as_str())) {
                    let modified = tag(item, "LastModified")
                        .and_then(|time| {
                            time::OffsetDateTime::parse(
                                &time,
                                &time::format_description::well_known::Rfc3339,
                            )
                            .ok()
                        })
                        .map_or(SystemTime::UNIX_EPOCH, SystemTime::from);
                    found.push(StoredObject {
                        key: key[prefix.len()..].to_string(),
                        size: tag(item, "Size")
                            .and_then(|size| size.parse().ok())
                            .unwrap_or(0),
                        modified,
                    });
                }
            }
            token = if tag(&xml, "IsTruncated").as_deref() == Some("true") {
                tag(&xml, "NextContinuationToken")
            } else {
                None
            };
            if token.is_none() {
                return Ok(found);
            }
        }
    }

    fn delete(&self, key: &str) -> Result<()> {
        self.send("DELETE", Some(key), &[], &[], None)?;
        Ok(())
    }
}

//! FL-430: proof that the address the app dialled answers for the server the account lists, before
//! a server-audience token is sent there. The server signs `frameleaf-lan-identity-v1|<id>|<nonce>|
//! <iat>|<origin>` with its Ed25519 identity key; the keys come from the account's Frameleaf Cloud
//! instance list (a trusted path), never from the server itself.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;
use serde_json::Value;
use url::Url;

const JWS_TYPE: &str = "frameleaf-lan-identity+jwt";
const PAYLOAD_PREFIX: &str = "frameleaf-lan-identity-v1";
/// How far a proof's signing time may sit from this computer's clock.
const CLOCK_SKEW_SECS: i64 = 300;

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct PinnedKey {
    kid: String,
    jwk: Jwk,
}
#[derive(Clone, Debug, Deserialize)]
struct Jwk {
    kty: String,
    crv: String,
    x: String,
}

/// The keys the account's `GET /v1/instances` answer pins for `instance`; `None` when the account
/// doesn't list that server (then there is nothing trusted to check a proof against).
pub(crate) fn pinned_keys(instances: &Value, instance: &str) -> Option<Vec<PinnedKey>> {
    let items = match instances {
        Value::Array(items) => items,
        Value::Object(object) => object.get("instances")?.as_array()?,
        _ => return None,
    };
    let entry = items.iter().find(|item| {
        item.get("instanceId").and_then(Value::as_str) == Some(instance)
            || item.get("id").and_then(Value::as_str) == Some(instance)
    })?;
    let keys: Vec<PinnedKey> =
        serde_json::from_value(entry.get("identityKeys")?.clone()).unwrap_or_default();
    Some(keys)
}

/// The origin a proof must name: what the server sees in its Host header for `base`.
pub(crate) fn proof_origin(base: &Url) -> String {
    base.origin().ascii_serialization().to_ascii_lowercase()
}

fn verify_one(
    proof: &str,
    keys: &[PinnedKey],
    instance: &str,
    nonce: &str,
    origin: &str,
    now: i64,
) -> bool {
    let mut parts = proof.split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    #[derive(Deserialize)]
    struct Header {
        alg: String,
        typ: String,
        kid: String,
    }
    let Some(header_value) = URL_SAFE_NO_PAD
        .decode(header)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Header>(&bytes).ok())
    else {
        return false;
    };
    if header_value.alg != "EdDSA" || header_value.typ != JWS_TYPE {
        return false;
    }
    let Some(key) = keys.iter().find(|key| {
        key.kid == header_value.kid && key.jwk.kty == "OKP" && key.jwk.crv == "Ed25519"
    }) else {
        return false;
    };
    let Some(text) = URL_SAFE_NO_PAD
        .decode(payload)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
    else {
        return false;
    };
    let fields: Vec<&str> = text.splitn(5, '|').collect();
    let [prefix, id, signed_nonce, iat, signed_origin] = fields[..] else {
        return false;
    };
    let fresh = iat
        .parse::<i64>()
        .is_ok_and(|iat| (now - iat).abs() <= CLOCK_SKEW_SECS);
    if prefix != PAYLOAD_PREFIX
        || id != instance
        || signed_nonce != nonce
        || signed_origin != origin
        || !fresh
    {
        return false;
    }
    let (Ok(public), Ok(signature)) = (
        URL_SAFE_NO_PAD.decode(&key.jwk.x),
        URL_SAFE_NO_PAD.decode(signature),
    ) else {
        return false;
    };
    let (Ok(public), Ok(signature)) = (
        <[u8; 32]>::try_from(public.as_slice()),
        <[u8; 64]>::try_from(signature.as_slice()),
    ) else {
        return false;
    };
    VerifyingKey::from_bytes(&public).is_ok_and(|key| {
        key.verify(
            format!("{header}.{payload}").as_bytes(),
            &Signature::from_bytes(&signature),
        )
        .is_ok()
    })
}

/// Asks `base` to sign a fresh nonce and checks the answer against the pinned keys.
pub(crate) async fn verify(
    client: &reqwest::Client,
    base: &Url,
    instance: &str,
    keys: &[PinnedKey],
) -> Result<(), String> {
    if keys.is_empty() {
        return Err("server_identity_unverified".into());
    }
    let nonce = crate::cloud_account::random_token(32);
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Answer {
        proof: String,
        retiring_proof: Option<String>,
    }
    let response = client
        .post(
            base.join("api/server/identity/challenge")
                .map_err(|_| "server_address_invalid")?,
        )
        .json(&serde_json::json!({ "nonce": nonce }))
        .send()
        .await
        .map_err(|_| "server_unreachable_or_certificate_invalid")?;
    let answer: Answer = crate::transport::json(response)
        .await
        .map_err(|_| "server_identity_unverified")?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "clock_invalid")?
        .as_secs() as i64;
    let origin = proof_origin(base);
    let proven = std::iter::once(&answer.proof)
        .chain(answer.retiring_proof.as_ref())
        .any(|proof| verify_one(proof, keys, instance, &nonce, &origin, now));
    if proven {
        Ok(())
    } else {
        Err("server_identity_unverified".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const ID: &str = "018f5e7a-6b1e-7f6e-9c2e-1a2b3c4d5e6f";

    fn key() -> (SigningKey, PinnedKey) {
        let signing = SigningKey::from_bytes(&[7; 32]);
        let pinned = PinnedKey {
            kid: "k1".into(),
            jwk: Jwk {
                kty: "OKP".into(),
                crv: "Ed25519".into(),
                x: URL_SAFE_NO_PAD.encode(signing.verifying_key().as_bytes()),
            },
        };
        (signing, pinned)
    }
    fn proof(signing: &SigningKey, kid: &str, payload: &str) -> String {
        let header = URL_SAFE_NO_PAD.encode(format!(
            r#"{{"alg":"EdDSA","typ":"{JWS_TYPE}","kid":"{kid}"}}"#
        ));
        let body = URL_SAFE_NO_PAD.encode(payload);
        let input = format!("{header}.{body}");
        format!(
            "{input}.{}",
            URL_SAFE_NO_PAD.encode(signing.sign(input.as_bytes()).to_bytes())
        )
    }

    #[test]
    fn a_proof_holds_only_for_this_server_nonce_origin_and_time() {
        let (signing, pinned) = key();
        let keys = [pinned];
        let origin = "http://192.168.1.20:2283";
        let good = |id: &str, nonce: &str, at: i64, from: &str| {
            proof(
                &signing,
                "k1",
                &format!("{PAYLOAD_PREFIX}|{id}|{nonce}|{at}|{from}"),
            )
        };
        assert!(verify_one(
            &good(ID, "n0nce", 1000, origin),
            &keys,
            ID,
            "n0nce",
            origin,
            1000
        ));
        assert!(!verify_one(
            &good("other", "n0nce", 1000, origin),
            &keys,
            ID,
            "n0nce",
            origin,
            1000
        ));
        assert!(!verify_one(
            &good(ID, "replayed", 1000, origin),
            &keys,
            ID,
            "n0nce",
            origin,
            1000
        ));
        assert!(!verify_one(
            &good(ID, "n0nce", 1000, "http://evil.lan"),
            &keys,
            ID,
            "n0nce",
            origin,
            1000
        ));
        assert!(!verify_one(
            &good(ID, "n0nce", 1000, origin),
            &keys,
            ID,
            "n0nce",
            origin,
            2000
        ));
        let stranger = SigningKey::from_bytes(&[9; 32]);
        let forged = proof(
            &stranger,
            "k1",
            &format!("{PAYLOAD_PREFIX}|{ID}|n0nce|1000|{origin}"),
        );
        assert!(!verify_one(&forged, &keys, ID, "n0nce", origin, 1000));
        assert!(!verify_one(
            &good(ID, "n0nce", 1000, origin),
            &[],
            ID,
            "n0nce",
            origin,
            1000
        ));
    }

    #[test]
    fn keys_come_only_from_a_listed_instance() {
        let (_, pinned) = key();
        let list = serde_json::json!([{ "instanceId": ID, "identityKeys": [{ "kid": pinned.kid, "jwk": { "kty": "OKP", "crv": "Ed25519", "x": pinned.jwk.x } }] }]);
        assert_eq!(pinned_keys(&list, ID).unwrap().len(), 1);
        assert!(pinned_keys(&list, "not-listed").is_none());
        assert_eq!(
            proof_origin(&Url::parse("HTTP://Tower.LAN:2283/").unwrap()),
            "http://tower.lan:2283"
        );
    }
}

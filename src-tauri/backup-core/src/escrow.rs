//! Key escrow: a backup key wrapped under a passphrase and stored with Frameleaf Cloud as an opaque
//! blob. The wrapping key is scrypt (N = 2^17, r = 8, p = 1, a random 16-byte salt) of the NFKC
//! passphrase; the key is sealed with AES-256-GCM (random 12-byte nonce, tag appended to the ciphertext,
//! associated data `frameleaf-backup-key-escrow/1`). Cloud checks the shape only.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;

use crate::{invalid, Result};

pub const ESCROW_BLOB_VERSION: u32 = 1;
pub const ESCROW_MIN_PASSPHRASE: usize = 12;
const ESCROW_N: u64 = 131_072;
const ESCROW_AAD: &[u8] = b"frameleaf-backup-key-escrow/1";
const TAG: usize = 16;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Kdf {
    pub name: String,
    #[serde(rename = "N")]
    pub n: u64,
    pub r: u32,
    pub p: u32,
    pub salt: String,
}

/// The blob Frameleaf Cloud stores. Every binary field is base64.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct KeyEscrowBlob {
    pub version: u32,
    pub kdf: Kdf,
    pub cipher: String,
    pub nonce: String,
    pub ciphertext: String,
}

/// RFC 7914 scrypt of the NFKC form of `passphrase`.
pub fn scrypt_derive(
    passphrase: &str,
    salt: &[u8],
    n: u64,
    r: u32,
    p: u32,
    length: usize,
) -> Result<Vec<u8>> {
    if !n.is_power_of_two() || n < 2 {
        return Err(invalid("scrypt's N must be a power of two"));
    }
    // As Node's maxmem: a blob from elsewhere cannot ask for more memory than escrow itself uses twice over.
    if 128 * n * u64::from(r) > 256 << 20 {
        return Err(invalid("These scrypt parameters ask for too much memory"));
    }
    let params = scrypt::Params::new(n.trailing_zeros() as u8, r, p, length)
        .map_err(|_| invalid("These scrypt parameters cannot be used"))?;
    let mut out = vec![0u8; length];
    let normal: String = passphrase.nfkc().collect();
    scrypt::scrypt(normal.as_bytes(), salt, &params, &mut out)
        .map_err(|_| invalid("scrypt failed"))?;
    Ok(out)
}

/// Why a passphrase cannot be used for escrow, or None. Length counts UTF-16 code units, as the TypeScript engine does.
pub fn escrow_passphrase_problem(passphrase: &str) -> Option<String> {
    let normal: String = passphrase.nfkc().collect();
    (normal.encode_utf16().count() < ESCROW_MIN_PASSPHRASE)
        .then(|| format!("Use a passphrase of at least {ESCROW_MIN_PASSPHRASE} characters."))
}

/// Wrap a backup key under a passphrase. `salt_and_nonce` is only given by tests.
pub fn wrap_bucket_key(
    key: &[u8],
    passphrase: &str,
    salt_and_nonce: Option<([u8; 16], [u8; 12])>,
) -> Result<KeyEscrowBlob> {
    if key.len() != 32 {
        return Err(invalid("A bucket key is 256 bits"));
    }
    if let Some(problem) = escrow_passphrase_problem(passphrase) {
        return Err(invalid(problem));
    }
    let (salt, nonce) = salt_and_nonce.unwrap_or_else(|| {
        let (mut salt, mut nonce) = ([0u8; 16], [0u8; 12]);
        rand::thread_rng().fill_bytes(&mut salt);
        rand::thread_rng().fill_bytes(&mut nonce);
        (salt, nonce)
    });
    let wrapping = scrypt_derive(passphrase, &salt, ESCROW_N, 8, 1, 32)?;
    let ciphertext = Aes256Gcm::new_from_slice(&wrapping)
        .expect("32 bytes")
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: key,
                aad: ESCROW_AAD,
            },
        )
        .map_err(|_| invalid("Could not wrap the key"))?;
    Ok(KeyEscrowBlob {
        version: ESCROW_BLOB_VERSION,
        kdf: Kdf {
            name: "scrypt".into(),
            n: ESCROW_N,
            r: 8,
            p: 1,
            salt: STANDARD.encode(salt),
        },
        cipher: "aes-256-gcm".into(),
        nonce: STANDARD.encode(nonce),
        ciphertext: STANDARD.encode(ciphertext),
    })
}

/// The backup key back from a blob and its passphrase; a wrong passphrase or an altered blob is refused.
pub fn unwrap_bucket_key(blob: &KeyEscrowBlob, passphrase: &str) -> Result<[u8; 32]> {
    let damaged = || invalid("This key copy is damaged.");
    let sealed = STANDARD.decode(&blob.ciphertext).map_err(|_| damaged())?;
    let nonce = STANDARD.decode(&blob.nonce).map_err(|_| damaged())?;
    let salt = STANDARD.decode(&blob.kdf.salt).map_err(|_| damaged())?;
    if sealed.len() <= TAG || nonce.len() != 12 {
        return Err(damaged());
    }
    let wrapping = scrypt_derive(passphrase, &salt, blob.kdf.n, blob.kdf.r, blob.kdf.p, 32)?;
    let opened = Aes256Gcm::new_from_slice(&wrapping)
        .expect("32 bytes")
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &sealed,
                aad: ESCROW_AAD,
            },
        )
        .map_err(|_| invalid("This passphrase does not open the key copy."))?;
    opened
        .try_into()
        .map_err(|_| invalid("This key copy does not hold a bucket key."))
}

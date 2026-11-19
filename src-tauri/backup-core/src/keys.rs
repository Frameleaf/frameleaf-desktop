use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;

use crate::{invalid, Error, Id, Result};

pub const FORMAT: &str = "frameleaf-repository";
pub const VERSION: u32 = 1;

const NONCE: usize = 12;
const TAG: usize = 16;

pub struct RepositoryKeys {
    /// HMAC key that names blobs, so names say nothing about content without the key.
    pub id: [u8; 32],
    /// Base key for blob encryption; each blob gets its own key from it.
    pub blob: [u8; 32],
    /// Seeds the chunker's table, so chunk boundaries depend on the key.
    pub cut: [u8; 32],
    /// Encrypts pack trailers, index objects and snapshots.
    pub meta: [u8; 32],
}

/// HKDF-SHA256 with `frameleaf-repository/1 <info>` as info.
pub fn derive(key: &[u8], salt: &[u8], info: &str, length: usize) -> Vec<u8> {
    let mut out = vec![0u8; length];
    Hkdf::<Sha256>::new(Some(salt), key)
        .expand(format!("{FORMAT}/{VERSION} {info}").as_bytes(), &mut out)
        .expect("HKDF output length is within bounds");
    out
}

fn derive32(key: &[u8], salt: &[u8], info: &str) -> [u8; 32] {
    derive(key, salt, info, 32).try_into().expect("32 bytes")
}

pub fn derive_keys(master: &[u8], repo_id: &str) -> Result<RepositoryKeys> {
    if master.len() != 32 {
        return Err(invalid("The repository key must be 32 bytes"));
    }
    let salt = repo_id.as_bytes();
    Ok(RepositoryKeys {
        id: derive32(master, salt, "id"),
        blob: derive32(master, salt, "blob"),
        cut: derive32(master, salt, "cut"),
        meta: derive32(master, salt, "meta"),
    })
}

pub fn blob_id(keys: &RepositoryKeys, plain: &[u8]) -> Id {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&keys.id).expect("any key length");
    mac.update(plain);
    mac.finalize().into_bytes().into()
}

fn cipher(key: &[u8]) -> Result<Aes256Gcm> {
    Aes256Gcm::new_from_slice(key).map_err(|_| invalid("A key must be 32 bytes"))
}

/// `nonce(12) | ciphertext | tag(16)`, random nonce.
pub fn seal(key: &[u8], aad: &[u8], plain: &[u8]) -> Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE];
    rand::thread_rng().fill_bytes(&mut nonce);
    seal_with_nonce(key, &nonce, aad, plain)
}

pub(crate) fn seal_with_nonce(
    key: &[u8],
    nonce: &[u8; NONCE],
    aad: &[u8],
    plain: &[u8],
) -> Result<Vec<u8>> {
    let sealed = cipher(key)?
        .encrypt(Nonce::from_slice(nonce), Payload { msg: plain, aad })
        .map_err(|_| Error::Unseal)?;
    Ok([nonce.as_slice(), &sealed].concat())
}

pub fn unseal(key: &[u8], aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() < NONCE + TAG {
        return Err(Error::Unseal);
    }
    cipher(key)?
        .decrypt(
            Nonce::from_slice(&sealed[..NONCE]),
            Payload {
                msg: &sealed[NONCE..],
                aad,
            },
        )
        .map_err(|_| Error::Unseal)
}

fn blob_key(keys: &RepositoryKeys, id: &Id) -> [u8; 32] {
    derive32(&keys.blob, id, "blob")
}

/// `flag(1) | sealed`. The flag says whether the plaintext was compressed, and is authenticated with the id.
pub fn seal_blob(keys: &RepositoryKeys, id: &Id, plain: &[u8]) -> Result<Vec<u8>> {
    // Photos and video don't shrink: keep them as they are unless compression saves at least 1/16.
    // Level 3 is what Node's zstdCompressSync uses by default.
    let packed = if plain.len() >= 64 {
        Some(zstd::bulk::compress(plain, 3)?)
    } else {
        None
    };
    let packed = packed.filter(|packed| packed.len() <= plain.len() - (plain.len() >> 4));
    let flag = u8::from(packed.is_some());
    let aad = [id.as_slice(), &[flag]].concat();
    let sealed = seal(
        &blob_key(keys, id),
        &aad,
        packed.as_deref().unwrap_or(plain),
    )?;
    Ok([&[flag][..], &sealed].concat())
}

pub fn open_blob(keys: &RepositoryKeys, id: &Id, blob: &[u8]) -> Result<Vec<u8>> {
    let flag = *blob.first().ok_or(Error::Unseal)?;
    if flag > 1 {
        return Err(Error::Unseal);
    }
    let aad = [id.as_slice(), &[flag]].concat();
    let plain = unseal(&blob_key(keys, id), &aad, &blob[1..])?;
    if flag == 1 {
        // Bytes that passed their seal are the bytes a writer made; failing to unpack them is not damage in storage.
        Ok(zstd::stream::decode_all(plain.as_slice())?)
    } else {
        Ok(plain)
    }
}

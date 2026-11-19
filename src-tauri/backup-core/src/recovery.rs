use hkdf::Hkdf;
use sha2::Sha256;

// Crockford base32: no I, L, O or U, so a written-down code is hard to misread.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const PREFIX: &str = "FLRK";

/// A 256-bit key as the code a recovery kit prints: `FLRK-XXXX-…` (52 symbols in 13 groups).
pub fn recovery_code(key: &[u8]) -> String {
    let (mut bits, mut value, mut symbols) = (0u32, 0u32, Vec::new());
    for &byte in key {
        value = (value << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            symbols.push(ALPHABET[((value >> (bits - 5)) & 31) as usize]);
            bits -= 5;
        }
        value &= (1 << bits) - 1;
    }
    if bits > 0 {
        symbols.push(ALPHABET[((value << (5 - bits)) & 31) as usize]);
    }
    let mut code = PREFIX.to_string();
    for group in symbols.chunks(4) {
        code.push('-');
        code.push_str(std::str::from_utf8(group).expect("ASCII"));
    }
    code
}

/// The key a recovery code stands for, or None when the code is not complete. Spaces, dashes and case
/// are ignored, and the letters people misread are taken for the digits they look like (O for 0, I and L for 1).
pub fn parse_recovery_code(code: &str) -> Option<[u8; 32]> {
    let upper: String = code
        .to_uppercase()
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect();
    let symbols = upper.strip_prefix(PREFIX).unwrap_or(&upper);
    let (mut bits, mut value, mut bytes) = (0u32, 0u32, Vec::new());
    for symbol in symbols.chars() {
        let symbol = match symbol {
            'O' => '0',
            'I' | 'L' => '1',
            other => other,
        };
        let index = ALPHABET
            .iter()
            .position(|&letter| char::from(letter) == symbol)? as u32;
        value = ((value << 5) | index) & 0xffff;
        bits += 5;
        if bits >= 8 {
            bytes.push(((value >> (bits - 8)) & 0xff) as u8);
            bits -= 8;
        }
    }
    bytes.try_into().ok()
}

/// Manager's Server Backup vault id: HKDF-SHA256 over the recovery key, empty salt, info
/// `frameleaf-server-backup vault`, 16 bytes shaped as a version 8 UUID. The key alone finds its backups.
pub fn server_backup_vault_id(key: &[u8]) -> String {
    let mut bytes = [0u8; 16];
    Hkdf::<Sha256>::new(Some(&[]), key)
        .expand(b"frameleaf-server-backup vault", &mut bytes)
        .expect("16 bytes");
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = hex::encode(bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

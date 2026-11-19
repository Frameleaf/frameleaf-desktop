use std::io::{self, Read};

use serde::{Deserialize, Serialize};

use crate::keys::derive;
use crate::{invalid, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkerParams {
    pub min: usize,
    /// A power of two.
    pub avg: usize,
    pub max: usize,
}

pub const DEFAULT_CHUNKER: ChunkerParams = ChunkerParams {
    min: 512 * 1024,
    avg: 2 * 1024 * 1024,
    max: 8 * 1024 * 1024,
};

pub fn check_chunker(params: &ChunkerParams) -> Result<()> {
    let ChunkerParams { min, avg, max } = *params;
    let bits = avg.trailing_zeros();
    let fine = avg.is_power_of_two()
        && (8..=26).contains(&bits)
        && min >= 64
        && min < avg
        && avg < max
        && max <= 64 << 20;
    if !fine {
        return Err(invalid(
            "Chunk sizes must satisfy 64 <= min < avg < max <= 64 MiB, with avg a power of two",
        ));
    }
    Ok(())
}

/// 256 values from the repository's cut key: without the key, nobody can predict where files are cut.
pub fn gear_table(cut_key: &[u8]) -> [u32; 256] {
    let bytes = derive(cut_key, &[], "gear", 1024);
    std::array::from_fn(|index| {
        u32::from_le_bytes(bytes[index * 4..index * 4 + 4].try_into().unwrap())
    })
}

const fn top_bits(count: u32) -> u32 {
    u32::MAX << (32 - count)
}

/// FastCDC with normalised chunking: a stricter test before the average size and a looser one after it,
/// which keeps sizes close to the average. Returns how many bytes of `data` form the next chunk, or None
/// when more data is needed to decide.
pub fn cut_point(
    data: &[u8],
    last: bool,
    params: &ChunkerParams,
    gear: &[u32; 256],
) -> Option<usize> {
    let ChunkerParams { min, avg, max } = *params;
    if data.len() <= min {
        return last.then_some(data.len());
    }
    let bits = avg.trailing_zeros();
    let (strict, loose) = (top_bits(bits + 2), top_bits(bits - 2));
    let end = data.len().min(max);
    let mut hash = 0u32;
    for (index, &byte) in data.iter().enumerate().take(end).skip(min) {
        hash = (hash << 1).wrapping_add(gear[byte as usize]);
        if hash & (if index < avg { strict } else { loose }) == 0 {
            return Some(index + 1);
        }
    }
    (end == max || last).then_some(end)
}

/// Cuts a stream into chunks. The same bytes under the same key always give the same chunks, however
/// the reader hands them over. A read error is the source's, and ends the iteration.
pub fn chunks<'a, R: Read + 'a>(
    reader: R,
    params: ChunkerParams,
    gear: &'a [u32; 256],
) -> impl Iterator<Item = io::Result<Vec<u8>>> + 'a {
    let mut reader = reader;
    let mut held: Vec<u8> = Vec::new();
    let mut ended = false;
    std::iter::from_fn(move || loop {
        // Deciding a cut never needs more than `max` bytes, so wait until that much is in hand.
        while !ended && held.len() < params.max {
            let start = held.len();
            held.resize(params.max, 0);
            match reader.read(&mut held[start..]) {
                Ok(0) => {
                    held.truncate(start);
                    ended = true;
                }
                Ok(read) => held.truncate(start + read),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => held.truncate(start),
                Err(error) => {
                    held.clear();
                    ended = true;
                    return Some(Err(error));
                }
            }
        }
        if held.is_empty() {
            return None;
        }
        if let Some(cut) = cut_point(&held, ended, &params, gear) {
            let rest = held.split_off(cut);
            return Some(Ok(std::mem::replace(&mut held, rest)));
        }
    })
}

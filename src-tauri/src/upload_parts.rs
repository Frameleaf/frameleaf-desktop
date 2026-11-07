//! FL-1268 part planning for parallel uploads: sizes, parallelism, halving and resume gaps.
use std::{collections::VecDeque, time::Duration};

const MIB: u64 = 1024 * 1024;
pub(crate) const UNMETERED_PART: u64 = 256 * MIB;
pub(crate) const METERED_PART: u64 = 16 * MIB;
pub(crate) const MIN_PART: u64 = 8 * MIB;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Network {
    /// Wi-Fi or Ethernet. Desktop has no cheap metered-connection signal, so this is its default.
    Unmetered,
    /// Cellular, metered or unknown.
    #[allow(dead_code)]
    Metered,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PartPolicy {
    pub part_size: u64,
    pub parallel: usize,
}
impl PartPolicy {
    pub fn new(network: Network, max_append: u64, max_parallel: usize) -> Self {
        let (part, parallel) = match network {
            Network::Unmetered => (UNMETERED_PART, 4),
            Network::Metered => (METERED_PART, 2),
        };
        Self {
            part_size: part.min(max_append).max(1),
            parallel: parallel.min(max_parallel).max(1),
        }
    }
    /// A resource can carry a smaller append limit than the server's current OPTIONS answer.
    pub fn cap(&mut self, max_append: u64) {
        self.part_size = self.part_size.min(max_append).max(1);
    }
    /// After a timeout or a part that died mid-body, parts not yet sent get half the size (floor 8 MiB).
    pub fn halve(&mut self) {
        self.part_size = (self.part_size / 2).max(MIN_PART.min(self.part_size));
    }
}

/// Byte ranges `[start, end)` the server has not received: after the contiguous prefix, between parts.
pub(crate) fn gaps(
    size: u64,
    offset: u64,
    parts: &[(u64, u64)],
) -> Result<VecDeque<(u64, u64)>, String> {
    let invalid = || String::from("source_upload_response_invalid");
    if offset > size {
        return Err(invalid());
    }
    let mut parts: Vec<_> = parts
        .iter()
        .map(|&(start, len)| {
            start
                .checked_add(len)
                .filter(|end| len > 0 && *end <= size)
                .map(|end| (start, end))
                .ok_or_else(invalid)
        })
        .collect::<Result<_, _>>()?;
    parts.sort_unstable();
    let mut gaps = VecDeque::new();
    let mut at = offset;
    for (start, end) in parts {
        if start > at {
            gaps.push_back((at, start));
        }
        at = at.max(end);
    }
    if at < size {
        gaps.push_back((at, size));
    }
    Ok(gaps)
}

/// Exponential backoff for retried parts, capped at 30 s.
pub(crate) fn backoff(failures: u32) -> Duration {
    Duration::from_secs(1u64 << failures.saturating_sub(1).min(5)).min(Duration::from_secs(30))
}

/// A part gets at least a minute plus a second per MiB before the client gives up on it.
pub(crate) fn part_timeout(len: u64) -> Duration {
    Duration::from_secs(60 + len / MIB)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_picks_size_and_parallelism_within_server_limits() {
        let gib = 1024 * MIB;
        assert_eq!(
            PartPolicy::new(Network::Unmetered, gib, 6),
            PartPolicy {
                part_size: 256 * MIB,
                parallel: 4
            }
        );
        assert_eq!(
            PartPolicy::new(Network::Metered, gib, 6),
            PartPolicy {
                part_size: 16 * MIB,
                parallel: 2
            }
        );
        assert_eq!(
            PartPolicy::new(Network::Unmetered, 64 * MIB, 3),
            PartPolicy {
                part_size: 64 * MIB,
                parallel: 3
            }
        );
        assert_eq!(
            PartPolicy::new(Network::Unmetered, 4, 0),
            PartPolicy {
                part_size: 4,
                parallel: 1
            }
        );
        let mut policy = PartPolicy::new(Network::Unmetered, gib, 6);
        policy.cap(32 * MIB);
        assert_eq!(policy.part_size, 32 * MIB);
    }

    #[test]
    fn halving_stops_at_eight_mebibytes_or_the_server_limit() {
        let mut policy = PartPolicy::new(Network::Unmetered, 1024 * MIB, 6);
        let sizes: Vec<_> = (0..7)
            .map(|_| {
                policy.halve();
                policy.part_size / MIB
            })
            .collect();
        assert_eq!(sizes, [128, 64, 32, 16, 8, 8, 8]);
        let mut small = PartPolicy::new(Network::Metered, 4, 6);
        small.halve();
        assert_eq!(small.part_size, 4);
    }

    #[test]
    fn resume_sends_only_the_gaps_in_a_parts_listing() {
        assert_eq!(gaps(10, 0, &[]).unwrap(), [(0, 10)]);
        assert_eq!(gaps(10, 10, &[]).unwrap(), []);
        assert_eq!(
            gaps(100, 20, &[(60, 20), (30, 10)]).unwrap(),
            [(20, 30), (40, 60), (80, 100)]
        );
        // Parts at or inside the contiguous prefix leave nothing behind it.
        assert_eq!(gaps(100, 40, &[(0, 40), (40, 60)]).unwrap(), []);
        assert!(gaps(10, 11, &[]).is_err());
        assert!(gaps(10, 0, &[(5, 6)]).is_err());
        assert!(gaps(10, 0, &[(5, 0)]).is_err());
        assert!(gaps(10, 0, &[(u64::MAX, 2)]).is_err());
    }

    #[test]
    fn backoff_and_timeouts_grow_with_failures_and_size() {
        assert_eq!(backoff(1), Duration::from_secs(1));
        assert_eq!(backoff(3), Duration::from_secs(4));
        assert_eq!(backoff(50), Duration::from_secs(30));
        assert_eq!(part_timeout(256 * MIB), Duration::from_secs(316));
    }
}

//! Admission for original payload bytes, including uncertain or repeated sends.
pub(crate) fn reserve(used: u64, bytes: u64, limit: u64) -> Result<u64, String> {
    used.checked_add(bytes)
        .filter(|next| *next <= limit)
        .ok_or_else(|| "source_upload_budget_exhausted".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn repeated_attempts_consume_the_allowance_and_overflow_is_refused() {
        let used = reserve(0, 4, 10).unwrap();
        assert_eq!(used, 4);
        let used = reserve(used, 4, 10).unwrap();
        assert_eq!(used, 8);
        assert_eq!(
            reserve(used, 3, 10).unwrap_err(),
            "source_upload_budget_exhausted"
        );
        assert_eq!(reserve(used, 2, 10).unwrap(), 10);
        assert_eq!(reserve(10, 0, 10).unwrap(), 10);
        assert!(reserve(u64::MAX, 1, u64::MAX).is_err());
        assert!(reserve(11, 0, 10).is_err());
    }
}

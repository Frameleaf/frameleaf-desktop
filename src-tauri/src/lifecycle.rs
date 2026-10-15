use serde::Serialize;
use std::future::Future;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignOutResult {
    pub local_cleared: bool,
    pub photos_cleared: bool,
    pub remote_revoked: bool,
}

/// Independent revocation/cleanup attempts must all run, including after a local OS failure.
pub async fn finish_sign_out(
    local: impl Future<Output = bool>,
    photos: impl Future<Output = bool>,
    remote: impl Future<Output = bool>,
) -> SignOutResult {
    let local_cleared = local.await;
    let photos_cleared = photos.await;
    let remote_revoked = remote.await;
    SignOutResult {
        local_cleared,
        photos_cleared,
        remote_revoked,
    }
}

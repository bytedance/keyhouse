use super::*;
use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Serialize)]
pub struct HealthResponse {
    pub online: bool,
    pub etcd_online: bool,
    pub etcd_last_contact_ms: u64,
}

pub static ETCD_LAST_CONTACT: AtomicU64 = AtomicU64::new(0);

pub(super) async fn health<T: KeyhouseImpl + 'static>(
    _req: HttpRequest,
) -> StdResult<Json<HealthResponse>, Error> {
    let etcd_last_contact = ETCD_LAST_CONTACT.load(Ordering::Relaxed);
    let etcd_last_contact_delta = crate::util::epoch() - etcd_last_contact;
    let cache_purge_time = crate::SERVER_CONFIG.get().0.etcd_max_refresh_rate_ms;
    Ok(Json(HealthResponse {
        online: true,
        etcd_online: etcd_last_contact_delta <= cache_purge_time * 2,
        etcd_last_contact_ms: etcd_last_contact_delta,
    }))
}

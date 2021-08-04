mod mock;
use crate::prelude::*;
pub use mock::MockAuth;
use std::sync::Arc;

pub struct KeychainMetadata {
    pub owners: Vec<String>,
    pub level: String,
}

pub enum AuthorizationResult {
    Ok,
    Unauthorized,
    UnauthorizedLink(String),
}

#[tonic::async_trait]
pub trait ControlPlaneAuth: Send + Sync + 'static {
    fn new() -> Result<Box<Self>>;

    fn authenticate_user(&self, token: &str) -> Result<Option<String>>; // Some(username), None => unauthenticated

    async fn check_authorization(
        &self,
        username: &str,
        keyring_alias: &str,
    ) -> Result<AuthorizationResult>;

    fn get_keyring_share_url(&self, username: &str, keyring_alias: &str) -> Option<String>;

    async fn authorize_users(&self, alias: String, usernames: Vec<String>) -> Result<()>;

    /// returns aliases of authorized keychains
    async fn get_authorized_keychains(&self, username: &str) -> Result<Vec<String>>;

    async fn create_keychain(&self, alias: String, owner: &str, level: &str) -> Result<()>;

    async fn keychain_metadata(&self, alias: String) -> Result<KeychainMetadata>;
}

#[allow(type_alias_bounds)]
pub type OwnedAuth<T: KeyhouseImpl + 'static> = Arc<T::ControlPlaneAuth>;

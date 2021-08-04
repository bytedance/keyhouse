use super::*;
use tokio::sync::RwLock;

pub struct MockAuth {
    keychain_aliases: RwLock<Vec<String>>,
}

impl MockAuth {
    pub fn new(keychain_aliases: Vec<String>) -> MockAuth {
        MockAuth {
            keychain_aliases: RwLock::new(keychain_aliases),
        }
    }
}

#[tonic::async_trait]
impl ControlPlaneAuth for MockAuth {
    fn new() -> Result<Box<Self>> {
        Ok(Box::new(MockAuth::new(vec![])))
    }

    fn authenticate_user(&self, _token: &str) -> Result<Option<String>> {
        Ok(Some("test-user".to_string()))
    }

    async fn check_authorization(
        &self,
        _username: &str,
        keyring_alias: &str,
    ) -> Result<AuthorizationResult> {
        if self
            .keychain_aliases
            .read()
            .await
            .iter()
            .any(|x| x == keyring_alias)
        {
            Ok(AuthorizationResult::Ok)
        } else {
            Ok(AuthorizationResult::Unauthorized)
        }
    }

    fn get_keyring_share_url(&self, _username: &str, _keyring_alias: &str) -> Option<String> {
        Some("mock_auth".to_string())
    }

    async fn get_authorized_keychains(&self, _username: &str) -> Result<Vec<String>> {
        Ok(self.keychain_aliases.read().await.clone())
    }

    async fn authorize_users(&self, _alias: String, _usernames: Vec<String>) -> Result<()> {
        Ok(())
    }

    async fn create_keychain(&self, alias: String, _owner: &str, _level: &str) -> Result<()> {
        self.keychain_aliases.write().await.push(alias);
        Ok(())
    }

    async fn keychain_metadata(&self, _alias: String) -> Result<KeychainMetadata> {
        Ok(KeychainMetadata {
            owners: vec!["test".to_string()],
            level: "L3".to_string(),
        })
    }
}

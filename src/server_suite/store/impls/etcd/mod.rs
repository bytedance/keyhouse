use super::*;
use crate::prelude::*;
use etcd_rs::{
    Client, ClientConfig, DeleteRequest, Event, EventType, KeyRange, PutRequest, RangeRequest,
    TxnCmp, TxnRequest,
};
use std::marker::PhantomData;
use tonic::transport::ClientTlsConfig;
use url::Url;

mod client;
mod store;
mod watch;

#[allow(unused_imports)]
use store::etcd_wrap;

#[derive(Clone)]
pub struct EtcdStore<T: KeyhouseImpl + 'static> {
    client: Client,
    prefix: String,
    endpoints: Vec<Url>,
    tls_auth: rustls::ClientConfig,
    auth: Option<(String, String)>,
    _phantom: PhantomData<T>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{sleep, Duration};

    async fn etcd_store(prefix: &str) -> EtcdStore<()> {
        crate::server_suite::server::init_spire_workload()
            .await
            .unwrap();
        assert!(prefix.ends_with("/"));
        let config = crate::server_suite::config::SERVER_CONFIG.get();
        let etcd_address = &config.0.etcd_addresses[0];

        let store = EtcdStore::<()>::new(
            prefix.to_string(),
            vec![etcd_address.clone()],
            config.1.etcd_client_tls_config(),
            None,
        )
        .await
        .unwrap();
        store.clear_store().await.unwrap();
        store
    }

    #[tokio::test]
    async fn etcd_roundtrip() -> Result<()> {
        let store = etcd_store("etcd_roundtrip/").await;
        let key = CustomerKey::new_base::<()>("test/test".to_string()).unwrap();
        let id = key.id;
        assert_eq!(store.get_customer_key_by_id(id).await?, None);
        store.store_customer_key(key.clone()).await?;
        assert_eq!(store.get_customer_key_by_id(id).await?, Some(key.clone()));
        assert_eq!(
            store.get_customer_key_by_alias(&key.alias).await?,
            Some(key.clone())
        );

        let keys = store.get_all_customer_keys().await?;
        assert_eq!(keys.len(), 1);
        assert_eq!(keys.get(&key.id), Some(&key));
        let aliases = store.get_all_customer_key_aliases().await?;
        assert_eq!(aliases.len(), 1);
        assert_eq!(aliases.get("test").unwrap().len(), 1);
        assert_eq!(
            aliases.get("test").map(|x| x.get("test")).flatten(),
            Some(&key.id)
        );

        Ok(())
    }

    #[tokio::test]
    async fn etcd_update_status() -> Result<()> {
        let store = etcd_store("etcd_update_status/").await;
        let mut key = CustomerKey::new_base::<()>("test/test".to_string()).unwrap();
        let id = key.id;
        store.store_customer_key(key.clone()).await?;
        store
            .mutate_customer_key(
                id,
                CustomerKeyMutation {
                    status: Some(KeyStatus::Disabled),
                    description: Some("test2".to_string()),
                    ..Default::default()
                },
            )
            .await?;
        key.description = "test2".to_string();
        assert_eq!(store.get_customer_key_by_id(id).await?, Some(key.clone()));

        Ok(())
    }

    #[tokio::test]
    async fn etcd_static_alias() -> Result<()> {
        let store = etcd_store("etcd_static_alias/").await;
        let key = CustomerKey::new_base::<()>("test/test".to_string()).unwrap();
        let key2 = CustomerKey::new_base::<()>("test/test".to_string()).unwrap();
        store.store_customer_key(key.clone()).await?;
        store
            .store_customer_key(key2.clone())
            .await
            .expect_err("did not fail");
        Ok(())
    }

    #[tokio::test]
    async fn etcd_watcher() -> Result<()> {
        let store = etcd_store("etcd_watcher/").await;
        let (sender, mut receiver) = mpsc::channel::<StoreUpdate>(1024);
        store.hook_updates(sender).await?;
        // make sure etcd is listening for events
        sleep(Duration::from_millis(1000)).await;

        let key = CustomerKey::new_base::<()>("test/test".to_string()).unwrap();
        let id = key.id;
        store.store_customer_key(key.clone()).await?;
        assert_eq!(
            receiver.recv().await.unwrap().data,
            StoreUpdateData::CacheInvalidate(key.clone())
        );

        store
            .mutate_customer_key(
                id,
                CustomerKeyMutation {
                    status: Some(KeyStatus::Disabled),
                    ..Default::default()
                },
            )
            .await?;
        let mut new_key = key.clone();
        new_key.status = KeyStatus::Enabled;
        assert_eq!(
            store.get_customer_key_by_id(id).await?,
            Some(new_key.clone())
        );

        assert_eq!(
            receiver.recv().await.unwrap().data,
            StoreUpdateData::CacheInvalidate(new_key.clone())
        );
        let keyring = Keyring::new_base("test".to_string());
        store.store_keyring(keyring.clone()).await?;

        assert_eq!(
            receiver.recv().await.unwrap().data,
            StoreUpdateData::CacheInvalidateKeyring(keyring.clone())
        );

        Ok(())
    }

    #[tokio::test]
    async fn etcd_keyring_roundtrip() -> Result<()> {
        let store = etcd_store("etcd_keyring_roundtrip/").await;
        let key1 = CustomerKey::new_base::<()>("test/test1".to_string()).unwrap();
        store.store_customer_key(key1.clone()).await.unwrap();
        let keyring = Keyring::new_base("test".to_string());
        assert_eq!(store.get_keyring(&keyring.alias).await.unwrap(), None);
        store.store_keyring(keyring.clone()).await.unwrap();
        assert_eq!(
            store.get_keyring(&keyring.alias).await.unwrap(),
            Some(keyring.clone())
        );

        assert_eq!(
            store.get_keyring_keys(&keyring.alias).await.unwrap(),
            vec![key1.clone()]
        );
        let key2 = CustomerKey::new_base::<()>("test/test2".to_string()).unwrap();
        store.store_customer_key(key2.clone()).await.unwrap();
        let keyring = store.get_keyring(&keyring.alias).await.unwrap().unwrap();
        assert_eq!(
            store.get_keyring_keys(&keyring.alias).await.unwrap(),
            vec![key1.clone(), key2.clone()]
        );
        assert_eq!(
            store
                .get_all_keyrings()
                .await
                .unwrap()
                .values()
                .collect::<Vec<&Keyring>>(),
            vec![&keyring]
        );

        Ok(())
    }

    #[tokio::test]
    async fn etcd_intermediate_key_roundtrip() {
        use crate::server_suite::store::intermediate_key;
        let store = Arc::new(etcd_store("etcd_intermediate_key_roundtrip/").await);
        assert_eq!(store.get_intermediate_key().await.unwrap(), None);
        let new_key = intermediate_key::IntermediateKey::reset(store.clone())
            .await
            .unwrap();
        assert_eq!(
            store.get_intermediate_key().await.unwrap().unwrap(),
            new_key
        );
    }

    #[tokio::test]
    async fn etcd_secret_roundtrip() {
        let store = etcd_store("etcd_secret_roundtrip/").await;
        let keyring = Keyring::new_base("test_ring".to_string());
        store.store_keyring(keyring.clone()).await.unwrap();
        let key = CustomerKey::new_base::<()>("test_ring/test_key".to_string()).unwrap();
        store.store_customer_key(key.clone()).await.unwrap();

        assert_eq!(store.get_all_secrets().await.unwrap(), HashMap::new());
        assert_eq!(
            store.get_key_secrets("test_ring/test_key").await.unwrap(),
            vec![]
        );
        assert_eq!(
            store
                .get_secret("test_ring/test_key/test_secret")
                .await
                .unwrap(),
            None
        );

        let secret = Secret::new_base("test_ring/test_key/test_secret".to_string());
        store.store_secret(None, secret.clone()).await.unwrap();

        assert_eq!(
            store
                .get_all_secrets()
                .await
                .unwrap()
                .get("test_ring/test_key")
                .unwrap()
                .get("test_secret")
                .unwrap(),
            &secret
        );
        assert_eq!(
            store.get_key_secrets("test_ring/test_key").await.unwrap(),
            vec![secret.clone()]
        );
        assert_eq!(
            store
                .get_secret("test_ring/test_key/test_secret")
                .await
                .unwrap(),
            Some(secret.clone())
        );
        store
            .store_secret(None, secret.clone())
            .await
            .expect_err("failed to prevent invalid transaction");

        let new_secret = Secret::new_base("test_ring/test_key/test_secret".to_string());
        store
            .store_secret(Some(new_secret.clone()), secret.clone())
            .await
            .expect_err("failed to prevent invalid transaction");
        store
            .store_secret(Some(secret.clone()), new_secret.clone())
            .await
            .unwrap();
        assert_eq!(
            store
                .get_all_secrets()
                .await
                .unwrap()
                .get("test_ring/test_key")
                .unwrap()
                .get("test_secret")
                .unwrap(),
            &new_secret
        );
        assert_eq!(
            store.get_key_secrets("test_ring/test_key").await.unwrap(),
            vec![new_secret.clone()]
        );
        assert_eq!(
            store
                .get_secret("test_ring/test_key/test_secret")
                .await
                .unwrap(),
            Some(new_secret.clone())
        );

        let secret2 = Secret::new_base("test_ring/test_key/test_secret2".to_string());
        store.store_secret(None, secret2.clone()).await.unwrap();
        assert_eq!(
            store
                .get_all_secrets()
                .await
                .unwrap()
                .get("test_ring/test_key")
                .unwrap()
                .get("test_secret")
                .unwrap(),
            &new_secret
        );
        assert_eq!(
            store
                .get_all_secrets()
                .await
                .unwrap()
                .get("test_ring/test_key")
                .unwrap()
                .get("test_secret2")
                .unwrap(),
            &secret2
        );
        let mut etcd_secrets = store.get_key_secrets("test_ring/test_key").await.unwrap();
        etcd_secrets.sort_by(|a, b| a.alias.cmp(&b.alias));
        let mut expected_secrets = vec![new_secret.clone(), secret2.clone()];
        expected_secrets.sort_by(|a, b| a.alias.cmp(&b.alias));
        assert_eq!(etcd_secrets, expected_secrets);
        assert_eq!(
            store
                .get_secret("test_ring/test_key/test_secret")
                .await
                .unwrap(),
            Some(new_secret.clone())
        );
        assert_eq!(
            store
                .get_secret("test_ring/test_key/test_secret2")
                .await
                .unwrap(),
            Some(secret2.clone())
        );
        assert_eq!(
            true,
            store
                .delete_secret("test_ring/test_key/test_secret2")
                .await
                .unwrap()
        );
        assert_eq!(
            store
                .get_secret("test_ring/test_key/test_secret2")
                .await
                .unwrap(),
            None
        );
    }
}

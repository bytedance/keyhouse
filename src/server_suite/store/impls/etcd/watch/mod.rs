use crate::Metric;

use super::*;
use futures::StreamExt;
use serde::{de::DeserializeOwned, Serialize};
use tokio::time::{sleep, Duration};

#[tonic::async_trait]
pub(super) trait StoreWatcher<
    T: Serialize + DeserializeOwned + Send + Sync + 'static,
    Y: KeyhouseImpl + 'static,
>
{
    async fn delete(&self, _key: &str) -> Result<()> {
        Ok(())
    }

    async fn put(&self, key: &str, value: T) -> Result<Option<StoreUpdate>>;

    fn prefix(&self) -> String;

    async fn handle_event(&self, mut event: Event) -> Result<Option<StoreUpdate>> {
        let event_type = event.event_type();
        match event_type {
            EventType::Delete => {
                self.delete(
                    &event
                        .take_kvs()
                        .map(|x| x.key_str().to_string())
                        .unwrap_or_else(|| "".to_string()),
                )
                .await?;
                Ok(None)
            }
            EventType::Put => {
                let value = match event.take_kvs() {
                    Some(value) => value,
                    None => {
                        return Err(anyhow!(
                            "no value present in kv of event in etcd watch loop"
                        ));
                    }
                };
                let key: T = match serde_json::from_str(value.value_str()) {
                    Ok(key) => key,
                    Err(e) => {
                        return Err(anyhow!(
                            "failed to parse item from etcd watch loop: {:?}",
                            e
                        ));
                    }
                };
                self.put(value.key_str(), key).await
            }
        }
    }

    async fn watch(&self, mut store: EtcdStore<Y>, sender: mpsc::Sender<StoreUpdate>) {
        loop {
            let prefix = self.prefix();
            let stream = store
                .client
                .watch(KeyRange::prefix(format!("{}{}", store.prefix, prefix)))
                .await;
            if let Err(e) = &stream {
                error!("failed to open etcd stream: {:?}", e);
                sleep(Duration::from_secs(1)).await;
            }
            let mut stream = stream.unwrap();
            while let Some(Ok(Some(mut update))) = stream.next().await {
                for event in update.take_events().into_iter() {
                    match self.handle_event(event).await {
                        Ok(Some(event)) => {
                            sender.send(event).await.ok();
                        }
                        Ok(None) => (),
                        Err(e) => {
                            sentry_error!("failed to handle etcd event: {:?}", e);
                        }
                    }
                }
            }
            warn!("etcd died during watch operation, restarting in 1 second...");
            sleep(Duration::from_secs(1)).await;
            match store.internal_duplicate_connection().await {
                Ok(new_store) => store = new_store,
                Err(e) => {
                    warn!("watcher failed to reconnect to etcd, retrying: {:?}", e);
                }
            }
        }
    }
}

pub(super) struct EtcdStoreWatcher;

#[tonic::async_trait]
impl<T: KeyhouseImpl + 'static> StoreWatcher<CustomerKey, T> for EtcdStoreWatcher {
    async fn delete(&self, key: &str) -> Result<()> {
        sentry_error!("illegal deletion detected for key '{}'!", key);
        Ok(())
    }

    async fn put(&self, _key: &str, mut value: CustomerKey) -> Result<Option<StoreUpdate>> {
        value.init_runtime::<T>().await.map_err(|e| {
            anyhow!(
                "failed to decode customer key's intermediate_key from etcd watch loop: {:?}",
                e
            )
        })?;
        T::KeyhouseExt::emit_metric(Metric::EtcdCustomerKeyUpdateReceived);
        Ok(Some(StoreUpdate {
            data: StoreUpdateData::CacheInvalidate(value),
            result: None,
        }))
    }

    fn prefix(&self) -> String {
        "keys/".to_string()
    }
}

#[tonic::async_trait]
impl<T: KeyhouseImpl + 'static> StoreWatcher<Keyring, T> for EtcdStoreWatcher {
    async fn delete(&self, key: &str) -> Result<()> {
        sentry_error!("illegal deletion detected for key '{}'!", key);
        Ok(())
    }

    async fn put(&self, _key: &str, value: Keyring) -> Result<Option<StoreUpdate>> {
        T::KeyhouseExt::emit_metric(Metric::EtcdKeyringUpdateReceived);
        Ok(Some(StoreUpdate {
            data: StoreUpdateData::CacheInvalidateKeyring(value),
            result: None,
        }))
    }

    fn prefix(&self) -> String {
        "keyrings/".to_string()
    }
}

#[tonic::async_trait]
impl<T: KeyhouseImpl + 'static> StoreWatcher<IntermediateKey, T> for EtcdStoreWatcher {
    async fn delete(&self, key: &str) -> Result<()> {
        sentry_error!("illegal deletion detected for key '{}'!", key);
        Ok(())
    }

    async fn put(&self, _key: &str, value: IntermediateKey) -> Result<Option<StoreUpdate>> {
        T::KeyhouseExt::emit_metric(Metric::EtcdIntermediateKeyUpdateReceived);
        Ok(Some(StoreUpdate {
            data: StoreUpdateData::CacheInvalidateIntermediateKey(value),
            result: None,
        }))
    }

    fn prefix(&self) -> String {
        "intermediate_key".to_string()
    }
}

#[tonic::async_trait]
impl<T: KeyhouseImpl + 'static> StoreWatcher<Secret, T> for EtcdStoreWatcher {
    async fn delete(&self, key: &str) -> Result<()> {
        sentry_error!("illegal deletion detected for key '{}'!", key);
        Ok(())
    }

    async fn put(&self, _key: &str, value: Secret) -> Result<Option<StoreUpdate>> {
        T::KeyhouseExt::emit_metric(Metric::EtcdSecretUpdateReceived);
        Ok(Some(StoreUpdate {
            data: StoreUpdateData::CacheInvalidateSecret(value),
            result: None,
        }))
    }

    fn prefix(&self) -> String {
        "secrets/".to_string()
    }
}

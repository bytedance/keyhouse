use super::*;
use tokio::time::{sleep, Duration};

impl<T: KeyhouseImpl + 'static> EtcdStore<T> {
    pub async fn new(
        prefix: String,
        endpoints: Vec<Url>,
        tls_auth: rustls::ClientConfig,
        auth: Option<(String, String)>,
    ) -> Result<EtcdStore<T>> {
        debug!("constructing etcd client");
        let endpoints_str: Vec<String> = endpoints.iter().map(|x| x.to_string()).collect();
        let tls_enabled = !endpoints_str.is_empty() && endpoints_str[0].starts_with("https://");
        let client_config = ClientConfig {
            endpoints: endpoints_str,
            auth: auth.clone(),
            tls: if tls_enabled {
                Some(ClientTlsConfig::new().rustls_client_config(tls_auth.clone()))
            } else {
                None
            },
        };
        let client: Client;
        debug!("etcd client constructed. connecting ...");
        loop {
            debug!("connecting to {:?}", endpoints);
            match Client::connect(client_config.clone()).await {
                Ok(new_client) => {
                    debug!("conneced!");
                    client = new_client;
                    break;
                }
                Err(e) => {
                    error!("failed to connect to etcd, retry in 1 second: {:?}", e);
                    sleep(Duration::from_secs(1)).await;
                }
            }
        }
        debug!("loop exited");

        Ok(EtcdStore {
            client,
            prefix,
            endpoints,
            tls_auth,
            auth,
            _phantom: PhantomData::<T>,
        })
    }

    // used to get avoid threading failure in etcd-rs for multiple watchers
    pub(super) async fn internal_duplicate_connection(&self) -> Result<EtcdStore<T>> {
        EtcdStore::<T>::new(
            self.prefix.clone(),
            self.endpoints.clone(),
            self.tls_auth.clone(),
            self.auth.clone(),
        )
        .await
    }

    #[cfg(test)]
    pub(crate) async fn clear_store(&self) -> Result<()> {
        etcd_wrap::<T, _, _>(
            "clear_store",
            self.client
                .kv()
                .delete(DeleteRequest::new(KeyRange::prefix(&*self.prefix))),
        )
        .await?;
        Ok(())
    }
}

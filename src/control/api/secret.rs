use super::*;
use crate::server_suite::store::{DecodedSecret, Secret};
use crate::util;
use actix_web::web::{self, Json};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Deserialize)]
pub struct CustomerKeyPath {
    keyring_alias: String,
    key_alias: String,
}

pub async fn list_secrets<T: KeyhouseImpl + 'static>(
    req: HttpRequest,
    id: web::Path<CustomerKeyPath>,
) -> Json<PlatformResponse<Vec<DecodedSecret>>> {
    _list_secrets::<T>(req, id).await.unwrap_or_else(|e| e)
}

async fn _list_secrets<T: KeyhouseImpl + 'static>(
    req: HttpRequest,
    id: web::Path<CustomerKeyPath>,
) -> PlatformResult<Vec<DecodedSecret>> {
    let identity = {
        let identity = req.extensions();
        identity.get::<Identity>().unwrap().clone()
    };

    let data: &ControlData<T> = req.app_data().unwrap();
    let (_keyring, _key) = data
        .authorized_key(&identity, &id.keyring_alias, &id.key_alias)
        .await?;

    let secrets = data
        .store
        .get_key_secrets(&format!("{}/{}", &id.keyring_alias, &id.key_alias))
        .await;

    match secrets {
        Ok(secrets) => Ok(PlatformResponse::ok(
            secrets.into_iter().map(Secret::empty_decoded).collect(),
        )),
        Err(e) => {
            sentry_error!("error in list_secrets: {:?}", e);
            Err(PlatformResponse::error("internal error"))
        }
    }
}

#[derive(Deserialize)]
pub struct SecretPath {
    keyring_alias: String,
    key_alias: String,
    secret_alias: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct IncomingSecret {
    pub secret: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

impl Zeroize for IncomingSecret {
    fn zeroize(&mut self) {
        if let Some(s) = self.secret.as_mut() {
            s.zeroize()
        }
        if let Some(d) = self.description.as_mut() {
            d.zeroize()
        }
    }
}

impl Drop for IncomingSecret {
    fn drop(&mut self) {
        self.zeroize();
    }
}

pub async fn store_secret<T: KeyhouseImpl + 'static>(
    req: HttpRequest,
    id: web::Path<SecretPath>,
    secret: Json<IncomingSecret>,
) -> Json<PlatformResponse<DecodedSecret>> {
    _store_secret::<T>(req, id, secret)
        .await
        .unwrap_or_else(|e| e)
}

async fn _store_secret<T: KeyhouseImpl + 'static>(
    req: HttpRequest,
    id: web::Path<SecretPath>,
    secret: Json<IncomingSecret>,
) -> PlatformResult<DecodedSecret> {
    let identity = {
        let identity = req.extensions();
        identity.get::<Identity>().unwrap().clone()
    };

    verify_alias(&id.secret_alias)?;

    let data: &ControlData<T> = req.app_data().unwrap();
    let (_keyring, key) = data
        .authorized_key(&identity, &id.keyring_alias, &id.key_alias)
        .await?;

    let secret_alias = format!("{}/{}/{}", id.keyring_alias, id.key_alias, id.secret_alias);

    let current_secret = match data.store.get_secret(&secret_alias).await {
        Err(e) => {
            sentry_error!("error getting secret: {:?}", e);
            return Err(PlatformResponse::error("internal error"));
        }
        Ok(x) => x,
    };

    if current_secret.is_none() {
        if let Some(max_secret_count) = SERVER_CONFIG.get().0.secret_limit {
            let secrets_count = data
                .store
                .count_key_secrets(&key.alias)
                .await
                .map_err(|e| {
                    sentry_error!("error in store_secret/count_key_secrets: {:?}", e);
                    PlatformResponse::error("internal error")
                })?;
            if secrets_count >= max_secret_count {
                return Err(PlatformResponse::error(format!(
                    "too many secrets: cannot make more than {} secrets",
                    max_secret_count
                )));
            }
        }
    }

    let new_secret = match &current_secret {
        Some(current_secret) => {
            let current_secret = match current_secret.clone().decode::<T>(&key) {
                Err(e) => {
                    sentry_error!(
                        "error in secret decoding for store_secret id: '{}': {:?}",
                        &current_secret.alias,
                        e
                    );
                    return Err(PlatformResponse::error("internal error"));
                }
                Ok(x) => x,
            };

            let current_secret_value = current_secret.value.clone();
            let current_secret_description = current_secret.description.clone();
            DecodedSecret {
                alias: current_secret.alias.clone(),
                value: secret.0.secret.clone().unwrap_or(current_secret_value),
                created_at: current_secret.created_at,
                updated_at: util::epoch(),
                description: secret
                    .0
                    .description
                    .clone()
                    .unwrap_or(current_secret_description),
            }
        }
        None => DecodedSecret {
            alias: secret_alias.clone(),
            value: secret.0.secret.clone().unwrap_or_default(),
            created_at: util::epoch(),
            updated_at: util::epoch(),
            description: secret.0.description.clone().unwrap_or_default(),
        },
    };
    if !new_secret.validate_size() {
        return Err(PlatformResponse::error(
            "secret cannot be larger than 16 kb (UTF-8)",
        ));
    }

    let new_secret_encoded = match new_secret.clone().encode::<T>(&key) {
        Err(e) => {
            sentry_error!(
                "error in secret encoding for store_secret id: '{}': {:?}",
                &new_secret.alias,
                e
            );
            return Err(PlatformResponse::error("internal error"));
        }
        Ok(x) => x,
    };

    if let Err(e) = data
        .store
        .store_secret(current_secret, new_secret_encoded.clone())
        .await
    {
        sentry_error!("error in store_secret: {:?}", e);
        return Err(PlatformResponse::error("internal error"));
    }
    Ok(PlatformResponse::ok(new_secret_encoded.empty_decoded()))
}

pub async fn delete_secret<T: KeyhouseImpl + 'static>(
    req: HttpRequest,
    id: web::Path<SecretPath>,
) -> Json<PlatformResponse<()>> {
    _delete_secret::<T>(req, id).await.unwrap_or_else(|e| e)
}

async fn _delete_secret<T: KeyhouseImpl + 'static>(
    req: HttpRequest,
    id: web::Path<SecretPath>,
) -> PlatformResult<()> {
    let identity = {
        let identity = req.extensions();
        identity.get::<Identity>().unwrap().clone()
    };

    verify_alias(&id.secret_alias)?;

    let data: &ControlData<T> = req.app_data().unwrap();
    let (_keyring, _key) = data
        .authorized_key(&identity, &id.keyring_alias, &id.key_alias)
        .await?;

    let secret_alias = format!("{}/{}/{}", id.keyring_alias, id.key_alias, id.secret_alias);

    let secret_deleted = match data.store.delete_secret(&secret_alias).await {
        Err(e) => {
            sentry_error!("error deleting secret: {:?}", e);
            return Err(PlatformResponse::error("internal error"));
        }
        Ok(x) => x,
    };
    if secret_deleted {
        Ok(PlatformResponse::ok(()))
    } else {
        Ok(PlatformResponse::error("secret does not exist"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::tests::*;
    use crate::server_suite::store::*;

    #[actix_web::main]
    #[test]
    async fn api_list_secrets() {
        let mocked_store = Arc::new(MockStore::<()>::new().await.unwrap());
        let keyring = Keyring::new_base("test".to_string());
        mocked_store.store_keyring(keyring.clone()).await.unwrap();
        let key = CustomerKey::new_base::<()>("test/test".to_string()).unwrap();
        mocked_store.store_customer_key(key.clone()).await.unwrap();
        let mut secret =
            DecodedSecret::new_base("test/test/test".to_string(), "test secret".to_string());
        let encoded_secret = secret.clone().encode::<()>(&key).unwrap();

        mocked_store
            .store_secret(None, encoded_secret.clone())
            .await
            .unwrap();

        let req = mock_request(mocked_store).to_http_request();
        let resp = _list_secrets::<()>(
            identify_request(req),
            CustomerKeyPath {
                keyring_alias: "test".to_string(),
                key_alias: "test".to_string(),
            }
            .into(),
        )
        .await
        .unwrap();

        secret.value = "".to_string();
        assert_eq!(resp.into_inner().data.unwrap(), vec![secret]);
    }

    #[actix_web::main]
    #[test]
    async fn api_store_secret() {
        let mocked_store = Arc::new(MockStore::new().await.unwrap());
        let keyring = Keyring::new_base("test".to_string());
        mocked_store.store_keyring(keyring.clone()).await.unwrap();
        let key = CustomerKey::new_base::<()>("test/test".to_string()).unwrap();
        mocked_store.store_customer_key(key.clone()).await.unwrap();

        //new
        {
            let req = mock_request::<()>(mocked_store.clone()).to_http_request();
            let resp = _store_secret::<()>(
                identify_request(req),
                SecretPath {
                    keyring_alias: "test".to_string(),
                    key_alias: "test".to_string(),
                    secret_alias: "test".to_string(),
                }
                .into(),
                Json(IncomingSecret {
                    secret: Some("testing".to_string()),
                    description: None,
                }),
            )
            .await
            .unwrap();

            let secret = resp.into_inner().data.unwrap();
            assert_eq!(&secret.value, "");
            let store_secret = mocked_store
                .get_secret(&secret.alias)
                .await
                .unwrap()
                .unwrap();
            let mut decoded_store_secret = store_secret.decode::<()>(&key).unwrap();

            decoded_store_secret.value = String::new();
            assert_eq!(secret, decoded_store_secret);
        }

        //update
        {
            let req = mock_request::<()>(mocked_store.clone()).to_http_request();
            let resp = _store_secret::<()>(
                identify_request(req),
                SecretPath {
                    keyring_alias: "test".to_string(),
                    key_alias: "test".to_string(),
                    secret_alias: "test".to_string(),
                }
                .into(),
                Json(IncomingSecret {
                    secret: Some("testing123".to_string()),
                    description: None,
                }),
            )
            .await
            .unwrap();

            let secret = resp.into_inner().data.unwrap();
            assert_eq!(&secret.value, "");
            let store_secret = mocked_store
                .get_secret(&secret.alias)
                .await
                .unwrap()
                .unwrap();
            let mut decoded_store_secret = store_secret.decode::<()>(&key).unwrap();

            decoded_store_secret.value = String::new();
            assert_eq!(secret, decoded_store_secret);
        }

        //oversize error
        {
            let secret_value = String::from_utf8(vec![b't'; 16 * 1024 + 1]).unwrap();
            let req = mock_request::<()>(mocked_store.clone()).to_http_request();
            let resp = _store_secret::<()>(
                identify_request(req),
                SecretPath {
                    keyring_alias: "test".to_string(),
                    key_alias: "test".to_string(),
                    secret_alias: "test".to_string(),
                }
                .into(),
                Json(IncomingSecret {
                    secret: Some(secret_value),
                    description: None,
                }),
            )
            .await
            .unwrap_or_else(|e| e)
            .into_inner();

            assert_eq!(resp.error_code, 1);
            assert_eq!(
                resp.msg.unwrap(),
                "secret cannot be larger than 16 kb (UTF-8)"
            );
            assert!(resp.data.is_none());
        }
    }

    #[actix_web::main]
    #[test]
    async fn api_delete_secret() {
        let mocked_store = Arc::new(MockStore::<()>::new().await.unwrap());
        let keyring = Keyring::new_base("test".to_string());
        mocked_store.store_keyring(keyring.clone()).await.unwrap();
        let key = CustomerKey::new_base::<()>("test/test".to_string()).unwrap();
        mocked_store.store_customer_key(key.clone()).await.unwrap();
        let secret =
            DecodedSecret::new_base("test/test/test".to_string(), "test secret".to_string());
        let encoded_secret = secret.clone().encode::<()>(&key).unwrap();

        mocked_store
            .store_secret(None, encoded_secret.clone())
            .await
            .unwrap();

        let req = mock_request(mocked_store.clone()).to_http_request();
        let resp = _delete_secret::<()>(
            identify_request(req),
            SecretPath {
                keyring_alias: "test".to_string(),
                key_alias: "test".to_string(),
                secret_alias: "test".to_string(),
            }
            .into(),
        )
        .await
        .unwrap();

        assert_eq!(resp.into_inner().error_code, 0);

        assert_eq!(
            mocked_store.get_secret("test/test/test").await.unwrap(),
            None
        );
    }
}

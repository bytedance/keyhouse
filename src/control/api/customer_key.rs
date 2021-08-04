use super::*;
use crate::server_suite::store::*;
use crate::util;
use actix_web::web::{self, Json};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Deserialize)]
pub struct PathId {
    keyring_alias: String,
    key_alias: String,
}

pub async fn get_customer_key<T: KeyhouseImpl + 'static>(
    req: HttpRequest,
    id: web::Path<PathId>,
) -> Json<PlatformResponse<CustomerKey>> {
    _get_customer_key::<T>(req, id).await.unwrap_or_else(|e| e)
}

async fn _get_customer_key<T: KeyhouseImpl + 'static>(
    req: HttpRequest,
    id: web::Path<PathId>,
) -> PlatformResult<CustomerKey> {
    let identity = {
        let identity = req.extensions();
        identity.get::<Identity>().unwrap().clone()
    };

    let data: &ControlData<T> = req.app_data().unwrap();
    let (_, key) = data
        .authorized_key(&identity, &id.keyring_alias, &id.key_alias)
        .await?;

    Ok(PlatformResponse::ok(
        key.censor().migrate_user_authorization_data(),
    ))
}

#[derive(Deserialize)]
pub struct KeyringPathId {
    keyring_alias: String,
}

pub async fn list_customer_keys<T: KeyhouseImpl + 'static>(
    req: HttpRequest,
    id: web::Path<KeyringPathId>,
) -> Json<PlatformResponse<Vec<CustomerKey>>> {
    _list_customer_keys::<T>(req, id)
        .await
        .unwrap_or_else(|e| e)
}

async fn _list_customer_keys<T: KeyhouseImpl + 'static>(
    req: HttpRequest,
    id: web::Path<KeyringPathId>,
) -> PlatformResult<Vec<CustomerKey>> {
    let identity = {
        let identity = req.extensions();
        identity.get::<Identity>().unwrap().clone()
    };

    let data: &ControlData<T> = req.app_data().unwrap();
    let keyring = data
        .authorized_keyring(&identity, &id.keyring_alias)
        .await?;

    let output: Vec<CustomerKey> = match data.store.get_keyring_keys(&keyring.alias).await {
        Ok(x) => x,
        Err(e) => {
            sentry_error!(
                "etcd error during list of customer keys for keyring {}: {:?}",
                &id.keyring_alias,
                e
            );
            return Err(PlatformResponse::error("internal error"));
        }
    }
    .into_iter()
    .map(|x| x.censor().migrate_user_authorization_data())
    .collect();
    Ok(PlatformResponse::ok(output))
}

#[derive(Serialize, Deserialize)]
pub struct InboundCustomerKey {
    pub alias: String,
    pub description: String,
    pub purpose: KeyPurpose,
    pub acls: BTreeMap<AccessControlDomain, AccessControlList>, // encode, decode,
}

pub async fn create_customer_key<T: KeyhouseImpl + 'static>(
    req: HttpRequest,
    id: web::Path<KeyringPathId>,
    key: Json<InboundCustomerKey>,
) -> Json<PlatformResponse<CustomerKey>> {
    _create_customer_key::<T>(req, id, key)
        .await
        .unwrap_or_else(|e| e)
}

async fn _create_customer_key<T: KeyhouseImpl + 'static>(
    req: HttpRequest,
    id: web::Path<KeyringPathId>,
    key: Json<InboundCustomerKey>,
) -> PlatformResult<CustomerKey> {
    let key = key.into_inner();
    let identity = {
        let identity = req.extensions();
        identity.get::<Identity>().unwrap().clone()
    };
    let alias = key.alias.to_ascii_lowercase();

    verify_alias(&alias)?;

    let data: &ControlData<T> = req.app_data().unwrap();
    let keyring = data
        .authorized_keyring(&identity, &id.keyring_alias)
        .await?;

    let real_alias = format!("{}/{}", keyring.alias, alias);

    if let Some(max_key_count) = SERVER_CONFIG.get().0.customer_key_limit {
        let keys = data
            .store
            .get_keyring_keys(&keyring.alias)
            .await
            .map_err(|e| {
                sentry_error!("error in create_customer_key/get_keyring_keys: {:?}", e);
                PlatformResponse::error("internal error")
            })?;
        if keys.len() >= max_key_count {
            return Err(PlatformResponse::error(format!(
                "too many customer keys: cannot make more than {} customer keys",
                max_key_count
            )));
        }
    }

    if let Some(max_acl_count) = SERVER_CONFIG.get().0.acl_limit {
        for (_, acls) in key.acls.iter() {
            if acls.len() >= max_acl_count {
                return Err(PlatformResponse::error(format!("too many acl entries: cannot make more than {} acl entries per authorization domain", max_acl_count)));
            }
        }
    }

    // this is a race to check aliases here, but the following is actually unnecessary, just provides a nicer api-level error for reused aliases.
    // the real atomic check happens within etcd
    match data.store.get_customer_key_by_alias(&real_alias).await {
        Err(e) => {
            sentry_error!("error in create_customer_key: {:?}", e);
            return Err(PlatformResponse::error("internal error"));
        }
        Ok(Some(_)) => {
            return Err(PlatformResponse::error("alias already in use"));
        }
        _ => (),
    }
    let intermediate_key = data
        .store
        .get_intermediate_key()
        .await
        .map_err(|_| PlatformResponse::error("internal error"))?;

    let intermediate_key = if let Some(intermediate_key) = intermediate_key {
        intermediate_key
    } else {
        sentry_error!("no intermediate key found!");
        return Err(PlatformResponse::error(
            "temporary internal error, try again shortly",
        ));
    };

    let key = CustomerKey {
        id: rand::random(),
        alias: real_alias.clone(),
        created_at: util::epoch(),
        updated_at: util::epoch(),
        description: key.description,
        purpose: key.purpose,

        acls: key.acls,
        status: KeyStatus::Enabled,
        sensitives: Some(Sensitives::generate::<T>(&intermediate_key).map_err(|e| {
            sentry_error!("error in create_customer_key: {:?}", e);
            PlatformResponse::error("internal error")
        })?),
        user_authorization_data: vec![],
    };
    data.store
        .store_customer_key(key.clone())
        .await
        .map_err(|e| {
            sentry_error!("error in create_customer_key: {:?}", e);
            PlatformResponse::error("internal error")
        })?;
    let key = key.censor().migrate_user_authorization_data();

    Ok(PlatformResponse::ok(key))
}

pub async fn update_customer_key<T: KeyhouseImpl + 'static>(
    req: HttpRequest,
    id: web::Path<PathId>,
    mutation: Json<CustomerKeyMutation>,
) -> Json<PlatformResponse<CustomerKey>> {
    _update_customer_key::<T>(req, id, mutation)
        .await
        .unwrap_or_else(|e| e)
}

async fn _update_customer_key<T: KeyhouseImpl + 'static>(
    req: HttpRequest,
    id: web::Path<PathId>,
    mutation: Json<CustomerKeyMutation>,
) -> PlatformResult<CustomerKey> {
    let identity = {
        let identity = req.extensions();
        identity.get::<Identity>().unwrap().clone()
    };

    let data: &ControlData<T> = req.app_data().unwrap();
    let (_, key) = data
        .authorized_key(&identity, &id.keyring_alias, &id.key_alias)
        .await?;
    let mutation = mutation.into_inner();
    let status = mutation.status;

    let mut key = data
        .store
        .mutate_customer_key(key.id, mutation)
        .await
        .map_err(|e| {
            sentry_error!(
                "error in update_customer_key, failed to mutate store: {:?}",
                e
            );
            PlatformResponse::error("internal error")
        })?;
    if let Some(KeyStatus::Disabled) = status {
        key = key.reload(&data.store).await.map_err(|e| {
            sentry_error!(
                "error in update_customer_key, failed to mutate store: {:?}",
                e
            );
            PlatformResponse::error("internal error")
        })?
    }
    Ok(PlatformResponse::ok(
        key.censor().migrate_user_authorization_data(),
    ))
}

#[cfg(test)]
mod tests {
    use spire_workload::SpiffeIDMatcher;
    use url::Url;

    use super::*;
    use crate::control::tests::*;

    #[actix_web::main]
    #[test]
    async fn api_get_customer_key() {
        let mocked_store = Arc::new(MockStore::<()>::new().await.unwrap());

        let keyring = Keyring::new_base("test".to_string());
        mocked_store.store_keyring(keyring.clone()).await.unwrap();
        let key = CustomerKey::new_base::<()>("test/test".to_string()).unwrap();
        mocked_store.store_customer_key(key.clone()).await.unwrap();

        let keyring_unauth = Keyring::new_base("test_unauth".to_string());
        mocked_store
            .store_keyring(keyring_unauth.clone())
            .await
            .unwrap();
        let key_unauth =
            CustomerKey::new_base::<()>("test_unauth/test_unauth".to_string()).unwrap();
        mocked_store
            .store_customer_key(key_unauth.clone())
            .await
            .unwrap();

        {
            let req = mock_request::<()>(mocked_store.clone()).to_http_request();
            let resp = _get_customer_key::<()>(
                identify_request(req),
                web::Path::from(PathId {
                    keyring_alias: keyring.alias.clone(),
                    key_alias: "test".to_string(),
                }),
            )
            .await
            .ok()
            .unwrap()
            .into_inner()
            .data
            .unwrap();
            if resp.sensitives.is_some() {
                panic!("did not hide key from control plane");
            }
            assert_eq!(resp, key.clone().censor().migrate_user_authorization_data());
        }
        {
            let req = mock_request::<()>(mocked_store.clone()).to_http_request();
            _get_customer_key::<()>(
                identify_request(req),
                web::Path::from(PathId {
                    keyring_alias: keyring_unauth.alias.clone(),
                    key_alias: "test_unauth".to_string(),
                }),
            )
            .await
            .err()
            .expect("did not fail to fetch unauthorized valid id pair");
        }
    }

    #[actix_web::main]
    #[test]
    async fn api_backmigrate_customer_key() {
        let mocked_store = Arc::new(MockStore::<()>::new().await.unwrap());

        let keyring = Keyring::new_base("test".to_string());
        mocked_store.store_keyring(keyring.clone()).await.unwrap();
        let mut key = CustomerKey::new_base::<()>("test/test".to_string()).unwrap();
        key.acls.insert(
            AccessControlDomain::Encode,
            vec![
                SpiffeIDMatcher::new(Url::parse("spiffe://test/ns:user/id:test_user").unwrap())
                    .unwrap(),
            ],
        );
        mocked_store.store_customer_key(key.clone()).await.unwrap();

        {
            let req = mock_request::<()>(mocked_store.clone()).to_http_request();
            let resp = _get_customer_key::<()>(
                identify_request(req),
                web::Path::from(PathId {
                    keyring_alias: keyring.alias.clone(),
                    key_alias: "test".to_string(),
                }),
            )
            .await
            .ok()
            .unwrap()
            .into_inner()
            .data
            .unwrap();
            if resp.sensitives.is_some() {
                panic!("did not hide key from control plane");
            }
            if resp.user_authorization_data.len() != 1 {
                panic!("did not backmigrate user_authorization_data");
            }
            assert_eq!(resp.user_authorization_data.get(0).unwrap(), "test_user");
            assert_eq!(resp, key.clone().censor().migrate_user_authorization_data());
        }
    }

    #[actix_web::main]
    #[test]
    async fn api_list_customer_keys() {
        let mocked_store = Arc::new(MockStore::<()>::new().await.unwrap());

        let keyring = Keyring::new_base("test".to_string());
        mocked_store.store_keyring(keyring.clone()).await.unwrap();
        let key = CustomerKey::new_base::<()>("test/test".to_string()).unwrap();
        mocked_store.store_customer_key(key.clone()).await.unwrap();

        {
            let req = mock_request::<()>(mocked_store.clone()).to_http_request();
            let resp = _list_customer_keys::<()>(
                identify_request(req),
                web::Path::from(KeyringPathId {
                    keyring_alias: keyring.alias.clone(),
                }),
            )
            .await
            .ok()
            .unwrap()
            .into_inner()
            .data
            .unwrap();
            assert_eq!(resp, vec![key.censor().migrate_user_authorization_data()]);
        }
    }

    #[actix_web::main]
    #[test]
    async fn api_create_customer_key() {
        let mocked_store = Arc::new(MockStore::<()>::new().await.unwrap());

        let keyring = Keyring::new_base("test".to_string());
        mocked_store.store_keyring(keyring.clone()).await.unwrap();
        let keyring_unauth = Keyring::new_base("test_unauth".to_string());
        mocked_store
            .store_keyring(keyring_unauth.clone())
            .await
            .unwrap();

        crate::server_suite::store::intermediate_key::IntermediateKey::reload_checked::<()>(
            mocked_store.clone(),
        )
        .await
        .unwrap();

        let key = {
            let req = mock_request::<()>(mocked_store.clone()).to_http_request();
            let resp = _create_customer_key::<()>(
                identify_request(req),
                web::Path::from(KeyringPathId {
                    keyring_alias: keyring.alias.clone(),
                }),
                Json(InboundCustomerKey {
                    alias: "test".to_string(),
                    description: "testing".to_string(),
                    purpose: KeyPurpose::EncodeDecode,
                    acls: BTreeMap::new(),
                }),
            )
            .await
            .ok()
            .unwrap();

            resp.into_inner().data.unwrap()
        };
        {
            let req = mock_request::<()>(mocked_store.clone()).to_http_request();
            _create_customer_key::<()>(
                identify_request(req),
                web::Path::from(KeyringPathId {
                    keyring_alias: keyring.alias.clone(),
                }),
                Json(InboundCustomerKey {
                    alias: "test".to_string(),
                    description: "testing".to_string(),
                    purpose: KeyPurpose::EncodeDecode,
                    acls: BTreeMap::new(),
                }),
            )
            .await
            .err()
            .expect("failed to block duplicate alias");
        }
        {
            let req = mock_request::<()>(mocked_store.clone()).to_http_request();
            _create_customer_key::<()>(
                identify_request(req),
                web::Path::from(KeyringPathId {
                    keyring_alias: keyring_unauth.alias.clone(),
                }),
                Json(InboundCustomerKey {
                    alias: "test2".to_string(),
                    description: "testing".to_string(),
                    purpose: KeyPurpose::EncodeDecode,
                    acls: BTreeMap::new(),
                }),
            )
            .await
            .err()
            .expect("failed to block creation in unauthorized keyring");
        }

        {
            let req = mock_request::<()>(mocked_store.clone()).to_http_request();
            let resp = _get_customer_key::<()>(
                identify_request(req),
                web::Path::from(PathId {
                    keyring_alias: keyring.alias.clone(),
                    key_alias: "test".to_string(),
                }),
            )
            .await
            .ok()
            .unwrap();
            assert_eq!(resp.into_inner().data.unwrap(), key);
        }
    }

    #[actix_web::main]
    #[test]
    async fn api_update_customer_key() {
        let mocked_store = Arc::new(MockStore::<()>::new().await.unwrap());

        let keyring = Keyring::new_base("test".to_string());
        mocked_store.store_keyring(keyring.clone()).await.unwrap();
        let mut key = CustomerKey::new_base::<()>("test/test".to_string()).unwrap();
        mocked_store.store_customer_key(key.clone()).await.unwrap();

        let keyring_unauth = Keyring::new_base("test_unauth".to_string());
        mocked_store
            .store_keyring(keyring_unauth.clone())
            .await
            .unwrap();
        let key_unauth =
            CustomerKey::new_base::<()>("test_unauth/test_unauth".to_string()).unwrap();
        mocked_store
            .store_customer_key(key_unauth.clone())
            .await
            .unwrap();

        {
            let req = mock_request::<()>(mocked_store.clone()).to_http_request();
            let resp = _update_customer_key::<()>(
                identify_request(req),
                web::Path::from(PathId {
                    keyring_alias: keyring.alias.clone(),
                    key_alias: "test".to_string(),
                }),
                Json(CustomerKeyMutation {
                    description: Some("new description".to_string()),
                    ..Default::default()
                }),
            )
            .await
            .unwrap()
            .into_inner()
            .data
            .unwrap();
            if resp.sensitives.is_some() {
                panic!("did not hide key from control plane");
            }
            key.description = "new description".to_string();
            assert_eq!(resp, key.clone().censor().migrate_user_authorization_data());
        }
        {
            let req = mock_request::<()>(mocked_store.clone()).to_http_request();
            _update_customer_key::<()>(
                identify_request(req),
                web::Path::from(PathId {
                    keyring_alias: keyring_unauth.alias.clone(),
                    key_alias: "test_unauth".to_string(),
                }),
                Json(CustomerKeyMutation {
                    description: Some("new description".to_string()),
                    ..Default::default()
                }),
            )
            .await
            .err()
            .expect("did not fail to update unauthorized valid id pair");
        }

        assert_eq!(
            mocked_store
                .get_customer_key_by_id(key.id)
                .await
                .unwrap()
                .unwrap(),
            key
        );
        assert_eq!(
            mocked_store
                .get_customer_key_by_id(key_unauth.id)
                .await
                .unwrap()
                .unwrap(),
            key_unauth
        );
    }
}

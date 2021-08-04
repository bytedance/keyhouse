use super::*;
use crate::server_suite::store::Keyring;
use crate::util;
use actix_web::web::{self, Json};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ApiKeyring {
    pub alias: String,
    pub created_at: u64,
    pub description: String,
    pub share_url: String,
    pub owners: Vec<String>,
    pub level: Option<String>,
}

impl ApiKeyring {
    fn from<T: KeyhouseImpl + 'static>(
        username: &str,
        keyring: Keyring,
        auth: &OwnedAuth<T>,
    ) -> ApiKeyring {
        let share_url = auth.get_keyring_share_url(username, &keyring.alias);
        ApiKeyring {
            alias: keyring.alias,
            created_at: keyring.created_at,
            description: keyring.description,
            share_url: share_url.unwrap_or_default(),
            owners: vec![],
            level: None,
        }
    }
}

impl From<ApiKeyring> for Keyring {
    fn from(keyring: ApiKeyring) -> Keyring {
        Keyring {
            alias: keyring.alias,
            created_at: keyring.created_at,
            description: keyring.description,
        }
    }
}

pub async fn list_keyrings<T: KeyhouseImpl + 'static>(
    req: HttpRequest,
) -> Json<PlatformResponse<Vec<ApiKeyring>>> {
    _list_keyrings::<T>(req).await.unwrap_or_else(|e| e)
}

async fn _list_keyrings<T: KeyhouseImpl + 'static>(
    req: HttpRequest,
) -> PlatformResult<Vec<ApiKeyring>> {
    let identity = {
        let identity = req.extensions();
        identity.get::<Identity>().unwrap().clone()
    };

    let data: &ControlData<T> = req.app_data().unwrap();
    let authorized_keyrings = data.authorized_keyrings(&identity).await?;

    let mut output: Vec<ApiKeyring> = vec![];
    for keyring in authorized_keyrings {
        let keyring = data.store.get_keyring(&keyring).await;
        match keyring {
            Err(e) => {
                sentry_error!("error in list_keyrings: {:?}", e);
                return Err(PlatformResponse::error("internal error"));
            }
            Ok(Some(keyring)) => {
                output.push(ApiKeyring::from::<T>(
                    &identity.username,
                    keyring,
                    &data.auth,
                ));
            }
            _ => (),
        }
    }
    Ok(PlatformResponse::ok(output))
}

#[derive(Deserialize)]
pub struct PathId {
    keyring_alias: String,
}

pub async fn get_keyring<T: KeyhouseImpl + 'static>(
    req: HttpRequest,
    id: web::Path<PathId>,
) -> Json<PlatformResponse<ApiKeyring>> {
    _get_keyring::<T>(req, id).await.unwrap_or_else(|e| e)
}

async fn _get_keyring<T: KeyhouseImpl + 'static>(
    req: HttpRequest,
    id: web::Path<PathId>,
) -> PlatformResult<ApiKeyring> {
    let identity = {
        let identity = req.extensions();
        identity.get::<Identity>().unwrap().clone()
    };

    let data: &ControlData<T> = req.app_data().unwrap();
    let keyring = data
        .authorized_keyring(&identity, &id.keyring_alias)
        .await?;

    let mut api_keyring: ApiKeyring =
        ApiKeyring::from::<T>(&identity.username, keyring, &data.auth);
    let auth_resource = data
        .auth
        .keychain_metadata(id.keyring_alias.clone())
        .await
        .map_err(|e| {
            sentry_error!(
                "failed to get keyring metadata<{}> from auth: {:?}",
                api_keyring.alias,
                e
            );
            PlatformResponse::error("internal error in auth")
        })?;
    api_keyring.owners = auth_resource.owners;
    api_keyring.level = Some(auth_resource.level);
    Ok(PlatformResponse::ok(api_keyring))
}

#[derive(Serialize, Deserialize, Debug)]
pub struct IncomingKeyring {
    pub alias: String,
    pub description: String,
    pub level: String,
}

pub async fn create_keyring<T: KeyhouseImpl + 'static>(
    req: HttpRequest,
    keyring: Json<IncomingKeyring>,
) -> Json<PlatformResponse<ApiKeyring>> {
    _create_keyring::<T>(req, keyring)
        .await
        .unwrap_or_else(|e| e)
}

static VALID_LEVELS: &[&str] = &["L2", "L3", "L4"];

async fn _create_keyring<T: KeyhouseImpl + 'static>(
    req: HttpRequest,
    keyring: Json<IncomingKeyring>,
) -> PlatformResult<ApiKeyring> {
    if !VALID_LEVELS.iter().any(|x| *x == keyring.level) {
        return Err(PlatformResponse::error("invalid level"));
    }

    let identity = {
        let identity = req.extensions();
        identity.get::<Identity>().unwrap().clone()
    };
    let alias = keyring.alias.to_ascii_lowercase();
    verify_alias(&alias)?;

    let data: &ControlData<T> = req.app_data().unwrap();

    // this is a race to check aliases here, but the following is actually unnecessary, just provides a nicer api-level error for reused aliases.
    // the real atomic check happens within etcd
    match data.store.get_keyring(&alias).await {
        Err(e) => {
            sentry_error!("error in create_keyring: {:?}", e);
            return Err(PlatformResponse::error("internal error"));
        }
        Ok(Some(_)) => {
            return Err(PlatformResponse::error("alias already in use"));
        }
        _ => (),
    }
    let api_keyring = Keyring {
        alias: alias.clone(),
        created_at: util::epoch(),
        description: keyring.description.clone(),
    };
    data.auth
        .create_keychain(
            api_keyring.alias.clone(),
            &*identity.username,
            &keyring.level,
        )
        .await
        .map_err(|e| {
            sentry_error!(
                "failed to send keyring<{}> to auth: {:?}",
                api_keyring.alias,
                e
            );
            PlatformResponse::error("internal error in auth")
        })?;
    if let Err(e) = data.store.store_keyring(api_keyring.clone()).await {
        sentry_error!("error in create_keyring: {:?}", e);
        return Err(PlatformResponse::error("internal error"));
    }
    Ok(PlatformResponse::ok(ApiKeyring::from::<T>(
        &identity.username,
        api_keyring,
        &data.auth,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::tests::*;
    use crate::server_suite::store::*;

    #[actix_web::main]
    #[test]
    async fn api_list_keyrings() {
        let mocked_store = Arc::new(MockStore::new().await.unwrap());
        let keyring = Keyring::new_base("test".to_string());
        mocked_store.store_keyring(keyring.clone()).await.unwrap();
        let keyring_unauth = Keyring::new_base("test_unauth".to_string());
        mocked_store.store_keyring(keyring_unauth).await.unwrap();

        let req = mock_request::<()>(mocked_store).to_http_request();
        let resp = _list_keyrings::<()>(identify_request(req))
            .await
            .ok()
            .unwrap();

        assert_eq!(
            resp.into_inner().data.unwrap(),
            vec![ApiKeyring::from::<()>(
                "test_user",
                keyring,
                &Arc::new(MockAuth::new(vec![]))
            )]
        );
    }

    #[actix_web::main]
    #[test]
    async fn api_get_keyring() {
        let mocked_store = Arc::new(MockStore::new().await.unwrap());
        let keyring = Keyring::new_base("test".to_string());
        mocked_store.store_keyring(keyring.clone()).await.unwrap();
        let keyring_unauth = Keyring::new_base("test_unauth".to_string());
        mocked_store
            .store_keyring(keyring_unauth.clone())
            .await
            .unwrap();

        {
            let req = mock_request::<()>(mocked_store.clone()).to_http_request();
            let resp = _get_keyring::<()>(
                identify_request(req),
                web::Path::from(PathId {
                    keyring_alias: keyring.alias.clone(),
                }),
            )
            .await
            .ok()
            .unwrap();

            // mock constants
            let mut api_keyring: ApiKeyring =
                ApiKeyring::from::<()>("test_user", keyring, &Arc::new(MockAuth::new(vec![])));
            api_keyring.owners = vec!["test".to_string()];
            api_keyring.level = Some("L3".to_string());

            assert_eq!(resp.into_inner().data.unwrap(), api_keyring);
        }
        {
            let req = mock_request::<()>(mocked_store.clone()).to_http_request();
            _get_keyring::<()>(
                identify_request(req),
                web::Path::from(PathId {
                    keyring_alias: keyring_unauth.alias.clone(),
                }),
            )
            .await
            .err()
            .expect("did not fail due to lack of authorization");
        }
    }

    #[actix_web::main]
    #[test]
    async fn api_create_keyring() {
        let mocked_store = Arc::new(MockStore::new().await.unwrap());

        // create confidential keyring
        let keyring: Keyring = {
            let req = mock_request::<()>(mocked_store.clone()).to_http_request();
            let resp = _create_keyring::<()>(
                identify_request(req),
                Json(IncomingKeyring {
                    alias: "test".to_string(),
                    description: "testing".to_string(),
                    level: "L4".to_string(),
                }),
            )
            .await
            .ok()
            .unwrap();

            resp.into_inner().data.unwrap().into()
        };
        // create unconfidential keyring
        {
            let req = mock_request::<()>(mocked_store.clone()).to_http_request();
            let resp = _create_keyring::<()>(
                identify_request(req),
                Json(IncomingKeyring {
                    alias: "test_nonconfidential".to_string(),
                    description: "testing".to_string(),
                    level: "L3".to_string(),
                }),
            )
            .await
            .ok()
            .unwrap();

            resp.into_inner().data.unwrap();
        };
        {
            let req = mock_request::<()>(mocked_store.clone()).to_http_request();
            _create_keyring::<()>(
                identify_request(req),
                Json(IncomingKeyring {
                    alias: "test".to_string(),
                    description: "testing".to_string(),
                    level: "L4".to_string(),
                }),
            )
            .await
            .err()
            .expect("failed to block duplicate alias");
        }

        {
            let req = mock_request::<()>(mocked_store.clone()).to_http_request();
            let resp = _get_keyring::<()>(
                identify_request(req),
                web::Path::from(PathId {
                    keyring_alias: keyring.alias.clone(),
                }),
            )
            .await
            .ok()
            .unwrap();

            // mock constants
            let mut api_keyring: ApiKeyring =
                ApiKeyring::from::<()>("test_user", keyring, &Arc::new(MockAuth::new(vec![])));
            api_keyring.owners = vec!["test".to_string()];
            api_keyring.level = Some("L3".to_string());

            assert_eq!(resp.into_inner().data.unwrap(), api_keyring);
        }
    }
}

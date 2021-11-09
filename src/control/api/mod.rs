use super::*;
pub(super) mod customer_key;
pub(super) mod keyring;
pub(super) mod secret;
use crate::server_suite::store::{CustomerKey, Keyring};
use crate::KeyhouseImpl;
use regex::Regex;

pub(super) async fn info(req: HttpRequest) -> impl Responder {
    let identity = {
        let identity = req.extensions();
        identity.get::<Identity>().unwrap().clone()
    };
    let hello_message = format!("hello {}", identity.username);
    let pr = PlatformResponse::<()> {
        error_code: 0,
        message: Some(hello_message),
        apply_url: None,
        data: None,
    };

    // generate valid json first
    // if failed, generate something similar to json but not guaranteed to be a valid json
    // bad case: username contains json meta char
    //  - Backspace
    //  - Form feed
    //  - Newline
    //  - Carriage return
    //  - Tab
    //  - Double quote
    //  - Backslash
    serde_json::to_string(&pr).unwrap_or_else(
        |_| format!("{{ \"error_code\": 0, \"message\": \"hello {}\", \"apply_url\": \"\", \"data\": null }}", identity.username)
    )
}

lazy_static! {
    static ref ALIAS_REGEX: Regex = Regex::new(r"^[a-zA-Z0-9_.-]+$").unwrap();
}

pub fn verify_alias<T: Serialize>(alias: &str) -> PlatformDataResult<(), T> {
    if !ALIAS_REGEX.is_match(alias) {
        return Err(PlatformResponse::error("invalid alias"));
    }
    Ok(())
}

impl<Y: KeyhouseImpl + 'static> ControlData<Y> {
    pub async fn authorized_keyrings<T: Serialize>(
        &self,
        identity: &Identity,
    ) -> PlatformDataResult<Vec<String>, T> {
        self.auth
            .get_authorized_keychains(&*identity.username)
            .await
            .map_err(|_| PlatformResponse::auth_error("unauthorized due to auth error", 3, None))
    }

    pub async fn check_keyring_authorization<T: Serialize>(
        &self,
        identity: &Identity,
        keyring_alias: &str,
    ) -> PlatformDataResult<AuthorizationResult, T> {
        self.auth
            .check_authorization(&*identity.username, keyring_alias)
            .await
            .map_err(|_| PlatformResponse::auth_error("unauthorized due to auth error", 3, None))
    }

    pub async fn authorized_keyring<T: Serialize>(
        &self,
        identity: &Identity,
        alias: &str,
    ) -> PlatformDataResult<Keyring, T> {
        match self.store.get_keyring(alias).await {
            Err(e) => {
                sentry_error!("error in authorized_keyring<{}>: {:?}", alias, e);
                Err(PlatformResponse::error("internal error"))
            }
            Ok(None) => Err(PlatformResponse::error("not found")),
            Ok(Some(keyring)) => {
                match self
                    .check_keyring_authorization(identity, &keyring.alias)
                    .await?
                {
                    AuthorizationResult::Ok => Ok(keyring),
                    AuthorizationResult::Unauthorized => Err(PlatformResponse::auth_error(
                        "Unauthorized".to_string(),
                        3,
                        None,
                    )),
                    AuthorizationResult::UnauthorizedLink(link) => {
                        Err(PlatformResponse::auth_error(
                            format!("Not authorized, apply here: {}", link),
                            3,
                            Some(link),
                        ))
                    }
                }
            }
        }
    }

    pub async fn authorized_key<T: Serialize>(
        &self,
        identity: &Identity,
        keyring_alias: &str,
        key_alias: &str,
    ) -> PlatformDataResult<(Keyring, CustomerKey), T> {
        let keyring = self.authorized_keyring(identity, keyring_alias).await?;
        let key = match self
            .store
            .get_customer_key_by_alias(&format!("{}/{}", keyring_alias, key_alias))
            .await
        {
            Err(e) => {
                sentry_error!("error in authorized_key<{}>: {:?}", key_alias, e);
                return Err(PlatformResponse::error("internal error"));
            }
            Ok(None) => {
                return Err(PlatformResponse::error("not found"));
            }
            Ok(Some(key)) => key,
        };
        Ok((keyring, key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aliases() {
        //^[a-zA-Z0-9_-]+$
        verify_alias::<()>("a").ok().unwrap();
        verify_alias::<()>("ggg").ok().unwrap();
        verify_alias::<()>("V").ok().unwrap();
        verify_alias::<()>("HGE").ok().unwrap();
        verify_alias::<()>("0A").ok().unwrap();
        verify_alias::<()>("A0").ok().unwrap();
        verify_alias::<()>("_test-").ok().unwrap();
        verify_alias::<()>("-test_").ok().unwrap();
        verify_alias::<()>("").err().unwrap();
        verify_alias::<()>("$").err().unwrap();
        verify_alias::<()>("/").err().unwrap();
        verify_alias::<()>(".").ok().unwrap();
    }
}

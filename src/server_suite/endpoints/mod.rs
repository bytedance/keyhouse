use super::handler::KeyhouseResponse;
use super::handler::KeyhouseService;
use crate::baseclient::ClientCoding;
use crate::customer_key::*;
use crate::event::*;
use crate::keyhouse::{self, ErrorCode};
use crate::prelude::*;
use crate::server_suite::coding::CodingItem;
use crate::server_suite::store::{
    split_last_alias, AccessControlDomain, AccessControlList, CustomerKey, DecodedSecret,
    KeyPurpose,
};
use crate::util;
use crate::KeyhouseImpl;
use crate::SERVER_CONFIG;
use prost::Message;
use spire_workload::SpiffeID;
use tonic::{Request, Status};

mod decode_data_key;
mod encode_data_key;
mod get_legacy_key;
mod get_secret;
mod get_secrets;
mod ping_pong;
mod store_secret;

impl<T: KeyhouseImpl + 'static> KeyhouseService<T> {
    pub(crate) fn authorize_acls(
        spiffe_id: Option<&SpiffeID>,
        acls: Option<&AccessControlList>,
    ) -> StdResult<(), ErrorCode> {
        if let Some(spiffe_id) = spiffe_id {
            if let Some(acls) = acls {
                let matched = acls.iter().any(|acl| acl.matches(spiffe_id));
                if matched {
                    return Ok(());
                }
            }
        }
        Err(ErrorCode::Unauthorized)
    }

    pub(crate) fn extract_alt_token(token: &str) -> (Option<SpiffeID>, Option<String>) {
        let token = match T::AlternateDataAuthProvider::authenticate_customer_key_token(token) {
            Some(s) => s,
            None => return (None, None),
        };
        let spiffe_id = token.into_spiffe_id();
        let value = serde_json::to_string(&token).ok();
        (spiffe_id, value)
    }

    pub(crate) async fn load_key_from_alias(
        &self,
        alias: &str,
    ) -> Result<StdResult<CustomerKey, ErrorCode>> {
        let key = self.store.get_customer_key_by_alias(alias).await;
        key.map(|key| match key {
            Some(key) => Ok(key),
            None => Err(ErrorCode::UnknownAlias),
        })
    }

    pub(crate) async fn load_key_from_id(
        &self,
        key_id: u32,
    ) -> Result<StdResult<CustomerKey, ErrorCode>> {
        let key = self
            .store
            .get_customer_key_by_id(key_id)
            .await
            .map(|key| match key {
                Some(key) => Ok(key),
                None => Err(ErrorCode::UnknownKey),
            })?;
        Ok(key)
    }

    pub(crate) fn get_auth_user_service(
        spiffe_id: Option<&SpiffeID>,
    ) -> (Option<String>, Option<String>) {
        spiffe_id
            .map(T::KeyhouseExt::get_spiffe_service_user)
            .unwrap_or((None, None))
    }
}

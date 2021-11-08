use super::store::OwnedStore;
use crate::keyhouse::{self, ErrorCode};
use crate::prelude::*;
use crate::server_suite::acceptor::WrappedStream;
use crate::util;
use crate::{KeyhouseImpl, Metric};
use spire_workload::SpiffeID;
use tonic::{
    transport::server::{Connected, TlsConnectInfo},
    Request, Response, Status,
};

/// The storage here lives across all incoming requests
pub struct KeyhouseService<T: KeyhouseImpl + 'static> {
    pub(crate) store: OwnedStore<T>,
}

pub(crate) struct KeyhouseResponse<T> {
    pub response: T,
    pub spiffe_id: Option<SpiffeID>,
    pub error_code: ErrorCode,
    pub target_alias: Option<String>,
}

#[allow(clippy::from_over_into)]
impl<T> Into<Response<T>> for KeyhouseResponse<T> {
    fn into(self) -> Response<T> {
        Response::new(self.response)
    }
}

impl<T: KeyhouseImpl + 'static> KeyhouseService<T> {
    pub fn new(store: OwnedStore<T>) -> Self {
        KeyhouseService { store }
    }

    pub(crate) async fn prepare_start(&self) -> Result<()> {
        tokio::spawn(super::store::intermediate_key::customer_key_recoder(
            self.store.clone(),
        ));
        tokio::spawn(super::store::customer_key_reloader(self.store.clone()));
        T::KeyhouseExt::service_load::<T>(self.store.clone()).await?;
        Ok(())
    }

    async fn get_spiffe_id<Y>(&self, request: &Request<Y>) -> StdResult<SpiffeID, Status> {
        let conn_info = request
            .extensions()
            .get::<TlsConnectInfo<<WrappedStream as Connected>::ConnectInfo>>()
            .ok_or_else(|| {
                Status::new(tonic::Code::Unauthenticated, "Invalid Client certificate")
            })?;
        let certs = &conn_info.peer_certs().ok_or_else(|| {
            Status::new(tonic::Code::Unauthenticated, "Invalid Client certificate")
        })?;
        let leaf: &tonic::transport::Certificate = certs
            .get(0)
            .ok_or_else(|| Status::new(tonic::Code::Unauthenticated, "Empty leaf certificate"))?;
        let spiffe_id = SpiffeID::from_x509_der(leaf.get_ref())
            .map_err(|e| Status::new(tonic::Code::Unauthenticated, format!("{:?}", e)))?;

        Ok(spiffe_id)
    }

    async fn wrap<
        'a,
        I,
        N,
        O: std::future::Future<Output = StdResult<KeyhouseResponse<N>, Status>>,
        F: Fn(&'a KeyhouseService<T>, Request<I>, Option<SpiffeID>, String) -> O,
    >(
        &'a self,
        endpoint: &str,
        func: F,
        raw_request: Request<I>,
    ) -> StdResult<Response<N>, Status> {
        let start = util::epoch_us();
        let ip = raw_request
            .extensions()
            .get::<TlsConnectInfo<<WrappedStream as Connected>::ConnectInfo>>()
            .map(|x| x.get_ref())
            .map(|osa| osa.map(|sa| sa.to_string()))
            .flatten()
            .unwrap_or_default();
        let spiffe_id = self.get_spiffe_id(&raw_request).await.ok();

        let result = func(self, raw_request, spiffe_id, ip).await;
        let latency = (util::epoch_us() - start) as f64 / 1000.0;

        let (auth_service, auth_user, error_code, target_alias) = if let Ok(result) = &result {
            let (auth_service, auth_user) = result
                .spiffe_id
                .as_ref()
                .map(|x| T::KeyhouseExt::get_spiffe_service_user(x))
                .unwrap_or((None, None));
            (
                auth_service,
                auth_user,
                result.error_code,
                result.target_alias.clone(),
            )
        } else {
            (None, None, ErrorCode::Unknown, None)
        };
        T::KeyhouseExt::emit_metric(Metric::DataQueryComplete {
            latency,
            endpoint: endpoint.to_string(),
            success: result.is_ok(),
            auth_service: auth_service.unwrap_or_default(),
            auth_user: auth_user.unwrap_or_default(),
            status: error_code.to_string(),
            target_alias: target_alias.unwrap_or_default(),
        });
        result.map(Into::into)
    }
}

#[tonic::async_trait]
impl<T: KeyhouseImpl + 'static> keyhouse::kms_server::Kms for KeyhouseService<T> {
    async fn encode_data_key(
        &self,
        raw_request: Request<keyhouse::EncodeDataKeyRequest>,
    ) -> StdResult<Response<keyhouse::EncodeDataKeyResponse>, Status> {
        self.wrap(
            "data_encode_data_key",
            KeyhouseService::encode_data_key_wrap,
            raw_request,
        )
        .await
    }

    async fn decode_data_key(
        &self,
        raw_request: Request<keyhouse::DecodeDataKeyRequest>,
    ) -> StdResult<Response<keyhouse::DecodeDataKeyResponse>, Status> {
        self.wrap(
            "data_decode_data_key",
            KeyhouseService::decode_data_key_wrap,
            raw_request,
        )
        .await
    }

    async fn ping_pong(
        &self,
        raw_request: Request<keyhouse::PingPongRequest>,
    ) -> StdResult<Response<keyhouse::PingPongResponse>, Status> {
        self.wrap(
            "data_ping_pong",
            KeyhouseService::ping_pong_wrap,
            raw_request,
        )
        .await
    }

    async fn get_secret(
        &self,
        raw_request: Request<keyhouse::GetSecretRequest>,
    ) -> StdResult<Response<keyhouse::GetSecretResponse>, Status> {
        self.wrap(
            "data_get_secret",
            KeyhouseService::get_secret_wrap,
            raw_request,
        )
        .await
    }

    async fn get_secrets(
        &self,
        raw_request: Request<keyhouse::GetSecretsRequest>,
    ) -> StdResult<Response<keyhouse::GetSecretsResponse>, Status> {
        self.wrap(
            "data_get_secrets",
            KeyhouseService::get_secrets_wrap,
            raw_request,
        )
        .await
    }

    async fn store_secret(
        &self,
        raw_request: Request<keyhouse::StoreSecretRequest>,
    ) -> StdResult<Response<keyhouse::StoreSecretResponse>, Status> {
        self.wrap(
            "data_store_secret",
            KeyhouseService::store_secret_wrap,
            raw_request,
        )
        .await
    }

    async fn get_legacy_key(
        &self,
        raw_request: Request<keyhouse::GetLegacyKeyRequest>,
    ) -> StdResult<Response<keyhouse::GetLegacyKeyResponse>, Status> {
        self.wrap(
            "data_get_legacy_key",
            KeyhouseService::get_legacy_key_wrap,
            raw_request,
        )
        .await
    }
}

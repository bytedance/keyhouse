use crate::prelude::*;
use crate::server_suite::config::SERVER_CONFIG;
use crate::store::OwnedStore;
use crate::Metric;
use actix_service::Service;
use actix_web::{
    dev::{Body, Response, ServiceRequest, ServiceResponse},
    error::Error,
    http::Method,
    web,
    web::Json,
    App, HttpMessage, HttpRequest, HttpResponse, HttpServer, Responder,
};
use futures::{
    future::{self, Either},
    Future,
};
use std::pin::Pin;
use std::thread;

mod api;
pub mod auth;
mod health;

use crate::event::*;
use crate::util;
use crate::KeyhouseImpl;
pub use auth::*;
pub use health::ETCD_LAST_CONTACT;
use regex::Regex;
use serde::Serialize;

async fn index(_req: HttpRequest) -> impl Responder {
    "keyhouse".to_string()
}

#[derive(Serialize, Debug)]
pub struct PlatformResponse<T: Serialize> {
    // 0 = ok, 1 = generic error (see msg), 2 = unauthenticated, 3 = unauthorized
    pub error_code: i32,
    pub message: Option<String>,
    pub apply_url: Option<String>,
    pub data: Option<T>,
}

impl<T: Serialize> PlatformResponse<T> {
    pub fn ok(data: T) -> Json<PlatformResponse<T>> {
        Json(PlatformResponse {
            error_code: 0,
            message: None,
            apply_url: None,
            data: Some(data),
        })
    }

    pub fn error(msg: impl Into<String>) -> Json<PlatformResponse<T>> {
        Json(PlatformResponse {
            error_code: 1,
            message: Some(msg.into()),
            apply_url: None,
            data: None,
        })
    }

    pub fn auth_error(
        msg: impl Into<String>,
        error_code: i32,
        apply_url: Option<String>,
    ) -> Json<PlatformResponse<T>> {
        Json(PlatformResponse {
            error_code,
            message: Some(msg.into()),
            apply_url,
            data: None,
        })
    }
}

pub type PlatformResult<T> = StdResult<Json<PlatformResponse<T>>, Json<PlatformResponse<T>>>;
pub type PlatformDataResult<T, E> = StdResult<T, Json<PlatformResponse<E>>>;

#[derive(Clone)]
pub struct Identity {
    pub username: String,
}

#[derive(Clone)]
pub struct RawJwtToken {
    pub token: String,
}

pub struct ControlData<T: KeyhouseImpl + 'static> {
    pub store: OwnedStore<T>,
    pub auth: OwnedAuth<T>,
}

pub type ActixFuture = Pin<Box<dyn Future<Output = StdResult<ServiceResponse, Error>> + 'static>>;
pub type ActixFutureLeft =
    future::Either<ActixFuture, future::Ready<StdResult<ServiceResponse, Error>>>;

pub fn early_response<R: Into<Response<Body>>>(req: ServiceRequest, response: R) -> ActixFuture {
    Box::pin(future::ok(req.into_response(response)))
}

pub fn early_response_left<R: Into<Response<Body>>>(
    req: ServiceRequest,
    response: R,
) -> ActixFutureLeft {
    future::Either::Left(early_response(req, response))
}

pub fn response_left_responder<R: Responder + 'static>(
    req: ServiceRequest,
    response: R,
) -> ActixFutureLeft {
    let (req, payload) = req.into_parts();
    let response = response.respond_to(&req);
    let req = ServiceRequest::from_parts(req, payload);
    future::Either::Left(Box::pin(async move { Ok(req.into_response(response)) }))
}

lazy_static! {
    static ref LOG_PATH_REGEX: Regex =
        Regex::new(r"/api/keyrings/([a-zA-Z0-9-_.]+)(?:/customer_key/([a-zA-Z0-9-_.]+))?(?:/secret/([a-zA-Z0-9-_.]+))?").unwrap();
}

#[actix_web::main]
pub async fn actix_main<T: KeyhouseImpl + 'static>(store: OwnedStore<T>, auth: OwnedAuth<T>) {
    let config = &SERVER_CONFIG.get().0;

    if let Some(health_check_ip) = config.health_check_ip.as_ref() {
        info!("health check spawned: {}", health_check_ip);
        let store = store.clone();
        let auth = auth.clone();
        tokio::spawn(
            HttpServer::new(move || {
                App::new()
                    .app_data(ControlData::<T> {
                        store: store.clone(),
                        auth: auth.clone(),
                    })
                    .route("/", web::get().to(index))
                    .route("/health", web::get().to(health::health::<T>))
            })
            .disable_signals()
            .bind(health_check_ip.clone())
            .expect("failed to bind health check")
            .run(),
        );
    }

    let tls_config = if config.enable_control_plane_tls {
        info!("control plane tls enabled");
        Some(SERVER_CONFIG.get().1.server_tls_config())
    } else {
        None
    };

    let mut builder = HttpServer::new(move || {
        let mut service = web::scope("/api")
            .wrap_fn(|req, srv| {
                if req.method() == Method::OPTIONS {
                    let mut response = HttpResponse::NoContent();
                    response.insert_header(("Access-Control-Allow-Origin", "*"));
                    response.insert_header((
                        "Access-Control-Allow-Methods",
                        "POST, GET, PUT, PATCH, OPTIONS, DELETE",
                    ));
                    response.insert_header(("Access-Control-Max-Age", "86400"));
                    response.insert_header(("Access-Control-Allow-Headers", "*"));
                    return early_response_left(req, response);
                }

                let jwt = req.headers().get("BS-TOKEN");
                if jwt.is_none() {
                    return response_left_responder(
                        req,
                        PlatformResponse::<()>::auth_error(
                            "invalid auth token, please refresh the page",
                            2,
                            None,
                        ),
                    );
                }
                let mut jwt = jwt.unwrap().to_str().unwrap_or("");
                if jwt.starts_with("Bearer ") {
                    jwt = &jwt[7..]
                }
                let data: &ControlData<T> = req.app_data().unwrap();

                let username = match data.auth.authenticate_user(jwt) {
                    Ok(Some(username)) => username,
                    Ok(None) => {
                        return response_left_responder(
                            req,
                            PlatformResponse::<()>::auth_error("Unauthenticated", 2, None),
                        )
                    }
                    Err(e) => {
                        info!("failed to authenticate control plane auth: {:?}", e);
                        return response_left_responder(
                            req,
                            PlatformResponse::<()>::auth_error(
                                "Failed to verify authentication",
                                2,
                                None,
                            ),
                        );
                    }
                };
                req.extensions_mut().insert(Identity { username });
                req.extensions_mut().insert(RawJwtToken {
                    token: jwt.to_string(),
                });
                Either::Left(srv.call(req))
            })
            .wrap_fn(|req, srv| {
                let path = req.path().to_string();
                let (keyring_alias, key_alias, secret_alias) = match LOG_PATH_REGEX.captures(&*path)
                {
                    Some(matcher) => (
                        matcher.get(1).map(|x| x.as_str().to_string()),
                        matcher.get(2).map(|x| x.as_str().to_string()),
                        matcher.get(3).map(|x| x.as_str().to_string()),
                    ),
                    None => (None, None, None),
                };
                let ip = req.peer_addr().map(|x| x.to_string()).unwrap_or_default();
                let xff_ip = req
                    .headers()
                    .get("x-forwarded-for")
                    .map(|x| x.to_str().unwrap_or_default().to_string());
                let log_id = req
                    .headers()
                    .get("x-tt-logid")
                    .map(|x| x.to_str().unwrap_or_default().to_string());
                let start = util::epoch_us();

                let response = srv.call(req);
                async move {
                    let response = response.await;
                    let latency = (util::epoch_us() - start) as f64 / 1000.0;
                    let username: Option<String> = response
                        .as_ref()
                        .ok()
                        .map(|response| {
                            response
                                .request()
                                .extensions()
                                .get::<Identity>()
                                .map(|x| x.username.to_string())
                        })
                        .flatten();
                    let status = response
                        .as_ref()
                        .map(|x| x.status().as_u16())
                        .unwrap_or_else(|x| x.as_response_error().status_code().as_u16());
                    T::KeyhouseExt::emit_metric(Metric::ControlQueryComplete {
                        latency,
                        endpoint: path.clone(),
                        success: status < 400,
                    });
                    LogEvent::ControlLogEvent(ControlLogEvent {
                        occurred_at: crate::util::epoch(),
                        path,
                        username,
                        ip,
                        xff_ip,
                        log_id,
                        key_alias,
                        keyring_alias,
                        secret_alias,
                        status,
                        message: None,
                    })
                    .fire::<T>();
                    response
                }
            })
            .wrap_fn(|req, srv| {
                let raw_jwt_token = req
                    .extensions()
                    .get::<RawJwtToken>()
                    .map(|x| x.token)
                    .unwrap_or_default();
                let response = srv.call(req);
                async {
                    let mut response = response.await;
                    if let Ok(response) = response.as_mut() {
                        response.headers_mut().insert(
                            "Cache-Control".parse().unwrap(),
                            "no-cache".parse().unwrap(),
                        );
                        response.headers_mut().insert(
                            "Access-Control-Allow-Origin".parse().unwrap(),
                            "*".parse().unwrap(),
                        );
                        response.headers_mut().insert(
                            "Raw-JWT-Token".parse().unwrap(),
                            raw_jwt_token.parse().unwrap(),
                        );
                    }
                    response
                }
            })
            .route("/info", web::get().to(api::info))
            .route("/keyrings", web::get().to(api::keyring::list_keyrings::<T>))
            .route(
                "/keyrings",
                web::post().to(api::keyring::create_keyring::<T>),
            )
            .route(
                "/keyrings/{keyring_alias}",
                web::get().to(api::keyring::get_keyring::<T>),
            )
            .route(
                "/keyrings/{keyring_alias}/customer_key",
                web::get().to(api::customer_key::list_customer_keys::<T>),
            )
            .route(
                "/keyrings/{keyring_alias}/customer_key",
                web::post().to(api::customer_key::create_customer_key::<T>),
            )
            .route(
                "/keyrings/{keyring_alias}/customer_key/{key_alias}",
                web::get().to(api::customer_key::get_customer_key::<T>),
            )
            .route(
                "/keyrings/{keyring_alias}/customer_key/{key_alias}",
                web::patch().to(api::customer_key::update_customer_key::<T>),
            )
            .route(
                "/keyrings/{keyring_alias}/customer_key/{key_alias}/secret",
                web::get().to(api::secret::list_secrets::<T>),
            )
            .route(
                "/keyrings/{keyring_alias}/customer_key/{key_alias}/secret/{secret_alias}",
                web::post().to(api::secret::store_secret::<T>),
            )
            .route(
                "/keyrings/{keyring_alias}/customer_key/{key_alias}/secret/{secret_alias}",
                web::delete().to(api::secret::delete_secret::<T>),
            );

        for (path, ext) in T::KeyhouseExt::add_extended_routes::<T>().into_iter() {
            service = service.route(&*path, ext);
        }
        App::new()
            .app_data(web::PayloadConfig::new(1 << 25)) // 32 MB to override default 256KB
            .app_data(web::JsonConfig::default().limit(1 << 25)) // 32 MB to override 32KB
            .app_data(ControlData::<T> {
                store: store.clone(),
                auth: auth.clone(),
            })
            .route("/", web::get().to(index))
            .route("/health", web::get().to(health::health::<T>))
            .service(service)
    })
    .disable_signals();

    builder = if let Some(tls_config) = tls_config {
        builder.bind_rustls(SERVER_CONFIG.get().0.control_plane_ip.clone(), tls_config)
    } else {
        builder.bind(SERVER_CONFIG.get().0.control_plane_ip.clone())
    }
    .expect("failed to bind control plane");

    info!(
        "starting control plane on: {}",
        SERVER_CONFIG.get().0.control_plane_ip
    );
    builder.run().await.expect("failed to start control plane");
}

pub fn spawn_control<T: KeyhouseImpl + 'static>(store: OwnedStore<T>, auth: OwnedAuth<T>) {
    thread::spawn(move || {
        actix_main(store, auth);
    });
}

// helpers for tests, used internally and in dependent crates
pub mod tests {
    use super::*;
    pub use actix_web::test::{self, TestRequest};
    pub use std::sync::Arc;

    pub fn mock_request<T: KeyhouseImpl<ControlPlaneAuth = MockAuth> + 'static>(
        store: OwnedStore<T>,
    ) -> TestRequest {
        mock_request_auth(store, Arc::new(MockAuth::new(vec!["test".to_string()])))
    }

    pub fn mock_request_auth<T: KeyhouseImpl<ControlPlaneAuth = MockAuth> + 'static>(
        store: OwnedStore<T>,
        auth: OwnedAuth<T>,
    ) -> TestRequest {
        TestRequest::app_data(TestRequest::default(), ControlData { store, auth })
    }

    pub fn identify_request(req: HttpRequest) -> HttpRequest {
        identify_request_named(req, "test")
    }

    pub fn identify_request_named(req: HttpRequest, username: &str) -> HttpRequest {
        req.extensions_mut().insert(Identity {
            username: username.to_string(),
        });
        req
    }
}

#[macro_use]
extern crate lazy_static;

use anyhow::Result;
use keyhouse::KeyhouseClient;
use keyhouse::Region;
use keyhouse::{server_suite::config::LoadedTlsBundle, start_server, SERVER_CONFIG};

use keyhouse::server_suite;
use keyhouse::store::*;
use keyhouse::KeyhouseService;
use log::*;
use spire_workload::SpiffeID;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::Duration as StdDuration;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::sleep;
use url::Url;

static FIRST_PORT: u16 = 51001;
static NEXT_TEST_PORT: AtomicU16 = AtomicU16::new(FIRST_PORT);

static CLIENT_SPIFFE_ID: &str = "spiffe://bytem-test/id:client";

fn make_client_config() -> rustls::ClientConfig {
    let identity = SpiffeID::new(CLIENT_SPIFFE_ID.parse::<Url>().unwrap()).unwrap();
    let server_identity = SERVER_CONFIG.get().1.server_identity.clone();
    spire_workload::make_client_config(
        Some(identity),
        &[b"h2".to_vec()],
        Box::new(server_identity),
        true,
    )
}

async fn init_test_server(store: OwnedStore<()>, addr: String) {
    keyhouse::server_suite::server::init_spire_workload()
        .await
        .unwrap();
    let mut new_identities = spire_workload::IDENTITIES.load().as_ref().clone();
    let client_identity =
        keyhouse::server_suite::server::prepare_bundle(&LoadedTlsBundle::new("./certs/client/"))
            .await
            .unwrap();
    new_identities.insert(
        SpiffeID::new(CLIENT_SPIFFE_ID.parse::<Url>().unwrap()).unwrap(),
        client_identity,
    );
    spire_workload::init_mock(new_identities, vec![]);
    let server_identity = SERVER_CONFIG.get().1.server_identity.clone();
    if let Err(e) = start_server(
        &addr,
        spire_workload::make_server_config(
            Some(server_identity),
            &[b"h2".to_vec()],
            Box::new(true),
            true,
        ),
        KeyhouseService::new(store),
    )
    .await
    {
        error!("error starting server: {:?}", e);
        sleep(StdDuration::from_millis(100)).await;
        std::process::exit(1); // TODO: find a way to panic in a thread and fail test (probably can be done with channels)
    }
}

async fn start_test_server(store: OwnedStore<()>) -> Region {
    let port = NEXT_TEST_PORT.fetch_add(1, Ordering::SeqCst);
    if port == FIRST_PORT {
        env_logger::Builder::from_default_env()
            .filter_level(LevelFilter::Info)
            .init();
    }
    let config = &server_suite::config::SERVER_CONFIG.get();
    let addr = format!("{}:{}", &config.0.server_address, port);
    let client_addr = format!("localhost:{}", port);
    tokio::spawn(init_test_server(store, addr.clone()));
    sleep(StdDuration::from_millis(100)).await; // TODO: if this doesn't resolve the race well enough for tests, switch to channels
    Region(client_addr.into_bytes())
}

lazy_static! {
    // basis spiffes in mock store
    static ref ACL_TEST: SpiffeID = SpiffeID::new(Url::parse("spiffe://bytem-test/id:client").unwrap()).unwrap();
    static ref ACL_FAIL_TEST: SpiffeID = SpiffeID::new(Url::parse("spiffe://bytem-test/id:client_fail").unwrap()).unwrap();
}

async fn mock_store(keys: Vec<CustomerKey>) -> Arc<MockStore<()>> {
    let store = Arc::new(MockStore::<()>::new().await.unwrap());
    store
        .store_keyring(Keyring {
            alias: "test".to_string(),
            description: "test keyring".to_string(),
            created_at: keyhouse::util::epoch(),
        })
        .await
        .unwrap();
    for key in keys.into_iter() {
        store.store_customer_key(key).await.unwrap();
    }
    store
}

async fn make_key_with_acls(
    name: String,
    encode: Option<SpiffeID>,
    decode: Option<SpiffeID>,
    sign: Option<SpiffeID>,
    verify: Option<SpiffeID>,
    get_secret: Option<SpiffeID>,
    store_secret: Option<SpiffeID>,
) -> CustomerKey {
    let mut key = CustomerKey::new_base::<()>(name).unwrap();
    if let Some(encode) = encode {
        key.acls
            .insert(AccessControlDomain::Encode, vec![encode.into()]);
        key.purpose = KeyPurpose::EncodeDecode;
    }
    if let Some(decode) = decode {
        key.acls
            .insert(AccessControlDomain::Decode, vec![decode.into()]);
        key.purpose = KeyPurpose::EncodeDecode;
    }
    if let Some(sign) = sign {
        key.acls
            .insert(AccessControlDomain::Sign, vec![sign.into()]);
        key.purpose = KeyPurpose::SignVerify;
    }
    if let Some(verify) = verify {
        key.acls
            .insert(AccessControlDomain::Verify, vec![verify.into()]);
        key.purpose = KeyPurpose::SignVerify;
    }
    if let Some(get_secret) = get_secret {
        key.acls
            .insert(AccessControlDomain::GetSecret, vec![get_secret.into()]);
        key.purpose = KeyPurpose::Secret;
    }
    if let Some(store_secret) = store_secret {
        key.acls
            .insert(AccessControlDomain::StoreSecret, vec![store_secret.into()]);
        key.purpose = KeyPurpose::Secret;
    }
    key
}

#[tokio::test]
async fn test_round_trip() -> Result<()> {
    let addr = start_test_server(
        mock_store(vec![
            make_key_with_acls(
                "test/test".to_string(),
                Some(ACL_TEST.clone()),
                Some(ACL_TEST.clone()),
                None,
                None,
                None,
                None,
            )
            .await,
        ])
        .await,
    )
    .await;

    let mut client = KeyhouseClient::<()>::connect(addr, make_client_config()).await?;

    let test_payloads: Vec<Vec<u8>> = vec![
        vec![0x00, 0x11, 0x22, 0x33],
        vec![
            0x00, 0x11, 0x22, 0x33, 0x00, 0x11, 0x22, 0x33, 0x00, 0x11, 0x22, 0x33, 0x00, 0x11,
            0x22, 0x33, 0x00, 0x11, 0x22, 0x33,
        ],
    ];

    for test_payload in test_payloads.into_iter() {
        let encoded = client
            .encode_data("test/test".to_string(), test_payload.clone())
            .await
            .unwrap();

        let decodeed = client.decode_data(encoded.clone()).await.unwrap();

        assert_eq!(decodeed, test_payload);
    }

    assert_eq!(
        client
            .get_legacy_key("test/test".to_string())
            .await
            .unwrap()
            .len(),
        32
    );

    Ok(())
}

#[tokio::test]
async fn test_branch_round_trip() -> Result<()> {
    let addr = start_test_server(
        mock_store(vec![
            make_key_with_acls(
                "test/test".to_string(),
                Some(ACL_TEST.clone()),
                Some(ACL_TEST.clone()),
                None,
                None,
                None,
                None,
            )
            .await,
        ])
        .await,
    )
    .await;
    assert!(addr.url::<()>().unwrap().starts_with("https://localhost"));

    let addr2 = format!(
        "localtest.me{}",
        &addr.url::<()>().unwrap()["https://localhost".len()..]
    ); // tonic doesn't work with ip addresses...

    let test_payloads: Vec<Vec<u8>> = vec![
        vec![0x00, 0x11, 0x22, 0x33],
        vec![
            0x00, 0x11, 0x22, 0x33, 0x00, 0x11, 0x22, 0x33, 0x00, 0x11, 0x22, 0x33, 0x00, 0x11,
            0x22, 0x33, 0x00, 0x11, 0x22, 0x33,
        ],
    ];

    for test_payload in test_payloads.into_iter() {
        let mut client = KeyhouseClient::<()>::connect(addr.clone(), make_client_config())
            .await
            .unwrap();
        let mut client2 =
            KeyhouseClient::<()>::connect(Region(addr2.clone().into_bytes()), make_client_config())
                .await
                .unwrap();

        let encodeed1 = client
            .encode_data("test/test".to_string(), test_payload.clone())
            .await
            .unwrap();
        let encodeed2 = client2
            .encode_data("test/test".to_string(), test_payload.clone())
            .await
            .unwrap();
        assert_eq!(client.secondary_count(), 0);
        assert_eq!(client2.secondary_count(), 0);

        let decodeed1 = client.decode_data(encodeed2.clone()).await.unwrap();
        let decodeed2 = client2.decode_data(encodeed1.clone()).await.unwrap();

        assert_eq!(client.secondary_count(), 1);
        assert_eq!(client2.secondary_count(), 1);
        assert_eq!(decodeed1, test_payload);
        assert_eq!(decodeed2, test_payload);
    }

    Ok(())
}
#[tokio::test]
async fn test_unauthorized_encode_decode() -> Result<()> {
    let addr = start_test_server(
        mock_store(vec![
            make_key_with_acls(
                "test/test_none".to_string(),
                Some(ACL_FAIL_TEST.clone()),
                None,
                None,
                None,
                None,
                None,
            )
            .await,
            make_key_with_acls(
                "test/test_none2".to_string(),
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .await,
            make_key_with_acls(
                "test/test_encode".to_string(),
                Some(ACL_TEST.clone()),
                Some(ACL_FAIL_TEST.clone()),
                None,
                None,
                None,
                None,
            )
            .await,
            make_key_with_acls(
                "test/test_encode2".to_string(),
                Some(ACL_TEST.clone()),
                None,
                None,
                None,
                None,
                None,
            )
            .await,
        ])
        .await,
    )
    .await;

    let mut client = KeyhouseClient::<()>::connect(addr, make_client_config()).await?;

    let test_payload: Vec<u8> = vec![
        0x00, 0x11, 0x22, 0x33, 0x00, 0x11, 0x22, 0x33, 0x00, 0x11, 0x22, 0x33, 0x00, 0x11, 0x22,
        0x33, 0x00, 0x11, 0x22, 0x33,
    ];

    client
        .encode_data("test/test_none".to_string(), test_payload.clone())
        .await
        .expect_err("expected to be unauthorized");
    client
        .encode_data("test/test_none2".to_string(), test_payload.clone())
        .await
        .expect_err("expected to be unauthorized");
    let encodeed = client
        .encode_data("test/test_encode".to_string(), test_payload.clone())
        .await
        .unwrap();
    client
        .decode_data(encodeed.clone())
        .await
        .expect_err("expected to be unauthorized");
    let encodeed = client
        .encode_data("test/test_encode2".to_string(), test_payload.clone())
        .await
        .unwrap();
    client
        .decode_data(encodeed.clone())
        .await
        .expect_err("expected to be unauthorized");

    Ok(())
}

#[tokio::test]
async fn test_unknown_key() -> Result<()> {
    let addr = start_test_server(
        mock_store(vec![
            make_key_with_acls(
                "test/test".to_string(),
                Some(ACL_TEST.clone()),
                Some(ACL_TEST.clone()),
                Some(ACL_TEST.clone()),
                Some(ACL_TEST.clone()),
                None,
                None,
            )
            .await,
        ])
        .await,
    )
    .await;

    let mut client = KeyhouseClient::<()>::connect(addr, make_client_config()).await?;

    let encodeed = client
        .encode_data("test/test2".to_string(), vec![0x00, 0x11, 0x22, 0x33])
        .await;
    assert!(encodeed.is_err());

    Ok(())
}

#[tokio::test]
async fn test_ping_pong() -> Result<()> {
    let addr = start_test_server(mock_store(vec![]).await).await;

    let mut client = KeyhouseClient::<()>::connect(addr, make_client_config()).await?;

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();

    let ponged = client.ping_pong(timestamp).await?;
    assert_eq!(timestamp, ponged);

    Ok(())
}

#[tokio::test]
async fn test_secret_round_trip() -> Result<()> {
    let addr = start_test_server(
        mock_store(vec![
            make_key_with_acls(
                "test/test".to_string(),
                None,
                None,
                None,
                None,
                Some(ACL_TEST.clone()),
                Some(ACL_TEST.clone()),
            )
            .await,
            make_key_with_acls(
                "test/test2".to_string(),
                None,
                None,
                None,
                None,
                Some(ACL_TEST.clone()),
                None,
            )
            .await,
            make_key_with_acls(
                "test/test3".to_string(),
                None,
                None,
                None,
                None,
                Some(ACL_TEST.clone()),
                Some(ACL_TEST.clone()),
            )
            .await,
        ])
        .await,
    )
    .await;

    let mut client = KeyhouseClient::<()>::connect(addr, make_client_config()).await?;

    client
        .get_secret("test/test/test".to_string())
        .await
        .expect_err("secret 'test/test/test' should not exist");
    client
        .store_secret("test/test/test".to_string(), "test_secret".to_string())
        .await
        .unwrap();

    assert_eq!(
        &client
            .get_secret("test/test/test".to_string())
            .await
            .unwrap(),
        "test_secret"
    );

    client
        .store_secret("test/test/test".to_string(), "test_secret2".to_string())
        .await
        .unwrap();
    assert_eq!(
        &client
            .get_secret("test/test/test".to_string())
            .await
            .unwrap(),
        "test_secret2"
    );

    client
        .store_secret("test/test/test2".to_string(), "test_secret3".to_string())
        .await
        .unwrap();
    client
        .store_secret("test/test3/test3".to_string(), "test_secret4".to_string())
        .await
        .unwrap();

    client
        .store_secret("test/test/test2_empty".to_string(), "".to_string())
        .await
        .unwrap();
    client
        .store_secret("test/test3/test3_empty".to_string(), "".to_string())
        .await
        .unwrap();

    let all_secrets = client.get_secrets("test/test".to_string()).await.unwrap();
    assert_eq!(all_secrets.len(), 3);
    assert_eq!(all_secrets.get("test").unwrap(), "test_secret2");
    assert_eq!(all_secrets.get("test2").unwrap(), "test_secret3");
    assert_eq!(all_secrets.get("test2_empty").unwrap(), "");

    let all_secrets = client.get_secrets("".to_string()).await.unwrap();
    assert_eq!(all_secrets.len(), 5);
    assert_eq!(all_secrets.get("test/test/test").unwrap(), "test_secret2");
    assert_eq!(all_secrets.get("test/test/test2").unwrap(), "test_secret3");
    assert_eq!(all_secrets.get("test/test/test2_empty").unwrap(), "");
    assert_eq!(all_secrets.get("test/test3/test3").unwrap(), "test_secret4");
    assert_eq!(all_secrets.get("test/test3/test3_empty").unwrap(), "");

    client
        .get_secret("test/test2/test".to_string())
        .await
        .expect_err("secret 'test' should not exist");
    client
        .store_secret("test/test2/test".to_string(), "test_secret".to_string())
        .await
        .expect_err("secret 'test/test2/test' should not get created");
    Ok(())
}

#[tokio::test]
async fn test_read_only() -> Result<()> {
    let addr = start_test_server(Arc::new(MaskStore::new(
        mock_store(vec![
            make_key_with_acls(
                "test/test".to_string(),
                None,
                None,
                None,
                None,
                Some(ACL_TEST.clone()),
                Some(ACL_TEST.clone()),
            )
            .await,
        ])
        .await,
        MaskMode::ReadOnly,
    )))
    .await;

    let mut client = KeyhouseClient::<()>::connect(addr, make_client_config()).await?;

    client
        .get_secret("test/test/test".to_string())
        .await
        .expect_err("secret 'test/test/test' should not exist");
    client
        .store_secret("test/test/test".to_string(), "test_secret".to_string())
        .await
        .expect_err("shouldn't be able store secret in read only mode");

    Ok(())
}

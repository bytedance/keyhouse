use super::*;

#[test]
fn test_customer_key_upgrade() {
    let raw_key = r#"{"id":1739243545,"alias":"test_ring/test_key","created_at":1606861284889,"updated_at":1606861284889,"description":"","purpose":"EncodeDecode","acls":{},"status":"Enabled","sensitives":{"seed":"AwQFBgcICQADBAUGBwgJAAMEBQYHCAkAAwQFBgcICQE=","keys":["BwYFBAMCAQAHBgUEAwIBAAcGBQQDAgEABwYFBAMCAQE="],"legacy_key":{"data_key":"AwQFBgcICQADBAUGBwgJAAMEBQYHCAkAAwQFBgcICQE="},"intermediate_key":{"id":"ea554e3d-90a6-4ee7-a8c7-14729e0c02b7","item":"","created_at":1606861284889,"master_key_id":""}},"user_authorization_data":[]}"#;
    let _key = serde_json::from_str::<CustomerKey>(raw_key).unwrap();
}

#[test]
fn test_keyring_upgrade() {
    let raw_keyring = r#"{"alias":"test_ring","created_at":1606861516539,"description":""}"#;
    let _keyring = serde_json::from_str::<Keyring>(raw_keyring).unwrap();
}

#[test]
fn test_secret_upgrade() {
    let raw_secret = r#"{"alias":"test_ring/test_key/test_secret","value":"zliw4+gYvk5H0cmcwDnBfVx0062cIiNGBW+buy1x4Vg=","created_at":1606861606971,"updated_at":1606861606971}"#;
    let _secret = serde_json::from_str::<Secret>(raw_secret).unwrap();
}

#[test]
fn test_intermediate_key_upgrade() {
    let intermediate_key = IntermediateKey {
        id: Uuid::new_v4(),
        item: vec![],
        created_at: crate::util::epoch(),
        master_key_id: "".to_string(),
        decoded: None,
    };

    let serialized = serde_json::to_string(&intermediate_key).unwrap();

    let deserialized = serde_json::from_str::<IntermediateKey>(&serialized).unwrap();

    assert_eq!(intermediate_key, deserialized);

    let raw_key = r#"{"id":"9c04915b-85e4-45a0-87b6-e75e71b12a06","item":"","created_at":1606862917644,"master_key_id":""}"#;
    let key = serde_json::from_str::<IntermediateKey>(raw_key).unwrap();

    let serialized = serde_json::to_string(&key).unwrap();
    assert_eq!(serialized, raw_key);
}

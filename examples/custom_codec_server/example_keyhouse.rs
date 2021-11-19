use keyhouse::codec::aes256gcm::AES256GCMCodecItem;
use keyhouse::control;
use keyhouse::master_key::mock::MockMasterKey;

#[derive(Debug, Clone)]
pub struct ExampleKeyhouse;

impl keyhouse::KeyhouseImpl for ExampleKeyhouse {
    type MasterKeyProvider = MockMasterKey;
    type CustomerItem = AES256GCMCodecItem;
    type IntermediateItem = AES256GCMCodecItem;
    type ClientCoding = AES256GCMCodecItem;
    type ControlPlaneAuth = control::MockAuth;
    type AlternateDataAuthToken = ();
    type AlternateDataAuthProvider = ();
    type IdentityCombiner = ();
    type KeyhouseExt = ();
}

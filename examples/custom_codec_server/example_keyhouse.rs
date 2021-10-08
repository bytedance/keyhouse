use keyhouse::master_key::mock::MockMasterKey;
use keyhouse::control;
use crate::codec::AES256GCMCodecItem;

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




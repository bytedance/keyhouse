use keyhouse::master_key::mock::MockMasterKey;
use keyhouse::control;

#[derive(Debug, Clone)]
pub struct ExampleKeyhouse;

impl keyhouse::KeyhouseImpl for ExampleKeyhouse {
    type MasterKeyProvider = MockMasterKey;
    type CustomerItem = ();
    type IntermediateItem = ();
    type ClientCoding = ();
    type ControlPlaneAuth = control::MockAuth;
    type AlternateDataAuthToken = ();
    type AlternateDataAuthProvider = ();
    type IdentityCombiner = ();
    type KeyhouseExt = ();
}




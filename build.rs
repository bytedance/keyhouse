fn main() {
    tonic_build::compile_protos("proto/keyhouse.proto").unwrap();
    prost_build::compile_protos(&["proto/key.proto"], &["src/", "proto/"]).unwrap();
}

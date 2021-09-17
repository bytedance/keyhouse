# Keyhouse

Keyhouse is a skeleton of general-purpose Key Management System. Keyhouse is not an off-the-shelf system, and it's not ready for production. It's a skeleton of KMS.

- Keyhouse depends on Spire based zero trust infrastructure.
- Keyhouse provides a control plane for users to manage their Customer Keys, and a data plane which responds to data key encoding/decoding requests for data encryption and decryption.
- Keyhouse provides a "secret service" which stores a piece of data and responds to inqueries.
- Keyhouse uses etcd for stage.

More info can be found in the CNCF Cloud Native Rust Day 2021 presentation [pdf](https://static.sched.com/hosted_files/cloudnativerustdayeu21/55/Keyhouse-Bruce-Ding-Shekyan.pdf) and [video](https://www.youtube.com/watch?v=O_diNCN5e4w).

Keyhouse is only a Rust `lib` (not a `bin`). To implement a real KMS, you *must* implement the `KeyhouseImpl` trait:

```rust
pub trait KeyhouseImpl: Send + Sync + Clone + std::fmt::Debug {
    type MasterKeyProvider: MasterKeyProvider + 'static; // Master key provider
    type CustomerItem: CodingItem + 'static;             // Customer Key codec
    type IntermediateItem: CodingItem + 'static;         // Intermediate Key codec
    type ClientCoding: ClientCoding + 'static;           // Data Key codec
    type ControlPlaneAuth: ControlPlaneAuth + 'static;   // Control plane authentication/authorization
    type AlternateDataAuthToken: AlternateDataAuthToken + 'static; // Secondary token-based authentication
    type AlternateDataAuthProvider: AlternateDataAuthProvider<Self::AlternateDataAuthToken> + 'static;
    type KeyhouseExt: KeyhouseExt + 'static;             // Handy functions for regioning/logging/authorization
}
```

We will provide a reference implementation in the future to provide:

- AES-256-GCM encryption for IntermediateKey/CustomerKey/DataKey/Secrets
- Go/C++/Python/Java client SDKs
- Sample setup of Spire based zero trust infrastructure and Keyhouse's integration

## Documents

- [Keyhouse Encryption](docs/encryption.md)
- [Keyhouse SPIFFE Integration](docs/spiffe.md)
- [Keyhouse Backend Storage](docs/store.md)
- [Keyhouse Data Plane](docs/data_plane.md)
- [Keyhouse Control Plane](docs/control_plane.md)

## Project structure

```plaintext
.
├── Cargo.lock              # dependency lock file
├── Cargo.toml              # main Cargo.toml
├── Readme.md
├── build.rs                # project build script
├── certs                   # dummy certificate for testing
├── conf                    # dummy configurations
├── docs                    # open source documentation
├── examples                # sample server
├── proto                   # grpc proto definition
├── src                     # source code
├── test_etcd               # scripts to launch testing etcd service
├── tests                   # self-contained end-to-end roundtrip setup
└── vendor                  # vendored dependencies
```

## Build

The default `cargo build` only builds the library.

## Example server

```sh
cargo build --examples
```

The output binary is at `./target/debug/examples/server`. This example does not contain real crypto primitives. It is intentional, as every user might have their own encryption standard.

```rust
fn encode_data_with_iv(&mut self, mut input: Vec<u8>, _iv: &[u8]) -> Result<Vec<u8>> {
    if !input.is_empty() {
        input[0] = input[0].wrapping_add(1);
    }
    input.reverse();
    Ok(input)
}

fn decode_data_with_iv(&mut self, mut input: Vec<u8>, _iv: &[u8]) -> Result<Vec<u8>> {
    input.reverse();
    if !input.is_empty() {
        input[0] = input[0].wrapping_sub(1);
    }
    Ok(input)
}
```

## Testing

First, make sure you have this line in your `/etc/hosts`:

```sh
127.0.0.1 localtest.me
```

Then, start an etcd using `./test_etcd/local.sh` and keep it running. Next, run

```sh
cargo test
```

## Authors

- [Lingxiang "LinG" Wang](https://github.com/w93163red)
- [Maxwell Bruce](https://github.com/Protryon)
- [Ruide Zhang](https://github.com/Ruide)
- [Sergey Shekyan](https://github.com/shekyan)
- [Yu Ding](https://github.com/dingelish)

and the fine folks at [ByteDance](https://bytedance.com/)


## License

Apache 2.0

#![recursion_limit = "256"]
#![allow(unreachable_patterns)]
#[macro_use]
extern crate log;

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate futures;

#[macro_use]
extern crate anyhow;

#[macro_use]
pub mod event;

#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;

pub mod util;

pub mod baseclient;
pub mod client_suite;
pub mod control;
mod customer_key;
mod keyhouse;
pub mod server_suite;
pub use baseclient::Region;
pub use client_suite::client::KeyhouseClient;
pub use server_suite::handler::KeyhouseService;
pub use server_suite::server::start_server;
pub use server_suite::store;
pub use server_suite::store::intermediate_key;
pub mod codec;
pub mod concrete;
pub mod master_key;
pub mod prelude;
pub mod result;
pub mod server;

pub use concrete::KeyhouseImpl;

pub use concrete::*;

pub use server_suite::config::SERVER_CONFIG;

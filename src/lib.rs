//! Code shared by the relay (`src/main.rs`), the desktop client (`src/bin/sap-adt-mcp-client.rs`)
//! and the integration tests: the one-time links, the tunnel wire format, the inner TLS of the
//! end-to-end channel and its keys, owner-only file storage, the smol runtime glue and the HTTPS
//! client. Each binary uses only part of it, which is why it is a library and not included with
//! `#[path]`.

pub mod https;
pub mod inner_tls;
pub mod keys;
pub mod link;
pub mod rt;
pub mod storage;
#[cfg(test)]
mod test_plugin;
pub mod token;
pub mod tunnel_proto;

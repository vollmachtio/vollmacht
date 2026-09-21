//! Experimental, ephemeral localhost passkey probe. Never issues Human Mandates.

pub mod ceremony;
pub mod http;

pub const ORIGIN: &str = "http://localhost:8374";
pub const HOST: &str = "localhost:8374";

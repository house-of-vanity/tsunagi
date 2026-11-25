//! The Android application. Mesh state belongs to one service-owned Rust agent.

pub mod dns;
mod monitor;
pub mod plan;

#[cfg(target_os = "android")]
mod android;
pub mod service;
#[cfg(test)]
mod tests;
#[cfg(unix)]
pub mod tun;
pub mod view;

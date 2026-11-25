//! KeyRelay receiver: presents a FIDO security key to the host over USB HID and
//! relays requests to the paired phone (docs/relay-contract.md).

pub mod core;
pub mod ctaphid;
pub mod keyinfo;

#[cfg(test)]
mod core_tests;

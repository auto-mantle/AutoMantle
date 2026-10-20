#[cfg(target_os = "linux")]
mod backend;
#[cfg(target_os = "linux")]
mod body;
#[cfg(target_os = "linux")]
mod credentials;
#[cfg(target_os = "linux")]
mod hypervisor_api;
#[cfg(target_os = "linux")]
mod injection;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
mod machines;
#[cfg(target_os = "linux")]
mod manager;
#[cfg(target_os = "linux")]
mod network_policy;
#[cfg(target_os = "linux")]
mod packet_gate;
#[cfg(target_os = "linux")]
mod proxy;
#[cfg(target_os = "linux")]
mod request_lifecycle;
mod sandbox;
#[cfg(target_os = "linux")]
mod storage;
#[cfg(target_os = "linux")]
mod tls;
#[cfg(target_os = "linux")]
mod transport;

use std::process::ExitCode;

fn main() -> ExitCode {
    match sandbox::run_cli(std::env::args().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("automantle-gateway: {error}");
            ExitCode::FAILURE
        }
    }
}

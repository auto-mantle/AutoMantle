use std::process::ExitCode;

fn main() -> ExitCode {
    match automantle_gateway::sandbox::run_cli(std::env::args().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("automantle-gateway: {error}");
            ExitCode::FAILURE
        }
    }
}

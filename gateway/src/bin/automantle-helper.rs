#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args == ["version"] {
        println!("automantle-helper {}", env!("CARGO_PKG_VERSION"));
        return std::process::ExitCode::SUCCESS;
    }
    if !args.is_empty() {
        eprintln!("automantle-helper: expected version or no arguments");
        return std::process::ExitCode::FAILURE;
    }
    match automantle_gateway::privileged::serve() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("automantle-helper: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("automantle-helper requires Linux");
    std::process::ExitCode::FAILURE
}

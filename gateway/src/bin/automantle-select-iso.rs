fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "linux")]
    {
        use ashpd::desktop::file_chooser::{FileFilter, SelectedFiles};
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let path = runtime.block_on(async {
            let request = SelectedFiles::open_file()
                .title("Select OS installer ISO")
                .multiple(false)
                .filter(FileFilter::new("OS installer ISO").glob("*.[iI][sS][oO]"))
                .send()
                .await?;
            match request.response() {
                Ok(files) => files
                    .uris()
                    .first()
                    .map(|uri| {
                        uri.to_file_path()
                            .map_err(|_| "The desktop chooser returned a non-local file".into())
                    })
                    .transpose(),
                Err(ashpd::Error::Response(ashpd::desktop::ResponseError::Cancelled)) => Ok(None),
                Err(error) => Err(Box::<dyn std::error::Error>::from(error)),
            }
        })?;
        println!("{}", serde_json::json!({"path": path}));
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("AutoMantle requires a Linux desktop session");
        std::process::exit(1);
    }
    Ok(())
}

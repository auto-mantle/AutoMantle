//! Maintainer tool for assembling QEMU's Linux release files.
use std::{
    collections::BTreeSet,
    env,
    error::Error,
    fs,
    path::{Path, PathBuf},
    process::{Command, ExitCode},
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn copy_tree(source: &Path, destination: &Path, active: &mut BTreeSet<PathBuf>) -> Result<()> {
    let metadata = fs::metadata(source)?; // Follow distribution firmware symlinks.
    if metadata.is_file() {
        fs::copy(source, destination)?;
    } else if metadata.is_dir() {
        let canonical = fs::canonicalize(source)?;
        if !active.insert(canonical.clone()) {
            return Err(format!("directory symlink cycle: {}", source.display()).into());
        }
        fs::create_dir_all(destination)?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            copy_tree(&entry.path(), &destination.join(entry.file_name()), active)?;
        }
        fs::set_permissions(destination, metadata.permissions())?;
        active.remove(&canonical);
    } else {
        return Err(format!("unsupported QEMU file: {}", source.display()).into());
    }
    Ok(())
}

fn dependencies(output: &str) -> Result<Vec<PathBuf>> {
    let mut result = Vec::new();
    for line in output.lines() {
        if line.contains("=> not found") {
            return Err(format!("unresolved QEMU library: {}", line.trim()).into());
        }
        let value = line
            .split_once("=>")
            .map_or(line, |(_, value)| value)
            .trim();
        if value.starts_with('/') {
            let path = value
                .rsplit_once(" (0x")
                .map_or(value, |(path, _)| path)
                .trim();
            result.push(PathBuf::from(path));
        }
    }
    Ok(result)
}

fn library_dependencies(source: &Path) -> Result<Vec<PathBuf>> {
    let output = Command::new("ldd")
        .env("LC_ALL", "C")
        .arg(source)
        .output()?;
    let stdout = String::from_utf8(output.stdout)?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success()
        && !stdout.contains("statically linked")
        && !stderr.contains("statically linked")
    {
        return Err(format!("ldd failed for {}: {stdout}{stderr}", source.display()).into());
    }
    dependencies(&stdout)
}

fn copy_firmware(qemu_data: &Path, seabios: &Path, destination: &Path) -> Result<()> {
    let mut active = BTreeSet::new();
    copy_tree(qemu_data, destination, &mut active)?;
    // QEMU's -L option searches one directory. Ubuntu installs SeaBIOS separately.
    copy_tree(seabios, destination, &mut active)?;
    for required in ["bios-256k.bin", "vgabios-stdvga.bin"] {
        if !destination.join(required).is_file() {
            return Err(format!("required QEMU firmware is missing: {required}").into());
        }
    }
    Ok(())
}

fn bundle(destination: &Path) -> Result<()> {
    if env::consts::OS != "linux" || env::consts::ARCH != "x86_64" {
        return Err("QEMU releases must be assembled on Linux x86_64".into());
    }
    let binary = env::split_paths(&env::var_os("PATH").ok_or("PATH is required")?)
        .map(|directory| directory.join("qemu-system-x86_64"))
        .find(|path| path.is_file())
        .ok_or("qemu-system-x86_64 is not on PATH")?;
    fs::create_dir(destination)?;
    fs::create_dir(destination.join("bin"))?;
    fs::create_dir(destination.join("lib"))?;
    // Use GLib's built-in local filesystem support, without loading host GVfs plugins.
    fs::create_dir(destination.join("gio-modules"))?;
    fs::copy(&binary, destination.join("bin/qemu-system-x86_64"))?;
    let modules = Path::new("/usr/lib/x86_64-linux-gnu/qemu");
    let mut active = BTreeSet::new();
    copy_tree(modules, &destination.join("modules"), &mut active)?;
    copy_firmware(
        Path::new("/usr/share/qemu"),
        Path::new("/usr/share/seabios"),
        &destination.join("share/qemu"),
    )?;
    let mut queue = vec![binary];
    for entry in fs::read_dir(modules)? {
        let path = entry?.path();
        if path.extension().is_some_and(|extension| extension == "so") {
            queue.push(path);
        }
    }
    let mut seen = BTreeSet::new();
    while let Some(source) = queue.pop() {
        if !seen.insert(source.clone()) {
            continue;
        }
        for dependency in library_dependencies(&source)? {
            let target = destination
                .join("lib")
                .join(dependency.file_name().ok_or("invalid library path")?);
            if !target.exists() {
                fs::copy(&dependency, target)?;
                queue.push(dependency);
            }
        }
    }
    let notice = Path::new("/usr/share/doc/qemu-system-common/copyright");
    if notice.is_file() {
        fs::copy(notice, destination.join("COPYRIGHT"))?;
    }
    Ok(())
}

fn main() -> ExitCode {
    let args = env::args_os().skip(1).collect::<Vec<_>>();
    let result = match args.as_slice() {
        [destination] => bundle(Path::new(destination)),
        _ => Err("usage: automantle-bundle-qemu DESTINATION".into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("QEMU packaging failed: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_libraries_and_loader_while_ignoring_virtual_entries() {
        let paths = dependencies("linux-vdso.so.1 (0x123)\n libgtk.so => /lib/libgtk.so (0x456)\n /lib64/ld-linux-x86-64.so.2 (0x789)\n").unwrap();
        assert_eq!(
            paths,
            vec![
                PathBuf::from("/lib/libgtk.so"),
                PathBuf::from("/lib64/ld-linux-x86-64.so.2")
            ]
        );
        assert!(dependencies("libmissing.so => not found\n").is_err());
        assert!(dependencies("statically linked\n").unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn copies_symlink_targets_and_preserves_executable_permissions() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let base = env::temp_dir().join(format!("automantle-qemu-copy-{}", std::process::id()));
        fs::create_dir(&base).unwrap();
        let source = base.join("source");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("firmware"), b"firmware data").unwrap();
        fs::set_permissions(source.join("firmware"), fs::Permissions::from_mode(0o755)).unwrap();
        symlink("firmware", source.join("alias")).unwrap();
        let destination = base.join("copied");
        copy_tree(&source, &destination, &mut BTreeSet::new()).unwrap();
        assert_eq!(
            fs::read(destination.join("alias")).unwrap(),
            b"firmware data"
        );
        assert!(
            !fs::symlink_metadata(destination.join("alias"))
                .unwrap()
                .is_symlink()
        );
        assert_eq!(
            fs::metadata(destination.join("alias"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
        symlink(".", source.join("cycle")).unwrap();
        assert!(copy_tree(&source, &base.join("cycle-copy"), &mut BTreeSet::new()).is_err());
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn firmware_is_collected_in_the_directory_qemu_actually_searches() {
        let base = env::temp_dir().join(format!("automantle-firmware-test-{}", std::process::id()));
        let qemu = base.join("qemu");
        let seabios = base.join("seabios");
        fs::create_dir_all(&qemu).unwrap();
        fs::create_dir(&seabios).unwrap();
        fs::write(qemu.join("keymap"), b"map").unwrap();
        fs::write(seabios.join("bios-256k.bin"), b"bios").unwrap();
        fs::write(seabios.join("vgabios-stdvga.bin"), b"vga").unwrap();
        let output = base.join("bundle/share/qemu");
        copy_firmware(&qemu, &seabios, &output).unwrap();
        assert_eq!(fs::read(output.join("bios-256k.bin")).unwrap(), b"bios");
        assert_eq!(fs::read(output.join("vgabios-stdvga.bin")).unwrap(), b"vga");
        assert!(output.join("keymap").is_file());
        fs::remove_file(seabios.join("bios-256k.bin")).unwrap();
        assert!(copy_firmware(&qemu, &seabios, &base.join("incomplete")).is_err());
        fs::remove_dir_all(base).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn launcher_uses_bundled_firmware_and_excludes_host_gio_modules() {
        use std::os::unix::fs::PermissionsExt;
        let base = env::temp_dir().join(format!("automantle qemu launcher {}", std::process::id()));
        fs::create_dir_all(base.join("bin")).unwrap();
        fs::create_dir_all(base.join("qemu/lib")).unwrap();
        let launcher = base.join("bin/automantle-qemu");
        fs::write(&launcher, include_str!("automantle-qemu")).unwrap();
        let loader = base.join("qemu/lib/ld-linux-x86-64.so.2");
        fs::write(&loader, "#!/usr/bin/env bash\nprintf '%s\\n' \"$GIO_MODULE_DIR\" \"${GIO_EXTRA_MODULES-unset}\" \"$GIO_USE_VFS\" \"$GSETTINGS_BACKEND\" \"$@\"\n").unwrap();
        fs::set_permissions(&loader, fs::Permissions::from_mode(0o755)).unwrap();
        let output = Command::new("bash")
            .arg(&launcher)
            .arg("--version")
            .env("GIO_MODULE_DIR", "/host/modules")
            .env("GIO_EXTRA_MODULES", "/host/extra-modules")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        let lines = stdout.lines().collect::<Vec<_>>();
        assert_eq!(lines[0], base.join("qemu/gio-modules").to_str().unwrap());
        assert_eq!(&lines[1..4], &["unset", "local", "memory"]);
        let bios = base.join("qemu/share/qemu/bios-256k.bin");
        assert!(
            lines
                .windows(2)
                .any(|pair| pair == ["-bios", bios.to_str().unwrap()])
        );
        assert_eq!(lines.last(), Some(&"--version"));
        fs::remove_dir_all(base).unwrap();
    }
}

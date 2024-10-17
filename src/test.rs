#[allow(unused_imports)]
use anyhow::Error;

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn main() -> Result<(), Error> {
    panic!("This program is not intended to run on this platform.");
}

#[cfg(target_os = "linux")]
fn main() -> Result<(), Error> {
    use std::process::Command as StdCommand;
    use users::get_effective_uid;

    let install_path = std::env::current_exe()
        .unwrap()
        .with_file_name("install-service");

    let uninstall_path = std::env::current_exe()
        .unwrap()
        .with_file_name("uninstall-service");

    if !install_path.exists() {
        eprintln!("The install-service binary not found.");
        std::process::exit(2);
    }

    if !uninstall_path.exists() {
        eprintln!("The uninstall-service binary not found.");
        std::process::exit(2);
    }

    let install_shell: String = install_path.to_string_lossy().replace(" ", "\\ ");
    let uninstall_shell: String = uninstall_path.to_string_lossy().replace(" ", "\\ ");

    let elevator = linux_elevator();
    let _ = match get_effective_uid() {
        0 => StdCommand::new(uninstall_path).status()?,
        _ => StdCommand::new(elevator)
            .arg("sh")
            .arg("-c")
            .arg(uninstall_shell)
            .status()?,
    };

    let elevator = linux_elevator();
    let status = match get_effective_uid() {
        0 => StdCommand::new(install_shell).status()?,
        _ => StdCommand::new(elevator)
            .arg("sh")
            .arg("-c")
            .arg(install_shell)
            .status()?,
    };

    if !status.success() {
        eprintln!(
            "failed to install service with status {}",
            status.code().unwrap()
        );
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_elevator() -> &'static str {
    use std::process::Command;
    match Command::new("which").arg("pkexec").output() {
        Ok(output) => {
            if output.stdout.is_empty() {
                "sudo"
            } else {
                "pkexec"
            }
        }
        Err(_) => "sudo",
    }
}

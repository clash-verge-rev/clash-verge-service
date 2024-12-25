#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn main() {
    panic!("This program is not intended to run on this platform.");
}

#[cfg(not(windows))]
use anyhow::Error;

// Helper function for command execution

#[cfg(target_os = "macos")]
fn main() -> Result<(), Error> {
    use clash_verge_service::utils::run_command;
    use std::env;
    use std::path::Path;

    let target_binary_path = "/Library/PrivilegedHelperTools/io.github.clashverge.helper";
    let plist_file = "/Library/LaunchDaemons/io.github.clashverge.helper.plist";

    let debug = env::args().any(|arg| arg == "--debug");

    // Stop and unload service
    let _ = run_command("launchctl", &["stop", "io.github.clashverge.helper"], debug);
    let _ = run_command("launchctl", &["bootout", "system", plist_file], debug);
    let _ = run_command(
        "launchctl",
        &["disable", "system/io.github.clashverge.helper"],
        debug,
    )?;

    // Remove files
    if Path::new(plist_file).exists() {
        std::fs::remove_file(plist_file)
            .map_err(|e| anyhow::anyhow!("Failed to remove plist file: {}", e))?;
    }

    if Path::new(target_binary_path).exists() {
        std::fs::remove_file(target_binary_path)
            .map_err(|e| anyhow::anyhow!("Failed to remove service binary: {}", e))?;
    }

    Ok(())
}

#[cfg(target_os = "linux")]
const SERVICE_NAME: &str = "clash-verge-service";

#[cfg(target_os = "linux")]
fn main() -> Result<(), Error> {
    use clash_verge_service::{utils::get_init_system, InitSystem};
    use std::env;

    let debug = env::args().any(|arg| arg == "--debug");

    let init = get_init_system();
    if init.is_none() {
        return Err(anyhow::anyhow!("Failed to detect init system"));
    }
    let init = init.unwrap();

    match init {
        InitSystem::Systemd => systemd_uninstall(debug),
        InitSystem::OpenRC => openrc_uninstall(debug),
    }
}

#[cfg(target_os = "linux")]
fn systemd_uninstall(debug: bool) -> Result<(), Error> {
    use clash_verge_service::utils::run_command;

    // Stop and disable service
    let _ = run_command(
        "systemctl",
        &["stop", &format!("{}.service", SERVICE_NAME)],
        debug,
    );
    let _ = run_command(
        "systemctl",
        &["disable", &format!("{}.service", SERVICE_NAME)],
        debug,
    );

    // Remove service file
    let unit_file = format!("/etc/systemd/system/{}.service", SERVICE_NAME);
    if std::path::Path::new(&unit_file).exists() {
        std::fs::remove_file(&unit_file)
            .map_err(|e| anyhow::anyhow!("Failed to remove service file: {}", e))?;
    }

    // Reload systemd
    let _ = run_command("systemctl", &["daemon-reload"], debug);

    Ok(())
}

#[cfg(target_os = "linux")]
fn openrc_uninstall(debug: bool) -> Result<(), Error> {
    use clash_verge_service::utils::run_command;

    // Stop and disable service
    let _ = run_command("rc-service", &[SERVICE_NAME, "stop"], debug);
    let _ = run_command("rc-update", &["del", SERVICE_NAME], debug);

    // Remove service file
    let unit_file = format!("/etc/init.d/{}", SERVICE_NAME);
    if std::path::Path::new(&unit_file).exists() {
        std::fs::remove_file(&unit_file)
            .map_err(|e| anyhow::anyhow!("Failed to remove service file: {}", e))?;
    }

    Ok(())
}

/// stop and uninstall the service
#[cfg(windows)]
fn main() -> windows_service::Result<()> {
    use std::{thread, time::Duration};
    use windows_service::{
        service::{ServiceAccess, ServiceState},
        service_manager::{ServiceManager, ServiceManagerAccess},
    };

    let manager_access = ServiceManagerAccess::CONNECT;
    let service_manager = ServiceManager::local_computer(None::<&str>, manager_access)?;

    let service_access = ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE;
    let service = service_manager.open_service("clash_verge_service", service_access)?;

    let service_status = service.query_status()?;
    if service_status.current_state != ServiceState::Stopped {
        if let Err(err) = service.stop() {
            eprintln!("{err}");
        }
        // Wait for service to stop
        thread::sleep(Duration::from_secs(1));
    }

    service.delete()?;
    Ok(())
}

use std::env;

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn main() {
    panic!("This program is not intended to run on this platform.");
}

#[cfg(not(windows))]
use anyhow::Error;
#[cfg(target_os = "macos")]
fn main() -> Result<(), Error> {
    use clash_verge_service::utils::run_command;
    use std::fs::File;
    use std::io::Write;
    use std::path::Path;

    let debug = env::args().any(|arg| arg == "--debug");

    let service_binary_path = env::current_exe()
        .unwrap()
        .with_file_name("clash-verge-service");
    let target_binary_path = "/Library/PrivilegedHelperTools/io.github.clashverge.helper";
    let target_binary_dir = Path::new("/Library/PrivilegedHelperTools");

    if !service_binary_path.exists() {
        return Err(anyhow::anyhow!("clash-verge-service binary not found"));
    }

    if !target_binary_dir.exists() {
        std::fs::create_dir("/Library/PrivilegedHelperTools")
            .map_err(|e| anyhow::anyhow!("Failed to create service file directory: {}", e))?;
    }

    std::fs::copy(&service_binary_path, &target_binary_path)
        .map_err(|e| anyhow::anyhow!("Failed to copy service file: {}", e))?;

    let plist_dir = Path::new("/Library/LaunchDaemons");
    if !plist_dir.exists() {
        std::fs::create_dir(plist_dir)
            .map_err(|e| anyhow::anyhow!("Failed to create plist directory: {}", e))?;
    }

    let plist_file = "/Library/LaunchDaemons/io.github.clashverge.helper.plist";
    let plist_file = Path::new(plist_file);

    let plist_file_content = include_str!("files/io.github.clashverge.helper.plist");
    File::create(plist_file)
        .and_then(|mut file| file.write_all(plist_file_content.as_bytes()))
        .map_err(|e| anyhow::anyhow!("Failed to write plist file: {}", e))?;

    // Execute commands in sequence, stopping if any fails
    let _ = run_command("chmod", &["644", plist_file.to_str().unwrap()], debug);
    let _ = run_command(
        "chown",
        &["root:wheel", plist_file.to_str().unwrap()],
        debug,
    );
    let _ = run_command("chmod", &["544", target_binary_path], debug);
    let _ = run_command("chown", &["root:wheel", target_binary_path], debug);
    let _ = run_command(
        "launchctl",
        &["enable", "system/io.github.clashverge.helper"],
        debug,
    );
    let _ = run_command(
        "launchctl",
        &["bootout", "system", plist_file.to_str().unwrap()],
        debug,
    );
    let _ = run_command(
        "launchctl",
        &["bootstrap", "system", plist_file.to_str().unwrap()],
        debug,
    );
    let _ = run_command(
        "launchctl",
        &["start", "io.github.clashverge.helper"],
        debug,
    );

    Ok(())
}

#[cfg(target_os = "linux")]
const SERVICE_NAME: &str = "clash-verge-service";

#[cfg(target_os = "linux")]
fn main() -> Result<(), Error> {
    use clash_verge_service::{utils::get_init_system, InitSystem};

    let debug = env::args().any(|arg| arg == "--debug");

    let service_binary_path = env::current_exe()
        .unwrap()
        .with_file_name("clash-verge-service");

    if !service_binary_path.exists() {
        return Err(anyhow::anyhow!("clash-verge-service binary not found"));
    }
    let service_binary_path = service_binary_path.to_str().unwrap();

    let init = get_init_system();
    if init.is_none() {
        return Err(anyhow::anyhow!("Failed to detect init system"));
    }
    let init = init.unwrap();

    match init {
        InitSystem::Systemd => systemd_install(service_binary_path, debug),
        InitSystem::OpenRC => openrc_install(service_binary_path, debug),
    }
}

#[cfg(target_os = "linux")]
fn systemd_install<S: AsRef<str>>(service_binary_path: S, debug: bool) -> Result<(), Error> {
    use clash_verge_service::utils::run_command;
    use std::fs::File;
    use std::io::Write;
    use std::path::Path;

    let status_output = std::process::Command::new("systemctl")
        .args(["status", &format!("{}.service", SERVICE_NAME), "--no-pager"])
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to check service status: {}", e))?;

    match status_output.status.code() {
        Some(0) => return Ok(()), // Service is running
        Some(1) | Some(2) | Some(3) => {
            run_command(
                "systemctl",
                &["start", &format!("{}.service", SERVICE_NAME)],
                debug,
            )?;
            return Ok(());
        }
        Some(4) => {} // Service not found, continue with installation
        _ => return Err(anyhow::anyhow!("Unexpected systemctl status code")),
    }

    // Create and write unit file
    let unit_file = format!("/etc/systemd/system/{}.service", SERVICE_NAME);
    let unit_file = Path::new(&unit_file);

    let unit_file_content = format!(
        include_str!("files/systemd_service_unit.tmpl"),
        service_binary_path.as_ref()
    );

    File::create(unit_file)
        .and_then(|mut file| file.write_all(unit_file_content.as_bytes()))
        .map_err(|e| anyhow::anyhow!("Failed to write unit file: {}", e))?;

    // Reload and start service
    let _ = run_command("systemctl", &["daemon-reload"], debug);
    let _ = run_command("systemctl", &["enable", SERVICE_NAME, "--now"], debug);

    Ok(())
}

#[cfg(target_os = "linux")]
fn openrc_install<S: AsRef<str>>(service_binary_path: S, debug: bool) -> Result<(), Error> {
    use clash_verge_service::utils::run_command;
    use std::fs::{self, File};
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    let status_output = std::process::Command::new("rc-service")
        .args(["-e", SERVICE_NAME])
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to check service status: {}", e))?;

    match status_output.status.code() {
        Some(0) => {
            run_command("rc-service", &[SERVICE_NAME, "--ifstopped", "start"], debug)?;
            return Ok(());
        }
        Some(1) => {} // Service not found, continue with installation
        _ => return Err(anyhow::anyhow!("Unexpected openrc status code")),
    }

    // Create and write unit file
    let unit_file = format!("/etc/init.d/{}", SERVICE_NAME);
    let unit_file = Path::new(&unit_file);

    let unit_file_content = include_str!("files/openrc_service_unit.tmpl");
    let unit_file_content =
        unit_file_content.replace("{SERVICE-BIN}", service_binary_path.as_ref());

    File::create(unit_file)
        .and_then(|mut file| file.write_all(unit_file_content.as_bytes()))
        .map_err(|e| anyhow::anyhow!("Failed to write unit file: {}", e))?;

    let mut perms = fs::metadata(unit_file)?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(unit_file, perms)
        .map_err(|e| anyhow::anyhow!("Failed to set permission: {}", e))?;

    // Reload and start service
    let _ = run_command("rc-update", &["add", SERVICE_NAME], debug);
    let _ = run_command("rc-service", &[SERVICE_NAME, "start"], debug);

    Ok(())
}

/// install and start the service
#[cfg(windows)]
fn main() -> windows_service::Result<()> {
    use std::ffi::{OsStr, OsString};
    use windows_service::{
        service::{
            ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceState,
            ServiceType,
        },
        service_manager::{ServiceManager, ServiceManagerAccess},
    };

    let manager_access = ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE;
    let service_manager = ServiceManager::local_computer(None::<&str>, manager_access)?;

    let service_access = ServiceAccess::QUERY_STATUS | ServiceAccess::START;
    if let Ok(service) = service_manager.open_service("clash_verge_service", service_access) {
        if let Ok(status) = service.query_status() {
            match status.current_state {
                ServiceState::StopPending
                | ServiceState::Stopped
                | ServiceState::PausePending
                | ServiceState::Paused => {
                    service.start(&Vec::<&OsStr>::new())?;
                }
                _ => {}
            };

            return Ok(());
        }
    }

    let service_binary_path = env::current_exe()
        .unwrap()
        .with_file_name("clash-verge-service.exe");

    if !service_binary_path.exists() {
        eprintln!("clash-verge-service.exe not found");
        std::process::exit(2);
    }

    let service_info = ServiceInfo {
        name: OsString::from("clash_verge_service"),
        display_name: OsString::from("Clash Verge Service"),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: service_binary_path,
        launch_arguments: vec![],
        dependencies: vec![],
        account_name: None, // run as System
        account_password: None,
    };

    let start_access = ServiceAccess::CHANGE_CONFIG | ServiceAccess::START;
    let service = service_manager.create_service(&service_info, start_access)?;

    service.set_description("Clash Verge Service helps to launch clash core")?;
    service.start(&Vec::<&OsStr>::new())?;

    Ok(())
}

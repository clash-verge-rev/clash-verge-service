#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn main() {
    panic!("This program is not intended to run on this platform.");
}

#[cfg(not(windows))]
use anyhow::Error;

// Helper function for command execution

#[cfg(target_os = "macos")]
fn main() -> Result<(), Error> {
    use clash_verge_service::utils::{run_command, uninstall_old_service};
    use std::{env, path::Path};

    let debug = env::args().any(|arg| arg == "--debug");

    let _ = uninstall_old_service();
    // 定义路径
    let bundle_path =
        "/Library/PrivilegedHelperTools/io.github.clash-verge-rev.clash-verge-rev.service.bundle";
    let plist_file =
        "/Library/LaunchDaemons/io.github.clash-verge-rev.clash-verge-rev.service.plist";
    let service_id = "io.github.clash-verge-rev.clash-verge-rev.service";

    // 停止并卸载服务
    let _ = run_command("launchctl", &["stop", service_id], debug);
    let _ = run_command(
        "launchctl",
        &["disable", &format!("system/{}", service_id)],
        debug,
    );
    let _ = run_command("launchctl", &["bootout", "system", plist_file], debug);

    // 删除文件
    if Path::new(plist_file).exists() {
        std::fs::remove_file(plist_file)
            .map_err(|e| anyhow::anyhow!("Failed to remove plist file: {}", e))?;
    }

    // 删除整个 bundle 目录
    if Path::new(bundle_path).exists() {
        std::fs::remove_dir_all(bundle_path)
            .map_err(|e| anyhow::anyhow!("Failed to remove bundle directory: {}", e))?;
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn main() -> Result<(), Error> {
    use clash_verge_service::installer::linux::prelude::*;

    let debug = std::env::args().any(|arg| arg == "--debug");

    let init = detect_init_system(debug)?;

    match init.check_status()? {
        ServiceStatus::NotFound => {}
        ServiceStatus::Inactive | ServiceStatus::Running => init.uninstall()?,
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
    println!("Service uninstalled successfully. Resource cleanup warnings can be ignored.");
    Ok(())
}

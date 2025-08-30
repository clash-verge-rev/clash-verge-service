// It should as same as verge's dirs logical

use std::{fs, path::PathBuf};
use anyhow::Result;

#[cfg(unix)]
fn app_home_dir() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("HOME environment variable not set"))
}

#[cfg(unix)]
fn ensure_mihomo_safe_dir() -> Option<PathBuf> {
    ["/var/tmp", "/tmp"]
        .iter()
        .map(PathBuf::from)
        .find(|path| path.exists())
        .or_else(|| {
            std::env::var_os("HOME").and_then(|home| {
                use std::fs;

                let home_config = PathBuf::from(home).join(".config");
                if home_config.exists() || fs::create_dir_all(&home_config).is_ok() {
                    Some(home_config)
                } else {
                    log::error!(target: "app", "Failed to create safe directory: {home_config:?}");
                    None
                }
            })
        })
}

#[cfg(unix)]
fn ipc_path() -> Result<PathBuf> {
    ensure_mihomo_safe_dir()
        .map(|base_dir| base_dir.join("verge").join("verge-mihomo.sock"))
        .or_else(|| {
            app_home_dir()
                .ok()
                .map(|dir| dir.join("verge").join("verge-mihomo.sock"))
        })
        .ok_or_else(|| anyhow::anyhow!("Failed to determine ipc path"))
}

#[cfg(target_os = "windows")]
fn ipc_path() -> Result<PathBuf> {
    Ok(PathBuf::from(r"\\.\pipe\verge-mihomo"))
}

pub fn clean_ipc_path() -> Result<()> {
    let ipc_path = ipc_path()?;
    
    #[cfg(not(target_os = "windows"))]
    {
        if ipc_path.exists() {
            fs::remove_file(&ipc_path)?;
            log::info!(target: "app", "Removed IPC socket: {:?}", ipc_path);
        } else {
            log::debug!(target: "app", "IPC socket does not exist: {:?}", ipc_path);
        }
    }
    
    #[cfg(target_os = "windows")]
    {
        log::debug!(target: "app", "Windows named pipe does not require file cleanup: {:?}", ipc_path);
    }
    
    Ok(())
}
mod openrc;
mod systemd;

pub mod prelude {
    pub use super::{
        detect_init_system, openrc::OpenRC, systemd::Systemd, InitSystem, ServiceCommand,
        ServiceStatus,
    };
}

use std::{
    env,
    fs::{read_to_string, remove_file},
    path::Path,
    str::FromStr,
};

use anyhow::{anyhow, bail};

const SERVICE_NAME: &str = "clash-verge-service";

pub fn detect_init_system(debug: bool) -> anyhow::Result<Box<dyn ServiceCommand>> {
    let init = InitSystem::from_str(read_to_string("/proc/1/comm")?.as_str())?;

    match init {
        InitSystem::Systemd => Ok(Box::new(systemd::Systemd::new(debug))),
        InitSystem::OpenRC => Ok(Box::new(openrc::OpenRC::new(debug))),
        _ => bail!("Unimplement init system: {init:?}"),
    }
}

#[derive(Debug)]
pub enum InitSystem {
    Systemd,
    OpenRC,
    Dinit,
    Runit,
    S6Svscan,
}

impl FromStr for InitSystem {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self> {
        match s {
            "systemd" => Ok(Self::Systemd),
            "init" => Ok(Self::OpenRC),
            "dinit" => Ok(Self::Dinit),
            "runit" => Ok(Self::Runit),
            "s6-svscan" => Ok(Self::S6Svscan),
            _ => bail!("Unsupport init system: {s}"),
        }
    }
}

pub enum ServiceStatus {
    NotFound,
    Inactive,
    Running,
}

pub trait ServiceCommand {
    fn check_bin_exists(&self) -> anyhow::Result<Option<String>> {
        let service_binary_path = env::current_exe()
            .map_err(|e| anyhow!("Failed to get current exe path: {e}"))?
            .with_file_name(SERVICE_NAME);

        if !service_binary_path.exists() {
            return Ok(None);
        }

        let service_binary_path = service_binary_path
            .to_str()
            .ok_or_else(|| anyhow!("Path is not valid UTF-8: {service_binary_path:?}"))?
            .to_string();

        Ok(Some(service_binary_path))
    }

    fn check_status(&self) -> anyhow::Result<ServiceStatus>;

    fn install(&self) -> anyhow::Result<()>;

    fn uninstall(&self) -> anyhow::Result<()>;

    fn run(&self);

    fn stop(&self);

    fn disable(&self);
}

pub fn remove_unit_file<S: AsRef<str>>(unit_file: S) -> anyhow::Result<()> {
    if !Path::new(unit_file.as_ref()).exists() {
        return Ok(());
    }

    remove_file(unit_file.as_ref()).map_err(|e| anyhow!("Failed to remove service file: {e}"))
}

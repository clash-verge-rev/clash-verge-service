use std::{fs::File, io::Write, path::Path, process::Command};

use anyhow::{anyhow, bail};

use crate::{
    installer::linux::{remove_unit_file, ServiceCommand, ServiceStatus, SERVICE_NAME},
    utils::run_command,
};

#[derive(Debug, Default)]
pub struct Systemd {
    debug: bool,
}

impl Systemd {
    pub fn new(debug: bool) -> Self {
        Self { debug }
    }
}

impl ServiceCommand for Systemd {
    fn check_status(&self) -> anyhow::Result<ServiceStatus> {
        let status_output = Command::new("systemctl")
            .args(["status", &format!("{SERVICE_NAME}.service"), "--no-pager"])
            .output()
            .map_err(|e| anyhow!("Failed to check service status: {e}"))?;

        let status_code = status_output.status.code();
        match status_code {
            Some(0) => Ok(ServiceStatus::Running),
            Some(1) | Some(2) | Some(3) => Ok(ServiceStatus::Inactive),

            Some(4) => Ok(ServiceStatus::NotFound),
            _ => bail!("Unexpected systemctl status code: {status_code:?}"),
        }
    }

    fn install(&self) -> anyhow::Result<()> {
        let service_binary_path = self
            .check_bin_exists()?
            .ok_or_else(|| anyhow!("{SERVICE_NAME} binary not found"))?;

        let unit_file = format!("/etc/systemd/system/{}.service", SERVICE_NAME);
        let unit_file = Path::new(&unit_file);

        let unit_file_content = format!(
            include_str!("../../files/systemd_service_unit.tmpl"),
            service_binary_path
        );

        File::create(unit_file)
            .and_then(|mut file| file.write_all(unit_file_content.as_bytes()))
            .map_err(|e| anyhow!("Failed to write unit file: {e}"))?;

        // Reload and start service
        let _ = run_command("systemctl", &["daemon-reload"], self.debug);
        let _ = run_command("systemctl", &["enable", SERVICE_NAME, "--now"], self.debug);

        Ok(())
    }

    fn uninstall(&self) -> anyhow::Result<()> {
        self.stop();
        self.disable();

        let unit_file = format!("/etc/systemd/system/{SERVICE_NAME}.service");

        remove_unit_file(unit_file)
    }

    fn run(&self) {
        let _ = run_command(
            "systemctl",
            &["start", &format!("{SERVICE_NAME}.service")],
            self.debug,
        );
    }

    fn stop(&self) {
        let _ = run_command(
            "systemctl",
            &["stop", &format!("{SERVICE_NAME}.service")],
            self.debug,
        );
    }

    fn disable(&self) {
        let _ = run_command(
            "systemctl",
            &["disable", &format!("{SERVICE_NAME}.service")],
            self.debug,
        );
    }
}

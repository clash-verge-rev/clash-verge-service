use std::{
    fs::{self, File},
    io::Write,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::Command,
};

use anyhow::{anyhow, bail};

use crate::{
    installer::linux::{remove_unit_file, ServiceCommand, ServiceStatus, SERVICE_NAME},
    utils::run_command,
};

pub struct OpenRC {
    debug: bool,
}

impl OpenRC {
    pub fn new(debug: bool) -> Self {
        Self { debug }
    }
}

impl ServiceCommand for OpenRC {
    fn check_status(&self) -> anyhow::Result<ServiceStatus> {
        let status_output = Command::new("rc-service")
            .args(["-e", SERVICE_NAME])
            .output()
            .map_err(|e| anyhow!("Failed to check service status: {e}"))?;

        let status_code = status_output.status.code();
        match status_code {
            Some(0) => {}
            Some(1) | Some(-1) => return Ok(ServiceStatus::NotFound),
            _ => bail!("Unexpected openrc status code: {status_code:?}"),
        }

        let status_output = Command::new("rc-service")
            .args(["-q", SERVICE_NAME, "status"])
            .output()
            .map_err(|e| anyhow!("Failed to check service status: {e}"))?;

        let status_code = status_output.status.code();
        match status_code {
            Some(0) => Ok(ServiceStatus::Running),
            Some(x) if x > 0 => Ok(ServiceStatus::Inactive),
            _ => bail!("Unexpected openrc status code: {status_code:?}"),
        }
    }

    fn install(&self) -> anyhow::Result<()> {
        let service_binary_path = self
            .check_bin_exists()?
            .ok_or_else(|| anyhow!("{SERVICE_NAME} binary not found"))?;

        let unit_file = format!("/etc/init.d/{}", SERVICE_NAME);
        let unit_file = Path::new(&unit_file);

        let unit_file_content = include_str!("../../files/openrc_service_unit.tmpl");
        let unit_file_content = unit_file_content.replace("{SERVICE-BIN}", &service_binary_path);

        File::create(unit_file)
            .and_then(|mut file| file.write_all(unit_file_content.as_bytes()))
            .map_err(|e| anyhow!("Failed to write unit file: {}", e))?;

        let mut perms = fs::metadata(unit_file)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(unit_file, perms)
            .map_err(|e| anyhow::anyhow!("Failed to set permission: {}", e))?;

        let _ = run_command("rc-update", &["add", SERVICE_NAME], self.debug);
        let _ = run_command("rc-service", &[SERVICE_NAME, "start"], self.debug);

        Ok(())
    }

    fn uninstall(&self) -> anyhow::Result<()> {
        self.stop();
        self.disable();

        let unit_file = format!("/etc/init.d/{SERVICE_NAME}");

        remove_unit_file(unit_file)
    }

    fn run(&self) {
        let _ = run_command("rc-service", &["-q", SERVICE_NAME, "start"], self.debug);
    }

    fn stop(&self) {
        let _ = run_command("rc-service", &["-q", SERVICE_NAME, "stop"], self.debug);
    }

    fn disable(&self) {
        let _ = run_command("rc-update", &["-q", "del", SERVICE_NAME], self.debug);
    }
}

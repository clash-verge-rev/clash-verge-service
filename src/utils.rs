use anyhow::Error;

#[cfg(target_os = "linux")]
pub fn get_init_system() -> Option<crate::InitSystem> {
    use crate::InitSystem;

    std::fs::read_to_string("/proc/1/comm").map_or(None, |init_name| match init_name.trim() {
        "systemd" => Some(InitSystem::Systemd),
        "init" => Some(InitSystem::OpenRC),
        _ => None,
    })
}

pub fn run_command(cmd: &str, args: &[&str], debug: bool) -> Result<(), Error> {
    if debug {
        println!("┌─────────────────────────────────────────");
        println!("│ Executing Command");
        println!("│ Command: {} {}", cmd, args.join(" "));
        println!("└─────────────────────────────────────────");
    }

    let output = std::process::Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to execute '{}': {}", cmd, e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);

        if debug {
            eprintln!("\n┌─────────────────────────────────────────");
            eprintln!("│ Command Execution Failed");
            eprintln!("├─────────────────────────────────────────");
            eprintln!("│ Command: {} {}", cmd, args.join(" "));
            eprintln!("│ Status: {}", output.status);
            eprintln!("├─────────────────────────────────────────");
            if !stdout.is_empty() {
                eprintln!("│ STDOUT:");
                for line in stdout.lines() {
                    eprintln!("│   {}", line);
                }
            }
            if !stderr.is_empty() {
                eprintln!("├─────────────────────────────────────────");
                eprintln!("│ STDERR:");
                for line in stderr.lines() {
                    eprintln!("│   {}", line);
                }
            }
            eprintln!("└─────────────────────────────────────────\n");
        }

        return Err(anyhow::anyhow!(
            "Command execution failed:\n\
            Command: {} {}\n\
            Status: {}\n\
            stdout: {}\n\
            stderr: {}",
            cmd,
            args.join(" "),
            output.status,
            stdout,
            stderr
        ));
    }

    Ok(())
}

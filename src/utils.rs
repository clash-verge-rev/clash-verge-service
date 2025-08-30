use anyhow::Error;

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

#[cfg(target_os = "macos")]
pub fn uninstall_old_service() -> Result<(), Error> {
    use std::path::Path;

    let target_binary_path = "/Library/PrivilegedHelperTools/io.github.clashverge.helper";
    let plist_file = "/Library/LaunchDaemons/io.github.clashverge.helper.plist";

    // Stop and unload service
    run_command("launchctl", &["stop", "io.github.clashverge.helper"], false)?;
    run_command("launchctl", &["bootout", "system", plist_file], false)?;
    run_command(
        "launchctl",
        &["disable", "system/io.github.clashverge.helper"],
        false,
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

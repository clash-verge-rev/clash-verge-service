use std::{
    io::{self, Write},
    process::{Command, Stdio},
};

use log::{info, warn, error, debug};

pub fn spawn_process(command: &str, args: &[&str], mut log: std::fs::File) -> io::Result<u32> {
    // Log the command being executed
    let _ = writeln!(log, "Spawning process: {} {}", command, args.join(" "));
    log.flush()?;
    
    info!("正在启动进程: {} {}", command, args.join(" "));

    #[cfg(target_os = "macos")]
    {
        // On macOS, use posix_spawn via Command
        let child = Command::new(command)
            .args(args)
            .stdout(Stdio::from(log))
            .stderr(Stdio::null())
            .spawn()?;

        // Get the process ID
        let pid = child.id();
        info!("子进程成功启动，PID: {}", pid);

        // Detach the child process
        std::thread::spawn(move || {
            let _ = child.wait_with_output();
        });

        Ok(pid)
    }

    #[cfg(not(target_os = "macos"))]
    {
        let child = Command::new(command)
            .args(args)
            .stdout(log)
            .stderr(Stdio::null())
            .spawn()?;
        let pid = child.id();
        info!("子进程成功启动，PID: {}", pid);
        Ok(pid)
    }
}

pub fn spawn_process_debug(command: &str, args: &[&str]) -> io::Result<(u32, String, i32)> {
    info!("正在启动调试进程: {} {}", command, args.join(" "));
    
    let child = Command::new(command)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let pid = child.id();
    debug!("调试进程已启动，PID: {}", pid);
    
    let output = child.wait_with_output()?;

    // Combine stdout and stderr
    let mut combined_output = String::new();
    if !output.stdout.is_empty() {
        combined_output.push_str(&String::from_utf8_lossy(&output.stdout));
    }
    if !output.stderr.is_empty() {
        if !combined_output.is_empty() {
            combined_output.push('\n');
        }
        combined_output.push_str(&String::from_utf8_lossy(&output.stderr));
    }

    // Get the exit code
    let exit_code = output.status.code().unwrap_or(-1);
    debug!("调试进程 PID {} 已退出，退出码: {}", pid, exit_code);

    Ok((pid, combined_output, exit_code))
}

#[cfg(target_os = "windows")]
pub fn kill_process(pid: u32) -> io::Result<()> {
    info!("尝试终止进程 PID {}", pid);

    let taskkill_args = &["/F", "/PID", &pid.to_string()];

    let output = Command::new("taskkill")
        .args(taskkill_args)
        .output()?;
    
    let stderr = if !output.stderr.is_empty() {
        // win尝试以GBK编码log
        let (cow, _encoding_used, _had_errors) = encoding_rs::GBK.decode(&output.stderr);
        cow.into_owned()
    } else {
        String::from("")
    };
    
    if output.status.success() {
        info!("成功终止进程 PID {}", pid);
        Ok(())
    } else {
        error!("无法终止进程 PID {}: {}", pid, stderr.trim());
        Err(io::Error::new(
            io::ErrorKind::Other,
            format!("终止进程失败: {}", stderr.trim()),
        ))
    }
}

#[cfg(target_os = "windows")]
pub fn find_processes(process_name: &str) -> io::Result<Vec<u32>> {
    debug!("正在搜索进程: {}", process_name);
    
    let output = Command::new("tasklist")
        .args(&["/FO", "CSV", "/NH"])
        .output()?;
    
    let output_str = if !output.stdout.is_empty() {
        let (cow, _encoding_used, _had_errors) = encoding_rs::GBK.decode(&output.stdout);
        cow.into_owned()
    } else {
        String::from("")
    };
    
    let mut pids = Vec::new();
    
    for line in output_str.lines() {
        let parts: Vec<&str> = line.split(',').collect();
        if parts.len() >= 2 {
            let name = parts[0].trim_matches('"');
            if name.to_lowercase().contains(&process_name.to_lowercase()) {
                if let Some(pid_str) = parts[1].trim_matches('"').split_whitespace().next() {
                    if let Ok(pid) = pid_str.parse::<u32>() {
                        pids.push(pid);
                    }
                }
            }
        }
    }
    
    info!("找到 {} 个匹配进程: {}", pids.len(), process_name);
    
    Ok(pids)
}

#[cfg(target_os = "linux")]
pub fn find_processes(process_name: &str) -> io::Result<Vec<u32>> {
    debug!("正在搜索进程: {}", process_name);
    
    let output = Command::new("pgrep")
        .arg("-f")
        .arg(process_name)
        .output()?;
    
    let output_str = String::from_utf8_lossy(&output.stdout);
    let mut pids = Vec::new();
    
    for line in output_str.lines() {
        if let Ok(pid) = line.trim().parse::<u32>() {
            pids.push(pid);
        }
    }
    
    info!("找到 {} 个匹配进程: {}", pids.len(), process_name);
    
    Ok(pids)
}

#[cfg(target_os = "macos")]
pub fn find_processes(process_name: &str) -> io::Result<Vec<u32>> {
    debug!("正在搜索进程: {}", process_name);
    
    let output = Command::new("pgrep")
        .arg("-f")
        .arg(process_name)
        .output()?;
    
    let output_str = String::from_utf8_lossy(&output.stdout);
    let mut pids = Vec::new();
    
    for line in output_str.lines() {
        if let Ok(pid) = line.trim().parse::<u32>() {
            pids.push(pid);
        }
    }
    
    info!("找到 {} 个匹配进程: {}", pids.len(), process_name);
    
    Ok(pids)
}

#[cfg(not(target_os = "windows"))]
pub fn kill_process(pid: u32) -> io::Result<()> {
    info!("尝试向进程 PID {} 发送 SIGINT (kill -2) 信号", pid);
    
    // SIGINT
    let kill_int_args = &["-2", &pid.to_string()];
    let output = Command::new("kill").args(kill_int_args).output()?;
    
    if output.status.success() {
        info!("成功向进程 PID {} 发送 SIGINT 信号", pid);
        std::thread::sleep(std::time::Duration::from_millis(1000));

        let check_process = Command::new("ps")
            .args(["-p", &pid.to_string()])
            .output()?;
            
        if !check_process.status.success() {
            return Ok(());
        }
        
        warn!("进程 {} 在接收 SIGINT 后未终止，尝试发送 SIGKILL", pid);
    } else {
        warn!("向进程 PID {} 发送 SIGINT 失败，尝试发送 SIGKILL", pid);
    }
    
    // SIGKILL
    let kill_kill_args = &["-9", &pid.to_string()];
    let output = Command::new("kill").args(kill_kill_args).output()?;
    
    let stderr = if !output.stderr.is_empty() {
        String::from_utf8_lossy(&output.stderr).to_string()
    } else {
        String::from("")
    };
    
    if output.status.success() {
        info!("成功使用 SIGKILL 终止进程 PID {}", pid);
        Ok(())
    } else {
        error!("使用 SIGKILL 终止进程 PID {} 失败: {}", pid, stderr.trim());
        Err(io::Error::other(
            format!("Kill command failed: {}", stderr.trim()),
        ))
    }
}

mod core;
mod data;
mod process;
mod ipc;

use self::ipc::{run_ipc_server, shutdown_ipc_server};
use tokio::runtime::Runtime;
use log::{info, error};

#[cfg(target_os = "macos")]
use clash_verge_service::utils;
#[cfg(windows)]
use std::{ffi::OsString, time::Duration};
#[cfg(windows)]
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher, Result,
};

#[cfg(windows)]
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;
#[cfg(not(target_os = "macos"))]
const SERVICE_NAME: &str = "clash_verge_service";

/// 运行IPC服务
pub async fn run_service() -> anyhow::Result<()> {
    // Unix系统注册信号处理器
    #[cfg(target_family = "unix")]
    {
        use tokio::signal;
        
        tokio::spawn(async {
            let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate()).unwrap();
            let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt()).unwrap();
            let mut sigquit = signal::unix::signal(signal::unix::SignalKind::quit()).unwrap();
            let mut sighup = signal::unix::signal(signal::unix::SignalKind::hangup()).unwrap();
            
            tokio::select! {
                _ = sigterm.recv() => {
                    info!("收到SIGTERM信号，正在清理IPC资源...");
                    graceful_shutdown("SIGTERM").await;
                }
                _ = sigint.recv() => {
                    info!("收到SIGINT信号，正在清理IPC资源...");
                    graceful_shutdown("SIGINT").await;
                }
                _ = sigquit.recv() => {
                    info!("收到SIGQUIT信号，正在清理IPC资源...");
                    graceful_shutdown("SIGQUIT").await;
                }
                _ = sighup.recv() => {
                    info!("收到SIGHUP信号，正在清理IPC资源...");
                    graceful_shutdown("SIGHUP").await;
                }
            }
        });
    }
    #[cfg(windows)]
    {
        // 为Windows注册控制台事件处理器
        setup_windows_ctrl_handler();
    }
    #[cfg(windows)]
    let status_handle = service_control_handler::register(
        SERVICE_NAME,
        move |event| -> ServiceControlHandlerResult {
            match event {
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                ServiceControl::Stop => {
                    info!("收到停止服务信号，正在清理IPC资源...");
                    if let Err(e) = shutdown_ipc_server() {
                        error!("清理IPC资源失败: {e}");
                    }
                    std::process::exit(0);
                },
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        },
    )?;
    #[cfg(windows)]
    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    info!("启动Clash Verge服务 - IPC模式");
    
    // 直接运行IPC服务器
    if let Err(err) = run_ipc_server().await {
        error!("IPC服务器错误: {err}");
    }

    Ok(())
}

// 停止服务
#[cfg(target_os = "windows")]
fn stop_service() -> Result<()> {
    let status_handle =
        service_control_handler::register(SERVICE_NAME, |_| ServiceControlHandlerResult::NoError)?;

    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    Ok(())
}
#[cfg(target_os = "linux")]
fn stop_service() -> anyhow::Result<()> {
    info!("正在停止Linux服务，清理IPC资源...");
    
    // 清理IPC资源
    if let Err(e) = shutdown_ipc_server() {
        error!("清理IPC资源失败: {e}");
    }
    
    // systemctl stop clash_verge_service
    std::process::Command::new("systemctl")
        .arg("stop")
        .arg(SERVICE_NAME)
        .output()
        .expect("failed to execute process");
    Ok(())
}

#[cfg(target_os = "macos")]
fn stop_service() -> anyhow::Result<()> {
    info!("正在停止macOS服务，清理IPC资源...");
    
    // 清理IPC资源
    if let Err(e) = shutdown_ipc_server() {
        error!("清理IPC资源失败: {e}");
    }
    
    // launchctl stop clash_verge_service
    let _ = utils::run_command(
        "launchctl",
        &["stop", "io.github.clash-verge-rev.clash-verge-rev.service"],
        true,
    );

    Ok(())
}

/// Service Main function
#[cfg(windows)]
pub fn main() -> Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

#[cfg(not(windows))]
pub fn main() {
    if let Ok(rt) = Runtime::new() {
        rt.block_on(async {
            let _ = run_service().await;
        });
    }
}

#[cfg(windows)]
define_windows_service!(ffi_service_main, my_service_main);

#[cfg(windows)]
pub fn my_service_main(_arguments: Vec<OsString>) {
    if let Ok(rt) = Runtime::new() {
        rt.block_on(async {
            let _ = run_service().await;
        });
    }
}

/// 优雅关闭函数
async fn graceful_shutdown(signal_name: &str) {
    info!("收到{}信号，开始优雅关闭流程...", signal_name);
    
    // 1. 立即停止接受新连接
    if let Err(e) = shutdown_ipc_server() {
        error!("停止IPC服务器失败: {e}");
    }
    
    // 2. 等待一小段时间让正在处理的连接完成
    info!("等待正在处理的连接完成...");
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    
    // 3. 强制清理所有资源
    force_cleanup_resources().await;
    
    info!("优雅关闭完成，进程即将退出");
    std::process::exit(0);
}

/// 强制清理所有资源
async fn force_cleanup_resources() {
    info!("开始强制清理所有资源...");
    
    // 清理IPC资源（如果之前失败的话再试一次）
    if let Err(e) = shutdown_ipc_server() {
        error!("第二次尝试清理IPC资源仍然失败: {e}");
        
        // 最后手段：直接删除socket文件（仅Unix）
        #[cfg(target_family = "unix")]
        {
            use crate::service::ipc::IPC_SOCKET_NAME;
            if std::path::Path::new(IPC_SOCKET_NAME).exists() {
                if let Err(e) = std::fs::remove_file(IPC_SOCKET_NAME) {
                    error!("强制删除socket文件失败: {e}");
                } else {
                    info!("强制删除socket文件成功");
                }
            }
        }
    }
    
    info!("资源清理完成");
}

/// Windows控制台事件处理器设置
#[cfg(windows)]
fn setup_windows_ctrl_handler() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    
    // 使用Arc<AtomicBool>来跟踪是否已经在处理关闭事件
    static SHUTDOWN_IN_PROGRESS: AtomicBool = AtomicBool::new(false);
    
    unsafe extern "system" fn ctrl_handler(ctrl_type: u32) -> i32 {
        use winapi::um::wincon::{CTRL_C_EVENT, CTRL_BREAK_EVENT, CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT};
        
        // 防止重复处理
        if SHUTDOWN_IN_PROGRESS.compare_exchange(false, true, Ordering::SeqCst, Ordering::Relaxed).is_err() {
            return 1; // 已经在处理中，直接返回
        }
        
        let event_name = match ctrl_type {
            CTRL_C_EVENT => "CTRL_C",
            CTRL_BREAK_EVENT => "CTRL_BREAK", 
            CTRL_CLOSE_EVENT => "CTRL_CLOSE",
            CTRL_LOGOFF_EVENT => "CTRL_LOGOFF",
            CTRL_SHUTDOWN_EVENT => "CTRL_SHUTDOWN",
            _ => "UNKNOWN_CTRL_EVENT",
        };
        
        info!("收到Windows控制台事件: {}", event_name);
        
        // 创建新的运行时来处理异步清理
        if let Ok(rt) = tokio::runtime::Runtime::new() {
            rt.block_on(async {
                graceful_shutdown(event_name).await;
            });
        } else {
            // 如果无法创建运行时，进行同步清理
            error!("无法创建Tokio运行时，进行同步清理");
            if let Err(e) = shutdown_ipc_server() {
                error!("同步清理IPC资源失败: {e}");
            }
            std::process::exit(1);
        }
        
        1 // 返回1表示已处理
    }
    
    unsafe {
        use winapi::um::consoleapi::SetConsoleCtrlHandler;
        if SetConsoleCtrlHandler(Some(ctrl_handler), 1) == 0 {
            error!("设置Windows控制台事件处理器失败");
        } else {
            info!("Windows控制台事件处理器设置成功");
        }
    }
}

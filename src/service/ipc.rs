use crate::service::data::*;
use crate::service::core::COREMANAGER;
use anyhow::{anyhow, Context, Result};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sha2::digest::Digest;
use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::atomic::{AtomicBool, Ordering};
use log::{info, error, debug};
#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStrExt;
#[cfg(target_os = "windows")]
use std::os::windows::io::FromRawHandle;
#[cfg(target_os = "windows")]
use std::ptr;
#[cfg(target_os = "windows")]
use std::ffi::OsStr;

/// IPC通信常量
pub const IPC_SOCKET_NAME: &str = if cfg!(windows) {
    r"\\.\pipe\clash-verge-service"
} else {
    "/tmp/clash-verge-service.sock"
};

/// 消息时间有效期(秒)
const MESSAGE_EXPIRY_SECONDS: u64 = 30;

/// IPC服务器运行状态
static IPC_SERVER_RUNNING: AtomicBool = AtomicBool::new(false);

/// Windows命名管道句柄存储
#[cfg(target_os = "windows")]
static mut CURRENT_PIPE_HANDLES: Vec<winapi::um::winnt::HANDLE> = Vec::new();
#[cfg(target_os = "windows")]
static PIPE_HANDLES_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// 进程锁文件路径
#[cfg(target_family = "unix")]
const LOCK_FILE_PATH: &str = "/tmp/clash-verge-service.lock";
#[cfg(target_os = "windows")]
const LOCK_FILE_PATH: &str = "clash-verge-service.lock";

/// 全局进程锁文件句柄
static mut PROCESS_LOCK_FILE: Option<std::fs::File> = None;
static PROCESS_LOCK_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// 定义命令类型
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpcCommand {
    GetClash,
    GetVersion,
    StartClash,
    StopClash,
}

/// 定义IPC消息格式
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcRequest {
    pub id: String,
    pub timestamp: u64,
    pub command: IpcCommand,
    pub payload: serde_json::Value,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcResponse {
    pub id: String,
    pub success: bool,
    pub data: Option<serde_json::Value>,
    pub error: Option<String>,
    pub signature: String,
}

/// todo - 必须与客户端使用相同的方法
fn derive_secret_key() -> Vec<u8> {
    let unique_app_id = "clash-verge-app-secret-fuck-me-until-daylight";
    let mut hasher = Sha256::new();
    hasher.update(unique_app_id.as_bytes());
    hasher.finalize().to_vec()
}

/// 验证请求签名
fn verify_request_signature(request: &IpcRequest) -> Result<bool> {
    let original_signature = request.signature.clone();

    let verification_request = IpcRequest {
        id: request.id.clone(),
        timestamp: request.timestamp,
        command: request.command.clone(),
        payload: request.payload.clone(),
        signature: String::new(),
    };

    let message = serde_json::to_string(&verification_request)?;
    let expected_signature = sign_message(&message)?;

    Ok(expected_signature == original_signature)
}

/// 检查消息时间戳
fn verify_timestamp(timestamp: u64) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    now >= timestamp && now - timestamp <= MESSAGE_EXPIRY_SECONDS
}

fn sign_message(message: &str) -> Result<String> {
    type HmacSha256 = Hmac<Sha256>;
    
    let secret_key = derive_secret_key();
    let mut mac = HmacSha256::new_from_slice(&secret_key)
        .context("HMAC初始化失败")?;
    
    mac.update(message.as_bytes());
    let result = mac.finalize();
    let signature = hex::encode(result.into_bytes());
    
    Ok(signature)
}

/// 创建签名响应
fn create_signed_response(
    request_id: &str, 
    success: bool, 
    data: Option<serde_json::Value>, 
    error: Option<String>
) -> Result<IpcResponse> {
    let unsigned_response = IpcResponse {
        id: request_id.to_string(),
        success,
        data: data.clone(),
        error: error.clone(),
        signature: String::new(),
    };

    let unsigned_json = serde_json::to_string(&unsigned_response)?;
    let signature = sign_message(&unsigned_json)?;

    Ok(IpcResponse {
        id: request_id.to_string(),
        success,
        data,
        error,
        signature,
    })
}

/// 处理IPC请求
pub fn handle_request(request: IpcRequest) -> Result<IpcResponse> {
    if !verify_request_signature(&request)? {
        return create_signed_response(
            &request.id, 
            false, 
            None, 
            Some("请求签名验证失败".to_string())
        );
    }

    if !verify_timestamp(request.timestamp) {
        return create_signed_response(
            &request.id, 
            false, 
            None, 
            Some("请求时间戳无效或过期".to_string())
        );
    }

    // 处理锁中毒
    let core_manager = match COREMANAGER.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            error!("COREMANAGER mutex is poisoned: {}", poisoned);
            return create_signed_response(
                &request.id,
                false,
                None,
                Some("内部服务器错误: 核心服务状态异常".to_string())
            );
        }
    };
    
    // 处理命令
    match request.command {
        IpcCommand::GetClash => {
            match core_manager.get_clash_status() {
                Ok(data) => {
                    let json_response = serde_json::json!({
                        "code": 0,
                        "msg": "ok",
                        "data": data
                    });
                    create_signed_response(&request.id, true, Some(json_response), None)
                }
                Err(err) => {
                    create_signed_response(
                        &request.id, 
                        false, 
                        None, 
                        Some(format!("{}", err))
                    )
                }
            }
        }
        
        IpcCommand::GetVersion => {
            match core_manager.get_version() {
                Ok(data) => {
                    let json_response = serde_json::json!({
                        "code": 0,
                        "msg": "ok",
                        "data": data
                    });
                    create_signed_response(&request.id, true, Some(json_response), None)
                }
                Err(err) => {
                    create_signed_response(
                        &request.id, 
                        false, 
                        None, 
                        Some(format!("{}", err))
                    )
                }
            }
        }
        
        IpcCommand::StartClash => {
            let start_body: StartBody = match serde_json::from_value(request.payload) {
                Ok(body) => body,
                Err(err) => {
                    return create_signed_response(
                        &request.id, 
                        false, 
                        None, 
                        Some(format!("无效的启动参数: {}", err))
                    );
                }
            };
            
            match core_manager.start_clash(start_body) {
                Ok(_) => {
                    let json_response = serde_json::json!({
                        "code": 0,
                        "msg": "ok"
                    });
                    create_signed_response(&request.id, true, Some(json_response), None)
                }
                Err(err) => {
                    create_signed_response(
                        &request.id, 
                        false, 
                        None, 
                        Some(err.to_string())
                    )
                }
            }
        }
        
        IpcCommand::StopClash => {
            match core_manager.stop_clash() {
                Ok(_) => {
                    let json_response = serde_json::json!({
                        "code": 0,
                        "msg": "ok"
                    });
                    create_signed_response(&request.id, true, Some(json_response), None)
                }
                Err(err) => {
                    create_signed_response(
                        &request.id, 
                        false, 
                        None, 
                        Some(format!("{}", err))
                    )
                }
            }
        }
    }
}

#[cfg(target_os = "windows")]
pub async fn run_ipc_server() -> Result<()> {
    use std::io::{Read, Write};
    use std::fs::File;
    use tokio::task::spawn_blocking;
    
    // 导入必要的Windows API
    use winapi::um::namedpipeapi::{ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe};
    use winapi::um::handleapi::{INVALID_HANDLE_VALUE, CloseHandle};
    use winapi::um::winbase::{
        PIPE_ACCESS_DUPLEX,
        PIPE_READMODE_MESSAGE,
        PIPE_TYPE_MESSAGE,
        PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        PIPE_REJECT_REMOTE_CLIENTS,
        FILE_FLAG_OVERLAPPED,
    };
    use winapi::um::errhandlingapi::GetLastError;
    use winapi::shared::winerror::ERROR_PIPE_CONNECTED;
    use winapi::um::securitybaseapi::{InitializeSecurityDescriptor, SetSecurityDescriptorDacl, AllocateAndInitializeSid, FreeSid};
    use winapi::um::aclapi::SetEntriesInAclW;
    use winapi::um::accctrl::{
        EXPLICIT_ACCESS_W, SET_ACCESS, TRUSTEE_W, 
        TRUSTEE_IS_SID, TRUSTEE_IS_WELL_KNOWN_GROUP
    };
    use winapi::um::winnt::{
        SECURITY_DESCRIPTOR, SECURITY_DESCRIPTOR_REVISION, GENERIC_ALL,
        SID_IDENTIFIER_AUTHORITY, SECURITY_WORLD_SID_AUTHORITY,
        SECURITY_WORLD_RID, PSID
    };
    use winapi::um::winbase::LocalFree;
    use winapi::um::minwinbase::SECURITY_ATTRIBUTES;
    use std::mem;

    info!("正在启动IPC服务器 (Windows) - {}", IPC_SOCKET_NAME);
    
    // 获取进程锁，防止多实例运行
    acquire_process_lock()
        .context("无法获取进程锁，可能已有其他服务实例在运行")?;
    
    // 启动时清理：尝试清理可能存在的旧管道连接
    cleanup_old_pipes_on_startup().await;
    
    // 设置服务器运行状态
    IPC_SERVER_RUNNING.store(true, Ordering::SeqCst);
    
    loop {
        // 创建命名管道
        let pipe_handle = unsafe {
            // 创建一个安全描述符以及所有用户都能访问的ACL
            let mut sd: SECURITY_DESCRIPTOR = mem::zeroed();
            let mut everyone_sid: PSID = ptr::null_mut();
            let mut acl = ptr::null_mut();
            
            // 初始化安全描述符
            if InitializeSecurityDescriptor(
                &mut sd as *mut SECURITY_DESCRIPTOR as *mut _, 
                SECURITY_DESCRIPTOR_REVISION
            ) == 0 {
                let error = GetLastError();
                error!("初始化安全描述符失败: {}", error);
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
            
            // 创建Everyone SID
            let mut sia = SID_IDENTIFIER_AUTHORITY { Value: SECURITY_WORLD_SID_AUTHORITY };
            
            if AllocateAndInitializeSid(
                &mut sia as *mut SID_IDENTIFIER_AUTHORITY,
                1,
                SECURITY_WORLD_RID,
                0, 0, 0, 0, 0, 0, 0,
                &mut everyone_sid
            ) == 0 {
                let error = GetLastError();
                error!("创建Everyone SID失败: {}", error);
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
            
            // 设置允许Everyone组完全访问的访问控制项
            let mut ea = EXPLICIT_ACCESS_W {
                grfAccessPermissions: GENERIC_ALL,
                grfAccessMode: SET_ACCESS,
                grfInheritance: 0,
                Trustee: TRUSTEE_W {
                    pMultipleTrustee: ptr::null_mut(),
                    MultipleTrusteeOperation: 0,
                    TrusteeForm: TRUSTEE_IS_SID,
                    TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
                    ptstrName: everyone_sid as *mut _
                }
            };
            
            // 创建访问控制列表
            let result = SetEntriesInAclW(
                1,
                &mut ea as *mut EXPLICIT_ACCESS_W,
                ptr::null_mut(),
                &mut acl
            );
            
            if result != 0 {
                error!("创建ACL失败: {}", result);
                FreeSid(everyone_sid);
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
            
            // 将ACL设置到安全描述符
            if SetSecurityDescriptorDacl(
                &mut sd as *mut SECURITY_DESCRIPTOR as *mut _,
                1, 
                acl, 
                0
            ) == 0 {
                let error = GetLastError();
                error!("设置安全描述符DACL失败: {}", error);
                LocalFree(acl as *mut _);
                FreeSid(everyone_sid);
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
            
            // 创建安全属性结构体
            let mut sa = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: &mut sd as *mut SECURITY_DESCRIPTOR as *mut _,
                bInheritHandle: 0
            };
            
            // 创建命名管道
            let wide_name: Vec<u16> = OsStr::new(IPC_SOCKET_NAME)
                .encode_wide()
                .chain(Some(0))
                .collect();
            
            let handle = CreateNamedPipeW(
                wide_name.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                4096,  // 输出缓冲区大小
                4096,  // 输入缓冲区大小
                0,     // 默认超时
                &mut sa
            );
            
            // 清理资源
            if !acl.is_null() {
                LocalFree(acl as *mut _);
            }
            
            if !everyone_sid.is_null() {
                FreeSid(everyone_sid);
            }
            
            handle
        };
        
        if pipe_handle == INVALID_HANDLE_VALUE {
            let error = unsafe { GetLastError() };
            error!("创建命名管道失败: {}", error);
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            continue;
        }
        
        // 存储管道句柄以便后续清理
        {
            let _lock = PIPE_HANDLES_MUTEX.lock().unwrap();
            unsafe {
                CURRENT_PIPE_HANDLES.push(pipe_handle);
            }
        }
        
        info!("等待客户端连接...");
        
        // 连接管道
        let connect_result = unsafe { ConnectNamedPipe(pipe_handle, ptr::null_mut()) };
        let last_error = unsafe { GetLastError() };

        if connect_result == 0 && last_error != ERROR_PIPE_CONNECTED {
            let error = unsafe { GetLastError() };
            error!("等待客户端连接失败: {}", error);
            unsafe { CloseHandle(pipe_handle) };
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            continue;
        }
        
        info!("接受到新的IPC连接");
        
        // 创建管道句柄的副本以便在不同作用域中使用
        let pipe_handle_for_cleanup = pipe_handle;
        
        // 将Windows句柄转换为Rust File对象
        let mut pipe_file  = unsafe { File::from_raw_handle(pipe_handle as _) };
        
        // 使用spawn_blocking处理阻塞IO
        let cleanup_result = spawn_blocking(move || -> Result<()> {
            // 读取消息长度前缀
            let mut len_bytes = [0u8; 4];
            if let Err(e) = pipe_file.read_exact(&mut len_bytes) {
                error!("读取请求长度失败: {}", e);
                return Err(anyhow::anyhow!("读取请求长度失败: {}", e));
            }
            
            let request_len = u32::from_be_bytes(len_bytes) as usize;
            debug!("请求长度: {}字节", request_len);
            
            // 读取消息内容
            let mut request_bytes = vec![0u8; request_len];
            if let Err(e) = pipe_file.read_exact(&mut request_bytes) {
                error!("读取请求内容失败: {}", e);
                return Err(anyhow::anyhow!("读取请求内容失败: {}", e));
            }
            
            // 解析请求
            let request: IpcRequest = match serde_json::from_slice(&request_bytes) {
                Ok(req) => req,
                Err(e) => {
                    error!("无法解析IPC请求: {}", e);
                    return Err(anyhow::anyhow!("无法解析IPC请求: {}", e));
                }
            };
            
            // 处理请求（不再需要运行时上下文中的 block_on）
            let response = handle_request(request)?;
            
            // 发送响应
            let response_json = serde_json::to_string(&response)?;
            let response_bytes = response_json.as_bytes();
            let response_len = response_bytes.len() as u32;
            
            // 写入响应长度
            if let Err(e) = pipe_file.write_all(&response_len.to_be_bytes()) {
                error!("写入响应长度失败: {}", e);
                return Err(anyhow::anyhow!("写入响应长度失败: {}", e));
            }
            
            // 写入响应内容
            if let Err(e) = pipe_file.write_all(response_bytes) {
                error!("写入响应内容失败: {}", e);
                return Err(anyhow::anyhow!("写入响应内容失败: {}", e));
            }
            
            // 刷新确保数据写入
            if let Err(e) = pipe_file.flush() {
                error!("刷新管道失败: {}", e);
                return Err(anyhow::anyhow!("刷新管道失败: {}", e));
            }
            
            Ok(())
        });
        
        // 等待连接处理完成并进行清理
        if let Err(e) = cleanup_result.await {
            error!("处理Windows IPC连接时发生错误: {:?}", e);
        }
        
        // 从存储中移除已处理完成的句柄
        {
            let _lock = PIPE_HANDLES_MUTEX.lock().unwrap();
            unsafe {
                CURRENT_PIPE_HANDLES.retain(|&h| h != pipe_handle_for_cleanup);
            }
        }
    }
}

/// 启动IPC服务器 - Unix版本
#[cfg(target_family = "unix")]
pub async fn run_ipc_server() -> Result<()> {
    use std::os::unix::net::UnixListener;

    info!("正在启动IPC服务器 (Unix) - {}", IPC_SOCKET_NAME);

    // 获取进程锁，防止多实例运行
    acquire_process_lock()
        .context("无法获取进程锁，可能已有其他服务实例在运行")?;

    if std::path::Path::new(IPC_SOCKET_NAME).exists() {
        info!("发现旧的套接字文件，正在删除: {}", IPC_SOCKET_NAME);
        if let Err(e) = std::fs::remove_file(IPC_SOCKET_NAME) {
            error!("删除旧套接字文件失败: {}，继续尝试创建新套接字", e);
        }
    }

    let listener = UnixListener::bind(IPC_SOCKET_NAME)
        .context("无法创建Unix域套接字监听器")?;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    set_socket_permissions().unwrap_or_else(|e| {
        error!("无法设置套接字权限: {}", e);
    });

    listener.set_nonblocking(true)
        .context("设置非阻塞模式失败")?;
    
    loop {
        match listener.accept() {
            Ok((stream, _addr)) => {
                info!("接受到新的IPC连接");
                tokio::task::spawn_blocking(move || {
                    if let Err(err) = handle_unix_connection_sync(stream) {
                        error!("处理Unix连接错误: {}", err);
                    }
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                continue;
            }
            Err(err) => {
                error!("接受IPC连接失败: {}", err);

                #[cfg(any(target_os = "linux", target_os = "macos"))]
                if err.to_string().contains("Permission denied") {
                    error!("检测到权限错误，尝试修复套接字权限");
                    if let Err(e) = set_socket_permissions() {
                        error!("修复套接字权限失败: {}", e);
                    }
                }

                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}

/// 设置套接字文件权限-Unix
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn set_socket_permissions() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;
    
    info!("设置套接字文件权限为全局可读写");

    let mut success = false;
    match std::fs::metadata(IPC_SOCKET_NAME) {
        Ok(metadata) => {
            let mut perms = metadata.permissions();
            let old_mode = perms.mode();
            debug!("当前套接字文件权限: {:o}", old_mode);
            
            perms.set_mode(0o666);
            match std::fs::set_permissions(IPC_SOCKET_NAME, perms) {
                Ok(_) => {
                    // 验证权限
                    if let Ok(new_metadata) = std::fs::metadata(IPC_SOCKET_NAME) {
                        let new_mode = new_metadata.permissions().mode() & 0o777;
                        info!("套接字文件权限已设置为: {:o}", new_mode);
                        if new_mode == 0o666 {
                            success = true;
                        } else {
                            error!("套接字权限设置可能未生效，应为666，实际为{:o}", new_mode);
                        }
                    }
                },
                Err(e) => {
                    error!("使用Rust API设置套接字文件权限失败: {}", e);
                }
            }
        },
        Err(e) => {
            error!("获取套接字文件元数据失败: {}", e);
        }
    }
    
    // 方法2：
    if !success {
        error!("使用系统chmod命令设置套接字权限");
        match Command::new("chmod")
            .args(["666", IPC_SOCKET_NAME])
            .output() 
        {
            Ok(output) => {
                if output.status.success() {
                    info!("使用chmod成功设置套接字权限");
                    success = true;
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    error!("chmod命令失败: {}", stderr);
                }
            },
            Err(e) => {
                error!("执行chmod命令失败: {}", e);
            }
        }
    }

    if success {
        info!("套接字权限设置成功");
        Ok(())
    } else {
        let err_msg = "所有权限设置方法均已失败";
        error!("{}", err_msg);
        Err(anyhow!(err_msg))
    }
}

/// 处理Unix域套接字连接
#[cfg(target_family = "unix")]
fn handle_unix_connection_sync(mut stream: std::os::unix::net::UnixStream) -> Result<()> {
    use std::io::{Read, Write};

    stream.set_nonblocking(false)
        .context("设置阻塞模式失败")?;

    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes)
        .context("读取请求长度失败")?;
    let request_len = u32::from_be_bytes(len_bytes) as usize;

    let mut request_bytes = vec![0u8; request_len];
    stream.read_exact(&mut request_bytes)
        .context("读取请求内容失败")?;

    let request: IpcRequest = serde_json::from_slice(&request_bytes)
        .context("无法解析IPC请求")?;

    let response = handle_request(request)?;

    let response_json = serde_json::to_string(&response)?;
    let response_bytes = response_json.as_bytes();
    let response_len = response_bytes.len() as u32;

    stream.write_all(&response_len.to_be_bytes())
        .context("写入响应长度失败")?;

    stream.write_all(response_bytes)
        .context("写入响应内容失败")?;
    
    Ok(())
}

/// 获取进程锁
fn acquire_process_lock() -> Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write;
    
    let _lock = PROCESS_LOCK_MUTEX.lock().unwrap();
    
    // 检查是否已经获得锁
    unsafe {
        if std::ptr::addr_of!(PROCESS_LOCK_FILE).read().is_some() {
            return Ok(()); // 已经有锁了
        }
    }
    
    #[cfg(target_family = "unix")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        
        // Unix系统使用文件锁
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o644)
            .open(LOCK_FILE_PATH)
            .context("无法创建进程锁文件")?;
        
        // 尝试获取独占锁
        use std::os::unix::io::AsRawFd;
        let fd = file.as_raw_fd();
        
        // 使用libc的flock进行文件锁定
        let lock_result = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
        
        if lock_result != 0 {
            return Err(anyhow::anyhow!("无法获取进程锁，可能已有其他实例在运行"));
        }
        
        // 写入当前进程ID
        let pid = std::process::id();
        writeln!(file, "{}", pid).context("写入PID到锁文件失败")?;
        file.flush().context("刷新锁文件失败")?;
        
        unsafe {
            PROCESS_LOCK_FILE = Some(file);
        }
        
        info!("Unix进程锁获取成功，PID: {}", pid);
    }
    
    #[cfg(target_os = "windows")]
    {
        // Windows系统使用命名互斥锁
        use winapi::um::synchapi::{CreateMutexW, WaitForSingleObject};
        use winapi::um::handleapi::{INVALID_HANDLE_VALUE, CloseHandle};
        use winapi::um::winbase::WAIT_TIMEOUT;
        use winapi::um::winerror::ERROR_ALREADY_EXISTS;
        use winapi::um::errhandlingapi::GetLastError;
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        
        let mutex_name = "Global\\clash-verge-service-mutex";
        let wide_name: Vec<u16> = OsStr::new(mutex_name)
            .encode_wide()
            .chain(Some(0))
            .collect();
        
        let mutex_handle = unsafe {
            CreateMutexW(
                std::ptr::null_mut(),
                1, // bInitialOwner = TRUE
                wide_name.as_ptr()
            )
        };
        
        if mutex_handle.is_null() || mutex_handle == INVALID_HANDLE_VALUE {
            return Err(anyhow::anyhow!("无法创建Windows互斥锁"));
        }
        
        let last_error = unsafe { GetLastError() };
        if last_error == ERROR_ALREADY_EXISTS {
            unsafe { CloseHandle(mutex_handle) };
            return Err(anyhow::anyhow!("无法获取进程锁，可能已有其他实例在运行"));
        }
        
        // 创建一个占位文件来模拟Unix的行为
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(LOCK_FILE_PATH)
            .context("无法创建进程锁文件")?;
        
        let pid = std::process::id();
        writeln!(file, "{}", pid).context("写入PID到锁文件失败")?;
        file.flush().context("刷新锁文件失败")?;
        
        unsafe {
            PROCESS_LOCK_FILE = Some(file);
        }
        
        info!("Windows进程锁获取成功，PID: {}", pid);
    }
    
    Ok(())
}

/// 释放进程锁
fn release_process_lock() -> Result<()> {
    let _lock = PROCESS_LOCK_MUTEX.lock().unwrap();
    
    unsafe {
        if let Some(_file) = std::ptr::addr_of_mut!(PROCESS_LOCK_FILE).read().take() {
            info!("释放进程锁");
            // 文件会在drop时自动关闭和解锁
        }
    }
    
    // 删除锁文件
    if std::path::Path::new(LOCK_FILE_PATH).exists() {
        if let Err(e) = std::fs::remove_file(LOCK_FILE_PATH) {
            error!("删除进程锁文件失败: {e}");
        } else {
            info!("进程锁文件删除成功");
        }
    }
    
    Ok(())
}

/// Windows版本的启动时清理函数
#[cfg(target_os = "windows")]
async fn cleanup_old_pipes_on_startup() {
    use winapi::um::namedpipeapi::{CreateNamedPipeW, DisconnectNamedPipe, WaitNamedPipeW};
    use winapi::um::handleapi::{INVALID_HANDLE_VALUE, CloseHandle};
    use winapi::um::winbase::{
        PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE, PIPE_READMODE_MESSAGE, 
        PIPE_WAIT, PIPE_NOWAIT, FILE_FLAG_OVERLAPPED
    };
    use winapi::um::errhandlingapi::GetLastError;
    use winapi::shared::winerror::{ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY};
    use winapi::um::fileapi::{CreateFileW, OPEN_EXISTING};
    use winapi::um::winnt::{GENERIC_READ, GENERIC_WRITE};
    
    info!("正在检查并清理可能存在的旧命名管道...");
    
    // 尝试连接到现有的管道实例来检测是否存在
    let wide_name: Vec<u16> = std::ffi::OsStr::new(IPC_SOCKET_NAME)
        .encode_wide()
        .chain(Some(0))
        .collect();
    
    unsafe {
        // 方法1: 尝试等待管道（如果管道不存在会立即返回错误）
        let wait_result = WaitNamedPipeW(wide_name.as_ptr(), 1); // 等待1毫秒
        let wait_error = GetLastError();
        
        if wait_result != 0 || wait_error == ERROR_PIPE_BUSY {
            info!("检测到可能存在的旧管道实例，尝试清理...");
            
            // 方法2: 尝试打开管道文件句柄
            let test_handle = CreateFileW(
                wide_name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut()
            );
            
            if test_handle != INVALID_HANDLE_VALUE {
                info!("发现旧的管道连接，正在关闭...");
                CloseHandle(test_handle);
                
                // 给系统一些时间清理
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
        
        // 方法3: 尝试创建一个临时管道来强制清理命名空间
        let temp_handle = CreateNamedPipeW(
            wide_name.as_ptr(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_NOWAIT,
            1, // 只允许一个实例
            1024,
            1024,
            1, // 很短的超时
            std::ptr::null_mut()
        );
        
        if temp_handle != INVALID_HANDLE_VALUE {
            info!("创建临时管道成功，立即关闭以清理命名空间");
            CloseHandle(temp_handle);
            
            // 短暂等待确保清理完成
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        } else {
            let error = GetLastError();
            if error != ERROR_FILE_NOT_FOUND {
                info!("尝试创建临时管道时发现错误: {}，这可能表示需要清理", error);
            }
        }
    }
    
    info!("Windows启动时清理完成");
}

/// Windows版本的IPC服务器停止函数
#[cfg(target_os = "windows")]
pub fn stop_ipc_server() -> Result<()> {
    use winapi::um::namedpipeapi::DisconnectNamedPipe;
    use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
    
    info!("正在停止Windows IPC服务器...");
    
    // 设置服务器停止状态
    IPC_SERVER_RUNNING.store(false, Ordering::SeqCst);
    
    // 释放进程锁
    if let Err(e) = release_process_lock() {
        error!("释放进程锁失败: {e}");
    }
    
    // 获取锁并清理所有管道句柄
    let _lock = PIPE_HANDLES_MUTEX.lock().unwrap();
    unsafe {
        for &handle in CURRENT_PIPE_HANDLES.iter() {
            if handle != INVALID_HANDLE_VALUE {
                // 断开管道连接
                DisconnectNamedPipe(handle);
                // 关闭句柄
                CloseHandle(handle);
            }
        }
        CURRENT_PIPE_HANDLES.clear();
    }
    
    info!("Windows IPC服务器已停止，所有管道句柄已清理");
    Ok(())
}

/// Unix版本的IPC服务器停止函数
#[cfg(target_family = "unix")]
pub fn stop_ipc_server() -> Result<()> {
    info!("正在停止Unix IPC服务器...");
    
    // 设置服务器停止状态
    IPC_SERVER_RUNNING.store(false, Ordering::SeqCst);
    
    // 释放进程锁
    if let Err(e) = release_process_lock() {
        error!("释放进程锁失败: {e}");
    }
    
    // 删除socket文件
    if std::path::Path::new(IPC_SOCKET_NAME).exists() {
        info!("删除Unix socket文件: {IPC_SOCKET_NAME}");
        std::fs::remove_file(IPC_SOCKET_NAME)
            .context("删除socket文件失败")?;
    }
    
    info!("Unix IPC服务器已停止，socket文件已清理");
    Ok(())
}

/// 通用的IPC服务器停止函数（自动选择平台）
pub fn shutdown_ipc_server() -> Result<()> {
    #[cfg(target_os = "windows")]
    return stop_ipc_server();
    
    #[cfg(target_family = "unix")]
    return stop_ipc_server();
} 
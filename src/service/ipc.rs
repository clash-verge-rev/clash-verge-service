use crate::service::{core::COREMANAGER, data::*};
use anyhow::{anyhow, Context, Result};
use hmac::{Hmac, Mac};
use log::{debug, error, info};
use serde::{Deserialize, Serialize};
use sha2::{digest::Digest, Sha256};
#[cfg(target_os = "windows")]
use std::ffi::OsStr;
#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStrExt;
#[cfg(target_os = "windows")]
use std::os::windows::io::FromRawHandle;
#[cfg(target_os = "windows")]
use std::ptr;
use std::time::{SystemTime, UNIX_EPOCH};

/// IPC通信常量
const IPC_SOCKET_NAME: &str = if cfg!(windows) {
    r"\\.\pipe\clash-verge-service"
} else {
    "/tmp/clash-verge-service.sock"
};

/// 消息时间有效期(秒)
const MESSAGE_EXPIRY_SECONDS: u64 = 30;

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
    let mut mac = HmacSha256::new_from_slice(&secret_key).context("HMAC初始化失败")?;

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
    error: Option<String>,
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
            Some("请求签名验证失败".to_string()),
        );
    }

    if !verify_timestamp(request.timestamp) {
        return create_signed_response(
            &request.id,
            false,
            None,
            Some("请求时间戳无效或过期".to_string()),
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
                Some("内部服务器错误: 核心服务状态异常".to_string()),
            );
        }
    };

    // 处理命令
    match request.command {
        IpcCommand::GetClash => match core_manager.get_clash_status() {
            Ok(data) => {
                let json_response = serde_json::json!({
                    "code": 0,
                    "msg": "ok",
                    "data": data
                });
                create_signed_response(&request.id, true, Some(json_response), None)
            }
            Err(err) => create_signed_response(&request.id, false, None, Some(format!("{}", err))),
        },

        IpcCommand::GetVersion => match core_manager.get_version() {
            Ok(data) => {
                let json_response = serde_json::json!({
                    "code": 0,
                    "msg": "ok",
                    "data": data
                });
                create_signed_response(&request.id, true, Some(json_response), None)
            }
            Err(err) => create_signed_response(&request.id, false, None, Some(format!("{}", err))),
        },

        IpcCommand::StartClash => {
            let start_body: StartBody = match serde_json::from_value(request.payload) {
                Ok(body) => body,
                Err(err) => {
                    return create_signed_response(
                        &request.id,
                        false,
                        None,
                        Some(format!("无效的启动参数: {}", err)),
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
                    create_signed_response(&request.id, false, None, Some(format!("{}", err)))
                }
            }
        }

        IpcCommand::StopClash => match core_manager.stop_clash() {
            Ok(_) => {
                let json_response = serde_json::json!({
                    "code": 0,
                    "msg": "ok"
                });
                create_signed_response(&request.id, true, Some(json_response), None)
            }
            Err(err) => create_signed_response(&request.id, false, None, Some(format!("{}", err))),
        },
    }
}

#[cfg(target_os = "windows")]
pub async fn run_ipc_server() -> Result<()> {
    use std::{
        fs::File,
        io::{Read, Write},
    };
    use tokio::task::spawn_blocking;

    // 导入必要的Windows API
    use std::mem;
    use winapi::{
        shared::winerror::ERROR_PIPE_CONNECTED,
        um::{
            accctrl::{
                EXPLICIT_ACCESS_W, SET_ACCESS, TRUSTEE_IS_SID, TRUSTEE_IS_WELL_KNOWN_GROUP,
                TRUSTEE_W,
            },
            aclapi::SetEntriesInAclW,
            errhandlingapi::GetLastError,
            handleapi::{CloseHandle, INVALID_HANDLE_VALUE},
            minwinbase::SECURITY_ATTRIBUTES,
            namedpipeapi::{ConnectNamedPipe, CreateNamedPipeW},
            securitybaseapi::{
                AllocateAndInitializeSid, FreeSid, InitializeSecurityDescriptor,
                SetSecurityDescriptorDacl,
            },
            winbase::{
                LocalFree, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX, PIPE_READMODE_MESSAGE,
                PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_MESSAGE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
            },
            winnt::{
                GENERIC_ALL, PSID, SECURITY_DESCRIPTOR, SECURITY_DESCRIPTOR_REVISION,
                SECURITY_WORLD_RID, SECURITY_WORLD_SID_AUTHORITY, SID_IDENTIFIER_AUTHORITY,
            },
        },
    };

    info!("正在启动IPC服务器 (Windows) - {}", IPC_SOCKET_NAME);

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
                SECURITY_DESCRIPTOR_REVISION,
            ) == 0
            {
                let error = GetLastError();
                error!("初始化安全描述符失败: {}", error);
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }

            // 创建Everyone SID
            let mut sia = SID_IDENTIFIER_AUTHORITY {
                Value: SECURITY_WORLD_SID_AUTHORITY,
            };

            if AllocateAndInitializeSid(
                &mut sia as *mut SID_IDENTIFIER_AUTHORITY,
                1,
                SECURITY_WORLD_RID,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                &mut everyone_sid,
            ) == 0
            {
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
                    ptstrName: everyone_sid as *mut _,
                },
            };

            // 创建访问控制列表
            let result = SetEntriesInAclW(
                1,
                &mut ea as *mut EXPLICIT_ACCESS_W,
                ptr::null_mut(),
                &mut acl,
            );

            if result != 0 {
                error!("创建ACL失败: {}", result);
                FreeSid(everyone_sid);
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }

            // 将ACL设置到安全描述符
            if SetSecurityDescriptorDacl(&mut sd as *mut SECURITY_DESCRIPTOR as *mut _, 1, acl, 0)
                == 0
            {
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
                bInheritHandle: 0,
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
                4096, // 输出缓冲区大小
                4096, // 输入缓冲区大小
                0,    // 默认超时
                &mut sa,
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

        // 将Windows句柄转换为Rust File对象
        let mut pipe_file = unsafe { File::from_raw_handle(pipe_handle as _) };

        // 使用spawn_blocking处理阻塞IO
        spawn_blocking(move || -> Result<()> {
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
    }
}

/// 启动IPC服务器 - Unix版本
#[cfg(target_family = "unix")]
pub async fn run_ipc_server() -> Result<()> {
    use std::os::unix::net::UnixListener;

    info!("正在启动IPC服务器 (Unix) - {}", IPC_SOCKET_NAME);

    if std::path::Path::new(IPC_SOCKET_NAME).exists() {
        info!("发现旧的套接字文件，正在删除: {}", IPC_SOCKET_NAME);
        if let Err(e) = std::fs::remove_file(IPC_SOCKET_NAME) {
            error!("删除旧套接字文件失败: {}，继续尝试创建新套接字", e);
        }
    }

    let listener = UnixListener::bind(IPC_SOCKET_NAME).context("无法创建Unix域套接字监听器")?;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    set_socket_permissions().unwrap_or_else(|e| {
        error!("无法设置套接字权限: {}", e);
    });

    listener
        .set_nonblocking(true)
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
    use std::{os::unix::fs::PermissionsExt, process::Command};

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
                }
                Err(e) => {
                    error!("使用Rust API设置套接字文件权限失败: {}", e);
                }
            }
        }
        Err(e) => {
            error!("获取套接字文件元数据失败: {}", e);
        }
    }

    // 方法2：
    if !success {
        error!("使用系统chmod命令设置套接字权限");
        match Command::new("chmod")
            .args(&["666", IPC_SOCKET_NAME])
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
            }
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

    stream.set_nonblocking(false).context("设置阻塞模式失败")?;

    let mut len_bytes = [0u8; 4];
    stream
        .read_exact(&mut len_bytes)
        .context("读取请求长度失败")?;
    let request_len = u32::from_be_bytes(len_bytes) as usize;

    let mut request_bytes = vec![0u8; request_len];
    stream
        .read_exact(&mut request_bytes)
        .context("读取请求内容失败")?;

    let request: IpcRequest = serde_json::from_slice(&request_bytes).context("无法解析IPC请求")?;

    let response = handle_request(request)?;

    let response_json = serde_json::to_string(&response)?;
    let response_bytes = response_json.as_bytes();
    let response_len = response_bytes.len() as u32;

    stream
        .write_all(&response_len.to_be_bytes())
        .context("写入响应长度失败")?;

    stream
        .write_all(response_bytes)
        .context("写入响应内容失败")?;

    Ok(())
}

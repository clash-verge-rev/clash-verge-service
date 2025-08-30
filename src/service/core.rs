use super::{
    data::{ClashStatus, CoreManager, MihomoStatus, StartBody, StatusInner, VersionResponse},
    process,
};
use anyhow::{anyhow, Context, Result};
use once_cell::sync::Lazy;
use std::{
    sync::{atomic::Ordering, Arc, Mutex},
    fs::File,
};
use log::{info, error};

impl CoreManager {
    pub fn new() -> Self {
        CoreManager {
            clash_status: StatusInner::new(ClashStatus::default()),
            mihomo_status: StatusInner::new(MihomoStatus::default()),
        }
    }

    pub fn test_config_file(&self) -> Result<(), String> {
        let config = match self
            .clash_status
            .inner
            .lock()
            .unwrap()
            .runtime_config
            .lock()
            .unwrap()
            .clone()
        {
            Some(config) => config,
            None => return Err("Runtime config is not set".to_string()),
        };

        let bin_path = config.bin_path.as_str();
        let config_dir = config.config_dir.as_str();
        let config_file = config.config_file.as_str();
        let args = vec!["-d", config_dir, "-f", config_file, "-t"];

        info!("正在测试配置文件: bin_path: {}, config_dir: {}, config_file: {}", 
            bin_path, config_dir, config_file);

        let result = process::spawn_process_debug(bin_path, &args)
            .map_err(|e| format!("Failed to execute config test: {}", e))?;

        let (_pid, output, _exit_code) = result;

        let mut errors: Vec<String> = Vec::new();
        for line in output.lines() {
            if line.contains("fata") || line.contains("error") {
                if let Some(pos) = line.find("msg=") {
                    if pos + 1 < line.len() {
                        let message = line[(pos + 4)..].trim().replace("'", "").replace('"', "");
                        let prefix = "[broken]";
                        errors.push(format!("{} {}", prefix, message));
                    }
                }
            }
        }

        if !errors.is_empty() {
            return Err(errors.join("\n"));
        }

        info!("配置测试通过");
        Ok(())
    }

    pub fn get_version(&self) -> Result<VersionResponse> {
        let current_pid = std::process::id() as i32;
        info!("服务当前PID: {}", current_pid);
        
        Ok(VersionResponse {
            service: "Clash Verge Service".into(),
            version: env!("CARGO_PKG_VERSION").into(),
        })
    }

    pub fn get_clash_status(&self) -> Result<StartBody> {
        let runtime_config = self
            .clash_status
            .inner
            .lock()
            .unwrap()
            .runtime_config
            .lock()
            .unwrap()
            .clone();
        if runtime_config.is_none() {
            return Ok(StartBody::default());
        }
        Ok(runtime_config.as_ref().unwrap().clone())
    }

    pub fn start_mihomo(&self) -> Result<()> {
        info!("正在启动mihomo");

        // 确保先停止已运行的mihomo进程
        let _ = self.stop_mihomo();
        
        // 停止系统中其他可能运行的verge-mihomo进程
        self.stop_other_mihomo_processes()?;

        // Get runtime config
        let config = match self
            .clash_status
            .inner
            .lock()
            .unwrap()
            .runtime_config
            .lock()
            .unwrap()
            .clone()
        {
            Some(config) => config,
            None => return Err(anyhow!("Runtime config is not set")),
        };

        let bin_path = config.bin_path.as_str();
        let config_dir = config.config_dir.as_str();
        let config_file = config.config_file.as_str();
        let log_file = config.log_file.as_str();
        let args = vec!["-d", config_dir, "-f", config_file];

        info!("正在启动mihomo: {} -d {} -f {}", bin_path, config_dir, config_file);

        // Open log file
        let log = File::options()
            .create(true)
            .append(true)
            .open(log_file)
            .with_context(|| format!("Failed to open log file: {}", log_file))?;

        // Spawn process
        let pid = process::spawn_process(bin_path, &args, log)?;

        // Update mihomo status
        let mihomo_status = self.mihomo_status.inner.lock().unwrap();
        mihomo_status.running_pid.store(pid as i32, Ordering::Relaxed);
        mihomo_status.is_running.store(true, Ordering::Relaxed);
        
        info!("Mihomo启动成功，PID: {}", pid);
        Ok(())
    }

    pub fn stop_mihomo(&self) -> Result<()> {
        // 获取mihomo状态信息
        let mihomo_status = self.mihomo_status.inner.lock().unwrap();
        let mihomo_pid = mihomo_status.running_pid.load(Ordering::Relaxed);
        
        if mihomo_pid <= 0 {
            info!("未找到运行中的mihomo进程");
            return Ok(());
        }
        info!("正在停止mihomo进程 {}", mihomo_pid);

        // 尝试终止进程
        let result = super::process::kill_process(mihomo_pid as u32)
            .with_context(|| format!("Failed to kill mihomo process with PID: {}", mihomo_pid));

        // 无论终止结果如何，都更新状态
        mihomo_status.running_pid.store(-1, Ordering::Relaxed);
        mihomo_status.is_running.store(false, Ordering::Relaxed);
        
        // 记录结果
        match result {
            Ok(_) => {
                info!("Mihomo进程 {} 已成功停止", mihomo_pid);
            }
            Err(e) => {
                error!("终止Mihomo进程时出错: {}", e);
            }
        }
        
        Ok(())
    }

    // 检测并停止其他verge-mihomo进程
    pub fn stop_other_mihomo_processes(&self) -> Result<()> {
        // 获取当前进程的PID和已跟踪的mihomo PID
        let current_pid = std::process::id();
        let tracked_mihomo_pid = self
            .mihomo_status
            .inner
            .lock()
            .unwrap()
            .running_pid
            .load(Ordering::Relaxed) as u32;

        let process_result = process::find_processes("verge-mihomo");
        if let Err(e) = &process_result {
            error!("查找verge-mihomo进程出错: {}", e);
            return Ok(());
        }
        
        let pids = process_result.unwrap();
        if pids.is_empty() {
            return Ok(());
        }
        
        // 过滤并终止进程
        let kill_count = pids.into_iter()
            .filter(|&pid| pid != current_pid && (tracked_mihomo_pid <= 1 || pid != tracked_mihomo_pid))
            .map(|pid| {
                info!("正在停止其他verge-mihomo进程: {}", pid);
                match process::kill_process(pid) {
                    Ok(_) => true,
                    Err(e) => {
                        error!("终止进程 {} 失败: {}", pid, e);
                        false
                    }
                }
            })
            .filter(|&success| success)
            .count();
            
        if kill_count > 0 {    
            info!("已停止 {} 个verge-mihomo进程", kill_count);
        }
        
        Ok(())
    }

    pub fn start_clash(&self, body: StartBody) -> Result<(), String> {
        // 设置配置并测试
        {
            info!("设置Clash运行时配置: {:?}", body);
            self.clash_status.inner.lock().unwrap().runtime_config =
                Arc::new(Mutex::new(Some(body.clone())));
            info!("正在测试配置文件");
            self.test_config_file()?;
        }

        // 不管mihomo当前状态如何，确保先停止所有实例，然后重新启动
        let _ = self.stop_mihomo();
        
        // 启动mihomo
        if let Err(e) = self.start_mihomo() {
            error!("启动mihomo失败: {}", e);
            return Err(format!("Failed to start mihomo: {}", e));
        }
        
        // 获取mihomo的PID并更新clash状态
        let mihomo_pid = self
            .mihomo_status
            .inner
            .lock()
            .unwrap()
            .running_pid
            .load(Ordering::Relaxed);
            
        if mihomo_pid > 0 {
            // 将mihomo的PID同时记录为clash的PID
            self.clash_status
                .inner
                .lock()
                .unwrap()
                .running_pid
                .store(mihomo_pid, Ordering::Relaxed);
            self.clash_status
                .inner
                .lock()
                .unwrap()
                .is_running
                .store(true, Ordering::Relaxed);
            info!("Clash正在使用mihomo进程，PID: {}", mihomo_pid);
        } else {
            return Err("Failed to get mihomo pid for clash".to_string());
        }

        info!("Clash启动成功");
        Ok(())
    }

    pub fn stop_clash(&self) -> Result<()> {
        info!("正在停止Clash");
        
        // 停止mihomo进程(实际上这就是clash使用的进程)
        let _ = self.stop_mihomo();
        
        // 确保所有其他verge-mihomo进程也被停止
        let _ = self.stop_other_mihomo_processes();

        info!("Clash已成功停止");
        Ok(())
    }
}

// 全局静态的 CoreManager 实例
pub static COREMANAGER: Lazy<Arc<Mutex<CoreManager>>> =
    Lazy::new(|| Arc::new(Mutex::new(CoreManager::new())));

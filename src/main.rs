mod service;

use log::{info, LevelFilter};
use log4rs::{
    append::file::FileAppender,
    config::{Appender, Config, Root},
    encode::pattern::PatternEncoder,
};
use std::{
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};

// 日志开关，设为true开启日志
pub static ENABLE_LOGGING: AtomicBool = AtomicBool::new(false);

fn setup_logger() -> Result<(), Box<dyn std::error::Error>> {
    // 如果日志开关关闭，直接返回
    if !ENABLE_LOGGING.load(Ordering::Relaxed) {
        return Ok(());
    }

    let exe_path = std::env::current_exe()?;
    let service_dir = exe_path.parent().unwrap_or(Path::new("."));
    let log_path = service_dir.join("clash-verge-service.log");

    let logfile = FileAppender::builder()
        .encoder(Box::new(PatternEncoder::new(
            "[{d(%Y-%m-%d %H:%M:%S)}][{l}] {m}\n",
        )))
        .build(log_path)?;

    // 日志配置
    let config = Config::builder()
        .appender(Appender::builder().build("logfile", Box::new(logfile)))
        .build(Root::builder().appender("logfile").build(LevelFilter::Info))?;

    log4rs::init_config(config)?;
    Ok(())
}

#[cfg(windows)]
fn main() -> windows_service::Result<()> {
    // 要启用日志输出取消这行注释
    // ENABLE_LOGGING.store(true, Ordering::Relaxed);

    if let Err(e) = setup_logger() {
        eprintln!("日志初始化失败: {}", e);
    }

    info!("Starting Clash Verge Service");
    service::main()
}

#[cfg(not(windows))]
fn main() {
    // 要启用日志输出这行注释
    // ENABLE_LOGGING.store(true, Ordering::Relaxed);
    if let Err(e) = setup_logger() {
        eprintln!("日志初始化失败: {}", e);
    }

    info!("Starting Clash Verge Service");
    service::main();
}

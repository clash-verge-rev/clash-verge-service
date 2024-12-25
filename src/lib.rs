pub mod utils;

#[cfg(target_os = "linux")]
pub enum InitSystem {
    Systemd,
    OpenRC,
}

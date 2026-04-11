#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

use anyhow::Result;

pub struct SysProxy {
    port: u16,
}

impl SysProxy {
    pub fn new(port: u16) -> Self {
        SysProxy { port }
    }

    pub fn enable(&self) -> Result<()> {
        #[cfg(target_os = "macos")]
        return macos::enable(self.port);
        #[cfg(target_os = "linux")]
        return linux::enable(self.port);
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            tracing::warn!("system proxy not supported on this platform");
            Ok(())
        }
    }

    pub fn disable(&self) -> Result<()> {
        #[cfg(target_os = "macos")]
        return macos::disable();
        #[cfg(target_os = "linux")]
        return linux::disable();
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        Ok(())
    }

    pub fn status(&self) -> Result<String> {
        #[cfg(target_os = "macos")]
        return macos::status();
        #[cfg(target_os = "linux")]
        return linux::status(self.port);
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        Ok("unsupported platform".to_string())
    }
}

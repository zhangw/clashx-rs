#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

use anyhow::Result;
use std::path::PathBuf;

pub struct SysProxy {
    port: u16,
    /// Where the pre-enable settings are recorded so `disable` can restore
    /// them. Only macOS mutates persistent state, so only macOS reads it.
    snapshot_path: PathBuf,
}

impl SysProxy {
    pub fn new(port: u16, snapshot_path: PathBuf) -> Self {
        SysProxy {
            port,
            snapshot_path,
        }
    }

    pub fn enable(&self) -> Result<()> {
        self.enable_with_bypass(&[])
    }

    pub fn enable_with_bypass(&self, bypass: &[String]) -> Result<()> {
        #[cfg(target_os = "macos")]
        return macos::enable(self.port, bypass, &self.snapshot_path);
        #[cfg(target_os = "linux")]
        {
            if !bypass.is_empty() {
                tracing::warn!("proxy bypass list is not yet supported on Linux");
            }
            linux::enable(self.port)
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            let _ = bypass;
            tracing::warn!("system proxy not supported on this platform");
            Ok(())
        }
    }

    pub fn disable(&self) -> Result<()> {
        #[cfg(target_os = "macos")]
        return macos::disable(self.port, &self.snapshot_path);
        #[cfg(target_os = "linux")]
        return linux::disable();
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        Ok(())
    }

    /// Switch the system proxy off outright, whoever set it — the explicit
    /// `sysproxy off` request, as opposed to [`Self::disable`]'s cleanup.
    pub fn turn_off(&self) -> Result<()> {
        #[cfg(target_os = "macos")]
        return macos::turn_off(&self.snapshot_path);
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

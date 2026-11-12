//! Atomic restricted-file writes shared by subscription state and downloads.
//!
//! Both call sites use a sibling `.yaml.tmp` file so a reader never observes a
//! partial write. On Unix the temp file is opened with `0600` and the final
//! file is re-secured after the rename, because subscription files may contain
//! access tokens.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

fn tmp_path(path: &Path) -> PathBuf {
    path.with_extension("yaml.tmp")
}

/// Write `bytes` to `path` atomically, restricting the result to owner-only on
/// Unix. The parent directory must already exist.
pub(crate) fn write_atomic_sync(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = tmp_path(path);
    write_restricted_sync(&tmp, bytes)
        .with_context(|| format!("failed to write {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| {
        let _ = std::fs::remove_file(&tmp);
        format!("failed to rename {} -> {}", tmp.display(), path.display())
    })?;
    set_owner_only_permissions_sync(path)
        .with_context(|| format!("failed to secure {}", path.display()))?;
    Ok(())
}

/// Async counterpart of [`write_atomic_sync`].
pub(crate) async fn write_atomic_async(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = tmp_path(path);
    write_restricted_async(&tmp, bytes)
        .await
        .with_context(|| format!("failed to write {}", tmp.display()))?;
    if let Err(error) = tokio::fs::rename(&tmp, path).await {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(error)
            .with_context(|| format!("failed to rename {} -> {}", tmp.display(), path.display()));
    }
    set_owner_only_permissions_async(path)
        .await
        .with_context(|| format!("failed to secure {}", path.display()))?;
    Ok(())
}

#[cfg(unix)]
fn write_restricted_sync(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.flush()?;
    Ok(())
}

#[cfg(not(unix))]
fn write_restricted_sync(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes)?;
    Ok(())
}

#[cfg(unix)]
async fn write_restricted_async(path: &Path, bytes: &[u8]) -> Result<()> {
    use tokio::io::AsyncWriteExt;

    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .await?;
    file.write_all(bytes).await?;
    file.flush().await?;
    Ok(())
}

#[cfg(not(unix))]
async fn write_restricted_async(path: &Path, bytes: &[u8]) -> Result<()> {
    tokio::fs::write(path, bytes).await?;
    Ok(())
}

#[cfg(unix)]
fn set_owner_only_permissions_sync(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_owner_only_permissions_sync(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
async fn set_owner_only_permissions_async(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await?;
    Ok(())
}

#[cfg(not(unix))]
async fn set_owner_only_permissions_async(_path: &Path) -> Result<()> {
    Ok(())
}

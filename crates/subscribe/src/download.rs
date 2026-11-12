//! Downloading subscription configs over HTTP.
//!
//! Responses are size-capped (8 MiB) and written to a sibling `.yaml.tmp` file
//! that is renamed into place, so readers never see a partial config. On Unix
//! the temp and final files are `0600`.

use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use reqwest::Client;
use tokio::io::AsyncWriteExt;

use crate::{expand_tilde, Subscription};

/// User-Agent header value — identifies us as a Clash client so subscription
/// providers return YAML config format rather than base64-encoded URIs.
pub const CLASH_USER_AGENT: &str = "clash";
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_SUBSCRIPTION_BYTES: usize = 8 * 1024 * 1024;

/// Build a reqwest client configured with the Clash User-Agent. Clients own a
/// connection pool, so callers should build once and reuse across downloads.
///
/// # Errors
///
/// Returns an error when the underlying TLS backend or client configuration
/// cannot be initialized.
pub fn build_client() -> Result<Client> {
    Client::builder()
        .user_agent(CLASH_USER_AGENT)
        .timeout(DOWNLOAD_TIMEOUT)
        .build()
        .context("failed to build HTTP client")
}

/// Download a subscription's config and write it atomically to the output path.
///
/// The output path comes from `sub.output`, with a leading `~/` expanded to the
/// user's home directory. The error context names the subscription.
///
/// # Errors
///
/// Returns an error when the request or body read fails, the endpoint returns
/// a non-success status or an oversized response, or the output file cannot be
/// created, written, or atomically renamed into place.
pub async fn download_subscription(client: &Client, sub: &Subscription) -> Result<()> {
    let output_path = expand_tilde(&sub.output);
    tracing::info!(name = %sub.name, "downloading subscription");
    download_to(client, &sub.url, &output_path)
        .await
        .with_context(|| format!("subscription '{}' download failed", sub.name))
}

/// Download `url` and write the response body atomically to `output_path`.
///
/// The parent directory is created if needed. Responses larger than 8 MiB are
/// rejected, whether declared by `Content-Length` or discovered while
/// streaming. On Unix both the temp file and the final file are restricted to
/// `0600`.
///
/// # Errors
///
/// Returns an error when the HTTP request fails, the endpoint returns a
/// non-success status, the declared or streamed body exceeds 8 MiB, or the
/// parent directory, temp file, rename, or permission change fails.
pub async fn download_to(client: &Client, url: &str, output_path: &Path) -> Result<()> {
    let mut response = client
        .get(url)
        .send()
        .await
        .context("HTTP request failed")?;

    let status = response.status();
    if !status.is_success() {
        bail!("HTTP {status} from subscription endpoint");
    }

    if let Some(len) = response.content_length() {
        if len > MAX_SUBSCRIPTION_BYTES as u64 {
            bail!(
                "subscription response too large: {len} bytes exceeds limit of {MAX_SUBSCRIPTION_BYTES} bytes"
            );
        }
    }

    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .context("failed to read response body")?
    {
        if bytes.len().saturating_add(chunk.len()) > MAX_SUBSCRIPTION_BYTES {
            bail!("subscription response exceeded limit of {MAX_SUBSCRIPTION_BYTES} bytes");
        }
        bytes.extend_from_slice(&chunk);
    }

    if let Some(parent) = output_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let tmp_path = output_path.with_extension("yaml.tmp");
    write_restricted_file(&tmp_path, &bytes)
        .await
        .with_context(|| format!("failed to write {}", tmp_path.display()))?;

    if let Err(e) = tokio::fs::rename(&tmp_path, output_path).await {
        let _ = tokio::fs::remove_file(&tmp_path).await;
        return Err(e).with_context(|| {
            format!(
                "failed to rename {} -> {}",
                tmp_path.display(),
                output_path.display()
            )
        });
    }

    set_owner_only_permissions(output_path)
        .await
        .with_context(|| format!("failed to secure {}", output_path.display()))?;

    tracing::info!(path = %output_path.display(), bytes = bytes.len(), "subscription downloaded");
    Ok(())
}

#[cfg(unix)]
async fn write_restricted_file(path: &Path, bytes: &[u8]) -> Result<()> {
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
async fn write_restricted_file(path: &Path, bytes: &[u8]) -> Result<()> {
    tokio::fs::write(path, bytes).await?;
    Ok(())
}

#[cfg(unix)]
async fn set_owner_only_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await?;
    Ok(())
}

#[cfg(not(unix))]
async fn set_owner_only_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

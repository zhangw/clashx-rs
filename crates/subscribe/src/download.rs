//! Downloading subscription configs over HTTP.
//!
//! Responses are size-capped (8 MiB) and written to a sibling `.yaml.tmp` file
//! that is renamed into place, so readers never see a partial config. On Unix
//! the temp and final files are `0600`.

use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use reqwest::Client;

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

    crate::fsutil::write_atomic_async(output_path, &bytes).await?;

    tracing::info!(path = %output_path.display(), bytes = bytes.len(), "subscription downloaded");
    Ok(())
}

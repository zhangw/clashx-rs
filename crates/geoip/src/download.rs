use std::path::Path;

use crate::GeoIpError;

/// Default download URL: Dreamacro/maxmind-geoip GitHub releases (same mirror used by Clash).
pub const DEFAULT_MMDB_URL: &str =
    "https://github.com/Dreamacro/maxmind-geoip/releases/latest/download/Country.mmdb";

/// Download an mmdb file to `output_path`.
///
/// Streams the response to a `.tmp` file, then atomically renames it to avoid
/// partial files being loaded by a concurrent daemon startup.
pub async fn download_mmdb(
    url: Option<&str>,
    proxy: Option<&str>,
    output_path: &Path,
) -> Result<(), GeoIpError> {
    let url = url.unwrap_or(DEFAULT_MMDB_URL);

    let mut builder = reqwest::Client::builder();
    if let Some(proxy_url) = proxy {
        let p = reqwest::Proxy::all(proxy_url)
            .map_err(|e| GeoIpError::Download(format!("invalid proxy URL: {e}")))?;
        builder = builder.proxy(p);
    }
    let client = builder
        .build()
        .map_err(|e| GeoIpError::Download(format!("failed to build HTTP client: {e}")))?;

    tracing::info!(url = %url, "downloading mmdb");

    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| GeoIpError::Download(format!("HTTP request failed: {e}")))?;

    if !response.status().is_success() {
        return Err(GeoIpError::Download(format!(
            "HTTP {} from {url}",
            response.status()
        )));
    }

    let tmp_path = output_path.with_extension("mmdb.tmp");

    // Ensure parent directory exists
    if let Some(parent) = output_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| GeoIpError::Download(format!("failed to create directory: {e}")))?;
    }

    let bytes = response
        .bytes()
        .await
        .map_err(|e| GeoIpError::Download(format!("failed to read response body: {e}")))?;

    tokio::fs::write(&tmp_path, &bytes)
        .await
        .map_err(|e| GeoIpError::Download(format!("failed to write temp file: {e}")))?;

    // Atomic rename
    tokio::fs::rename(&tmp_path, output_path)
        .await
        .map_err(|e| {
            // Best-effort cleanup of temp file
            let _ = std::fs::remove_file(&tmp_path);
            GeoIpError::Download(format!("failed to rename temp file: {e}"))
        })?;

    tracing::info!(path = %output_path.display(), "mmdb downloaded successfully");
    Ok(())
}

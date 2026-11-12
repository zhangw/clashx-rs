//! CLI-side client for the daemon control socket.
//!
//! Sends one JSON request line and reads one JSON response line over the Unix
//! socket at [`crate::paths::socket_path`]. Reporting and exit behavior for
//! the user live in the `send_command*` helpers; transport errors are ordinary
//! `anyhow` errors.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;

use anyhow::Result;

use crate::control::{ControlRequest, ControlResponse};

fn send_raw(request: &ControlRequest, port: u16) -> Result<ControlResponse> {
    let path = crate::paths::socket_path(port);
    let mut stream = UnixStream::connect(&path).map_err(|e| {
        anyhow::anyhow!(
            "failed to connect to daemon socket at {}: {}",
            path.display(),
            e
        )
    })?;

    let mut payload = serde_json::to_string(&request)?;
    payload.push('\n');
    stream.write_all(payload.as_bytes())?;

    let mut reader = BufReader::new(&stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;

    Ok(serde_json::from_str(line.trim())?)
}

/// Send a command, print the response payload (or `ok`/`error`), and exit
/// non-zero on failure. Intended for interactive CLI commands.
pub fn send_command(request: ControlRequest, port: u16) -> Result<()> {
    let resp = send_raw(&request, port)?;
    if resp.ok {
        if let Some(data) = resp.data {
            println!("{}", serde_json::to_string_pretty(&data)?);
        } else {
            println!("ok");
        }
        Ok(())
    } else {
        let err = resp.error.unwrap_or_else(|| "unknown error".to_string());
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

/// Best-effort send — returns Err when the daemon is not running or rejects the
/// request. Intended for callers that want to decide how to report failures.
pub fn send_command_quiet(request: ControlRequest, port: u16) -> Result<()> {
    let resp = send_raw(&request, port)?;
    if resp.ok {
        Ok(())
    } else {
        Err(anyhow::anyhow!(resp
            .error
            .unwrap_or_else(|| "unknown error".to_string())))
    }
}

/// Send a command and return the response data on success, or an error.
/// Send a command and return its JSON payload. Used by commands that format
/// the result themselves.
pub fn send_command_with_data(request: ControlRequest, port: u16) -> Result<serde_json::Value> {
    let resp = send_raw(&request, port)?;
    if resp.ok {
        resp.data
            .ok_or_else(|| anyhow::anyhow!("daemon returned success with no data"))
    } else {
        Err(anyhow::anyhow!(resp
            .error
            .unwrap_or_else(|| "unknown error".to_string())))
    }
}

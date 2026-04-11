use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;

use anyhow::Result;

use crate::control::{ControlRequest, ControlResponse};

pub fn send_command(request: ControlRequest) -> Result<()> {
    let path = crate::paths::socket_path();
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

    let resp: ControlResponse = serde_json::from_str(line.trim())?;
    if resp.ok {
        if let Some(data) = resp.data {
            println!("{}", serde_json::to_string_pretty(&data)?);
        } else {
            println!("ok");
        }
    } else {
        let err = resp.error.unwrap_or_else(|| "unknown error".to_string());
        eprintln!("error: {err}");
        std::process::exit(1);
    }

    Ok(())
}

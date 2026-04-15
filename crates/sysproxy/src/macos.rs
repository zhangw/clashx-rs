use anyhow::{anyhow, Context, Result};
use std::process::Command;

fn run_networksetup(args: &[&str]) -> Result<String> {
    let output = Command::new("networksetup")
        .args(args)
        .output()
        .context("failed to execute networksetup")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!(
            "networksetup command failed with status {}: {}",
            output.status,
            stderr.trim()
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn get_active_services() -> Result<Vec<String>> {
    let stdout = run_networksetup(&["-listallnetworkservices"])?;

    let services = stdout
        .lines()
        .skip(1) // skip the header line
        .filter(|line| !line.starts_with('*')) // skip disabled services
        .map(|line| line.to_string())
        .collect();

    Ok(services)
}

/// Default bypass entries applied when no explicit bypass list is provided.
const DEFAULT_BYPASS: &[&str] = &[
    "192.168.0.0/16",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "127.0.0.1",
    "localhost",
    "*.local",
];

pub fn enable(port: u16, bypass: &[String]) -> Result<()> {
    let services = get_active_services()?;
    let host = "127.0.0.1";
    let port_str = port.to_string();

    let bypass_list: Vec<&str> = if bypass.is_empty() {
        DEFAULT_BYPASS.to_vec()
    } else {
        bypass.iter().map(|s| s.as_str()).collect()
    };

    for service in &services {
        run_networksetup(&["-setwebproxy", service, host, &port_str])
            .with_context(|| format!("failed to set web proxy for {service}"))?;

        run_networksetup(&["-setsecurewebproxy", service, host, &port_str])
            .with_context(|| format!("failed to set secure web proxy for {service}"))?;

        run_networksetup(&["-setsocksfirewallproxy", service, host, &port_str])
            .with_context(|| format!("failed to set SOCKS proxy for {service}"))?;

        // Set proxy bypass domains/subnets
        let mut args = vec!["-setproxybypassdomains", service];
        args.extend(&bypass_list);
        run_networksetup(&args)
            .with_context(|| format!("failed to set proxy bypass for {service}"))?;
    }

    Ok(())
}

pub fn disable() -> Result<()> {
    let services = get_active_services()?;

    for service in &services {
        run_networksetup(&["-setwebproxystate", service, "off"])
            .with_context(|| format!("failed to disable web proxy for {service}"))?;

        run_networksetup(&["-setsecurewebproxystate", service, "off"])
            .with_context(|| format!("failed to disable secure web proxy for {service}"))?;

        run_networksetup(&["-setsocksfirewallproxystate", service, "off"])
            .with_context(|| format!("failed to disable SOCKS proxy for {service}"))?;
    }

    Ok(())
}

pub fn status() -> Result<String> {
    let services = get_active_services()?;
    let mut result = String::new();

    for service in &services {
        let info = run_networksetup(&["-getwebproxy", service])
            .with_context(|| format!("failed to get web proxy status for {service}"))?;

        result.push_str(&format!("[{service}]\n{info}\n"));
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_active_services_returns_list() {
        // On macOS, this should return at least one service
        let services = get_active_services().unwrap();
        assert!(
            !services.is_empty(),
            "expected at least one network service"
        );
    }
}

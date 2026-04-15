mod client;
mod control;
mod daemon;
mod paths;
mod retry;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use clashx_rs_sysproxy::SysProxy;
use tracing_subscriber::EnvFilter;

use control::ControlRequest;

/// clashx-rs — a Clash-compatible proxy daemon
#[derive(Debug, Parser)]
#[command(name = "clashx-rs", version, about)]
struct Cli {
    /// Config file path (used by `run`, `sysproxy on`, and to resolve port for control commands)
    #[arg(
        short,
        long,
        global = true,
        default_value = "~/.config/clashx-rs/config.yaml"
    )]
    config: String,
    /// Override the daemon mixed-port (falls back to config, then default)
    #[arg(long, global = true)]
    port: Option<u16>,
    #[command(subcommand)]
    command: Command,
}

/// Resolve the daemon port: explicit --port wins, else config mixed-port, else default.
fn resolve_port(cli: &Cli) -> u16 {
    if let Some(p) = cli.port {
        return p;
    }
    let path = expand_tilde(&cli.config);
    match clashx_rs_config::load_config(&path) {
        Ok(c) => c.mixed_port.unwrap_or(paths::DEFAULT_MIXED_PORT),
        Err(e) => {
            tracing::warn!(
                path = %path.display(),
                err = %e,
                "failed to load config, using default port"
            );
            paths::DEFAULT_MIXED_PORT
        }
    }
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Start the proxy daemon
    Run {
        /// Run as a background daemon
        #[arg(short = 'd', long)]
        daemon: bool,
        /// Override the selected proxy in a group at startup (GROUP=PROXY)
        #[arg(long = "select", value_name = "GROUP=PROXY")]
        selections: Vec<String>,
        /// Path to the GeoIP mmdb database file
        #[arg(long = "mmdb")]
        mmdb: Option<String>,
        /// If mmdb is missing, download it in the background after proxy starts
        #[arg(long = "mmdb-auto-download")]
        mmdb_auto_download: bool,
    },
    /// Stop the running daemon
    Stop,
    /// Reload the daemon configuration
    Reload,
    /// Show daemon status
    Status,
    /// List all proxies
    Proxies,
    /// List proxy groups
    Groups,
    /// List active rules
    Rules,
    /// Switch the active proxy in a group
    Switch {
        /// Proxy group name
        group: String,
        /// Proxy name to activate
        proxy: String,
    },
    /// Test reachability of a domain
    Test {
        /// Domain to test
        domain: String,
    },
    /// Manage system proxy settings
    Sysproxy {
        #[command(subcommand)]
        action: SysproxyAction,
    },
    /// Download the GeoIP mmdb database
    MmdbDownload {
        /// SOCKS5 or HTTP proxy URL for the download
        #[arg(long)]
        proxy: Option<String>,
        /// Override the download URL
        #[arg(long)]
        url: Option<String>,
        /// Output file path
        #[arg(long)]
        output: Option<String>,
    },
}

#[derive(Debug, Subcommand, Clone)]
enum SysproxyAction {
    /// Enable system proxy
    On {
        /// Subnets/domains to bypass the proxy (default: private ranges + localhost)
        #[arg(long = "bypass")]
        bypass: Vec<String>,
    },
    /// Disable system proxy
    Off,
    /// Show system proxy status
    Status,
}

fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("~"));
        home.join(rest)
    } else if path == "~" {
        dirs::home_dir().unwrap_or_else(|| PathBuf::from("~"))
    } else {
        PathBuf::from(path)
    }
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let config_path = expand_tilde(&cli.config);
    let ctrl_port = resolve_port(&cli);

    match cli.command {
        Command::Run {
            daemon,
            selections,
            mmdb,
            mmdb_auto_download,
        } => {
            rustls::crypto::ring::default_provider()
                .install_default()
                .ok();
            let mmdb_path = mmdb
                .map(|p| expand_tilde(&p))
                .unwrap_or_else(paths::default_mmdb_path);
            if daemon {
                daemon::start_background(&config_path, &selections, mmdb_path, mmdb_auto_download)?;
            } else {
                daemon::start_foreground(&config_path, &selections, mmdb_path, mmdb_auto_download)?;
            }
        }

        Command::Stop => client::send_command(ControlRequest::Stop, ctrl_port)?,
        Command::Reload => client::send_command(ControlRequest::Reload, ctrl_port)?,
        Command::Status => client::send_command(ControlRequest::Status, ctrl_port)?,
        Command::Proxies => client::send_command(ControlRequest::Proxies, ctrl_port)?,
        Command::Groups => client::send_command(ControlRequest::Groups, ctrl_port)?,
        Command::Rules => client::send_command(ControlRequest::Rules, ctrl_port)?,

        Command::Switch { group, proxy } => {
            client::send_command(ControlRequest::Switch { group, proxy }, ctrl_port)?
        }

        Command::Test { domain } => {
            client::send_command(ControlRequest::Test { domain }, ctrl_port)?
        }

        Command::Sysproxy { action } => match action {
            SysproxyAction::On { bypass } => {
                // Priority: CLI --bypass > config skip-proxy > built-in defaults
                let bypass_rules = if !bypass.is_empty() {
                    bypass
                } else {
                    clashx_rs_config::load_config(&config_path)
                        .ok()
                        .map(|c| c.skip_proxy)
                        .unwrap_or_default()
                };
                SysProxy::new(ctrl_port).enable_with_bypass(&bypass_rules)?;
                if bypass_rules.is_empty() {
                    println!("system proxy enabled on port {ctrl_port} (default bypass rules)");
                } else {
                    println!(
                        "system proxy enabled on port {ctrl_port} (bypass: {})",
                        bypass_rules.join(", ")
                    );
                }
            }
            SysproxyAction::Off => {
                SysProxy::new(ctrl_port).disable()?;
                println!("system proxy disabled");
            }
            SysproxyAction::Status => {
                let status = SysProxy::new(ctrl_port).status()?;
                println!("{status}");
            }
        },

        Command::MmdbDownload { proxy, url, output } => {
            rustls::crypto::ring::default_provider()
                .install_default()
                .ok();
            let output_path = output
                .map(|p| expand_tilde(&p))
                .unwrap_or_else(paths::default_mmdb_path);

            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            rt.block_on(async {
                clashx_rs_geoip::download::download_mmdb(
                    url.as_deref(),
                    proxy.as_deref(),
                    &output_path,
                )
                .await
            })
            .map_err(|e| anyhow::anyhow!("{e}"))?;

            println!("mmdb downloaded to {}", output_path.display());
        }
    }

    Ok(())
}

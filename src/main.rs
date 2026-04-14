mod client;
mod control;
mod daemon;
mod paths;
mod retry;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use clashx_rs_sysproxy::SysProxy;
use tracing_subscriber::EnvFilter;

use control::ControlRequest;

/// clashx-rs — a Clash-compatible proxy daemon
#[derive(Debug, Parser)]
#[command(name = "clashx-rs", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Start the proxy daemon
    Run {
        /// Path to the configuration file
        #[arg(short, long, default_value = "~/.config/clashx-rs/config.yaml")]
        config: String,
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
        /// Config file to read mixed-port from
        #[arg(short, long, default_value = "~/.config/clashx-rs/config.yaml")]
        config: String,
        /// Subnets/domains to bypass the proxy (default: private ranges + localhost)
        #[arg(long = "bypass")]
        bypass: Vec<String>,
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

#[derive(Debug, Subcommand, Clone, ValueEnum)]
enum SysproxyAction {
    /// Enable system proxy
    On,
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

    match cli.command {
        Command::Run {
            config,
            daemon,
            selections,
            mmdb,
            mmdb_auto_download,
        } => {
            rustls::crypto::ring::default_provider()
                .install_default()
                .ok();
            let config_path = expand_tilde(&config);
            let mmdb_path = mmdb
                .map(|p| expand_tilde(&p))
                .unwrap_or_else(paths::default_mmdb_path);
            if daemon {
                daemon::start_background(&config_path, &selections, mmdb_path, mmdb_auto_download)?;
            } else {
                daemon::start_foreground(&config_path, &selections, mmdb_path, mmdb_auto_download)?;
            }
        }

        Command::Stop => client::send_command(ControlRequest::Stop)?,
        Command::Reload => client::send_command(ControlRequest::Reload)?,
        Command::Status => client::send_command(ControlRequest::Status)?,
        Command::Proxies => client::send_command(ControlRequest::Proxies)?,
        Command::Groups => client::send_command(ControlRequest::Groups)?,
        Command::Rules => client::send_command(ControlRequest::Rules)?,

        Command::Switch { group, proxy } => {
            client::send_command(ControlRequest::Switch { group, proxy })?
        }

        Command::Test { domain } => client::send_command(ControlRequest::Test { domain })?,

        Command::Sysproxy {
            action,
            config,
            bypass,
        } => {
            let config_path = expand_tilde(&config);
            let cfg = clashx_rs_config::load_config(&config_path).ok();
            let port = cfg
                .as_ref()
                .and_then(|c| c.mixed_port)
                .unwrap_or(paths::DEFAULT_MIXED_PORT);
            // Priority: CLI --bypass > config skip-proxy > built-in defaults
            let bypass_rules = if !bypass.is_empty() {
                bypass
            } else {
                cfg.as_ref()
                    .map(|c| c.skip_proxy.clone())
                    .unwrap_or_default()
            };
            let sp = SysProxy::new(port);
            match action {
                SysproxyAction::On => {
                    sp.enable_with_bypass(&bypass_rules)?;
                    if bypass_rules.is_empty() {
                        println!("system proxy enabled on port {port} (default bypass rules)");
                    } else {
                        println!(
                            "system proxy enabled on port {port} (bypass: {})",
                            bypass_rules.join(", ")
                        );
                    }
                }
                SysproxyAction::Off => {
                    sp.disable()?;
                    println!("system proxy disabled");
                }
                SysproxyAction::Status => {
                    let status = sp.status()?;
                    println!("{status}");
                }
            }
        }

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

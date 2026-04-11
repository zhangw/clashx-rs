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
        } => {
            rustls::crypto::ring::default_provider()
                .install_default()
                .ok();
            let config_path = expand_tilde(&config);
            if daemon {
                daemon::start_background(&config_path, &selections)?;
            } else {
                daemon::start_foreground(&config_path, &selections)?;
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

        Command::Sysproxy { action } => {
            let sp = SysProxy::new(paths::DEFAULT_MIXED_PORT);
            match action {
                SysproxyAction::On => {
                    sp.enable()?;
                    println!("system proxy enabled on port 7890");
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
    }

    Ok(())
}

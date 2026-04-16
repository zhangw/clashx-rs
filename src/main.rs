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
    /// Manage config subscriptions
    Subscribe {
        #[command(subcommand)]
        action: SubscribeAction,
    },
}

#[derive(Debug, Subcommand)]
enum SubscribeAction {
    /// Add a new subscription
    Add {
        #[arg(long)]
        name: String,
        #[arg(long)]
        url: String,
        #[arg(long)]
        output: String,
        #[arg(long, default_value = "86400")]
        interval: u64,
    },
    /// Remove a subscription by name
    Remove {
        /// Subscription name
        name: String,
    },
    /// List all subscriptions
    List,
    /// Download subscription configs now
    Update {
        /// Update only this subscription (all if omitted)
        #[arg(long)]
        name: Option<String>,
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

        Command::Subscribe { action } => {
            run_subscribe(action, ctrl_port)?;
        }
    }

    Ok(())
}

fn run_subscribe(action: SubscribeAction, ctrl_port: u16) -> Result<()> {
    use clashx_rs_subscribe::{
        add_subscription, load_subscriptions, remove_subscription, save_subscriptions,
        update_all_subscriptions, update_subscription_by_name, Subscription, SubscriptionConfig,
    };

    match action {
        SubscribeAction::Add {
            name,
            url,
            output,
            interval,
        } => {
            let mut config = load_subscriptions()?;
            add_subscription(
                &mut config,
                Subscription {
                    name: name.clone(),
                    url,
                    output,
                    interval,
                    last_updated: 0,
                },
            )?;
            save_subscriptions(&config)?;
            println!("added subscription '{name}'");
        }

        SubscribeAction::Remove { name } => {
            let mut config = load_subscriptions()?;
            remove_subscription(&mut config, &name)?;
            save_subscriptions(&config)?;
            println!("removed subscription '{name}'");
        }

        SubscribeAction::List => {
            let config: SubscriptionConfig = load_subscriptions()?;
            if config.subscriptions.is_empty() {
                println!("no subscriptions configured");
            } else {
                for sub in &config.subscriptions {
                    let last = if sub.last_updated == 0 {
                        "never".to_string()
                    } else {
                        format_unix_time(sub.last_updated)
                    };
                    println!("- {}", sub.name);
                    println!("    url:          {}", redact_url_for_display(&sub.url));
                    println!("    output:       {}", sub.output);
                    println!("    interval:     {}s", sub.interval);
                    println!("    last_updated: {last}");
                }
            }
        }

        SubscribeAction::Update { name } => {
            rustls::crypto::ring::default_provider()
                .install_default()
                .ok();
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            let mut config = load_subscriptions()?;
            let had_success = rt.block_on(async {
                let mut any_ok = false;
                if let Some(target) = name.as_deref() {
                    match update_subscription_by_name(&mut config, target).await {
                        Ok(()) => {
                            println!("updated subscription '{target}'");
                            any_ok = true;
                        }
                        Err(e) => {
                            eprintln!("error: {e}");
                        }
                    }
                } else {
                    let results = update_all_subscriptions(&mut config).await;
                    if results.is_empty() {
                        println!("no subscriptions configured");
                    }
                    for (sub_name, result) in results {
                        match result {
                            Ok(()) => {
                                println!("updated subscription '{sub_name}'");
                                any_ok = true;
                            }
                            Err(e) => {
                                eprintln!("error updating '{sub_name}': {e}");
                            }
                        }
                    }
                }
                any_ok
            });
            save_subscriptions(&config)?;

            if had_success {
                // Best-effort reload — daemon may not be running.
                match client::send_command_quiet(ControlRequest::Reload, ctrl_port) {
                    Ok(()) => println!("daemon reloaded"),
                    Err(_) => println!("daemon not running — reload skipped"),
                }
            }
        }
    }

    Ok(())
}

fn format_unix_time(ts: u64) -> String {
    // Format as "YYYY-MM-DD HH:MM:SS UTC" without pulling in chrono.
    let secs = ts as i64;
    let days_since_epoch = secs.div_euclid(86400);
    let time_of_day = secs.rem_euclid(86400);
    let hour = time_of_day / 3600;
    let minute = (time_of_day % 3600) / 60;
    let second = time_of_day % 60;

    // Civil-from-days algorithm (Howard Hinnant, public domain).
    let z = days_since_epoch + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!("{y:04}-{m:02}-{d:02} {hour:02}:{minute:02}:{second:02} UTC")
}

fn redact_url_for_display(url: &str) -> String {
    let (base, fragment) = match url.split_once('#') {
        Some((base, fragment)) => (base, Some(fragment)),
        None => (url, None),
    };
    let (base, had_query) = match base.split_once('?') {
        Some((base, _query)) => (base, true),
        None => (base, false),
    };

    let redacted_auth = if let Some((scheme, rest)) = base.split_once("://") {
        let redacted_rest = if let Some((userinfo, host_and_path)) = rest.split_once('@') {
            if userinfo.contains('/') {
                rest.to_string()
            } else {
                format!("***@{host_and_path}")
            }
        } else {
            rest.to_string()
        };
        format!("{scheme}://{redacted_rest}")
    } else {
        base.to_string()
    };

    let mut out = redacted_auth;
    if had_query {
        out.push_str("?REDACTED");
    }
    if fragment.is_some() {
        out.push_str("#REDACTED");
    }
    out
}

#[cfg(test)]
mod cli_tests {
    use super::redact_url_for_display;

    #[test]
    fn redact_url_hides_query_and_fragment() {
        let url = "https://example.com/sub?token=secret#frag";
        assert_eq!(
            redact_url_for_display(url),
            "https://example.com/sub?REDACTED#REDACTED"
        );
    }

    #[test]
    fn redact_url_hides_userinfo() {
        let url = "https://user:pass@example.com/sub";
        assert_eq!(redact_url_for_display(url), "https://***@example.com/sub");
    }

    #[test]
    fn redact_url_leaves_plain_url_unchanged() {
        let url = "https://example.com/sub";
        assert_eq!(redact_url_for_display(url), url);
    }
}

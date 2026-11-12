//! JSON request/response types shared by the daemon control socket and CLI.
//!
//! The protocol is line-oriented: one serialized [`ControlRequest`] per line
//! and one [`ControlResponse`] per line. Both sides derive the wire format
//! from these types, so field renames are protocol changes.

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "lowercase")]
pub enum ControlRequest {
    /// Report daemon status: port, mode, config path, proxy/rule/group counts,
    /// selections, and resource counters.
    Status,
    /// Ask the daemon to shut down.
    Stop,
    /// Re-read the config file and rebuild resolvers, rules, and proxies.
    Reload,
    /// Select `proxy` inside `group` until the next config reload.
    Switch { group: String, proxy: String },
    /// List the configured proxies.
    Proxies,
    /// List proxy groups and their current selections.
    Groups,
    /// List the parsed rules in evaluation order.
    Rules,
    /// Resolve routing for `domain`: resolve DNS lazily for `IP-CIDR`/`GEOIP`
    /// rules, skip `PROCESS-NAME` (no client source address), and report the
    /// decision plus whether process rules were skipped.
    Test { domain: String },
    /// Measure latency for every proxy; `full` performs an HTTP round trip
    /// instead of a TCP connect.
    Latency { full: bool },
    /// Flush resolver caches, optionally only the entry for `host`.
    DnsFlush { host: Option<String> },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ControlResponse {
    /// Whether the request succeeded.
    pub ok: bool,
    /// Command-specific payload on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    /// Human-readable failure description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ControlResponse {
    /// Success response carrying a JSON payload.
    pub fn success(data: serde_json::Value) -> Self {
        ControlResponse {
            ok: true,
            data: Some(data),
            error: None,
        }
    }

    /// Failure response carrying a human-readable message.
    pub fn error(msg: impl Into<String>) -> Self {
        ControlResponse {
            ok: false,
            data: None,
            error: Some(msg.into()),
        }
    }

    /// Success response without a payload.
    pub fn ok() -> Self {
        ControlResponse {
            ok: true,
            data: None,
            error: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_switch_request() {
        let req = ControlRequest::Switch {
            group: "Proxy".to_string(),
            proxy: "node1".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains(r#""command":"switch""#));
        assert!(json.contains("Proxy"));
    }

    #[test]
    fn deserialize_status_request() {
        let json = r#"{"command":"status"}"#;
        let req: ControlRequest = serde_json::from_str(json).unwrap();
        assert!(matches!(req, ControlRequest::Status));
    }

    #[test]
    fn serialize_response() {
        let resp = ControlResponse::error("something went wrong");
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains(r#""ok":false"#));
        assert!(json.contains("something went wrong"));
    }

    #[test]
    fn serialize_latency_request() {
        let req = ControlRequest::Latency { full: true };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains(r#""command":"latency""#));
        assert!(json.contains(r#""full":true"#));
    }

    #[test]
    fn deserialize_latency_request() {
        let json = r#"{"command":"latency","full":false}"#;
        let req: ControlRequest = serde_json::from_str(json).unwrap();
        assert!(matches!(req, ControlRequest::Latency { full: false }));
    }

    #[test]
    fn serialize_dnsflush_request() {
        let req = ControlRequest::DnsFlush {
            host: Some("example.com".to_string()),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains(r#""command":"dnsflush""#));
        assert!(json.contains(r#""host":"example.com""#));
    }

    #[test]
    fn deserialize_dnsflush_without_host() {
        let json = r#"{"command":"dnsflush","host":null}"#;
        let req: ControlRequest = serde_json::from_str(json).unwrap();
        assert!(matches!(req, ControlRequest::DnsFlush { host: None }));
    }
}

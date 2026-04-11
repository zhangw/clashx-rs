use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "lowercase")]
pub enum ControlRequest {
    Status,
    Stop,
    Reload,
    Switch { group: String, proxy: String },
    Proxies,
    Groups,
    Rules,
    Test { domain: String },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ControlResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ControlResponse {
    #[allow(dead_code)]
    pub fn success(data: serde_json::Value) -> Self {
        ControlResponse {
            ok: true,
            data: Some(data),
            error: None,
        }
    }

    #[allow(dead_code)]
    pub fn error(msg: impl Into<String>) -> Self {
        ControlResponse {
            ok: false,
            data: None,
            error: Some(msg.into()),
        }
    }

    #[allow(dead_code)]
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
}

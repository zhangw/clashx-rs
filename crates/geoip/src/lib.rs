use std::fmt;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

pub mod download;

/// A loaded MaxMind GeoIP database.
pub struct GeoIpDb {
    reader: maxminddb::Reader<Vec<u8>>,
}

impl GeoIpDb {
    /// Load an mmdb file from disk.
    pub fn open(path: &Path) -> Result<Self, GeoIpError> {
        let reader = maxminddb::Reader::open_readfile(path)
            .map_err(|e| GeoIpError::Open(path.to_path_buf(), e))?;
        Ok(Self { reader })
    }

    /// Look up the ISO 3166-1 alpha-2 country code for an IP address.
    /// Returns None if the IP is not found in the database (e.g., private ranges).
    pub fn lookup_country(&self, ip: IpAddr) -> Option<&str> {
        let result = self.reader.lookup(ip).ok()?;
        let result: maxminddb::geoip2::Country = result.decode().ok()??;
        result.country.iso_code
    }
}

#[derive(Debug)]
pub enum GeoIpError {
    Open(PathBuf, maxminddb::MaxMindDbError),
    Download(String),
}

impl fmt::Display for GeoIpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GeoIpError::Open(path, e) => {
                write!(f, "failed to open mmdb at {}: {}", path.display(), e)
            }
            GeoIpError::Download(msg) => write!(f, "mmdb download failed: {msg}"),
        }
    }
}

impl std::error::Error for GeoIpError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_fixture_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/GeoIP2-Country-Test.mmdb")
    }

    #[test]
    fn lookup_known_ip() {
        let db = GeoIpDb::open(&test_fixture_path()).unwrap();
        // 2.125.160.216 is mapped to GB in MaxMind test data
        let ip: IpAddr = "2.125.160.216".parse().unwrap();
        assert_eq!(db.lookup_country(ip), Some("GB"));
    }

    #[test]
    fn lookup_another_country() {
        let db = GeoIpDb::open(&test_fixture_path()).unwrap();
        // 89.160.20.112 is mapped to SE in MaxMind test data
        let ip: IpAddr = "89.160.20.112".parse().unwrap();
        assert_eq!(db.lookup_country(ip), Some("SE"));
    }

    #[test]
    fn lookup_private_ip_returns_none() {
        let db = GeoIpDb::open(&test_fixture_path()).unwrap();
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert_eq!(db.lookup_country(ip), None);
    }

    #[test]
    fn lookup_ipv6() {
        let db = GeoIpDb::open(&test_fixture_path()).unwrap();
        // 2001:218:: is mapped to JP in MaxMind test data
        let ip: IpAddr = "2001:218::1".parse().unwrap();
        assert_eq!(db.lookup_country(ip), Some("JP"));
    }

    #[test]
    fn open_nonexistent_file() {
        let result = GeoIpDb::open(Path::new("/nonexistent/path.mmdb"));
        assert!(result.is_err());
        let err = result.err().expect("expected error");
        assert!(matches!(err, GeoIpError::Open(_, _)));
        assert!(err.to_string().contains("/nonexistent/path.mmdb"));
    }

    #[test]
    fn open_invalid_file() {
        // Cargo.toml is not a valid mmdb file
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        let result = GeoIpDb::open(&manifest);
        assert!(result.is_err());
    }
}

use crate::conf::raw::{CertConfig, GlobalConfig, ServerConfig, SimpleProxyConfig, UpstreamConfig};
use anyhow::{Context, Result, anyhow};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fs;

#[derive(Debug, Clone)]
pub struct ProxyConfigResolved {
    pub global: GlobalConfigResolved,
    pub servers: HashMap<String, ServerConfigResolved>,
}

#[derive(Debug, Clone)]
pub struct GlobalConfigResolved {
    pub port: u16,
    pub tls: Option<CertConfigResolved>,
}

#[derive(Debug, Clone)]
pub struct CertConfigResolved {
    pub cert: String,
    pub key: String,
}

#[derive(Debug, Clone)]
pub struct ServerConfigResolved {
    pub tls: Option<CertConfigResolved>,
    pub upstream: UpstreamConfigResolved,
}

#[derive(Debug, Clone)]
pub struct UpstreamConfigResolved {
    pub servers: Vec<String>,
}

impl TryFrom<&CertConfig> for CertConfigResolved {
    type Error = anyhow::Error;

    fn try_from(cert: &CertConfig) -> Result<Self, Self::Error> {
        let cert_path = cert.cert_path.as_path();
        let key_path = cert.key_path.as_path();

        // Load certificate and key contents
        let cert_content = fs::read_to_string(cert_path)
            .with_context(|| format!("Failed to load certificate from: {:?}", cert_path))?;

        let key_content = fs::read_to_string(key_path)
            .with_context(|| format!("Failed to load key from: {:?}", key_path))?;

        Ok(CertConfigResolved {
            cert: cert_content,
            key: key_content,
        })
    }
}

impl From<&UpstreamConfig> for UpstreamConfigResolved {
    fn from(upstream: &UpstreamConfig) -> Self {
        UpstreamConfigResolved {
            servers: upstream.servers.clone(),
        }
    }
}

impl TryFrom<SimpleProxyConfig> for ProxyConfigResolved {
    type Error = anyhow::Error;

    fn try_from(raw: SimpleProxyConfig) -> Result<Self, Self::Error> {
        // Build cert map for lookups
        let mut cert_map = HashMap::new();
        for cert in &raw.certs {
            let resolved_cert = CertConfigResolved::try_from(cert)?;
            cert_map.insert(cert.name.clone(), resolved_cert);
        }

        // Build upstream map for lookups
        let mut upstream_map = HashMap::new();
        for upstream in &raw.upstreams {
            let resolved_upstream = UpstreamConfigResolved::from(upstream);
            upstream_map.insert(upstream.name.clone(), resolved_upstream);
        }

        // Resolve global config
        let global = GlobalConfigResolved::try_from_with_map(&raw.global, &cert_map)?;

        // Resolve server configs
        let mut servers = HashMap::new();
        for server in raw.servers {
            let resolved_server =
                ServerConfigResolved::try_from_with_maps(&server, &cert_map, &upstream_map)?;

            // Add server for each domain name
            for server_name in server.server_name {
                if servers.contains_key(&server_name) {
                    return Err(anyhow!("Duplicate server name: {}", server_name));
                }
                servers.insert(server_name, resolved_server.clone());
            }
        }

        Ok(ProxyConfigResolved { global, servers })
    }
}

// Helper for GlobalConfigResolved that requires cert map for lookup
impl GlobalConfigResolved {
    fn try_from_with_map(
        global: &GlobalConfig,
        cert_map: &HashMap<String, CertConfigResolved>,
    ) -> Result<Self> {
        let tls = match &global.tls {
            Some(cert_name) => {
                let cert = cert_map
                    .get(cert_name)
                    .ok_or_else(|| anyhow!("Global TLS certificate '{}' not found", cert_name))?;
                Some(cert.clone())
            }
            None => None,
        };

        Ok(GlobalConfigResolved {
            port: global.port,
            tls,
        })
    }
}

// Helper for ServerConfigResolved that requires cert and upstream maps for lookups
impl ServerConfigResolved {
    fn try_from_with_maps(
        server: &ServerConfig,
        cert_map: &HashMap<String, CertConfigResolved>,
        upstream_map: &HashMap<String, UpstreamConfigResolved>,
    ) -> Result<Self> {
        // Resolve TLS for this server if configured
        let tls = match &server.tls {
            Some(cert_name) => {
                let cert = cert_map
                    .get(cert_name)
                    .ok_or_else(|| anyhow!("Server TLS certificate '{}' not found", cert_name))?;
                Some(cert.clone())
            }
            None => None,
        };

        // Get the upstream configuration
        let upstream_name = &server.upstream;
        let upstream = upstream_map
            .get(upstream_name)
            .ok_or_else(|| anyhow!("Upstream '{}' not found", upstream_name))?
            .clone();

        Ok(ServerConfigResolved { tls, upstream })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    // Helper to create a temporary file with content
    fn create_temp_file(dir: &TempDir, filename: &str, content: &str) -> PathBuf {
        let file_path = dir.path().join(filename);
        fs::write(&file_path, content).expect("Failed to write temp file");
        file_path
    }

    #[test]
    fn test_cert_config_resolved_try_from() {
        let temp_dir = TempDir::new().unwrap();

        // Create temporary cert and key files
        let cert_content = "-----BEGIN CERTIFICATE-----\nMIICert\n-----END CERTIFICATE-----";
        let key_content = "-----BEGIN PRIVATE KEY-----\nMIIKey\n-----END PRIVATE KEY-----";

        let cert_path = create_temp_file(&temp_dir, "cert.pem", cert_content);
        let key_path = create_temp_file(&temp_dir, "key.pem", key_content);

        // Create raw CertConfig
        let raw_cert = CertConfig {
            name: "test_cert".to_string(),
            cert_path,
            key_path,
        };

        // Convert to resolved
        let resolved_cert = CertConfigResolved::try_from(&raw_cert).unwrap();

        // Verify contents
        assert_eq!(resolved_cert.cert, cert_content);
        assert_eq!(resolved_cert.key, key_content);
    }

    #[test]
    fn test_upstream_config_resolved_from() {
        // Create raw UpstreamConfig
        let raw_upstream = UpstreamConfig {
            name: "test_upstream".to_string(),
            servers: vec!["127.0.0.1:8001".to_string(), "127.0.0.1:8002".to_string()],
        };

        // Convert to resolved
        let resolved_upstream = UpstreamConfigResolved::from(&raw_upstream);

        // Verify contents
        assert_eq!(resolved_upstream.servers.len(), 2);
        assert_eq!(resolved_upstream.servers[0], "127.0.0.1:8001");
        assert_eq!(resolved_upstream.servers[1], "127.0.0.1:8002");
    }

    #[test]
    fn test_global_config_resolved_without_tls() {
        // Create raw GlobalConfig without TLS
        let raw_global = GlobalConfig {
            port: 8080,
            tls: None,
        };

        // Create empty cert map
        let cert_map = HashMap::new();

        // Convert to resolved
        let resolved_global =
            GlobalConfigResolved::try_from_with_map(&raw_global, &cert_map).unwrap();

        // Verify contents
        assert_eq!(resolved_global.port, 8080);
        assert!(resolved_global.tls.is_none());
    }

    #[test]
    fn test_global_config_resolved_with_tls() {
        let temp_dir = TempDir::new().unwrap();

        // Create temporary cert and key files
        let cert_content = "-----BEGIN CERTIFICATE-----\nMIICert\n-----END CERTIFICATE-----";
        let key_content = "-----BEGIN PRIVATE KEY-----\nMIIKey\n-----END PRIVATE KEY-----";

        create_temp_file(&temp_dir, "cert.pem", cert_content);
        create_temp_file(&temp_dir, "key.pem", key_content);

        // Create raw GlobalConfig with TLS
        let raw_global = GlobalConfig {
            port: 8443,
            tls: Some("test_cert".to_string()),
        };

        // Create cert map with our test cert
        let mut cert_map = HashMap::new();
        cert_map.insert(
            "test_cert".to_string(),
            CertConfigResolved {
                cert: cert_content.to_string(),
                key: key_content.to_string(),
            },
        );

        // Convert to resolved
        let resolved_global =
            GlobalConfigResolved::try_from_with_map(&raw_global, &cert_map).unwrap();

        // Verify contents
        assert_eq!(resolved_global.port, 8443);
        assert!(resolved_global.tls.is_some());
        assert_eq!(resolved_global.tls.unwrap().cert, cert_content);
    }

    #[test]
    fn test_server_config_resolved() {
        // Create necessary maps
        let mut cert_map = HashMap::new();
        cert_map.insert(
            "test_cert".to_string(),
            CertConfigResolved {
                cert: "cert_content".to_string(),
                key: "key_content".to_string(),
            },
        );

        let mut upstream_map = HashMap::new();
        upstream_map.insert(
            "test_upstream".to_string(),
            UpstreamConfigResolved {
                servers: vec!["127.0.0.1:8001".to_string(), "127.0.0.1:8002".to_string()],
            },
        );

        // Create raw ServerConfig
        let raw_server = ServerConfig {
            server_name: vec!["example.com".to_string(), "www.example.com".to_string()],
            upstream: "test_upstream".to_string(),
            tls: Some("test_cert".to_string()),
        };

        // Convert to resolved
        let resolved_server =
            ServerConfigResolved::try_from_with_maps(&raw_server, &cert_map, &upstream_map)
                .unwrap();

        // Verify contents
        assert!(resolved_server.tls.is_some());
        assert_eq!(resolved_server.tls.unwrap().cert, "cert_content");
        assert_eq!(resolved_server.upstream.servers.len(), 2);
        assert_eq!(resolved_server.upstream.servers[0], "127.0.0.1:8001");
    }

    #[test]
    fn test_proxy_config_resolved_try_from() {
        let temp_dir = TempDir::new().unwrap();

        // Create temporary cert and key files
        let cert_content = "-----BEGIN CERTIFICATE-----\nMIICert\n-----END CERTIFICATE-----";
        let key_content = "-----BEGIN PRIVATE KEY-----\nMIIKey\n-----END PRIVATE KEY-----";

        let cert_path = create_temp_file(&temp_dir, "cert.pem", cert_content);
        let key_path = create_temp_file(&temp_dir, "key.pem", key_content);

        // Create a complete raw config
        let raw_config = SimpleProxyConfig {
            global: GlobalConfig {
                port: 8443,
                tls: Some("proxy_cert".to_string()),
            },
            certs: vec![
                CertConfig {
                    name: "proxy_cert".to_string(),
                    cert_path: cert_path.clone(),
                    key_path: key_path.clone(),
                },
                CertConfig {
                    name: "web_cert".to_string(),
                    cert_path,
                    key_path,
                },
            ],
            servers: vec![ServerConfig {
                server_name: vec!["example.com".to_string(), "www.example.com".to_string()],
                upstream: "web_servers".to_string(),
                tls: Some("web_cert".to_string()),
            }],
            upstreams: vec![UpstreamConfig {
                name: "web_servers".to_string(),
                servers: vec!["127.0.0.1:8001".to_string(), "127.0.0.1:8002".to_string()],
            }],
        };

        // Convert to resolved
        let resolved_config = ProxyConfigResolved::try_from(raw_config).unwrap();

        // Verify global config
        assert_eq!(resolved_config.global.port, 8443);
        assert!(resolved_config.global.tls.is_some());

        // Verify server configs
        assert!(resolved_config.servers.contains_key("example.com"));
        assert!(resolved_config.servers.contains_key("www.example.com"));

        let server = resolved_config.servers.get("example.com").unwrap();
        assert!(server.tls.is_some());
        assert_eq!(server.upstream.servers.len(), 2);
        assert_eq!(server.upstream.servers[0], "127.0.0.1:8001");
    }

    #[test]
    fn test_error_handling_unknown_cert() {
        // Create a config with a reference to a non-existent certificate
        let raw_config = SimpleProxyConfig {
            global: GlobalConfig {
                port: 8443,
                tls: Some("nonexistent_cert".to_string()),
            },
            certs: vec![],
            servers: vec![],
            upstreams: vec![],
        };

        // Try to convert - should fail
        let result = ProxyConfigResolved::try_from(raw_config);
        assert!(result.is_err());

        // Verify error message mentions the missing certificate
        let error = result.unwrap_err().to_string();
        assert!(error.contains("nonexistent_cert"));
    }

    #[test]
    fn test_error_handling_unknown_upstream() {
        let temp_dir = TempDir::new().unwrap();
        let cert_path = create_temp_file(&temp_dir, "cert.pem", "cert content");
        let key_path = create_temp_file(&temp_dir, "key.pem", "key content");

        // Create a config with a reference to a non-existent upstream
        let raw_config = SimpleProxyConfig {
            global: GlobalConfig {
                port: 8080,
                tls: None,
            },
            certs: vec![CertConfig {
                name: "test_cert".to_string(),
                cert_path,
                key_path,
            }],
            servers: vec![ServerConfig {
                server_name: vec!["example.com".to_string()],
                upstream: "nonexistent_upstream".to_string(),
                tls: None,
            }],
            upstreams: vec![],
        };

        // Try to convert - should fail
        let result = ProxyConfigResolved::try_from(raw_config);
        assert!(result.is_err());

        // Verify error message mentions the missing upstream
        let error = result.unwrap_err().to_string();
        assert!(error.contains("nonexistent_upstream"));
    }

    #[test]
    fn test_error_handling_duplicate_server_name() {
        let temp_dir = TempDir::new().unwrap();
        let cert_path = create_temp_file(&temp_dir, "cert.pem", "cert content");
        let key_path = create_temp_file(&temp_dir, "key.pem", "key content");

        // Create a config with duplicate server names
        let raw_config = SimpleProxyConfig {
            global: GlobalConfig {
                port: 8080,
                tls: None,
            },
            certs: vec![CertConfig {
                name: "test_cert".to_string(),
                cert_path,
                key_path,
            }],
            servers: vec![
                ServerConfig {
                    server_name: vec!["example.com".to_string(), "duplicate.com".to_string()],
                    upstream: "upstream1".to_string(),
                    tls: None,
                },
                ServerConfig {
                    server_name: vec!["other.com".to_string(), "duplicate.com".to_string()],
                    upstream: "upstream1".to_string(),
                    tls: None,
                },
            ],
            upstreams: vec![UpstreamConfig {
                name: "upstream1".to_string(),
                servers: vec!["127.0.0.1:8001".to_string()],
            }],
        };

        // Try to convert - should fail due to duplicate server name
        let result = ProxyConfigResolved::try_from(raw_config);
        assert!(result.is_err());

        // Verify error message mentions the duplicate server name
        let error = result.unwrap_err().to_string();
        assert!(error.contains("duplicate.com"));
    }
}

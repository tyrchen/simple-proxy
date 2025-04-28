use crate::conf::raw::{GlobalConfig, ServerConfig, SimpleProxyConfig, TlsConfig, UpstreamConfig};
use crate::plugins::PluginConfig;
use anyhow::{Result, anyhow};
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct ProxyConfigResolved {
    pub global: GlobalConfigResolved,
    pub servers: HashMap<String, ServerConfigResolved>,
    pub plugins: Option<Vec<PluginConfig>>,
}

#[derive(Debug, Clone)]
pub struct GlobalConfigResolved {
    pub port: u16,
    pub tls: Option<TlsConfigResolved>,
}

#[derive(Debug, Clone)]
pub struct TlsConfigResolved {
    pub cert: String,
    pub key: String,
    pub ca: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ServerConfigResolved {
    pub tls: bool,
    pub upstream: UpstreamConfigResolved,
}

#[derive(Debug, Clone)]
pub struct UpstreamConfigResolved {
    pub servers: Vec<String>,
}

impl ProxyConfigResolved {
    pub fn load(file: impl AsRef<Path>) -> Result<Self> {
        let config = SimpleProxyConfig::from_yaml_file(file)?;
        Self::try_from(config)
    }
}

impl TryFrom<&TlsConfig> for TlsConfigResolved {
    type Error = anyhow::Error;

    fn try_from(tls: &TlsConfig) -> Result<Self, Self::Error> {
        let cert_path = tls.cert.as_path();
        let key_path = tls.key.as_path();

        // Check if files exist
        if !cert_path.exists() {
            return Err(anyhow!("Certificate file does not exist: {:?}", cert_path));
        }

        if !key_path.exists() {
            return Err(anyhow!("Key file does not exist: {:?}", key_path));
        }

        // Check if CA file exists if present
        let ca = if let Some(ca_path) = &tls.ca {
            if !ca_path.exists() {
                return Err(anyhow!("CA file does not exist: {:?}", ca_path));
            }

            Some(ca_path.to_string_lossy().to_string())
        } else {
            None
        };

        Ok(TlsConfigResolved {
            cert: cert_path.to_string_lossy().to_string(),
            key: key_path.to_string_lossy().to_string(),
            ca,
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
        // Build upstream map for lookups
        let mut upstream_map = HashMap::new();
        for upstream in &raw.upstreams {
            let resolved_upstream = UpstreamConfigResolved::from(upstream);
            upstream_map.insert(upstream.name.clone(), resolved_upstream);
        }

        // Resolve global config
        let global = GlobalConfigResolved::try_from(&raw.global)?;

        // Resolve server configs
        let mut servers = HashMap::new();
        for server in raw.servers {
            let resolved_server = ServerConfigResolved::try_from_with_maps(&server, &upstream_map)?;

            // Add server for each domain name
            for server_name in server.server_name {
                if servers.contains_key(&server_name) {
                    return Err(anyhow!("Duplicate server name: {}", server_name));
                }
                servers.insert(server_name, resolved_server.clone());
            }
        }

        Ok(ProxyConfigResolved {
            global,
            servers,
            plugins: raw.plugins,
        })
    }
}

impl TryFrom<&GlobalConfig> for GlobalConfigResolved {
    type Error = anyhow::Error;

    fn try_from(global: &GlobalConfig) -> Result<Self, Self::Error> {
        let tls = match &global.tls {
            Some(tls_config) => {
                let resolved_tls = TlsConfigResolved::try_from(tls_config)?;
                Some(resolved_tls)
            }
            None => None,
        };

        Ok(GlobalConfigResolved {
            port: global.port,
            tls,
        })
    }
}

// Helper for ServerConfigResolved that requires upstream maps for lookups
impl ServerConfigResolved {
    fn try_from_with_maps(
        server: &ServerConfig,
        upstream_map: &HashMap<String, UpstreamConfigResolved>,
    ) -> Result<Self> {
        // Get the tls setting, default to false if not specified
        let tls = server.tls.unwrap_or(false);

        // Get the upstream configuration
        let upstream_name = &server.upstream;
        let upstream = upstream_map
            .get(upstream_name)
            .ok_or_else(|| anyhow!("Upstream '{}' not found", upstream_name))?
            .clone();

        Ok(ServerConfigResolved { tls, upstream })
    }

    pub fn choose(&self) -> Option<&str> {
        let upstream = self.upstream.servers.choose(&mut OsRng);
        upstream.map(|s| s.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::PathBuf};
    use tempfile::TempDir;

    // Helper to create a temporary file with content
    fn create_temp_file(dir: &TempDir, filename: &str, content: &str) -> PathBuf {
        let file_path = dir.path().join(filename);
        fs::write(&file_path, content).expect("Failed to write temp file");
        file_path
    }

    #[test]
    fn test_tls_config_resolved_try_from() {
        let temp_dir = TempDir::new().unwrap();

        // Create temporary cert and key files
        let cert_content = "-----BEGIN CERTIFICATE-----\nMIICert\n-----END CERTIFICATE-----";
        let key_content = "-----BEGIN PRIVATE KEY-----\nMIIKey\n-----END PRIVATE KEY-----";
        let ca_content = "-----BEGIN CERTIFICATE-----\nMIICA\n-----END CERTIFICATE-----";

        let cert_path = create_temp_file(&temp_dir, "cert.pem", cert_content);
        let key_path = create_temp_file(&temp_dir, "key.pem", key_content);
        let ca_path = create_temp_file(&temp_dir, "ca.pem", ca_content);

        // Create raw TlsConfig with CA
        let raw_tls_with_ca = TlsConfig {
            cert: cert_path.clone(),
            key: key_path.clone(),
            ca: Some(ca_path.clone()),
        };

        // Create raw TlsConfig without CA
        let raw_tls_without_ca = TlsConfig {
            cert: cert_path.clone(),
            key: key_path.clone(),
            ca: None,
        };

        // Convert to resolved
        let resolved_tls_with_ca = TlsConfigResolved::try_from(&raw_tls_with_ca).unwrap();
        let resolved_tls_without_ca = TlsConfigResolved::try_from(&raw_tls_without_ca).unwrap();

        // Verify contents - we now store paths as strings
        assert_eq!(resolved_tls_with_ca.cert, cert_path.to_string_lossy());
        assert_eq!(resolved_tls_with_ca.key, key_path.to_string_lossy());
        assert_eq!(
            resolved_tls_with_ca.ca,
            Some(ca_path.to_string_lossy().to_string())
        );

        assert_eq!(resolved_tls_without_ca.cert, cert_path.to_string_lossy());
        assert_eq!(resolved_tls_without_ca.key, key_path.to_string_lossy());
        assert_eq!(resolved_tls_without_ca.ca, None);
    }

    #[test]
    fn test_upstream_config_resolved_from() {
        let raw_upstream = UpstreamConfig {
            name: "test_upstream".to_string(),
            servers: vec!["127.0.0.1:8080".to_string(), "127.0.0.1:8081".to_string()],
        };

        let resolved_upstream = UpstreamConfigResolved::from(&raw_upstream);

        assert_eq!(
            resolved_upstream.servers,
            vec!["127.0.0.1:8080".to_string(), "127.0.0.1:8081".to_string()]
        );
    }

    #[test]
    fn test_global_config_resolved_without_tls() {
        let raw_global = GlobalConfig {
            port: 8080,
            tls: None,
        };

        let resolved_global = GlobalConfigResolved::try_from(&raw_global).unwrap();

        assert_eq!(resolved_global.port, 8080);
        assert!(resolved_global.tls.is_none());
    }

    #[test]
    fn test_global_config_resolved_with_tls() {
        let temp_dir = TempDir::new().unwrap();

        // Create temporary cert and key files
        let cert_content = "-----BEGIN CERTIFICATE-----\nMIICert\n-----END CERTIFICATE-----";
        let key_content = "-----BEGIN PRIVATE KEY-----\nMIIKey\n-----END PRIVATE KEY-----";

        let cert_path = create_temp_file(&temp_dir, "cert.pem", cert_content);
        let key_path = create_temp_file(&temp_dir, "key.pem", key_content);

        let tls_config = TlsConfig {
            cert: cert_path.clone(),
            key: key_path.clone(),
            ca: None,
        };

        let raw_global = GlobalConfig {
            port: 8080,
            tls: Some(tls_config),
        };

        let resolved_global = GlobalConfigResolved::try_from(&raw_global).unwrap();

        assert_eq!(resolved_global.port, 8080);
        assert!(resolved_global.tls.is_some());
        let tls = resolved_global.tls.unwrap();
        assert_eq!(tls.cert, cert_path.to_string_lossy());
        assert_eq!(tls.key, key_path.to_string_lossy());
        assert!(tls.ca.is_none());
    }

    #[test]
    fn test_server_config_resolved() {
        let upstream = UpstreamConfigResolved {
            servers: vec!["127.0.0.1:8080".to_string(), "127.0.0.1:8081".to_string()],
        };

        let mut upstream_map = HashMap::new();
        upstream_map.insert("test_upstream".to_string(), upstream);

        let raw_server = ServerConfig {
            server_name: vec!["test.com".to_string(), "www.test.com".to_string()],
            upstream: "test_upstream".to_string(),
            tls: Some(true),
        };

        let resolved_server =
            ServerConfigResolved::try_from_with_maps(&raw_server, &upstream_map).unwrap();

        assert!(resolved_server.tls);
        assert_eq!(
            resolved_server.upstream.servers,
            vec!["127.0.0.1:8080".to_string(), "127.0.0.1:8081".to_string()]
        );

        // Test with tls=false
        let raw_server_no_tls = ServerConfig {
            server_name: vec!["test2.com".to_string()],
            upstream: "test_upstream".to_string(),
            tls: Some(false),
        };

        let resolved_server_no_tls =
            ServerConfigResolved::try_from_with_maps(&raw_server_no_tls, &upstream_map).unwrap();

        assert!(!resolved_server_no_tls.tls);

        // Test with tls=None (should default to false)
        let raw_server_default_tls = ServerConfig {
            server_name: vec!["test3.com".to_string()],
            upstream: "test_upstream".to_string(),
            tls: None,
        };

        let resolved_server_default_tls =
            ServerConfigResolved::try_from_with_maps(&raw_server_default_tls, &upstream_map)
                .unwrap();

        assert!(!resolved_server_default_tls.tls);
    }

    #[test]
    fn test_proxy_config_resolved_try_from() {
        let temp_dir = TempDir::new().unwrap();

        // Create temporary cert and key files
        let cert_content = "-----BEGIN CERTIFICATE-----\nMIICert\n-----END CERTIFICATE-----";
        let key_content = "-----BEGIN PRIVATE KEY-----\nMIIKey\n-----END PRIVATE KEY-----";

        let cert_path = create_temp_file(&temp_dir, "cert.pem", cert_content);
        let key_path = create_temp_file(&temp_dir, "key.pem", key_content);

        // Create raw configuration
        let tls_config = TlsConfig {
            cert: cert_path.clone(),
            key: key_path.clone(),
            ca: None,
        };

        let global_config = GlobalConfig {
            port: 8080,
            tls: Some(tls_config),
        };

        let server_configs = vec![
            ServerConfig {
                server_name: vec!["test.com".to_string(), "www.test.com".to_string()],
                upstream: "web_servers".to_string(),
                tls: Some(true),
            },
            ServerConfig {
                server_name: vec!["api.test.com".to_string()],
                upstream: "api_servers".to_string(),
                tls: Some(false),
            },
        ];

        let upstream_configs = vec![
            UpstreamConfig {
                name: "web_servers".to_string(),
                servers: vec!["127.0.0.1:8080".to_string(), "127.0.0.1:8081".to_string()],
            },
            UpstreamConfig {
                name: "api_servers".to_string(),
                servers: vec!["127.0.0.1:9090".to_string(), "127.0.0.1:9091".to_string()],
            },
        ];

        let raw_config = SimpleProxyConfig {
            global: global_config,
            servers: server_configs,
            upstreams: upstream_configs,
            plugins: None,
        };

        // Convert to resolved
        let resolved_config = ProxyConfigResolved::try_from(raw_config).unwrap();

        // Verify global config
        assert_eq!(resolved_config.global.port, 8080);
        assert!(resolved_config.global.tls.is_some());
        let tls = &resolved_config.global.tls.as_ref().unwrap();
        assert_eq!(tls.cert, cert_path.to_string_lossy());
        assert_eq!(tls.key, key_path.to_string_lossy());

        // Verify server configs
        assert_eq!(resolved_config.servers.len(), 3);

        let test_com_server = resolved_config.servers.get("test.com").unwrap();
        assert!(test_com_server.tls);
        assert_eq!(
            test_com_server.upstream.servers,
            vec!["127.0.0.1:8080".to_string(), "127.0.0.1:8081".to_string()]
        );

        let www_test_com_server = resolved_config.servers.get("www.test.com").unwrap();
        assert!(www_test_com_server.tls);
        assert_eq!(
            www_test_com_server.upstream.servers,
            vec!["127.0.0.1:8080".to_string(), "127.0.0.1:8081".to_string()]
        );

        let api_test_com_server = resolved_config.servers.get("api.test.com").unwrap();
        assert!(!api_test_com_server.tls);
        assert_eq!(
            api_test_com_server.upstream.servers,
            vec!["127.0.0.1:9090".to_string(), "127.0.0.1:9091".to_string()]
        );
    }

    #[test]
    fn test_error_handling_unknown_upstream() {
        let server_config = ServerConfig {
            server_name: vec!["test.com".to_string()],
            upstream: "unknown_upstream".to_string(),
            tls: Some(false),
        };

        let upstream_map = HashMap::new();

        let result = ServerConfigResolved::try_from_with_maps(&server_config, &upstream_map);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Upstream 'unknown_upstream' not found"
        );
    }

    #[test]
    fn test_error_handling_duplicate_server_name() {
        let temp_dir = TempDir::new().unwrap();

        // Create temporary cert and key files
        let cert_content = "-----BEGIN CERTIFICATE-----\nMIICert\n-----END CERTIFICATE-----";
        let key_content = "-----BEGIN PRIVATE KEY-----\nMIIKey\n-----END PRIVATE KEY-----";

        let cert_path = create_temp_file(&temp_dir, "cert.pem", cert_content);
        let key_path = create_temp_file(&temp_dir, "key.pem", key_content);

        // Create raw configuration with duplicate server names
        let tls_config = TlsConfig {
            cert: cert_path,
            key: key_path,
            ca: None,
        };

        let global_config = GlobalConfig {
            port: 8080,
            tls: Some(tls_config),
        };

        let server_configs = vec![
            ServerConfig {
                server_name: vec!["test.com".to_string()],
                upstream: "web_servers".to_string(),
                tls: Some(true),
            },
            ServerConfig {
                server_name: vec!["test.com".to_string()], // Duplicate server name
                upstream: "api_servers".to_string(),
                tls: Some(false),
            },
        ];

        let upstream_configs = vec![
            UpstreamConfig {
                name: "web_servers".to_string(),
                servers: vec!["127.0.0.1:8080".to_string()],
            },
            UpstreamConfig {
                name: "api_servers".to_string(),
                servers: vec!["127.0.0.1:9090".to_string()],
            },
        ];

        let raw_config = SimpleProxyConfig {
            global: global_config,
            servers: server_configs,
            upstreams: upstream_configs,
            plugins: None,
        };

        // Try to convert to resolved
        let result = ProxyConfigResolved::try_from(raw_config);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Duplicate server name: test.com"
        );
    }
}

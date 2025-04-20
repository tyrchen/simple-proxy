use http::{HeaderValue, Uri};

pub(crate) fn get_host_port<'a>(host: Option<&'a HeaderValue>, uri: &'a Uri) -> (&'a str, u16) {
    let default_port = match uri.scheme() {
        Some(scheme) if scheme.as_str() == "https" => 443,
        _ => 80,
    };

    match host {
        Some(h) => split_host_port(h.to_str().unwrap_or_default(), default_port),
        None => (
            uri.host().unwrap_or_default(),
            uri.port_u16().unwrap_or(default_port),
        ),
    }
}

fn split_host_port(host: &str, default_port: u16) -> (&str, u16) {
    let mut parts = host.split(':');
    let host = parts.next().unwrap_or("");
    let port = parts.next();
    match port {
        Some(port) => (host, port.parse().unwrap_or(default_port)),
        None => (host, default_port),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{HeaderMap, HeaderValue, Uri};

    #[test]
    fn test_get_host_port_with_host_header() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("example.com"));
        let uri = "http://example.org/path".parse::<Uri>().unwrap();

        let (host, port) = get_host_port(headers.get("host"), &uri);

        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
    }

    #[test]
    fn test_get_host_port_with_host_header_and_port() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("example.com:8080"));
        let uri = "http://example.org/path".parse::<Uri>().unwrap();

        let (host, port) = get_host_port(headers.get("host"), &uri);

        assert_eq!(host, "example.com");
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_get_host_port_with_https_scheme() {
        let headers = HeaderMap::new();
        let uri = "https://example.org/path".parse::<Uri>().unwrap();

        let (host, port) = get_host_port(headers.get("host"), &uri);

        assert_eq!(host, "example.org");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_get_host_port_with_uri_port() {
        let headers = HeaderMap::new();
        let uri = "http://example.org:8443/path".parse::<Uri>().unwrap();

        let (host, port) = get_host_port(headers.get("host"), &uri);

        assert_eq!(host, "example.org");
        assert_eq!(port, 8443);
    }

    #[test]
    fn test_get_host_port_with_invalid_host_header() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_bytes(b"\xFF\xFF").unwrap());
        let uri = "http://example.org/path".parse::<Uri>().unwrap();

        let (host, port) = get_host_port(headers.get("host"), &uri);

        assert_eq!(host, "");
        assert_eq!(port, 80);
    }

    #[test]
    fn test_split_host_port_with_port() {
        let (host, port) = split_host_port("example.com:8080", 80);

        assert_eq!(host, "example.com");
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_split_host_port_without_port() {
        let (host, port) = split_host_port("example.com", 80);

        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
    }

    #[test]
    fn test_split_host_port_with_invalid_port() {
        let (host, port) = split_host_port("example.com:invalid", 80);

        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
    }

    #[test]
    fn test_split_host_port_empty_host() {
        let (host, port) = split_host_port("", 80);

        assert_eq!(host, "");
        assert_eq!(port, 80);
    }
}

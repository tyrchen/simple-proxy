# Proxy Config

Please help to define config for the simple proxy, in YAML format, like the nginx config. It should have the following sections:

- global: port, tls cert.
- certs: list of certs to be used.
- servers: server_name (list of domains), upstream (list of upstream servers).
- upstreams: list of upstream servers.

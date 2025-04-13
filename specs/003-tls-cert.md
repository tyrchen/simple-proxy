# TLS Cert

Please use openssl to generate a CA cert and sign it for wildcard cert for `*.acme.com` and a cert for `api.acme.com`. Put the certs in the `fixtures/certs` directory. The script should be put into `Makefile` (make certs). Please use ECDSA for the certs.

build:
	@cargo build

test:
	@cargo nextest run --all-features --examples

certs:
	@echo "Generating ECDSA certificates for *.acme.com and api.acme.com..."
	@# Create directory if it doesn't exist
	@mkdir -p fixtures/certs
	@# Generate CA key and certificate
	@openssl ecparam -name prime256v1 -genkey -noout -out fixtures/certs/ca.key
	@openssl req -new -x509 -key fixtures/certs/ca.key -out fixtures/certs/ca.crt -days 3650 \
		-subj "/C=US/ST=State/L=City/O=Acme Inc/OU=IT/CN=Acme Root CA"
	@# Generate wildcard certificate key and CSR
	@openssl ecparam -name prime256v1 -genkey -noout -out fixtures/certs/wildcard.acme.com.key
	@openssl req -new -key fixtures/certs/wildcard.acme.com.key -out fixtures/certs/wildcard.acme.com.csr \
		-subj "/C=US/ST=State/L=City/O=Acme Inc/OU=IT/CN=*.acme.com"
	@# Create a temporary extfile for the wildcard certificate
	@echo "subjectAltName=DNS:*.acme.com,DNS:acme.com" > fixtures/certs/wildcard-ext.cnf
	@# Sign the wildcard certificate
	@openssl x509 -req -in fixtures/certs/wildcard.acme.com.csr -CA fixtures/certs/ca.crt \
		-CAkey fixtures/certs/ca.key -CAcreateserial -out fixtures/certs/wildcard.acme.com.crt -days 3650 \
		-extfile fixtures/certs/wildcard-ext.cnf
	@# Generate specific domain certificate key and CSR
	@openssl ecparam -name prime256v1 -genkey -noout -out fixtures/certs/api.acme.com.key
	@openssl req -new -key fixtures/certs/api.acme.com.key -out fixtures/certs/api.acme.com.csr \
		-subj "/C=US/ST=State/L=City/O=Acme Inc/OU=IT/CN=api.acme.com"
	@# Create a temporary extfile for the api certificate
	@echo "subjectAltName=DNS:api.acme.com" > fixtures/certs/api-ext.cnf
	@# Sign the specific domain certificate
	@openssl x509 -req -in fixtures/certs/api.acme.com.csr -CA fixtures/certs/ca.crt \
		-CAkey fixtures/certs/ca.key -CAcreateserial -out fixtures/certs/api.acme.com.crt -days 3650 \
		-extfile fixtures/certs/api-ext.cnf
	@echo "Certificates generated successfully in fixtures/certs/"
	@# Clean up temporary extfiles
	@rm -f fixtures/certs/wildcard-ext.cnf fixtures/certs/api-ext.cnf

release:
	@cargo release tag --execute
	@git cliff -o CHANGELOG.md
	@git commit -a -n -m "Update CHANGELOG.md" || true
	@git push origin master
	@cargo release push --execute

update-submodule:
	@git submodule update --init --recursive --remote

.PHONY: build test release update-submodule certs

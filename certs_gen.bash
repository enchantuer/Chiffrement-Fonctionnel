CERT_DIR="certs"

# Create directories for CA, trust server, computing server, and clients
mkdir -p "$CERT_DIR/ca"
mkdir -p "$CERT_DIR/trust_server"
mkdir -p "$CERT_DIR/computing_server"
mkdir -p "$CERT_DIR/clients/0"
mkdir -p "$CERT_DIR/clients/1"

# Private key for the CA / Trust server (Ed25519)
openssl genpkey -algorithm Ed25519 -out "$CERT_DIR/ca/ca.key"
# Self-signed certificate for the CA
openssl req -new -x509 -key "$CERT_DIR/ca/ca.key" -out "$CERT_DIR/ca/ca.cert" -days 3650 \
  -subj "/C=CA/ST=QC/L=Chicoutimi/O=UQAC/OU=8INF874/CN=CA"


# Private key for the trust server (Ed25519)
openssl genpkey -algorithm Ed25519 -out "$CERT_DIR/trust_server/server.key"
# CSR (Certificate Signing Request)
openssl req -new -key "$CERT_DIR/trust_server/server.key" -out "$CERT_DIR/trust_server/server.csr" \
  -subj "/C=CA/ST=QC/L=Chicoutimi/O=UQAC/OU=8INF874/CN=localhost"
# Sign CSR with the CA
openssl x509 -req -in "$CERT_DIR/trust_server/server.csr" -CA "$CERT_DIR/ca/ca.cert" -CAkey "$CERT_DIR/ca/ca.key" \
  -CAcreateserial -out "$CERT_DIR/trust_server/server.cert" -days 365

# Private key for the computing server (Ed25519)
openssl genpkey -algorithm Ed25519 -out "$CERT_DIR/computing_server/server.key"
# CSR (Certificate Signing Request)
openssl req -new -key "$CERT_DIR/computing_server/server.key" -out "$CERT_DIR/computing_server/server.csr" \
  -subj "/C=CA/ST=QC/L=Chicoutimi/O=UQAC/OU=8INF874/CN=localhost"
# Sign CSR with the CA
openssl x509 -req -in "$CERT_DIR/computing_server/server.csr" -CA "$CERT_DIR/ca/ca.cert" -CAkey "$CERT_DIR/ca/ca.key" \
  -CAcreateserial -out "$CERT_DIR/computing_server/server.cert" -days 365


# Private key for client 0 (Ed25519)
openssl genpkey -algorithm Ed25519 -out "$CERT_DIR/clients/0/client.key"
# CSR (Certificate Signing Request)
openssl req -new -key "$CERT_DIR/clients/0/client.key" -out "$CERT_DIR/clients/0/client.csr" \
  -subj "/C=CA/ST=QC/L=Chicoutimi/O=UQAC/OU=8INF874/CN=client_0"
# Sign CSR with the CA
openssl x509 -req -in "$CERT_DIR/clients/0/client.csr" -CA "$CERT_DIR/ca/ca.cert" -CAkey "$CERT_DIR/ca/ca.key" \
  -CAcreateserial -out "$CERT_DIR/clients/0/client.cert" -days 365

# Private key for client 0 (Ed25519)
openssl genpkey -algorithm Ed25519 -out "$CERT_DIR/clients/1/client.key"
# CSR (Certificate Signing Request)
openssl req -new -key "$CERT_DIR/clients/1/client.key" -out "$CERT_DIR/clients/1/client.csr" \
  -subj "/C=CA/ST=QC/L=Chicoutimi/O=UQAC/OU=8INF874/CN=client_1"
# Sign CSR with the CA
openssl x509 -req -in "$CERT_DIR/clients/1/client.csr" -CA "$CERT_DIR/ca/ca.cert" -CAkey "$CERT_DIR/ca/ca.key" \
  -CAcreateserial -out "$CERT_DIR/clients/1/client.cert" -days 365
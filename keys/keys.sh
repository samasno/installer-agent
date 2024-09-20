#!/bin/bash

mkdir -p ca
mkdir -p client

# Step 1: Create CA key and certificate
openssl genrsa -out ca/ca.key 2048
openssl req -x509 -new -nodes -key ca/ca.key -sha256 -days 365 \
  -subj "/CN=CA" -out ca/ca.crt

# Step 2: Create client key
openssl genrsa -out client/client.key 2048

# Step 3: Create a certificate signing request (CSR) for the client
openssl req -new -key client/client.key -out client/client.csr \
  -subj "/CN=My Client"

# Step 4: Sign the client CSR with the CA
openssl x509 -req -in client/client.csr -CA ca/ca.crt -CAkey ca/ca.key \
  -CAcreateserial -out client/client.crt -days 365 -sha256

# Cleanup
rm client/client.csr

echo "CA and client certificates and keys created."

# Database CA certificate

Cloud MySQL providers that use their own certificate authority (for example **Aiven**) need their CA certificate to verify the TLS connection.

1. Download the CA certificate from your MySQL service page.
2. Save it here as `certs/ca.pem` and commit it. A CA certificate is public, not a secret.
3. Set `DB_SSL=true` and `DB_SSL_CA_FILE=certs/ca.pem`.

Never put private keys (`*.key`, `id_rsa`…) in this folder; `.gitignore` blocks them.

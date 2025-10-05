# Oracle SBC Certificate Renewal Tool

A Go application for automating certificate renewal on Oracle Session Border Controllers (SBC) using the REST API.

## Overview

This tool automates the certificate management process for Oracle SBCs, including:
- Creating certificate records
- Generating Certificate Signing Requests (CSR)
- Importing signed certificates
- Managing configuration locks and activation

## Features

- 🔐 **Secure Authentication**: Token-based authentication with the SBC REST API
- 📝 **CSR Generation**: Automatically generate CSRs for certificate records
- 📜 **Certificate Import**: Import CA-signed certificates back to the SBC
- 🔄 **Idempotent Operations**: Safely update existing certificate records
- ⚙️ **Configuration Management**: Automatic configuration save, verify, and activate
- 🖨️ **Stdout Logging Option**: Use -logstd to mirror log output to the terminal
- 🛡️ **TLS Support**: Support for both secure and insecure (self-signed) connections
- 🎯 **Explicit Operation Modes**: Clear flag-based control over operations

## Prerequisites

- Go 1.21 or later
- Access to Oracle SBC with REST API enabled (version 8.4.0+)
- Administrative credentials for the SBC
- Network connectivity to the SBC management interface

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/negbie/oracle-cert-renew.git
cd oracle-cert-renew

# Download dependencies
go mod download

# Build the application
go build -o oracle-cert-renew

# Optional: Install globally
go install
```

### Using go install

```bash
go install github.com/negbie/oracle-cert-renew@latest
```

## Configuration

Create a configuration file based on the example:

```bash
cp config.yaml.example config.yaml
```

Edit `config.yaml` with your SBC details:

```yaml
# SBC Connection Settings
sbc:
  host: "10.0.0.2"              # Your SBC IP or hostname
  port: 443                      # REST API port
  username: "admin"              # Admin username
  password: "your-password"      # Admin password
  insecure: true                 # Set to true for self-signed certificates

# Certificate Settings
certificate:
  # Fields used by Oracle SBC certificate-record:
  name: "my-cert"                # Name of the certificate record (default if omitted: <mon><yy>, e.g. sep25)
  country: "US"                  # 2-letter country code
  state: "California"            # State or Province
  organization: "My Company"     # Organization name
  common_name: "sbc.example.com" # FQDN of your SBC
  alternate_name: ""             # Subject Alternative Name (SAN) - additional hostname/IP (default: empty)
  key_size: 4096                 # RSA key size in bits (default: 4096)
  key_algorithm: "rsa"           # Key algorithm: rsa (default: rsa)

# TLS Profile Settings (Optional)
# Automatically update TLS profile after certificate import
tls_profile:
  enabled: false                 # Enable TLS profile management
  profile_name: "defaultTlsProfile" # Name of the TLS profile to update
  update_after_import: true      # Auto-update TLS profile after import
  delete_old_certificate: false  # Delete old certificate after update
  old_certificate_name: ""       # Name of old certificate to delete
  trusted-ca-certificates: "R10,R11" # Comma separated list of allowed intermediate CA certificate CNs (optional)

post-generate-hook: "echo CSR generated: $(date) >> csr_events.log" # Optional shell command run after successful CSR generation

# (General settings section removed: verbose flag no longer exists; logging always on. Use -logstd to also log to stdout. post-generate-hook runs after CSR generation.)
```

## Usage

### Command Line Options

```bash
oracle-cert-renew [OPTIONS]

Options:
  -config string    Configuration file path (default "config.yaml")
  -mode string      Operation mode (default "generate")
                    Options: generate, import, check
  -csr-out string   Path to save generated CSR (optional, stdout if not specified)
  -cert_path string Path to signed certificate for import (required for import)
  -record string    Override certificate record name from config
  -force           Force overwrite existing certificate record
  -logstd          Also log to stdout (in addition to oracle-cert-renew.log)
  -version         Show version information
  -h, -help        Show help message
```

### Operation Modes

#### 1. Generate Mode (Default)
Creates a certificate record and generates a CSR.

```bash
# Generate CSR and save to file
oracle-cert-renew -mode generate -csr-out sbc.csr

# Generate CSR and output to stdout
oracle-cert-renew -mode generate

# Force overwrite existing record
oracle-cert-renew -mode generate -force
```

#### 2. Import Mode
Imports a CA-signed certificate after CSR generation.

```bash
# Import certificate
oracle-cert-renew -mode import -cert_path sbc.crt

# Mirror logs to terminal while importing
oracle-cert-renew -mode import -cert_path sbc.crt -logstd
```

**Note:** If TLS profile management is enabled in the configuration, the import mode will automatically:
- Update the specified TLS profile to use the new certificate
- Optionally delete the old certificate record
- Save and activate the configuration

#### 3. Check Mode
Verifies connection and authentication with the SBC.

```bash
# Test connection
oracle-cert-renew -mode check

# Also log to stdout
oracle-cert-renew -mode check -logstd
```

## Certificate Renewal Workflow

### Option 1: Step-by-Step Process

#### Step 1: Generate CSR
```bash
oracle-cert-renew -mode generate -csr-out sbc.csr
```
This will:
- Create a new certificate record on the SBC
- Generate a CSR
- Save the CSR to `sbc.csr`

#### Step 2: Get Certificate Signed
Submit the CSR to your Certificate Authority (CA):
- Internal CA for testing/development
- Public CA (DigiCert, Let's Encrypt, etc.) for production
- Self-signed for lab environments

#### Step 3: Import Signed Certificate
```bash
oracle-cert-renew -mode import -cert_path sbc.crt
```
This will:
- Import the signed certificate to the SBC
- Activate the configuration
- Display any required post-import steps



## Advanced Usage

### Override Certificate Record Name

```bash
# Use a different record name than configured
oracle-cert-renew -mode generate -record "new-cert-2024" -csr-out new.csr
```

### Custom Configuration File

```bash
# Use alternative configuration
oracle-cert-renew -config /etc/sbc/prod-config.yaml -mode generate
```

### TLS Profile Management

When enabled in the configuration, the tool can automatically update the TLS profile after certificate import. This is essential for the SBC to use the new certificate for HTTPS/REST API connections.

```yaml
# Enable TLS profile management in config.yaml
tls_profile:
  enabled: true                      # Enable TLS profile updates
  profile_name: "defaultTlsProfile"  # Profile to update (usually defaultTlsProfile)
  update_after_import: true          # Auto-update after certificate import
  delete_old_certificate: true       # Remove old self-signed certificate
  old_certificate_name: "defaultSelfSignedRestCert"
  trusted-ca-certificates: "R10,R11" # Allowed intermediate CA certificate CNs (comma separated). If set, every intermediate CA in the imported chain must match one entry.
```

When TLS profile management is enabled, the import process will:
1. Import the signed certificate
2. Update the specified TLS profile to use the new certificate
3. Optionally delete the old certificate record
4. Save and activate the configuration


### Automation Example

```bash
#!/bin/bash
# Automated certificate renewal script

CONFIG="/etc/sbc/config.yaml"
CSR_PATH="/tmp/sbc.csr"
CERT_PATH="/etc/ssl/certs/sbc.crt"

# Generate CSR
oracle-cert-renew -config $CONFIG -mode generate -csr-out $CSR_PATH

# Submit to CA and wait for certificate (implementation depends on your CA)
# submit_to_ca $CSR_PATH $CERT_PATH

# Import certificate once available
oracle-cert-renew -config $CONFIG -mode import -cert_path $CERT_PATH

```

## Docker Usage

### Build Docker Image

```bash
docker build -t oracle-cert-renew:latest .
```

### Run with Docker

```bash
# Check connection
docker run --rm \
  -v $(pwd)/config.yaml:/app/config/config.yaml:ro \
  oracle-cert-renew:latest \
  -mode check

# Generate CSR
docker run --rm \
  -v $(pwd)/config.yaml:/app/config/config.yaml:ro \
  -v $(pwd)/certs:/app/certs \
  oracle-cert-renew:latest \
  -mode generate -csr-out /app/certs/sbc.csr

# Import certificate
docker run --rm \
  -v $(pwd)/config.yaml:/app/config/config.yaml:ro \
  -v $(pwd)/certs:/app/certs:ro \
  oracle-cert-renew:latest \
  -mode import -cert_path /app/certs/sbc.crt
```

## REST API Endpoints Used

This tool interacts with the following Oracle SBC REST API endpoints:

- `POST /auth/token` - Authentication
- `POST /configuration/lock` - Acquire configuration lock
- `POST /configuration/unlock` - Release configuration lock
- `GET /system/status` - Check system status and connectivity
- `GET /configuration/configElements` - Check existing records
- `POST /configuration/configElements` - Create certificate record
- `PUT /configuration/configElements/certificate-record/{name}` - Update record
- `PUT /configuration/certificates/generateRequest` - Generate CSR
- `PUT /configuration/certificates/import` - Import certificate
- `POST /configuration/save` - Save configuration
- `POST /configuration/verify` - Verify configuration
- `POST /configuration/activate` - Activate configuration

## Security Considerations

1. **Credentials**: Store configuration files securely and use appropriate file permissions:
   ```bash
   chmod 600 config.yaml
   ```

2. **TLS Verification**: In production, set `insecure: false` and ensure proper CA certificates are installed

3. **Token Management**: The tool handles token acquisition and renewal automatically

4. **Network Security**: Ensure management access to the SBC is properly secured (VPN, firewall rules, etc.)

5. **Certificate Storage**: Keep generated CSRs and certificates secure:
   ```bash
   chmod 600 *.csr *.crt *.key
   ```

## Troubleshooting

### Common Issues

1. **Authentication Failed**
   - Verify username and password
   - Check if REST API is enabled on the SBC
   - Ensure the user has appropriate permissions

2. **Connection Refused**
   - Verify the SBC IP address and port
   - Check network connectivity
   - Ensure REST API is running on the specified port
   - Try using `-mode check` to diagnose

3. **Certificate Import Failed**
   - Verify the certificate matches the CSR
   - Check certificate format (PEM format expected)
   - Ensure the certificate chain is complete
   - Verify the certificate record exists (use `-mode generate` first)

4. **Configuration Lock Failed**
   - Another session may have the lock
   - Wait and retry or manually release via web interface

5. **Record Already Exists**
   - Use the `-force` flag to overwrite: `oracle-cert-renew -mode generate -force`
   - Or use a different record name: `oracle-cert-renew -record "new-name"`

### Logging

Logging is always enabled and written to oracle-cert-renew.log.
Use -logstd to also stream logs to stdout:

```bash
# Generate CSR and see logs in terminal too
oracle-cert-renew -mode generate -csr-out sbc.csr -logstd

# Import certificate with stdout logging
oracle-cert-renew -mode import -cert_path sbc.crt -logstd
```

## Building from Source

### Standard Build
```bash
make build
```

### Cross-Platform Build
```bash
# Build for all platforms
make build-all

# Build for Linux only
make build-linux
```

### Run Tests
```bash
make test
make test-coverage
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Based on Oracle SBC REST API documentation
- Implements the certificate replacement workflow from Oracle's official guide

## Support

For issues, questions, or suggestions, please open an issue on GitHub:
https://github.com/negbie/oracle-cert-renew/issues

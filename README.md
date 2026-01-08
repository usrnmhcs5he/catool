# Certificate Generator Script

A simple, interactive Bash script for creating a custom Certificate Authority (CA) and issuing certificates using OpenSSL.  
Ideal for local development, self-hosted services (e.g., UniFi, web servers), and WPA2/WPA3-Enterprise WiFi with EAP-TLS authentication.

## Features

- Creates a root CA (4096-bit RSA) if none exists, with user-defined Common Name and validity.
- Generates both **RSA (2048-bit)** and **ECDSA (prime256v1)** key pairs simultaneously.
- Supports four certificate types:
  - `client` – for general client authentication
  - `server` – for web servers (TLS serverAuth)
  - `wifi-client` – for EAP-TLS client authentication on devices (Android, iOS, macOS)
  - `wifi-server` – for RADIUS / access point server authentication
- Automatic **Subject Alternative Name (SAN)** inclusion:
  - Common Name is always added as the first SAN
  - Optional additional SANs (DNS or IP, comma-separated)
- Exports in multiple formats:
  - `.key` (private key)
  - `.crt` (certificate)
  - `.pfx` (PKCS#12 with CA chain, optional passphrase) – compatible with Windows, Android, iOS, macOS
- Minimal interaction, self-contained (no external config files needed)

## Prerequisites

- macOS, Linux, or any system with Bash and OpenSSL 1.1+ / 3.x
- Run in Terminal

## Usage

1. Save the script as `cert-generator.sh`
2. Make it executable:  
   ```bash
   chmod +x cert-generator.sh
   ```
3. Run it:  
   ```bash
   ./cert-generator.sh
   ```

The script will guide you through prompts:

- If no CA exists: enter CA Common Name and validity (days).
- Choose certificate type: `client`, `server`, `wifi-client`, or `wifi-server`
- Enter Common Name (e.g., `unifi.local` or `user1`)
- Optional: additional SANs (comma-separated)
- Optional: passphrase for .pfx export

## Expected Output

- `CA/` folder with root CA key, certificate, index, and serial files (created once)
- A folder named after the Common Name containing:
  - `CN-rsa-[type].key` / `.crt` / `.pfx`
  - `CN-ec-[type].key` / `.crt` / `.pfx`  
    (where `[type]` is `client`, `server`, `wifi-client`, or `wifi-server`)

Example files for CN `unifi.local` and type `wifi-server`:
```
unifi.local/
├── unifi.local-rsa-wifi-server.key
├── unifi.local-rsa-wifi-server.crt
├── unifi.local-rsa-wifi-server.pfx
├── unifi.local-ec-wifi-server.key
├── unifi.local-ec-wifi-server.crt
└── unifi.local-ec-wifi-server.pfx
```

## Notes

- For web servers: trust the CA in browsers and import the server cert.
- For WiFi EAP-TLS: use `wifi-server` cert on RADIUS/AP, `wifi-client` .pfx on devices.
- Always verify certificates with `openssl verify` or `openssl s_client`.

## Changelog Summary

| Version | Changes |
|---------|---------|
| 1       | Initial basic client cert generator |
| 8       | Added client/server types, dual RSA+EC, SAN support, extensions |
| 9       | Always include CN in SAN |
| 10      | Added wifi-client and wifi-server types |
| 11      | Added this changelog and README guidance |
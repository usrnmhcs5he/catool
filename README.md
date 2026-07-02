# Certificate Generator Script

An interactive Bash script for creating a local Certificate Authority (CA) and
issuing certificates with OpenSSL — with optional YubiKey PIV backing for the
CA key. Ideal for local development, self-hosted services (e.g., UniFi, web
servers), and WPA2/WPA3-Enterprise WiFi with EAP-TLS authentication.

## Features

- Creates a root CA if none exists — key type selectable
  (`rsa3072` default for YubiKey compatibility, `rsa2048`, `ecp256`),
  optional AES-256 passphrase on the CA key
- **YubiKey PIV support**: import the CA to slot 9a and sign via PKCS#11,
  so the CA key never has to live on disk during issuance
- Generates both **RSA (2048)** and **ECDSA (prime256v1)** key pairs per run
- Four certificate types via numbered menu:
  `client`, `server`, `wifi-client` (EAP-TLS devices), `wifi-server` (RADIUS/AP)
- Automatic **SAN** handling: CN always included first; optional additional
  SANs (comma-separated, `DNS:`/`IP:` prefixes or auto-detected)
- Per-run certificate validity prompt (default 365 days)
- Exports `.key`, `.crt`, and `.pfx` (PKCS#12 with CA chain, optional
  passphrase) — Windows / Android / iOS / macOS compatible
- Self-contained: no external config files; Bash 3.2 compatible (stock macOS)

## Prerequisites

- Bash and OpenSSL 1.1+ / 3.x (macOS, Linux)
- For YubiKey signing only: `yubico-piv-tool`, OpenSC, and the OpenSSL
  `pkcs11` engine (libp11)

## Usage

```bash
chmod +x cert-generator.sh
./cert-generator.sh
```

Follow the prompts: CA creation (first run only) → optional YubiKey import →
signing backend (file / YubiKey) → certificate type → CN → additional SANs →
validity → PFX passphrase.

Optional environment variables:

| Variable      | Effect                                              |
|---------------|-----------------------------------------------------|
| `CERT_DAYS`   | Preset validity, skips the prompt                   |
| `CA_KEY_URI`  | PKCS#11 URI override for the CA key (YubiKey mode)  |
| `PFX_LEGACY=1`| Legacy PKCS#12 encryption for old Windows/devices   |

## Output

- `CA/` — root CA key, certificate, index and serial files (created once;
  existing CA state is picked up and continued)
- `<CN>/` — issued material, e.g. for CN `unifi.local`, type `wifi-server`:

```
unifi.local/
├── unifi.local-rsa-wifi-server.{key,crt,pfx}
└── unifi.local-ec-wifi-server.{key,crt,pfx}
```

Existing output files prompt before being overwritten.

## Notes

- Web servers: trust the CA in the client trust store, deploy the server cert.
- WiFi EAP-TLS: `wifi-server` cert on RADIUS/AP, `wifi-client` `.pfx` on devices.
- Verify issuance with `openssl verify -CAfile CA/ca.crt <cert>`.
- Known limitation: `yubico-piv-tool` takes the management key as a CLI
  argument (briefly visible in the process list); the tool offers no alternative.

## Changelog Summary

| Version | Changes |
|---------|---------|
| 1–11    | Basic client certs → dual RSA+EC, cert types, SANs, wifi types |
| 12      | YubiKey PIV import and PKCS#11 signing |
| 13–14   | Hardening: input validation, critical KU/BC, SKI/AKI, strict mode |
| 15      | Bug fixes (CN validation, sanitizer, Bash 3.2 compat, Python argv), passphrases off argv, validity prompt, optional CA key encryption, corrected PKCS#11 URI default, overwrite guard, ASCII menu interface |

Full per-version history is kept in the script header.

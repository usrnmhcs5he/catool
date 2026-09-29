<div align="center">

# 🔐 catool

**An interactive Bash tool for running a local Certificate Authority with OpenSSL, with optional YubiKey PIV protection for the CA key.**

![Bash 3.2+](https://img.shields.io/badge/bash-3.2%2B-4EAA25?logo=gnubash&logoColor=white)
![OpenSSL](https://img.shields.io/badge/OpenSSL-1.1%20%7C%203.x-721412?logo=openssl&logoColor=white)
![YubiKey](https://img.shields.io/badge/YubiKey-PIV%20optional-84BD00?logo=yubico&logoColor=white)
![Version](https://img.shields.io/badge/version-16-blue)

</div>

Built for local development, self-hosted services (UniFi, web servers, etc.) and
WPA2/WPA3-Enterprise WiFi using EAP-TLS. One script, no config files.

## ✨ Features

- **Root CA on demand**: created on first run. Key type is selectable
  (`rsa3072` default for YubiKey compatibility, `rsa2048`, `ecp256`), with an
  optional AES-256 passphrase on the CA key.
- **YubiKey PIV support**: import the CA into slot 9a and sign via PKCS#11, so
  the CA key never has to sit on disk during issuance.
- **Dual key pairs**: every run produces both **RSA 2048** and **ECDSA prime256v1**.
- **Four certificate types**: `client`, `server`, `wifi-client` (EAP-TLS devices)
  and `wifi-server` (RADIUS / AP).
- **Smart SANs**: the CN is always included first. Extra SANs are optional,
  comma-separated, with `DNS:` / `IP:` prefixes or auto-detection.
- **Flexible validity**: prompted per run (default 365 days).
- **Ready-to-use exports**: `.key`, `.crt` and `.pfx` (PKCS#12 with CA chain and
  optional passphrase), compatible with Windows, Android, iOS and macOS.
- **Portable and self-contained**: Bash 3.2 compatible (stock macOS).
- **Friendly navigation**: every menu offers `[b]` Back and `[q]` Quit, every
  text prompt accepts `:b` / `:q`, and a summary screen lets you Generate or
  Start over. Colour output is TTY-guarded and honours `NO_COLOR`.

## 📦 Prerequisites

| Need | For |
|------|-----|
| Bash and OpenSSL 1.1+ / 3.x | Everything (macOS, Linux) |
| `yubico-piv-tool`, OpenSC, OpenSSL `pkcs11` engine (libp11) | YubiKey signing only |

## 🚀 Quick start

```bash
chmod +x certv16.sh
./certv16.sh
```

The guided flow:

```
CA creation (first run) → YubiKey import (optional) → signing backend
   → certificate type → CN → additional SANs → validity → PFX passphrase
   → summary → generate
```

### Environment variables

| Variable        | Effect                                             |
|-----------------|----------------------------------------------------|
| `CERT_DAYS`     | Preset validity, skips the prompt                  |
| `CA_KEY_URI`    | PKCS#11 URI override for the CA key (YubiKey mode) |
| `PFX_LEGACY=1`  | Legacy PKCS#12 encryption for old Windows/devices  |
| `NO_COLOR`      | Disable coloured output                            |

## 📁 Output

- `CA/` holds the root CA key, certificate, index and serial files. It is
  created once, and existing CA state is picked up and continued.
- `<CN>/` holds the issued material. For CN `unifi.local`, type `wifi-server`:

```
unifi.local/
├── unifi.local-rsa-wifi-server.{key,crt,pfx}
└── unifi.local-ec-wifi-server.{key,crt,pfx}
```

Existing output files prompt before being overwritten.

## 💡 Usage notes

- **Web servers**: trust the CA in the client trust store and deploy the server cert.
- **WiFi EAP-TLS**: put the `wifi-server` cert on the RADIUS server / AP and the
  `wifi-client` `.pfx` on devices.
- **Verify** an issued cert:
  ```bash
  openssl verify -CAfile CA/ca.crt <cert>
  ```

> [!NOTE]
> Known limitation: `yubico-piv-tool` takes the management key as a CLI argument,
> so it is briefly visible in the process list. The tool offers no alternative.

## 🕘 Changelog

| Version | Changes |
|---------|---------|
| 1–11    | Basic client certs → dual RSA+EC, cert types, SANs, WiFi types |
| 12      | YubiKey PIV import and PKCS#11 signing |
| 13–14   | Hardening: input validation, critical KU/BC, SKI/AKI, strict mode |
| 15      | Bug fixes (CN validation, sanitizer, Bash 3.2 compat, Python argv), passphrases off argv, validity prompt, optional CA key encryption, corrected PKCS#11 URI default, overwrite guard, ASCII menu interface |
| **16**  | Navigation and visual polish: main flow is now a state machine; `[b]` Back / `[q]` Quit on every menu and `:b` / `:q` on text prompts (silent passphrase/PIN prompts deliberately excluded so literal values are never intercepted); navigable CA creation; pre-generation summary screen; `printf -v` instead of `eval`; TTY-guarded colour (respects `NO_COLOR`); step counters in headers. No changes to cryptographic behaviour, file formats, naming or CA state handling. |

Full per-version history is kept in the script header.

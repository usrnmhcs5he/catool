#!/bin/bash
# Changelog
# | Version | Changes |
# |---------|---------|
# | 1 | Initial creation: Basic bash script to create CA if not exists (asks for CN and validity), generates single RSA client cert with CN, signs using inline OpenSSL config, exports to .key, .crt, .pfx, creates client dir based on CN, handles serial/index. |
# | 8 | Major expansion: Added certificate type selection (client/server) with corresponding extensions (usr_client: clientAuth; usr_server: serverAuth), optional SAN input with parsing for DNS/IP prefixes, generates both RSA (2048) and EC (prime256v1) keys/certs simultaneously, shared PFX passphrase prompt, suffix in filenames based on type, copy_extensions=copy in config. |
# | 9 | SAN enhancement: Always includes the Common Name (CN) as the first SAN entry (with DNS/IP detection), changed SAN prompt to "additional SANs" to reflect automatic CN inclusion. |
# | 10 | WiFi support addition: Extended certificate type options to include wifi-client and wifi-server (mapping to same usr_client/usr_server extensions), adjusted suffix in filenames for wifi types to distinguish them. |
# | 11 | Added changelog comment at the beginning of the script. |
# | 12 | Added YubiKey support: Option to import file-based CA to YubiKey PIV (slot 9a), and choice to use file or YubiKey for signing via PKCS#11 engine (requires yubico-piv-tool, opensc, engine_pkcs11). |
# | 13 | Patches for bugs/security: Reduced CA key to RSA3072 for YubiKey compat; added PIN/MGMT args for import; removed PIN from PKCS11 URI; improved slot check; robust SAN parsing with Python/ipaddress; CN sanitizing; added CA extensions; standard CA db setup with newcerts; set -euo pipefail; added SKI/AKI to cert extensions. |
# | 14 | More hardening: validate CN against subject injection; make KU/BC critical; strict SAN addext format; heal CA DB structure even for existing CA; modern keygen (genpkey); improved YubiKey PKCS#11 key selection via env/prompt + pkcs11-tool hint; remove unused YubiKey signing PIN prompt; add minimal dependency checks. |

set -euo pipefail
umask 077

CA_DIR="CA"
CA_KEY="$CA_DIR/ca.key"
CA_CRT="$CA_DIR/ca.crt"
INDEX="$CA_DIR/index.txt"
SERIAL="$CA_DIR/serial"

PKCS11_MODULE="/usr/local/lib/opensc-pkcs11.so"  # Adjust if path differs on your system
ENGINE="pkcs11"
CA_SLOT="9a"   # PIV slot for CA key (9a commonly used for auth)
CA_ID="01"     # Legacy/default object name fallback (often NOT correct on all systems)

CERT_DAYS_DEFAULT=365

die() { echo "Error: $*" >&2; exit 1; }
need_cmd() { command -v "$1" >/dev/null 2>&1 || die "Missing command: $1"; }

ensure_ca_db() {
  mkdir -p "$CA_DIR/newcerts"
  [ -f "$INDEX" ] || : > "$INDEX"
  [ -f "$SERIAL" ] || echo "1000" > "$SERIAL"
}

validate_days() {
  local d="$1"
  [[ "$d" =~ ^[0-9]+$ ]] || die "Validity must be a number of days."
  [ "$d" -ge 1 ] || die "Validity must be >= 1 day."
}

validate_cn_subject() {
  local cn="$1"
  [ -n "$cn" ] || die "CN cannot be empty."
  # Prevent OpenSSL -subj injection and newline garbage
  if [[ "$cn" =~ [/$'\n''\r'] ]]; then
    die "CN contains illegal characters ('/' or newline)."
  fi
}

sanitize_for_fs() {
  # Keep it predictable across filesystems
  printf '%s' "$1" | tr -cs 'A-Za-z0-9._-@' '_'
}

has_python_ipaddress() {
  command -v python3 >/dev/null 2>&1 || return 1
  python3 - <<'PY' >/dev/null 2>&1
import ipaddress
PY
}

is_ip_addr() {
  # Returns 0 if argument is IP, else 1.
  local s="$1"
  if has_python_ipaddress; then
    python3 - <<PY >/dev/null 2>&1
import ipaddress
try:
    ipaddress.ip_address("$s")
    raise SystemExit(0)
except ValueError:
    raise SystemExit(1)
PY
    return $?
  fi

  # Fallback heuristics if python3/ipaddress isn't available.
  if [[ "$s" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    return 0
  fi
  # Minimal IPv6 heuristic: contains ':' and only hex/colon and at least 2 colons
  if [[ "$s" =~ : ]] && [[ "$s" =~ ^[0-9a-fA-F:]+$ ]] && [[ "$(printf '%s' "$s" | tr -cd ':' | wc -c)" -ge 2 ]]; then
    return 0
  fi
  return 1
}

build_san_list() {
  local cn="$1"
  local extra="${2:-}"
  local -a items=()
  items+=("$cn")

  if [ -n "$extra" ]; then
    IFS=',' read -r -a tmp <<< "$extra"
    items+=("${tmp[@]}")
  fi

  local out=""
  for raw in "${items[@]}"; do
    local s="${raw//[[:space:]]/}"
    [ -z "$s" ] && continue

    local entry=""
    if [[ "$s" =~ ^([Dd][Nn][Ss]|[Ii][Pp]): ]]; then
      local prefix="${s%%:*}"
      local rest="${s#*:}"
      prefix="${prefix^^}"
      entry="$prefix:$rest"
    else
      if is_ip_addr "$s"; then
        entry="IP:$s"
      else
        entry="DNS:$s"
      fi
    fi

    out+="${out:+,}$entry"
  done

  printf '%s' "$out"
}

openssl_ca_config() {
  # $1 = private_key value for config (file path or pkcs11 URI)
  local priv="$1"
  local cert_days="$2"
  cat <<EOF
[ ca ]
default_ca = local_ca

[ local_ca ]
dir = $CA_DIR
certificate = $CA_CRT
database = $INDEX
serial = $SERIAL
new_certs_dir = $CA_DIR/newcerts

private_key = $priv

default_days = $cert_days
default_md = sha256

copy_extensions = copy
unique_subject = no
policy = local_ca_policy

[ local_ca_policy ]
commonName = supplied

[ req ]
prompt = no
distinguished_name = dummy

[ usr_client ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer

[ usr_server ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EOF
}

create_file_ca() {
  need_cmd openssl
  ensure_ca_db

  local CA_CN="" CA_DAYS="" CA_KEYTYPE=""
  read -r -p "Enter CA Common Name (e.g., MyCA): " CA_CN
  validate_cn_subject "$CA_CN"

  read -r -p "Enter CA validity in days (e.g., 3650): " CA_DAYS
  validate_days "$CA_DAYS"

  read -r -p "CA key type (rsa2048/rsa3072/ecp256) [rsa3072]: " CA_KEYTYPE
  CA_KEYTYPE="${CA_KEYTYPE:-rsa3072}"

  case "$CA_KEYTYPE" in
    rsa2048)
      openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$CA_KEY"
      ;;
    rsa3072)
      openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$CA_KEY"
      ;;
    ecp256)
      openssl genpkey -algorithm EC \
        -pkeyopt ec_paramgen_curve:P-256 \
        -pkeyopt ec_param_enc:named_curve \
        -out "$CA_KEY"
      ;;
    *)
      die "Invalid CA key type: $CA_KEYTYPE"
      ;;
  esac

  openssl req -new -x509 -days "$CA_DAYS" -key "$CA_KEY" -out "$CA_CRT" -subj "/CN=$CA_CN" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash"

  : > "$INDEX"
  echo "1000" > "$SERIAL"

  echo "File-based CA created:"
  echo "  CA key : $CA_KEY"
  echo "  CA cert: $CA_CRT"
}

# --- Start ---
need_cmd openssl

# Ensure CA exists
if [ ! -f "$CA_KEY" ] || [ ! -f "$CA_CRT" ]; then
  create_file_ca
else
  ensure_ca_db
fi

# Optional: import file-based CA to YubiKey
read -r -p "Import existing file-based CA to YubiKey? (y/n): " IMPORT_YK
if [ "${IMPORT_YK:-n}" = "y" ]; then
  need_cmd yubico-piv-tool

  if yubico-piv-tool -a read-certificate -s "$CA_SLOT" >/dev/null 2>&1; then
    echo "Slot $CA_SLOT already occupied. Skipping import."
  else
    local_mgmt_key=""
    local_pin=""

    read -r -s -p "Enter YubiKey management key (default: 010203040506070801020304050607080102030405060708): " local_mgmt_key
    local_mgmt_key="${local_mgmt_key:-010203040506070801020304050607080102030405060708}"
    echo
    read -r -s -p "Enter YubiKey PIN (if set): " local_pin
    echo

    PIN_ARG=()
    [ -n "${local_pin:-}" ] && PIN_ARG=(-P "$local_pin")

    # Import key
    yubico-piv-tool "${PIN_ARG[@]}" -a import-key -s "$CA_SLOT" -k "$local_mgmt_key" -i "$CA_KEY" -K PEM \
      --pin-policy=once --touch-policy=always

    # Import certificate
    yubico-piv-tool "${PIN_ARG[@]}" -a import-certificate -s "$CA_SLOT" -k "$local_mgmt_key" -i "$CA_CRT" -K PEM

    echo "CA imported to YubiKey slot $CA_SLOT."
  fi
fi

# Ask for CA type for signing (file or yubikey)
read -r -p "Use file-based CA or YubiKey for signing? (file/yubikey): " CA_TYPE
if [ "${CA_TYPE:-}" != "file" ] && [ "${CA_TYPE:-}" != "yubikey" ]; then
  echo "Invalid type. Defaulting to file."
  CA_TYPE="file"
fi

CA_KEY_FORM=""
CA_KEY_SPEC=""

if [ "$CA_TYPE" = "yubikey" ]; then
  need_cmd yubico-piv-tool

  if ! yubico-piv-tool -a read-certificate -s "$CA_SLOT" >/dev/null 2>&1; then
    echo "No CA found on YubiKey slot $CA_SLOT. Falling back to file."
    CA_TYPE="file"
    CA_KEY_SPEC="$CA_KEY"
  else
    # Key selection is environment-specific. Allow override via CA_KEY_URI env var or prompt.
    # If things fail, run: pkcs11-tool --module "$PKCS11_MODULE" -O
    if command -v pkcs11-tool >/dev/null 2>&1; then
      echo "PKCS#11 objects (for troubleshooting / choosing the right key):"
      pkcs11-tool --module "$PKCS11_MODULE" -O || true
    else
      echo "Tip: install pkcs11-tool (OpenSC) to list available objects if signing fails."
    fi

    DEFAULT_URI="pkcs11:module=$PKCS11_MODULE;object=$CA_ID"
    read -r -p "Enter PKCS#11 URI for CA key (empty = default; or set CA_KEY_URI env): " USER_URI

    if [ -n "${USER_URI:-}" ]; then
      CA_KEY_SPEC="$USER_URI"
    else
      CA_KEY_SPEC="${CA_KEY_URI:-$DEFAULT_URI}"
    fi

    CA_KEY_FORM="engine"
    echo "Using YubiKey CA key via PKCS#11. You may be prompted for a PIN by the PKCS#11 engine."
  fi
else
  CA_KEY_SPEC="$CA_KEY"
fi

# Ask for certificate type
read -r -p "Enter certificate type (client/server/wifi-client/wifi-server): " CERT_TYPE
case "$CERT_TYPE" in
  client)       EXT_SECTION="usr_client"; SUFFIX="client" ;;
  server)       EXT_SECTION="usr_server"; SUFFIX="server" ;;
  wifi-client)  EXT_SECTION="usr_client"; SUFFIX="wifi-client" ;;
  wifi-server)  EXT_SECTION="usr_server"; SUFFIX="wifi-server" ;;
  *) die "Invalid type. Must be client/server/wifi-client/wifi-server." ;;
esac

# Subject/SAN input
read -r -p "Enter Common Name (e.g., client1.example.com or server.example.com): " CN
validate_cn_subject "$CN"

read -r -p "Enter additional SANs (comma-separated; supports DNS: / IP: prefixes; empty if none): " SAN_INPUT

SAFE_CN="$(sanitize_for_fs "$CN")"
DIR="$SAFE_CN"
mkdir -p "$DIR"

SAN_LIST="$(build_san_list "$CN" "${SAN_INPUT:-}")"
SAN_EXT="subjectAltName=$SAN_LIST"

read -r -s -p "Enter passphrase for PFX export (leave empty for none): " PFX_PASS
echo

generate_cert() {
  local KEY_TYPE="$1"
  local KEY_SIZE="${2:-}"
  local CURVE="${3:-}"

  local KEY="$DIR/$SAFE_CN-$KEY_TYPE-$SUFFIX.key"
  local CSR="$DIR/$SAFE_CN-$KEY_TYPE-$SUFFIX.csr"
  local CRT="$DIR/$SAFE_CN-$KEY_TYPE-$SUFFIX.crt"
  local PFX="$DIR/$SAFE_CN-$KEY_TYPE-$SUFFIX.pfx"

  # Cleanup CSR even if something fails inside this function
  trap 'rm -f "$CSR"' RETURN

  if [ "$KEY_TYPE" = "rsa" ]; then
    openssl genpkey -algorithm RSA -pkeyopt "rsa_keygen_bits:$KEY_SIZE" -out "$KEY"
  else
    openssl genpkey -algorithm EC \
      -pkeyopt "ec_paramgen_curve:$CURVE" \
      -pkeyopt ec_param_enc:named_curve \
      -out "$KEY"
  fi

  openssl req -new -key "$KEY" -out "$CSR" -subj "/CN=$CN" -addext "$SAN_EXT"

  local CERT_DAYS="${CERT_DAYS:-$CERT_DAYS_DEFAULT}"
  validate_days "$CERT_DAYS"

  if [ "$CA_TYPE" = "yubikey" ]; then
    openssl ca -batch \
      -engine "$ENGINE" \
      -keyform "$CA_KEY_FORM" \
      -keyfile "$CA_KEY_SPEC" \
      -cert "$CA_CRT" \
      -in "$CSR" \
      -out "$CRT" \
      -extensions "$EXT_SECTION" \
      -config <(openssl_ca_config "$CA_KEY_SPEC" "$CERT_DAYS")
  else
    openssl ca -batch \
      -keyfile "$CA_KEY_SPEC" \
      -cert "$CA_CRT" \
      -in "$CSR" \
      -out "$CRT" \
      -extensions "$EXT_SECTION" \
      -config <(openssl_ca_config "$CA_KEY_SPEC" "$CERT_DAYS")
  fi

  if [ -n "${PFX_PASS:-}" ]; then
    openssl pkcs12 -export -out "$PFX" -inkey "$KEY" -in "$CRT" -certfile "$CA_CRT" -passout "pass:$PFX_PASS"
  else
    openssl pkcs12 -export -out "$PFX" -inkey "$KEY" -in "$CRT" -certfile "$CA_CRT" -passout pass:
  fi

  echo "$KEY_TYPE-$SUFFIX certificate created:"
  echo "  Key : $KEY"
  echo "  Cert: $CRT"
  echo "  PFX : $PFX"
}

generate_cert "rsa" "2048" ""
generate_cert "ec" "" "prime256v1"

echo "Done."
echo "CA cert (import this into trust store if needed): $CA_CRT"
# Version 14
# Note: For a true on-YubiKey CA (no file CA private key ever), add a mode that generates the CA key on-device and self-signs via PKCS#11.

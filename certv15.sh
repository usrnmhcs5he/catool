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
# | 15 | Bug fixes + modernisation: FIX CN validation char class that wrongly rejected any CN containing 'r' or '\' (literal '\r' in bracket expression); FIX sanitize_for_fs invalid reverse tr range '_-@' (fatal on GNU tr); restore Bash 3.2 compatibility (removed ${var^^}, guarded empty-array expansion under set -u); FIX Python code injection in is_ip_addr (input now passed as argv, not interpolated); clear stale RETURN trap in generate_cert; PFX passphrase moved off argv to fd:3; restored per-run cert validity prompt (default 365, CERT_DAYS env honoured); optional CA key encryption (AES-256, default off = previous behaviour); corrected default PKCS#11 URI to RFC 7512 id form (pkcs11:id=%01 for PIV 9a, OpenSC mapping); engine availability pre-check; overwrite warning for existing output files; PFX_LEGACY=1 env for OpenSSL3 -legacy pkcs12; ASCII interface overhaul (banner, sections, numbered menus). |

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
# OpenSC PIV slot -> PKCS#11 object ID mapping (per OpenSC docs; verify with
# 'pkcs11-tool -O' on your system): 9a->%01  9c->%02  9d->%03  9e->%04
CA_PKCS11_ID="%01"

CERT_DAYS_DEFAULT=365
# Optional env toggles:
#   CA_KEY_URI=...   override PKCS#11 URI for the CA key
#   CERT_DAYS=N      preset cert validity (skips prompt default)
#   PFX_LEGACY=1     use 'openssl pkcs12 -legacy' for old Windows/device imports
#
# Known limitation: yubico-piv-tool takes the management key as a command-line
# argument (-k); it is briefly visible in the process list. The tool offers no
# stdin/fd alternative for it.

# ---------------------------------------------------------------- ui helpers
banner() {
  cat <<'EOF'
+============================================================+
|                                                            |
|      L O C A L   C A   B U I L D E R          v15          |
|                                                            |
|      file CA / YubiKey PIV  .  RSA + EC  .  PFX export     |
|                                                            |
+============================================================+
EOF
}

section() {
  printf '\n==[ %s ]' "$1"
  local len=${#1}
  local pad=$((54 - len))
  local i=0
  while [ "$i" -lt "$pad" ]; do printf '='; i=$((i+1)); done
  printf '\n'
}

die() { echo "Error: $*" >&2; exit 1; }
need_cmd() { command -v "$1" >/dev/null 2>&1 || die "Missing command: $1"; }

# menu <varname> <prompt> <opt1> <opt2> ...  (bash 3.2 compatible)
menu() {
  local __var="$1"; shift
  local __prompt="$1"; shift
  local i=1
  local opt
  for opt in "$@"; do
    printf '  [%d] %s\n' "$i" "$opt"
    i=$((i+1))
  done
  local choice=""
  while :; do
    read -r -p "$__prompt [1-$#]: " choice
    if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le $# ]; then
      break
    fi
    echo "  Invalid choice."
  done
  local n=1
  for opt in "$@"; do
    if [ "$n" -eq "$choice" ]; then
      eval "$__var=\"\$opt\""
      return 0
    fi
    n=$((n+1))
  done
}

# ------------------------------------------------------------- core helpers
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
  # v15 FIX: previous bracket expression [/$'\n''\r'] contained a literal
  # backslash and a literal 'r', rejecting e.g. "server.example.com".
  local cn="$1"
  [ -n "$cn" ] || die "CN cannot be empty."
  case "$cn" in
    */*)        die "CN contains illegal character '/'." ;;
  esac
  if [[ "$cn" == *$'\n'* ]] || [[ "$cn" == *$'\r'* ]]; then
    die "CN contains illegal newline characters."
  fi
}

sanitize_for_fs() {
  # v15 FIX: '_-@' inside the tr set was parsed as a reverse range and is
  # fatal on GNU tr. Dash must be last; all set members are now literal.
  printf '%s' "$1" | tr -cs 'A-Za-z0-9._@-' '_'
}

to_upper() {
  printf '%s' "$1" | tr '[:lower:]' '[:upper:]'
}

has_python_ipaddress() {
  command -v python3 >/dev/null 2>&1 || return 1
  python3 -c 'import ipaddress' >/dev/null 2>&1
}

is_ip_addr() {
  # Returns 0 if argument is IP, else 1.
  # v15 FIX: input is passed as argv, never interpolated into Python source.
  local s="$1"
  if has_python_ipaddress; then
    python3 -c '
import ipaddress, sys
try:
    ipaddress.ip_address(sys.argv[1])
    sys.exit(0)
except ValueError:
    sys.exit(1)
' "$s"
    return $?
  fi

  # Fallback heuristics if python3/ipaddress is not available.
  if [[ "$s" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    return 0
  fi
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
    local -a tmp=()
    IFS=',' read -r -a tmp <<< "$extra"
    # v15 FIX: guard empty-array expansion (set -u, bash < 4.4)
    items+=(${tmp[@]+"${tmp[@]}"})
  fi

  local out=""
  local raw s entry prefix rest
  for raw in "${items[@]}"; do
    s="${raw//[[:space:]]/}"
    [ -z "$s" ] && continue

    entry=""
    if [[ "$s" =~ ^([Dd][Nn][Ss]|[Ii][Pp]): ]]; then
      prefix="${s%%:*}"
      rest="${s#*:}"
      # v15 FIX: ${var^^} is bash 4+; replaced for Bash 3.2 compatibility
      prefix="$(to_upper "$prefix")"
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
  section "CREATE FILE-BASED CA"

  local CA_CN="" CA_DAYS="" CA_KEYTYPE="" CA_ENCRYPT=""
  read -r -p "Enter CA Common Name (e.g., MyCA): " CA_CN
  validate_cn_subject "$CA_CN"

  read -r -p "Enter CA validity in days (e.g., 3650): " CA_DAYS
  validate_days "$CA_DAYS"

  menu CA_KEYTYPE "CA key type" "rsa3072 (default, YubiKey compatible)" "rsa2048" "ecp256"
  case "$CA_KEYTYPE" in
    rsa3072*) CA_KEYTYPE="rsa3072" ;;
    rsa2048*) CA_KEYTYPE="rsa2048" ;;
    ecp256*)  CA_KEYTYPE="ecp256" ;;
  esac

  # v15: optional at-rest encryption of the CA key. Default 'n' preserves
  # previous behaviour. Note: an encrypted CA key will prompt for the
  # passphrase on every signing operation.
  read -r -p "Encrypt CA private key with a passphrase (AES-256)? (y/n) [n]: " CA_ENCRYPT
  CA_ENCRYPT="${CA_ENCRYPT:-n}"

  local -a ENC_ARGS=()
  [ "$CA_ENCRYPT" = "y" ] && ENC_ARGS=(-aes-256-cbc)

  case "$CA_KEYTYPE" in
    rsa2048)
      openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 ${ENC_ARGS[@]+"${ENC_ARGS[@]}"} -out "$CA_KEY"
      ;;
    rsa3072)
      openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 ${ENC_ARGS[@]+"${ENC_ARGS[@]}"} -out "$CA_KEY"
      ;;
    ecp256)
      openssl genpkey -algorithm EC \
        -pkeyopt ec_paramgen_curve:P-256 \
        -pkeyopt ec_param_enc:named_curve \
        ${ENC_ARGS[@]+"${ENC_ARGS[@]}"} -out "$CA_KEY"
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

# =============================================================== Start =====
need_cmd openssl
banner

# Ensure CA exists
if [ ! -f "$CA_KEY" ] || [ ! -f "$CA_CRT" ]; then
  create_file_ca
else
  ensure_ca_db
  echo "Existing CA found: $CA_CRT"
fi

# ------------------------------------------------- optional YubiKey import
section "YUBIKEY (OPTIONAL)"
read -r -p "Import existing file-based CA to YubiKey? (y/n) [n]: " IMPORT_YK
if [ "${IMPORT_YK:-n}" = "y" ]; then
  need_cmd yubico-piv-tool

  if yubico-piv-tool -a read-certificate -s "$CA_SLOT" >/dev/null 2>&1; then
    echo "Slot $CA_SLOT already occupied. Skipping import."
  else
    yk_mgmt_key=""
    yk_pin=""

    read -r -s -p "Enter YubiKey management key (empty = factory default; CHANGE IT if still default): " yk_mgmt_key
    yk_mgmt_key="${yk_mgmt_key:-010203040506070801020304050607080102030405060708}"
    echo
    read -r -s -p "Enter YubiKey PIN (if set): " yk_pin
    echo

    PIN_ARG=()
    [ -n "${yk_pin:-}" ] && PIN_ARG=(-P "$yk_pin")

    # v15 FIX: guarded empty-array expansion (set -u, bash < 4.4)
    yubico-piv-tool ${PIN_ARG[@]+"${PIN_ARG[@]}"} -a import-key -s "$CA_SLOT" -k "$yk_mgmt_key" -i "$CA_KEY" -K PEM \
      --pin-policy=once --touch-policy=always

    yubico-piv-tool ${PIN_ARG[@]+"${PIN_ARG[@]}"} -a import-certificate -s "$CA_SLOT" -k "$yk_mgmt_key" -i "$CA_CRT" -K PEM

    echo "CA imported to YubiKey slot $CA_SLOT."
  fi
fi

# -------------------------------------------------------- signing backend
section "SIGNING BACKEND"
menu CA_TYPE "Sign with" "file  (CA key on disk)" "yubikey  (CA key on PIV, via PKCS#11)"
case "$CA_TYPE" in
  file*)    CA_TYPE="file" ;;
  yubikey*) CA_TYPE="yubikey" ;;
esac

CA_KEY_FORM=""
CA_KEY_SPEC=""

if [ "$CA_TYPE" = "yubikey" ]; then
  need_cmd yubico-piv-tool

  # v15: verify the pkcs11 engine is actually usable before committing to it
  if ! openssl engine "$ENGINE" -t >/dev/null 2>&1; then
    die "OpenSSL engine '$ENGINE' not available. Install libp11/engine_pkcs11 (and OpenSC), or sign with the file CA."
  fi

  if ! yubico-piv-tool -a read-certificate -s "$CA_SLOT" >/dev/null 2>&1; then
    echo "No CA found on YubiKey slot $CA_SLOT. Falling back to file."
    CA_TYPE="file"
    CA_KEY_SPEC="$CA_KEY"
  else
    if command -v pkcs11-tool >/dev/null 2>&1; then
      echo "PKCS#11 objects (for troubleshooting / choosing the right key):"
      pkcs11-tool --module "$PKCS11_MODULE" -O || true
    else
      echo "Tip: install pkcs11-tool (OpenSC) to list available objects if signing fails."
    fi

    # v15 FIX: RFC 7512 has no 'module=' attribute and 'object=' names a
    # label. OpenSC exposes PIV slot 9a as ID %01 (see mapping at top).
    DEFAULT_URI="pkcs11:id=$CA_PKCS11_ID"
    read -r -p "Enter PKCS#11 URI for CA key (empty = $DEFAULT_URI; or set CA_KEY_URI env): " USER_URI

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

# ------------------------------------------------------- certificate input
section "CERTIFICATE REQUEST"
menu CERT_TYPE "Certificate type" "client" "server" "wifi-client" "wifi-server"
case "$CERT_TYPE" in
  client)       EXT_SECTION="usr_client"; SUFFIX="client" ;;
  server)       EXT_SECTION="usr_server"; SUFFIX="server" ;;
  wifi-client)  EXT_SECTION="usr_client"; SUFFIX="wifi-client" ;;
  wifi-server)  EXT_SECTION="usr_server"; SUFFIX="wifi-server" ;;
  *) die "Invalid type. Must be client/server/wifi-client/wifi-server." ;;
esac

read -r -p "Enter Common Name (e.g., client1.example.com or server.example.com): " CN
validate_cn_subject "$CN"

read -r -p "Enter additional SANs (comma-separated; supports DNS: / IP: prefixes; empty if none): " SAN_INPUT

# v15: validity prompt restored (was silently fixed at 365 unless env set)
CERT_DAYS_IN="${CERT_DAYS:-}"
if [ -z "$CERT_DAYS_IN" ]; then
  read -r -p "Certificate validity in days [$CERT_DAYS_DEFAULT]: " CERT_DAYS_IN
  CERT_DAYS_IN="${CERT_DAYS_IN:-$CERT_DAYS_DEFAULT}"
fi
validate_days "$CERT_DAYS_IN"
CERT_DAYS="$CERT_DAYS_IN"

SAFE_CN="$(sanitize_for_fs "$CN")"
DIR="$SAFE_CN"
mkdir -p "$DIR"

SAN_LIST="$(build_san_list "$CN" "${SAN_INPUT:-}")"
SAN_EXT="subjectAltName=$SAN_LIST"

read -r -s -p "Enter passphrase for PFX export (leave empty for none): " PFX_PASS
echo

# --------------------------------------------------------------- generate
section "GENERATE + SIGN"

generate_cert() {
  local KEY_TYPE="$1"
  local KEY_SIZE="${2:-}"
  local CURVE="${3:-}"

  local KEY="$DIR/$SAFE_CN-$KEY_TYPE-$SUFFIX.key"
  local CSR="$DIR/$SAFE_CN-$KEY_TYPE-$SUFFIX.csr"
  local CRT="$DIR/$SAFE_CN-$KEY_TYPE-$SUFFIX.crt"
  local PFX="$DIR/$SAFE_CN-$KEY_TYPE-$SUFFIX.pfx"

  # v15: warn before silently overwriting a previous key/cert set
  if [ -f "$KEY" ] || [ -f "$CRT" ]; then
    local OVERWRITE=""
    read -r -p "Output files for $KEY_TYPE-$SUFFIX exist and will be OVERWRITTEN. Continue? (y/n) [n]: " OVERWRITE
    [ "${OVERWRITE:-n}" = "y" ] || { echo "Skipped $KEY_TYPE-$SUFFIX."; return 0; }
  fi

  # v15 FIX: clear the trap after it fires so it cannot re-fire on later
  # function returns with an out-of-scope \$CSR
  trap 'rm -f "$CSR"; trap - RETURN' RETURN

  if [ "$KEY_TYPE" = "rsa" ]; then
    openssl genpkey -algorithm RSA -pkeyopt "rsa_keygen_bits:$KEY_SIZE" -out "$KEY"
  else
    openssl genpkey -algorithm EC \
      -pkeyopt "ec_paramgen_curve:$CURVE" \
      -pkeyopt ec_param_enc:named_curve \
      -out "$KEY"
  fi

  openssl req -new -key "$KEY" -out "$CSR" -subj "/CN=$CN" -addext "$SAN_EXT"

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

  # v15: PFX passphrase via fd:3 herestring - never on the command line.
  # PFX_LEGACY=1 adds -legacy for OpenSSL 3 -> old Windows/device imports.
  local -a P12_EXTRA=()
  [ "${PFX_LEGACY:-0}" = "1" ] && P12_EXTRA=(-legacy)

  openssl pkcs12 -export ${P12_EXTRA[@]+"${P12_EXTRA[@]}"} \
    -out "$PFX" -inkey "$KEY" -in "$CRT" -certfile "$CA_CRT" \
    -passout fd:3 3<<<"${PFX_PASS:-}"

  echo "$KEY_TYPE-$SUFFIX certificate created:"
  echo "  Key : $KEY"
  echo "  Cert: $CRT"
  echo "  PFX : $PFX"
}

generate_cert "rsa" "2048" ""
generate_cert "ec" "" "prime256v1"

section "DONE"
echo "CA cert (import this into trust store if needed): $CA_CRT"
# Version 15
# Note: For a true on-YubiKey CA (no file CA private key ever), add a mode that generates the CA key on-device and self-signs via PKCS#11.

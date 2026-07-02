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
# | 16 | Navigation + visual polish: main flow restructured as a state machine; every menu now offers [b] Back and [q] Quit; every text prompt accepts :b (back) and :q (quit) tokens (silent passphrase/PIN prompts deliberately excluded so literal values are never intercepted); CA creation prompts also navigable; new pre-generation summary screen with Generate / Start over options; internal variable assignment via printf -v instead of eval; TTY-guarded bold/colour output (disabled when piped, respects NO_COLOR); step counters in section headers. No changes to cryptographic behaviour, file formats, naming, or CA state handling. |

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
#   NO_COLOR=1       disable coloured/bold output even on a TTY
#
# Navigation: type ':b' to go back or ':q' to quit at any text prompt;
# menus accept 'b' / 'q'. Passphrase/PIN prompts do not parse these tokens.
#
# Known limitation: yubico-piv-tool takes the management key as a command-line
# argument (-k); it is briefly visible in the process list. The tool offers no
# stdin/fd alternative for it.

# Navigation return code used by ask()/menu(): 10 = go back one step
NAV_BACK=10

# ---------------------------------------------------------------- ui helpers
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_BOLD="$(printf '\033[1m')"
  C_GREEN="$(printf '\033[32m')"
  C_YELLOW="$(printf '\033[33m')"
  C_RESET="$(printf '\033[0m')"
else
  C_BOLD=""; C_GREEN=""; C_YELLOW=""; C_RESET=""
fi

banner() {
  printf '%s' "$C_BOLD"
  cat <<'EOF'
+============================================================+
|                                                            |
|      L O C A L   C A   B U I L D E R          v16          |
|                                                            |
|      file CA / YubiKey PIV  .  RSA + EC  .  PFX export     |
|                                                            |
+============================================================+
EOF
  printf '%s' "$C_RESET"
  printf ' Navigation: ":b" back, ":q" quit at prompts; "b"/"q" in menus.\n'
  printf ' (Passphrase prompts take input literally.)\n'
}

section() {
  printf '\n%s==[ %s ]%s' "$C_BOLD" "$1" "$C_RESET"
  local len=${#1}
  local pad=$((54 - len))
  local i=0
  while [ "$i" -lt "$pad" ]; do printf '='; i=$((i+1)); done
  printf '\n'
}

ok() { printf '%s[ok]%s %s\n' "$C_GREEN" "$C_RESET" "$1"; }

die() { echo "Error: $*" >&2; exit 1; }
need_cmd() { command -v "$1" >/dev/null 2>&1 || die "Missing command: $1"; }

quit_now() { echo "Quit."; exit 0; }

# ask <varname> <prompt>   text prompt with :b / :q navigation tokens
# returns 0 = value set, NAV_BACK = user requested back
ask() {
  local __var="$1"
  local __prompt="$2"
  local val=""
  read -r -p "$__prompt" val
  case "$val" in
    :b) return "$NAV_BACK" ;;
    :q) quit_now ;;
  esac
  printf -v "$__var" '%s' "$val"
  return 0
}

# menu <varname> <prompt> <opt1> <opt2> ...  (bash 3.2 compatible)
# returns 0 = option chosen, NAV_BACK = back requested; 'q' quits directly
menu() {
  local __var="$1"; shift
  local __prompt="$1"; shift
  local i=1
  local opt
  for opt in "$@"; do
    printf '  [%d] %s\n' "$i" "$opt"
    i=$((i+1))
  done
  printf '  %s[b] Back    [q] Quit%s\n' "$C_YELLOW" "$C_RESET"
  local choice=""
  while :; do
    read -r -p "$__prompt [1-$#/b/q]: " choice
    case "$choice" in
      b|B|:b) return "$NAV_BACK" ;;
      q|Q|:q) quit_now ;;
    esac
    if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le $# ]; then
      break
    fi
    echo "  Invalid choice."
  done
  local n=1
  for opt in "$@"; do
    if [ "$n" -eq "$choice" ]; then
      printf -v "$__var" '%s' "$opt"
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
  # Returns 0 if argument is IP, else 1. Input passed as argv (no interpolation).
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
  local cstep=1 rc=0

  while :; do
    case "$cstep" in
      1)
        rc=0; ask CA_CN "Enter CA Common Name (e.g., MyCA): " || rc=$?
        if [ "$rc" -eq "$NAV_BACK" ]; then echo "  (already at first step)"; continue; fi
        validate_cn_subject "$CA_CN"
        cstep=2 ;;
      2)
        rc=0; ask CA_DAYS "Enter CA validity in days (e.g., 3650): " || rc=$?
        if [ "$rc" -eq "$NAV_BACK" ]; then cstep=1; continue; fi
        validate_days "$CA_DAYS"
        cstep=3 ;;
      3)
        rc=0; menu CA_KEYTYPE "CA key type" "rsa3072 (default, YubiKey compatible)" "rsa2048" "ecp256" || rc=$?
        if [ "$rc" -eq "$NAV_BACK" ]; then cstep=2; continue; fi
        case "$CA_KEYTYPE" in
          rsa3072*) CA_KEYTYPE="rsa3072" ;;
          rsa2048*) CA_KEYTYPE="rsa2048" ;;
          ecp256*)  CA_KEYTYPE="ecp256" ;;
        esac
        cstep=4 ;;
      4)
        rc=0; ask CA_ENCRYPT "Encrypt CA private key with a passphrase (AES-256)? (y/n) [n]: " || rc=$?
        if [ "$rc" -eq "$NAV_BACK" ]; then cstep=3; continue; fi
        CA_ENCRYPT="${CA_ENCRYPT:-n}"
        break ;;
    esac
  done

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

  ok "File-based CA created:"
  echo "  CA key : $CA_KEY"
  echo "  CA cert: $CA_CRT"
}

do_yubikey_import() {
  need_cmd yubico-piv-tool

  if yubico-piv-tool -a read-certificate -s "$CA_SLOT" >/dev/null 2>&1; then
    echo "Slot $CA_SLOT already occupied. Skipping import."
    return 0
  fi

  local yk_mgmt_key="" yk_pin=""

  # Silent prompts: navigation tokens intentionally NOT parsed here
  read -r -s -p "Enter YubiKey management key (empty = factory default; CHANGE IT if still default): " yk_mgmt_key
  yk_mgmt_key="${yk_mgmt_key:-010203040506070801020304050607080102030405060708}"
  echo
  read -r -s -p "Enter YubiKey PIN (if set): " yk_pin
  echo

  PIN_ARG=()
  [ -n "${yk_pin:-}" ] && PIN_ARG=(-P "$yk_pin")

  yubico-piv-tool ${PIN_ARG[@]+"${PIN_ARG[@]}"} -a import-key -s "$CA_SLOT" -k "$yk_mgmt_key" -i "$CA_KEY" -K PEM \
    --pin-policy=once --touch-policy=always

  yubico-piv-tool ${PIN_ARG[@]+"${PIN_ARG[@]}"} -a import-certificate -s "$CA_SLOT" -k "$yk_mgmt_key" -i "$CA_CRT" -K PEM

  ok "CA imported to YubiKey slot $CA_SLOT."
}

# select_backend: sets CA_TYPE, CA_KEY_FORM, CA_KEY_SPEC
# returns 0 = done, NAV_BACK = back requested
select_backend() {
  local rc=0 SEL=""
  menu SEL "Sign with" "file  (CA key on disk)" "yubikey  (CA key on PIV, via PKCS#11)" || rc=$?
  [ "$rc" -eq "$NAV_BACK" ] && return "$NAV_BACK"

  case "$SEL" in
    file*)    CA_TYPE="file" ;;
    yubikey*) CA_TYPE="yubikey" ;;
  esac

  CA_KEY_FORM=""
  CA_KEY_SPEC=""

  if [ "$CA_TYPE" = "yubikey" ]; then
    need_cmd yubico-piv-tool

    if ! openssl engine "$ENGINE" -t >/dev/null 2>&1; then
      die "OpenSSL engine '$ENGINE' not available. Install libp11/engine_pkcs11 (and OpenSC), or sign with the file CA."
    fi

    if ! yubico-piv-tool -a read-certificate -s "$CA_SLOT" >/dev/null 2>&1; then
      echo "No CA found on YubiKey slot $CA_SLOT. Falling back to file."
      CA_TYPE="file"
      CA_KEY_SPEC="$CA_KEY"
      return 0
    fi

    if command -v pkcs11-tool >/dev/null 2>&1; then
      echo "PKCS#11 objects (for troubleshooting / choosing the right key):"
      pkcs11-tool --module "$PKCS11_MODULE" -O || true
    else
      echo "Tip: install pkcs11-tool (OpenSC) to list available objects if signing fails."
    fi

    local DEFAULT_URI="pkcs11:id=$CA_PKCS11_ID"
    local USER_URI="" urc=0
    ask USER_URI "Enter PKCS#11 URI for CA key (empty = $DEFAULT_URI; or set CA_KEY_URI env): " || urc=$?
    # back from the URI prompt returns to the backend menu
    [ "$urc" -eq "$NAV_BACK" ] && return "$NAV_BACK"

    if [ -n "${USER_URI:-}" ]; then
      CA_KEY_SPEC="$USER_URI"
    else
      CA_KEY_SPEC="${CA_KEY_URI:-$DEFAULT_URI}"
    fi

    CA_KEY_FORM="engine"
    echo "Using YubiKey CA key via PKCS#11. You may be prompted for a PIN by the PKCS#11 engine."
  else
    CA_KEY_SPEC="$CA_KEY"
  fi
  return 0
}

generate_cert() {
  local KEY_TYPE="$1"
  local KEY_SIZE="${2:-}"
  local CURVE="${3:-}"

  local KEY="$DIR/$SAFE_CN-$KEY_TYPE-$SUFFIX.key"
  local CSR="$DIR/$SAFE_CN-$KEY_TYPE-$SUFFIX.csr"
  local CRT="$DIR/$SAFE_CN-$KEY_TYPE-$SUFFIX.crt"
  local PFX="$DIR/$SAFE_CN-$KEY_TYPE-$SUFFIX.pfx"

  if [ -f "$KEY" ] || [ -f "$CRT" ]; then
    local OVERWRITE=""
    read -r -p "Output files for $KEY_TYPE-$SUFFIX exist and will be OVERWRITTEN. Continue? (y/n) [n]: " OVERWRITE
    [ "${OVERWRITE:-n}" = "y" ] || { echo "Skipped $KEY_TYPE-$SUFFIX."; return 0; }
  fi

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

  local -a P12_EXTRA=()
  [ "${PFX_LEGACY:-0}" = "1" ] && P12_EXTRA=(-legacy)

  openssl pkcs12 -export ${P12_EXTRA[@]+"${P12_EXTRA[@]}"} \
    -out "$PFX" -inkey "$KEY" -in "$CRT" -certfile "$CA_CRT" \
    -passout fd:3 3<<<"${PFX_PASS:-}"

  ok "$KEY_TYPE-$SUFFIX certificate created:"
  echo "  Key : $KEY"
  echo "  Cert: $CRT"
  echo "  PFX : $PFX"
}

# =============================================================== Start =====
need_cmd openssl
banner

if [ ! -f "$CA_KEY" ] || [ ! -f "$CA_CRT" ]; then
  create_file_ca
else
  ensure_ca_db
  echo "Existing CA found: $CA_CRT"
fi

# ------------------------------------------------------ interactive flow --
# State machine: [b]/:b moves one step back, :q / [q] quits, summary screen
# allows restart from step 1.
CA_TYPE=""; CA_KEY_FORM=""; CA_KEY_SPEC=""
CERT_TYPE=""; EXT_SECTION=""; SUFFIX=""
CN=""; SAN_INPUT=""; CERT_DAYS=""; PFX_PASS=""

step=1
while :; do
  rc=0
  case "$step" in

    1)  section "1/5  YUBIKEY (OPTIONAL)"
        IMPORT_YK=""
        ask IMPORT_YK "Import existing file-based CA to YubiKey? (y/n) [n]: " || rc=$?
        if [ "$rc" -eq "$NAV_BACK" ]; then echo "  (already at first step)"; continue; fi
        if [ "${IMPORT_YK:-n}" = "y" ]; then
          do_yubikey_import
        fi
        step=2 ;;

    2)  section "2/5  SIGNING BACKEND"
        select_backend || rc=$?
        if [ "$rc" -eq "$NAV_BACK" ]; then step=1; continue; fi
        step=3 ;;

    3)  section "3/5  CERTIFICATE TYPE"
        menu CERT_TYPE "Certificate type" "client" "server" "wifi-client" "wifi-server" || rc=$?
        if [ "$rc" -eq "$NAV_BACK" ]; then step=2; continue; fi
        case "$CERT_TYPE" in
          client)       EXT_SECTION="usr_client"; SUFFIX="client" ;;
          server)       EXT_SECTION="usr_server"; SUFFIX="server" ;;
          wifi-client)  EXT_SECTION="usr_client"; SUFFIX="wifi-client" ;;
          wifi-server)  EXT_SECTION="usr_server"; SUFFIX="wifi-server" ;;
          *) die "Invalid type." ;;
        esac
        step=4 ;;

    4)  section "4/5  SUBJECT + OPTIONS"
        ask CN "Enter Common Name (e.g., client1.example.com or server.example.com): " || rc=$?
        if [ "$rc" -eq "$NAV_BACK" ]; then step=3; continue; fi
        validate_cn_subject "$CN"

        rc=0
        ask SAN_INPUT "Enter additional SANs (comma-separated; supports DNS: / IP: prefixes; empty if none): " || rc=$?
        if [ "$rc" -eq "$NAV_BACK" ]; then continue; fi   # back to CN (same step)

        CERT_DAYS_IN="${CERT_DAYS_ENV_ONCE:-${CERT_DAYS:-}}"
        if [ -z "$CERT_DAYS_IN" ]; then
          rc=0
          ask CERT_DAYS_IN "Certificate validity in days [$CERT_DAYS_DEFAULT]: " || rc=$?
          if [ "$rc" -eq "$NAV_BACK" ]; then continue; fi # back to CN (same step)
          CERT_DAYS_IN="${CERT_DAYS_IN:-$CERT_DAYS_DEFAULT}"
        fi
        validate_days "$CERT_DAYS_IN"
        CERT_DAYS="$CERT_DAYS_IN"

        # Silent prompt: navigation tokens intentionally NOT parsed here
        read -r -s -p "Enter passphrase for PFX export (leave empty for none): " PFX_PASS
        echo
        step=5 ;;

    5)  section "5/5  SUMMARY"
        SAN_LIST="$(build_san_list "$CN" "${SAN_INPUT:-}")"
        printf '  Backend  : %s\n' "$CA_TYPE"
        printf '  Type     : %s\n' "$CERT_TYPE"
        printf '  CN       : %s\n' "$CN"
        printf '  SANs     : %s\n' "$SAN_LIST"
        printf '  Validity : %s days\n' "$CERT_DAYS"
        if [ -n "${PFX_PASS:-}" ]; then
          printf '  PFX pass : set\n'
        else
          printf '  PFX pass : (none)\n'
        fi
        SUMSEL=""
        menu SUMSEL "Proceed" "Generate certificates" "Start over (from step 1)" || rc=$?
        if [ "$rc" -eq "$NAV_BACK" ]; then step=4; continue; fi
        case "$SUMSEL" in
          Generate*)   break ;;
          Start*)      step=1; continue ;;
        esac ;;
  esac
done

# --------------------------------------------------------------- generate
section "GENERATE + SIGN"

SAFE_CN="$(sanitize_for_fs "$CN")"
DIR="$SAFE_CN"
mkdir -p "$DIR"

SAN_LIST="$(build_san_list "$CN" "${SAN_INPUT:-}")"
SAN_EXT="subjectAltName=$SAN_LIST"

generate_cert "rsa" "2048" ""
generate_cert "ec" "" "prime256v1"

section "DONE"
echo "CA cert (import this into trust store if needed): $CA_CRT"
# Version 16
# Note: For a true on-YubiKey CA (no file CA private key ever), add a mode that generates the CA key on-device and self-signs via PKCS#11.

#!/bin/bash
# Changelog
# | Version | Changes |
# |---------|---------|
# | 1 | Initial creation: Basic bash script to create CA if not exists (asks for CN and validity), generates single RSA client cert with CN, signs using inline OpenSSL config, exports to .key, .crt, .pfx, creates client dir based on CN, handles serial/index. |
# | 8 | Major expansion: Added certificate type selection (client/server) with corresponding extensions (usr_client: clientAuth; usr_server: serverAuth), optional SAN input with parsing for DNS/IP prefixes, generates both RSA (2048) and EC (prime256v1) keys/certs simultaneously, shared PFX passphrase prompt, suffix in filenames based on type, copy_extensions=copy in config. |
# | 9 | SAN enhancement: Always includes the Common Name (CN) as the first SAN entry (with DNS/IP detection), changed SAN prompt to "additional SANs" to reflect automatic CN inclusion. |
# | 10 | WiFi support addition: Extended certificate type options to include wifi-client and wifi-server (mapping to same usr_client/usr_server extensions), adjusted suffix in filenames for wifi types to distinguish them. |
# | 11 | Added changelog comment at the beginning of the script. |

CA_DIR="CA"
CA_KEY="$CA_DIR/ca.key"
CA_CRT="$CA_DIR/ca.crt"
INDEX="$CA_DIR/index.txt"
SERIAL="$CA_DIR/serial"
# Function to create CA if not exists (RSA by default)
create_ca() {
    mkdir -p "$CA_DIR"
    read -p "Enter CA Common Name (e.g., MyCA): " CA_CN
    read -p "Enter CA validity in days (e.g., 3650): " CA_DAYS
    openssl genrsa -out "$CA_KEY" 4096
    openssl req -new -x509 -days "$CA_DAYS" -key "$CA_KEY" -out "$CA_CRT" -subj "/CN=$CA_CN"
    touch "$INDEX"
    echo "1000" > "$SERIAL"
    echo "CA created successfully."
}
# Check if CA exists, create if not
if [ ! -f "$CA_KEY" ] || [ ! -f "$CA_CRT" ]; then
    create_ca
fi
# Ask for certificate type
read -p "Enter certificate type (client/server/wifi-client/wifi-server): " CERT_TYPE
if [ "$CERT_TYPE" != "client" ] && [ "$CERT_TYPE" != "server" ] && [ "$CERT_TYPE" != "wifi-client" ] && [ "$CERT_TYPE" != "wifi-server" ]; then
    echo "Invalid type. Must be 'client', 'server', 'wifi-client', or 'wifi-server'."
    exit 1
fi
# Set extension section and suffix based on type
if [ "$CERT_TYPE" = "server" ] || [ "$CERT_TYPE" = "wifi-server" ]; then
    EXT_SECTION="usr_server"
    if [ "$CERT_TYPE" = "wifi-server" ]; then
        SUFFIX="wifi-server"
    else
        SUFFIX="server"
    fi
else
    EXT_SECTION="usr_client"
    if [ "$CERT_TYPE" = "wifi-client" ]; then
        SUFFIX="wifi-client"
    else
        SUFFIX="client"
    fi
fi
# Ask for client/server details (shared for both RSA and EC)
read -p "Enter Common Name (e.g., client1.example.com or server.example.com): " CN
read -p "Enter additional SANs (comma-separated, e.g., example.com,www.example.com,192.168.1.1,2001:db8::1; leave empty if none): " SAN_INPUT
DIR="$CN"
mkdir -p "$DIR"
# Prepare SAN extension, always including CN as the first SAN
SAN_ARRAY=("$CN")
if [ -n "$SAN_INPUT" ]; then
    IFS=',' read -r -a EXTRA_SANS <<< "$SAN_INPUT"
    SAN_ARRAY+=("${EXTRA_SANS[@]}")
fi
SAN_EXT=""
for san in "${SAN_ARRAY[@]}"; do
    san="${san// /}" # Remove spaces
    if [[ $san =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || [[ $san =~ ^[0-9a-fA-F:]+$ ]]; then
        PREFIX="IP:"
    else
        PREFIX="DNS:"
    fi
    if [ -n "$SAN_EXT" ]; then
        SAN_EXT="$SAN_EXT,"
    fi
    SAN_EXT="${SAN_EXT}${PREFIX}${san}"
done
SAN_EXT="subjectAltName = $SAN_EXT"
# Ask for PFX passphrase once (shared)
read -s -p "Enter passphrase for PFX export (leave empty for none): " PFX_PASS
# Function to generate cert for a given key type (RSA or EC)
generate_cert() {
    local KEY_TYPE="$1"
    local KEY_SIZE="$2"
    local CURVE="$3" # Empty for RSA
    local KEY="$DIR/$CN-$KEY_TYPE-$SUFFIX.key"
    local CSR="$DIR/$CN-$KEY_TYPE-$SUFFIX.csr"
    local CRT="$DIR/$CN-$KEY_TYPE-$SUFFIX.crt"
    local PFX="$DIR/$CN-$KEY_TYPE-$SUFFIX.pfx"
    # Generate key based on type
    if [ "$KEY_TYPE" = "rsa" ]; then
        openssl genrsa -out "$KEY" "$KEY_SIZE"
    else
        openssl ecparam -name "$CURVE" -genkey -noout -out "$KEY"
    fi
    # Generate CSR with SAN (always included)
    openssl req -new -key "$KEY" -out "$CSR" -subj "/CN=$CN" -addext "$SAN_EXT"
    # Sign the CSR with CA, applying type-specific extensions
    openssl ca -batch -keyfile "$CA_KEY" -cert "$CA_CRT" -in "$CSR" -out "$CRT" -outdir "$DIR" -extensions "$EXT_SECTION" -config <(cat <<-EOF
[ ca ]
default_ca = local_ca
[ local_ca ]
dir = $CA_DIR
certificate = $CA_CRT
database = $INDEX
private_key = $CA_KEY
serial = $SERIAL
default_days = 365
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
basicConstraints = CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = clientAuth
[ usr_server ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
EOF
)
    # Export to PFX (Windows)
    if [ -n "$PFX_PASS" ]; then
        openssl pkcs12 -export -out "$PFX" -inkey "$KEY" -in "$CRT" -certfile "$CA_CRT" -passout pass:"$PFX_PASS"
    else
        openssl pkcs12 -export -out "$PFX" -inkey "$KEY" -in "$CRT" -certfile "$CA_CRT" -passout pass:
    fi
    # Clean up CSR
    rm "$CSR"
    echo "$KEY_TYPE-$SUFFIX certificate created: $KEY, $CRT, $PFX"
}
# Generate both key types with the selected cert type
generate_cert "rsa" "2048" ""
generate_cert "ec" "" "prime256v1"
# Version 11
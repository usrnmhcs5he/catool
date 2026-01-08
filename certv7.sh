#!/bin/bash

CA_DIR="CA"
CA_KEY="$CA_DIR/ca.key"
CA_CRT="$CA_DIR/ca.crt"
INDEX="$CA_DIR/index.txt"
SERIAL="$CA_DIR/serial"

# Function to create CA if it doesn't exist (RSA by default)
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

# Ask for client details (shared for both RSA and EC)
read -p "Enter Client Common Name (e.g., client1.example.com): " CLIENT_CN
read -p "Enter SANs (comma-separated, e.g., example.com,www.example.com,192.168.1.1,2001:db8::1; leave empty if none): " SAN_INPUT
CLIENT_DIR="$CLIENT_CN"
mkdir -p "$CLIENT_DIR"

# Prepare SAN extension if provided (shared)
if [ -n "$SAN_INPUT" ]; then
    IFS=',' read -r -a SAN_ARRAY <<< "$SAN_INPUT"
    SAN_EXT=""
    for san in "${SAN_ARRAY[@]}"; do
        san="${san// /}"  # Remove spaces
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
fi

# Ask for PFX passphrase once (shared)
read -s -p "Enter passphrase for PFX export (leave empty for none): " PFX_PASS

# Function to generate cert for a given type (RSA or EC)
generate_cert() {
    local TYPE="$1"
    local KEY_SIZE="$2"
    local CURVE="$3"  # Empty for RSA

    local CLIENT_KEY="$CLIENT_DIR/$CLIENT_CN-$TYPE.key"
    local CLIENT_CSR="$CLIENT_DIR/$CLIENT_CN-$TYPE.csr"
    local CLIENT_CRT="$CLIENT_DIR/$CLIENT_CN-$TYPE.crt"
    local CLIENT_PFX="$CLIENT_DIR/$CLIENT_CN-$TYPE.pfx"

    # Generate key based on type
    if [ "$TYPE" = "rsa" ]; then
        openssl genrsa -out "$CLIENT_KEY" "$KEY_SIZE"
    else
        openssl ecparam -name "$CURVE" -genkey -noout -out "$CLIENT_KEY"
    fi

    # Generate CSR with SAN if provided
    if [ -n "$SAN_EXT" ]; then
        openssl req -new -key "$CLIENT_KEY" -out "$CLIENT_CSR" -subj "/CN=$CLIENT_CN" -addext "$SAN_EXT"
    else
        openssl req -new -key "$CLIENT_KEY" -out "$CLIENT_CSR" -subj "/CN=$CLIENT_CN"
    fi

    # Sign the CSR with CA
    openssl ca -batch -keyfile "$CA_KEY" -cert "$CA_CRT" -in "$CLIENT_CSR" -out "$CLIENT_CRT" -outdir "$CLIENT_DIR" -config <(cat <<-EOF
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
x509_extensions = local_ca_ext

[ local_ca_ext ]
basicConstraints = CA:TRUE
EOF
)

    # Export to PFX (Windows)
    if [ -n "$PFX_PASS" ]; then
        openssl pkcs12 -export -out "$CLIENT_PFX" -inkey "$CLIENT_KEY" -in "$CLIENT_CRT" -certfile "$CA_CRT" -passout pass:"$PFX_PASS"
    else
        openssl pkcs12 -export -out "$CLIENT_PFX" -inkey "$CLIENT_KEY" -in "$CLIENT_CRT" -certfile "$CA_CRT" -passout pass:
    fi

    # Clean up CSR
    rm "$CLIENT_CSR"

    echo "$TYPE certificate created: $CLIENT_KEY, $CLIENT_CRT, $CLIENT_PFX"
}

# Generate both types
generate_cert "rsa" "2048" ""
generate_cert "ec" "" "prime256v1"

# Version 7

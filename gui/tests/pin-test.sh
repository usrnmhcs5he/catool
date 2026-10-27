#!/bin/bash
# Run on the Mac with the YubiKey plugged in.
# Question answered: can the OpenSSL pkcs11 engine sign with the CA key in
# slot 9a while the PIN arrives non-interactively (no argv, no env, no file)?
#
# Usage: gui/tests/pin-test.sh [openssl-binary]
#   e.g. gui/tests/pin-test.sh /opt/homebrew/bin/openssl
# Nothing is written outside a private temp dir, which is removed on exit.
# If your CA slot requires touch, touch the key when it blinks.
set -uo pipefail
umask 077

OSSL="${1:-openssl}"
URI_BASE="${CA_KEY_URI:-pkcs11:id=%01}"   # slot 9a, same default as certv16.sh
SLOT="${CA_SLOT:-9a}"

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
say() { printf '\n== %s\n' "$*"; }

say "Environment"
command -v "$OSSL" || { echo "openssl not found: $OSSL"; exit 1; }
"$OSSL" version
"$OSSL" engine pkcs11 -t 2>&1 | head -5
echo "providers:"; "$OSSL" list -providers 2>&1 | head -8
for c in yubico-piv-tool pkcs11-tool ykman; do
  printf '%s: ' "$c"; command -v "$c" || echo "(missing)"
done

say "PIV slot $SLOT info (touch/pin policy, if ykman present)"
if command -v ykman >/dev/null; then ykman piv keys info "$SLOT" 2>&1 || true; fi

say "Reading CA certificate from slot $SLOT"
yubico-piv-tool -a read-certificate -s "$SLOT" > "$T/ca.crt" 2>"$T/err" \
  || { cat "$T/err"; echo "FAIL: cannot read CA cert"; exit 1; }
"$OSSL" x509 -in "$T/ca.crt" -noout -subject -dates

"$OSSL" req -newkey rsa:2048 -nodes -keyout "$T/leaf.key" -subj "/CN=pin-test" \
  -out "$T/leaf.csr" 2>/dev/null

printf 'YubiKey PIN (hidden): '; read -r -s PIN; echo

try() {   # $1 = label; remaining args = openssl x509 options; PIN on fd 3
  local label="$1"; shift
  say "Variant $label"
  local start=$SECONDS
  if "$OSSL" x509 -req -in "$T/leaf.csr" -days 1 -CA "$T/ca.crt" \
       -engine pkcs11 -CAkeyform engine "$@" -out "$T/out-$label.crt" \
       3< <(printf '%s\n' "$PIN") 2>"$T/err-$label"; then
    echo "OK ($((SECONDS-start))s)"
    "$OSSL" verify -CAfile "$T/ca.crt" "$T/out-$label.crt"
  else
    echo "FAIL ($((SECONDS-start))s)"; tail -5 "$T/err-$label"
  fi
}

# A: PIN via -passin fd:3 (engine UI callback receives it)
try A -CAkey "$URI_BASE" -passin fd:3
# B: PIN via PKCS#11 URI pin-source reading the descriptor
try B -CAkey "${URI_BASE};pin-source=file:/dev/fd/3"

say "Done. Report which variants say OK, whether you had to touch the key,"
say "and the openssl/engine lines from the Environment section."
unset PIN

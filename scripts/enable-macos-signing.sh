#!/usr/bin/env bash
# Switch on Developer ID signing + notarisation of the macOS release
# binaries (see docs/code-signing.md). Run it once, after enrolling in the
# Apple Developer Program, with the two files Apple gave you:
#
#   scripts/enable-macos-signing.sh DeveloperID.p12 AuthKey_ABC123XYZ.p8
#
# It asks for the .p12 password and the App Store Connect Issuer ID, reads
# the signing identity from the certificate itself, stores everything in
# the repository's approval-gated "release-signing" environment and sets
# MACOS_SIGNING=true. No secret is ever passed as a command-line argument
# or in the environment: each one goes to `gh` and `openssl` on stdin or a
# file descriptor.
set -euo pipefail

REPO="${PATCHSCOPE_REPO:-RobS96/patchscope}"
ENVIRONMENT=release-signing

die() { printf 'enable-macos-signing: %s\n' "$*" >&2; exit 1; }

[ $# -eq 2 ] || die "usage: $0 <DeveloperID.p12> <AuthKey_KEYID.p8>"
p12=$1
p8=$2
[ -f "$p12" ] || die "no such file: $p12"
[ -f "$p8" ] || die "no such file: $p8"
command -v gh >/dev/null || die "the GitHub CLI (gh) is needed"
gh auth status >/dev/null 2>&1 || die "run 'gh auth login' first"
grep -q 'BEGIN PRIVATE KEY' "$p8" || die "$p8 does not look like an App Store Connect API key (.p8)"

# The Key ID is in Apple's file name: AuthKey_<KEYID>.p8.
key_id=$(basename "$p8" | sed -n 's/^AuthKey_\([A-Z0-9]\{8,\}\)\.p8$/\1/p')
if [ -z "$key_id" ]; then
  read -r -p "App Store Connect Key ID: " key_id
fi
read -r -p "App Store Connect Issuer ID (a UUID, under Users and Access → Integrations): " issuer_id
printf '%s' "$issuer_id" | grep -Eqi '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$' || die "that Issuer ID is not a UUID"
read -r -s -p "Password of $(basename "$p12"): " p12_password
echo

# The identity, exactly as codesign wants it: the certificate's common name.
subject=""
for ossl in /usr/bin/openssl "$(command -v openssl || true)"; do
  [ -x "$ossl" ] || continue
  for legacy in "" "-legacy"; do
    # shellcheck disable=SC2086  # $legacy is deliberately empty or one flag
    if subject=$("$ossl" pkcs12 $legacy -in "$p12" -nokeys -passin fd:3 3<<<"$p12_password" 2>/dev/null \
        | "$ossl" x509 -noout -subject -nameopt multiline 2>/dev/null) && [ -n "$subject" ]; then
      break 2
    fi
  done
done
identity=$(printf '%s\n' "$subject" | sed -n 's/^ *commonName *= *//p' | head -n 1)
[ -n "$identity" ] || die "could not open $p12 with that password"
case "$identity" in
  "Developer ID Application:"*) ;;
  *) die "the certificate is '$identity', not a 'Developer ID Application' certificate" ;;
esac
echo "Signing identity: $identity"
echo "Key ID: $key_id"

set_secret() { # name, then the value on stdin
  gh secret set "$1" --env "$ENVIRONMENT" --repo "$REPO" >/dev/null
  echo "  ✓ $1"
}

echo "Storing the credentials in $REPO → $ENVIRONMENT:"
base64 < "$p12" | tr -d '\n' | set_secret MACOS_CERT_P12_BASE64
printf '%s' "$p12_password" | set_secret MACOS_CERT_PASSWORD
printf '%s' "$identity" | set_secret MACOS_SIGNING_IDENTITY
set_secret APPLE_API_KEY_P8 < "$p8"
printf '%s' "$key_id" | set_secret APPLE_API_KEY_ID
printf '%s' "$issuer_id" | set_secret APPLE_API_ISSUER_ID
unset p12_password
gh variable set MACOS_SIGNING --body true --repo "$REPO" >/dev/null
echo "  ✓ MACOS_SIGNING=true"

echo
echo "Done. The next signed release tag (vX.Y.Z on main) pauses at"
echo "'Sign and notarise (macOS)' until you approve the release-signing"
echo "deployment in the Actions tab; if signing fails, nothing is published."
echo "Now delete the local copies of $(basename "$p12") and $(basename "$p8");"
echo "keep the certificate in your login keychain."

# Code signing

Releases are not yet code-signed. They are **verifiable**: every archive has
a SHA-256 sum and a GitHub build-provenance attestation proving it was
built by this repository's CI from a signed tag (see the
[README](../README.md#1-download)). But on first launch macOS Gatekeeper
and Windows SmartScreen warn about an unknown developer, because those
checks only trust certificates the operating system vendor recognises.

Removing the warnings needs a certificate per platform. Both are paid, and
both identify the signer by legal name.

## macOS: ready to switch on

**What it needs:** an [Apple Developer Program](https://developer.apple.com/programs/)
membership (individual: US$99 / £79 a year). With it, the release
pipeline signs both binaries with a *Developer ID Application* certificate
(hardened runtime, secure timestamp) and has Apple notarise them, so
Gatekeeper opens them without a warning.

The pipeline is already in place (`sign-macos` in
[ci.yml](../.github/workflows/ci.yml)) and skipped until it is switched on.
To switch it on:

1. **Enrol** in the Apple Developer Program as an individual.
2. **Create the certificate:** Xcode → Settings → Accounts → Manage
   Certificates → **+** → *Developer ID Application*. In Keychain Access,
   export it with its private key as a `.p12` with a strong password.
3. **Create a notarisation API key:** App Store Connect → Users and Access
   → Integrations → App Store Connect API → **+**, role *Developer*.
   Download the `AuthKey_XXXX.p8` (it can be downloaded only once) and note
   the Key ID and Issuer ID.
4. **Store the credentials in the `release-signing` environment** (it
   exists already, requires your approval for every run, and only accepts
   `v*` tags). Each value goes in on stdin, never on the command line:

   ```bash
   R=RobS96/patchscope; E=release-signing
   base64 -i DeveloperID.p12 | gh secret set MACOS_CERT_P12_BASE64 --env $E -R $R
   gh secret set MACOS_CERT_PASSWORD   --env $E -R $R      # prompts; paste the .p12 password
   gh secret set MACOS_SIGNING_IDENTITY --env $E -R $R     # e.g. Developer ID Application: Your Name (TEAMID)
   gh secret set APPLE_API_KEY_P8      --env $E -R $R < AuthKey_XXXX.p8
   gh secret set APPLE_API_KEY_ID      --env $E -R $R      # the Key ID
   gh secret set APPLE_API_ISSUER_ID   --env $E -R $R      # the Issuer ID
   gh variable set MACOS_SIGNING --body true -R $R
   ```

   Then delete the local `.p12` and `.p8` copies (keep the certificate in
   your login keychain).
5. **Release as usual** (signed tag `vX.Y.Z` on `main`). The run pauses at
   *Sign and notarise (macOS)* until you approve the `release-signing`
   deployment in the Actions tab. If signing or notarisation fails, nothing
   is published: the release fails closed rather than shipping unsigned.

How the credentials are protected: they exist only in that environment,
only the signing job can read them, and that job runs no code from the
repository or its dependencies. It downloads the already-built archive,
signs inside a temporary keychain it deletes afterwards, and uploads the
result. Turning signing off again is `gh variable set MACOS_SIGNING --body
false`.

## Windows: needs a certificate choice first

For an individual in the UK, as of October 2026:

| Route | Status |
|---|---|
| [Azure Artifact Signing](https://azure.microsoft.com/en-us/products/artifact-signing) (formerly Trusted Signing, about $9.99/month) | Individuals only in the USA and Canada; organisations in the UK qualify. ([Microsoft's options](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options)) |
| [SignPath Foundation](https://signpath.org/terms) (free for open source) | Its terms exclude security vulnerability scanners, which patchscope arguably is. |
| **OV code-signing certificate** from a certificate authority (typically $150–300 a year, per Microsoft's guidance) | Available. The key must sit in a hardware token or the CA's cloud HSM. A cloud-HSM product can sign from GitHub Actions; a USB token means signing on a Windows machine by hand. |

Even signed, a new certificate starts with no SmartScreen reputation, so
early downloads can still show a warning until reputation builds up. That
makes Windows signing worth less per pound than macOS signing. Once a
certificate is chosen, a `sign-windows` job mirrors `sign-macos`: same
environment, same approval, signs `patchscope.exe` and
`patchscope-gui.exe` with `signtool` and a timestamp, and fails closed.

Until then, Windows users see *Windows protected your PC* on first launch
and can choose **More info → Run anyway** after checking the download (SHA-256
or `gh attestation verify`).

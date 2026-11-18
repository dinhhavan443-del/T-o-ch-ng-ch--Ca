# PEDINHIOS CERTIFICATE BUILDER PRO

A local-first browser application for creating and inspecting X.509 certificates and generating Apple `.mobileconfig` profile files.

## Features

- Self-signed Root CA generation.
- Intermediate CA and server certificate issuance from a Root CA held in the current browser session.
- RSA 2048/3072/4096 and ECDSA P-256/P-384 keys.
- SHA-256 / SHA-384 / SHA-512 signature hashes.
- Validity days and CA path length.
- X.509 CRT, CER, PEM and PKCS#8 private-key exports.
- PKCS#10 CSR creation.
- Certificate inspection and signature verification.
- Mobileconfig builder with DNS, VPN profile shell, Wi-Fi, Web Clip, restrictions and optional Root CA certificate payload.
- GitHub Actions deployment to GitHub Pages.

## Requirements

- Node.js 20+ (workflow uses Node 22).
- Modern browser with Web Crypto.
- HTTPS or localhost is required for Web Crypto in most browsers.

## Run locally

```bash
npm install
npm run dev
```

Open the local URL printed by Vite.

## Build

```bash
npm run build
npm run preview
```

## Deploy with GitHub Actions

1. Create a GitHub repository and upload this project.
2. Push the default branch named `main`.
3. In repository Settings → Pages, set **Build and deployment** source to **GitHub Actions**.
4. Open Actions and wait for **Build and deploy PEDINHIOS** to finish.
5. Open the published Pages URL.

## Important technical and security notes

- Web Crypto creates key pairs and signs data. `@peculiar/x509` encodes and parses X.509 certificates.
- The private key is generated in the browser and is never sent to a backend. Exported `.key` files are unencrypted PKCS#8; store them offline and protect them.
- Root CA creation and signing of child certificates are performed in the same active browser session. Reloading the page loses the in-memory CA signing key. Keep a secure backup before closing the page. This starter does not import an existing CA private key.
- RSA-3072 and ECDSA P-256 are approximately 128-bit security. There is no such thing as a 128-bit RSA modulus for a modern CA.
- The profile builder writes an Apple plist XML configuration profile. DNS-over-HTTPS/TLS values must point to a real resolver. VPN fields are a configuration shell and require a compatible real VPN server and authentication details. The generated profile does not create a VPN service.
- Apple payload availability and exact keys vary by iOS version, supervision and MDM enrollment. Review and test profiles on a non-production device before deployment.
- A Root CA installed on iOS does not create AIM, change game memory, alter hitboxes, or bypass app protections.
- P12/PFX export is not included in this initial version. Use a trusted offline PKCS#12 tool if a password-protected bundle is required.
- The `Restrictions` payload included here is intentionally minimal; managed restrictions commonly require MDM/supervision and should be validated against Apple's current payload reference.
- For production use, pin and audit dependencies, host dependencies locally, add CSP/security headers, and consider a hardware-backed or encrypted key store.

## Dependency

- [`@peculiar/x509`](https://peculiarventures.github.io/x509/) for X.509 and CSR operations using Web Crypto.

# PEDINHIOS CERTIFICATE BUILDER PRO

Web app local-first for X.509 certificates and Apple `.mobileconfig` profiles.

## Updates in this build

- DNS payload is **opt-in**: no DNS or VPN profile is selected by default, preventing an accidental resolver/VPN profile from taking over device connectivity.
- Safe DoH example: `https://cloudflare-dns.com/dns-query` (standard Cloudflare resolver; no content-filtering policy selected by this app). DoT example: hostname `one.one.one.one`, address `1.1.1.1`.
- DNS DoH validates HTTPS URL; DoT requires hostname and IP address.
- Mobileconfig download is retained and can be downloaded again.
- ZIP export contains the generated `.mobileconfig`, optional PEM certificate, optional custom-code text file, and README.
- Settings include Vietnamese/English interface labels, developer name, Zalo, support phone and email. Contact fields are user-editable and are only included in ZIP when supplied.
- Custom text supports Plain text, Base64, C++ source and JavaScript source labels. These are exported as text attachments only. iOS configuration profiles do not execute arbitrary C++/JavaScript/Base64.

## Install and build

```bash
npm install
npm run dev
npm run build
```

Node.js 20+ recommended. Deploy `dist/` with GitHub Pages using the workflow in `.github/workflows/deploy.yml`.

## Important iPhone recovery steps

If a DNS profile causes connectivity problems, remove it at **Settings → General → VPN & Device Management**, then set DNS back to Automatic in the relevant Wi-Fi network settings. This project leaves DNS unchecked by default.

An unsigned `.mobileconfig` may show **Not Verified / Chưa xác thực**. That status does not mean the profile is signed or trusted. The builder currently exports an unsigned profile; it does not create an Apple CMS-signed profile. A self-signed Root CA must be installed and then explicitly enabled under **Settings → General → About → Certificate Trust Settings**. Installing a root certificate does not automatically make the profile signed or trusted.

## Security notes

- Private keys are generated in the browser using Web Crypto and are not uploaded to a server.
- Root CA key material remains in memory only; reload loses it. Export and store private keys securely.
- VPN profile fields do not create a VPN server. A real compatible IKEv2/IPSec server, certificate and authentication configuration are required.
- DNS only resolves hostnames; it does not guarantee lower game ping, change game routing, or bypass anti-cheat systems.
- Never install profiles from untrusted sources. Review every payload before installing.

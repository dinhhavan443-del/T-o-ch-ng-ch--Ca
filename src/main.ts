
import "reflect-metadata";
import * as x509 from "@peculiar/x509";
import "./style.css";

type ProfilePayload = "dns" | "vpn" | "wifi" | "webclip" | "restrictions";
type KeyChoice = "RSA-2048" | "RSA-3072" | "RSA-4096" | "P-256" | "P-384";

const $ = <T extends HTMLElement>(s: string) =>
  document.querySelector(s) as T;

const app = $("#app");

let caKeys: CryptoKeyPair | null = null;
let caCert: x509.X509Certificate | null = null;
let caAlgorithm: any = null;
let caName = "";
let lastCertificatePem = "";
let lastPrivateKeyPem = "";

let payloads = new Set<ProfilePayload>([
  "dns",
  "vpn",
  "wifi",
  "webclip"
]);

function esc(s: string) {
  return s.replace(/[&<>"']/g, c => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  }[c]!));
}

function download(
  name: string,
  data: BlobPart,
  type = "application/octet-stream"
) {
  const url = URL.createObjectURL(new Blob([data], { type }));
  const a = document.createElement("a");

  a.href = url;
  a.download = name;
  a.click();

  setTimeout(() => URL.revokeObjectURL(url), 1500);
}

function pemToDer(pem: string): Uint8Array {
  const b64 = pem
    .replace(/-----BEGIN [^-]+-----/g, "")
    .replace(/-----END [^-]+-----/g, "")
    .replace(/\s/g, "");

  const bin = atob(b64);

  return Uint8Array.from(bin, c => c.charCodeAt(0));
}

function pemBlock(
  bytes: ArrayBuffer | Uint8Array,
  label: string
) {
  const b = bytes instanceof Uint8Array
    ? bytes
    : new Uint8Array(bytes);

  let binary = "";

  b.forEach(v => {
    binary += String.fromCharCode(v);
  });

  const base = btoa(binary)
    .match(/.{1,64}/g)
    ?.join("\n") ?? "";

  return `-----BEGIN ${label}-----\n${base}\n-----END ${label}-----\n`;
}

function getVal(id: string) {
  const el = document.getElementById(id) as
    | HTMLInputElement
    | HTMLSelectElement
    | HTMLTextAreaElement;

  if (!el) return "";

  return el.value.trim();
}

function subjectName() {
  const parts = [
    ["CN", getVal("commonName")],
    ["O", getVal("org")],
    ["OU", getVal("unit")],
    ["L", getVal("city")],
    ["ST", getVal("state")],
    ["C", getVal("country")],
    ["E", getVal("email")]
  ]
    .filter(x => x[1])
    .map(([k, v]) =>
      `${k}=${String(v).replace(/[,+"\\<>;]/g, " ")}`
    );

  if (!parts.some(x => x.startsWith("CN="))) {
    throw new Error("Common Name là bắt buộc.");
  }

  const description = getVal("description");

  if (description) {
    parts.push(
      `2.5.4.13=${description.replace(/[,+"\\<>;]/g, " ")}`
    );
  }

  const country = getVal("country");

  if (country && !/^[A-Za-z]{2}$/.test(country)) {
    throw new Error(
      "Country Code phải gồm đúng 2 chữ cái, ví dụ VN."
    );
  }

  return parts.join(", ");
}

function algorithmFor(choice: KeyChoice, hash: string) {
  if (choice.startsWith("RSA")) {
    const bits = Number(choice.split("-")[1]);

    return {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: bits,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash
    };
  }

  return {
    name: "ECDSA",
    namedCurve: choice,
    hash
  };
}

function validity() {
  const days = Number(getVal("days"));

  if (
    !Number.isInteger(days) ||
    days < 1 ||
    days > 36500
  ) {
    throw new Error(
      "Validity phải từ 1 đến 36500 ngày."
    );
  }

  const start = new Date(Date.now() - 5 * 60 * 1000);

  return {
    notBefore: start,
    notAfter: new Date(
      start.getTime() + days * 86400000
    )
  };
}

function pathLimit(): number | undefined {
  const v = getVal("pathLength");

  if (v === "unlimited") {
    return undefined;
  }

  const n = Number(v);

  if (
    !Number.isInteger(n) ||
    n < 0 ||
    n > 20
  ) {
    throw new Error(
      "Path length phải từ 0 đến 20 hoặc Unlimited."
    );
  }

  return n;
}

function keyStrengthLabel(choice: string) {
  return choice === "RSA-2048"
    ? "~112-bit"
    : choice === "RSA-3072" || choice === "P-256"
      ? "~128-bit"
      : choice === "P-384"
        ? "~192-bit"
        : "~150-bit";
}

async function extensionsForCA(
  path: number | undefined,
  keys: CryptoKeyPair
) {
  return [
    new x509.BasicConstraintsExtension(true, path, true),

    new x509.KeyUsagesExtension(
      x509.KeyUsageFlags.keyCertSign |
      x509.KeyUsageFlags.cRLSign,
      true
    ),

    await x509.SubjectKeyIdentifierExtension.create(
      keys.publicKey
    )
  ];
}

function setStatus(msg: string, good = false) {
  const el = $("#status");

  el.textContent = msg;
  el.className = good ? "status good" : "status";
}

function setOutput(
  pem: string,
  key: string,
  title: string
) {
  lastCertificatePem = pem;
  lastPrivateKeyPem = key;

  $("#resultTitle").textContent = title;

  $("#resultPreview").textContent =
    pem.slice(0, 900) +
    (pem.length > 900 ? "\n…" : "");

  $("#result").classList.remove("hidden");

  $("#downloadCrt").onclick = () => {
    download(
      "PEDINHIOS_CERTIFICATE.crt",
      pem,
      "application/x-x509-ca-cert"
    );
  };

  $("#downloadCer").onclick = () => {
    download(
      "PEDINHIOS_CERTIFICATE.cer",
      pem,
      "application/pkix-cert"
    );
  };

  $("#downloadPem").onclick = () => {
    download(
      "PEDINHIOS_CERTIFICATE.pem",
      pem,
      "application/x-pem-file"
    );
  };

  $("#downloadKey").onclick = () => {
    download(
      "PEDINHIOS_PRIVATE_KEY.key",
      key,
      "application/pkcs8"
    );
  };

  $("#copyPem").onclick = async () => {
    await navigator.clipboard.writeText(pem);
    setStatus("Đã sao chép PEM.", true);
  };
}

async function createRoot() {
  const name = subjectName();
  const { notBefore, notAfter } = validity();

  const choice = getVal("keyAlgorithm") as KeyChoice;
  const hash = getVal("hash");

  const alg = algorithmFor(choice, hash) as any;

  const keys = await crypto.subtle.generateKey(
    alg,
    true,
    ["sign", "verify"]
  ) as CryptoKeyPair;

  const cert =
    await x509.X509CertificateGenerator.createSelfSigned({
      name,
      notBefore,
      notAfter,
      keys,
      signingAlgorithm: alg,
      extensions: await extensionsForCA(
        pathLimit(),
        keys
      )
    });

  const keyDer = await crypto.subtle.exportKey(
    "pkcs8",
    keys.privateKey
  );

  const keyPem = pemBlock(
    keyDer,
    "PRIVATE KEY"
  );

  caKeys = keys;
  caCert = cert;
  caAlgorithm = alg;
  caName = name;

  const pem = cert.toString("pem");

  setOutput(
    pem,
    keyPem,
    "ROOT CA ĐÃ TẠO"
  );

  setStatus(
    `Tạo Root CA thành công · ${choice} · ${hash} · ${keyStrengthLabel(choice)} · ${notAfter.toLocaleDateString("vi-VN")}`,
    true
  );
}

async function createIssued() {
  if (!caKeys || !caCert || !caAlgorithm) {
    throw new Error(
      "Hãy tạo Root CA trong phiên hiện tại trước."
    );
  }

  const name = subjectName();
  const { notBefore, notAfter } = validity();

  const choice = getVal("keyAlgorithm") as KeyChoice;
  const hash = getVal("hash");

  const alg = algorithmFor(choice, hash) as any;

  const keys = await crypto.subtle.generateKey(
    alg,
    true,
    ["sign", "verify"]
  ) as CryptoKeyPair;

  const isCA = getVal("certType") === "intermediate";

  const exts: any[] = [
    new x509.BasicConstraintsExtension(
      isCA,
      isCA ? pathLimit() : undefined,
      true
    ),

    new x509.KeyUsagesExtension(
      isCA
        ? (
          x509.KeyUsageFlags.keyCertSign |
          x509.KeyUsageFlags.cRLSign
        )
        : (
          x509.KeyUsageFlags.digitalSignature |
          x509.KeyUsageFlags.keyEncipherment
        ),
      true
    ),

    await x509.SubjectKeyIdentifierExtension.create(
      keys.publicKey
    ),

    await x509.AuthorityKeyIdentifierExtension.create(
      caCert
    )
  ];

  if (!isCA) {
    exts.push(
      new x509.ExtendedKeyUsageExtension([
        x509.ExtendedKeyUsage.serverAuth
      ])
    );

    const sans = getVal("sanDNS")
      .split(",")
      .map(v => v.trim())
      .filter(Boolean);

    /*
     * FIX TYPESCRIPT TS2769:
     * Khai báo JsonGeneralName[] để TypeScript
     * giữ đúng kiểu GeneralNameType cho từng SAN.
     */
    const sanNames: x509.JsonGeneralName[] =
      sans.map(
        (value): x509.JsonGeneralName => ({
          type: x509.DNS,
          value
        })
      );

    if (sanNames.length > 0) {
      exts.push(
        new x509.SubjectAlternativeNameExtension(
          sanNames
        )
      );
    }
  }

  const cert = await x509.X509CertificateGenerator.create({
    subject: name,
    issuer: caCert.subject,
    notBefore,
    notAfter,
    publicKey: keys.publicKey,
    signingKey: caKeys.privateKey,
    signingAlgorithm: caAlgorithm as any,
    extensions: exts
  });

  const keyPem = pemBlock(
    await crypto.subtle.exportKey(
      "pkcs8",
      keys.privateKey
    ),
    "PRIVATE KEY"
  );

  const pem = cert.toString("pem");

  setOutput(
    pem,
    keyPem,
    isCA
      ? "INTERMEDIATE CA ĐÃ TẠO"
      : "SERVER CERTIFICATE ĐÃ TẠO"
  );

  setStatus(
    "Đã ký chứng chỉ bằng Root CA hiện tại. Hãy giữ an toàn khóa CA.",
    true
  );
}

async function createCSR() {
  const name = subjectName();

  const choice = getVal("keyAlgorithm") as KeyChoice;
  const hash = getVal("hash");

  const alg = algorithmFor(choice, hash) as any;

  const keys = await crypto.subtle.generateKey(
    alg,
    true,
    ["sign", "verify"]
  ) as CryptoKeyPair;

  const csr =
    await x509.Pkcs10CertificateRequestGenerator.create({
      name,
      keys,
      signingAlgorithm: alg
    });

  const keyPem = pemBlock(
    await crypto.subtle.exportKey(
      "pkcs8",
      keys.privateKey
    ),
    "PRIVATE KEY"
  );

  download(
    "PEDINHIOS_REQUEST.csr",
    csr.toString("pem"),
    "application/pkcs10"
  );

  download(
    "PEDINHIOS_CSR_PRIVATE_KEY.key",
    keyPem,
    "application/pkcs8"
  );

  setStatus(
    "Đã tạo CSR và khóa riêng tương ứng.",
    true
  );
}

async function inspectCertificate() {
  const file = (
    $("#certFile") as HTMLInputElement
  ).files?.[0];

  if (!file) {
    throw new Error(
      "Chọn tệp CRT, CER hoặc PEM."
    );
  }

  const text = await file.text();
  const cert = new x509.X509Certificate(text);

  const info = [
    `Subject: ${cert.subject}`,
    `Issuer: ${cert.issuer}`,
    `Serial: ${cert.serialNumber}`,
    `Not before: ${cert.notBefore.toISOString()}`,
    `Not after: ${cert.notAfter.toISOString()}`,
    `Public key: ${cert.publicKey.algorithm.name}`,
    `Self-signed: ${await cert.isSelfSigned()}`,
    "Signature: cần chứng chỉ issuer để xác minh đầy đủ."
  ].join("\n");

  $("#inspectOutput").textContent = info;

  $("#inspectPanel").classList.remove("hidden");

  setStatus("Đã đọc chứng chỉ.", true);
}

function uuid() {
  return crypto.randomUUID().toUpperCase();
}

function payload(
  type: string,
  displayName: string,
  content: any
) {
  return {
    PayloadType: type,
    PayloadVersion: 1,
    PayloadIdentifier:
      `com.pedinhios.profile.${type.toLowerCase()}.${uuid().toLowerCase()}`,
    PayloadUUID: uuid(),
    PayloadDisplayName: displayName,
    ...content
  };
}

function buildMobileconfig() {
  const items: any[] = [];

  if (payloads.has("dns")) {
    const method = getVal("dnsMethod");

    const dns = method === "DoH"
      ? {
        DNSProtocol: "HTTPS",
        ServerURL: getVal("dnsServer")
      }
      : {
        DNSProtocol: "TLS",
        ServerName: getVal("dnsServer"),
        ServerAddress:
          getVal("dnsAddress") ||
          getVal("dnsServer")
      };

    items.push(
      payload(
        "com.apple.dnsSettings.managed",
        "PEDINHIOS DNS",
        {
          DNSSettings: dns,
          OnDemandRules: []
        }
      )
    );
  }

  if (payloads.has("vpn")) {
    const server = getVal("vpnServer");
    const proto = getVal("vpnType");

    if (!server) {
      throw new Error(
        "Nhập VPN server trước khi xuất profile."
      );
    }

    const config: any = proto === "IKEv2"
      ? {
        IKEv2: {
          RemoteAddress: server,
          RemoteIdentifier:
            getVal("vpnRemoteId") || server,
          AuthenticationMethod: "None",
          ...(getVal("vpnLocalId")
            ? {
              LocalIdentifier: getVal("vpnLocalId")
            }
            : {})
        }
      }
      : {
        IPSec: {
          RemoteAddress: server,
          RemoteIdentifier:
            getVal("vpnRemoteId") || server,
          AuthenticationMethod: "None",
          LocalIdentifier:
            getVal("vpnLocalId") || "pedinhios"
        }
      };

    items.push(
      payload(
        "com.apple.vpn.managed",
        "PEDINHIOS VPN",
        {
          UserDefinedName: "PEDINHIOS VPN",
          VPNType: proto,
          ...config,
          OnDemandEnabled: 0
        }
      )
    );
  }

  if (payloads.has("wifi")) {
    const ssid = getVal("wifiSSID");

    if (!ssid) {
      throw new Error(
        "Nhập Wi-Fi SSID trước khi xuất profile."
      );
    }

    items.push(
      payload(
        "com.apple.wifi.managed",
        "PEDINHIOS Wi-Fi",
        {
          SSID_STR: ssid,
          AutoJoin: true,
          EncryptionType: getVal("wifiSecurity"),
          ...(getVal("wifiPassword")
            ? { Password: getVal("wifiPassword") }
            : {})
        }
      )
    );
  }

  if (payloads.has("webclip")) {
    const url = getVal("clipURL");

    if (!/^https?:\/\//i.test(url)) {
      throw new Error(
        "Web Clip URL phải bắt đầu bằng https:// hoặc http://."
      );
    }

    items.push(
      payload(
        "com.apple.webClip.managed",
        "PEDINHIOS Web Clip",
        {
          Label: getVal("clipLabel"),
          URL: url,
          IsRemovable: true,
          FullScreen: false
        }
      )
    );
  }

  if (payloads.has("restrictions")) {
    items.push(
      payload(
        "com.apple.applicationaccess",
        "PEDINHIOS Restrictions",
        {
          allowAppInstallation: true,
          allowSafari: true
        }
      )
    );
  }

  const certText =
    getVal("profileCert") || lastCertificatePem;

  if (certText) {
    try {
      const cert = new x509.X509Certificate(certText);
      const der = cert.rawData;

      let binary = "";

      new Uint8Array(der).forEach(v => {
        binary += String.fromCharCode(v);
      });

      items.push(
        payload(
          "com.apple.security.root",
          "PEDINHIOS Root CA",
          {
            PayloadContent: {
              __data: btoa(binary)
            }
          }
        )
      );
    } catch {
      throw new Error(
        "Chứng chỉ nhúng không hợp lệ. Dán PEM hợp lệ hoặc tạo CA trước."
      );
    }
  }

  if (items.length === 0) {
    throw new Error(
      "Hãy chọn ít nhất một payload."
    );
  }

  const profile = {
    PayloadContent: items,
    PayloadDescription:
      getVal("profileDescription") ||
      "PEDINHIOS iOS Configuration Profile",

    PayloadDisplayName:
      getVal("profileName") ||
      "PEDINHIOS CONFIGURATION",

    PayloadIdentifier:
      `com.pedinhios.mobileconfig.${uuid().toLowerCase()}`,

    PayloadOrganization:
      getVal("profileOrg") || "PEDINHIOS",

    PayloadRemovalDisallowed: false,
    PayloadType: "Configuration",
    PayloadUUID: uuid(),
    PayloadVersion: 1
  };

  const xml =
    `<?xml version="1.0" encoding="UTF-8"?>\n` +
    `<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" ` +
    `"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n` +
    `<plist version="1.0"><dict>${dictPlist(profile)}</dict></plist>`;

  download(
    "PEDINHIOS_CONFIGURATION.mobileconfig",
    xml,
    "application/x-apple-aspen-config"
  );

  setStatus(
    `Đã xuất Mobileconfig với ${items.length} payload. Một số payload yêu cầu máy chủ VPN/DNS hoặc MDM tương thích.`,
    true
  );
}

function toPlist(v: any): string {
  if (v === null || v === undefined) {
    return "<string></string>";
  }

  if (typeof v === "string") {
    return `<string>${esc(v)}</string>`;
  }

  if (typeof v === "boolean") {
    return `<${v ? "true" : "false"}/>`;
  }

  if (typeof v === "number") {
    return `<integer>${v}</integer>`;
  }

  if (Array.isArray(v)) {
    return `<array>${v.map(valuePlist).join("")}</array>`;
  }

  return "<string></string>";
}

function dictPlist(obj: any): string {
  return Object.entries(obj)
    .map(
      ([k, v]) =>
        `<key>${esc(k)}</key>${valuePlist(v)}`
    )
    .join("");
}

function valuePlist(v: any): string {
  if (
    v &&
    typeof v === "object" &&
    typeof v.__data === "string"
  ) {
    return `<data>${v.__data}</data>`;
  }

  if (Array.isArray(v)) {
    return `<array>${v.map(valuePlist).join("")}</array>`;
  }

  if (v && typeof v === "object") {
    return `<dict>${dictPlist(v)}</dict>`;
  }

  return toPlist(v);
}

function render() {
  app.innerHTML = `
<header class="top">
  <div class="brandmark">P<span>·</span></div>
  <div>
    <div class="brand">PEDINHIOS</div>
    <div class="subbrand">CERTIFICATE BUILDER <b>PRO</b></div>
  </div>
  <div class="secure"><i></i> LOCAL CRYPTO</div>
</header>

<main>
<section class="hero">
  <div class="eyebrow">X.509 • PKI • APPLE CONFIGURATION</div>
  <h1>Build trust.<br><span>Configure devices.</span></h1>
  <p>Tạo chứng chỉ X.509 và cấu hình iOS ngay trên thiết bị. Khóa riêng không được tải lên máy chủ.</p>
  <div class="chips">
    <span>WEB CRYPTO</span>
    <span>X.509</span>
    <span>MOBILECONFIG</span>
  </div>
</section>

<div class="tabs">
  <button class="tab active" data-tab="cert">01&nbsp; CERTIFICATE</button>
  <button class="tab" data-tab="mobile">02&nbsp; MOBILECONFIG</button>
  <button class="tab" data-tab="viewer">03&nbsp; VIEWER</button>
</div>

<section id="cert" class="pane active">
<div class="sectionhead">
  <div><small>IDENTITY</small><h2>Certificate details</h2></div>
  <span class="step">01 / 03</span>
</div>

<div class="grid">
<label>Common Name *
  <input id="commonName" placeholder="PEDINHIOS ROOT CA" value="PEDINHIOS ROOT CA">
</label>

<label>Organisation
  <input id="org" placeholder="PEDINHIOS">
</label>

<label>Organisational Unit
  <input id="unit" placeholder="Security">
</label>

<label>City / Locality
  <input id="city" placeholder="Ha Noi">
</label>

<label>State / Province
  <input id="state" placeholder="Ha Noi">
</label>

<label>Country Code
  <input id="country" maxlength="2" placeholder="VN" value="VN">
</label>

<label>Email
  <input id="email" type="email" placeholder="admin@example.com">
</label>

<label>Certificate description
  <input id="description" placeholder="Private test certificate">
</label>

<label class="wide">Subject Alternative DNS names
  <input id="sanDNS" placeholder="example.com, www.example.com (dành cho Server Certificate)">
</label>
</div>

<div class="sectionhead sub">
  <div><small>CRYPTOGRAPHY</small><h2>Key & validity</h2></div>
</div>

<div class="grid">
<label>Certificate type
<select id="certType">
  <option value="root">Root CA (self-signed)</option>
  <option value="intermediate">Intermediate CA (signed by current Root)</option>
  <option value="server">Server certificate (signed by current Root)</option>
</select>
</label>

<label>Key algorithm
<select id="keyAlgorithm">
  <option>RSA-2048</option>
  <option selected>RSA-3072</option>
  <option>RSA-4096</option>
  <option>P-256</option>
  <option>P-384</option>
</select>
</label>

<label>Signature hash
<select id="hash">
  <option>SHA-256</option>
  <option>SHA-384</option>
  <option>SHA-512</option>
</select>
</label>

<label>Security strength
  <input id="strength" value="~128-bit security" readonly>
</label>

<label>Valid for (days)
  <input id="days" type="number" min="1" max="36500" value="3650">
</label>

<label>Path length limit
<select id="pathLength">
  <option value="unlimited">Unlimited</option>
  <option value="0">0 – no subordinate CA</option>
  <option value="1">1</option>
  <option value="2">2</option>
  <option value="3">3</option>
</select>
</label>
</div>

<div class="note">
  <b>Key strength:</b> RSA-3072 ≈ 128-bit; P-256 ≈ 128-bit; P-384 ≈ 192-bit. “128-bit strength” là mức bảo mật tương đương, không phải khóa RSA dài 128 bit.
</div>

<div class="actions">
  <button id="buildCert" class="primary">✦ GENERATE CERTIFICATE</button>
  <button id="buildCSR" class="secondary">CREATE CSR</button>
</div>

<div id="status" class="status">
  Sẵn sàng. Tất cả thao tác mật mã chạy cục bộ.
</div>

<div id="result" class="result hidden">
  <div class="resulthead">
    <div><small>GENERATED OUTPUT</small><h3 id="resultTitle">Certificate</h3></div>
    <span class="live">READY</span>
  </div>

  <pre id="resultPreview"></pre>

  <div class="downloads">
    <button id="downloadCrt">.CRT</button>
    <button id="downloadCer">.CER</button>
    <button id="downloadPem">.PEM</button>
    <button id="downloadKey">.KEY</button>
    <button id="copyPem">COPY PEM</button>
  </div>

  <p class="warning">
    ⚠ Khóa riêng tải xuống không được bảo vệ bằng mật khẩu. Cất giữ ngoại tuyến và không chia sẻ.
  </p>
</div>
</section>

<section id="mobile" class="pane">
<div class="sectionhead">
  <div><small>APPLE CONFIGURATION PROFILE</small><h2>Mobileconfig builder</h2></div>
  <span class="step">02 / 03</span>
</div>

<div class="grid">
<label>Profile name
  <input id="profileName" value="PEDINHIOS CONFIGURATION">
</label>

<label>Organisation
  <input id="profileOrg" value="PEDINHIOS">
</label>

<label class="wide">Description
  <input id="profileDescription" value="Custom iOS configuration profile">
</label>
</div>

<h3 class="minor">Payload selection</h3>

<div class="payloads">
<label class="check">
  <input type="checkbox" data-payload="dns" checked>
  <span><b>DNS Settings</b><small>DNS-over-HTTPS / DNS-over-TLS</small></span>
</label>

<label class="check">
  <input type="checkbox" data-payload="vpn" checked>
  <span><b>VPN</b><small>IKEv2 / IPSec profile shell</small></span>
</label>

<label class="check">
  <input type="checkbox" data-payload="wifi" checked>
  <span><b>Wi-Fi</b><small>SSID and security settings</small></span>
</label>

<label class="check">
  <input type="checkbox" data-payload="webclip" checked>
  <span><b>Web Clip</b><small>Home-screen web shortcut</small></span>
</label>

<label class="check">
  <input type="checkbox" data-payload="restrictions">
  <span><b>Restrictions</b><small>Basic managed restrictions payload</small></span>
</label>
</div>

<div class="sectionhead sub">
  <div><small>NETWORK PAYLOADS</small><h2>DNS & VPN</h2></div>
</div>

<div class="grid">
<label>DNS method
<select id="dnsMethod">
  <option>DoH</option>
  <option>DoT</option>
</select>
</label>

<label>DNS server / hostname
  <input id="dnsServer" value="https://dns.example/dns-query">
</label>

<label>DNS address (DoT)
  <input id="dnsAddress" placeholder="1.1.1.1">
</label>

<label>VPN type
<select id="vpnType">
  <option>IKEv2</option>
  <option>IPSec</option>
</select>
</label>

<label>VPN server address
  <input id="vpnServer" placeholder="vpn.example.com">
</label>

<label>VPN remote identifier
  <input id="vpnRemoteId" placeholder="vpn.example.com">
</label>

<label>VPN local identifier
  <input id="vpnLocalId" placeholder="device-id">
</label>
</div>

<div class="sectionhead sub">
  <div><small>DEVICE PAYLOADS</small><h2>Wi-Fi & Web Clip</h2></div>
</div>

<div class="grid">
<label>Wi-Fi SSID
  <input id="wifiSSID" placeholder="Your Wi-Fi name">
</label>

<label>Wi-Fi security
<select id="wifiSecurity">
  <option>WPA</option>
  <option>WEP</option>
  <option>Any</option>
</select>
</label>

<label>Wi-Fi password
  <input id="wifiPassword" type="password" placeholder="Optional">
</label>

<label>Web Clip label
  <input id="clipLabel" value="PEDINHIOS">
</label>

<label class="wide">Web Clip URL
  <input id="clipURL" value="https://example.com">
</label>

<label class="wide">Root CA PEM (optional)
  <textarea id="profileCert" rows="4" placeholder="Dán nội dung PEM hoặc tạo Root CA trước để nhúng chứng chỉ hiện tại."></textarea>
</label>
</div>

<div class="note">
  VPN payload cần máy chủ VPN thật và cấu hình xác thực tương ứng. Payload được xuất ở dạng khung cấu hình; không tự tạo máy chủ VPN. Một số payload yêu cầu MDM hoặc quyền quản trị.
</div>

<div class="actions">
  <button id="buildMobile" class="primary">⇩ BUILD MOBILECONFIG</button>
</div>
</section>

<section id="viewer" class="pane">
<div class="sectionhead">
  <div><small>INSPECT & VERIFY</small><h2>Certificate viewer</h2></div>
  <span class="step">03 / 03</span>
</div>

<label class="filebox">
  Choose CRT / CER / PEM
  <input id="certFile" type="file" accept=".crt,.cer,.pem,.txt">
</label>

<div class="actions">
  <button id="inspect" class="primary">INSPECT CERTIFICATE</button>
</div>

<div id="inspectPanel" class="result hidden">
  <h3>Certificate information</h3>
  <pre id="inspectOutput"></pre>
</div>
</section>

<footer>
  <span>PEDINHIOS CERTIFICATE BUILDER PRO</span>
  <span>LOCAL-FIRST · X.509 TOOLKIT</span>
</footer>
</main>
`;

  document.querySelectorAll<HTMLButtonElement>(".tab")
    .forEach(b => {
      b.addEventListener("click", () => {
        document.querySelectorAll(".tab")
          .forEach(x => x.classList.remove("active"));

        b.classList.add("active");

        document.querySelectorAll(".pane")
          .forEach(x => x.classList.remove("active"));

        $("#" + b.dataset.tab).classList.add("active");
      });
    });

  $("#buildCert").addEventListener("click", async () => {
    const b = $("#buildCert") as HTMLButtonElement;

    b.disabled = true;
    b.textContent = "GENERATING…";

    try {
      if (getVal("certType") === "root") {
        await createRoot();
      } else {
        await createIssued();
      }
    } catch (e) {
      setStatus(
        e instanceof Error ? e.message : String(e)
      );
    } finally {
      b.disabled = false;
      b.textContent = "✦ GENERATE CERTIFICATE";
    }
  });

  $("#buildCSR").addEventListener("click", async () => {
    try {
      await createCSR();
    } catch (e) {
      setStatus(
        e instanceof Error ? e.message : String(e)
      );
    }
  });

  $("#buildMobile").addEventListener("click", () => {
    try {
      buildMobileconfig();
    } catch (e) {
      setStatus(
        e instanceof Error ? e.message : String(e)
      );
    }
  });

  $("#inspect").addEventListener("click", async () => {
    try {
      await inspectCertificate();
    } catch (e) {
      setStatus(
        e instanceof Error ? e.message : String(e)
      );
    }
  });

  document.querySelectorAll<HTMLInputElement>(
    "[data-payload]"
  ).forEach(c => {
    c.addEventListener("change", () => {
      const p = c.dataset.payload as ProfilePayload;

      if (c.checked) {
        payloads.add(p);
      } else {
        payloads.delete(p);
      }
    });
  });

  $("#keyAlgorithm").addEventListener("change", () => {
    ($("#strength") as HTMLInputElement).value =
      keyStrengthLabel(getVal("keyAlgorithm")) +
      " security";
  });
}

if (!window.crypto?.subtle) {
  app.innerHTML =
    "<p class='fatal'>Trình duyệt không hỗ trợ Web Crypto. Hãy dùng HTTPS hoặc localhost.</p>";
} else {
  render();
}


import "reflect-metadata";
import * as x509 from "@peculiar/x509";
import JSZip from "jszip";
import "./style.css";

type ProfilePayload = "dns" | "vpn" | "wifi" | "webclip" | "restrictions";
type KeyChoice = "RSA-2048" | "RSA-3072" | "RSA-4096" | "P-256" | "P-384";

let lastMobileconfig = "";

const $ = <T extends HTMLElement>(s: string) =>
  document.querySelector(s) as T;

const app = $("#app");

let caKeys: CryptoKeyPair | null = null;
let caCert: x509.X509Certificate | null = null;
let caAlgorithm: any = null;
let caName = "";
let lastCertificatePem = "";
let lastPrivateKeyPem = "";

let payloads = new Set<ProfilePayload>();

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
  const blob = new Blob([data], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.rel = "noopener";
  a.style.display = "none";
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 10000);
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
    // `as const` prevents TypeScript from widening "dns" to `string`.
    // @peculiar/x509 expects GeneralNameType, whose DNS value is "dns".
    const sanNames: x509.JsonGeneralName[] = sans.map(value => ({
      type: "dns" as const,
      value
    }));

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
    const host = getVal("dnsServer");
    if (method === "DoH") {
      let parsed: URL;
      try { parsed = new URL(host); } catch { throw new Error("DoH cần URL HTTPS hợp lệ, ví dụ https://cloudflare-dns.com/dns-query."); }
      if (parsed.protocol !== "https:") throw new Error("DoH bắt buộc dùng HTTPS.");
    } else {
      if (!host || !getVal("dnsAddress")) throw new Error("DoT cần hostname và địa chỉ IP DNS.");
      if (!/^(?:\d{1,3}\.){3}\d{1,3}$/.test(getVal("dnsAddress")) && !getVal("dnsAddress").includes(":")) throw new Error("Địa chỉ DoT phải là IPv4 hoặc IPv6.");
    }

    const dns = method === "DoH"
      ? { DNSProtocol: "HTTPS", ServerURL: host }
      : { DNSProtocol: "TLS", ServerName: host, ServerAddress: getVal("dnsAddress") };

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

  lastMobileconfig = xml;
  const downloadPanel = document.getElementById("mobileDownloads");
  if (downloadPanel) downloadPanel.classList.remove("hidden");
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

async function exportProjectZip() {
  if (!lastMobileconfig) throw new Error("Hãy tạo Mobileconfig trước khi xuất ZIP.");
  const zip = new JSZip();
  zip.file("PEDINHIOS_CONFIGURATION.mobileconfig", lastMobileconfig);
  const cert = getVal("profileCert") || lastCertificatePem;
  if (cert) zip.file("certificate/root-ca.pem", cert);
  const code = getVal("customCode");
  const mode = getVal("codeFormat");
  if (code) {
    let output = code;
    if (mode === "Base64") output = btoa(unescape(encodeURIComponent(code)));
    zip.file(`custom-code/custom-code-${mode.toLowerCase().replace(/[^a-z0-9]+/g,"-")}.txt`, output);
    zip.file("custom-code/README.txt", "Custom code is exported as a text attachment only. iOS configuration profiles do not execute C++, JavaScript, shell scripts or Base64 content. Review code before using it.");
  }
  const contact = [
    `Developer: ${getVal("creatorName") || "PEDINHIOS"}`,
    getVal("creatorZalo") ? `Zalo: ${getVal("creatorZalo")}` : "",
    getVal("creatorPhone") ? `Phone: ${getVal("creatorPhone")}` : "",
    getVal("creatorEmail") ? `Email: ${getVal("creatorEmail")}` : ""
  ].filter(Boolean).join("\n");
  zip.file("README.txt", `PEDINHIOS export bundle\n${contact}\n\nInstall the .mobileconfig only if you trust its contents. DNS payload is optional. If network access fails, remove the profile in iOS Settings > General > VPN & Device Management and return DNS to Automatic. A self-signed Root CA must be explicitly trusted in Certificate Trust Settings. An unsigned profile may show as not verified. Custom code is attached as text only and is not executed by iOS.`);
  const blob = await zip.generateAsync({type:"blob", compression:"DEFLATE", compressionOptions:{level:6}});
  download("PEDINHIOS-EXPORT.zip", blob, "application/zip");
  setStatus("Đã tạo gói ZIP Mobileconfig và tệp đính kèm.", true);
}

function updateCodePreview() {
  const input = getVal("customCode");
  const mode = getVal("codeFormat");
  const output = mode === "Base64" ? btoa(unescape(encodeURIComponent(input))) : input;
  const preview = document.getElementById("codePreview");
  if (preview) preview.textContent = output || "Bản xem trước sẽ hiển thị tại đây.";
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

function applyUiLanguage(lang: string) {
  const vi: Record<string,string> = {
    commonName:"Tên chung *", org:"Tổ chức", unit:"Đơn vị", city:"Thành phố", state:"Tỉnh / Bang", country:"Mã quốc gia", email:"Email", description:"Mô tả chứng chỉ", sanDNS:"Tên DNS thay thế (SAN)", certType:"Loại chứng chỉ", keyAlgorithm:"Thuật toán khóa", hash:"Hàm băm chữ ký", strength:"Mức bảo mật", days:"Thời hạn (ngày)", pathLength:"Giới hạn Path Length", profileName:"Tên cấu hình", profileOrg:"Tổ chức", profileDescription:"Mô tả", dnsMethod:"Phương thức DNS", dnsServer:"Máy chủ DNS / hostname", dnsAddress:"Địa chỉ DNS (DoT)", vpnType:"Loại VPN", vpnServer:"Địa chỉ máy chủ VPN", vpnRemoteId:"Mã định danh VPN từ xa", vpnLocalId:"Mã định danh VPN cục bộ", wifiSSID:"Tên Wi-Fi (SSID)", wifiSecurity:"Bảo mật Wi-Fi", wifiPassword:"Mật khẩu Wi-Fi", clipLabel:"Tên Web Clip", clipURL:"Địa chỉ Web Clip", profileCert:"Root CA PEM / CRT (không bắt buộc)", customCode:"Mã / String đính kèm (không thực thi trên iPhone)", appLanguage:"Ngôn ngữ giao diện", creatorName:"Người phát triển", creatorZalo:"Zalo người phát triển", creatorPhone:"Số điện thoại hỗ trợ", creatorEmail:"Email hỗ trợ"
  };
  const en: Record<string,string> = {
    commonName:"Common Name *", org:"Organisation", unit:"Organisational Unit", city:"City / Locality", state:"State / Province", country:"Country Code", email:"Email", description:"Certificate description", sanDNS:"Subject Alternative DNS names", certType:"Certificate type", keyAlgorithm:"Key algorithm", hash:"Signature hash", strength:"Security strength", days:"Valid for (days)", pathLength:"Path length limit", profileName:"Profile name", profileOrg:"Organisation", profileDescription:"Description", dnsMethod:"DNS method", dnsServer:"DNS server / hostname", dnsAddress:"DNS address (DoT)", vpnType:"VPN type", vpnServer:"VPN server address", vpnRemoteId:"VPN remote identifier", vpnLocalId:"VPN local identifier", wifiSSID:"Wi-Fi SSID", wifiSecurity:"Wi-Fi security", wifiPassword:"Wi-Fi password", clipLabel:"Web Clip label", clipURL:"Web Clip URL", profileCert:"Root CA PEM / CRT (optional)", customCode:"Code / String attachment (not executed on iPhone)", appLanguage:"Interface language", creatorName:"Developer", creatorZalo:"Developer Zalo", creatorPhone:"Support phone", creatorEmail:"Support email"
  };
  const map = lang === "vi" ? vi : en;
  Object.entries(map).forEach(([id,label]) => {
    const el = document.getElementById(id);
    const parent = el?.parentElement;
    const first = parent?.firstChild;
    if (first && first.nodeType === Node.TEXT_NODE) first.textContent = `\n  ${label}\n  `;
  });
  document.documentElement.lang = lang;
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
  <button class="tab" data-tab="settings">04&nbsp; SETTINGS</button>
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
  <input type="checkbox" data-payload="dns">
  <span><b>DNS Settings</b><small>DNS-over-HTTPS / DNS-over-TLS</small></span>
</label>

<label class="check">
  <input type="checkbox" data-payload="vpn">
  <span><b>VPN</b><small>IKEv2 / IPSec profile shell</small></span>
</label>

<label class="check">
  <input type="checkbox" data-payload="wifi">
  <span><b>Wi-Fi</b><small>SSID and security settings</small></span>
</label>

<label class="check">
  <input type="checkbox" data-payload="webclip">
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
  <input id="dnsServer" value="https://cloudflare-dns.com/dns-query">
</label>

<label>DNS address (DoT)
  <input id="dnsAddress" value="1.1.1.1" placeholder="1.1.1.1">
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

<label class="wide">Root CA PEM / CRT (không bắt buộc)
  <textarea id="profileCert" rows="4" placeholder="Dán chứng chỉ PEM bắt đầu bằng -----BEGIN CERTIFICATE----- hoặc tạo Root CA trước."></textarea>
</label>
<label class="wide">Mã / String đính kèm (không thực thi trên iPhone)
  <select id="codeFormat"><option>Plain text</option><option>Base64</option><option>C++ source</option><option>JavaScript source</option></select>
  <textarea id="customCode" rows="5" placeholder="Dán string, Base64 hoặc mã nguồn C++..."></textarea>
  <small id="codePreview" class="codepreview">Bản xem trước sẽ hiển thị tại đây.</small>
</label>
</div>

<div class="note">
  DNS chỉ được thêm khi bạn chủ động tích chọn. Mặc định không cài DNS/VPN để tránh làm mất kết nối. Nếu profile gây lỗi mạng, vào Cài đặt iPhone → Cài đặt chung → VPN & Quản lý thiết bị để xóa profile. VPN cần máy chủ thật. Profile chưa ký có thể hiện “Chưa xác thực”; Root CA tự ký cần bật tin cậy thủ công trong Cài đặt → Cài đặt chung → Giới thiệu → Cài đặt tin cậy chứng chỉ.<br><br>Mã C++/JavaScript/Base64 chỉ được đính kèm trong ZIP dưới dạng tệp văn bản; iOS không thực thi mã nguồn từ Mobileconfig.
</div>

<div class="actions">
  <button id="buildMobile" class="primary">⇩ TẠO MOBILECONFIG</button>
  <button id="exportZip" class="secondary">⇩ XUẤT ZIP</button>
</div>
<div id="mobileDownloads" class="result hidden">
  <b>Mobileconfig đã tạo</b>
  <p>Trên iPhone, mở ứng dụng Tệp (Files) để chọn và cài đặt profile vừa tải.</p>
  <button id="downloadMobileAgain" class="secondary">TẢI LẠI MOBILECONFIG</button>
  <button id="downloadZipAgain" class="secondary">TẢI GÓI ZIP</button>
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

<section id="settings" class="pane">
<div class="sectionhead"><div><small>APPLICATION SETTINGS</small><h2>Cài đặt PEDINHIOS</h2></div><span class="step">04 / 04</span></div>
<div class="grid">
<label>Ngôn ngữ giao diện<select id="appLanguage"><option value="vi" selected>Tiếng Việt</option><option value="en">English</option></select></label>
<label>Người phát triển<input id="creatorName" value="Ah Định" placeholder="Tên người phát triển"></label>
<label>Zalo người phát triển<input id="creatorZalo" placeholder="ID Zalo hoặc số điện thoại"></label>
<label>Số điện thoại hỗ trợ<input id="creatorPhone" placeholder="Nhập số hỗ trợ (tùy chọn)"></label>
<label class="wide">Email hỗ trợ<input id="creatorEmail" type="email" placeholder="Email hỗ trợ (tùy chọn)"></label>
</div>
<div class="note"><b>Thông tin tác giả</b><p id="creatorPreview">Phát triển bởi Ah Định · PEDINHIOS</p><p>Thông tin liên hệ chỉ được đưa vào gói ZIP khi bạn tự nhập. Không tự tạo số điện thoại hoặc tài khoản Zalo.</p></div>
<div class="actions"><button id="saveSettings" class="primary">LƯU CÀI ĐẶT TRÊN TRANG NÀY</button></div>
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

  $("#exportZip").addEventListener("click", async () => {
    try { await exportProjectZip(); }
    catch (e) { setStatus(e instanceof Error ? e.message : String(e)); }
  });
  $("#downloadMobileAgain").addEventListener("click", () => {
    if (lastMobileconfig) download("PEDINHIOS_CONFIGURATION.mobileconfig", lastMobileconfig, "application/x-apple-aspen-config");
  });
  $("#downloadZipAgain").addEventListener("click", async () => {
    try { await exportProjectZip(); } catch (e) { setStatus(e instanceof Error ? e.message : String(e)); }
  });
  $("#customCode").addEventListener("input", updateCodePreview);
  $("#codeFormat").addEventListener("change", updateCodePreview);
  $("#dnsMethod").addEventListener("change", () => {
    if (getVal("dnsMethod") === "DoT") {
      (document.getElementById("dnsServer") as HTMLInputElement).value = "one.one.one.one";
      (document.getElementById("dnsAddress") as HTMLInputElement).value = "1.1.1.1";
    } else {
      (document.getElementById("dnsServer") as HTMLInputElement).value = "https://cloudflare-dns.com/dns-query";
    }
  });
  const savedSettings = (() => { try { return JSON.parse(localStorage.getItem("pedinhios-settings") || "{}"); } catch { return {}; } })();
  for (const id of ["appLanguage", "creatorName", "creatorZalo", "creatorPhone", "creatorEmail"]) {
    const el = document.getElementById(id) as HTMLInputElement | HTMLSelectElement;
    if (savedSettings[id]) el.value = savedSettings[id];
  }
  $("#appLanguage").addEventListener("change", () => applyUiLanguage(getVal("appLanguage")));
  applyUiLanguage(getVal("appLanguage") || "vi");
  $("#saveSettings").addEventListener("click", () => {
    const values: Record<string,string> = {};
    for (const id of ["appLanguage", "creatorName", "creatorZalo", "creatorPhone", "creatorEmail"]) values[id] = getVal(id);
    localStorage.setItem("pedinhios-settings", JSON.stringify(values));
    const name = getVal("creatorName") || "PEDINHIOS";
    $("#creatorPreview").textContent = `Phát triển bởi ${name} · PEDINHIOS`;
    applyUiLanguage(getVal("appLanguage") || "vi");
    setStatus("Đã lưu thông tin tác giả và cài đặt trên trình duyệt này.", true);
  });
  const initialCreator = getVal("creatorName") || "PEDINHIOS";
  $("#creatorPreview").textContent = `Phát triển bởi ${initialCreator} · PEDINHIOS`;

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

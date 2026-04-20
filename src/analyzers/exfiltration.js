import {
  EXFIL_WHITELIST_HOSTS,
  EXFIL_PLACEHOLDER_HOSTS_DROP,
  EXFIL_PLACEHOLDER_SUFFIXES_LOW,
  SHORTENER_HOSTS,
  BLACKLIST_HOST_PATTERNS,
} from "../constants.js";
import { hostnameFromUrl } from "../util/url.js";

function isBlacklistedHost(host) {
  const h = host.toLowerCase();
  for (const pattern of BLACKLIST_HOST_PATTERNS) {
    if (pattern.test(h)) {
      return true;
    }
  }
  return false;
}

const IPv4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;

const IPv6_RE = /\b(?:[0-9a-f]{1,4}:){3,7}[0-9a-f]{1,4}\b/gi;

const HEX_IP_RE = /\b0x[0-9a-f]{1,2}\.0x[0-9a-f]{1,2}\.0x[0-9a-f]{1,2}\.0x[0-9a-f]{1,2}\b/gi;

const DECIMAL_IP_RE = /\b(16843009|4294967295|\d{10,})\b/g;

const DNS_EXFIL_RE =
  /\b(dig|nslookup|host)\b[^;\n]{0,120}(\+short|exfil)/i;

export function analyzeExfiltration(parsedFiles) {
  const analyzer = "exfiltration";
  const findings = [];
  for (const pf of parsedFiles) {
    const file = pf.relativePath;
    for (const u of pf.urls) {
      const host = hostnameFromUrl(u.url);
      if (!host) {
        continue;
      }
      if (EXFIL_WHITELIST_HOSTS.has(host)) {
        continue;
      }
      if (EXFIL_PLACEHOLDER_HOSTS_DROP.has(host)) {
        continue;
      }
      const isPlaceholderSuffix = EXFIL_PLACEHOLDER_SUFFIXES_LOW.some((s) =>
        host.endsWith(s),
      );
      if (isBlacklistedHost(host)) {
        findings.push({
          analyzer,
          severity: "high",
          file,
          line: u.line,
          rule: "blacklist-domain",
          excerpt: u.url,
          message: `High-risk domain: ${host}`,
        });
        continue;
      }
      if (SHORTENER_HOSTS.has(host)) {
        findings.push({
          analyzer,
          severity: "medium",
          file,
          line: u.line,
          rule: "url-shortener",
          excerpt: u.url,
          message: `URL shortener: ${host}`,
        });
        continue;
      }
      findings.push({
        analyzer,
        severity: isPlaceholderSuffix ? "low" : "medium",
        file,
        line: u.line,
        rule: "non-whitelist-domain",
        excerpt: u.url,
        message: `Network endpoint not on common-doc/CDN allowlist: ${host}`,
      });
    }
    let m;
    IPv4_RE.lastIndex = 0;
    while ((m = IPv4_RE.exec(pf.content)) !== null) {
      const ipStr = m[0];
      if (ipStr.startsWith("0.0.0.0")) {
        continue;
      }
      if (/^127\./.test(ipStr)) {
        continue;
      }
      const octets = ipStr.split(".");
      if (octets.some((o) => o.length > 1 && o.startsWith("0"))) {
        continue;
      }
      const line = pf.content.slice(0, m.index).split(/\r?\n/).length;
      findings.push({
        analyzer,
        severity: "high",
        file,
        line,
        rule: "hardcoded-ip",
        excerpt: ipStr,
        message: "Hardcoded IP address in content",
      });
    }

    // IPv6 detection (exclude loopback and link-local)
    IPv6_RE.lastIndex = 0;
    while ((m = IPv6_RE.exec(pf.content)) !== null) {
      const ip = m[0].toLowerCase();
      const segs = ip.split(":").filter((s) => s.length > 0);
      if (segs.length < 4 && !/[a-f]/.test(ip)) {
        continue;
      }
      if (/^(::1|fe80::|ff02::)/.test(ip)) {
        continue;
      }
      const line = pf.content.slice(0, m.index).split(/\r?\n/).length;
      findings.push({
        analyzer,
        severity: "high",
        file,
        line,
        rule: "hardcoded-ipv6",
        excerpt: ip,
        message: "Hardcoded IPv6 address in content",
      });
    }

    // Hex-encoded IP detection
    HEX_IP_RE.lastIndex = 0;
    while ((m = HEX_IP_RE.exec(pf.content)) !== null) {
      const line = pf.content.slice(0, m.index).split(/\r?\n/).length;
      findings.push({
        analyzer,
        severity: "high",
        file,
        line,
        rule: "obfuscated-ip-hex",
        excerpt: m[0],
        message: "Hex-encoded IP address (obfuscation technique)",
      });
    }

    // Decimal-encoded IP detection (context-aware)
    DECIMAL_IP_RE.lastIndex = 0;
    while ((m = DECIMAL_IP_RE.exec(pf.content)) !== null) {
      const before = pf.content.slice(Math.max(0, m.index - 100), m.index);
      const after = pf.content.slice(m.index, Math.min(pf.content.length, m.index + 100));
      if (/(curl|wget|fetch|connect|socket|send)/i.test(before + after)) {
        const line = pf.content.slice(0, m.index).split(/\r?\n/).length;
        findings.push({
          analyzer,
          severity: "high",
          file,
          line,
          rule: "obfuscated-ip-decimal",
          excerpt: m[0],
          message: "Decimal-encoded IP address in network context (obfuscation)",
        });
      }
    }

    // Check base64 blobs for encoded URLs
    for (const blob of pf.base64Blobs) {
      const decoded = blob.decoded.toLowerCase();
      if (/https?:\/\//.test(decoded)) {
        const urlRe = /https?:\/\/[^\s`'")>\]]+/gi;
        let urlMatch;
        while ((urlMatch = urlRe.exec(blob.decoded)) !== null) {
          const host = hostnameFromUrl(urlMatch[0]);
          if (host && !EXFIL_WHITELIST_HOSTS.has(host)) {
            if (isBlacklistedHost(host)) {
              findings.push({
                analyzer,
                severity: "high",
                file,
                line: blob.line,
                rule: "base64-encoded-blacklist-url",
                excerpt: `base64:[${host}]`,
                message: `Blacklist domain hidden in base64 blob: ${host}`,
              });
            }
          }
        }
      }
    }
    if (DNS_EXFIL_RE.test(pf.content)) {
      const line = pf.content.search(DNS_EXFIL_RE) >= 0
        ? pf.content.slice(0, pf.content.search(DNS_EXFIL_RE)).split(/\r?\n/).length
        : 1;
      findings.push({
        analyzer,
        severity: "high",
        file,
        line,
        rule: "dns-exfil-pattern",
        excerpt: "dig/nslookup exfil pattern",
        message: "Possible DNS-based data exfiltration command",
      });
    }
    const gitRemote = /git\s+remote\s+add\s+\S+\s+(https?:\/\/[^\s]+)/gi;
    let gr;
    while ((gr = gitRemote.exec(pf.content)) !== null) {
      const h = hostnameFromUrl(gr[1]);
      if (h && !EXFIL_WHITELIST_HOSTS.has(h) && !isBlacklistedHost(h)) {
        const line = pf.content.slice(0, gr.index).split(/\r?\n/).length;
        findings.push({
          analyzer,
          severity: "medium",
          file,
          line,
          rule: "git-remote-nonstandard",
          excerpt: gr[1],
          message: `git remote to non-allowlist host: ${h}`,
        });
      }
    }
  }
  return findings;
}

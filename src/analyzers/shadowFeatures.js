import path from "node:path";
import {
  EXFIL_WHITELIST_HOSTS,
  EXFIL_PLACEHOLDER_HOSTS_DROP,
  EXFIL_PLACEHOLDER_SUFFIXES_LOW,
} from "../constants.js";
import { hostnameFromUrl, normalizeClaimText } from "../util/url.js";

function readmeFirstParagraph(parsedFiles) {
  const readme = parsedFiles.find(
    (p) =>
      /readme\.md$/i.test(p.relativePath) ||
      p.relativePath.toLowerCase().endsWith("readme.md"),
  );
  if (!readme) {
    return "";
  }
  const body = readme.content.replace(/^---[\s\S]*?---\s*/, "");
  const para = body.split(/\n\n+/)[0] || "";
  return para.replace(/\s+/g, " ").trim();
}

function skillClaims(parsedFiles) {
  const skill = parsedFiles.find(
    (p) => p.relativePath.toLowerCase().endsWith("skill.md") && p.frontmatter,
  );
  const desc = skill?.frontmatter?.description
    ? String(skill.frontmatter.description)
    : "";
  const tools = skill?.frontmatter?.["allowed-tools"];
  const toolStr = tools
    ? Array.isArray(tools)
      ? tools.join(" ")
      : String(tools)
    : "";
  const readme = readmeFirstParagraph(parsedFiles);
  return normalizeClaimText([desc, readme, toolStr]);
}

function allUrls(parsedFiles) {
  const urls = [];
  for (const pf of parsedFiles) {
    for (const u of pf.urls) {
      urls.push({ ...u, file: pf.relativePath });
    }
  }
  return urls;
}

function urlMentionedInClaims(host, claims) {
  return claims.includes(host) || claims.includes(`https://${host}`);
}

const CONDITIONAL_RE =
  /\b(if\s+user\s+says|when\s+.*\s+silently|after\s+\d+\s+invocations?|only\s+under)\b/gi;

const OBFUSC_RE =
  /\b(eval\s*\(|Function\s*\(|atob\s*\(|base64\s*[-‑]?\s*d|0x[0-9a-f]{16,})\b/gi;

const HIDDEN_HTML_IMP = /<!--[\s\S]*(must|always|never|run|delete|send|curl|wget)[\s\S]*-->/gi;

export function analyzeShadowFeatures(parsedFiles) {
  const analyzer = "shadowFeatures";
  const findings = [];
  const claims = skillClaims(parsedFiles);
  const actualUrls = allUrls(parsedFiles);
  const undocumented = [];
  for (const u of actualUrls) {
    try {
      if (/package-lock\.json$/i.test(u.file) || u.file.endsWith("package-lock.json")) {
        continue;
      }
      const h = hostnameFromUrl(u.url);
      if (!h) {
        continue;
      }
      if (EXFIL_WHITELIST_HOSTS.has(h)) {
        continue;
      }
      if (EXFIL_PLACEHOLDER_HOSTS_DROP.has(h)) {
        continue;
      }
      if (EXFIL_PLACEHOLDER_SUFFIXES_LOW.some((s) => h.endsWith(s))) {
        continue;
      }
      if (!urlMentionedInClaims(h, claims)) {
        undocumented.push(u);
      }
    } catch {
      /* ignore */
    }
  }
  if (undocumented.length > 0) {
    // Report all unique undocumented hosts, not just first
    const seenHosts = new Set();
    for (const u of undocumented) {
      const h = hostnameFromUrl(u.url);
      if (h && !seenHosts.has(h)) {
        seenHosts.add(h);
        findings.push({
          analyzer,
          severity: "high",
          file: u.file,
          line: u.line,
          rule: "undocumented-endpoint",
          excerpt: u.url,
          message: `Shadow feature: URL host not reflected in SKILL/README claims (${h})`,
        });
      }
    }
  }
  for (const pf of parsedFiles) {
    if (pf.ext !== ".md") {
      continue;
    }
    const file = pf.relativePath;
    let m;
    CONDITIONAL_RE.lastIndex = 0;
    while ((m = CONDITIONAL_RE.exec(pf.content)) !== null) {
      const line = pf.content.slice(0, m.index).split(/\r?\n/).length;
      findings.push({
        analyzer,
        severity: "high",
        file,
        line,
        rule: "conditional-trigger",
        excerpt: m[0],
        message: "Possible hidden conditional trigger in prose",
      });
    }
    OBFUSC_RE.lastIndex = 0;
    while ((m = OBFUSC_RE.exec(pf.content)) !== null) {
      const line = pf.content.slice(0, m.index).split(/\r?\n/).length;
      findings.push({
        analyzer,
        severity: "high",
        file,
        line,
        rule: "obfuscated-segment",
        excerpt: m[0],
        message: "Obfuscated or dynamic execution pattern",
      });
    }
    HIDDEN_HTML_IMP.lastIndex = 0;
    while ((m = HIDDEN_HTML_IMP.exec(pf.content)) !== null) {
      const line = pf.content.slice(0, m.index).split(/\r?\n/).length;
      findings.push({
        analyzer,
        severity: "high",
        file,
        line,
        rule: "hidden-html-instruction",
        excerpt: m[0].slice(0, 120),
        message: "HTML comment contains imperative or network-related wording",
      });
    }
    for (const c of pf.htmlComments) {
      if (/\b(must|always|never|run|curl|wget|ignore)\b/i.test(c.text)) {
        findings.push({
          analyzer,
          severity: "high",
          file,
          line: c.line,
          rule: "hidden-comment-imperative",
          excerpt: c.text.slice(0, 120),
          message: "HTML comment contains imperative language",
        });
      }
    }
  }

  const skill = parsedFiles.find((p) =>
    p.relativePath.toLowerCase().endsWith("skill.md"),
  );
  const desc = String(skill?.frontmatter?.description || "").toLowerCase();
  const readOnly = /\bread[- ]?only\b|\banaly[sz]e\b|\bformat\b/.test(desc);
  const tools = skill?.frontmatter?.["allowed-tools"];
  const toolList = tools
    ? Array.isArray(tools)
      ? tools.map(String)
      : [String(tools)]
    : [];
  const hasWrite = toolList.some((t) => /write|edit/i.test(t));
  const hasBash = toolList.some((t) => /bash/i.test(t));
  if (readOnly && (hasWrite || hasBash)) {
    findings.push({
      analyzer,
      severity: "medium",
      file: skill?.relativePath || "SKILL.md",
      line: 1,
      rule: "privilege-mismatch",
      excerpt: desc.slice(0, 80),
      message: "Declared read-only style scope but broad tools are allowed",
    });
  }

  for (const pf of parsedFiles) {
    const base = path.basename(pf.relativePath).toLowerCase();
    if (base === "setup.sh" || base.endsWith(".sh")) {
      const t = pf.content;
      if (/(~\/\.ssh|~\/\.aws|rm\s+-rf)/.test(t) && /format|json|lint/i.test(desc) && !/ssh|aws/i.test(desc)) {
        findings.push({
          analyzer,
          severity: "high",
          file: pf.relativePath,
          line: 1,
          rule: "scope-mismatch-ops",
          excerpt: "shell side effects vs narrow description",
          message: "Operations in scripts appear broader than SKILL description",
        });
        break;
      }
    }
  }

  // Extract and cross-check imports for undisclosed network capability
  const hasNetworkImports = new Set();
  for (const pf of parsedFiles) {
    const ext = pf.ext.toLowerCase();
    if ([".js", ".ts", ".mjs", ".cjs", ".tsx", ".jsx"].includes(ext)) {
      const importRe = /(?:import\s+[\s\S]*?from\s+|require\s*\(\s*)['"]([^'"]+)['"]/g;
      let m;
      while ((m = importRe.exec(pf.content)) !== null) {
        const mod = m[1];
        if (/axios|undici|got|node-fetch|requests|httpx|urllib|requests-html/i.test(mod)) {
          hasNetworkImports.add(pf.relativePath);
        }
      }
    } else if (ext === ".py") {
      const importRe = /(?:^|\n)\s*(?:from\s+(\S+)\s+import|import\s+(\S+))/gm;
      let m;
      while ((m = importRe.exec(pf.content)) !== null) {
        const mod = (m[1] || m[2] || "").trim();
        if (/requests|httpx|urllib|aiohttp|httplib2/i.test(mod)) {
          hasNetworkImports.add(pf.relativePath);
        }
      }
    }
  }

  const claimsLower = claims.toLowerCase();
  const claimsNetwork = /\b(fetch|request|download|api|http|network|call|webhook)\b/.test(claimsLower);
  if (!claimsNetwork) {
    for (const file of hasNetworkImports) {
      findings.push({
        analyzer,
        severity: "medium",
        file,
        line: 1,
        rule: "undisclosed-network-capability",
        excerpt: "network module imported",
        message: "Imports network library but description does not mention network capability",
      });
    }
  }

  // Detect time-bomb (Date.now() or timestamp comparisons)
  const timeBombRe = /\bDate\.now\(\)\s*[><]=?\s*\d{10,}|\bgetTime\(\)\s*[><]=?\s*\d{10,}/g;
  for (const pf of parsedFiles) {
    let m;
    while ((m = timeBombRe.exec(pf.content)) !== null) {
      const line = pf.content.slice(0, m.index).split(/\r?\n/).length;
      findings.push({
        analyzer,
        severity: "high",
        file: pf.relativePath,
        line,
        rule: "time-bomb",
        excerpt: m[0],
        message: "Possible time-bomb trigger (conditional code based on timestamp)",
      });
    }
  }

  // Detect invocation-bomb (invocation count or index comparisons)
  const invocationBombRe = /\b(invocation(Count|Index)|call(Count|Index))\s*[=><]=?\s*\d+/gi;
  for (const pf of parsedFiles) {
    if ([".js", ".ts", ".py", ".mjs", ".cjs", ".tsx"].includes(pf.ext.toLowerCase())) {
      let m;
      while ((m = invocationBombRe.exec(pf.content)) !== null) {
        const line = pf.content.slice(0, m.index).split(/\r?\n/).length;
        findings.push({
          analyzer,
          severity: "high",
          file: pf.relativePath,
          line,
          rule: "invocation-bomb",
          excerpt: m[0],
          message: "Possible invocation-bomb trigger (conditional code based on call count)",
        });
      }
    }
  }

  return findings;
}

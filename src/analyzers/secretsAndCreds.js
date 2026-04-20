function shannonEntropy(s) {
  const freq = {};
  for (const c of s) {
    freq[c] = (freq[c] || 0) + 1;
  }
  let h = 0;
  const n = s.length;
  for (const k of Object.keys(freq)) {
    const p = freq[k] / n;
    h -= p * Math.log2(p);
  }
  return h;
}

const PLACEHOLDER_RE =
  /\b(YOUR_KEY_HERE|xxxxx|xxxxxx|<token>|sk-test|fake-|00000000)\b/i;

const PATTERNS = [
  {
    rule: "openai-key",
    severity: "high",
    re: /OPENAI_API_KEY\s*=\s*['"]?(sk-[A-Za-z0-9]{20,})/gi,
  },
  {
    rule: "aws-secret",
    severity: "high",
    re: /AWS_SECRET_ACCESS_KEY\s*=\s*['"]?([A-Za-z0-9/+=]{40})/gi,
  },
  {
    rule: "aws-access",
    severity: "high",
    re: /AWS_ACCESS_KEY_ID\s*=\s*['"]?(AKIA[0-9A-Z]{16})/gi,
  },
  {
    rule: "github-token",
    severity: "high",
    re: /GITHUB_TOKEN\s*=\s*['"]?(gh[pousr]_[A-Za-z0-9]{36,})/gi,
  },
  {
    rule: "anthropic-key",
    severity: "high",
    re: /ANTHROPIC_API_KEY\s*=\s*['"]?(sk-ant-[A-Za-z0-9-]+)/gi,
  },
  {
    rule: "slack-token",
    severity: "high",
    re: /SLACK_TOKEN\s*=\s*['"]?(xox[abprs]-[A-Za-z0-9-]+)/gi,
  },
  {
    rule: "stripe-secret",
    severity: "high",
    re: /\b(sk|rk)_live_[0-9a-zA-Z]{20,}\b/g,
  },
  {
    rule: "stripe-webhook",
    severity: "high",
    re: /\bwhsec_[0-9a-zA-Z]{20,}\b/g,
  },
  {
    rule: "google-api-key",
    severity: "high",
    re: /\bAIza[0-9A-Za-z\-_]{35}\b/g,
  },
  {
    rule: "npm-token",
    severity: "high",
    re: /\bnpm_[A-Za-z0-9]{36}\b/g,
  },
  {
    rule: "heroku-key",
    severity: "high",
    re: /\bheroku[_-]?[a-f0-9]{32}\b/gi,
  },
  {
    rule: "twilio-sid",
    severity: "medium",
    re: /\bAC[a-f0-9]{32}\b/gi,
  },
  {
    rule: "sendgrid-key",
    severity: "high",
    re: /\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b/g,
  },
];

const PRIVATE_KEY_RE =
  /-----BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE KEY-----[\s\S]{0,16000}?-----END (RSA|EC|OPENSSH|PGP) PRIVATE KEY-----/gi;

const JWT_RE =
  /\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g;

const ENV_READ_RE =
  /(?:process\.env\.(\w+)|os\.environ\[['"](\w+)['"]\]|\$(TOKEN|SECRET|API_KEY|PASSWORD|CREDENTIAL|KEY))/gi;

const HTTP_CALL_RE =
  /\b(fetch\s*\(|axios\.|http\.request|requests\.(get|post)|curl\s|wget\s)/i;

// Database URI patterns with embedded credentials
const DB_URI_PATTERNS = [
  {
    rule: "mongodb-uri-creds",
    severity: "high",
    re: /\bmongodb(\+srv)?:\/\/[^:\/\s]+:[^@\s]+@/gi,
  },
  {
    rule: "postgres-uri-creds",
    severity: "high",
    re: /\b(postgres|postgresql)(\+\w+)?:\/\/[^:\/\s]+:[^@\s]+@/gi,
  },
  {
    rule: "mysql-uri-creds",
    severity: "high",
    re: /\b(mysql|mariadb)(\+\w+)?:\/\/[^:\/\s]+:[^@\s]+@/gi,
  },
  {
    rule: "redis-uri-creds",
    severity: "high",
    re: /\bredis(\+\w+)?:\/\/[^:\/\s]+:[^@\s]+@/gi,
  },
];

const AZURE_STORAGE_RE =
  /DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]{20,}/i;

const GCP_SERVICE_ACCOUNT_RE =
  /"type"\s*:\s*"service_account"[\s\S]{0,2000}"private_key"\s*:\s*"-----BEGIN/i;

function lineNumber(content, index) {
  return content.slice(0, index).split(/\r?\n/).length;
}

function isPlaceholderLine(line) {
  return PLACEHOLDER_RE.test(line);
}

export function analyzeSecretsAndCreds(parsedFiles) {
  const analyzer = "secretsAndCreds";
  const findings = [];
  for (const pf of parsedFiles) {
    const file = pf.relativePath;
    const text = pf.content;
    if (isPlaceholderLine(text) && text.length < 200) {
      continue;
    }
    for (const { rule, severity, re } of PATTERNS) {
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(text)) !== null) {
        const line = lineNumber(text, m.index);
        const lineText = pf.lines[line - 1]?.text || "";
        if (PLACEHOLDER_RE.test(lineText) || /example|placeholder/i.test(lineText)) {
          continue;
        }
        findings.push({
          analyzer,
          severity,
          file,
          line,
          rule,
          excerpt: m[1].slice(0, 40),
          message: `Possible hardcoded credential (${rule})`,
        });
      }
    }
    let m;
    PRIVATE_KEY_RE.lastIndex = 0;
    while ((m = PRIVATE_KEY_RE.exec(text)) !== null) {
      const line = lineNumber(text, m.index);
      findings.push({
        analyzer,
        severity: "high",
        file,
        line,
        rule: "private-key-block",
        excerpt: "-----BEGIN ... PRIVATE KEY-----",
        message: "Private key material in repository",
      });
    }
    JWT_RE.lastIndex = 0;
    while ((m = JWT_RE.exec(text)) !== null) {
      const line = lineNumber(text, m.index);
      const jwt = m[0];
      if (jwt.length < 40) {
        continue;
      }
      if (/example|fake|test/i.test(jwt)) {
        continue;
      }
      findings.push({
        analyzer,
        severity: "high",
        file,
        line,
        rule: "jwt-hardcoded",
        excerpt: jwt.slice(0, 40) + "...",
        message: "Possible hardcoded JWT",
      });
    }

    const suspectStrings = text.matchAll(
      /(?:secret|token|password|api[_-]?key)\s*[=:]\s*['"]([^'"]{33,})['"]/gi,
    );
    for (const sm of suspectStrings) {
      const val = sm[1];
      if (PLACEHOLDER_RE.test(val) || /^0+$/.test(val)) {
        continue;
      }
      if (shannonEntropy(val) > 4.5) {
        const line = lineNumber(text, sm.index);
        findings.push({
          analyzer,
          severity: "high",
          file,
          line,
          rule: "high-entropy-assignment",
          excerpt: val.slice(0, 24) + "...",
          message: "High-entropy string assigned to sensitive variable name",
        });
      }
    }

    if (ENV_READ_RE.test(text) && HTTP_CALL_RE.test(text)) {
      ENV_READ_RE.lastIndex = 0;
      let hasSensitiveEnv = false;
      let em;
      while ((em = ENV_READ_RE.exec(text)) !== null) {
        const name = em[1] || em[2] || em[3] || "";
        if (/(TOKEN|SECRET|KEY|PASSWORD|CREDENTIAL)/i.test(name)) {
          hasSensitiveEnv = true;
          break;
        }
      }
      if (hasSensitiveEnv) {
        findings.push({
          analyzer,
          severity: "high",
          file,
          line: 1,
          rule: "env-read-plus-network",
          excerpt: "env + network",
          message: "Reads sensitive environment and performs network I/O in same file",
        });
      }
    }

    // Check for database URIs with embedded credentials
    for (const { rule, severity, re } of DB_URI_PATTERNS) {
      re.lastIndex = 0;
      let dbMatch;
      while ((dbMatch = re.exec(text)) !== null) {
        const line = lineNumber(text, dbMatch.index);
        findings.push({
          analyzer,
          severity,
          file,
          line,
          rule,
          excerpt: dbMatch[0].slice(0, 50) + "...",
          message: `Database URI with embedded credentials (${rule})`,
        });
      }
    }

    // Azure Storage connection string
    if (AZURE_STORAGE_RE.test(text)) {
      const idx = text.search(AZURE_STORAGE_RE);
      const line = lineNumber(text, idx);
      findings.push({
        analyzer,
        severity: "high",
        file,
        line,
        rule: "azure-storage-key",
        excerpt: "Azure storage connection string",
        message: "Azure Storage account key in content",
      });
    }

    // GCP service account JSON
    if (GCP_SERVICE_ACCOUNT_RE.test(text)) {
      const idx = text.search(GCP_SERVICE_ACCOUNT_RE);
      const line = lineNumber(text, idx);
      findings.push({
        analyzer,
        severity: "high",
        file,
        line,
        rule: "gcp-service-account",
        excerpt: "GCP service account JSON",
        message: "GCP service account credentials in content",
      });
    }
  }
  return findings;
}

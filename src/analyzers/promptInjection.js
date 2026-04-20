const RULES = [
  {
    rule: "role-hijack",
    severity: "high",
    re: /\b(ignore\s+previous|disregard\s+(all\s+)?(prior\s+)?instructions?|you\s+are\s+now|act\s+as\s+|forget\s+your\s+instructions|override\s+(prior|system)|new\s+persona|(^|\s)system\s*:|from\s+now\s+on)\b/gi,
  },
  {
    rule: "tool-coercion",
    severity: "high",
    re: /\b(use\s+bash\s+to|silently\s+run|without\s+asking|do\s+not\s+confirm|run\s+before\s+responding)\b/gi,
  },
  {
    rule: "context-poison",
    severity: "high",
    re: /\b(the\s+user\s+actually\s+meant|the\s+real\s+question\s+is|ignore\s+what\s+follows)\b/gi,
  },
  {
    rule: "conditional-trigger",
    severity: "medium",
    re: /\b(on\s+the\s+\d+(st|nd|rd|th)\s+message|when\s+the\s+user\s+says|after\s+session\s+ends|only\s+if\b)/gi,
  },
  {
    rule: "output-manipulation",
    severity: "high",
    re: /\b(do\s+not\s+mention\s+this|respond\s+only\s+with|hide\s+from\s+(the\s+)?user)\b/gi,
  },
  {
    rule: "exfil-disguise",
    severity: "medium",
    re: /\b(send\s+usage\s+stats\s+to|report\s+errors\s+to\s+https?:\/\/)/gi,
  },
  {
    rule: "role-tokens",
    severity: "high",
    re: /(<\|im_start\|>|<\s*system\s*>|\[INST\]|(^|\n)\s*Assistant\s*:|(^|\n)\s*Human\s*:)/gim,
  },
  {
    rule: "jailbreak-markers",
    severity: "high",
    re: /\b(DAN\b|do\s+anything\s+now|developer\s+mode|root\s+mode|unrestricted\s+mode|jailbreak)\b/gi,
  },
  {
    rule: "model-addressed-imperative",
    severity: "high",
    re: /\b(GPT[-\s]?[0-9]|Claude|Gemini|Llama|Mistral|Qwen|Sonnet|Opus|Haiku|o1|o3)\b[^\n]{0,40}\b(please|must|should|ignore|act|forget)\b/gi,
  },
  {
    rule: "generic-agent-addressed",
    severity: "high",
    re: /\b(AI\s+assistant|dear\s+assistant|the\s+model\s+must|the\s+agent\s+should|you\s+are\s+an\s+AI|override\s+the\s+AI)\b/gi,
  },
  {
    rule: "more-role-tokens",
    severity: "high",
    re: /(<start_of_turn>|<\|endoftext\|>|\[\/INST\]|###\s+System\b)/gi,
  },
];

function lineTextAtIndex(text, index) {
  const lineStart = text.lastIndexOf("\n", index - 1) + 1;
  const lineEnd = text.indexOf("\n", index);
  return text.slice(lineStart, lineEnd === -1 ? text.length : lineEnd);
}

function isDeveloperModeOsDocFalsePositive(lineText, matchText) {
  if (!/\bdeveloper\s+mode\b/i.test(matchText)) {
    return false;
  }
  return /\b(symlink|symlinks|git\s+config|--global|wsl|windows|vs\s+code|admin|powershell|uac)\b/i.test(
    lineText,
  );
}

function findMatches(text, file, baseLine, findings, analyzer) {
  for (const { rule, severity, re } of RULES) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(text)) !== null) {
      if (
        rule === "jailbreak-markers" &&
        isDeveloperModeOsDocFalsePositive(lineTextAtIndex(text, m.index), m[0])
      ) {
        continue;
      }
      const before = text.slice(0, m.index);
      const line = baseLine + before.split(/\r?\n/).length - 1;
      findings.push({
        analyzer,
        severity,
        file,
        line,
        rule,
        excerpt: m[0].trim().slice(0, 200),
        message: `Prompt injection pattern (${rule})`,
      });
    }
  }
}

export function analyzePromptInjection(parsedFiles) {
  const analyzer = "promptInjection";
  const findings = [];
  for (const pf of parsedFiles) {
    if (pf.ext !== ".md") {
      continue;
    }
    const file = pf.relativePath;
    findMatches(pf.content, file, 1, findings, analyzer);
    for (const c of pf.htmlComments) {
      if (c.text.length > 3) {
        findMatches(c.text, file, c.line, findings, analyzer);
      }
    }
    for (const line of pf.lines) {
      if (line.text.length > 500 && !line.text.trim().startsWith("```")) {
        findings.push({
          analyzer,
          severity: "medium",
          file,
          line: line.n,
          rule: "long-line",
          excerpt: line.text.slice(0, 80),
          message: "Unusually long line without code fence (possible hidden instruction)",
        });
      }
    }
    if (pf.frontmatter?.["allowed-tools"]) {
      const at = pf.frontmatter["allowed-tools"];
      const arr = Array.isArray(at) ? at : [String(at)];
      if (arr.some((x) => String(x).includes("*"))) {
        findings.push({
          analyzer,
          severity: "high",
          file,
          line: 1,
          rule: "frontmatter-wildcard-tools",
          excerpt: JSON.stringify(arr),
          message: "Frontmatter allows wildcard tools",
        });
      }
    }
    const desc = String(pf.frontmatter?.description || "").toLowerCase();
    if (/\b(always\s+use\s+this|before\s+any)\b/.test(desc)) {
      findings.push({
        analyzer,
        severity: "high",
        file,
        line: 1,
        rule: "frontmatter-suspicious-desc",
        excerpt: desc.slice(0, 120),
        message: "Suspicious imperative phrasing in frontmatter description",
      });
    }
    if (pf.unicode.kinds.length > 0) {
      findings.push({
        analyzer,
        severity: "high",
        file,
        line: pf.unicode.line || 1,
        rule: "unicode-evasion",
        excerpt: pf.unicode.kinds.join(", "),
        message: `Unicode evasion markers: ${pf.unicode.kinds.join(", ")}`,
      });
    }
    for (const blob of pf.base64Blobs) {
      findMatches(blob.decoded, file, blob.line, findings, analyzer);
    }
    // Check for image alt text injection
    const imgAltRe = /!\[[^\]]*\b(ignore|run|fetch|delete|curl|execute|bypass|override|inject)\b[^\]]*\]\([^)]+\)/gi;
    let altMatch;
    while ((altMatch = imgAltRe.exec(pf.content)) !== null) {
      const line = pf.content.slice(0, altMatch.index).split(/\r?\n/).length;
      findings.push({
        analyzer,
        severity: "medium",
        file,
        line,
        rule: "image-alt-injection",
        excerpt: altMatch[0].slice(0, 100),
        message: "Markdown image alt text contains imperative language",
      });
    }
  }
  return findings;
}

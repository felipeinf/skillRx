const RULES = [
  {
    rule: "role-hijack",
    severity: "high",
    re: /\b(ignore\s+previous|disregard\s+(all\s+)?(prior\s+)?instructions?|you\s+are\s+now|act\s+as\s+|forget\s+your\s+instructions|override\s+(prior|system)|new\s+persona|(^|\s)system\s*:|from\s+now\s+on)\b/gi,
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

const TOOL_COERCION_RE =
  /(?:\buse\s+bash\s+to\b|silently\s+run|do\s+not\s+confirm|run\s+before\s+responding|(?:\b(bash|shell|tool|command|script|exec|run|execute|invoke)\b[^\n.]{0,60}\bwithout\s+asking(?!\s+routine)\b|without\s+asking(?!\s+routine)\b[^\n.]{0,50}\b(bash|shell|command|script|run|tool|task)\b))/gi;

const TOOL_COERCION_STRONG_RE =
  /(?:\buse\s+bash\s+to\b|(?:\b(bash|shell)\b|run\s+command|exec(?:ute)?\b|invoke\s+tool)\b[^\n.]{0,50}(?:silently\s+run|do\s+not\s+confirm|run\s+before\s+responding|without\s+asking(?!\s+routine))|\b(curl|wget|base64)\b[^\n.]{0,40}\b(?:silently|do\s+not\s+confirm|pipe\s*to|>\s*\/(dev|tmp)\b|without\s+asking(?!\s+routine)))/gi;

function isDocishMarkdownFile(file) {
  const f = file.replace(/\\/g, "/");
  if (/(?:^|\/)(?:docs?|references?|prompts?|commands?|agents?)\//i.test(f)) {
    return true;
  }
  if (/\/plugins\/[^/]+\/[^/]+\/skills\//i.test(f)) {
    return true;
  }
  if (f.includes("/plugins/") && f.endsWith(".md")) {
    return true;
  }
  if (/(?:^|\/)skills\/[^/]+?\/.+\.md$/i.test(f)) {
    return true;
  }
  if (f.includes("references/") || f.includes("/prompts/") || f.includes("references\\")) {
    return true;
  }
  return false;
}

function isProseMetaLineForToolCoercion(lineText) {
  if (!lineText) {
    return false;
  }
  const t = lineText.trimStart();
  if (
    /^Use when\b/i.test(t) &&
    /routine questions|act without asking|without asking routine/i.test(t)
  ) {
    return true;
  }
  if (
    /^(?:For example|Example|Note|Tip|See also):?\s/i.test(t) ||
    /^>\s+/.test(t)
  ) {
    return true;
  }
  return false;
}

function isMetaInstructionLineForModelHeuristic(lineText) {
  if (!lineText) {
    return false;
  }
  const t = lineText.trimStart();
  if (/^[-*+]\s+/.test(t) || /^\d+\.\s+/.test(t) || /^\s*#{1,4}\s+/.test(t) || /```\w/.test(t)) {
    return true;
  }
  if (
    /\bClaude (?:thread|Code)?\s+should\b/i.test(t) ||
    /\bthe (?:thread|agent) should\b/i.test(t)
  ) {
    return true;
  }
  return false;
}

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
      const lineText = lineTextAtIndex(text, m.index);
      if (
        (rule === "model-addressed-imperative" || rule === "generic-agent-addressed") &&
        isDocishMarkdownFile(file) &&
        isMetaInstructionLineForModelHeuristic(lineText)
      ) {
        const before = text.slice(0, m.index);
        const line = baseLine + before.split(/\r?\n/).length - 1;
        findings.push({
          analyzer,
          severity: "low",
          file,
          line,
          rule: `${rule}-doc-context`,
          excerpt: m[0].trim().slice(0, 200),
          message: `Prompt injection pattern (${rule}, doc list context)`,
        });
        continue;
      }
      let sev = severity;
      if (
        (rule === "model-addressed-imperative" || rule === "generic-agent-addressed") &&
        isDocishMarkdownFile(file)
      ) {
        sev = "medium";
      }
      const before = text.slice(0, m.index);
      const line = baseLine + before.split(/\r?\n/).length - 1;
      findings.push({
        analyzer,
        severity: sev,
        file,
        line,
        rule,
        excerpt: m[0].trim().slice(0, 200),
        message: `Prompt injection pattern (${rule})`,
      });
    }
  }
}

function findToolCoercionMatches(text, file, baseLine, findings, analyzer) {
  const strongLineNums = new Set();
  TOOL_COERCION_STRONG_RE.lastIndex = 0;
  let sm;
  while ((sm = TOOL_COERCION_STRONG_RE.exec(text)) !== null) {
    const lineText = lineTextAtIndex(text, sm.index);
    if (isProseMetaLineForToolCoercion(lineText)) {
      continue;
    }
    const before = text.slice(0, sm.index);
    const line = baseLine + before.split(/\r?\n/).length - 1;
    strongLineNums.add(line);
    findings.push({
      analyzer,
      severity: "high",
      file,
      line,
      rule: "tool-coercion-strong",
      excerpt: sm[0].trim().slice(0, 200),
      message: "Prompt injection pattern (tool-coercion-strong)",
    });
  }
  TOOL_COERCION_RE.lastIndex = 0;
  let m;
  while ((m = TOOL_COERCION_RE.exec(text)) !== null) {
    const before = text.slice(0, m.index);
    const line = baseLine + before.split(/\r?\n/).length - 1;
    if (strongLineNums.has(line)) {
      continue;
    }
    const lineText = lineTextAtIndex(text, m.index);
    if (isProseMetaLineForToolCoercion(lineText)) {
      continue;
    }
    findings.push({
      analyzer,
      severity: "medium",
      file,
      line,
      rule: "tool-coercion",
      excerpt: m[0].trim().slice(0, 200),
      message: "Prompt injection pattern (tool-coercion)",
    });
  }
}

function classifyFrontmatterWildcards(arr) {
  const list = arr.map((x) => String(x));
  const join = list.join(" ");
  const broad = [];
  const scoped = [];
  const seenB = new Set();
  const seenS = new Set();
  for (const s of list) {
    if (s.trim() === "*") {
      if (!seenB.has("*")) {
        seenB.add("*");
        broad.push("*");
      }
    }
  }
  for (const m of join.matchAll(/Bash\(([^)]+)\)/gi)) {
    const inner = m[1].replace(/\s+/g, " ").trim();
    if (inner === "*") {
      if (!seenB.has("Bash(*)")) {
        seenB.add("Bash(*)");
        broad.push("Bash(*)");
      }
    } else if (/\w[\w-]*\s*:\s*\*+\s*$/i.test(inner)) {
      if (!seenS.has(m[0])) {
        seenS.add(m[0]);
        scoped.push(m[0]);
      }
    }
  }
  for (const re of [
    /\bRead\(\*+\s*\)/gi,
    /\bEdit\(\*+\s*\)/gi,
    /\bWrite\(\*+\s*\)/gi,
    /\bGlob\(\*+\s*\)/gi,
    /\bGrep\(\*+\s*\)/gi,
  ]) {
    for (const m of join.matchAll(re)) {
      if (m[0] && !seenB.has(m[0])) {
        seenB.add(m[0]);
        broad.push(m[0]);
      }
    }
  }
  return { broad, scoped };
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
    findToolCoercionMatches(pf.content, file, 1, findings, analyzer);
    for (const c of pf.htmlComments) {
      if (c.text.length > 3) {
        findMatches(c.text, file, c.line, findings, analyzer);
        findToolCoercionMatches(c.text, file, c.line, findings, analyzer);
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
      const { broad, scoped } = classifyFrontmatterWildcards(arr);
      for (const b of broad) {
        findings.push({
          analyzer,
          severity: "high",
          file,
          line: 1,
          rule: "frontmatter-bash-star",
          excerpt: b,
          message: "Frontmatter allows unscoped wildcard tools (Bash(*), Read(**), or equivalent)",
        });
      }
      for (const s of scoped) {
        if (!broad.includes(s)) {
          findings.push({
            analyzer,
            severity: "medium",
            file,
            line: 1,
            rule: "frontmatter-scoped-wildcard",
            excerpt: s,
            message: "Frontmatter allows scoped tool wildcards (Bash(node:*), etc.)",
          });
        }
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
      findToolCoercionMatches(blob.decoded, file, blob.line, findings, analyzer);
    }
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

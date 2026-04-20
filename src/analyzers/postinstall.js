import path from "node:path";

const LIFECYCLE = [
  "preinstall",
  "postinstall",
  "prepare",
  "prepublish",
  "prepack",
];

const CURL_PIPE_SH = /curl[^|\n]{0,200}\|\s*(ba)?sh|wget[^|\n]{0,200}\|\s*(ba)?sh/i;

export function analyzePostinstall(parsedFiles) {
  const analyzer = "postinstall";
  const findings = [];
  for (const pf of parsedFiles) {
    if (!pf.relativePath.endsWith("package.json")) {
      continue;
    }
    let pkg;
    try {
      pkg = JSON.parse(pf.content);
    } catch {
      continue;
    }
    const scripts = pkg.scripts || {};
    for (const key of LIFECYCLE) {
      const sc = scripts[key];
      if (!sc) {
        continue;
      }
      if (/\|/.test(sc) || /curl|wget|eval|node\s+-e|python\s+-c/i.test(sc)) {
        findings.push({
          analyzer,
          severity: "high",
          file: pf.relativePath,
          line: 1,
          rule: `npm-${key}-risk`,
          excerpt: sc.slice(0, 80),
          message: `Risky ${key} script`,
        });
      }
      if (CURL_PIPE_SH.test(sc)) {
        findings.push({
          analyzer,
          severity: "high",
          file: pf.relativePath,
          line: 1,
          rule: "curl-pipe-sh",
          excerpt: sc.slice(0, 80),
          message: "curl/wget piped to shell in lifecycle script",
        });
      }
    }
  }
  for (const pf of parsedFiles) {
    if (!pf.relativePath.endsWith("setup.py")) {
      continue;
    }
    const t = pf.content;
    const idxSetup = t.search(/^def\s+setup\s*\(/m);
    const idxPrint = t.search(/^print\s*\(/m);
    if (idxPrint !== -1 && (idxSetup === -1 || idxPrint < idxSetup)) {
      findings.push({
        analyzer,
        severity: "high",
        file: pf.relativePath,
        line: 1,
        rule: "setup-py-toplevel",
        excerpt: "top-level",
        message: "setup.py contains top-level executable code before setup()",
      });
    }
  }
  for (const pf of parsedFiles) {
    const p = pf.relativePath.replace(/\\/g, "/");
    if (!p.includes(".git/hooks/") && !p.includes("committed-hooks/hooks/")) {
      continue;
    }
    findings.push({
      analyzer,
      severity: "high",
      file: pf.relativePath,
      line: 1,
      rule: "committed-git-hook",
      excerpt: pf.relativePath,
      message: "Git hook script committed inside repository",
    });
  }

  // Dockerfile RUN with curl pipe to shell
  for (const pf of parsedFiles) {
    if (!pf.relativePath.toLowerCase().endsWith("dockerfile")) {
      continue;
    }
    const t = pf.content;
    const dockerfileCurlPipeRe = /RUN\s+.*(curl|wget)[^\n]*\|\s*(ba)?sh/gi;
    let m;
    while ((m = dockerfileCurlPipeRe.exec(t)) !== null) {
      const line = t.slice(0, m.index).split(/\r?\n/).length;
      findings.push({
        analyzer,
        severity: "high",
        file: pf.relativePath,
        line,
        rule: "dockerfile-curl-pipe",
        excerpt: m[0].slice(0, 80),
        message: "Dockerfile RUN with curl/wget piped to shell (unverified)",
      });
    }
    // Dockerfile ADD from remote URL
    const dockerfileAddRe = /ADD\s+https?:\/\//gi;
    while ((m = dockerfileAddRe.exec(t)) !== null) {
      const line = t.slice(0, m.index).split(/\r?\n/).length;
      findings.push({
        analyzer,
        severity: "medium",
        file: pf.relativePath,
        line,
        rule: "dockerfile-add-remote",
        excerpt: m[0],
        message: "Dockerfile ADD from remote URL without verification",
      });
    }
  }

  // Makefile/justfile curl pipe detection
  for (const pf of parsedFiles) {
    const base = pf.relativePath.toLowerCase();
    if (!base.endsWith("makefile") && !base.endsWith("justfile")) {
      continue;
    }
    const t = pf.content;
    const makeCurlPipeRe = /^[\t ]*[^\s:]+[^:]*:\s*(?:[^\n]*;\s*)?.*?(curl|wget)[^\n]*\|\s*(ba)?sh/gmi;
    let m;
    while ((m = makeCurlPipeRe.exec(t)) !== null) {
      const line = t.slice(0, m.index).split(/\r?\n/).length;
      findings.push({
        analyzer,
        severity: "high",
        file: pf.relativePath,
        line,
        rule: "make-curl-pipe",
        excerpt: m[0].slice(0, 80),
        message: "Makefile target with curl/wget piped to shell",
      });
    }
  }

  // Installer scripts with curl pipe
  for (const pf of parsedFiles) {
    const base = path.basename(pf.relativePath).toLowerCase();
    if (!["install.sh", "bootstrap.sh", "setup.sh"].includes(base)) {
      continue;
    }
    const t = pf.content;
    if (CURL_PIPE_SH.test(t)) {
      findings.push({
        analyzer,
        severity: "high",
        file: pf.relativePath,
        line: 1,
        rule: "installer-curl-pipe",
        excerpt: base,
        message: `Installer script (${base}) with curl/wget piped to shell`,
      });
    }
  }

  // pyproject.toml script definitions with risky operations
  for (const pf of parsedFiles) {
    if (!pf.relativePath.toLowerCase().endsWith("pyproject.toml")) {
      continue;
    }
    const t = pf.content;
    // Look for [project.scripts] or [tool.poetry.scripts] sections
    const scriptSectionRe = /\[(project\.scripts|tool\.poetry\.scripts)\][\s\S]{0,2000}?(?=\[|$)/g;
    let scriptSection;
    while ((scriptSection = scriptSectionRe.exec(t)) !== null) {
      if (/curl|wget|eval|bash|sh\b/.test(scriptSection[0])) {
        const line = t.slice(0, scriptSection.index).split(/\r?\n/).length;
        findings.push({
          analyzer,
          severity: "medium",
          file: pf.relativePath,
          line,
          rule: "pyproject-script-risk",
          excerpt: "script definition with network/shell",
          message: "pyproject.toml script definition contains risky operations",
        });
        break;
      }
    }
  }

  return findings;
}

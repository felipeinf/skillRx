import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import pLimit from "p-limit";

/**
 * @typedef {Object} ParsedLine
 * @property {number} n
 * @property {string} text
 */

/**
 * @typedef {Object} ParsedFile
 * @property {string} relativePath
 * @property {string} ext
 * @property {string} content
 * @property {ParsedLine[]} lines
 * @property {{ url: string, line: number }[]} urls
 * @property {{ text: string, line: number }[]} shellBlocks
 * @property {Record<string, unknown>|null} frontmatter
 * @property {{ text: string, line: number }[]} htmlComments
 * @property {{ kinds: string[], line?: number }} unicode
 * @property {{ decoded: string, line: number }[]} base64Blobs
 * @property {string} fullTextForImports
 */

const BASE64_RE = /[A-Za-z0-9+/=]{40,}/g;
const FENCE_SHELL = /^```(?:bash|sh|zsh|shell)\s*$/i;
const FENCE_END = /^```\s*$/;

const ZW = new Set([0x200b, 0x200c, 0x200d, 0xfeff]);
const BIDI = new Set([0x202e]);
function isTagChar(cp) {
  return cp >= 0xe0000 && cp <= 0xe007f;
}

function lineStarts(content) {
  const lines = content.split(/\r?\n/);
  return lines.map((text, i) => ({ n: i + 1, text }));
}

function extractUrls(content) {
  const urls = [];
  const re = /https?:\/\/[^\s`'")>\]]+/gi;
  let m;
  while ((m = re.exec(content)) !== null) {
    const before = content.slice(0, m.index);
    const line = before.split(/\r?\n/).length;
    let url = m[0];
    while (/[.,;:!?)]$/.test(url)) {
      url = url.slice(0, -1);
    }
    urls.push({ url, line });
  }
  return urls;
}

function extractShellFromMd(content) {
  const blocks = [];
  const lines = content.split(/\r?\n/);
  let i = 0;
  while (i < lines.length) {
    if (FENCE_SHELL.test(lines[i])) {
      const startLine = i + 1;
      i++;
      const buf = [];
      while (i < lines.length && !FENCE_END.test(lines[i])) {
        buf.push(lines[i]);
        i++;
      }
      blocks.push({
        text: buf.join("\n"),
        line: startLine,
      });
    }
    i++;
  }
  return blocks;
}

function parseYamlFrontmatter(content) {
  if (!content.startsWith("---\n") && !content.startsWith("---\r\n")) {
    return { frontmatter: null, bodyStartLine: 1 };
  }
  const nl = content.startsWith("---\r\n") ? "\r\n" : "\n";
  const rest = content.slice(4);
  const endIdx = rest.indexOf(`---${nl}`);
  if (endIdx === -1) {
    return { frontmatter: null, bodyStartLine: 1 };
  }
  const yamlBlock = rest.slice(0, endIdx);
  const bodyStartLine = yamlBlock.split(/\r?\n/).length + 2;
  const fm = parseMinimalYaml(yamlBlock);
  return { frontmatter: fm, bodyStartLine };
}

function parseMinimalYaml(text) {
  const out = {};
  const lines = text.split(/\r?\n/);
  for (const line of lines) {
    const kv = line.match(/^([\w-]+)\s*:\s*(.*)$/);
    if (!kv) {
      continue;
    }
    const key = kv[1];
    let val = kv[2].trim();
    if (val.startsWith("[") && val.endsWith("]")) {
      const inner = val.slice(1, -1);
      out[key] = inner
        .split(",")
        .map((s) => s.trim().replace(/^["']|["']$/g, ""))
        .filter(Boolean);
    } else {
      out[key] = val.replace(/^["']|["']$/g, "");
    }
  }
  return out;
}

function extractHtmlComments(content) {
  const comments = [];
  const re = /<!--([\s\S]*?)-->/g;
  let m;
  while ((m = re.exec(content)) !== null) {
    const before = content.slice(0, m.index);
    const line = before.split(/\r?\n/).length;
    comments.push({ text: m[1].trim(), line });
  }
  return comments;
}

function scanUnicode(content) {
  const kinds = [];
  let lineWithBidi = 0;
  let hasCyrillicLatinMix = false;
  let latin = false;
  let cyr = false;
  for (let i = 0; i < content.length; i++) {
    const cp = content.codePointAt(i);
    if (cp === undefined) {
      break;
    }
    if (cp > 0xffff) {
      i++;
    }
    if (ZW.has(cp)) {
      kinds.push("zero-width");
    }
    if (BIDI.has(cp)) {
      kinds.push("bidi");
      lineWithBidi = content.slice(0, i).split(/\r?\n/).length;
    }
    if (isTagChar(cp)) {
      kinds.push("tag");
    }
    if (cp >= 0x410 && cp <= 0x44f) {
      cyr = true;
    }
    if ((cp >= 0x41 && cp <= 0x5a) || (cp >= 0x61 && cp <= 0x7a)) {
      latin = true;
    }
  }
  if (latin && cyr) {
    hasCyrillicLatinMix = true;
    kinds.push("homoglyph-mix");
  }
  return {
    kinds: [...new Set(kinds)],
    line: lineWithBidi || undefined,
  };
}

function tryDecodeBase64(match, line) {
  try {
    const buf = Buffer.from(match, "base64");
    if (buf.length < 16) {
      return null;
    }
    const s = buf.toString("utf8");
    let printable = 0;
    for (let i = 0; i < s.length; i++) {
      const c = s.charCodeAt(i);
      if (c >= 32 && c <= 126) {
        printable++;
      }
    }
    if (printable / s.length < 0.85) {
      return null;
    }
    return { decoded: s, line };
  } catch {
    return null;
  }
}

function extractBase64(content) {
  const blobs = [];
  const lines = content.split(/\r?\n/);
  lines.forEach((lineText, idx) => {
    BASE64_RE.lastIndex = 0;
    let m;
    while ((m = BASE64_RE.exec(lineText)) !== null) {
      const decoded = tryDecodeBase64(m[0], idx + 1);
      if (decoded) {
        blobs.push(decoded);
      }
    }
  });
  return blobs;
}

export function parseFile(relativePath, content, ext) {
  const lines = lineStarts(content);
  const urls = extractUrls(content);
  let shellBlocks = [];
  if (ext === ".md" || ext === ".mdx") {
    shellBlocks = extractShellFromMd(content);
  } else if (
    [".sh", ".bash", ".zsh", ".ps1"].includes(ext) ||
    ext === "" ||
    /(^|\/)Dockerfile$|(^|\/)Makefile$|(^|\/)justfile$/i.test(relativePath)
  ) {
    shellBlocks = [{ text: content, line: 1 }];
  }
  let frontmatter = null;
  if (ext === ".md") {
    const pm = parseYamlFrontmatter(content);
    frontmatter = pm.frontmatter;
  }
  const htmlComments = ext === ".md" ? extractHtmlComments(content) : [];
  const unicode = scanUnicode(content);
  const base64Blobs = extractBase64(content);
  return {
    relativePath,
    ext,
    content,
    lines,
    urls,
    shellBlocks,
    frontmatter,
    htmlComments,
    unicode,
    base64Blobs,
    fullTextForImports: content,
  };
}

export async function parseWorkspace(rootPath, relativeFiles, shouldScan) {
  const limit = pLimit(10);
  const seenHashes = new Set();
  const parsed = [];
  const readErrors = [];

  await Promise.all(
    relativeFiles.map((rel) =>
      limit(async () => {
        const full = path.join(rootPath, rel);
        let st;
        try {
          st = fs.statSync(full);
        } catch (e) {
          readErrors.push({ rel, error: String(e) });
          return;
        }
        const check = shouldScan(rel, st.size);
        if (!check.ok) {
          return;
        }
        let raw;
        try {
          raw = fs.readFileSync(full, "utf8");
        } catch (e) {
          readErrors.push({ rel, error: String(e) });
          return;
        }
        const hash = crypto.createHash("sha1").update(raw).digest("hex");
        if (seenHashes.has(hash)) {
          return;
        }
        seenHashes.add(hash);
        const ext = path.extname(rel).toLowerCase();
        const pf = parseFile(rel, raw, ext);
        parsed.push(pf);
      }),
    ),
  );

  return { parsed, readErrors };
}

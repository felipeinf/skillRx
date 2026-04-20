import fs from "node:fs";
import path from "node:path";
import simpleGit from "simple-git";
import tmp from "tmp";
import {
  EXT_WHITELIST,
  NAME_WHITELIST,
  SIZE_CAP_BYTES,
  SKIP_DIRS,
} from "./constants.js";

tmp.setGracefulCleanup();

export class ResolverError extends Error {
  constructor(message, code) {
    super(message);
    this.name = "ResolverError";
    this.code = code;
  }
}

const GITHUB_SHORTHAND = /^[\w.-]+\/[\w.-]+$/;

const GITHUB_TREE_URL_RE =
  /^https?:\/\/github\.com\/([^/]+)\/([^/]+)\/tree\/([^/]+)\/(.+?)\/?$/i;

export function parseGithubTreeUrl(target) {
  const trimmed = target.trim();
  const m = trimmed.match(GITHUB_TREE_URL_RE);
  if (!m) {
    return null;
  }
  let pathPart = m[4].replace(/\/$/, "");
  try {
    pathPart = decodeURIComponent(pathPart);
  } catch {
    /* keep raw */
  }
  pathPart = pathPart.replace(/\\/g, "/");
  if (!pathPart || pathPart.includes("..")) {
    return null;
  }
  return {
    owner: m[1],
    repo: m[2],
    branch: m[3],
    subdir: pathPart,
    repoSlug: `${m[1]}/${m[2]}`,
  };
}

export function normalizeSubdir(subdir) {
  if (subdir == null || String(subdir).trim() === "") {
    return null;
  }
  let s = String(subdir).trim().replace(/^\/+|\/+$/g, "").replace(/\\/g, "/");
  if (!s || s.includes("..")) {
    throw new ResolverError(
      'Invalid --subdir: use a path like "skills/frontend-design" without ".."',
      "BAD_SUBDIR",
    );
  }
  return s;
}

export function skillIdToSparsePath(skillId) {
  const s = String(skillId).trim();
  if (!s) {
    throw new ResolverError(
      "Invalid --skill: provide a skill id (e.g. frontend-design).",
      "EMPTY_SKILL",
    );
  }
  if (s.includes("..") || s.includes("/") || s.includes("\\")) {
    throw new ResolverError(
      '--skill takes a single id (e.g. frontend-design). For other paths use --subdir.',
      "BAD_SKILL",
    );
  }
  if (!/^[\w.-]+$/.test(s)) {
    throw new ResolverError(
      "Invalid --skill name: use letters, numbers, dot, hyphen, or underscore only.",
      "BAD_SKILL",
    );
  }
  return `skills/${s}`;
}

function sparsePathFromSkillOption(skill) {
  if (skill == null || String(skill).trim() === "") {
    return null;
  }
  return skillIdToSparsePath(skill);
}

export function detectInputType(target) {
  const trimmed = target.trim();
  if (!trimmed) {
    throw new ResolverError("Empty target", "EMPTY");
  }
  const abs = path.resolve(trimmed);
  if (fs.existsSync(abs)) {
    const st = fs.statSync(abs);
    if (!st.isDirectory()) {
      throw new ResolverError(`Not a directory: ${trimmed}`, "NOT_DIR");
    }
    try {
      fs.accessSync(abs, fs.constants.R_OK);
    } catch {
      throw new ResolverError(`Permission denied: ${trimmed}`, "PERMISSION");
    }
    return { kind: "path", resolved: abs };
  }
  if (/^https?:\/\//i.test(trimmed)) {
    return { kind: "url", url: trimmed };
  }
  if (GITHUB_SHORTHAND.test(trimmed) && !trimmed.includes("..")) {
    return { kind: "github", repo: trimmed };
  }
  throw new ResolverError(
    `Unknown target: ${trimmed}. Use a local path, https:// Git URL, or owner/repo.`,
    "UNKNOWN",
  );
}

function githubCloneUrl(kind, url, repo) {
  if (kind === "github") {
    return `https://github.com/${repo}.git`;
  }
  if (kind === "url") {
    const u = url.trim();
    if (/github\.com\//i.test(u) && !/\.git$/i.test(u)) {
      return `${u.replace(/\/$/, "")}.git`;
    }
    return u;
  }
  return "";
}

function isGithubHttpsCloneUrl(cloneUrl) {
  return /^https?:\/\/github\.com\/[^/]+\/[^/]+\.git$/i.test(
    String(cloneUrl).trim(),
  );
}

async function cloneGitRepo(cloneUrl, cloneRoot, cloneArgs) {
  const git = simpleGit();
  await git.clone(cloneUrl, cloneRoot, cloneArgs);
}

function handleCloneError(e, target) {
  const msg = e?.message || String(e);
  if (/not found|404|Repository not found/i.test(msg)) {
    throw new ResolverError(
      `Repository not found or inaccessible: ${target}. Try cloning locally and scanning a path.`,
      "REPO_NOT_FOUND",
    );
  }
  if (/fetch|network|ENOTFOUND|ETIMEDOUT|ECONNREFUSED/i.test(msg)) {
    throw new ResolverError(
      `Network error while cloning: ${msg}. Try a local path instead.`,
      "NETWORK",
    );
  }
  throw new ResolverError(`Clone failed: ${msg}`, "CLONE_FAILED");
}

async function cloneSparseCheckout(cloneUrl, branch, subdir, targetLabel) {
  const dir = tmp.dirSync({ unsafeCleanup: true, prefix: "skillrx-" });
  const cloneRoot = dir.name;
  const cloneArgs = [
    "--depth",
    "1",
    "--single-branch",
    "--filter=blob:none",
    "--sparse",
  ];
  if (branch) {
    cloneArgs.push("--branch", branch);
  }
  try {
    await cloneGitRepo(cloneUrl, cloneRoot, cloneArgs);
  } catch (e) {
    try {
      fs.rmSync(cloneRoot, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
    handleCloneError(e, targetLabel);
  }
  const gitRepo = simpleGit(cloneRoot);
  try {
    await gitRepo.raw(["sparse-checkout", "set", subdir]);
  } catch (e) {
    try {
      fs.rmSync(cloneRoot, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
    const msg = e?.message || String(e);
    throw new ResolverError(
      `Sparse checkout failed for "${subdir}". The path may not exist on the default branch, or git is too old (need sparse-checkout). ${msg}`,
      "SPARSE_CHECKOUT_FAILED",
    );
  }
  const scanRoot = path.join(cloneRoot, subdir);
  if (!fs.existsSync(scanRoot) || !fs.statSync(scanRoot).isDirectory()) {
    try {
      fs.rmSync(cloneRoot, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
    throw new ResolverError(
      `After sparse checkout, path not found: ${subdir}`,
      "SUBDIR_NOT_FOUND",
    );
  }
  return {
    rootPath: scanRoot,
    cleanup: async () => {
      try {
        fs.rmSync(cloneRoot, { recursive: true, force: true });
      } catch {
        /* ignore */
      }
    },
  };
}

export async function resolveTarget(target, options = {}) {
  const skillPath = sparsePathFromSkillOption(options.skill);
  const subdirOpt = normalizeSubdir(options.subdir);
  if (skillPath && subdirOpt) {
    throw new ResolverError(
      "Use either --skill or --subdir, not both.",
      "SKILL_SUBDIR_CONFLICT",
    );
  }
  const effectiveSubdir = skillPath ?? subdirOpt;

  const trimmed = target.trim();
  const treeFromUrl = parseGithubTreeUrl(trimmed);
  if (treeFromUrl) {
    if (effectiveSubdir) {
      throw new ResolverError(
        "Do not use --skill or --subdir with a GitHub /tree/... URL; the path is already in the URL.",
        "SKILL_WITH_TREE",
      );
    }
    const cloneUrl = `https://github.com/${treeFromUrl.repoSlug}.git`;
    return cloneSparseCheckout(
      cloneUrl,
      treeFromUrl.branch,
      treeFromUrl.subdir,
      trimmed,
    );
  }

  const detected = detectInputType(trimmed);
  if (detected.kind === "path") {
    if (skillPath) {
      throw new ResolverError(
        "--skill only applies when cloning from GitHub (owner/repo or https://github.com/...).",
        "SKILL_WITH_PATH",
      );
    }
    return {
      rootPath: detected.resolved,
      cleanup: async () => {},
    };
  }

  const cloneUrl = githubCloneUrl(
    detected.kind,
    detected.url,
    detected.repo,
  );

  if (detected.kind === "url") {
    const treeFromHttp = parseGithubTreeUrl(detected.url.trim());
    if (treeFromHttp) {
      if (effectiveSubdir) {
        throw new ResolverError(
          "Do not use --skill or --subdir with a GitHub /tree/... URL; the path is already in the URL.",
          "SKILL_WITH_TREE",
        );
      }
      const cu = `https://github.com/${treeFromHttp.repoSlug}.git`;
      return cloneSparseCheckout(
        cu,
        treeFromHttp.branch,
        treeFromHttp.subdir,
        trimmed,
      );
    }
  }

  if (effectiveSubdir) {
    if (detected.kind === "github") {
      return cloneSparseCheckout(cloneUrl, null, effectiveSubdir, trimmed);
    }
    if (detected.kind === "url" && isGithubHttpsCloneUrl(cloneUrl)) {
      return cloneSparseCheckout(cloneUrl, null, effectiveSubdir, trimmed);
    }
    throw new ResolverError(
      "--skill and --subdir only work with GitHub repos (owner/repo or https://github.com/owner/repo). Use a /tree/branch/path URL to scan a subfolder of a GitHub repo.",
      "SUBDIR_UNSUPPORTED",
    );
  }

  const dir = tmp.dirSync({ unsafeCleanup: true, prefix: "skillrx-" });
  const rootPath = dir.name;
  try {
    await cloneGitRepo(cloneUrl, rootPath, [
      "--depth",
      "1",
      "--single-branch",
    ]);
  } catch (e) {
    try {
      fs.rmSync(rootPath, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
    handleCloneError(e, trimmed);
  }
  return {
    rootPath,
    cleanup: async () => {
      try {
        fs.rmSync(rootPath, { recursive: true, force: true });
      } catch {
        /* ignore */
      }
    },
  };
}

export function walkFiles(rootDir, options = {}) {
  const maxFiles = options.maxFiles;
  const out = [];
  let stopped = false;
  function walk(rel) {
    if (stopped) {
      return;
    }
    const full = path.join(rootDir, rel);
    let entries;
    try {
      entries = fs.readdirSync(full, { withFileTypes: true });
    } catch {
      return;
    }
    for (const ent of entries) {
      if (stopped) {
        return;
      }
      const name = ent.name;
      const subRel = rel ? `${rel}/${name}` : name;
      if (ent.isDirectory()) {
        if (name === ".git" && rel === "") {
          walk(".git/hooks");
          if (stopped) {
            return;
          }
          continue;
        }
        if (SKIP_DIRS.has(name)) {
          continue;
        }
        if (name.startsWith(".") && name !== ".claude") {
          continue;
        }
        walk(subRel);
      } else if (ent.isFile()) {
        out.push(subRel.replace(/\\/g, "/"));
        if (maxFiles != null && out.length >= maxFiles) {
          stopped = true;
          return;
        }
      }
    }
  }
  walk("");
  return out.sort();
}

export function shouldScanFile(relativePath, sizeBytes) {
  const base = path.basename(relativePath);
  const ext = path.extname(relativePath).toLowerCase();
  const norm = relativePath.replace(/\\/g, "/");
  if (
    (norm.includes(".git/hooks/") || norm.includes("committed-hooks/hooks/")) &&
    !base.includes(".")
  ) {
    return { ok: true };
  }
  if (NAME_WHITELIST.has(base)) {
    return { ok: true };
  }
  if (!EXT_WHITELIST.has(ext)) {
    return { ok: false, reason: "extension" };
  }
  if (sizeBytes > SIZE_CAP_BYTES && !NAME_WHITELIST.has(base)) {
    return { ok: false, reason: "size" };
  }
  return { ok: true };
}

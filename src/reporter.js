import chalk from "chalk";
import boxen from "boxen";
import { ANALYZER_WEIGHTS } from "./constants.js";

const sevLabel = {
  high: "HIGH",
  medium: "MED",
  low: "LOW",
};

const SEV_ICON = {
  high: "●",
  medium: "▲",
  low: "■",
};

const TOP_N = 3;

function labelColor(label) {
  if (label === "MALICIOUS" || label === "RISKY") {
    return chalk.red;
  }
  if (label === "CAUTION") {
    return chalk.yellow;
  }
  return chalk.green;
}

function borderColorFor(label) {
  if (label === "MALICIOUS" || label === "RISKY") {
    return "red";
  }
  if (label === "CAUTION") {
    return "yellow";
  }
  return "green";
}

function sevIcon(sev) {
  if (sev === "high") {
    return chalk.red(SEV_ICON.high);
  }
  if (sev === "medium") {
    return chalk.yellow(SEV_ICON.medium);
  }
  return chalk.gray(SEV_ICON.low);
}

function scoreBar(score) {
  const width = 20;
  const filled = Math.max(0, Math.min(width, Math.round((score / 100) * width)));
  const empty = width - filled;
  const color =
    score >= 80 ? chalk.green : score >= 50 ? chalk.yellow : chalk.red;
  return color("█".repeat(filled)) + chalk.gray("░".repeat(empty));
}

function groupKey(f) {
  return `${f.analyzer}|${f.rule}|${f.message}`;
}

function countBySeverity(findings) {
  let high = 0;
  let medium = 0;
  let low = 0;
  for (const f of findings) {
    if (f.severity === "high") {
      high++;
    } else if (f.severity === "medium") {
      medium++;
    } else if (f.severity === "low") {
      low++;
    }
  }
  return { high, medium, low };
}

function countByAnalyzer(findings) {
  const m = new Map();
  for (const f of findings) {
    const k = f.analyzer || "unknown";
    m.set(k, (m.get(k) || 0) + 1);
  }
  return m;
}

function groupFindings(findings) {
  const m = new Map();
  for (const f of findings) {
    const k = groupKey(f);
    const cur = m.get(k) || { count: 0, sample: f };
    cur.count++;
    if (!cur.sample.file && f.file) {
      cur.sample = f;
    }
    m.set(k, cur);
  }
  return m;
}

function formatFullReport(target, score, label, findings, critical) {
  const lines = [];
  lines.push(`skillrx ${target}`);
  lines.push("");
  lines.push(`  Analyzing ${target}...`);
  lines.push("");
  if (critical && critical.length > 0) {
    lines.push(chalk.red.bold("  Critical findings (malicious patterns)"));
    lines.push("  " + "─".repeat(37));
    for (const c of critical.slice(0, 20)) {
      lines.push(
        chalk.red(`  [${c.rule}]   ${c.message || c.rule}`),
      );
      if (c.file) {
        lines.push(`           ${c.file}:${c.line}`);
      }
    }
    if (critical.length > 20) {
      lines.push(chalk.dim(`  ... +${critical.length - 20} more critical`));
    }
    lines.push("");
  }
  const scoreLine =
    label === "MALICIOUS"
      ? chalk.red.bold(`  Score: ${score} / 100   ${label}`)
      : `  Score: ${score} / 100   ${label}`;
  lines.push(scoreLine);
  lines.push("");
  lines.push("  Findings");
  lines.push("  " + "─".repeat(37));
  if (findings.length === 0) {
    lines.push(chalk.gray("  (no findings)"));
  } else {
    for (const f of findings) {
      const tag = sevLabel[f.severity] || f.severity.toUpperCase();
      const color =
        f.severity === "high"
          ? chalk.red
          : f.severity === "medium"
            ? chalk.yellow
            : chalk.gray;
      lines.push(color(`  [${tag}]   ${f.message}`));
      if (f.file) {
        lines.push(`           ${f.file}:${f.line}`);
      }
      if (f.excerpt) {
        lines.push(
          chalk.dim(
            `           "${f.excerpt.slice(0, 120)}${f.excerpt.length > 120 ? "..." : ""}"`,
          ),
        );
      }
      lines.push("");
    }
  }
  lines.push("  " + "─".repeat(37));
  lines.push(
    label === "MALICIOUS"
      ? "  Exit code: 1  (MALICIOUS — critical rule matched)"
      : `  Exit code: ${score >= 50 ? 0 : 1}  (score ${score >= 50 ? ">=" : "<"} 50)`,
  );
  return lines.join("\n");
}

function truncate(s, n) {
  const str = String(s ?? "");
  if (str.length <= n) {
    return str;
  }
  return str.slice(0, n - 1) + "…";
}

function buildCompactBody(
  target,
  score,
  label,
  findings,
  parsedCount,
  critical,
) {
  const lines = [];
  const lc = labelColor(label);

  const scoreStr =
    label === "MALICIOUS"
      ? chalk.red.bold(`${score}`) + chalk.gray(" / 100")
      : chalk.bold(`${score}`) + chalk.gray(" / 100");
  lines.push(
    `  ${chalk.gray("SCORE")}  ${scoreStr}   ${lc.bold(label)}`,
  );
  lines.push(`  ${scoreBar(score)}`);
  lines.push("");

  const sev = countBySeverity(findings);
  const total = findings.length;
  const filesHit = new Set(findings.map((f) => f.file).filter(Boolean)).size;
  const scanned =
    parsedCount != null && Number.isFinite(parsedCount)
      ? parsedCount
      : filesHit;

  lines.push(
    `  ${sevIcon("high")} ${chalk.red(String(sev.high).padStart(2))} high    ` +
      `${sevIcon("medium")} ${chalk.yellow(String(sev.medium).padStart(2))} medium    ` +
      `${sevIcon("low")} ${chalk.gray(String(sev.low).padStart(2))} low`,
  );
  lines.push(
    chalk.gray(
      `  ${total} findings · ${filesHit} / ${scanned} files scanned`,
    ),
  );

  if (critical && critical.length > 0) {
    lines.push("");
    lines.push(chalk.red.bold("  Critical rules matched"));
    for (const c of critical.slice(0, 5)) {
      const file = c.file ? chalk.gray(` — ${c.file}:${c.line}`) : "";
      lines.push(
        chalk.red(`    ${SEV_ICON.high} ${c.message || c.rule}`) + file,
      );
    }
    if (critical.length > 5) {
      lines.push(chalk.dim(`    +${critical.length - 5} more critical`));
    }
  }

  const byAnalyzer = countByAnalyzer(findings);
  if (byAnalyzer.size > 0) {
    lines.push("");
    lines.push(chalk.bold("  By analyzer"));
    const names = [...byAnalyzer.keys()].sort((a, b) => {
      const diff = byAnalyzer.get(b) - byAnalyzer.get(a);
      return diff !== 0 ? diff : a.localeCompare(b);
    });
    for (const name of names.slice(0, 6)) {
      const group = findings.filter((f) => f.analyzer === name);
      const gs = countBySeverity(group);
      const w = ANALYZER_WEIGHTS[name] ?? 1;
      const parts = [];
      if (gs.high) parts.push(`${sevIcon("high")} ${chalk.red(gs.high)}`);
      if (gs.medium)
        parts.push(`${sevIcon("medium")} ${chalk.yellow(gs.medium)}`);
      if (gs.low) parts.push(`${sevIcon("low")} ${chalk.gray(gs.low)}`);
      const dist = parts.join("  ") || chalk.gray("—");
      lines.push(
        `    ${name.padEnd(18)} ${dist}   ${chalk.gray(`(w ${w})`)}`,
      );
    }
  }

  const highs = findings.filter((f) => f.severity === "high");
  const meds = findings.filter((f) => f.severity === "medium");

  if (highs.length + meds.length > 0) {
    lines.push("");
    lines.push(chalk.bold("  Top issues"));

    const shown = [];
    for (let i = 0; i < Math.min(TOP_N, highs.length); i++) {
      shown.push(highs[i]);
    }
    if (shown.length < TOP_N) {
      const medGroups = groupFindings(meds);
      const medSorted = [...medGroups.values()].sort(
        (a, b) => b.count - a.count,
      );
      for (const g of medSorted) {
        if (shown.length >= TOP_N) break;
        shown.push({
          ...g.sample,
          _count: g.count,
        });
      }
    }

    for (const f of shown) {
      const multi = f._count > 1 ? chalk.dim(` ×${f._count}`) : "";
      lines.push(
        `    ${sevIcon(f.severity)} ${truncate(f.message, 56)}${multi}`,
      );
      if (f.file) {
        lines.push(chalk.gray(`        ${f.file}:${f.line}`));
      }
    }

    const remaining =
      highs.length + meds.length + findings.filter((f) => f.severity === "low").length -
      shown.length;
    if (remaining > 0) {
      lines.push(
        chalk.dim(`    +${remaining} more — run with --full to see all`),
      );
    }
  }

  if (total === 0 && (!critical || critical.length === 0)) {
    lines.push("");
    lines.push(chalk.green("  No findings. Clean."));
  }

  return lines.join("\n");
}

function formatCompactReport(
  target,
  score,
  label,
  findings,
  parsedCount,
  critical,
) {
  const title =
    `${chalk.bold.cyan("skillrx")} ${chalk.gray("·")} ${chalk.white(target)}`;
  const body = buildCompactBody(
    target,
    score,
    label,
    findings,
    parsedCount,
    critical,
  );
  const exitNote =
    label === "MALICIOUS"
      ? chalk.red("  exit 1 — MALICIOUS (critical rule matched)")
      : chalk.gray(
          `  exit ${score >= 50 ? 0 : 1} — score ${score >= 50 ? "≥" : "<"} 50`,
        );
  const content = `${body}\n\n${exitNote}`;
  return boxen(content, {
    title,
    titleAlignment: "left",
    padding: { top: 1, right: 2, bottom: 1, left: 1 },
    margin: { top: 1, right: 0, bottom: 1, left: 0 },
    borderStyle: label === "MALICIOUS" ? "double" : "round",
    borderColor: borderColorFor(label),
  });
}

export function formatReport(target, score, label, findings, options = {}) {
  const critical = options.critical || [];
  if (options.json) {
    return JSON.stringify(
      {
        target,
        score,
        label,
        critical,
        findings,
        exitCode: score >= 50 ? 0 : 1,
      },
      null,
      2,
    );
  }
  if (options.full) {
    return formatFullReport(target, score, label, findings, critical);
  }
  return formatCompactReport(
    target,
    score,
    label,
    findings,
    options.parsedCount,
    critical,
  );
}

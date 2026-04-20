import {
  ANALYZER_WEIGHTS,
  SEVERITY_PENALTY,
  CRITICAL_RULES,
  ANALYZER_PENALTY_CAP,
  TOTAL_PENALTY_CAP_NONMALICIOUS,
} from "./constants.js";

export function dedupeFindings(findings) {
  const seen = new Set();
  return findings.filter((f) => {
    const k = `${f.file}:${f.line}:${f.rule}:${f.analyzer}`;
    if (seen.has(k)) {
      return false;
    }
    seen.add(k);
    return true;
  });
}

export function scoreFindings(findings) {
  const criticalHits = findings.filter((f) => CRITICAL_RULES.has(f.rule));
  if (criticalHits.length > 0) {
    return { score: 0, label: "MALICIOUS", critical: criticalHits };
  }
  const perAnalyzer = new Map();
  for (const f of findings) {
    const base = SEVERITY_PENALTY[f.severity] ?? 10;
    const w = ANALYZER_WEIGHTS[f.analyzer] ?? 1;
    const p = base * w;
    const a = f.analyzer || "unknown";
    perAnalyzer.set(a, (perAnalyzer.get(a) || 0) + p);
  }
  let totalPenalty = 0;
  for (const [a, p] of perAnalyzer) {
    const cap = ANALYZER_PENALTY_CAP[a] ?? 60;
    totalPenalty += Math.min(p, cap);
  }
  totalPenalty = Math.min(totalPenalty, TOTAL_PENALTY_CAP_NONMALICIOUS);
  const score = Math.max(0, Math.round(100 - totalPenalty));
  return { score, label: labelForScore(score), critical: [] };
}

export function labelForScore(score) {
  if (score >= 80) {
    return "TRUSTED";
  }
  if (score >= 50) {
    return "CAUTION";
  }
  return "RISKY";
}

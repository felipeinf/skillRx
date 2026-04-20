import { analyzePromptInjection } from "./promptInjection.js";
import { analyzeShadowFeatures } from "./shadowFeatures.js";
import { analyzeExfiltration } from "./exfiltration.js";
import { analyzeSecretsAndCreds } from "./secretsAndCreds.js";
import { analyzeDangerousPerms } from "./dangerousPerms.js";
import { analyzePostinstall } from "./postinstall.js";

const RUNNERS = [
  ["promptInjection", analyzePromptInjection],
  ["shadowFeatures", analyzeShadowFeatures],
  ["exfiltration", analyzeExfiltration],
  ["secretsAndCreds", analyzeSecretsAndCreds],
  ["dangerousPerms", analyzeDangerousPerms],
  ["postinstall", analyzePostinstall],
];

export function runAllAnalyzers(parsedFiles, log, onPhase) {
  const all = [];
  for (const [name, fn] of RUNNERS) {
    if (onPhase) {
      onPhase(name);
    }
    try {
      const part = fn(parsedFiles);
      all.push(...part);
    } catch (e) {
      if (log) {
        log(`Analyzer ${name} failed: ${e?.message || e}`);
      }
    }
  }
  return all;
}

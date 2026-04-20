import { Command } from "commander";
import ora from "ora";
import chalk from "chalk";
import {
  resolveTarget,
  walkFiles,
  shouldScanFile,
  ResolverError,
} from "./resolver.js";
import { parseWorkspace } from "./parser.js";
import { runAllAnalyzers } from "./analyzers/index.js";
import { dedupeFindings, scoreFindings } from "./scorer.js";
import { formatReport } from "./reporter.js";

const PHASE_LABEL = {
  resolve: "Resolviendo origen",
  parse: "Leyendo archivos",
  promptInjection: "Analizando prompt injection",
  shadowFeatures: "Revisando capacidades ocultas",
  exfiltration: "Buscando exfiltración",
  secretsAndCreds: "Detectando secretos",
  dangerousPerms: "Permisos peligrosos",
  postinstall: "Scripts post-install",
  done: "Scan completado",
};

export async function scanTarget(target, options = {}) {
  const onPhase = options.onPhase;
  if (onPhase) {
    onPhase("resolve");
  }
  const { rootPath, cleanup } = await resolveTarget(target, {
    subdir: options.subdir,
    skill: options.skill,
  });
  try {
    if (onPhase) {
      onPhase("parse");
    }
    const cap = options.maxFiles;
    const walkOpts =
      cap != null && Number.isFinite(cap) && cap > 0 ? { maxFiles: cap } : {};
    const files = walkFiles(rootPath, walkOpts);
    const { parsed, readErrors } = await parseWorkspace(
      rootPath,
      files,
      shouldScanFile,
    );
    if (options.verbose && readErrors.length > 0) {
      for (const e of readErrors) {
        console.error(`Read error ${e.rel}: ${e.error}`);
      }
    }
    const log = options.verbose ? (m) => console.error(m) : null;
    let findings = runAllAnalyzers(parsed, log, onPhase);
    findings = dedupeFindings(findings);
    const classified = scoreFindings(findings);
    if (onPhase) {
      onPhase("done");
    }
    return {
      target,
      rootPath,
      score: classified.score,
      label: classified.label,
      critical: classified.critical,
      findings,
      readErrors,
      parsedCount: parsed.length,
    };
  } finally {
    await cleanup();
  }
}

export async function runCli(argv) {
  const program = new Command();
  program
    .name("skillrx")
    .description("Static analysis scanner for Claude Code plugins and skills")
    .version("0.1.0")
    .argument("<target>", "Local path, owner/repo, or https Git URL")
    .option("--json", "Output JSON report")
    .option(
      "--full",
      "Show every finding with file and excerpt instead of compact summary",
    )
    .option(
      "--skill <name>",
      "With owner/repo or github.com HTTPS URL, scan only skills/<name> (sparse checkout)",
    )
    .option(
      "--subdir <path>",
      "Clone only this path inside the repo (sparse checkout); use --skill for skills/<name>",
    )
    .option("-v, --verbose", "Verbose logging");
  program.parse(argv);
  const opts = program.opts();
  const target = program.args[0];
  if (!target) {
    program.help();
    process.exit(1);
  }
  const showSpinner =
    !opts.json && !opts.verbose && process.stderr.isTTY && !process.env.NO_COLOR;
  let spinner = null;
  const startTs = Date.now();
  if (showSpinner) {
    process.stderr.write(
      "\n" + chalk.cyan.bold("  skillrx") + chalk.gray(` · ${target}\n\n`),
    );
    spinner = ora({
      text: PHASE_LABEL.resolve,
      stream: process.stderr,
      spinner: "dots",
      color: "cyan",
    }).start();
  }
  const onPhase = (phase) => {
    if (!spinner) return;
    if (phase === "done") {
      const ms = Date.now() - startTs;
      spinner.succeed(chalk.green(`Scan completado en ${ms} ms`));
      spinner = null;
      return;
    }
    spinner.text = PHASE_LABEL[phase] || phase;
  };

  try {
    const result = await scanTarget(target, {
      json: opts.json,
      verbose: opts.verbose,
      subdir: opts.subdir,
      skill: opts.skill,
      onPhase,
    });
    if (result.parsedCount === 0) {
      console.error(
        "Warning: no scannable files found (check extensions and size limits). Score defaults to 100.",
      );
    }
    const effectiveScore =
      result.parsedCount === 0 && result.findings.length === 0
        ? 100
        : result.score;
    const effectiveLabel =
      result.parsedCount === 0 && result.findings.length === 0
        ? "TRUSTED"
        : result.label;
    const effectiveCritical =
      result.parsedCount === 0 && result.findings.length === 0
        ? []
        : result.critical || [];
    const findings =
      result.parsedCount === 0 && result.findings.length === 0
        ? []
        : result.findings;
    const out = formatReport(target, effectiveScore, effectiveLabel, findings, {
      json: opts.json,
      full: opts.full,
      parsedCount: result.parsedCount,
      critical: effectiveCritical,
    });
    console.log(out);
    const code = effectiveScore >= 50 ? 0 : 1;
    process.exit(code);
  } catch (e) {
    if (spinner) {
      spinner.fail(chalk.red("Scan falló"));
      spinner = null;
    }
    if (e instanceof ResolverError) {
      console.error(e.message);
      process.exit(1);
    }
    console.error(e?.stack || e?.message || String(e));
    process.exit(1);
  }
}

const SENSITIVE_PATH_RE =
  /~\/\.(ssh|aws|claude|gnupg|config)(\/|\b)/;

const REVERSE_SHELL_RE =
  /bash\s+-i\s+>&|\/dev\/tcp\/|nc\s+[^;\n]*\s+-e|python\s+-c\s+['"]import\s+socket/;

const OBFUSC_SHELL_RE =
  /base64\s+[-‑]?\s*d\s*\|\s*(ba)?sh|\\x[0-9a-f]{2}/i;

const PERSIST_RE =
  /\b(crontab|launchctl)\b|>>\s*~\/\.(bashrc|zshrc)/;

const POWERSHELL_IEX_RE =
  /\b(IEX\s*\(|Invoke-Expression|DownloadString|-ExecutionPolicy\s+Bypass|-enc\s+[A-Za-z0-9+\/=]{20,})/i;

const WINDOWS_LOLBIN_RE =
  /\b(certutil\s+-decode|mshta\s|regsvr32\s.*scrobj|wmic\s+process\s+call\s+create)/i;

const DOCKER_SOCK_RE = /\/var\/run\/docker\.sock\b/;

const FIREWALL_DISABLE_RE =
  /\b(iptables\s+-F|ufw\s+disable|pfctl\s+-d|netsh\s+advfirewall\s+set\s+allprofiles\s+state\s+off)/i;

const KERNEL_MODULE_RE =
  /\b(insmod|kextload|modprobe\s+)/;

const STORAGE_WIPE_RE =
  /\bdd\s+if=\/dev\/(zero|urandom)|shred\s+-|mkfs\./;

const BROWSER_COOKIE_RE =
  /\b(Cookies\.sqlite|Login Data|Local State|Login Keychain)\b/;

const KEYRING_HARVEST_RE =
  /\b(secret-tool\s+(lookup|search)|gnome-keyring|pass\s+show)\b/;

const ETC_SHADOW_RE = /\/etc\/(shadow|sudoers|passwd)\b(?!.*\|)/;

function looksLikeAgentConfigFile(relPath) {
  if (/\.(json|ya?ml|toml)$/i.test(relPath)) {
    return true;
  }
  const base = relPath.split("/").pop().toLowerCase();
  return /^(settings|hooks|agent|claude|codex)\b/.test(base);
}

const AGENT_HOOK_KEY_RE =
  /["']?\b(hooks|onStart|onStop|statusLine|PreToolUse|PostToolUse|SessionStart|Stop)\b["']?\s*:/;

const SHELL_TOKEN_RE =
  /\b(curl|wget|bash|sh|zsh|powershell|cmd|python\s+-c|node\s+-e)\b/i;

export function analyzeDangerousPerms(parsedFiles) {
  const analyzer = "dangerousPerms";
  const findings = [];
  for (const pf of parsedFiles) {
    const file = pf.relativePath;
    const t = pf.content;
    if (/sudo\b|chmod\s+777|\bchown\b/.test(t)) {
      const idx = t.search(/sudo\b|chmod\s+777|\bchown\b/);
      const line = t.slice(0, idx).split(/\r?\n/).length;
      findings.push({
        analyzer,
        severity: "medium",
        file,
        line,
        rule: "privilege-escalation",
        excerpt: t.slice(idx, idx + 40),
        message: "Possible privilege escalation command",
      });
    }
    if (/rm\s+-rf\b/.test(t) && !/\/tmp\b|\/var\/folders|mktemp/i.test(t)) {
      const idx = t.search(/rm\s+-rf\b/);
      const line = t.slice(0, idx).split(/\r?\n/).length;
      findings.push({
        analyzer,
        severity: "medium",
        file,
        line,
        rule: "rm-rf",
        excerpt: "rm -rf",
        message: "rm -rf outside obvious temp paths",
      });
    }
    if (SENSITIVE_PATH_RE.test(t)) {
      const idx = t.search(SENSITIVE_PATH_RE);
      const line = t.slice(0, idx).split(/\r?\n/).length;
      findings.push({
        analyzer,
        severity: "high",
        file,
        line,
        rule: "sensitive-path",
        excerpt: t.slice(idx, idx + 40),
        message: "Reference to sensitive user directory",
      });
    }
    if (/security\s+find-generic-password|\.bash_history|\.zsh_history|git\s+config\s+--get\s+credential\.helper/.test(
      t,
    )) {
      findings.push({
        analyzer,
        severity: "high",
        file,
        line: 1,
        rule: "credential-harvest",
        excerpt: "credential access",
        message: "Possible credential harvesting pattern",
      });
    }
    if (REVERSE_SHELL_RE.test(t)) {
      const idx = t.search(REVERSE_SHELL_RE);
      const line = t.slice(0, idx).split(/\r?\n/).length;
      findings.push({
        analyzer,
        severity: "high",
        file,
        line,
        rule: "reverse-shell",
        excerpt: t.slice(idx, idx + 50),
        message: "Possible reverse shell pattern",
      });
    }
    if (OBFUSC_SHELL_RE.test(t)) {
      const idx = t.search(OBFUSC_SHELL_RE);
      const line = t.slice(0, idx).split(/\r?\n/).length;
      findings.push({
        analyzer,
        severity: "high",
        file,
        line,
        rule: "obfuscated-shell",
        excerpt: "obfuscated shell",
        message: "Obfuscated shell execution",
      });
    }
    if (PERSIST_RE.test(t)) {
      findings.push({
        analyzer,
        severity: "high",
        file,
        line: 1,
        rule: "persistence",
        excerpt: "persistence",
        message: "Possible persistence mechanism",
      });
    }
    if (/\$(TOKEN|SECRET|API_KEY|PASSWORD|PRIVATE_KEY)\b/.test(t)) {
      findings.push({
        analyzer,
        severity: "medium",
        file,
        line: 1,
        rule: "sensitive-env-var",
        excerpt: "$SECRET",
        message: "Sensitive environment variable referenced in commands",
      });
    }
    if (file.endsWith(".claude/settings.json") || file.endsWith("settings.json")) {
      if (/permissions\.allow|"Bash\(\*\)"|"Read\(\*\*\)"/.test(t)) {
        findings.push({
          analyzer,
          severity: "high",
          file,
          line: 1,
          rule: "claude-wide-perms",
          excerpt: "wildcard permissions",
          message: "Claude settings allow overly broad tool wildcards",
        });
      }
    }
    if (/PreToolUse|PostToolUse|SessionStart|Stop/.test(t) && /command\s*:\s*["']?[^"'\n]+(curl|bash|sh)/i.test(t)) {
      findings.push({
        analyzer,
        severity: "high",
        file,
        line: 1,
        rule: "claude-hook-shell",
        excerpt: "hook",
        message: "Hook configuration may execute shell commands",
      });
    }
    if (/statusLine\.command/.test(t) && /curl|wget|bash/i.test(t)) {
      findings.push({
        analyzer,
        severity: "high",
        file,
        line: 1,
        rule: "statusline-cmd",
        excerpt: "statusLine.command",
        message: "Suspicious statusLine.command",
      });
    }
    if (/tools\s*:\s*['"]\*['"]/.test(t) || /"tools"\s*:\s*"\*"/.test(t)) {
      findings.push({
        analyzer,
        severity: "high",
        file,
        line: 1,
        rule: "agent-tools-star",
        excerpt: "tools:*",
        message: "Agent manifest allows all tools",
      });
    }

    // PowerShell IEX detection
    if (POWERSHELL_IEX_RE.test(t)) {
      const idx = t.search(POWERSHELL_IEX_RE);
      const line = t.slice(0, idx).split(/\r?\n/).length;
      findings.push({
        analyzer,
        severity: "high",
        file,
        line,
        rule: "powershell-iex",
        excerpt: "IEX/Invoke-Expression",
        message: "PowerShell code execution pattern (IEX/Invoke-Expression)",
      });
    }

    // Windows LOLBin detection
    if (WINDOWS_LOLBIN_RE.test(t)) {
      const idx = t.search(WINDOWS_LOLBIN_RE);
      const line = t.slice(0, idx).split(/\r?\n/).length;
      findings.push({
        analyzer,
        severity: "high",
        file,
        line,
        rule: "windows-lolbin",
        excerpt: t.slice(idx, idx + 40),
        message: "Windows Living-off-the-Land binary (LOLBin) detected",
      });
    }

    // Docker socket access
    if (DOCKER_SOCK_RE.test(t)) {
      const idx = t.search(DOCKER_SOCK_RE);
      const line = t.slice(0, idx).split(/\r?\n/).length;
      findings.push({
        analyzer,
        severity: "high",
        file,
        line,
        rule: "docker-sock",
        excerpt: "/var/run/docker.sock",
        message: "Direct Docker socket access (privilege escalation vector)",
      });
    }

    // Firewall disable
    if (FIREWALL_DISABLE_RE.test(t)) {
      const idx = t.search(FIREWALL_DISABLE_RE);
      const line = t.slice(0, idx).split(/\r?\n/).length;
      findings.push({
        analyzer,
        severity: "high",
        file,
        line,
        rule: "firewall-disable",
        excerpt: t.slice(idx, idx + 40),
        message: "Firewall disable command detected",
      });
    }

    // Kernel module operations
    if (KERNEL_MODULE_RE.test(t)) {
      const idx = t.search(KERNEL_MODULE_RE);
      const line = t.slice(0, idx).split(/\r?\n/).length;
      findings.push({
        analyzer,
        severity: "high",
        file,
        line,
        rule: "kernel-module-load",
        excerpt: t.slice(idx, idx + 30),
        message: "Kernel module load command (insmod/modprobe)",
      });
    }

    // Storage wipe operations
    if (STORAGE_WIPE_RE.test(t)) {
      const idx = t.search(STORAGE_WIPE_RE);
      const line = t.slice(0, idx).split(/\r?\n/).length;
      findings.push({
        analyzer,
        severity: "high",
        file,
        line,
        rule: "storage-wipe",
        excerpt: t.slice(idx, idx + 30),
        message: "Storage destruction command (dd/shred/mkfs)",
      });
    }

    // Browser cookie harvest
    if (BROWSER_COOKIE_RE.test(t)) {
      findings.push({
        analyzer,
        severity: "high",
        file,
        line: 1,
        rule: "browser-cookie-harvest",
        excerpt: "browser credentials",
        message: "Browser credential/cookie database referenced",
      });
    }

    // Linux keyring harvest
    if (KEYRING_HARVEST_RE.test(t)) {
      findings.push({
        analyzer,
        severity: "high",
        file,
        line: 1,
        rule: "linux-keyring-harvest",
        excerpt: "keyring",
        message: "Linux keyring/password manager harvest pattern",
      });
    }

    // /etc/shadow, /etc/sudoers, /etc/passwd read
    if (ETC_SHADOW_RE.test(t)) {
      const idx = t.search(ETC_SHADOW_RE);
      const line = t.slice(0, idx).split(/\r?\n/).length;
      findings.push({
        analyzer,
        severity: "high",
        file,
        line,
        rule: "etc-sensitive-read",
        excerpt: t.slice(idx, idx + 20),
        message: "Sensitive system file access (/etc/shadow, /etc/sudoers, /etc/passwd)",
      });
    }

    if (
      looksLikeAgentConfigFile(file) &&
      AGENT_HOOK_KEY_RE.test(t) &&
      SHELL_TOKEN_RE.test(t)
    ) {
      const idx = t.search(AGENT_HOOK_KEY_RE);
      const line = t.slice(0, idx).split(/\r?\n/).length;
      findings.push({
        analyzer,
        severity: "high",
        file,
        line,
        rule: "agent-config-hook-shell",
        excerpt: "hook with shell exec",
        message: "Agent config hook or callback may execute shell commands",
      });
    }

    // Dotfile persistence
    if (/>>\s*~\/\.(bash_profile|profile|zprofile|bash_logout)|>>\s*\/etc\/profile/.test(t)) {
      findings.push({
        analyzer,
        severity: "medium",
        file,
        line: 1,
        rule: "dotfile-persistence",
        excerpt: "dotfile append",
        message: "Appending to shell initialization files (persistence)",
      });
    }
  }
  return findings;
}

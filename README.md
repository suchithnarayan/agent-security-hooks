# Agent Security Hooks

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

A Python-based security monitoring system that integrates with AI coding assistant hooks to validate commands against blacklists, block dangerous operations, and log all activities for compliance auditing.

**Designed for Safety**: Built with a "fail-closed" architecture, security-conscious defaults, and sensitive data redaction to prevent accidental operations or data leaks by AI agents.

## Table of Contents

- [Supported Platforms](#supported-platforms)
- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Configuration](#configuration)
- [Audit Logs](#audit-logs)
- [CLI Reference](#cli-reference)
- [Security Controls](#security-controls)
- [Development](#development)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)
- [References](#references)

## Supported Platforms

| Platform | Config File | Documentation |
|----------|-------------|---------------|
| **Claude Code** | `.claude/settings.json` | [code.claude.com/docs/en/hooks](https://code.claude.com/docs/en/hooks) |
| **Cursor** | `.cursor/hooks.json` | [cursor.com/docs/agent/hooks](https://cursor.com/docs/agent/hooks) |
| **Gemini CLI** | `.gemini/settings.json` | [geminicli.com/docs/hooks](https://geminicli.com/docs/hooks/) |

## Features

- **Command Validation** - Block dangerous shell commands (`rm -rf`, `kubectl delete cluster`, etc.)
- **File Protection** - Prevent access to sensitive files (`.env`, `secrets/`, `*.pem`, etc.)
- **Confirmation Prompts** - Require approval for risky operations (`kubectl apply`, `git push`, etc.)
- **Audit Logging** - JSON Lines logs for compliance and forensics
- **Multi-Platform** - Single tool works with Claude Code, Cursor, and Gemini CLI
- **Security-First Design** - Fail-closed on errors and anti-obfuscation rules over `sh` and `eval`.

## Architecture

```text
                                       +------------------+
                                       |  Configuration   |
                                       | (blacklist.yaml) |
                                       +--------+---------+
                                                ^
                                                | 5. Match Patterns
                                                |
+--------------------+                 +--------+---------+
|   AI Environment   | 1. Trigger Hook |     Security     |
| (Claude / Cursor / |---------------->|    Validator     |
|      Gemini)       |                 +--------+---------+
+--------+-----------+                          ^
         ^                                      | 4. Validate
         | 8. Exit Code                +--------+---------+
         | (0=Allow, 2=Block)          | Platform Adapter |
         +-----------------------------|   (Normalizer)   |
                                       +--------+---------+
                                                ^
                                                | 3. Dispatch
                                                |
                                       +--------+---------+
                                       | CLI Entry Point  |
                                       |   (Safe Load)    |
                                       +--------+---------+
                                                |
                                                | 6. Log Decision
                                                v
                                       +--------+---------+       7. Write
                                       |   Audit Logger   |------------------+
                                       | (Redacts Secrets)|                  |
                                       +------------------+                  v
                                                                    +-----------------+
                                                                    |   Audit Logs    |
                                                                    |    (JSONL)      |
                                                                    +-----------------+
```

## Installation

### Prerequisites

- **Python 3.10+**
- **pip** (or another Python package installer)
- One of: [Claude Code](https://code.claude.com/), [Cursor](https://cursor.com/), or [Gemini CLI](https://geminicli.com/) (for hook integration)

### From Source

Using a [virtual environment](https://docs.python.org/3/library/venv.html) is recommended.

```bash
git clone https://github.com/suchith-narayan/agent-security-hooks.git
cd agent-security-hooks
pip install -e .

# Install configuration
mkdir -p ~/.config/agent-security-hooks
cp config/blacklist.yaml ~/.config/agent-security-hooks/
chmod 644 ~/.config/agent-security-hooks/blacklist.yaml   # ensure hook process can read it
```

### Verify Installation

```bash
agent-security-hooks --help

# Verify config is found
python3 -c "from agent_security_hooks.cli import get_config_path; print('Config:', get_config_path())"
```

**⚠️ Important:** Without the configuration file, the security hooks will allow all commands!

### 2. Configure Your AI Tool

#### Claude Code

Copy the hook configuration to your Claude settings:

```bash
# Project-level
mkdir -p .claude
cp hooks/claude/settings.json .claude/

# Or user-level
cp hooks/claude/settings.json ~/.claude/settings.json
```

Or add hooks to your existing `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": "Bash",
      "hooks": [{
        "type": "command",
        "command": "agent-security-hooks --platform claude --event pre"
      }]
    }],
    "PostToolUse": [{
      "matcher": "*",
      "hooks": [{
        "type": "command",
        "command": "agent-security-hooks --platform claude --event post"
      }]
    }]
  }
}
```

#### Cursor

Copy the hook configuration:

```bash
# Project-level
mkdir -p .cursor
cp hooks/cursor/hooks.json .cursor/

# Or user-level
cp hooks/cursor/hooks.json ~/.cursor/hooks.json
```

#### Gemini CLI

Copy the hook configuration:

```bash
mkdir -p .gemini
cp hooks/gemini/settings.json .gemini/
```

### 3. Test It

Try running a blocked command in your AI tool:

```bash
# This should be blocked
kubectl delete cluster my-cluster

# This should require confirmation
kubectl apply -f deployment.yaml
```

## Configuration

### Blacklist Configuration

The security rules are defined in `config/blacklist.yaml`. You can customize it:

```bash
# Copy to user config directory
mkdir -p ~/.config/agent-security-hooks
cp config/blacklist.yaml ~/.config/agent-security-hooks/

# Edit the rules
vim ~/.config/agent-security-hooks/blacklist.yaml
```

**File permissions:** Use permissions that allow the AI tool’s hook process to read the file (e.g. **644** or **664**). Overly restrictive permissions (e.g. **600**) can cause hook errors when the hook runs in a different context—see [FAQ](#userpromptsubmit--pretooluse--posttooluse-hook-errors-claude-code).

### Rule Format

```yaml
rules:
  - id: unique-rule-id
    pattern: "regex pattern"
    severity: CRITICAL | HIGH | MEDIUM | LOW
    action: block | ask
    category: kubernetes | database | infrastructure | git | system | secrets
    message: "User-friendly message"
    case_insensitive: false  # Optional
```

### Severity Levels

| Severity | Action | Examples |
|----------|--------|----------|
| **CRITICAL** | Block | `rm -rf /`, `kubectl delete cluster`, `terraform destroy` |
| **HIGH** | Block | `git push --force`, `DROP DATABASE`, secret exposure |
| **MEDIUM** | Ask | `kubectl apply`, `git push`, AWS/GCloud commands |
| **LOW** | Log | For audit purposes only |

## Audit Logs

Logs are written to `~/.agent-security-hooks/logs/` in JSON Lines format:

```bash
# View today's logs
cat ~/.agent-security-hooks/logs/audit-$(date +%Y-%m-%d).jsonl | jq .

# Search for blocked operations
grep '"decision":"block"' ~/.agent-security-hooks/logs/*.jsonl | jq .
```

### Log Format

```json
{
  "timestamp": "2026-01-28T12:00:00.000Z",
  "platform": "cursor",
  "event_type": "before_shell",
  "command": "kubectl apply -f deployment.yaml",
  "decision": "ask",
  "reason": "Kubernetes mutation requires confirmation",
  "matched_rules": ["k8s-mutate"],
  "severity": "MEDIUM",
  "category": "kubernetes",
  "user": "developer@example.com",
  "project_dir": "/path/to/project"
}
```

## CLI Reference

```bash
agent-security-hooks [OPTIONS]

Options:
  -p, --platform [claude|cursor|gemini]  AI platform (auto-detected if not specified)
  -e, --event TEXT                       Hook event type (required)
  -c, --config PATH                      Path to blacklist.yaml
  -l, --log-dir PATH                     Directory for audit logs
  -d, --debug                            Enable debug logging to stderr
  --help                                 Show this message and exit
```

### Event Types

| Platform | Events |
|----------|--------|
| Claude Code | `pre`, `post`, `prompt` |
| Cursor | `before-shell`, `after-shell`, `before-read`, `after-edit`, `session-start`, `session-end` |
| Gemini CLI | `before`, `after`, `session_start` |

## Exit Codes

| Code | Meaning | Description |
|----------|--------|----------|
| 0 | Allow | Operation proceeds normally |
| 2 | Block | Operation is rejected (compatible with Claude Code and Cursor) |

## Security Controls

### Commands Blocked (CRITICAL/HIGH)

| Category | Examples |
|----------|----------|
| **Kubernetes** | `kubectl delete cluster`, `kubectl drain`, secret exposure |
| **Database** | `DROP DATABASE`, `TRUNCATE`, `FLUSHALL` |
| **Infrastructure** | `terraform destroy`, `aws delete-*`, `gcloud delete` |
| **Git** | `git push --force`, `git branch -D main` |
| **System** | `rm -rf /`, `chmod 777`, `curl \| bash` |
| **Secrets** | `env \| grep secret`, `cat *.key`, `printenv TOKEN` |

### Commands Requiring Confirmation (MEDIUM)

| Category | Examples |
|----------|----------|
| **Kubernetes** | `kubectl apply`, `kubectl exec`, production namespaces |
| **Helm** | `helm install`, `helm upgrade`, `helm uninstall` |
| **Infrastructure** | `terraform apply`, `pulumi up`, cloud CLI commands |
| **Git** | `git push`, `git merge`, `git rebase` |
| **Database** | `mysql`, `psql`, `mongo`, `redis-cli` |
| **Deployment** | `docker push`, `npm publish`, `ssh` |

### Files Protected

| Pattern | Reason |
|---------|--------|
| `.env`, `.env.*` | Environment secrets |
| `secrets/`, `credentials/` | Credential directories |
| `*.pem`, `*.key`, `*.p12` | Cryptographic material |
| `id_rsa`, `id_ed25519` | SSH keys |
| `terraform.tfstate` | Infrastructure state |
| `.npmrc`, `.pypirc` | Package credentials |

### Known Limitations

> **⚠️ Important:** This tool validates the **literal command string** passed to the hook. It cannot detect or prevent all bypass techniques.

**Shell aliases** can bypass security controls. For example:

```bash
# If a user has this alias in their shell
alias delete_everything='rm -rf /'

# The hook sees "delete_everything", not "rm -rf /"
# This would NOT be blocked
delete_everything
```

**Other potential bypass vectors:**

| Bypass | Example | Mitigation |
|--------|---------|------------|
| **Aliases** | `alias k='kubectl'` then `k delete cluster` | Add rules for common aliases |
| **Shell functions** | `function rmd() { rm -rf "$@"; }` | Cannot be detected |
| **Scripts** | `./my-script.sh` (contains dangerous commands) | Block unknown script execution |
| **Indirect execution** | `xargs rm -rf` | Included in blacklist |
| **Environment variables** | `$CMD` where CMD='rm -rf /' | Cannot be fully detected |

**Recommendations:**

1. **Audit your shell aliases** - Review `~/.bashrc`, `~/.zshrc` for dangerous aliases
2. **Add custom rules** - Extend `blacklist.yaml` with aliases used in your environment
3. **Defense in depth** - Use this tool alongside other security measures (RBAC, network policies, etc.)
4. **Monitor audit logs** - Regularly review logs for suspicious patterns

**🚀 Upcoming Enhancements:**

We're actively working on advanced techniques to address these bypass vectors:

- **Alias expansion** - Resolve shell aliases before validation by querying the user's shell configuration
- **LLM-based semantic analysis** - Use language models to detect dangerous intent even when commands are obfuscated or aliased
- **Script content scanning** - Analyze script files before execution to detect dangerous patterns
- **Behavioral analysis** - Learn normal usage patterns and flag anomalies

Stay tuned for updates. Contributions and ideas are welcome.

## Development

### Setup

```bash
git clone https://github.com/suchith-narayan/agent-security-hooks.git
cd agent-security-hooks
pip install -e ".[dev]"
```

### Run Tests

```bash
pytest
pytest --cov=agent_security_hooks
```

### Project Structure

```
agent-security-hooks/
├── src/agent_security_hooks/
│   ├── __init__.py
│   ├── validator.py      # Pattern matching engine
│   ├── logger.py         # JSON audit logging
│   ├── cli.py            # CLI entry point
│   └── adapters/
│       ├── claude.py     # Claude Code adapter
│       ├── cursor.py     # Cursor adapter
│       └── gemini.py     # Gemini CLI adapter
├── config/
│   └── blacklist.yaml    # Security rules
├── hooks/
│   ├── claude/           # Claude Code config
│   ├── cursor/           # Cursor config
│   └── gemini/           # Gemini CLI config
├── tests/
└── logs/                 # Audit logs (gitignored)
```

## Troubleshooting

### Hooks Not Running

1. Ensure `agent-security-hooks` is in your PATH
2. Check hook configuration syntax
3. Restart the AI tool
4. Enable debug mode: `agent-security-hooks --debug ...`

### Claude Code PreToolUse Not Blocking

Claude Code's PreToolUse event requires **hookSpecificOutput** (not top-level `decision`/`reason`). This project outputs `hookSpecificOutput` with `hookEventName: "PreToolUse"`, `permissionDecision` ("deny" or "ask"), and `permissionDecisionReason`. If blocks are ignored, ensure your Claude Code version supports this format and that the hook receives JSON on stdin.

### Gemini CLI Output Issues

Gemini CLI requires **strict JSON on stdout only**. Any non-JSON text (including debug or log messages) on stdout breaks parsing and the CLI defaults to "Allow". All logging and debug output from this tool goes to **stderr**; Gemini CLI does not parse stderr, so it is safe for diagnostics. If hooks default to "Allow", check that nothing is printed to stdout before or after the single JSON object.

### Permission Denied

Ensure the hook script is executable and `agent-security-hooks` is installed:

```bash
which agent-security-hooks
agent-security-hooks --help
```

## FAQ

### UserPromptSubmit / PreToolUse / PostToolUse hook errors (Claude Code)

If you see **UserPromptSubmit hook error**, **PreToolUse: Bash hook error**, or **PostToolUse: Bash hook error** in Claude Code, the hook may be failing to read the config. A common cause is **blacklist.yaml file permissions**.

- **Cause:** If `blacklist.yaml` has permissions **600** (owner read/write only), the process that runs the hook (e.g. Claude Code’s subprocess) may run as a different user or in a context that cannot read the file. The hook then fails and Claude Code reports a hook error.
- **Fix:** Use permissions that allow the hook process to read the file, for example **644** (owner read/write, others read) or **664** (owner/group read/write, others read):

  ```bash
  chmod 644 ~/.config/agent-security-hooks/blacklist.yaml
  # or
  chmod 664 ~/.config/agent-security-hooks/blacklist.yaml
  ```

  Ensure the path matches where your config lives (e.g. `~/.config/agent-security-hooks/` or project `config/blacklist.yaml`).

### How does "ask" mode work differently across platforms?

Rules with `action: ask` in `blacklist.yaml` require confirmation before execution, but behavior varies by platform:

- **Claude Code**: Shows an **interactive permission dialog**. Users can approve to proceed or deny to block. This is the only platform with true interactive confirmation.
- **Cursor**: **Treats "ask" as a hard block** with a denial message prefixed with "⚠️ Confirmation required:". Operations are blocked, and users must manually approve or modify commands and retry. The message helps distinguish review-needed operations from hard blocks.
- **Gemini CLI**: **Treats "ask" as a hard block**. Operations are denied with a "Confirmation required:" message, and users must manually modify/approve commands.

**Why the limitation?** Both Cursor and Gemini CLI's hook protocols only support `allow` or `deny` decisions—there is no native "ask for confirmation" decision type. Only Claude Code's hook protocol supports interactive permission dialogs with `permissionDecision: "ask"`.

## Contributing

Contributions are welcome. Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Add tests for new functionality
4. Run the test suite (`pytest`)
5. Submit a pull request

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, code style, and pull request guidelines.

## Security

If you discover a security vulnerability, please **do not** open a public issue. Report it responsibly by emailing the maintainers or using the repository’s private vulnerability reporting (e.g. GitHub Security Advisories). See [CONTRIBUTING.md](CONTRIBUTING.md) for contact details.

## License

Apache License 2.0 - See [LICENSE](LICENSE) for details.

## References

- [Claude Code Hooks](https://code.claude.com/docs/en/hooks)
- [Cursor Hooks](https://cursor.com/docs/agent/hooks)
- [Gemini CLI Hooks](https://geminicli.com/docs/hooks/)


# Skill Evaluator

Security auditor for Claude Code skills. Analyzes any SKILL.md file for vulnerabilities and produces a risk report directly in chat.

## What it checks

| Category | What it finds |
|----------|---------------|
| Prompt Injection | Hidden instructions, role override, base64, unicode tricks |
| Data Exfiltration | Reading .env/.ssh, webhook URLs, tracking pixels |
| Command Injection | Dangerous shell commands, package installs, curl pipes |
| MCP/Tool Abuse | Unauthorized network access, MCP server additions |
| Scope Creep | Overly broad triggers, persistence via hooks/cron/config |
| Third-Party Dependencies | Unknown npm/pip packages, CDN links, npx execution |

**Risk levels:** LOW / MEDIUM / HIGH / CRITICAL

## Usage

Point it at a local file or GitHub URL:

```
Evaluate this skill: https://github.com/someone/repo/tree/main/my-skill
```

```
Is this skill safe? /path/to/SKILL.md
```

## Getting started

1. Copy `SKILL.md` into your project directory
2. Start Claude Code
3. Ask it to evaluate any skill you are considering installing

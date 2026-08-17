# Plutonium Skill

The official Plutonium Skill brings Plutonium's signed security assessments into Claude, Codex, and Cursor. It helps users review AI connectors, desktop extensions, MCP servers, plugins, and skills across Claude, Microsoft Copilot, and the Plutonium Market-Space.

The Skill is read-only. It does not install, enable, disable, configure, or execute the product being assessed.

## What it provides

- Plutonium risk ratings or reviewed Market-Space status
- Key permissions, capabilities, and tool-level warnings
- The strongest published security risks and risk-reduction guidance
- Clear handling of ambiguous product names across ecosystems
- A direct link to the complete assessment on [Plutonium](https://plutonium.pluto.security/)

## Install

The published ZIP is identical for every host. Only the skills directory differs:

| Host | Skills directory |
| --- | --- |
| Claude Code | `~/.claude/skills` |
| Codex CLI | `${CODEX_HOME:-~/.codex}/skills` |
| Cursor | `~/.cursor/skills` |

### Claude.ai

1. Download the ZIP from the [latest GitHub release](https://github.com/plutosecurity/plutonium-skill/releases/latest). Each release also includes a `SHA256SUMS` file for verification.
2. Open **Customize → Skills → + → Create skill → Upload a skill**.
3. Upload the downloaded ZIP without extracting it, then enable **Plutonium Skill**.

### Claude Code, Codex CLI, and Cursor

Set `SKILLS_DIR` to the row above for your host, then run:

```bash
SKILLS_DIR="$HOME/.claude/skills"  # or "${CODEX_HOME:-$HOME/.codex}/skills", or "$HOME/.cursor/skills"
skill_zip="$(mktemp -t plutonium-skill)"
curl -fsSL "https://github.com/plutosecurity/plutonium-skill/releases/download/v0.1.0/plutonium-skill-0.1.0.zip" -o "$skill_zip"
echo "0c506fb8a35c171df33f85bb630f26d3b161bbfdde08f0bb2718c3c08ff2484c  $skill_zip" | shasum -a 256 -c -
mkdir -p "$SKILLS_DIR"
unzip -oq "$skill_zip" -d "$SKILLS_DIR"
rm -f "$skill_zip"
```

Restart the host afterwards so it rediscovers its skills directory.

The helper resolves `git` and `openssl` from a fixed POSIX path allowlist, so it runs on macOS, Linux, and WSL. On a host that cannot reach those tools it returns `status: unavailable` with `reason_code: environment_unsupported` and gives no rating.

Codex sandboxes network access by default. Approve the escalation when the Skill fetches the signed catalog; without it the lookup fails closed as `unavailable`.

Try prompts such as:

- `Is the Claude Trello connector safe to use?`
- `Why is LawToolBox rated High Risk?`
- `What permissions and capabilities does Frontify have?`
- `Use Plutonium Skill to check Apify MCP Server Remote.`

## How it works

The bundled helper performs a fresh, read-only Git fetch from the public [`plutonium-catalog-data`](https://github.com/plutosecurity/plutonium-catalog-data) repository. Before returning an assessment, it verifies the release tag, publisher signature, pinned public key, manifest schema, catalog hash, byte length, and record counts.

The helper never checks out or executes catalog repository content. It reads a fixed set of signed data files and emits a bounded JSON result. The Skill does not use Web Search, Web Fetch, MCP, or a connector as its assessment transport.

## Repository layout

```text
skills/plutonium-skill/
├── SKILL.md
├── LICENSE
├── agents/openai.yaml
├── references/
│   ├── catalog-signing-public.pem
│   └── trust.json
└── scripts/plutonium_lookup.py
```

`tools/package_skill.py` validates the exact package contents and creates a deterministic ZIP. Public tests are in `tests/`.

## Build and test

Requirements: Python 3.9+, Git, and OpenSSL.

```bash
python3 -m unittest discover -s tests -v
python3 tools/package_skill.py
```

The generated archive is written to `dist/`.

## Security

Only install releases published by the `plutosecurity` organization. See [SECURITY.md](SECURITY.md) for private vulnerability reporting instructions.

Plutonium assessments are security guidance, not a guarantee of safety. Review each product's permissions and your environment before installing it.

## License

Apache License 2.0. See [LICENSE](LICENSE).

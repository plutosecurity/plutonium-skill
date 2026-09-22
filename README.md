# Plutonium Skill

The official Plutonium Skill brings Plutonium's current security assessments into Claude, Codex, and Cursor. It helps users review AI connectors, desktop extensions, MCP servers, plugins, and skills across Claude, Microsoft Copilot, and the Plutonium Market-Space.

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
curl -fsSL "https://github.com/plutosecurity/plutonium-skill/releases/download/v0.2.0/plutonium-skill-0.2.0.zip" -o "$skill_zip"
echo "5c1cebd90902214aa29af331dc298142bd676fc3633483d98993d7add5224ee1  $skill_zip" | shasum -a 256 -c -
mkdir -p "$SKILLS_DIR"
unzip -oq "$skill_zip" -d "$SKILLS_DIR"
rm -f "$skill_zip"
```

Restart the host afterwards so it rediscovers its skills directory.

The helper uses Python's standard HTTPS client, so it has no Git, OpenSSL CLI, or third-party package dependency. Codex sandboxes network access by default; without approved access to the lookup endpoint, the helper fails closed as `unavailable` and gives no rating.

Try prompts such as:

- `Is the Claude Trello connector safe to use?`
- `Why is LawToolBox rated High Risk?`
- `What permissions and capabilities does Frontify have?`
- `Use Plutonium Skill to check Apify MCP Server Remote.`

## How it works

The bundled helper sends one product query to a rate-limited AWS API and validates the bounded response before exposing it to the agent. The API reads a hash-verified catalog from a private, encrypted, versioned S3 bucket. There is no public list, export, pagination, or raw-catalog endpoint.

The helper never downloads or executes catalog content. The Skill does not use Web Search, Web Fetch, MCP, or a connector as its assessment transport. The lookup service and its deployment infrastructure are maintained separately in the private Plutonium repository.

## Repository layout

```text
skills/plutonium-skill/
├── SKILL.md
├── LICENSE
├── agents/openai.yaml
├── references/
│   └── api.json
└── scripts/plutonium_lookup.py
```

`tools/package_skill.py` validates the exact package contents and creates a deterministic ZIP. Public tests are in `tests/`.

## Build and test

Requirements: Python 3.9+.

```bash
python3 -m unittest discover -s tests -v
python3 tools/package_skill.py
```

The generated archive is written to `dist/`.

Use `python3 tools/package_skill.py --release` for a release build. It refuses to package while the API endpoint is still the pre-deployment placeholder.

## Security

Only install releases published by the `plutosecurity` organization. See [SECURITY.md](SECURITY.md) for private vulnerability reporting instructions.

Plutonium assessments are security guidance, not a guarantee of safety. Review each product's permissions and your environment before installing it.

## License

Apache License 2.0. See [LICENSE](LICENSE).

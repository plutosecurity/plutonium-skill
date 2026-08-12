# Plutonium Skill

The official Plutonium Skill brings Plutonium's signed security assessments into Claude. It helps users review AI connectors, desktop extensions, MCP servers, plugins, and skills across Claude, Microsoft Copilot, and the Plutonium Market-Space.

The Skill is read-only. It does not install, enable, disable, configure, or execute the product being assessed.

## What it provides

- Plutonium risk ratings or reviewed Market-Space status
- Key permissions, capabilities, and tool-level warnings
- The strongest published security risks and risk-reduction guidance
- Clear handling of ambiguous product names across ecosystems
- A direct link to the complete assessment on [Plutonium](https://plutonium.pluto.security/)

## Install in Claude

1. Download the ZIP from the [latest GitHub release](https://github.com/plutosecurity/plutonium-skill/releases/latest). Each release also includes a `SHA256SUMS` file for verification.
2. In Claude, open **Customize → Skills → + → Create skill → Upload a skill**.
3. Upload the downloaded ZIP without extracting it, then enable **Plutonium Skill**.

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

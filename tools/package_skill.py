#!/usr/bin/env python3
"""Validate and deterministically package Plutonium Skill v0.11.0."""

from __future__ import annotations

import argparse
import ast
import hashlib
import io
import json
import re
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKILL_NAME = "plutonium-skill"
VERSION = "0.11.0"
SKILL_DIR = ROOT / "skills" / SKILL_NAME
PACKAGE_FILES = (
    Path("SKILL.md"),
    Path("LICENSE"),
    Path("agents/openai.yaml"),
    Path("scripts/plutonium_lookup.py"),
    Path("references/trust.json"),
    Path("references/catalog-signing-public.pem"),
)
EXECUTABLE_FILES = {Path("scripts/plutonium_lookup.py")}
ZIP_TIMESTAMP = (2026, 8, 12, 0, 0, 0)
TRUSTED_PUBLIC_KEY_SHA256 = (
    "5f08f28346541f07e3de4b938c5592730006bf168043c6ae3b9eabfe1e1c541c"
)
APPROVED_HELPER_SHA256 = (
    "6e8f8b1047fdf50ead8403d9d5693d06411a4b10c1d8d33e9e7b8ec46571c2fa"
)
TRUST_KEYS = {
    "schema_version",
    "repository",
    "tag_pattern",
    "public_key_sha256",
}


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def validate_frontmatter(text: str) -> None:
    match = re.match(r"\A---\n(.*?)\n---\n", text, flags=re.DOTALL)
    if not match:
        raise SystemExit("SKILL.md frontmatter is invalid")
    frontmatter = match.group(1)
    keys = [
        line.split(":", 1)[0].strip()
        for line in frontmatter.splitlines()
        if ":" in line
    ]
    if keys != ["name", "description"]:
        raise SystemExit("SKILL.md frontmatter must contain only name and description")
    if not re.search(
        rf"^name:\s*{re.escape(SKILL_NAME)}\s*$", frontmatter, flags=re.MULTILINE
    ):
        raise SystemExit("SKILL.md name must match the skill directory")
    description = re.search(r"^description:\s*(.+)$", frontmatter, flags=re.MULTILINE)
    if not description or not 1 <= len(description.group(1).strip()) <= 1024:
        raise SystemExit("SKILL.md description must contain 1-1024 characters")


def validate_helper_ast(source: str, filename: str) -> None:
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError as exc:
        raise SystemExit("Helper Python source is invalid") from exc
    forbidden_names = {
        "__import__",
        "compile",
        "eval",
        "exec",
        "getattr",
        "globals",
        "locals",
        "setattr",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for imported in node.names:
                if imported.name in {"os", "subprocess"} and imported.asname:
                    raise SystemExit(
                        f"Helper may not alias the {imported.name} module"
                    )
        if isinstance(node, ast.ImportFrom) and node.module in {
            "builtins",
            "os",
            "subprocess",
        }:
            raise SystemExit(f"Helper may not import names from {node.module}")
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name) and node.func.id in forbidden_names:
            raise SystemExit(f"Helper may not call {node.func.id}()")
        if isinstance(node.func, ast.Attribute):
            owner = node.func.value
            if isinstance(owner, ast.Name) and owner.id == "os" and node.func.attr == "system":
                raise SystemExit("Helper may not call os.system()")
            if node.func.attr in {"Popen", "call", "check_call", "check_output", "system"}:
                raise SystemExit(f"Helper may not call {node.func.attr}()")
            if isinstance(owner, ast.Name) and owner.id == "subprocess":
                if node.func.attr != "run":
                    raise SystemExit(
                        f"Helper may not call subprocess.{node.func.attr}()"
                    )
                for keyword in node.keywords:
                    if keyword.arg is None:
                        raise SystemExit(
                            "Helper subprocess calls may not expand keyword dictionaries"
                        )
                    if keyword.arg == "shell" and not (
                        isinstance(keyword.value, ast.Constant)
                        and keyword.value.value is False
                    ):
                        raise SystemExit("Helper subprocess calls may not enable a shell")


def validate_skill_source() -> dict[Path, bytes]:
    missing = [str(relative) for relative in PACKAGE_FILES if not (SKILL_DIR / relative).is_file()]
    if missing:
        raise SystemExit("Missing required skill files: " + ", ".join(missing))

    for path in SKILL_DIR.rglob("*"):
        if path.is_symlink():
            raise SystemExit(
                "Skill packages may not contain symlinks: "
                + str(path.relative_to(SKILL_DIR))
            )
    actual_files = {
        path.relative_to(SKILL_DIR)
        for path in SKILL_DIR.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts
    }
    if actual_files != set(PACKAGE_FILES):
        extras = sorted(str(path) for path in actual_files - set(PACKAGE_FILES))
        raise SystemExit("Unexpected skill files: " + ", ".join(extras))
    source = {relative: (SKILL_DIR / relative).read_bytes() for relative in PACKAGE_FILES}

    try:
        skill_text = source[Path("SKILL.md")].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SystemExit("SKILL.md must be UTF-8") from exc
    validate_frontmatter(skill_text)
    required_phrases = (
        "signed public data catalog",
        "Microsoft Copilot",
        "MCP servers",
        "trusted_membership",
        "Do not use Web Search, Web Fetch, MCP",
        "latest signed Plutonium catalog could not be reached or verified",
        "At a glance",
        "Top security risks",
        "Open review findings",
        "compact_summary.detail_sections",
    )
    for phrase in required_phrases:
        if phrase not in skill_text:
            raise SystemExit(f"SKILL.md is missing required rule: {phrase!r}")

    helper_relative = Path("scripts/plutonium_lookup.py")
    try:
        helper_source = source[helper_relative].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SystemExit("Helper must be UTF-8") from exc
    validate_helper_ast(helper_source, str(helper_relative))
    if sha256_bytes(source[helper_relative]) != APPROVED_HELPER_SHA256:
        raise SystemExit(
            "Helper bytes differ from the security-reviewed v0.11.0 implementation"
        )
    if "subprocess.run" not in helper_source:
        raise SystemExit("Helper must use subprocess argv arrays without a shell")

    trust_relative = Path("references/trust.json")
    public_key_relative = Path("references/catalog-signing-public.pem")
    try:
        trust = json.loads(source[trust_relative].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemExit("trust.json is invalid") from exc
    if not isinstance(trust, dict) or set(trust) != TRUST_KEYS:
        raise SystemExit("trust.json must use the exact approved schema")
    if trust.get("schema_version") != 1:
        raise SystemExit("trust.json schema version is invalid")
    if trust.get("repository") != "https://github.com/plutosecurity/plutonium-catalog-data.git":
        raise SystemExit("trust.json repository is invalid")
    if trust.get("tag_pattern") != r"^catalog-v([0-9]{10})$":
        raise SystemExit("trust.json tag pattern is invalid")
    public_key_bytes = source[public_key_relative]
    if (
        trust.get("public_key_sha256") != TRUSTED_PUBLIC_KEY_SHA256
        or sha256_bytes(public_key_bytes) != TRUSTED_PUBLIC_KEY_SHA256
    ):
        raise SystemExit("catalog public key does not match the pinned trust root")
    try:
        public_key = public_key_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise SystemExit("Catalog public key must be ASCII PEM") from exc
    if "BEGIN PUBLIC KEY" not in public_key or "PRIVATE KEY" in public_key:
        raise SystemExit("Skill must contain only the catalog public key")
    return source


def write_deterministic_file(
    archive: zipfile.ZipFile, relative: Path, payload: bytes
) -> None:
    archive_name = (Path(SKILL_NAME) / relative).as_posix()
    mode = 0o755 if relative in EXECUTABLE_FILES else 0o644
    info = zipfile.ZipInfo(archive_name, date_time=ZIP_TIMESTAMP)
    info.create_system = 3
    info.external_attr = (mode & 0xFFFF) << 16
    info.compress_type = zipfile.ZIP_DEFLATED
    archive.writestr(
        info, payload, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9
    )


def render_zip(source: dict[Path, bytes]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for relative in PACKAGE_FILES:
            write_deterministic_file(archive, relative, source[relative])
    return output.getvalue()


def build_zip(output_dir: Path) -> Path:
    source = validate_skill_source()
    output_dir.mkdir(parents=True, exist_ok=True)
    output = output_dir / f"{SKILL_NAME}-{VERSION}.zip"
    archive_bytes = render_zip(source)
    if archive_bytes != render_zip(source):
        raise SystemExit("ZIP rendering is not deterministic")
    output.write_bytes(archive_bytes)
    with zipfile.ZipFile(output) as archive:
        expected = [(Path(SKILL_NAME) / relative).as_posix() for relative in PACKAGE_FILES]
        if archive.namelist() != expected:
            raise SystemExit("ZIP contents do not match the approved skill package")
        if any(info.filename.endswith("/") for info in archive.infolist()):
            raise SystemExit("ZIP must not contain directory entries")
        for relative, archive_name in zip(PACKAGE_FILES, expected):
            if archive.read(archive_name) != source[relative]:
                raise SystemExit(f"ZIP member changed after validation: {archive_name}")
    return output


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "dist")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    output = build_zip(args.output_dir.resolve())
    print(f"Created Plutonium Skill v{VERSION}: {output}")
    print(f"SHA-256: {sha256_file(output)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Validate and deterministically package Plutonium Skill v0.2.0."""

from __future__ import annotations

import argparse
import ast
import hashlib
import io
import json
import re
import zipfile
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
SKILL_NAME = "plutonium-skill"
VERSION = "0.2.0"
SKILL_DIR = ROOT / "skills" / SKILL_NAME
PACKAGE_FILES = (
    Path("SKILL.md"),
    Path("LICENSE"),
    Path("agents/openai.yaml"),
    Path("scripts/plutonium_lookup.py"),
    Path("references/api.json"),
)
EXECUTABLE_FILES = {Path("scripts/plutonium_lookup.py")}
ZIP_TIMESTAMP = (2026, 9, 11, 0, 0, 0)
APPROVED_HELPER_SHA256 = (
    "08647685fcb40272a42d9e9e9e6f2972020f20069cfa5113aa186bdd85d2b68f"
)
PLACEHOLDER_HOST = "replace-after-deploy.invalid"


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
    forbidden_modules = {"ctypes", "importlib", "os", "shutil", "socket", "subprocess"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for imported in node.names:
                if imported.name.split(".", 1)[0] in forbidden_modules:
                    raise SystemExit(f"Helper may not import {imported.name}")
        if isinstance(node, ast.ImportFrom) and (node.module or "").split(".", 1)[0] in forbidden_modules:
            raise SystemExit(f"Helper may not import from {node.module}")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in forbidden_names:
                raise SystemExit(f"Helper may not call {node.func.id}()")


def validate_api_config(payload: bytes, *, release: bool) -> None:
    try:
        raw = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemExit("references/api.json is invalid") from exc
    if not isinstance(raw, dict) or set(raw) != {"endpoint", "schema_version"}:
        raise SystemExit("references/api.json must use the exact approved schema")
    if raw["schema_version"] != 1 or not isinstance(raw["endpoint"], str):
        raise SystemExit("references/api.json values are invalid")
    try:
        parsed = urlparse(raw["endpoint"])
        port = parsed.port
    except ValueError as exc:
        raise SystemExit("references/api.json endpoint is invalid") from exc
    host = (parsed.hostname or "").casefold()
    host_allowed = host.endswith(
        ".execute-api.eu-central-1.amazonaws.com"
    ) or host.endswith(".pluto.security")
    if host == PLACEHOLDER_HOST and not release:
        host_allowed = True
    if (
        parsed.scheme != "https"
        or not host_allowed
        or port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != "/v1/lookup"
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        raise SystemExit("references/api.json endpoint is not an approved lookup endpoint")
    if release and host == PLACEHOLDER_HOST:
        raise SystemExit("release blocked: configure the deployed API endpoint first")


def validate_skill_source(*, release: bool = False) -> dict[Path, bytes]:
    missing = [
        str(relative) for relative in PACKAGE_FILES if not (SKILL_DIR / relative).is_file()
    ]
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
    source = {
        relative: (SKILL_DIR / relative).read_bytes() for relative in PACKAGE_FILES
    }
    try:
        skill_text = source[Path("SKILL.md")].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SystemExit("SKILL.md must be UTF-8") from exc
    validate_frontmatter(skill_text)
    required_phrases = (
        "rate-limited API",
        "Microsoft Copilot",
        "MCP servers",
        "trusted_membership",
        "Do not use Web Search, Web Fetch, MCP",
        "current Plutonium lookup service could not be reached or verified",
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
    digest = sha256_bytes(source[helper_relative])
    if digest != APPROVED_HELPER_SHA256:
        raise SystemExit("Helper bytes differ from the security-reviewed v0.2.0 implementation")
    forbidden_text = (
        "plutonium-catalog-data",
        "release/catalog.json",
        "git clone",
        "git fetch",
        "BEGIN PRIVATE KEY",
    )
    combined = b"\n".join(source.values()).decode("utf-8")
    for phrase in forbidden_text:
        if phrase.casefold() in combined.casefold():
            raise SystemExit(f"Public Skill package contains forbidden transport text: {phrase}")
    validate_api_config(source[Path("references/api.json")], release=release)
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


def build_zip(output_dir: Path, *, release: bool = False) -> Path:
    source = validate_skill_source(release=release)
    output_dir.mkdir(parents=True, exist_ok=True)
    output = output_dir / f"{SKILL_NAME}-{VERSION}.zip"
    archive_bytes = render_zip(source)
    if archive_bytes != render_zip(source):
        raise SystemExit("ZIP rendering is not deterministic")
    output.write_bytes(archive_bytes)
    with zipfile.ZipFile(output) as archive:
        expected = [
            (Path(SKILL_NAME) / relative).as_posix() for relative in PACKAGE_FILES
        ]
        if archive.namelist() != expected:
            raise SystemExit("ZIP contents do not match the approved skill package")
        for relative, archive_name in zip(PACKAGE_FILES, expected):
            if archive.read(archive_name) != source[relative]:
                raise SystemExit(f"ZIP member changed after validation: {archive_name}")
    return output


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "dist")
    parser.add_argument(
        "--release",
        action="store_true",
        help="require a deployed endpoint and enforce all release gates",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    output = build_zip(args.output_dir.resolve(), release=args.release)
    print(f"Created Plutonium Skill v{VERSION}: {output}")
    print(f"SHA-256: {sha256_file(output)}")
    if not args.release:
        print("Development build only; use --release for the publication gate.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

import base64
import hashlib
import importlib.util
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKILL_DIR = ROOT / "skills" / "plutonium-skill"
HELPER_PATH = SKILL_DIR / "scripts" / "plutonium_lookup.py"
PACKAGER_PATH = ROOT / "tools" / "package_skill.py"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


helper = load_module("plutonium_skill_helper", HELPER_PATH)
packager = load_module("plutonium_skill_packager", PACKAGER_PATH)


class PublicSkillTests(unittest.TestCase):
    def test_public_name_and_version_are_consistent(self):
        skill_text = (SKILL_DIR / "SKILL.md").read_text(encoding="utf-8")
        interface_text = (SKILL_DIR / "agents" / "openai.yaml").read_text(
            encoding="utf-8"
        )
        self.assertIn("\nname: plutonium-skill\n", skill_text)
        self.assertIn("# Plutonium Skill", skill_text)
        self.assertIn("$plutonium-skill", interface_text)
        self.assertEqual(helper.VERSION, "0.11.0")
        self.assertEqual(packager.SKILL_NAME, "plutonium-skill")
        self.assertEqual(packager.VERSION, "0.11.0")

    def test_package_is_reproducible_and_exact(self):
        with tempfile.TemporaryDirectory() as first_dir, tempfile.TemporaryDirectory() as second_dir:
            first = packager.build_zip(Path(first_dir))
            second = packager.build_zip(Path(second_dir))
            self.assertEqual(first.name, "plutonium-skill-0.11.0.zip")
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with zipfile.ZipFile(first) as archive:
                self.assertEqual(
                    archive.namelist(),
                    [
                        "plutonium-skill/SKILL.md",
                        "plutonium-skill/LICENSE",
                        "plutonium-skill/agents/openai.yaml",
                        "plutonium-skill/scripts/plutonium_lookup.py",
                        "plutonium-skill/references/trust.json",
                        "plutonium-skill/references/catalog-signing-public.pem",
                    ],
                )
                for name in archive.namelist():
                    self.assertNotIn("PRIVATE KEY", archive.read(name).decode("utf-8"))

    def test_packager_pins_reviewed_helper_and_public_key(self):
        source = packager.validate_skill_source()
        helper_bytes = source[Path("scripts/plutonium_lookup.py")]
        public_key = source[Path("references/catalog-signing-public.pem")]
        self.assertEqual(
            hashlib.sha256(helper_bytes).hexdigest(),
            packager.APPROVED_HELPER_SHA256,
        )
        self.assertEqual(
            hashlib.sha256(public_key).hexdigest(),
            packager.TRUSTED_PUBLIC_KEY_SHA256,
        )

    def test_query_base64_mode_preserves_unicode(self):
        query = "HUE エージェント"
        token = base64.b64encode(query.encode("utf-8")).decode("ascii")
        parsed = helper.parse_args(["--query-base64", token])
        self.assertEqual(parsed.query, query)

    def test_old_private_skill_name_is_absent(self):
        public_files = [
            SKILL_DIR / "SKILL.md",
            SKILL_DIR / "agents" / "openai.yaml",
            HELPER_PATH,
            PACKAGER_PATH,
        ]
        for path in public_files:
            self.assertNotIn("plutonium-analysis", path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()

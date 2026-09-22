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
CONFIGURER_PATH = ROOT / "tools" / "configure_api.py"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


helper = load_module("plutonium_skill_helper", HELPER_PATH)
packager = load_module("plutonium_skill_packager", PACKAGER_PATH)
configurer = load_module("plutonium_skill_configurer", CONFIGURER_PATH)


class PublicSkillTests(unittest.TestCase):
    def test_public_name_and_version_are_consistent(self):
        skill_text = (SKILL_DIR / "SKILL.md").read_text(encoding="utf-8")
        interface_text = (SKILL_DIR / "agents" / "openai.yaml").read_text(
            encoding="utf-8"
        )
        self.assertIn("\nname: plutonium-skill\n", skill_text)
        self.assertIn("# Plutonium Skill", skill_text)
        self.assertIn("$plutonium-skill", interface_text)
        self.assertEqual(helper.VERSION, "0.2.0")
        self.assertEqual(packager.VERSION, "0.2.0")

    def test_package_is_reproducible_and_exact(self):
        with tempfile.TemporaryDirectory() as first_dir, tempfile.TemporaryDirectory() as second_dir:
            first = packager.build_zip(Path(first_dir))
            second = packager.build_zip(Path(second_dir))
            self.assertEqual(first.name, "plutonium-skill-0.2.0.zip")
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with zipfile.ZipFile(first) as archive:
                self.assertEqual(
                    archive.namelist(),
                    [
                        "plutonium-skill/SKILL.md",
                        "plutonium-skill/LICENSE",
                        "plutonium-skill/agents/openai.yaml",
                        "plutonium-skill/scripts/plutonium_lookup.py",
                        "plutonium-skill/references/api.json",
                    ],
                )
                combined = b"\n".join(
                    archive.read(name) for name in archive.namelist()
                )
                self.assertNotIn(b"PRIVATE KEY", combined)
                self.assertNotIn(b"plutonium-catalog-data", combined)
                self.assertNotIn(b"catalog.json", combined)

    def test_packager_pins_reviewed_helper(self):
        source = packager.validate_skill_source()
        helper_bytes = source[Path("scripts/plutonium_lookup.py")]
        self.assertEqual(
            hashlib.sha256(helper_bytes).hexdigest(),
            packager.APPROVED_HELPER_SHA256,
        )

    def test_release_build_accepts_configured_production_endpoint(self):
        source = packager.validate_skill_source(release=True)
        self.assertIn(Path("references/api.json"), source)

    def test_query_base64_mode_preserves_unicode(self):
        query = "HUE エージェント"
        token = base64.b64encode(query.encode("utf-8")).decode("ascii")
        parsed = helper.parse_args(["--query-base64", token])
        self.assertEqual(parsed.query, query)

    def test_production_endpoint_loads_from_config(self):
        self.assertEqual(
            helper.load_endpoint(),
            "https://v4m0umvde5.execute-api.eu-central-1.amazonaws.com/v1/lookup",
        )

    def test_only_expected_production_endpoint_hosts_are_accepted(self):
        endpoint = "https://abc.execute-api.eu-central-1.amazonaws.com/v1/lookup"
        self.assertEqual(
            helper._validate_endpoint(endpoint, allow_placeholder=False), endpoint
        )
        for unsafe in (
            "http://abc.execute-api.eu-central-1.amazonaws.com/v1/lookup",
            "https://example.com/v1/lookup",
            "https://abc.execute-api.us-east-1.amazonaws.com/v1/lookup",
            "https://abc.execute-api.eu-central-1.amazonaws.com/v1/lookup?all=true",
        ):
            with self.assertRaises(helper.LookupError):
                helper._validate_endpoint(unsafe, allow_placeholder=False)

    def test_configurer_writes_canonical_endpoint_config(self):
        endpoint = "https://abc.execute-api.eu-central-1.amazonaws.com/v1/lookup"
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "api.json"
            original = configurer.CONFIG_PATH
            try:
                configurer.CONFIG_PATH = destination
                self.assertEqual(configurer.main(["--endpoint", endpoint]), 0)
            finally:
                configurer.CONFIG_PATH = original
            self.assertEqual(
                destination.read_text(encoding="utf-8"),
                '{"endpoint":"https://abc.execute-api.eu-central-1.amazonaws.com/v1/lookup","schema_version":1}\n',
            )

    def test_bounded_no_match_response_validates(self):
        query = "Unknown Product"
        result = {
            "schema_version": 1,
            "status": "no_match",
            "query": query,
            "match_reason": "no_reliable_match",
            "catalog_provenance": {
                "verification": "private-s3+sha256",
                "published_at": "2026-09-11T12:00:00Z",
                "record_count": 2862,
                "catalog_counts": {
                    "claudesec": 632,
                    "copilotsec": 1715,
                    "marketplace": 515,
                },
            },
            "suggestions": [],
        }
        self.assertEqual(helper.validate_result(result, query), result)
        result["bulk_catalog"] = []
        with self.assertRaises(helper.LookupError):
            helper.validate_result(result, query)

    def test_skill_keeps_transport_and_rendering_boundaries_explicit(self):
        skill_text = (SKILL_DIR / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("rate-limited API", skill_text)
        self.assertIn("Do not download a catalog", skill_text)
        self.assertIn(
            "Never present a truncated list as the complete capability set", skill_text
        )
        self.assertIn("handpicked and reviewed", skill_text)
        self.assertIn(
            "Verified Plutonium catalog · Updated READABLE_PUBLISHED_DATE", skill_text
        )


if __name__ == "__main__":
    unittest.main()

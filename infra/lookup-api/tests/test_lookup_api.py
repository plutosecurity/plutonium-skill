import hashlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SRC))

import catalog
import handler


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


publisher = load_module("publish_catalog", SCRIPTS / "publish_catalog.py")
public_helper = load_module(
    "public_plutonium_lookup",
    ROOT.parents[1] / "skills" / "plutonium-skill" / "scripts" / "plutonium_lookup.py",
)


def risk_record(*, record_id: str, planet: str, name: str, publisher_name: str, route: str):
    return {
        "record_id": record_id,
        "planet": planet,
        "ecosystem": "Claude" if planet == "claudesec" else "Microsoft Copilot",
        "type": "web_connector" if planet == "claudesec" else "connector",
        "category": "Connector",
        "name": name,
        "publisher": publisher_name,
        "id": route,
        "uuid": "12345678-1234-1234-1234-123456789012" if planet == "claudesec" else "",
        "route_dids": [route],
        "source_occurrences": 1,
        "description": f"{name} description",
        "long_description": f"{name} long description",
        "assessment": {"kind": "risk_rating", "level": "high"},
        "security_risks": [
            {
                "risk_type": "deletes_data",
                "severity": "high",
                "title": "Can permanently delete data",
                "description": "Destructive operations are available.",
                "evidence": "A delete tool is present.",
                "remediation_steps": ["Disable the delete tool."],
            }
        ],
        "tags": ["network_access", "deletes_data"],
        "risky_tools": [
            {
                "name": "delete_item",
                "description": "Delete one item",
                "risk": {
                    "level": "high",
                    "category": "destructive",
                    "why": "Deletes data",
                    "recommendation": "Require approval",
                },
            }
        ],
        "capabilities": [{"name": "Search", "description": "Search items"}],
        "tools_count": 2,
        "source_code_reviewed": False,
        "analysis_method": "capability_triage",
        "added_at": "2026-09-01",
        "last_scanned": "2026-09-10",
        "urls": {
            "plutonium": (
                "https://plutonium.pluto.security/detail.html"
                f"?planet={planet}&did={route}"
            ),
            "listing": "https://example.com/listing",
            "source": "",
            "repository": "",
            "homepage": "https://example.com",
        },
    }


def fixture():
    records = [
        risk_record(
            record_id="claudesec:trello",
            planet="claudesec",
            name="Trello",
            publisher_name="Atlassian",
            route="trello-claude",
        ),
        risk_record(
            record_id="copilotsec:trello",
            planet="copilotsec",
            name="Trello",
            publisher_name="Microsoft",
            route="trello-copilot",
        ),
        risk_record(
            record_id="claudesec:cloudflare",
            planet="claudesec",
            name="Cloudflare Developer Platform",
            publisher_name="Cloudflare",
            route="cloudflare",
        ),
    ]
    payload = (json.dumps({"schema_version": 1, "records": records}, sort_keys=True) + "\n").encode()
    digest = hashlib.sha256(payload).hexdigest()
    pointer = {
        "schema_version": 1,
        "catalog_key": f"releases/{digest}/catalog.json",
        "sha256": digest,
        "bytes": len(payload),
        "record_count": len(records),
        "catalog_counts": {"claudesec": 2, "copilotsec": 1},
        "published_at": "2026-09-11T12:00:00Z",
        "expires_at": "2026-10-01T12:00:00Z",
        "source_commit": "a" * 40,
    }
    return payload, pointer


class Body:
    def __init__(self, payload):
        self.payload = payload

    def read(self, maximum):
        return self.payload[:maximum]


class FakeS3:
    def __init__(self, objects):
        self.objects = objects
        self.calls = []

    def get_object(self, *, Bucket, Key):
        self.calls.append((Bucket, Key))
        return {"Body": Body(self.objects[Key])}


class LookupApiTests(unittest.TestCase):
    def setUp(self):
        self.payload, self.pointer = fixture()
        self.records = catalog.validate_catalog(self.payload, self.pointer)
        self.provenance = {
            "verification": "private-s3+sha256",
            "published_at": self.pointer["published_at"],
            "record_count": 3,
            "catalog_counts": self.pointer["catalog_counts"],
        }

    def test_unqualified_duplicate_name_is_ambiguous_without_ratings(self):
        result = catalog.build_result("Trello", self.records, self.provenance, details=False)
        self.assertEqual(result["status"], "ambiguous")
        self.assertEqual({match["planet"] for match in result["matches"]}, {"claudesec", "copilotsec"})
        self.assertTrue(all("assessment" not in match for match in result["matches"]))

    def test_qualified_name_returns_one_bounded_match(self):
        result = catalog.build_result(
            "Claude Trello connector", self.records, self.provenance, details=False
        )
        self.assertEqual(result["status"], "match")
        self.assertEqual(result["item"]["record_id"], "claudesec:trello")
        self.assertEqual(len(result["item"]["security_risks"]), 1)
        self.assertEqual(result["item"]["risky_tools"], [])
        serialized = json.dumps(result)
        self.assertNotIn("install", serialized)
        self.assertNotIn("skill_md", serialized)
        self.assertEqual(public_helper.validate_result(result, "Claude Trello connector"), result)

    def test_details_return_only_the_matched_records_details(self):
        result = catalog.build_result(
            "Cloudflare Developer Platform", self.records, self.provenance, details=True
        )
        self.assertEqual(result["status"], "match")
        self.assertEqual(result["item"]["risky_tools"][0]["name"], "delete_item")
        self.assertEqual(len(result["item"]["capabilities"]), 1)

    def test_catalog_store_verifies_private_release_and_caches_it(self):
        pointer_bytes = (json.dumps(self.pointer, sort_keys=True) + "\n").encode()
        client = FakeS3({"current.json": pointer_bytes, self.pointer["catalog_key"]: self.payload})
        times = iter((100.0, 101.0, 200.0))
        store = catalog.CatalogStore(
            client=client,
            bucket="private-bucket",
            ttl_seconds=60,
            clock=lambda: next(times),
            utcnow=lambda: datetime(2026, 9, 11, 13, 0, tzinfo=timezone.utc),
        )
        first, _ = store.load()
        second, _ = store.load()
        third, _ = store.load()
        self.assertIs(first, second)
        self.assertIs(second, third)
        self.assertEqual(
            client.calls,
            [
                ("private-bucket", "current.json"),
                ("private-bucket", self.pointer["catalog_key"]),
                ("private-bucket", "current.json"),
            ],
        )

    def test_tampered_catalog_fails_closed(self):
        with self.assertRaises(catalog.CatalogError):
            catalog.validate_catalog(self.payload + b" ", self.pointer)

    def test_stale_catalog_pointer_fails_closed(self):
        payload = (json.dumps(self.pointer, sort_keys=True) + "\n").encode()
        with self.assertRaises(catalog.CatalogError) as context:
            catalog.validate_pointer(
                payload,
                now=datetime(2027, 1, 1, tzinfo=timezone.utc),
            )
        self.assertEqual(str(context.exception), "catalog_stale")

    def test_handler_rejects_non_json_and_oversized_requests(self):
        event = self.event(body="{}", content_type="text/plain")
        self.assertEqual(handler.lambda_handler(event, None)["statusCode"], 415)
        event = self.event(body=json.dumps({"query": "x" * 501}))
        self.assertEqual(handler.lambda_handler(event, None)["statusCode"], 400)

    def test_handler_returns_lookup_result(self):
        class Store:
            def load(inner_self):
                return self.records, self.provenance

        event = self.event(body=json.dumps({"query": "Claude Trello connector"}))
        with mock.patch.object(handler, "STORE", Store()):
            response = handler.lambda_handler(event, None)
        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(json.loads(response["body"])["status"], "match")
        self.assertEqual(response["headers"]["cache-control"], "no-store")

    def test_publisher_dry_run_validates_manifest_and_builds_pointer(self):
        digest = hashlib.sha256(self.payload).hexdigest()
        manifest = {
            "published_at": "2026-09-11T12:00:00Z",
            "expires_at": "2026-10-01T12:00:00Z",
            "source": {"commit": "b" * 40},
            "catalog": {
                "bytes": len(self.payload),
                "sha256": digest,
                "record_count": 3,
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalog_path = root / "catalog.json"
            manifest_path = root / "manifest.json"
            catalog_path.write_bytes(self.payload)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            args = publisher.parse_args(
                [
                    "--bucket",
                    "private-bucket",
                    "--catalog",
                    str(catalog_path),
                    "--manifest",
                    str(manifest_path),
                    "--dry-run",
                ]
            )
            pointer = publisher.publish(
                args, now=datetime(2026, 9, 11, 13, 0, tzinfo=timezone.utc)
            )
        self.assertEqual(pointer["sha256"], digest)
        self.assertEqual(pointer["catalog_counts"], {"claudesec": 2, "copilotsec": 1})

    def test_publisher_rejects_an_expired_manifest(self):
        digest = hashlib.sha256(self.payload).hexdigest()
        manifest = {
            "published_at": "2026-07-01T12:00:00Z",
            "expires_at": "2026-07-31T12:00:00Z",
            "source": {"commit": "b" * 40},
            "catalog": {
                "bytes": len(self.payload),
                "sha256": digest,
                "record_count": 3,
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalog_path = root / "catalog.json"
            manifest_path = root / "manifest.json"
            catalog_path.write_bytes(self.payload)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            args = publisher.parse_args(
                [
                    "--bucket",
                    "private-bucket",
                    "--catalog",
                    str(catalog_path),
                    "--manifest",
                    str(manifest_path),
                    "--dry-run",
                ]
            )
            with self.assertRaises(SystemExit) as context:
                publisher.publish(
                    args,
                    now=datetime(2026, 9, 11, 13, 0, tzinfo=timezone.utc),
                )
        self.assertIn("expired", str(context.exception))

    @staticmethod
    def event(*, body, content_type="application/json"):
        return {
            "version": "2.0",
            "rawPath": "/v1/lookup",
            "headers": {"content-type": content_type},
            "requestContext": {"http": {"method": "POST", "sourceIp": "127.0.0.1"}},
            "body": body,
            "isBase64Encoded": False,
        }


if __name__ == "__main__":
    unittest.main()

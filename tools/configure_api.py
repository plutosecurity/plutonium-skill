#!/usr/bin/env python3
"""Pin a deployed lookup endpoint into the public Skill package."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "skills" / "plutonium-skill" / "references" / "api.json"
sys.path.insert(0, str(ROOT / "skills" / "plutonium-skill" / "scripts"))

from plutonium_lookup import LookupError, _validate_endpoint


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True)
    args = parser.parse_args(argv)
    try:
        endpoint = _validate_endpoint(args.endpoint, allow_placeholder=False)
    except LookupError as exc:
        parser.error(f"invalid endpoint: {exc.reason_code}")
    payload = {"endpoint": endpoint, "schema_version": 1}
    CONFIG_PATH.write_text(
        json.dumps(
            payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"Configured {CONFIG_PATH} for {endpoint}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

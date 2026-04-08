#!/usr/bin/env python3
# Unless explicitly stated otherwise all files in this repository are licensed under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/) Copyright 2026-present Datadog, Inc.
"""
Pull custom static analysis rules from the Datadog API to disk.

Fetches all custom rulesets and writes them as YAML files under rulesets/.
Existing files are overwritten. Intended as a one-time bootstrap when setting
up this repo for the first time with rules that already exist in Datadog.

Required env vars:
  DD_API_KEY  - Datadog API key
  DD_APP_KEY  - Datadog Application key

Optional env vars:
  DD_SITE     - Datadog site (default: datadoghq.com)
"""

import base64
import os
import sys
from pathlib import Path
from typing import Any

import requests
import yaml
from loguru import logger


def setup_logging() -> None:
    logger.remove()
    logger.add(
        sys.stderr,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",

    )

RULESETS_DIR = Path(__file__).parent.parent / "rulesets"


def b64decode(s: str) -> str:
    if not s:
        return ""
    try:
        return base64.b64decode(s.encode()).decode()
    except Exception:
        return s


def fetch_rulesets(session: requests.Session, base_url: str) -> list[dict]:
    resp = session.get(f"{base_url}/rulesets", timeout=10)
    resp.raise_for_status()
    return resp.json().get("data") or []


def write_ruleset(ruleset_dir: Path, attrs: dict[str, Any]) -> None:
    ruleset_dir.mkdir(parents=True, exist_ok=True)
    meta = {
        "name": attrs["name"],
        "short_description": b64decode(attrs.get("short_description", "")),
        "description": b64decode(attrs.get("description", "")),
    }
    with (ruleset_dir / "ruleset.yaml").open("w") as f:
        yaml.dump(meta, f, default_flow_style=False, allow_unicode=True, sort_keys=False)


def write_rule(ruleset_dir: Path, rule: dict[str, Any]) -> None:
    rev = rule.get("last_revision")
    arguments = []
    tests = []

    if rev:
        arguments = [
            {
                "name": b64decode(a.get("name", "")),
                "description": b64decode(a.get("description", "")),
            }
            for a in (rev.get("arguments") or [])
        ]
        tests = [
            {
                "filename": t["filename"],
                "code": b64decode(t.get("code", "")),
                "annotation_count": t["annotation_count"],
            }
            for t in (rev.get("tests") or [])
        ]

    rule_data = {
        "name": rule["name"],
        "short_description": b64decode(rev.get("short_description", "")) if rev else "",
        "description": b64decode(rev.get("description", "")) if rev else "",
        "category": rev.get("category", "") if rev else "",
        "severity": rev.get("severity", "") if rev else "",
        "language": rev.get("language", "") if rev else "",
        "checksum": "",
        "cwe": "",
        "arguments": arguments,
        "tree_sitter_query": b64decode(rev.get("tree_sitter_query", "")) if rev else "",
        "code": b64decode(rev.get("code", "")) if rev else "",
        "tests": tests,
        "is_published": True,
    }

    filename = f"{rule['name']}.yaml"
    with (ruleset_dir / filename).open("w") as f:
        yaml.dump(rule_data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)


def main() -> None:
    api_key = os.environ.get("DD_API_KEY")
    app_key = os.environ.get("DD_APP_KEY")
    site = os.environ.get("DD_SITE") or "datadoghq.com"

    setup_logging()

    missing = [k for k, v in {"DD_API_KEY": api_key, "DD_APP_KEY": app_key}.items() if not v]
    if missing:
        logger.error("Missing required environment variable(s): {vars}", vars=", ".join(missing))
        sys.exit(1)

    base_url = f"https://api.{site}/api/v2/static-analysis/custom"

    session = requests.Session()
    session.headers["dd-api-key"] = api_key
    session.headers["dd-application-key"] = app_key
    session.headers["Content-Type"] = "application/json"

    logger.info("Fetching custom rulesets from {site}...", site=site)

    try:
        rulesets = fetch_rulesets(session, base_url)
    except requests.exceptions.RequestException as e:
        logger.error("Failed to fetch rulesets: {e}", e=e)
        sys.exit(1)

    if not rulesets:
        logger.info("No custom rulesets found.")
        sys.exit(0)

    for item in rulesets:
        attrs = item["attributes"]
        name = attrs["name"]
        rules = attrs.get("rules") or []
        ruleset_dir = RULESETS_DIR / name

        write_ruleset(ruleset_dir, attrs)
        for rule in rules:
            write_rule(ruleset_dir, rule)

        no_revision = sum(1 for r in rules if not r.get("last_revision"))
        suffix = f", {no_revision} without content" if no_revision else ""
        logger.info(
            "{name} ({count} {word}{suffix})",
            name=name,
            count=len(rules),
            word="rules" if len(rules) != 1 else "rule",
            suffix=suffix,
        )

    logger.info("Pulled {count} ruleset(s) to rulesets/", count=len(rulesets))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# Unless explicitly stated otherwise all files in this repository are licensed under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/) Copyright 2026-present Datadog, Inc.
"""
Upload custom static analysis rules to the Datadog API.

Reads rulesets from the rulesets/ directory and syncs them to the Datadog
static analysis API (v2). On each run the script:
  - Creates rulesets/rules that are new on disk
  - Updates rulesets/rules that already exist in the backend
  - Deletes rulesets/rules that were removed from disk

Required env vars:
  DD_API_KEY           - Datadog API key
  DD_APP_KEY           - Datadog Application key
  DD_SITE              - Datadog site (default: datadoghq.com)
"""

import argparse
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



def b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def read_local_rulesets(rulesets_dir: Path) -> dict[str, dict[str, Any]]:
    """
    Walk rulesets_dir and return:
      { ruleset_name: {"meta": {...}, "rules": {rule_name: rule_dict}} }
    """
    result = {}
    for ruleset_dir in sorted(rulesets_dir.iterdir()):
        if not ruleset_dir.is_dir():
            continue
        meta_file = ruleset_dir / "ruleset.yaml"
        if not meta_file.exists():
            logger.warning(
                "{dir}/ has no ruleset.yaml — skipping", dir=ruleset_dir.name
            )
            continue

        with meta_file.open() as f:
            meta = yaml.safe_load(f)

        rules = {}
        for rule_file in sorted(ruleset_dir.glob("*.yaml")):
            if rule_file.name == "ruleset.yaml":
                continue
            with rule_file.open() as f:
                rule = yaml.safe_load(f)
            rules[rule["name"]] = rule

        result[meta["name"]] = {"meta": meta, "rules": rules}
    return result


def fetch_remote_rulesets(session: requests.Session, base_url: str) -> dict[str, dict[str, Any]]:
    """
    GET /custom/rulesets → returns all rulesets with rules inline.
    Returns:
      {
        ruleset_name: {
          "id": str,
          "short_description": str,  # b64 as returned by API
          "description": str,        # b64 as returned by API
          "rules": {
            rule_name: {             # fields from last_revision, b64 as-is
              "short_description", "description", "code",
              "tree_sitter_query", "language", "severity", "category"
            } | None                 # None if rule has no revision yet
          }
        }
      }
    """
    resp = session.get(f"{base_url}/rulesets", timeout=10)
    resp.raise_for_status()
    data = resp.json().get("data") or []

    result = {}
    for item in data:
        attrs = item["attributes"]
        rules = {}
        for r in attrs.get("rules") or []:
            rev = r.get("last_revision")
            rules[r["name"]] = (
                {
                    "short_description": rev.get("short_description", ""),
                    "description": rev.get("description", ""),
                    "code": rev.get("code", ""),
                    "tree_sitter_query": rev.get("tree_sitter_query", ""),
                    "language": rev.get("language", ""),
                    "severity": rev.get("severity", ""),
                    "category": rev.get("category", ""),
                    "arguments": rev.get("arguments") or [],
                    "tests": rev.get("tests") or [],
                    "is_published": rev.get("is_published", False),
                }
                if rev
                else None
            )
        result[attrs["name"]] = {
            "id": item["id"],
            "short_description": attrs.get("short_description", ""),
            "description": attrs.get("description", ""),
            "rules": rules,
        }
    return result


def upsert_ruleset(
    session: requests.Session,
    base_url: str,
    meta: dict[str, Any],
    remote: dict[str, Any] | None,
    dry_run: bool,
) -> bool | None:
    """Returns True if changed, None if no-op, False if failed."""
    name = meta["name"]
    exists = remote is not None

    if exists:
        changed = (
            b64(meta.get("short_description", "")) != remote["short_description"]
            or b64(meta.get("description", "")) != remote["description"]
        )
        if not changed:
            return None

    action = "Would update" if exists else "Would create"
    if dry_run:
        logger.info("[dry-run] {action} ruleset: {name}", action=action, name=name)
        return True

    payload = {
        "data": {
            "type": "custom_ruleset",
            "attributes": {
                "id": name,
                "name": name,
                "short_description": b64(meta.get("short_description", "")),
                "description": b64(meta.get("description", "")),
            },
        }
    }
    if exists:
        remote_id = remote["id"]
        resp = session.patch(
            f"{base_url}/rulesets/{remote_id}", json=payload, timeout=10
        )
    else:
        resp = session.put(f"{base_url}/rulesets", json=payload, timeout=10)

    if not resp.ok:
        logger.error(
            "FAILED to {action} ruleset {name} — HTTP {status}: {text}",
            action="update" if exists else "create",
            name=name,
            status=resp.status_code,
            text=resp.text,
        )
        return False
    return True


def delete_ruleset(
    session: requests.Session, base_url: str, name: str, dry_run: bool
) -> bool:
    if dry_run:
        logger.info("[dry-run] Would delete ruleset: {name}", name=name)
        return True
    resp = session.delete(f"{base_url}/rulesets/{name}", timeout=10)
    if not resp.ok:
        logger.error(
            "FAILED to delete ruleset {name} — HTTP {status}: {text}",
            name=name,
            status=resp.status_code,
            text=resp.text,
        )
        return False
    logger.info("Deleted ruleset: {name}", name=name)
    return True


def delete_rule(
    session: requests.Session,
    base_url: str,
    ruleset_name: str,
    rule_name: str,
    dry_run: bool,
) -> bool:
    if dry_run:
        logger.info("[dry-run] Would delete rule: {rule_name}", rule_name=rule_name)
        return True
    resp = session.delete(
        f"{base_url}/rulesets/{ruleset_name}/rules/{rule_name}", timeout=10
    )
    if not resp.ok:
        logger.error(
            "FAILED to delete rule {rule_name} — HTTP {status}: {text}",
            rule_name=rule_name,
            status=resp.status_code,
            text=resp.text,
        )
        return False
    logger.info("  Deleted rule: {rule_name}", rule_name=rule_name)
    return True


def build_revision_payload(rule: dict[str, Any]) -> dict[str, Any]:
    tests = [
        {
            "filename": t["filename"],
            "code": b64(t["code"]),
            "annotation_count": t["annotation_count"],
        }
        for t in rule.get("tests", [])
    ]
    arguments = [
        {"name": b64(a["name"]), "description": b64(a.get("description", ""))}
        for a in rule.get("arguments", [])
    ]
    return {
        "data": {
            "type": "custom_rule_revision",
            "attributes": {
                "id": rule["name"],
                "short_description": b64(rule.get("short_description", "")),
                "description": b64(rule.get("description", "")),
                "language": rule["language"],
                "tree_sitter_query": b64(rule.get("tree_sitter_query", "")),
                "code": b64(rule["code"]),
                "severity": rule["severity"],
                "category": rule["category"],
                "arguments": arguments,
                "tests": tests,
                "is_published": rule.get("is_published", False),
                "should_use_ai_fix": False,
                "is_testing": False,
            },
        }
    }


def sync_rule(
    session: requests.Session,
    base_url: str,
    ruleset_name: str,
    rule: dict[str, Any],
    remote_rule: dict[str, Any] | None,
    dry_run: bool,
) -> bool | None:
    """Returns True if changed, None if no-op, False if failed."""
    rule_name = rule["name"]
    rules_url = f"{base_url}/rulesets/{ruleset_name}/rules"
    exists = remote_rule is not None

    # Skip if nothing has changed
    if remote_rule is not None:
        local_arguments = [
            {"name": b64(a["name"]), "description": b64(a.get("description", ""))}
            for a in rule.get("arguments", [])
        ]
        local_tests = [
            {
                "filename": t["filename"],
                "code": b64(t["code"]),
                "annotation_count": t["annotation_count"],
            }
            for t in rule.get("tests", [])
        ]
        changed = (
            b64(rule.get("short_description", "")) != remote_rule["short_description"]
            or b64(rule.get("description", "")) != remote_rule["description"]
            or b64(rule["code"]) != remote_rule["code"]
            or b64(rule.get("tree_sitter_query", ""))
            != remote_rule["tree_sitter_query"]
            or rule["language"] != remote_rule["language"]
            or rule["severity"] != remote_rule["severity"]
            or rule["category"] != remote_rule["category"]
            or local_arguments != remote_rule["arguments"]
            or local_tests != remote_rule["tests"]
            or rule.get("is_published", False) != remote_rule["is_published"]
        )
        if not changed:
            if dry_run:
                logger.info("[dry-run] No changes: {rule_name}", rule_name=rule_name)
            return None

    if dry_run:
        action = "Would update" if exists else "Would create"
        logger.info(
            "[dry-run] {action} rule: {rule_name}", action=action, rule_name=rule_name
        )
        return True

    # Create rule stub if it doesn't exist
    if not exists:
        create_payload = {
            "data": {
                "type": "custom_rule",
                "attributes": {"id": rule_name, "name": rule_name},
            }
        }
        resp = session.put(rules_url, json=create_payload, timeout=10)
        if not resp.ok:
            logger.error(
                "FAILED to create rule stub {rule_name} — HTTP {status}: {text}",
                rule_name=rule_name,
                status=resp.status_code,
                text=resp.text,
            )
            return False

    # Push new revision (is_published: true publishes in the same call)
    rev_resp = session.put(
        f"{rules_url}/{rule_name}/revisions",
        json=build_revision_payload(rule),
        timeout=10,
    )
    if not rev_resp.ok:
        logger.error(
            "FAILED to push revision for {rule_name} — HTTP {status}: {text}",
            rule_name=rule_name,
            status=rev_resp.status_code,
            text=rev_resp.text,
        )
        return False

    action = "Created" if not exists else "Updated"
    logger.info("  {action} rule: {rule_name}", action=action, rule_name=rule_name)
    return True


def sync_ruleset(
    session: requests.Session,
    base_url: str,
    dry_run: bool,
    meta: dict[str, Any],
    rules: dict[str, dict[str, Any]],
    remote: dict[str, Any] | None,
) -> bool:
    name = meta["name"]
    exists = remote is not None
    remote_rules = remote["rules"] if exists else {}

    ruleset_changed = upsert_ruleset(session, base_url, meta, remote, dry_run)
    if ruleset_changed is False:
        return False

    # Delete rules that are in the backend but no longer on disk
    deleted_rules = sorted(set(remote_rules) - set(rules))
    for remote_rule_name in deleted_rules:
        delete_rule(session, base_url, name, remote_rule_name, dry_run)

    # Sync each local rule
    failed_rules = []
    any_rule_changed = False
    for rule in rules.values():
        remote_rule = remote_rules.get(rule["name"])  # None if new, dict if existing
        result = sync_rule(session, base_url, name, rule, remote_rule, dry_run)
        if result is False:
            failed_rules.append(rule["name"])
        elif result is True:
            any_rule_changed = True

    if failed_rules:
        logger.error(
            "Ruleset: {name} — {count} rule(s) failed: {rules}",
            name=name,
            count=len(failed_rules),
            rules=", ".join(failed_rules),
        )
        return False

    if ruleset_changed is True or any_rule_changed or deleted_rules:
        action = "updated" if exists else "created"
        logger.info("Ruleset: {name} — {action}", name=name, action=action)
    else:
        logger.info("Ruleset: {name} — no changes", name=name)
    return True


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be created, updated, or deleted without making any changes",
    )
    args = parser.parse_args()
    dry_run: bool = args.dry_run

    api_key = os.environ.get("DD_API_KEY")
    app_key = os.environ.get("DD_APP_KEY")
    site = os.environ.get("DD_SITE")

    if not site:
        site = "datadoghq.com"

    missing = [
        k for k, v in {"DD_API_KEY": api_key, "DD_APP_KEY": app_key}.items() if not v
    ]
    setup_logging()

    if missing:
        logger.error(
            "Missing required environment variable(s): {vars}", vars=", ".join(missing)
        )
        sys.exit(1)
    base_url = f"https://api.{site}/api/v2/static-analysis/custom"

    local = read_local_rulesets(RULESETS_DIR)
    if not local:
        logger.info("No rulesets found in rulesets/")
        sys.exit(0)

    session = requests.Session()
    session.headers["dd-api-key"] = api_key
    session.headers["dd-application-key"] = app_key
    session.headers["Content-Type"] = "application/json"

    if dry_run:
        logger.info("Dry run — no changes will be made.")

    logger.info("Syncing {count} ruleset(s) to {site}...", count=len(local), site=site)

    try:
        remote = fetch_remote_rulesets(session, base_url)
    except requests.exceptions.RequestException as e:
        logger.error("Failed to fetch remote rulesets: {e}", e=e)
        sys.exit(1)

    failures = 0

    # Delete rulesets removed from disk
    for name in sorted(set(remote) - set(local)):
        if not delete_ruleset(session, base_url, remote[name]["id"], dry_run):
            failures += 1

    # Sync local rulesets
    for name, rs in local.items():
        remote_rs = remote.get(name)  # None if new, dict with id+rules if existing
        if not sync_ruleset(
            session, base_url, dry_run, rs["meta"], rs["rules"], remote_rs
        ):
            failures += 1

    if failures:
        logger.error("{count} ruleset(s) had failures.", count=failures)
        sys.exit(1)

    logger.info("All {count} ruleset(s) synced successfully.", count=len(local))


if __name__ == "__main__":
    main()

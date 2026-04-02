#!/usr/bin/env python3
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
  DD_SITE              - Datadog site (e.g. datadoghq.com, datadoghq.eu)
"""

import argparse
import base64
import operator
import os
import random
import sys
from pathlib import Path

import requests
import yaml

RULESETS_DIR = Path(__file__).parent.parent / "rulesets"


def confirm() -> bool:
    ops = {
        "+": operator.add,
        "-": operator.sub,
        "*": operator.mul,
    }
    symbol, fn = random.choice(list(ops.items()))
    a, b = random.randint(1, 12), random.randint(1, 12)
    answer = fn(a, b)
    try:
        guess = input(f"Confirm: {a} {symbol} {b} = ")
    except (KeyboardInterrupt, EOFError):
        print()
        return False
    return guess.strip() == str(answer)


def b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def read_local_rulesets(rulesets_dir: Path) -> dict[str, dict]:
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
            print(f"  WARNING: {ruleset_dir.name}/ has no ruleset.yaml — skipping")
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


def fetch_remote_rulesets(
    session: requests.Session, base_url: str
) -> dict[str, dict]:
    """
    GET /custom/rulesets → returns all rulesets with rules inline.
    Returns { ruleset_name: {"id": ..., "rules": set_of_rule_names} }.
    """
    resp = session.get(f"{base_url}/rulesets", timeout=10)
    resp.raise_for_status()
    data = resp.json().get("data") or []

    return {
        item["attributes"]["name"]: {
            "id": item["id"],
            "rules": {r["name"] for r in (item["attributes"].get("rules") or [])},
        }
        for item in data
    }


def upsert_ruleset(
    session: requests.Session,
    base_url: str,
    meta: dict,
    remote: dict | None,
    dry_run: bool,
) -> bool:
    name = meta["name"]
    exists = remote is not None
    action = "Would update" if exists else "Would create"
    if dry_run:
        print(f"  [dry-run] {action} ruleset: {name}")
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
        resp = session.patch(f"{base_url}/rulesets/{remote_id}", json=payload, timeout=10)
    else:
        resp = session.put(f"{base_url}/rulesets", json=payload, timeout=10)

    if not resp.ok:
        print(
            f"  FAILED to {'update' if exists else 'create'} ruleset {name} — HTTP {resp.status_code}: {resp.text}"
        )
        return False
    return True


def delete_ruleset(
    session: requests.Session, base_url: str, name: str, dry_run: bool
) -> bool:
    if dry_run:
        print(f"  [dry-run] Would delete ruleset: {name}")
        return True
    resp = session.delete(f"{base_url}/rulesets/{name}", timeout=10)
    if not resp.ok:
        print(
            f"  FAILED to delete ruleset {name} — HTTP {resp.status_code}: {resp.text}"
        )
        return False
    print(f"  Deleted ruleset: {name}")
    return True


def delete_rule(
    session: requests.Session,
    base_url: str,
    ruleset_name: str,
    rule_name: str,
    dry_run: bool,
) -> bool:
    if dry_run:
        print(f"    [dry-run] Would delete rule: {rule_name}")
        return True
    resp = session.delete(
        f"{base_url}/rulesets/{ruleset_name}/rules/{rule_name}", timeout=10
    )
    if not resp.ok:
        print(
            f"    FAILED to delete rule {rule_name} — HTTP {resp.status_code}: {resp.text}"
        )
        return False
    print(f"    Deleted rule: {rule_name}")
    return True


def build_revision_payload(rule: dict) -> dict:
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
                "id": "1",
                "short_description": b64(rule.get("short_description", "")),
                "description": b64(rule.get("description", "")),
                "language": rule["language"],
                "tree_sitter_query": b64(rule.get("tree_sitter_query", "")),
                "code": b64(rule["code"]),
                "severity": rule["severity"],
                "category": rule["category"],
                "arguments": arguments,
                "tests": tests,
                "is_published": True,
                "should_use_ai_fix": False,
                "is_testing": False,
            },
        }
    }


def sync_rule(
    session: requests.Session,
    base_url: str,
    ruleset_name: str,
    rule: dict,
    exists: bool,
    dry_run: bool,
) -> bool:
    rule_name = rule["name"]
    rules_url = f"{base_url}/rulesets/{ruleset_name}/rules"

    if dry_run:
        action = "Would update" if exists else "Would create"
        print(f"    [dry-run] {action} rule: {rule_name}")
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
            print(
                f"    FAILED to create rule stub {rule_name} — HTTP {resp.status_code}: {resp.text}"
            )
            return False

    # Push new revision (is_published: true publishes in the same call)
    rev_resp = session.put(
        f"{rules_url}/{rule_name}/revisions",
        json=build_revision_payload(rule),
        timeout=10,
    )
    if not rev_resp.ok:
        print(
            f"    FAILED to push revision for {rule_name} — HTTP {rev_resp.status_code}: {rev_resp.text}"
        )
        return False

    return True


def sync_ruleset(
    session: requests.Session,
    base_url: str,
    dry_run: bool,
    meta: dict,
    rules: dict[str, dict],
    remote: dict | None,
) -> bool:
    name = meta["name"]
    exists = remote is not None
    remote_rule_names = remote["rules"] if exists else None

    if not upsert_ruleset(session, base_url, meta, remote, dry_run):
        return False

    # Delete rules that are in the backend but no longer on disk
    if remote_rule_names:
        for remote_rule in sorted(remote_rule_names - set(rules)):
            delete_rule(session, base_url, name, remote_rule, dry_run)

    # Sync each local rule
    failed_rules = []
    for rule in rules.values():
        rule_exists = remote_rule_names is not None and rule["name"] in remote_rule_names
        if not sync_rule(session, base_url, name, rule, rule_exists, dry_run):
            failed_rules.append(rule["name"])

    if failed_rules:
        print(
            f"  FAILED: {name} — {len(failed_rules)} rule(s) failed: {', '.join(failed_rules)}"
        )
        return False

    action = "Updated" if exists else "Created"
    print(f"  {action}: {name} ({len(rules)} rule{'s' if len(rules) != 1 else ''})")
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

    missing = [
        k
        for k, v in {
            "DD_API_KEY": api_key,
            "DD_APP_KEY": app_key,
            "DD_SITE": site,
        }.items()
        if not v
    ]
    if missing:
        print(f"ERROR: Missing required environment variable(s): {', '.join(missing)}")
        sys.exit(1)
    base_url = f"https://api.{site}/api/v2/static-analysis/custom"

    local = read_local_rulesets(RULESETS_DIR)
    if not local:
        print("No rulesets found in rulesets/")
        sys.exit(0)

    session = requests.Session()
    session.headers["dd-api-key"] = api_key
    session.headers["dd-application-key"] = app_key
    session.headers["Content-Type"] = "application/json"

    if dry_run:
        print("Dry run — no changes will be made.\n")
    else:
        if not confirm():
            print("Incorrect. Aborting.")
            sys.exit(1)

    print(f"Syncing {len(local)} ruleset(s) to {site}...")

    try:
        remote = fetch_remote_rulesets(session, base_url)
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Failed to fetch remote rulesets: {e}")
        sys.exit(1)

    failures = 0

    # Delete rulesets removed from disk
    for name in sorted(set(remote) - set(local)):
        if not delete_ruleset(session, base_url, remote[name]["id"], dry_run):
            failures += 1

    # Sync local rulesets
    for name, rs in local.items():
        remote_rs = remote.get(name)  # None if new, dict with id+rules if existing
        if not sync_ruleset(session, base_url, dry_run, rs["meta"], rs["rules"], remote_rs):
            failures += 1

    print()
    if failures:
        print(f"{failures} ruleset(s) had failures.")
        sys.exit(1)

    print(f"All {len(local)} ruleset(s) synced successfully.")


if __name__ == "__main__":
    main()

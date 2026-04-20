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
from pydantic import BaseModel, Field


def setup_logging() -> None:
    logger.remove()
    logger.add(
        sys.stderr,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
    )


RULESETS_DIR = Path(__file__).parent.parent / "rulesets"


def b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def _decode(v: str) -> str:
    return base64.b64decode(v.encode()).decode() if v else v


class RemoteArgument(BaseModel):
    name: str
    description: str



class RemoteTest(BaseModel):
    filename: str
    code: str
    annotation_count: int


class RemoteRuleRevision(BaseModel):
    short_description: str
    description: str
    code: str
    tree_sitter_query: str
    language: str
    severity: str
    category: str
    cwe: str | None = None
    is_published: bool
    should_use_ai_fix: bool
    is_testing: bool
    tags: list[str] = Field(default_factory=list)
    arguments: list[RemoteArgument] = Field(default_factory=list)
    tests: list[RemoteTest] = Field(default_factory=list)


class RemoteRule(BaseModel):
    name: str
    last_revision: RemoteRuleRevision


class RemoteRuleset(BaseModel):
    name: str
    short_description: str
    description: str


class Argument(BaseModel):
    name: str
    description: str


class Test(BaseModel):
    filename: str
    code: str
    annotation_count: int


class Rule(BaseModel):
    name: str
    short_description: str
    description: str
    language: str
    code: str
    tree_sitter_query: str
    severity: str
    category: str
    cwe: str | None = None
    is_published: bool
    should_use_ai_fix: bool = False
    is_testing: bool = False
    tags: list[str] = Field(default_factory=list)
    arguments: list[Argument] = Field(default_factory=list)
    tests: list[Test] = Field(default_factory=list)


class Ruleset(BaseModel):
    name: str
    short_description: str
    description: str
    id: str | None = None
    rules: dict[str, Rule | None] = Field(default_factory=dict)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Ruleset):
            return NotImplemented
        return (
            self.name == other.name
            and self.short_description == other.short_description
            and self.description == other.description
            and self.rules == other.rules
        )


def remote_rule_to_rule(remote: RemoteRule) -> Rule:
    rev = remote.last_revision
    return Rule(
        name=remote.name,
        short_description=_decode(rev.short_description),
        description=_decode(rev.description),
        code=_decode(rev.code),
        tree_sitter_query=_decode(rev.tree_sitter_query),
        language=rev.language,
        severity=rev.severity,
        category=rev.category,
        cwe=rev.cwe,
        is_published=rev.is_published,
        should_use_ai_fix=rev.should_use_ai_fix,
        is_testing=rev.is_testing,
        tags=rev.tags,
        arguments=[
            Argument(name=_decode(a.name), description=_decode(a.description))
            for a in rev.arguments
        ],
        tests=[
            Test(
                filename=t.filename,
                code=_decode(t.code),
                annotation_count=t.annotation_count,
            )
            for t in rev.tests
        ],
    )


def rule_to_remote_rule(local: Rule) -> RemoteRule:
    return RemoteRule(
        name=local.name,
        last_revision=RemoteRuleRevision(
            short_description=b64(local.short_description),
            description=b64(local.description),
            code=b64(local.code),
            tree_sitter_query=b64(local.tree_sitter_query),
            language=local.language,
            severity=local.severity,
            category=local.category,
            cwe=local.cwe,
            is_published=local.is_published,
            should_use_ai_fix=local.should_use_ai_fix,
            is_testing=local.is_testing,
            tags=local.tags,
            arguments=[
                RemoteArgument(name=b64(a.name), description=b64(a.description))
                for a in local.arguments
            ],
            tests=[
                RemoteTest(
                    filename=t.filename,
                    code=b64(t.code),
                    annotation_count=t.annotation_count,
                )
                for t in local.tests
            ],
        ),
    )


def remote_ruleset_to_ruleset(item: dict) -> Ruleset:
    attrs = item["attributes"]
    remote = RemoteRuleset(**attrs)
    rules: dict[str, Rule | None] = {}
    for r in attrs.get("rules") or []:
        remote_rule = RemoteRule(**r)
        rules[remote_rule.name] = (
            remote_rule_to_rule(remote_rule) if remote_rule.last_revision else None
        )
    return Ruleset(
        name=remote.name,
        short_description=_decode(remote.short_description),
        description=_decode(remote.description),
        id=item["id"],
        rules=rules,
    )


def ruleset_to_remote_ruleset(local: Ruleset) -> RemoteRuleset:
    return RemoteRuleset(
        name=local.name,
        short_description=b64(local.short_description),
        description=b64(local.description),
    )


def read_local_rulesets(rulesets_dir: Path) -> dict[str, Ruleset]:
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

        rules: dict[str, Rule] = {}
        for rule_file in sorted(ruleset_dir.glob("*.yaml")):
            if rule_file.name == "ruleset.yaml":
                continue
            with rule_file.open() as f:
                data = yaml.safe_load(f)
            data.pop("checksum", None)
            rule = Rule(**data)
            rules[rule.name] = rule

        ruleset = Ruleset(**meta, rules=rules)
        result[ruleset.name] = ruleset
    return result


def fetch_remote_rulesets(
    session: requests.Session, base_url: str
) -> dict[str, Ruleset]:
    resp = session.get(f"{base_url}/rulesets", timeout=10)
    resp.raise_for_status()
    data = resp.json().get("data") or []
    return {
        item["attributes"]["name"]: remote_ruleset_to_ruleset(item) for item in data
    }


# Business logic


def ruleset_metadata_changed(local: Ruleset, remote: Ruleset) -> bool:
    return (
        local.short_description != remote.short_description
        or local.description != remote.description
    )


def compute_rule_changes(
    local: dict[str, Rule],
    remote: dict[str, Rule | None],
) -> tuple[list[Rule], list[Rule], list[str]]:
    to_create = [r for name, r in local.items() if name not in remote]
    to_update = [
        r
        for name, r in local.items()
        if name in remote and remote[name] is not None and r != remote[name]
    ]
    to_delete = sorted(name for name in remote if name not in local)
    return to_create, to_update, to_delete


# Payload builders


def build_ruleset_payload(ruleset: Ruleset) -> dict[str, Any]:
    remote = ruleset_to_remote_ruleset(ruleset)
    return {
        "data": {
            "type": "custom_ruleset",
            "attributes": {"id": remote.name, **remote.model_dump()},
        }
    }


def build_revision_payload(rule: Rule) -> dict[str, Any]:
    remote = rule_to_remote_rule(rule)
    return {
        "data": {
            "type": "custom_rule_revision",
            "attributes": {"id": rule.name, **remote.last_revision.model_dump()},
        }
    }


# API calls


def api_upsert_ruleset(
    session: requests.Session,
    base_url: str,
    local: Ruleset,
    remote: Ruleset | None,
) -> bool:
    payload = build_ruleset_payload(local)
    if remote is not None:
        resp = session.patch(
            f"{base_url}/rulesets/{remote.id}", json=payload, timeout=10
        )
        action = "update"
    else:
        resp = session.put(f"{base_url}/rulesets", json=payload, timeout=10)
        action = "create"
    if not resp.ok:
        logger.error(
            "FAILED to {action} ruleset {name} — HTTP {status}: {text}",
            action=action,
            name=local.name,
            status=resp.status_code,
            text=resp.text,
        )
        return False
    return True


def api_delete_ruleset(
    session: requests.Session, base_url: str, ruleset_id: str
) -> bool:
    resp = session.delete(f"{base_url}/rulesets/{ruleset_id}", timeout=10)
    if not resp.ok:
        logger.error(
            "FAILED to delete ruleset {id} — HTTP {status}: {text}",
            id=ruleset_id,
            status=resp.status_code,
            text=resp.text,
        )
        return False
    logger.info("Deleted ruleset: {id}", id=ruleset_id)
    return True


def api_push_revision(
    session: requests.Session, base_url: str, ruleset_name: str, rule: Rule
) -> bool:
    resp = session.put(
        f"{base_url}/rulesets/{ruleset_name}/rules/{rule.name}/revisions",
        json=build_revision_payload(rule),
        timeout=10,
    )
    if not resp.ok:
        logger.error(
            "FAILED to push revision for {rule_name} — HTTP {status}: {text}",
            rule_name=rule.name,
            status=resp.status_code,
            text=resp.text,
        )
        return False
    return True


def api_create_rule(
    session: requests.Session, base_url: str, ruleset_name: str, rule: Rule
) -> bool:
    rules_url = f"{base_url}/rulesets/{ruleset_name}/rules"
    resp = session.put(
        rules_url,
        json={
            "data": {
                "type": "custom_rule",
                "attributes": {"id": rule.name, "name": rule.name},
            }
        },
        timeout=10,
    )
    if not resp.ok:
        logger.error(
            "FAILED to create rule stub {rule_name} — HTTP {status}: {text}",
            rule_name=rule.name,
            status=resp.status_code,
            text=resp.text,
        )
        return False
    return api_push_revision(session, base_url, ruleset_name, rule)


def api_update_rule(
    session: requests.Session, base_url: str, ruleset_name: str, rule: Rule
) -> bool:
    return api_push_revision(session, base_url, ruleset_name, rule)


def api_delete_rule(
    session: requests.Session, base_url: str, ruleset_name: str, rule_name: str
) -> bool:
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


# Orchestration


def sync_ruleset(
    session: requests.Session,
    base_url: str,
    dry_run: bool,
    local: Ruleset,
    remote: Ruleset | None,
) -> bool:
    exists = remote is not None
    remote_rules = remote.rules if exists else {}

    needs_upsert = not exists or ruleset_metadata_changed(local, remote)
    assert local.rules is not None
    to_create, to_update, to_delete = compute_rule_changes(local.rules, remote_rules)

    if dry_run:
        if needs_upsert:
            action = "Would update" if exists else "Would create"
            logger.info(
                "[dry-run] {action} ruleset: {name}", action=action, name=local.name
            )
        for rule in to_create:
            logger.info("[dry-run] Would create rule: {name}", name=rule.name)
        for rule in to_update:
            logger.info("[dry-run] Would update rule: {name}", name=rule.name)
        for name in to_delete:
            logger.info("[dry-run] Would delete rule: {name}", name=name)
        if not needs_upsert and not to_create and not to_update and not to_delete:
            logger.info("Ruleset: {name} — no changes", name=local.name)
        return True

    if needs_upsert:
        if not api_upsert_ruleset(session, base_url, local, remote):
            return False

    for name in to_delete:
        api_delete_rule(session, base_url, local.name, name)

    failed_rules = []
    for rule in to_create:
        if not api_create_rule(session, base_url, local.name, rule):
            failed_rules.append(rule.name)
    for rule in to_update:
        if not api_update_rule(session, base_url, local.name, rule):
            failed_rules.append(rule.name)

    if failed_rules:
        logger.error(
            "Ruleset: {name} — {count} rule(s) failed: {rules}",
            name=local.name,
            count=len(failed_rules),
            rules=", ".join(failed_rules),
        )
        return False

    if needs_upsert or to_create or to_update or to_delete:
        action = "updated" if exists else "created"
        logger.info("Ruleset: {name} — {action}", name=local.name, action=action)
    else:
        logger.info("Ruleset: {name} — no changes", name=local.name)
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
        if dry_run:
            logger.info("[dry-run] Would delete ruleset: {name}", name=name)
        elif not api_delete_ruleset(session, base_url, remote[name].id):
            failures += 1

    for name, rs in local.items():
        remote_rs = remote.get(name)
        if not sync_ruleset(session, base_url, dry_run, rs, remote_rs):
            failures += 1

    if failures:
        logger.error("{count} ruleset(s) had failures.", count=failures)
        sys.exit(1)

    logger.info("All {count} ruleset(s) synced successfully.", count=len(local))


if __name__ == "__main__":
    main()

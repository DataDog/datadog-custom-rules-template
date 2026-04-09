# Unless explicitly stated otherwise all files in this repository are licensed under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/) Copyright 2026-present Datadog, Inc.
import base64

import pytest

from pathlib import Path

import yaml

from scripts.upload import (
    b64,
    build_revision_payload,
    compute_rule_changes,
    read_local_rulesets,
    rule_has_changed,
    ruleset_has_changed,
)


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def make_rule(**kwargs) -> dict:
    """Build a local rule dict (as read from YAML — plain strings, not b64)."""
    defaults = {
        "name": "test-rule",
        "short_description": "A test rule",
        "description": "A longer description",
        "code": "function visit(query) {}",
        "tree_sitter_query": "(identifier) @id",
        "language": "PYTHON",
        "severity": "WARNING",
        "category": "SECURITY",
        "arguments": [],
        "tests": [],
        "is_published": True,
    }
    defaults.update(kwargs)
    return defaults


def make_remote_rule(**kwargs) -> dict:
    """Build a remote rule dict (as returned by the API — string fields are b64 encoded)."""
    rule = make_rule(**kwargs)
    return {
        "short_description": _b64(rule["short_description"]),
        "description": _b64(rule["description"]),
        "code": _b64(rule["code"]),
        "tree_sitter_query": _b64(rule["tree_sitter_query"]),
        "language": rule["language"],
        "severity": rule["severity"],
        "category": rule["category"],
        "arguments": [
            {"name": _b64(a["name"]), "description": _b64(a.get("description", ""))}
            for a in rule["arguments"]
        ],
        "tests": [
            {
                "filename": t["filename"],
                "code": _b64(t["code"]),
                "annotation_count": t["annotation_count"],
            }
            for t in rule["tests"]
        ],
        "is_published": rule["is_published"],
    }


# --- b64 ---


def test_b64_encodes_string():
    assert b64("hello") == _b64("hello")


def test_b64_empty_string():
    assert b64("") == _b64("")


def test_b64_multiline():
    code = "function visit() {\n  return;\n}"
    assert b64(code) == _b64(code)


# --- build_revision_payload ---


def test_build_revision_payload_encodes_string_fields():
    rule = make_rule()
    payload = build_revision_payload(rule)
    attrs = payload["data"]["attributes"]

    assert attrs["short_description"] == _b64(rule["short_description"])
    assert attrs["description"] == _b64(rule["description"])
    assert attrs["code"] == _b64(rule["code"])
    assert attrs["tree_sitter_query"] == _b64(rule["tree_sitter_query"])


def test_build_revision_payload_passthrough_fields():
    rule = make_rule()
    attrs = build_revision_payload(rule)["data"]["attributes"]

    assert attrs["language"] == rule["language"]
    assert attrs["severity"] == rule["severity"]
    assert attrs["category"] == rule["category"]
    assert attrs["is_published"] == rule["is_published"]


def test_build_revision_payload_respects_is_published():
    attrs_true = build_revision_payload(make_rule(is_published=True))["data"][
        "attributes"
    ]
    attrs_false = build_revision_payload(make_rule(is_published=False))["data"][
        "attributes"
    ]

    assert attrs_true["is_published"] is True
    assert attrs_false["is_published"] is False


def test_build_revision_payload_encodes_arguments():
    rule = make_rule(arguments=[{"name": "myArg", "description": "does something"}])
    attrs = build_revision_payload(rule)["data"]["attributes"]

    assert attrs["arguments"] == [
        {"name": _b64("myArg"), "description": _b64("does something")}
    ]


def test_build_revision_payload_encodes_test_code():
    rule = make_rule(
        tests=[{"filename": "test.py", "code": "eval('x')", "annotation_count": 1}]
    )
    attrs = build_revision_payload(rule)["data"]["attributes"]

    assert attrs["tests"] == [
        {"filename": "test.py", "code": _b64("eval('x')"), "annotation_count": 1}
    ]


# --- rule_has_changed ---


def test_rule_has_changed_no_changes():
    rule = make_rule()
    remote = make_remote_rule()
    assert rule_has_changed(rule, remote) is False


@pytest.mark.parametrize(
    "field,local_val,remote_val",
    [
        ("code", "function visit() { return 1; }", "function visit() { return 2; }"),
        ("short_description", "new description", "old description"),
        ("description", "new", "old"),
        ("tree_sitter_query", "(call) @call", "(identifier) @id"),
        ("language", "JAVASCRIPT", "PYTHON"),
        ("severity", "ERROR", "WARNING"),
        ("category", "BEST_PRACTICES", "SECURITY"),
        ("is_published", False, True),
        (
            "arguments",
            [{"name": "myArg", "description": "does something"}],
            [{"name": "myArg", "description": "does something else"}],
        ),
        (
            "tests",
            [{"filename": "test.py", "code": "eval('x')", "annotation_count": 1}],
            [{"filename": "test.py", "code": "eval('y')", "annotation_count": 1}],
        ),
    ],
)
def test_rule_has_changed_detects_field_change(field, local_val, remote_val):
    rule = make_rule(**{field: local_val})
    remote = make_remote_rule(**{field: remote_val})
    assert rule_has_changed(rule, remote) is True


@pytest.mark.parametrize(
    "field,val",
    [
        ("arguments", [{"name": "myArg", "description": "does something"}]),
        (
            "tests",
            [{"filename": "test.py", "code": "eval('x')", "annotation_count": 1}],
        ),
    ],
)
def test_rule_has_changed_unchanged(field, val):
    rule = make_rule(**{field: val})
    remote = make_remote_rule(**{field: val})
    assert rule_has_changed(rule, remote) is False


# --- read_local_rulesets ---


def _write_yaml(path: Path, data: dict) -> None:
    path.write_text(yaml.dump(data))


def test_read_local_rulesets_single_ruleset(tmp_path):
    rs_dir = tmp_path / "my-ruleset"
    rs_dir.mkdir()
    _write_yaml(
        rs_dir / "ruleset.yaml",
        {"name": "my-ruleset", "short_description": "A ruleset"},
    )
    _write_yaml(rs_dir / "no-eval.yaml", make_rule(name="no-eval"))

    result = read_local_rulesets(tmp_path)

    assert "my-ruleset" in result
    assert "no-eval" in result["my-ruleset"]["rules"]


def test_read_local_rulesets_multiple_rulesets(tmp_path):
    for rs_name in ["ruleset-a", "ruleset-b"]:
        rs_dir = tmp_path / rs_name
        rs_dir.mkdir()
        _write_yaml(rs_dir / "ruleset.yaml", {"name": rs_name})
        _write_yaml(rs_dir / "rule.yaml", make_rule(name="rule"))

    result = read_local_rulesets(tmp_path)

    assert "ruleset-a" in result
    assert "ruleset-b" in result


def test_read_local_rulesets_skips_missing_ruleset_yaml(tmp_path):
    rs_dir = tmp_path / "bad-ruleset"
    rs_dir.mkdir()
    _write_yaml(rs_dir / "rule.yaml", make_rule(name="rule"))

    result = read_local_rulesets(tmp_path)

    assert "bad-ruleset" not in result


def test_read_local_rulesets_empty_directory(tmp_path):
    result = read_local_rulesets(tmp_path)
    assert result == {}


# --- ruleset_has_changed ---


def test_ruleset_has_changed_no_changes():
    meta = {"name": "rs", "short_description": "desc", "description": "full"}
    remote = {"short_description": _b64("desc"), "description": _b64("full")}
    assert ruleset_has_changed(meta, remote) is False


@pytest.mark.parametrize(
    "field,local_val,remote_val",
    [
        ("short_description", "new desc", "old desc"),
        ("description", "new full", "old full"),
    ],
)
def test_ruleset_has_changed_field_change(field, local_val, remote_val):
    meta = {
        "name": "rs",
        "short_description": "short_description",
        "description": "description",
    }
    remote = {
        "short_description": _b64("short_description"),
        "description": _b64("description"),
    }
    meta[field] = local_val
    remote[field] = _b64(remote_val)
    assert ruleset_has_changed(meta, remote) is True


# --- compute_rule_changes ---


def test_compute_rule_changes_all_new():
    local = {"rule-a": make_rule(name="rule-a"), "rule-b": make_rule(name="rule-b")}
    to_create, to_update, to_delete = compute_rule_changes(local, {})
    assert {rule["name"] for rule in to_create} == {"rule-a", "rule-b"}
    assert to_update == []
    assert to_delete == []


def test_compute_rule_changes_all_unchanged():
    rule = make_rule()
    to_create, to_update, to_delete = compute_rule_changes(
        {rule["name"]: rule}, {rule["name"]: make_remote_rule()}
    )
    assert to_create == []
    assert to_update == []
    assert to_delete == []


def test_compute_rule_changes_detects_update():
    rule = make_rule(code="new code")
    to_create, to_update, to_delete = compute_rule_changes(
        {rule["name"]: rule}, {rule["name"]: make_remote_rule(code="old code")}
    )
    assert to_create == []
    assert [r["name"] for r in to_update] == [rule["name"]]
    assert to_delete == []


def test_compute_rule_changes_detects_delete():
    to_create, to_update, to_delete = compute_rule_changes(
        {}, {"old-rule": make_remote_rule()}
    )
    assert to_create == []
    assert to_update == []
    assert to_delete == ["old-rule"]


def test_compute_rule_changes_mixed():
    new_rule = make_rule(name="new-rule")
    changed_rule = make_rule(name="changed-rule", code="new code")
    unchanged_rule = make_rule(name="unchanged-rule")

    local = {
        "new-rule": new_rule,
        "changed-rule": changed_rule,
        "unchanged-rule": unchanged_rule,
    }
    remote = {
        "changed-rule": make_remote_rule(code="old code"),
        "unchanged-rule": make_remote_rule(),
        "deleted-rule": make_remote_rule(),
    }

    to_create, to_update, to_delete = compute_rule_changes(local, remote)
    assert [rule["name"] for rule in to_create] == ["new-rule"]
    assert [rule["name"] for rule in to_update] == ["changed-rule"]
    assert to_delete == ["deleted-rule"]

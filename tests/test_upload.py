# Unless explicitly stated otherwise all files in this repository are licensed under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/) Copyright 2026-present Datadog, Inc.
import base64
from pathlib import Path
from typing import Any

import pytest
import yaml

from scripts.upload import (
    Argument,
    RemoteArgument,
    RemoteRule,
    RemoteRuleRevision,
    RemoteTest,
    Rule,
    Ruleset,
    Test,
    build_revision_payload,
    compute_rule_changes,
    read_local_rulesets,
    remote_rule_to_rule,
    ruleset_metadata_changed,
)


def encode_b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def make_rule(**kwargs: Any) -> Rule:
    return Rule(**{
        "name": "test-rule",
        "short_description": "A test rule",
        "description": "A longer description",
        "code": "function visit(node, filename, code) {}",
        "tree_sitter_query": "(identifier) @id",
        "language": "JAVASCRIPT",
        "severity": "WARNING",
        "category": "BEST_PRACTICES",
        "is_published": True,
        **kwargs,
    })


def make_remote_rule(**kwargs: Any) -> RemoteRule:
    rule = make_rule(**kwargs)
    rev = RemoteRuleRevision(
        short_description=encode_b64(rule.short_description),
        description=encode_b64(rule.description),
        code=encode_b64(rule.code),
        tree_sitter_query=encode_b64(rule.tree_sitter_query),
        language=rule.language,
        severity=rule.severity,
        category=rule.category,
        is_published=rule.is_published,
        should_use_ai_fix=rule.should_use_ai_fix,
        is_testing=rule.is_testing,
        arguments=[
            RemoteArgument(name=encode_b64(a.name), description=encode_b64(a.description))
            for a in rule.arguments
        ],
        tests=[
            RemoteTest(filename=t.filename, code=encode_b64(t.code), annotation_count=t.annotation_count)
            for t in rule.tests
        ],
    )
    return RemoteRule(name=rule.name, last_revision=rev)


def _write_yaml(path: Path, data: dict) -> None:
    _ = path.write_text(yaml.dump(data))



# remote_rule_to_rule


def test_remote_rule_to_rule_decodes_fields():
    remote = make_remote_rule()
    rule = remote_rule_to_rule(remote)

    assert rule.name == remote.name
    assert rule.short_description == "A test rule"
    assert rule.code == "function visit(node, filename, code) {}"
    assert rule.tree_sitter_query == "(identifier) @id"


def test_remote_rule_to_rule_decodes_arguments():
    remote = make_remote_rule(
        arguments=[Argument(name="myArg", description="does something")]
    )
    rule = remote_rule_to_rule(remote)

    assert rule.arguments[0].name == "myArg"
    assert rule.arguments[0].description == "does something"


def test_remote_rule_to_rule_decodes_tests():
    remote = make_remote_rule(
        tests=[Test(filename="test.js", code="eval('x')", annotation_count=1)]
    )
    rule = remote_rule_to_rule(remote)

    assert rule.tests[0].code == "eval('x')"


# build_revision_payload


def test_build_revision_payload_encodes_string_fields():
    rule = make_rule()
    attrs = build_revision_payload(rule)["data"]["attributes"]

    assert attrs["short_description"] == encode_b64(rule.short_description)
    assert attrs["description"] == encode_b64(rule.description)
    assert attrs["code"] == encode_b64(rule.code)
    assert attrs["tree_sitter_query"] == encode_b64(rule.tree_sitter_query)



def test_build_revision_payload_encodes_arguments():
    rule = make_rule(arguments=[Argument(name="myArg", description="does something")])
    attrs = build_revision_payload(rule)["data"]["attributes"]

    assert attrs["arguments"] == [
        {"name": encode_b64("myArg"), "description": encode_b64("does something")}
    ]


def test_build_revision_payload_encodes_test_code():
    rule = make_rule(
        tests=[Test(filename="test.js", code="eval('x')", annotation_count=1)]
    )
    attrs = build_revision_payload(rule)["data"]["attributes"]

    assert attrs["tests"] == [
        {"filename": "test.js", "code": encode_b64("eval('x')"), "annotation_count": 1}
    ]


# ruleset_metadata_changed


def test_ruleset_metadata_changed_no_changes():
    local = Ruleset(name="rs", short_description="desc", description="full")
    remote = Ruleset(name="rs", short_description="desc", description="full")
    assert ruleset_metadata_changed(local, remote) is False


@pytest.mark.parametrize("field,local_val,remote_val", [
    ("short_description", "new desc", "old desc"),
    ("description", "new full", "old full"),
])
def test_ruleset_metadata_changed_detects_change(field: str, local_val: Any, remote_val: Any):
    base = dict(short_description="desc", description="full")
    local = Ruleset(name="rs", **{**base, field: local_val})
    remote = Ruleset(name="rs", **{**base, field: remote_val})
    assert ruleset_metadata_changed(local, remote) is True


# compute_rule_changes


def test_compute_rule_changes_all_new():
    local = {"rule-a": make_rule(name="rule-a"), "rule-b": make_rule(name="rule-b")}
    to_create, to_update, to_delete = compute_rule_changes(local, {})

    assert {r.name for r in to_create} == {"rule-a", "rule-b"}
    assert to_update == []
    assert to_delete == []


def test_compute_rule_changes_all_unchanged():
    rule = make_rule()
    remote_rule = remote_rule_to_rule(make_remote_rule())
    to_create, to_update, to_delete = compute_rule_changes(
        {rule.name: rule}, {rule.name: remote_rule}
    )

    assert to_create == []
    assert to_update == []
    assert to_delete == []


def test_compute_rule_changes_detects_update():
    local_rule = make_rule(code="new code")
    remote_rule = remote_rule_to_rule(make_remote_rule(code="old code"))
    to_create, to_update, to_delete = compute_rule_changes(
        {local_rule.name: local_rule}, {local_rule.name: remote_rule}
    )

    assert to_create == []
    assert [r.name for r in to_update] == [local_rule.name]
    assert to_delete == []


def test_compute_rule_changes_detects_delete():
    remote_rule = remote_rule_to_rule(make_remote_rule())
    to_create, to_update, to_delete = compute_rule_changes(
        {}, {remote_rule.name: remote_rule}
    )

    assert to_create == []
    assert to_update == []
    assert to_delete == [remote_rule.name]


def test_compute_rule_changes_mixed():
    new_rule = make_rule(name="new-rule")
    changed_local = make_rule(name="changed-rule", code="new code")
    changed_remote = remote_rule_to_rule(make_remote_rule(name="changed-rule", code="old code"))
    unchanged_rule = make_rule(name="unchanged-rule")
    unchanged_remote = remote_rule_to_rule(make_remote_rule(name="unchanged-rule"))
    deleted_remote = remote_rule_to_rule(make_remote_rule(name="deleted-rule"))

    local = {
        "new-rule": new_rule,
        "changed-rule": changed_local,
        "unchanged-rule": unchanged_rule,
    }
    remote = {
        "changed-rule": changed_remote,
        "unchanged-rule": unchanged_remote,
        "deleted-rule": deleted_remote,
    }

    to_create, to_update, to_delete = compute_rule_changes(local, remote)
    assert [r.name for r in to_create] == ["new-rule"]
    assert [r.name for r in to_update] == ["changed-rule"]
    assert to_delete == ["deleted-rule"]


# read_local_rulesets


def test_read_local_rulesets_single_ruleset(tmp_path: Path):
    rs_dir = tmp_path / "my-ruleset"
    rs_dir.mkdir()
    _write_yaml(rs_dir / "ruleset.yaml", {"name": "my-ruleset", "short_description": "A ruleset", "description": "A description"})
    _write_yaml(rs_dir / "no-eval.yaml", make_rule(name="no-eval").model_dump())

    result = read_local_rulesets(tmp_path)

    assert "my-ruleset" in result
    assert "no-eval" in result["my-ruleset"].rules



def test_read_local_rulesets_skips_missing_ruleset_yaml(tmp_path: Path):
    rs_dir = tmp_path / "bad-ruleset"
    rs_dir.mkdir()
    _write_yaml(rs_dir / "rule.yaml", make_rule(name="rule").model_dump())

    result = read_local_rulesets(tmp_path)

    assert result == {}


def test_read_local_rulesets_empty_directory(tmp_path: Path):
    result = read_local_rulesets(tmp_path)
    assert result == {}

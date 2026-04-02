# Custom Static Analysis Rules

A template for managing custom [Datadog Static Analysis](https://docs.datadoghq.com/code_analysis/static_analysis/) rules in Git. Rules defined here are automatically synced to Datadog on every push to `main` — created, updated, or deleted to match what's on disk.

> **Note:** This repo manages only your custom rules. Datadog's default rulesets are configured separately via your SAST config file and do not belong here.

## Getting started

1. Click **Use this template** on GitHub to create your own copy of this repo.
2. Add your Datadog API key and Application key as GitHub secrets (see [Authentication](#authentication)).
3. Rename `rulesets/my-custom-rules/` or add new ruleset directories under `rulesets/`.
4. Push to `main` — the GitHub Action uploads your rules automatically.

## Repository structure

```
rulesets/
  my-custom-rules/
    ruleset.yaml        # Ruleset metadata (name, description)
    no-eval.yaml        # Example rule — rename or delete this
    your-rule.yaml      # Add your own rules here
scripts/
  upload.py             # Sync script (no changes needed)
.github/
  workflows/
    upload-rules.yml    # GitHub Action (no changes needed)
pyproject.toml
uv.lock
```

## Authentication

The upload script authenticates with your Datadog API key and Application key.

1. In your GitHub repo, go to **Settings → Secrets and variables → Actions**.
2. Add two **secrets**:
   - `DD_API_KEY` — your [Datadog API key](https://app.datadoghq.com/organization-settings/api-keys)
   - `DD_APP_KEY` — your [Datadog Application key](https://app.datadoghq.com/organization-settings/application-keys)

3. Add a third secret named `DD_SITE` with your Datadog site hostname (e.g. `datadoghq.com`, `datadoghq.eu`, `us3.datadoghq.com`).

## How to test locally

```bash
export DD_API_KEY=<your-api-key>
export DD_APP_KEY=<your-app-key>
export DD_SITE=datadoghq.com

uv run scripts/upload.py
```

To target staging instead of production:

```bash
export DD_SITE=dd.datad0g.com
uv run scripts/upload.py
```

## Writing rules

Each ruleset is a directory under `rulesets/` containing a `ruleset.yaml` and one `.yaml` file per rule. The `no-eval.yaml` example is a good starting point.

### ruleset.yaml

```yaml
name: my-org-custom-rules       # Must be globally unique across Datadog
short_description: One-line summary
description: Longer description of what this ruleset covers.
```

### Rule file (e.g. `my-rule.yaml`)

```yaml
name: my-rule                   # Must match the filename (without .yaml)
short_description: One-line summary
description: |-
  Detailed description. Supports markdown.
category: SECURITY              # SECURITY | BEST_PRACTICES | CODE_STYLE | ERROR_PRONE | PERFORMANCE
severity: WARNING               # ERROR | WARNING | NOTICE | NONE
language: PYTHON                # See supported languages below
checksum: ""                    # Leave blank — computed by the server
cwe: "89"                       # Optional CWE identifier
arguments: []
tree_sitter_query: |-
  (call function: (identifier) @name (#eq? @name "eval"))
code: |-
  // JavaScript — runs in the Datadog analyzer
  function visit(node, filename, code) {
    const fn = node.captures["name"];
    if (!fn) return;
    addError(buildError(
      fn.start.line, fn.start.col,
      fn.end.line, fn.end.col,
      "Description of the violation",
    ));
  }
tests:
  - filename: compliant.py
    code: |
      safe_call()   # should NOT be flagged
    annotation_count: 0
  - filename: not_compliant.py
    code: |
      eval("1+1")   # should be flagged
    annotation_count: 1
is_published: true
```

### Supported languages

`PYTHON` `GO` `JAVA` `JAVASCRIPT` `TYPESCRIPT` `RUBY` `KOTLIN` `CSHARP` `RUST` `SWIFT` `PHP` `BASH` `TERRAFORM` `DOCKERFILE` `YAML` `JSON`

### Rule authoring tools

The [Datadog VSCode extension](https://marketplace.visualstudio.com/items?itemName=Datadog.datadog-vscode) includes a rule editor with real-time feedback as you write tree-sitter queries and detection logic. It's the fastest way to iterate on a new rule before pushing.

Additional resources:
- [Tree-sitter query syntax](https://tree-sitter.github.io/tree-sitter/using-parsers#pattern-matching-with-queries)
- [Datadog Static Analysis rule writing guide](https://docs.datadoghq.com/code_analysis/static_analysis/rules/)

## Multiple rulesets

Add as many ruleset directories as you need under `rulesets/`. Each is synced independently:

```
rulesets/
  my-org-python-rules/
    ruleset.yaml
    no-eval.yaml
  my-org-go-rules/
    ruleset.yaml
    no-sql-injection.yaml
```

## Triggering manually

You can trigger the sync from the **Actions** tab in GitHub without pushing a commit — useful for debugging or re-syncing after a key rotation. Click **Upload Custom Rules → Run workflow**.

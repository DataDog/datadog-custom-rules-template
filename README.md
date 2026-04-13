# Custom Static Analysis Rules

A template for managing custom [Datadog Static Analysis](https://docs.datadoghq.com/code_analysis/static_analysis/) rules in Git. Rules defined here are automatically synced to Datadog on every push to `main` — created, updated, or deleted to match what's on disk.

> **Note:** This repo manages only your custom rules. Datadog's default rulesets are configured separately via your SAST config file and do not belong here.

## Getting started

1. Click **Use this template** on GitHub to create your own copy of this repo.
2. Add your Datadog credentials as GitHub secrets (see [Authentication](#authentication)).
3. Rename `rulesets/my-custom-rules/` or add new ruleset directories under `rulesets/`.
4. Push to `main` — the GitHub Action uploads your rules automatically.

## Repository structure

```
rulesets/
  my-custom-rules/
    ruleset.yaml        # Ruleset metadata (name, description)
    no-debugger.yaml    # Example rule — replace or delete this
    your-rule.yaml      # Add your own rules here
scripts/
  upload.py             # Sync script (no changes needed)
.github/
  workflows/
    upload-rules.yml    # GitHub Action (no changes needed)
.ddsainclude            # Tells the Datadog extension which files open in the rule editor
pyproject.toml
uv.lock
```

## Authentication

1. In your GitHub repo, go to **Settings → Secrets and variables → Actions**.
2. Add three **secrets**:
   - `DD_API_KEY` — your [Datadog API key](https://app.datadoghq.com/organization-settings/api-keys)
   - `DD_APP_KEY` — your [Datadog Application key](https://app.datadoghq.com/organization-settings/application-keys)
   - `DD_SITE` — your Datadog site hostname (e.g. `datadoghq.com`, `datadoghq.eu`, `us3.datadoghq.com`)

## How sync works

On every push to `main`, the GitHub Action runs `upload.py` which:

- **Creates** rulesets and rules that are new on disk
- **Updates** rulesets and rules whose content has changed
- **Deletes** rulesets and rules that have been removed from disk

Only changed rules trigger API calls — unchanged rules are skipped.

You can also trigger a sync manually from the **Actions** tab without pushing a commit. Click **Upload Custom Rules → Run workflow**.

## Testing locally

```bash
export DD_API_KEY=<your-api-key>
export DD_APP_KEY=<your-app-key>
export DD_SITE=datadoghq.com

uv run scripts/upload.py
```

To preview what the sync would do without making any API calls — useful for validating changes before they hit the GitHub Action:

```bash
uv run scripts/upload.py --dry-run
```

To target staging instead of production:

```bash
export DD_SITE=datad0g.com
uv run scripts/upload.py
```

## Datadog VS Code extension

The `.ddsainclude` file controls which YAML files the [Datadog VS Code extension](https://marketplace.visualstudio.com/items?itemName=Datadog.datadog-vscode) automatically opens in the rule editor. By default it includes all rule files under `rulesets/` while excluding `ruleset.yaml` metadata files. If you add new ruleset directories or change your layout, update the glob patterns in `.ddsainclude` to match.

## Writing rules

Each ruleset is a directory under `rulesets/` containing a `ruleset.yaml` and one `.yaml` file per rule.

### ruleset.yaml

```yaml
name: my-org-custom-rules       # Must be globally unique across Datadog
short_description: One-line summary
description: Longer description of what this ruleset covers.
```

### Rule file (e.g. `no-debugger.yaml`)

```yaml
name: no-debugger
short_description: Disallow the use of debugger
description: |-
  The `debugger` statement pauses execution and opens the browser debugger. It should
  never appear in production code as it can expose internals and halt execution for end users.
  See [CWE-489](https://cwe.mitre.org/data/definitions/489.html).
category: BEST_PRACTICES        # SECURITY | BEST_PRACTICES | CODE_STYLE | ERROR_PRONE | PERFORMANCE
severity: ERROR                 # ERROR | WARNING | NOTICE | NONE
language: JAVASCRIPT
arguments: []
tree_sitter_query: (debugger_statement) @stmt
code: |-
  function visit(query, filename, code) {
    const stmt = query.captures["stmt"];
    if (!stmt) return;
    addError(buildError(
      stmt.start.line, stmt.start.col,
      stmt.end.line, stmt.end.col,
      "Remove debugger statement before committing to production.",
      "ERROR",
      "BEST_PRACTICES"
    ));
  }
tests:
  - filename: Compliant.js
    code: |
      function fetchData() {
        return fetch("/api/data");
      }
    annotation_count: 0
  - filename: NotCompliant.js
    code: |
      function fetchData() {
        debugger;
        return fetch("/api/data");
      }
    annotation_count: 1
is_published: false
```

> **Note:** The example rule (`my-custom-rules/no-debugger.yaml`) has `is_published: false` and will not surface in scans until set to `true`. Use it as a reference and delete or replace it with your own rules.

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

# Contributing

## Reporting Issues

If you encounter a bug or have a feature request, please open a GitHub issue.

## Development

### Prerequisites

- Python 3.11+
- [uv](https://docs.astral.sh/uv/)

### Setup

```bash
git clone https://github.com/DataDog/datadog-custom-rules-template.git
cd datadog-custom-rules-template
uv sync
```

### Making Changes

1. Fork the repository and create a branch from `main`.
2. Make your changes to `scripts/upload.py` or `scripts/pull.py`.
3. Test locally against your Datadog environment.
4. Open a pull request.

## License

By contributing, you agree that your contributions will be licensed under the [Apache 2.0 License](LICENSE).

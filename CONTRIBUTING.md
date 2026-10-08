# Contributing

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
ruff check src tests
```

For frontend changes:

```bash
cd frontend
npm ci
npm run build
```

## Pull requests

Please include:

- a clear problem statement
- tests for behavioral changes
- security implications for changes involving document content, tokens, AWS, or the LLM
- documentation updates where configuration or behavior changes

Never commit:

- `.env` files
- credentials
- real customer documents
- raw PII
- production logs
- token-vault exports

## Commit hygiene

Keep commits focused and descriptive. Avoid mixing refactors with unrelated behavior changes when practical.

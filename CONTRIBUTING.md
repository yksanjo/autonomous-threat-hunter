# Contributing to Autonomous Threat-Hunter

Thank you for your interest in contributing!

## Development Setup

1. Clone the repository
2. Create virtual environment: `python -m venv venv`
3. Activate: `source venv/bin/activate` (or `venv\Scripts\activate` on Windows)
4. Install dependencies: `pip install -r requirements.txt`
5. Install dev dependencies: `pip install -r requirements.txt[dev]`

## Running Tests

```bash
pytest tests/
```

## Code Style

We use Black for formatting and flake8 for linting:

```bash
black src/ tests/
flake8 src/ tests/
```

## Submitting Changes

1. Create a feature branch
2. Make your changes
3. Add tests
4. Ensure all tests pass
5. Submit a pull request

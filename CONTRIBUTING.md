# Contributing to Agent Security Hooks

Thank you for your interest in contributing to Agent Security Hooks! This project aims to make AI coding assistants safer for everyone.

## Getting Started

1.  **Fork the repository** on GitHub.
2.  **Clone your fork** locally:
    ```bash
    git clone https://github.com/suchithnarayan/agent-security-hooks.git
    cd agent-security-hooks
    ```

3.  **Create a virtual environment** and install dependencies:
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    pip install -e ".[dev]"
    ```

## Development Workflow

1.  Create a new branch for your feature or fix:
    ```bash
    git checkout -b feature/my-awesome-feature
    ```
2.  Make your changes.
3.  **Run tests** to ensure no regressions:
    ```bash
    pytest
    ```
    Please add new tests for any new functionality or bug fixes.
4.  Commit your changes with clear messages.

## Security

If you discover a potential security issue in this project, please **do not** report it via public GitHub issues. Instead:

- Use [GitHub Security Advisories](https://github.com/suchith-narayan/agent-security-hooks/security/advisories/new) (preferred)
- Or email the maintainers (see repository maintainers list)

This allows us to fix the issue before public disclosure.

## Code Style

- We use standard Python styling (PEP 8).
- Ensure code is typed where possible.

## Pull Requests

1.  Push your branch to GitHub.
2.  Open a Pull Request against the `main` branch.
3.  Describe your changes and why they are necessary.

Thank you for contributing!

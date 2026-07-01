# Contributing to PyShieldBuilder

Thank you for your interest in contributing to PyShieldBuilder! This document provides guidelines and instructions for contributing.

## Code of Conduct

Please be respectful and constructive in all interactions.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/your-username/PyShieldBuilder.git`
3. Create a development branch: `git checkout -b feature/your-feature-name`
4. Set up the development environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -e ".[dev]"
   ```

## Development Workflow

1. Write your code following PEP 8 and the project's style guide
2. Add type hints to all functions and methods
3. Write comprehensive docstrings
4. Add unit tests for new functionality
5. Ensure all tests pass: `pytest`
6. Run linting: `ruff check src/`
7. Run type checking: `mypy src/`
8. Commit with clear messages: `git commit -m "Clear description of changes"`
9. Push to your fork and create a Pull Request

## Code Style

- Follow PEP 8 strictly
- Use type hints for all function parameters and return types
- Write docstrings for all public functions, classes, and modules
- Use meaningful variable names
- Keep functions focused and single-responsibility

## Testing

- Write unit tests for all new features
- Aim for >90% code coverage
- Test both success and failure paths
- Use descriptive test names
- Place tests in the `tests/` directory with matching module structure

## Documentation

- Update README.md if adding user-facing features
- Add docstrings to all public APIs
- Keep examples up-to-date
- Document any new configuration options

## Pull Request Process

1. Update CHANGELOG.md with your changes
2. Ensure all tests pass locally
3. Provide clear description of changes in PR
4. Link any related issues
5. Wait for review and address feedback

## Reporting Issues

- Check existing issues before creating a new one
- Provide clear reproduction steps
- Include Python version and OS
- Include full error messages and stack traces

## Security

If you discover a security vulnerability, please email scrapperpentestv@gmail.com instead of using the issue tracker.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

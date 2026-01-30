# Contributing to Rift

First off, thank you for considering contributing to Rift! It's people like you that make this tool better for the security community.

## Project Vision

This project aims to provide a free, open-source, and extensible security compliance scanning tool that helps organizations and individuals audit their systems against industry-standard security frameworks. We value:

- **Security First** - All contributions should enhance security, never weaken it
- **Code Quality** - Clean, readable, maintainable code
- **Documentation** - Well-documented features and changes
- **Testing** - Comprehensive test coverage
- **Accessibility** - Easy for both beginners and experts to use

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check the existing issues to avoid duplicates. When you create a bug report, include as many details as possible:

**Bug Report Template:**
```markdown
**Describe the bug**
A clear and concise description of what the bug is.

**To Reproduce**
Steps to reproduce the behavior:
1. Run command '...'
2. With options '...'
3. See error

**Expected behavior**
What you expected to happen.

**Actual behavior**
What actually happened.

**Environment:**
 - OS: [e.g., Ubuntu 22.04]
 - Python Version: [e.g., 3.9.5]
 - Scanner Version: [e.g., 0.1.0]

**Additional context**
Add any other context about the problem, including logs or screenshots.
```

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion:

**Enhancement Template:**
```markdown
**Is your feature request related to a problem?**
A clear description of what the problem is.

**Describe the solution you'd like**
A clear description of what you want to happen.

**Describe alternatives you've considered**
Any alternative solutions or features you've considered.

**Additional context**
Any other context, mockups, or examples.
```

### Your First Code Contribution

Unsure where to begin? Look for issues labeled:
- `good first issue` - Simple issues perfect for newcomers
- `help wanted` - Issues where we'd appreciate community help
- `documentation` - Documentation improvements needed

## 🔧 Development Setup

### 1. Fork and Clone

```bash
# Fork the repository on GitHub, then:
git clone https://github.com/brad-eck/rift.git
cd security-compliance-scanner

# Add upstream remote
git remote add upstream https://github.com/ORIGINAL_OWNER/rift.git
```

### 2. Create a Branch

```bash
# Always create a new branch for your work
git checkout -b feature/your-feature-name

# Or for bug fixes
git checkout -b fix/issue-description
```

Branch naming conventions:
- `feature/feature-name` - New features
- `fix/bug-description` - Bug fixes
- `docs/what-changed` - Documentation updates
- `refactor/what-changed` - Code refactoring
- `test/what-added` - Test additions

### 3. Set Up Development Environment

```bash
# Install development dependencies (when we add them)
pip install -r requirements-dev.txt

# Verify your setup works
python3 scanner.py --help
```

### 4. Make Your Changes

Follow our coding standards (see below) and make your changes.

### 5. Test Your Changes

```bash
# Run the scanner to verify it works
sudo python3 scanner.py --verbose

# Run unit tests (as we build them out)
python3 -m unittest discover tests

# Verify your specific check works
sudo python3 scanner.py --category your_new_category
```

### 6. Commit Your Changes

We follow conventional commit messages:

```bash
# Format: <type>(<scope>): <subject>

git commit -m "feat(checks): add kernel parameter verification"
git commit -m "fix(scanner): resolve circular import issue"
git commit -m "docs(readme): update installation instructions"
git commit -m "test(checks): add tests for SSH configuration checks"
```

**Commit Types:**
- `feat` - New feature
- `fix` - Bug fix
- `docs` - Documentation changes
- `style` - Code style changes (formatting, no logic change)
- `refactor` - Code refactoring
- `test` - Adding or updating tests
- `chore` - Maintenance tasks

### 7. Push and Create Pull Request

```bash
# Push your branch
git push origin feature/your-feature-name

# Then create a Pull Request on GitHub
```

## 📝 Pull Request Guidelines

### PR Checklist

Before submitting your PR, ensure:

- [ ] Code follows the project's style guidelines
- [ ] Self-review of your own code completed
- [ ] Comments added for complex logic
- [ ] Documentation updated (README, docstrings, etc.)
- [ ] No new warnings generated
- [ ] Tests added/updated and passing
- [ ] PR title follows conventional commit format
- [ ] PR description clearly explains what and why

### PR Description Template

```markdown
## Description
Brief description of what this PR does.

## Motivation and Context
Why is this change required? What problem does it solve?
Fixes # (issue number)

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to change)
- [ ] Documentation update

## How Has This Been Tested?
Describe the tests you ran and how to reproduce them.

## Screenshots (if appropriate)

## Checklist
- [ ] My code follows the code style of this project
- [ ] I have updated the documentation accordingly
- [ ] I have added tests to cover my changes
- [ ] All new and existing tests passed
```

## Coding Standards

### Python Style Guide

We follow [PEP 8](https://pep8.org/) with some specific preferences:

### Security Check Development

When creating new security checks:

**1. Inherit from ComplianceCheck:**
```python
class MyNewCheck(ComplianceCheck):
    def __init__(self):
        super().__init__(
            check_id="UNIQUE_ID",
            title="Clear, concise title",
            description="Detailed explanation of what this checks",
            severity="HIGH",  # CRITICAL, HIGH, MEDIUM, or LOW
            framework="CIS",
            control_id="X.Y.Z"
        )
```

**2. Implement the run() method:**
```python
def run(self):
    """Execute the security check"""
    try:
        # Your check logic here
        if passes_check:
            self.status = "PASS"
        else:
            self.status = "FAIL"
            self.findings.append("Specific issue found")
            self.remediation = "Specific steps to fix"
    except Exception as e:
        self.status = "ERROR"
        self.findings.append(f"Error: {str(e)}")
        logger.error(f"Check {self.check_id} failed: {str(e)}")
```

**3. Provide clear remediation:**
```python
# Good: Specific, actionable
self.remediation = "Run: chmod 600 /etc/ssh/ssh_host_rsa_key"

# Bad: Vague
self.remediation = "Fix the permissions"
```

**4. Handle edge cases:**
```python
# Check if file exists before checking permissions
if not os.path.exists(self.file_path):
    self.status = "PASS"
    self.findings.append(f"File {self.file_path} does not exist")
    return
```

### Test Coverage

We aim for:
- **80%+ code coverage** for all modules
- **100% coverage** for critical security check logic
- **Edge case testing** for all public methods

## Documentation

### When to Update Documentation

Update documentation when you:
- Add a new feature or check
- Change existing behavior
- Fix a bug that affects usage
- Add new configuration options
- Change command-line arguments

### What to Update

- **README.md** - For user-facing changes
- **CHANGELOG.md** - For all changes (see format below)
- **Code docstrings** - For all new functions/classes
- **Inline comments** - For complex logic
- **examples/** - For new usage patterns

### CHANGELOG Format

```markdown
## [Unreleased]

### Added
- New kernel parameter verification checks (#42)
- Support for custom check configuration files (#38)

### Changed
- Improved HTML report styling (#45)
- Updated CIS Benchmark control mappings (#40)

### Fixed
- Circular import error in scanner module (#43)
- SSH config parsing for non-standard paths (#41)

### Security
- Fixed potential command injection in service checks (#44)
```

## Security Considerations

### Security-Critical Changes

Changes affecting security require extra scrutiny:

1. **Never weaken security** - Ensure changes don't reduce security posture
2. **Validate inputs** - All user inputs must be validated and sanitized
3. **Avoid command injection** - Use subprocess with lists, not shell=True
4. **Handle permissions carefully** - Don't request more privileges than needed
5. **Secure by default** - Default configurations should be secure

### Security Review Process

Security-critical PRs will be:
- Reviewed by multiple maintainers
- Tested extensively
- Potentially held for security audit
- May require sign-off before merging

## Adding New Security Frameworks

Want to add NIST, STIG, or another framework?

1. Create `checks/framework_name.py`
2. Implement checks following the same pattern as `linux_cis.py`
3. Add framework option to CLI in `scanner.py`
4. Document the framework in README.md
5. Add example usage
6. Include tests

## Questions?

- **General questions:** Open a GitHub Discussion
- **Bug reports:** Create an issue with the bug template
- **Feature requests:** Create an issue with the enhancement template
- **Direct contact:** Reach out via email or LinkedIn (see README)

## Recognition

Contributors will be:
- Listed in the project README
- Acknowledged in release notes
- Credited in their PR merges

Significant contributors may be invited to join the project as maintainers.

## Code of Conduct

### Our Standards

- **Be respectful** - Treat everyone with respect
- **Be inclusive** - Welcome diverse perspectives
- **Be collaborative** - Work together constructively
- **Be professional** - Keep discussions focused and productive
- **Be patient** - Remember everyone is learning

### Unacceptable Behavior

- Harassment or discriminatory language
- Personal attacks or trolling
- Publishing others' private information
- Other unprofessional conduct

---

## 🙏 Thank You!

Your contributions make this project better for everyone in the security community. Whether you're fixing a typo, adding a new check, or proposing a major feature - every contribution matters.

**Happy Contributing!**

---

*This document is adapted from open-source contribution guidelines and will evolve as the project grows.*
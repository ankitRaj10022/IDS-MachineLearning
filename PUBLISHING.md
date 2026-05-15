# Publishing IDS Sentinel Terminal

This project is prepared for public installation as:

```bash
pipx install ids-sentinel-terminal
```

The remaining work is ownership and release setup on GitHub and PyPI.

## Package Identity

- PyPI project name: `ids-sentinel-terminal`
- GitHub repository: `ankitRaj10022/IDS-Sentinel`
- Release workflow file: `.github/workflows/release.yml`
- PyPI environment name in GitHub Actions: `pypi`

## First-Time PyPI Setup

Use PyPI Trusted Publishing with a pending publisher so the first GitHub release can create the project automatically.

On PyPI:

1. Sign in to the PyPI account that should own `ids-sentinel-terminal`.
2. Open account `Publishing`.
3. Add a new GitHub trusted publisher.
4. Use these exact values:

```text
PyPI project name: ids-sentinel-terminal
Owner: ankitRaj10022
Repository name: IDS-Sentinel
Workflow name: release.yml
Environment name: pypi
```

Important:

- A pending publisher does not reserve the package name until the first successful publish.
- If someone else registers `ids-sentinel-terminal` on PyPI first, the pending publisher becomes unusable for that name.

## GitHub Setup

In the GitHub repository:

1. Push the packaging changes to the default branch.
2. Create a GitHub environment named `pypi`.
3. Optionally require manual approval for that environment.
4. Ensure GitHub Actions is enabled for the repository.

## Local Validation Before Release

Build Python package artifacts:

```powershell
python scripts\build_python_package.py
```

Build portable archives:

```powershell
python scripts\build_distributions.py
```

Install the wheel locally:

```bash
pipx install dist/ids_sentinel_terminal-0.2.0-py3-none-any.whl
ids-sentinel --version
ids-sentinel status
```

## Release Flow

Once the branch is pushed and the pending publisher is configured:

1. Create a Git tag such as `v0.2.0`.
2. Publish a GitHub Release for that tag.
3. GitHub Actions will:
   - build the wheel and source distribution
   - build the portable archives
   - upload `dist/*` to the GitHub Release
   - publish the wheel and sdist to PyPI through OIDC Trusted Publishing

After that, end users can install with:

```bash
pipx install ids-sentinel-terminal
```

## Notes

- The public package exposes `ids-sentinel`, `ids-sentinel-terminal`, and the compatibility alias `ids-sentinal`.
- The installed tool bootstraps its writable home under `~/.ids-sentinel-terminal` on Linux/macOS and `%USERPROFILE%\.ids-sentinel-terminal` on Windows.
- The release workflow does not require storing a PyPI API token in GitHub secrets.

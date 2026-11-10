---
title: "Isolating and Managing Python Projects with <span style='font-family:monospace; font-weight: 600;'>uv</span>"
# author:
#   name: 0xKirito
#   link: https://github.com/0xKirito
date: 2026-11-09T02:34:23+05:30
categories: [Dev, Python]
tags: [Dev, Python, uv, Cheat Sheet]
render_with_liquid: false
---

## Installing <span style='font-family:monospace; font-weight: bold;'>uv</span>

[Astral uv Installation Docs](https://docs.astral.sh/uv/getting-started/installation/)

```sh
# on linux/macOS with curl
curl -LsSf https://astral.sh/uv/install.sh | sh
# or with wget
wget -qO- https://astral.sh/uv/install.sh | sh
```

`uv` and `uvx` are installed to `~/.local/bin`. Open a new terminal (or run `source $HOME/.local/bin/env`) so they are on your `PATH`, then verify:

```sh
uv --version
# update later with
uv self update
```

---

## Isolating and Running Python Projects with <span style='font-family:monospace; font-weight: bold;'>uv</span>

With `uv`, you can run old or new Python projects with completely separate Python versions and dependencies, without polluting system Python or installed packages. On Kali (and other Debian-based distros), system Python is "externally managed" (PEP 668), so a plain `pip install` fails with `externally-managed-environment`. The fix is an isolated environment, not `--break-system-packages`.

**Rule of Thumb:**

- Old projects <span class="fat-arrow">=></span> `uv venv` + `uv pip` + `uv run --no-project`.
- New projects <span class="fat-arrow">=></span> `uv init` + `uv add` + `uv run`.

**AVOID:**

- Never use `sudo pip install`, `pip install --break-system-packages`, `uv pip install --system`, or usual system-level `pip install` when you need to run isolated projects.

| Situation                                                  | Commands                                                                                  |
| ---------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| Random GitHub project with `requirements.txt`              | `uv venv` → `uv pip install -r requirements.txt` → `uv run --no-project python script.py` |
| New uv-managed project                                     | `uv init` → `uv add requests` → `uv run python main.py`                                   |
| Single Python script with dependencies declared inline     | `uv run script.py` (see PEP 723 section below)                                            |
| Single Python script, ad-hoc dependencies (no edits to it) | `uv run --with requests script.py`                                                        |
| Run a Python CLI tool without permanently installing it    | `uvx ruff check .`                                                                        |
| Run a specific version of a CLI tool                       | `uvx ruff@0.14.0 check .`                                                                 |
| Run a CLI tool with extra dependencies                     | `uvx --with requests some-tool`                                                           |

`uvx` <span class="fat-arrow">=></span> `uv tool run`

---

## Isolating and Managing a Random Python Project with requirements.txt

```sh
# random Python project that you cloned
git clone https://github.com/example/random-python-project.git
cd random-python-project

# Check which Python uv would use by default
# (if you don't need a specific version, try the project with the default one first)
uv run --no-project python --version

# List available/installed Python versions
uv python list

# Install a specific Python version if needed
# (optional: `uv venv --python 3.10` downloads it automatically if missing)
uv python install 3.10

# Create isolated environment INSIDE project directory (.venv)
uv venv                # default Python version
uv venv --python 3.10  # specific version

# Install all requirements into that environment
uv pip install -r requirements.txt

# Verify the Python version in the environment
uv run --no-project python --version

# Or install packages individually
# (old pins need a Python version that has wheels for them; these support 3.10)
uv pip install numpy==1.23.5
uv pip install scipy==1.9.3

# Or install the current Python project itself with its dependencies into the venv
uv pip install .
# editable install (for development)
uv pip install -e .

# Run the script or project using the isolated environment
# --no-project stops uv from locking/syncing the repo's pyproject.toml (if it has one)
uv run --no-project python script.py
uv run --no-project python main.py

# Run a module
uv run --no-project python -m package.module_name
uv run --no-project python -m http.server    # standard library module
uv run --no-project python -m mytool.scanner
```

> Alternatively, activate the venv the classic way (`source .venv/bin/activate`) and use `python` directly, or call `.venv/bin/python script.py`.

### Migrating a requirements.txt project to a uv-managed project

```sh
# create a pyproject.toml first (--bare = no sample main.py/README)
uv init --bare --python 3.10

# import dependencies from requirements.txt into pyproject.toml,
# resolve them, write uv.lock, and sync the project environment
uv add -r requirements.txt

# after this, plain `uv run python script.py` works (and `uv sync` rebuilds the env)
```

---

## Isolating and Running a Random Script (Zero Setup)

If you just downloaded a random `script.py` from Exploit-DB or GitHub and it requires third-party libraries (e.g., `requests`, `impacket`), you can use `uv run` to create a temporary, isolated environment on the fly:

```sh
uv run --with requests --with impacket script.py --target 10.10.10.10

# If you want a completely independent execution that does not inherit project dependencies
uv run --no-project --with requests --with impacket script.py --target 10.10.10.10
```

- **`--with`**: Temporarily injects the specified PyPI packages into an isolated environment just for that execution (cached by `uv`, so repeat runs are fast).
- **Python 2 scripts**: `uv` does not support Python 2. Old Exploit-DB scripts written for Python 2 need porting (e.g. with [`2to3`](https://docs.python.org/3.12/library/2to3.html), [`modernize`](https://pypi.org/project/modernize/)) first.
- Always read untrusted exploit code before running it, even in an isolated environment. _Isolation protects your packages, not your machine._

---

### Isolated Single-File Scripts (Inline Metadata)

For complex scripts you reuse across boxes, you can declare dependencies _inside_ the script file itself, using the standard **[PEP 723 (Inline Script Metadata)](https://peps.python.org/pep-0723/#script-type)** format.

Add these lines to the top of your `script.py` and modify them as needed for minimum Python or dependency version:

```python
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "requests>=2.31.0",
#     "pycryptodome",
# ]
# ///

import requests
```

Then run it directly with `uv`:

```sh
uv run script.py [args]
```

Or instead of writing the comment block manually, you can use the CLI to create or update it for you:

```sh
# create a new script with the metadata block already in place
uv init --script your_script.py --python 3.11

# add dependencies to the block
uv add --script your_script.py 'requests>=2.31.0' 'rich'
```

---

## Running Standalone CLI Tools (Instead of pipx)

If you need to install a standalone tool (like `bloodhound` or `certipy-ad`) so it's available on your `PATH` without breaking your OS, `uv tool install` puts each tool in its own isolated environment:

```sh
# BloodHound CE ingestor (command: bloodhound-ce-python)
uv tool install bloodhound-ce

# AD CS enumeration/abuse (command: certipy), needs Python 3.12+
uv tool install --python 3.12 certipy-ad

# NetExec (command: nxc), installed from GitHub since it's not on PyPI, needs Python 3.10+
uv tool install --python 3.12 git+https://github.com/Pennyw0rth/NetExec

# bloodyAD (command: bloodyAD)
uv tool install bloodyAD
```

- **Execute it anywhere:** `bloodhound-python -u ...`, `certipy ...`, `nxc ...`
- **If the command isn't found:** run `uv tool update-shell` and restart your shell (tools are linked into `~/.local/bin`).
- **List / upgrade:**

```sh
uv tool list
uv tool upgrade --all
```

- **Uninstall:**

```sh
uv tool uninstall bloodhound-ce
uv tool uninstall certipy-ad
```

---

## Running Python Packages without Installing (uvx)

`uvx` <span class="fat-arrow">=></span> alias for `uv tool run`

```sh
# Run NetExec straight from GitHub without cloning or installing
uvx --from git+https://github.com/Pennyw0rth/NetExec nxc --help

# Run Ruff (ruff = Python linter & code formatter)
uvx ruff check .

# Run HTTPie
uvx httpie --help
uvx --from httpie http --help

# Run a specific version (black = Python code formatter)
uvx black@24.10.0 --check .

# Run certipy (package name differs from command name, so use --from)
uvx --from certipy-ad certipy
```

> Some tools need OS-level build libraries (e.g. `libkrb5-dev`, `libssl-dev`, `build-essential`) when a dependency has to compile. Install those with `apt`; uv can't provide them.

---

## Actual pip Inside an Isolated Environment

If you need an actual `pip` inside your `uv venv`, create the venv with `--seed` (installs pip, setuptools and wheel), or install pip into an existing one:

```sh
uv venv --seed
# or, for an existing venv
uv pip install pip

uv run --no-project python -m pip install package-name
```

---

## New Python Projects: Modern uv Workflow

```sh
uv init new-project --python 3.12
cd new-project

# Or change the Python version later
uv python pin 3.13

# Add dependencies
uv add requests numpy pandas

# Run project
uv run python main.py
```

`uv init` also creates `main.py`, `README.md`, `.python-version` and `pyproject.toml`.

**`uv`** automatically:

- Creates `.venv` (on first `uv add`/`uv run`/`uv sync`).
- Installs dependencies.
- Maintains `pyproject.toml`.
- Generates and maintains `uv.lock`.
- Keeps dependencies reproducible.
- Updates the environment when necessary.

To recreate the environment from an existing uv project (e.g. after cloning), run `uv sync`.

---

## Common pip <span class="fat-arrow">=></span> uv commands

| pip                               | uv                                   |
| --------------------------------- | ------------------------------------ |
| `pip install pkg`                 | `uv pip install pkg`                 |
| `pip install -r requirements.txt` | `uv pip install -r requirements.txt` |
| `pip install -e .`                | `uv pip install -e .`                |
| `pip uninstall pkg`               | `uv pip uninstall pkg`               |
| `pip list`                        | `uv pip list`                        |
| `pip freeze`                      | `uv pip freeze`                      |
| `pip show pkg`                    | `uv pip show pkg`                    |
| `pip check`                       | `uv pip check`                       |

Note: `uv pip` commands need an active or local `.venv`. Without one, `uv` refuses to touch the system Python (which is a good thing).

## Useful uv Commands

```sh
# Create environment
uv venv --python 3.10

# Install Python version
uv python install 3.10

# Install into a specific environment
uv pip install --python .venv/bin/python package-name

# Run Python script or project
uv run --no-project python script.py
uv run python main.py

# Run a module
uv run --no-project python -m package.module_name
```

---

## Other Points to Note

- Never use `sudo pip install` or `--break-system-packages`.
- Avoid `uv pip install --system`.
- For OS-level dependencies (CUDA, shared libraries, compilers, etc.), use `apt`, or Docker/VM if stronger isolation is needed.

Another uv Guide on RealPython: [https://realpython.com/python-uv/](https://realpython.com/python-uv/)

---

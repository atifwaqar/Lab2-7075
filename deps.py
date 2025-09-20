# -*- coding: utf-8 -*-
"""Dynamic dependency installer used by the TLS Secure Chat launcher.

The educational lab should "just run" even on fresh machines, so this module
ensures required third-party packages are importable.  It keeps the focus on
TLS concepts rather than Python packaging troubleshooting.
"""

from __future__ import annotations
import importlib
import os
import sys
import subprocess
from types import ModuleType
from typing import Optional, Sequence

PIP_ARGS: Sequence[str] = (
    "--disable-pip-version-check",
    "--no-input",
)

# Optionally pin versions here, e.g. {"colorama": "0.4.6"}
PINNED: dict[str, str] = {
    # "colorama": "0.4.6",
    # "pyfiglet": "0.8.post1",
}

def _pkg_spec(package: str) -> str:
    ver = PINNED.get(package)
    return f"{package}=={ver}" if ver else package

def _run_pip(args: list[str]) -> int:
    return subprocess.call([sys.executable, "-m", "pip", *args])

def install_if_missing(package: str, import_name: Optional[str] = None) -> ModuleType:
    """Import a dependency, installing it via pip if necessary.

    Args:
      package: The package spec to pass to ``pip install``.
      import_name: Alternative module name to import if it differs from the
        package name (e.g., ``PyYAML`` vs. ``yaml``).

    Returns:
      ModuleType: The imported module object.

    Raises:
      ImportError: If the package could not be installed/imported.

    Security Notes:
      - Installs packages into the current environment, potentially mutating a
        shared interpreter.  In hardened environments run the lab inside an
        isolated virtual environment instead of relying on this helper.
    """
    name = import_name or package
    try:
        return importlib.import_module(name)
    except ImportError:
        print(f"[deps] Installing {package} ...")

        # 1) try normal install into current environment
        rc = _run_pip(["install", _pkg_spec(package), *PIP_ARGS])

        if rc != 0:
            # 2) fallback to --user (Windows non-admin common case)
            print(f"[deps] Standard install failed, trying --user for {package} ...")
            rc = _run_pip(["install", "--user", _pkg_spec(package), *PIP_ARGS])

        if rc != 0:
            # 3) one quick retry (network hiccups, locks, etc.)
            print(f"[deps] Retry once for {package} ...")
            rc = _run_pip(["install", _pkg_spec(package), *PIP_ARGS])

        if rc != 0:
            raise ImportError(
                f"Failed to install {package}. Try running "
                f"'{sys.executable} -m pip install {package}' manually."
            )

        # Ensure Python sees newly installed packages in this session (esp. after --user)
        # On Windows this is usually fine, but we force a fresh import to be safe.
        if hasattr(importlib, "invalidate_caches"):
            importlib.invalidate_caches()

        return importlib.import_module(name)

def ensure_all() -> dict[str, ModuleType]:
    """Ensure all third-party packages used by the demos are importable.

    Args:
      None.

    Returns:
      dict[str, ModuleType]: Mapping of module import names to module objects
        that were successfully imported.

    Raises:
      None.

    Security Notes:
      - Dependencies are pulled from PyPI over HTTPS.  The TLS security of pip
        is outside the scope of this lab, but instructors may wish to pre-cache
        packages in tightly controlled environments.
    """

    print("[deps] Going to check packages ...")
    required = [
        ("colorama", None),
        ("pyfiglet", None),
        ("emoji", None),
        ("prompt_toolkit", None),
        ("rich", None),
    ]
    loaded = {}
    for pkg, import_name in required:
        mod = install_if_missing(pkg, import_name)
        loaded[import_name or pkg] = mod
    return loaded

if __name__ == "__main__":
    ensure_all()
    print("[deps] All dependencies are present.")

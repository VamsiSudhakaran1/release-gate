"""release-gate: the independent admission controller for AI systems."""

try:
    from importlib.metadata import version, PackageNotFoundError
    __version__ = version("release-gate")
except PackageNotFoundError:
    __version__ = "0.11.2"

__author__ = "Vamsi Sudhakaran"
__email__ = "vamsi.sudhakaran@gmail.com"

from . import checks

#: The product surface, resolved on first use. `import release_gate` costs 36ms and
#: `import release_gate.assurance` costs 237ms, so importing the assurance package
#: eagerly here would make every consumer of the old surface pay for a package it
#: does not touch. PEP 562 lets `rg.create_case` work without that.
_LAZY = {
    "create_case": "release_gate.assurance.api",
    "Case": "release_gate.assurance.api",
    "CaseDecision": "release_gate.assurance.api",
    "ApiError": "release_gate.assurance.api",
}

__all__ = ["checks", "create_case", "Case", "CaseDecision", "ApiError"]


def __getattr__(name):
    """Resolve the product surface on first touch, and cache it on the module."""
    module_path = _LAZY.get(name)
    if module_path is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib

    value = getattr(importlib.import_module(module_path), name)
    globals()[name] = value
    return value


def __dir__():
    return sorted(set(globals()) | set(_LAZY))

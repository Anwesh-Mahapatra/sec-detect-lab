"""Rule registry. Auto-discovers every Rule subclass in this package."""

import importlib
import inspect
import pkgutil
from pathlib import Path

from detections.base import Rule, TestCase, deep_get_first, get  # noqa: F401

__all__ = ["Rule", "TestCase", "get", "deep_get_first", "all_rules"]


def all_rules() -> list[Rule]:
    """Every rule in the package, instantiated, sorted by id."""
    found: list[Rule] = []
    pkg_dir = Path(__file__).parent
    for mod in pkgutil.iter_modules([str(pkg_dir)]):
        if mod.name in {"base", "__init__"}:
            continue
        module = importlib.import_module(f"detections.{mod.name}")
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if issubclass(obj, Rule) and obj is not Rule and obj.__module__ == module.__name__:
                found.append(obj())
    return sorted(found, key=lambda r: r.id)

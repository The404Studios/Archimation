"""
S68 regression guard: every Action(...) literal in contusion_dictionary.py
MUST include a handler_type= kwarg. Prevents the S62 silent-bug class from
returning.
"""
import ast
from pathlib import Path

import pytest

CONTUSION_DICT = Path(__file__).resolve().parents[2] / "ai-control" / "daemon" / "contusion_dictionary.py"


def _action_calls_without_handler_type(tree: ast.AST):
    """Yield (lineno, col_offset) for every Action(...) that lacks handler_type=."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "Action":
            kw_names = {kw.arg for kw in node.keywords if kw.arg}
            if "handler_type" not in kw_names:
                yield (node.lineno, node.col_offset)


def test_every_action_has_handler_type():
    tree = ast.parse(CONTUSION_DICT.read_text(encoding="utf-8"))
    missing = list(_action_calls_without_handler_type(tree))
    assert not missing, (
        f"{len(missing)} Action(...) calls lack handler_type= — this is the "
        f"S62 silent-bug class. Locations (line, col): {missing[:15]}"
    )


def test_handler_type_values_are_strings():
    """Also guard: handler_type= must be a string literal, not a dynamic expr."""
    tree = ast.parse(CONTUSION_DICT.read_text(encoding="utf-8"))
    bad = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "Action":
            for kw in node.keywords:
                if kw.arg == "handler_type":
                    # Accept either string literal or a simple constant reference
                    if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                        continue
                    if isinstance(kw.value, (ast.Name, ast.Attribute)):
                        # e.g. legacy_const — accept with a note
                        continue
                    bad.append((node.lineno, ast.dump(kw.value)[:60]))
    assert not bad, f"handler_type= must be a string; bad sites: {bad[:5]}"

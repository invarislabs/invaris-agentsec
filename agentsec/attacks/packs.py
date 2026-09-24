"""Attack packs: load extra scenario categories from a local file or an installed Python package.

A pack is a Python module (yours, private, never published) that exposes a `CATEGORIES` mapping of
the same shape as `agentsec.attacks.CATEGORIES`: `{category_name: build(ctx) -> List[Scenario]}`.
Nothing here validates the *content* of a pack's scenarios; write them the way you would a built-in
category (see docs/extending.md).

Packs run as ordinary Python import: **only load packs you wrote or trust**, the same as any
dependency. A pack spec that names a local file is imported directly; anything else is imported as
an installed module.
"""
from __future__ import annotations

import importlib
import importlib.util
import os
import sys
import uuid
from dataclasses import dataclass
from typing import Callable, Dict, List

from ..policies import PolicyError
from .base import Scenario, ScenarioContext

BuildFn = Callable[[ScenarioContext], List[Scenario]]


@dataclass
class PackCategory:
    spec: str        # the pack this category came from, for error messages
    build: BuildFn


def _looks_like_a_path(spec: str) -> bool:
    return spec.endswith(".py") or os.sep in spec or (os.altsep and os.altsep in spec)


def _import(spec: str):
    if _looks_like_a_path(spec):
        path = os.path.abspath(spec)
        if not os.path.isfile(path):
            raise PolicyError("attack pack %r: no such file" % spec)
        name = "agentsec_attack_pack_%s" % uuid.uuid4().hex
        module_spec = importlib.util.spec_from_file_location(name, path)
        if module_spec is None or module_spec.loader is None:
            raise PolicyError("attack pack %r: could not load it as a Python module" % spec)
        module = importlib.util.module_from_spec(module_spec)
        sys.modules[name] = module
        try:
            module_spec.loader.exec_module(module)
        except Exception as exc:
            raise PolicyError("attack pack %r: raised %s while importing: %s"
                              % (spec, type(exc).__name__, exc))
        return module
    try:
        return importlib.import_module(spec)
    except ImportError as exc:
        raise PolicyError("attack pack %r: could not import it (pip install it first?): %s" % (spec, exc))
    except Exception as exc:
        raise PolicyError("attack pack %r: raised %s while importing: %s" % (spec, type(exc).__name__, exc))


def load_pack(spec: str) -> Dict[str, BuildFn]:
    """Import one pack and return its `CATEGORIES` mapping, validated."""
    module = _import(spec)
    categories = getattr(module, "CATEGORIES", None)
    if not isinstance(categories, dict) or not categories:
        raise PolicyError("attack pack %r has no non-empty `CATEGORIES` dict (see docs/extending.md)" % spec)
    for name, fn in categories.items():
        if not isinstance(name, str) or not name:
            raise PolicyError("attack pack %r: category names must be non-empty strings" % spec)
        if not callable(fn):
            raise PolicyError("attack pack %r: CATEGORIES[%r] must be a function build(ctx) -> [Scenario]"
                              % (spec, name))
    return dict(categories)


def load_packs(specs: List[str], reserved: Dict[str, object]) -> Dict[str, PackCategory]:
    """Load several packs and merge them, rejecting any category name that collides with a
    built-in one (`reserved`) or with another pack."""
    merged: Dict[str, PackCategory] = {}
    for spec in specs:
        for name, fn in load_pack(spec).items():
            if name in reserved:
                raise PolicyError("attack pack %r: category %r is a built-in category name" % (spec, name))
            if name in merged:
                raise PolicyError("attack pack %r: category %r is already defined by attack pack %r"
                                  % (spec, name, merged[name].spec))
            merged[name] = PackCategory(spec, fn)
    return merged


def load_pack_evaluators(spec: str) -> List[type]:
    """Import one pack and return its `EVALUATORS` list (Evaluator subclasses), if it has one.

    Optional, unlike `CATEGORIES`: a pack that only adds scenarios using the built-in
    marker/canary/forbidden-action checks does not need this. A pack needs its own evaluator when
    the danger is in a tool call's *arguments* rather than which tool got called or whether output
    contains a marker -- see `examples/attack_packs/coding_agent_pack.py` for a worked example.
    """
    # Imported lazily, same reason as the always-on import this module itself avoids at the top of
    # agentsec/attacks/__init__.py: evaluators only need Evaluator's shape, not the whole package.
    from ..evaluators.base import Evaluator

    module = _import(spec)
    evaluators = getattr(module, "EVALUATORS", [])
    if not isinstance(evaluators, (list, tuple)):
        raise PolicyError("attack pack %r: EVALUATORS must be a list of Evaluator subclasses" % spec)
    for cls in evaluators:
        if not (isinstance(cls, type) and issubclass(cls, Evaluator)):
            raise PolicyError("attack pack %r: EVALUATORS must contain Evaluator subclasses, got %r"
                              % (spec, cls))
    return list(evaluators)


def load_packs_evaluators(specs: List[str]) -> List[type]:
    """Evaluators contributed by several packs, each spec imported once. Safe to call even when
    every pack in `specs` only defines `CATEGORIES` -- it just contributes nothing then."""
    seen: List[str] = []
    merged: List[type] = []
    for spec in specs:
        if spec in seen:
            continue
        seen.append(spec)
        merged.extend(load_pack_evaluators(spec))
    return merged


def load_pack_judge_checks(spec: str) -> Dict[str, object]:
    """Import one pack and return its `JUDGE_CHECKS` mapping (name -> JudgeCheck), if it has one.

    Optional, like `EVALUATORS`: most packs need no judge check at all, because their danger is
    deterministically expressible (a marker, a canary, a forbidden call). Add one when it isn't --
    see `examples/attack_packs/rag_pack.py`'s `rag_citation_spoofing` for a worked example, where
    the only usable signal is "did the agent's answer act on an untrusted instruction", which the
    built-in `goal_hijack` question already covers well enough that a dedicated one is optional but
    lets a pack phrase the question in terms of its own domain.
    """
    # Imported lazily, same reason as load_pack_evaluators avoids a hard, always-on import.
    from ..evaluators.base import JudgeCheck

    module = _import(spec)
    checks = getattr(module, "JUDGE_CHECKS", {})
    if not isinstance(checks, dict):
        raise PolicyError("attack pack %r: JUDGE_CHECKS must be a dict of name -> JudgeCheck" % spec)
    for name, jc in checks.items():
        if not isinstance(name, str) or not name:
            raise PolicyError("attack pack %r: JUDGE_CHECKS names must be non-empty strings" % spec)
        if not isinstance(jc, JudgeCheck):
            raise PolicyError("attack pack %r: JUDGE_CHECKS[%r] must be a JudgeCheck, got %r"
                              % (spec, name, jc))
    return dict(checks)


def load_packs_judge_checks(specs: List[str]) -> Dict[str, object]:
    """Judge checks contributed by several packs, merged and name-checked.

    Unlike evaluators (which just get concatenated and all run), judge checks are looked up by name
    from `policy.judge.checks`, so a name collision -- with a built-in check or with another pack's
    check -- would silently shadow one of them. Reject it instead, the same way `load_packs` rejects
    a category name collision.
    """
    from ..policies import JUDGE_CHECKS

    seen: List[str] = []
    merged: Dict[str, object] = {}
    for spec in specs:
        if spec in seen:
            continue
        seen.append(spec)
        for name, jc in load_pack_judge_checks(spec).items():
            if name in JUDGE_CHECKS:
                raise PolicyError("attack pack %r: judge check %r is a built-in check name" % (spec, name))
            if name in merged:
                raise PolicyError("attack pack %r: judge check %r is already defined by another attack pack"
                                  % (spec, name))
            merged[name] = jc
    return merged


def check_pack_scenarios(spec: str, category: str, scenarios: List[Scenario]) -> None:
    """Basic sanity checks so a broken pack fails loudly instead of producing a silently empty or
    malformed run. Raised as PolicyError, same as any other policy problem."""
    if not scenarios:
        raise PolicyError("attack pack %r: category %r built no scenarios" % (spec, category))
    seen = set()
    for sc in scenarios:
        if not isinstance(sc, Scenario):
            raise PolicyError("attack pack %r: category %r must build Scenario objects, got %s"
                              % (spec, category, type(sc).__name__))
        if sc.category != category:
            raise PolicyError("attack pack %r: a scenario built by %r has category %r, expected %r"
                              % (spec, category, sc.category, category))
        if sc.id in seen:
            raise PolicyError("attack pack %r: duplicate scenario id %r" % (spec, sc.id))
        seen.add(sc.id)

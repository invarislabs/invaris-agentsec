"""Invaris AgentSec: adversarial security testing for autonomous AI agents."""

__version__ = "0.5.0"

from .api import AgentTarget, RunResult, SecuritySuite  # noqa: E402
from .attacks import CATEGORIES as _CATEGORIES  # noqa: E402

CATEGORIES = list(_CATEGORIES)

__all__ = ["AgentTarget", "CATEGORIES", "RunResult", "SecuritySuite", "__version__"]

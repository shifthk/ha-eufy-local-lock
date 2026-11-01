"""Make ``smartlock`` importable on its own: it has no Home Assistant imports, while
the integration package around it does (and HA does not run on every dev machine)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "custom_components" / "eufy_local_lock"))

"""release-gate: Governance enforcement for AI agents"""

try:
    from importlib.metadata import version, PackageNotFoundError
    __version__ = version("release-gate")
except PackageNotFoundError:
    __version__ = "0.5.0"

__author__ = "Vamsi Sudhakaran"
__email__ = "vamsi.sudhakaran@gmail.com"

from . import checks

__all__ = ["checks"]

"""release-gate: AI agent release decision engine"""

try:
    from importlib.metadata import version, PackageNotFoundError
    __version__ = version("release-gate")
except PackageNotFoundError:
    __version__ = "0.8.3"

__author__ = "Vamsi Sudhakaran"
__email__ = "vamsi.sudhakaran@gmail.com"

from . import checks

__all__ = ["checks"]

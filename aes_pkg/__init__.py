# aes_pkg/__init__.py
from .aes import AES
__all__ = ["aes"]

try:
    from importlib.metadata import version, PackageNotFoundError
    __version__ = version("aes-project")  # your project name
except PackageNotFoundError:
    __version__ = "0.0.0"
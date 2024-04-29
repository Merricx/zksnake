import os

try:
    if os.environ.get("ZKSNAKE_FLINT", True):
        from .optimized_polynomial import *
    else:
        from .polynomial import *
except ImportError:
    from .polynomial import *

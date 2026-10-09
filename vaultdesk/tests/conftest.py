"""Pytest bootstrap for the VaultDesk test suite.

The application package lives at ``vaultdesk/app`` and the tests import it as
the top-level ``app`` package (``from app import create_app``). That only works
when ``vaultdesk/`` is on ``sys.path``, which is true when pytest is invoked
from inside ``vaultdesk/`` but *not* when it is invoked from the repository
root (where pytest inserts ``vaultdesk/tests`` instead).

Make the suite independent of the working directory / rootdir by adding the
``vaultdesk`` directory to ``sys.path`` before the test modules are imported.
"""

import os
import sys

APP_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

if APP_ROOT not in sys.path:
    sys.path.insert(0, APP_ROOT)

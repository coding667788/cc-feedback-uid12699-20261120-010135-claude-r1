"""Offline sandbox capability-check service.

Public entry points:

* :class:`solution.engine.Engine` - executes single steps against SQLite.
* :func:`solution.capability.evaluate` - the pure capability model.
* ``python -m solution --input cases.json --output result.json``
"""

__version__ = "1.0.0"
FORMAT_VERSION = "sandbox-service/1"

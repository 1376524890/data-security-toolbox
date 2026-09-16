"""Shared code that runs unchanged inside the platform and inside the probe.

Nothing in this package may import FastAPI, SQLAlchemy, Celery or any other
platform-only dependency: the probe installs it as a plain directory next to
``probe.py`` and imports it with the interpreter that ships with the OS.
"""

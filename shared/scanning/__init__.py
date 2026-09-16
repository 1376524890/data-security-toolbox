"""Bounded file scanning primitives shared by the probe and the platform.

Everything here draws from one :class:`~shared.scanning.budget.ScanBudget`, so
hash, type probe, sampling, decompression and parsing cannot each quietly exceed
the limits the operator configured. Nothing in this package performs detection
and nothing returns file content: ``samples`` are handed to the detection engine
in memory and only aggregate counts reach a report.
"""
from __future__ import annotations

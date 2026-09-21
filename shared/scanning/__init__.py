"""Bounded file scanning primitives shared by the probe and the platform.

Everything here draws from one :class:`~shared.scanning.budget.ScanBudget`, so
hash, type probe, sampling, decompression and parsing cannot each quietly exceed
the limits the operator configured. Nothing in this package performs detection
and nothing returns file content: ``samples`` are handed to the detection engine
in memory, and a report carries only counts - plus, by explicit operator
requirement, the bounded matched原文 the engine returns for confirmed hits
(``evidence.hits[].matches``), never the file it came from.
"""
from __future__ import annotations

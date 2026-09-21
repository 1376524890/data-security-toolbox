"""Read-only data-security assessments.

Every endpoint under ``/api/v1/assessments`` is a pure aggregation over the
existing object model and engines (`sensitivity_map`, `data_objects.queries`,
`Detection`, `Flow`, `compliance_engine` findings, `Vulnerability`, and the DLP
transfer objects). Nothing here introduces a new fact source, writes a row, or
returns a number without the denominator and coverage boundary it was computed
against. Submodules are imported explicitly by callers so importing this package
stays cheap and free of import cycles.
"""

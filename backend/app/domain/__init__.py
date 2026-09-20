"""Domain-level pure logic shared by the API, application and worker layers.

Modules here must not import ``app.api``, ``app.workers``, ``app.services`` or
open database sessions: they are the leaf every caller can depend on.
"""

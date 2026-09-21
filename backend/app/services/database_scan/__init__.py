"""Server-side target-database scanning.

The worker connects to a configured target, reflects its metadata, reads a
bounded sample per column and runs the *same* shared detection engine the probe
and the network DLP stage use, so a type cannot mean two things. Findings land in
the existing object model as database-sourced instances, with the matched原文
bounded exactly like the probe reports it.

Division of labour:

* ``credentials`` - AES-GCM at rest, its own key and AAD (never the SSH key);
* ``adapters``    - engine allow-list, connection, read-only enforcement,
                    metadata reflection and bounded sampling;
* ``detect``      - shared-engine rule matching for one table's columns;
* ``ingest``      - object/instance/detection/evidence writes;
* ``connection_service`` - connection CRUD, credential lifecycle, scan queueing;
* ``scan``        - the orchestrator the Celery task calls.
"""

from app.services.database_scan.adapters import (
    ENGINES,
    DatabaseError,
    normalise_engine,
)
from app.services.database_scan.connection_service import (
    SCAN_TASK_KIND,
    ConnectionConflict,
    ConnectionInvalid,
    ConnectionNotFound,
)
from app.services.database_scan.credentials import CredentialError
from app.services.database_scan.scan import ScanError

__all__ = [
    "ENGINES",
    "SCAN_TASK_KIND",
    "ConnectionConflict",
    "ConnectionInvalid",
    "ConnectionNotFound",
    "CredentialError",
    "DatabaseError",
    "ScanError",
    "normalise_engine",
]

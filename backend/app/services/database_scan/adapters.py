"""Engine allow-list, connections, metadata reflection and bounded sampling.

Two rules shape this module:

* only engines with a real driver are accepted (``mysql`` -> PyMySQL,
  ``postgresql`` -> psycopg2); an unknown engine is rejected, not stored as a
  placeholder option;
* every statement this module emits is a *read*. There is no path that accepts
  SQL text from a caller, identifiers always come from reflection, and the
  session is put in read-only mode so a mistake fails instead of writing to the
  target.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import MetaData, Table, create_engine, event, inspect, select, text
from sqlalchemy.engine import URL, Engine
from sqlalchemy.exc import DBAPIError, OperationalError, ProgrammingError, SQLAlchemyError

from app.core.config import settings

#: The engines the platform really supports. ``read_only`` is the session-level
#: statement that turns a wrong write into an error instead of data loss.
ENGINES: dict[str, dict[str, Any]] = {
    "mysql": {
        "driver": "mysql+pymysql",
        "default_port": 3306,
        "label": "MySQL / MariaDB",
        "version_query": "SELECT VERSION()",
        "read_only": "SET SESSION TRANSACTION READ ONLY",
        "read_only_check": "SELECT @@session.transaction_read_only",
        "schemas_are_databases": True,
        "needs_host": True,
    },
    "postgresql": {
        "driver": "postgresql+psycopg2",
        "default_port": 5432,
        "label": "PostgreSQL",
        "version_query": "SHOW server_version",
        "read_only": "SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY",
        "read_only_check": "SHOW transaction_read_only",
        "schemas_are_databases": False,
        "needs_host": True,
    },
}


#: The only per-connection driver options this platform honours. A caller can
#: never smuggle an arbitrary connection argument (or SQL) into the session.
OPTION_KEYS = {
    "charset": "mysql",
    "sslmode": "postgresql",
    "connect_timeout_seconds": "any",
    "statement_timeout_seconds": "any",
}


def clean_options(engine_name: str, value: Any) -> dict[str, Any]:
    """Drop unknown option keys instead of forwarding them to the driver."""
    if not isinstance(value, dict):
        return {}
    clean: dict[str, Any] = {}
    for key, item in value.items():
        name = str(key)[:64]
        owner = OPTION_KEYS.get(name)
        if owner is None or (owner != "any" and owner != engine_name):
            continue
        if name.endswith("_seconds"):
            try:
                number = int(item)
            except (TypeError, ValueError):
                continue
            clean[name] = max(1, min(number, 3600))
        else:
            text = str(item)[:64]
            if text:
                clean[name] = text
    return clean


class DatabaseError(Exception):
    """A target-database failure with a classification the API can show."""

    def __init__(self, message: str, *, status: str = "error") -> None:
        super().__init__(message)
        self.status = status


def normalise_engine(value: Any) -> str:
    engine = str(value or "").strip().lower()
    aliases = {"mariadb": "mysql", "mysql": "mysql", "postgres": "postgresql",
               "postgresql": "postgresql", "psql": "postgresql"}
    if engine not in aliases:
        raise DatabaseError(
            f"unsupported engine {value!r}: supported engines are "
            + ", ".join(sorted(ENGINES)), status="unsupported_engine")
    return aliases[engine]


def classify(exc: Exception) -> str:
    """One status word for a driver failure; never a silent "ok"."""
    message = str(exc).lower()
    if any(token in message for token in
           ("access denied", "authentication", "password", "not allowed to connect",
            "role ", "auth")):
        return "auth_error"
    if any(token in message for token in
           ("refused", "unreachable", "getaddrinfo", "timed out", "timeout",
            "no route", "name or service not known", "could not connect",
            "can't connect", "server closed the connection", "network")):
        return "unreachable"
    if any(token in message for token in ("permission", "denied", "read-only", "read only")):
        return "permission"
    return "error"


@dataclass(slots=True)
class ConnectionConfig:
    """The connection fields the adapter needs; no ORM object required."""

    id: int
    engine: str
    host: str
    port: int
    database: str
    username: str
    tls_mode: str = ""
    options: dict[str, Any] | None = None


def _connect_args(config: ConnectionConfig) -> dict[str, Any]:
    options = config.options or {}
    timeout = int(options.get("connect_timeout_seconds")
                  or settings.database_scan_connect_timeout)
    timeout = max(1, int(timeout))
    statement = int(options.get("statement_timeout_seconds")
                    or settings.database_scan_max_seconds)
    statement = max(1, min(int(statement), 3600 * 4))
    if config.engine == "mysql":
        return {"connect_timeout": timeout, "read_timeout": statement, "write_timeout": statement}
    if config.engine == "postgresql":
        return {"connect_timeout": timeout,
                "options": f"-c statement_timeout={statement * 1000}"}
    # Any other dialect gets no invented arguments: a driver that does not
    # understand them must not be handed one.
    return {}


def build_url(config: ConnectionConfig, password: str) -> URL:
    """The SQLAlchemy URL. ``hide_parameters`` keeps it out of logs."""
    spec = ENGINES[config.engine]
    options = config.options or {}
    query: dict[str, str] = {}
    if config.engine == "mysql":
        # Never let a driver surprise us with an implicit read-write session.
        query["charset"] = str(options.get("charset") or "utf8mb4")
    elif options.get("sslmode"):
        query["sslmode"] = str(options["sslmode"])
    if config.tls_mode == "require" and config.engine == "mysql":
        query["ssl_verify_cert"] = "false"
    return URL.create(
        spec["driver"], username=config.username or None,
        password=password or None, host=config.host or None,
        port=config.port or spec["default_port"],
        database=config.database or None, query=query,
    )


def make_engine(config: ConnectionConfig, password: str) -> Engine:
    engine_name = normalise_engine(config.engine)
    config.engine = engine_name
    config.options = clean_options(engine_name, config.options)
    engine = create_engine(
        build_url(config, password), pool_pre_ping=True, pool_recycle=1800,
        connect_args=_connect_args(config), hide_parameters=True,
        future=True, isolation_level=None,
    )
    _install_read_only(engine, engine_name)
    return engine


def _install_read_only(engine: Engine, engine_name: str) -> None:
    """Put *every* pooled connection into read-only mode, at connect time.

    Doing it in the pool hook instead of once per session means a helper that
    opens its own ``engine.connect()`` cannot accidentally work with write
    access: the target server, not this code, is what refuses a mistaken write.
    """
    statement = str(ENGINES[engine_name]["read_only"])

    @event.listens_for(engine, "connect")
    def _on_connect(dbapi_connection: Any, _record: Any) -> None:
        apply_read_only(dbapi_connection, statement)


def apply_read_only(dbapi_connection: Any, statement: str) -> None:
    """Run one read-only statement on a freshly opened DBAPI connection."""
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute(statement)
    finally:
        cursor.close()


def read_only_state(conn: Any, engine_name: str) -> bool | None:
    """Ask the server whether this session is read-only; ``None`` if it cannot say."""
    try:
        value = conn.execute(text(str(ENGINES[engine_name]["read_only_check"]))).scalar()
    except (OperationalError, ProgrammingError, DBAPIError):
        return None
    normalised = str(value).strip().lower()
    if normalised in ("1", "true", "on", "yes"):
        return True
    if normalised in ("0", "false", "off", "no"):
        return False
    return None


def open_read_only(engine: Engine, engine_name: str) -> dict[str, Any]:
    """Open a session, prove it is read-only and read the server version.

    A session the server reports as writable is a hard failure: the platform
    must never be able to modify a customer database because a flag was missing.
    """
    spec = ENGINES[engine_name]
    try:
        with engine.connect() as conn:
            state = read_only_state(conn, engine_name)
            version = conn.execute(text(spec["version_query"])).scalar()
            conn.rollback()
    except (OperationalError, ProgrammingError, DBAPIError) as exc:
        raise DatabaseError(f"{type(exc).__name__}: {exc}", status=classify(exc)) from exc
    if state is False:
        raise DatabaseError("目标数据库未进入只读会话，已拒绝采集",
                            status="read_only_violation")
    return {"server_version": str(version or "").splitlines()[0][:128], "read_only": state}


def test_connection(config: ConnectionConfig, password: str) -> dict[str, Any]:
    """Really connect, really read the version, and report what happened."""
    engine_name = normalise_engine(config.engine)
    engine = make_engine(config, password)
    try:
        info = open_read_only(engine, engine_name)
        return {"status": "ok", "engine": engine_name,
                "server_version": info["server_version"], "read_only": info["read_only"],
                "database": config.database, "host": config.host,
                "port": config.port or ENGINES[engine_name]["default_port"]}
    finally:
        engine.dispose()


def schemas_of(engine: Engine, engine_name: str) -> list[str]:
    """User schemas/databases only; system schemas are never scan targets."""
    try:
        names = [str(name) for name in inspect(engine).get_schema_names()]
    except (OperationalError, ProgrammingError, DBAPIError) as exc:
        raise DatabaseError(f"{type(exc).__name__}: {exc}", status=classify(exc)) from exc
    if ENGINES[engine_name]["schemas_are_databases"]:
        names = [name for name in names
                 if name not in {"information_schema", "performance_schema", "mysql", "sys"}]
    else:
        names = [name for name in names
                 if name not in {"pg_catalog", "information_schema", "pg_toast"}]
    return sorted(dict.fromkeys(names))


def tables_of(engine: Engine, engine_name: str, schema: str,
              database: str = "") -> list[dict[str, Any]]:
    """Tables and views of one schema, with their column counts."""
    try:
        inspector = inspect(engine)
        target = schema or database or None
        rows: list[dict[str, Any]] = []
        for kind, names in (("table", inspector.get_table_names(schema=target)),
                            ("view", inspector.get_view_names(schema=target))):
            for name in sorted(names):
                rows.append({"name": str(name), "kind": kind, "schema": target or "",
                             "columns": len(inspector.get_columns(str(name), schema=target))})
        return rows
    except (OperationalError, ProgrammingError, DBAPIError) as exc:
        raise DatabaseError(f"{type(exc).__name__}: {exc}", status=classify(exc)) from exc


def list_schemas(config: ConnectionConfig, password: str) -> list[str]:
    """Reflect the schemas of one configured target (one short-lived engine)."""
    engine_name = normalise_engine(config.engine)
    engine = make_engine(config, password)
    try:
        return schemas_of(engine, engine_name)
    finally:
        engine.dispose()


def list_tables(config: ConnectionConfig, password: str, schema: str) -> list[dict[str, Any]]:
    engine_name = normalise_engine(config.engine)
    engine = make_engine(config, password)
    try:
        return tables_of(engine, engine_name, schema, config.database)
    finally:
        engine.dispose()


def sample_table(
    engine: Engine, schema: str, table: str, *, limit_rows: int, value_chars: int
) -> dict[str, Any]:
    """Read at most ``limit_rows`` rows of one table.

    ``SELECT *`` with a hard ``LIMIT`` is the only read: nothing here ever writes,
    and the caller reports the sample ceiling next to the sample size so a
    truncated read is never presented as the whole table.
    """
    metadata = MetaData()
    reflected = Table(table, metadata, schema=schema or None, autoload_with=engine)
    statement = select(reflected).limit(max(1, int(limit_rows)))
    columns: dict[str, list[str]] = {}
    nulls: dict[str, int] = {}
    rows_read = 0
    with engine.connect() as conn:
        result = conn.execute(statement)
        for row in result:
            rows_read += 1
            mapping = row._mapping
            for column in reflected.columns:
                key = column.name
                value = mapping.get(column)
                if value is None:
                    nulls[key] = nulls.get(key, 0) + 1
                    continue
                columns.setdefault(key, []).append(str(value)[:value_chars])
        conn.rollback()
    types = {column.name: str(column.type) for column in reflected.columns}
    return {
        "schema": schema,
        "table": table,
        "rows_read": rows_read,
        "columns": [{"name": column.name, "type": types[column.name],
                     "sample_size": len(columns.get(column.name, [])),
                     "nulls": nulls.get(column.name, 0)} for column in reflected.columns],
        "values": columns,
    }


def disconnect(engine: Engine) -> None:
    try:
        engine.dispose()
    except SQLAlchemyError:  # pragma: no cover - disposal is best effort
        pass

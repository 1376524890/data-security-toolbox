"""Engine allow-list, read-only enforcement and bounded sampling."""
from __future__ import annotations

import importlib

import pytest
from app.services.database_scan import adapters
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError


def test_only_allow_listed_engines_are_accepted() -> None:
    assert sorted(adapters.ENGINES) == ["mysql", "postgresql"]
    assert adapters.normalise_engine("MariaDB") == "mysql"
    assert adapters.normalise_engine(" postgres ") == "postgresql"
    with pytest.raises(adapters.DatabaseError) as excinfo:
        adapters.normalise_engine("oracle")
    assert excinfo.value.status == "unsupported_engine"
    with pytest.raises(adapters.DatabaseError):
        adapters.normalise_engine("")


@pytest.mark.parametrize(
    ("driver", "module"),
    [("mysql+pymysql", "pymysql"), ("postgresql+psycopg2", "psycopg2")],
)
def test_both_supported_drivers_are_really_installed(driver: str, module: str) -> None:
    """A placeholder engine with no driver behind it is not support."""
    spec = [item for item in adapters.ENGINES.values() if item["driver"] == driver]
    assert spec, f"{driver} is not in the allow-list"
    importlib.import_module(module)


def test_option_keys_are_allow_listed_per_engine() -> None:
    assert adapters.clean_options(
        "mysql",
        {"charset": "utf8mb4", "sslmode": "require", "init_command": "DROP TABLE t",
         "connect_timeout_seconds": "3", "statement_timeout_seconds": 5},
    ) == {"charset": "utf8mb4", "connect_timeout_seconds": 3,
          "statement_timeout_seconds": 5}
    assert adapters.clean_options("postgresql", {"sslmode": "require", "charset": "x"}) == {
        "sslmode": "require"
    }
    assert adapters.clean_options("mysql", {"connect_timeout_seconds": "nonsense"}) == {}
    assert adapters.clean_options("mysql", None) == {}


def test_timeouts_are_clamped_into_a_usable_range() -> None:
    assert adapters.clean_options(
        "mysql", {"connect_timeout_seconds": 99999}
    ) == {"connect_timeout_seconds": 3600}
    assert adapters.clean_options(
        "mysql", {"connect_timeout_seconds": -4}
    ) == {"connect_timeout_seconds": 1}


def _config(**overrides) -> adapters.ConnectionConfig:
    base = {"id": 1, "engine": "mysql", "host": "db.internal", "port": 3306,
            "database": "dst_demo", "username": "dst_ro"}
    return adapters.ConnectionConfig(**{**base, **overrides})


def test_the_password_never_appears_in_an_engine_string() -> None:
    engine = adapters.make_engine(_config(), "top-secret-pw")
    try:
        assert "top-secret-pw" not in str(engine)
        assert "top-secret-pw" not in repr(engine)
        assert "top-secret-pw" not in engine.url.render_as_string(hide_password=True)
        assert "dst_ro" in str(engine)
    finally:
        adapters.disconnect(engine)


def test_the_read_only_statement_runs_on_a_fresh_dbapi_connection() -> None:
    executed: list[str] = []
    closed: list[bool] = []

    class _Cursor:
        def execute(self, statement: str) -> None:
            executed.append(statement)

        def close(self) -> None:
            closed.append(True)

    class _RawConnection:
        def cursor(self) -> _Cursor:
            return _Cursor()

    adapters.apply_read_only(_RawConnection(), "SET SESSION TRANSACTION READ ONLY")
    assert executed == ["SET SESSION TRANSACTION READ ONLY"]
    assert closed == [True]


def test_the_statement_is_installed_on_every_connect(monkeypatch) -> None:
    """The hook is what enforces read-only, so it must run on connect itself.

    A statement the target cannot execute has to break the connect: that is the
    behaviour that turns a mistaken write into an error instead of data loss.
    """
    engine = create_engine("sqlite://")
    adapters._install_read_only(engine, "mysql")
    with pytest.raises(SQLAlchemyError):
        engine.connect().close()
    monkeypatch.setitem(adapters.ENGINES["mysql"], "read_only", "PRAGMA query_only = ON")
    working = create_engine("sqlite://")
    adapters._install_read_only(working, "mysql")
    with working.connect() as conn:
        assert conn.execute(text("SELECT 1")).scalar() == 1


def test_the_read_only_state_is_read_from_the_server() -> None:
    class _Result:
        def __init__(self, value: object) -> None:
            self._value = value

        def scalar(self) -> object:
            return self._value

    class _Connection:
        def __init__(self, value: object) -> None:
            self._value = value

        def execute(self, _statement: object) -> _Result:
            return _Result(self._value)

    assert adapters.read_only_state(_Connection(1), "mysql") is True
    assert adapters.read_only_state(_Connection("ON"), "mysql") is True
    assert adapters.read_only_state(_Connection("0"), "mysql") is False
    assert adapters.read_only_state(_Connection("maybe"), "mysql") is None


def test_driver_failures_get_a_status_the_api_can_show() -> None:
    assert adapters.classify(Exception("Access denied for user 'x'@'y'")) == "auth_error"
    refused = ("(2003, \"Can't connect to MySQL server on '10.0.0.9' "
               "([Errno 111] Connection refused)\")")
    assert adapters.classify(Exception(refused)) == "unreachable"
    unknown_host = ("(2003, \"Can't connect to MySQL server on 'db' "
                    "([Errno -2] Name or service not known)\")")
    assert adapters.classify(Exception(unknown_host)) == "unreachable"
    assert adapters.classify(Exception("no route to host")) == "unreachable"
    assert adapters.classify(Exception("SELECT command denied to user")) == "permission"
    assert adapters.classify(Exception("something else entirely")) == "error"

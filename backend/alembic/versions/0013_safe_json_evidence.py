"""Repair binary NUL escapes in legacy JSON evidence without dropping findings."""
import json
from alembic import op
import sqlalchemy as sa

revision = '0013_safe_json_evidence'
down_revision = '0012_asset_objects'
branch_labels = None
depends_on = None


def _normalize(value):
    if isinstance(value, str):
        return value.replace(chr(0), r"\x00").encode('utf-8', 'replace').decode('utf-8')
    if isinstance(value, dict):
        return {_normalize(key): _normalize(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_normalize(item) for item in value]
    return value


def upgrade():
    connection = op.get_bind()
    inspector = sa.inspect(connection)
    for name in inspector.get_table_names():
        columns = inspector.get_columns(name)
        json_columns = [c['name'] for c in columns if isinstance(c['type'], sa.JSON)]
        primary = inspector.get_pk_constraint(name).get('constrained_columns', [])
        if not json_columns or not primary:
            continue
        table = sa.Table(name, sa.MetaData(), autoload_with=connection)
        for column in json_columns:
            # Read JSON as text; JSON operators fail on legacy NUL escapes.
            raw = sa.cast(table.c[column], sa.Text)
            query = sa.select(*(table.c[k] for k in primary), raw.label('raw')).where(raw.contains(r'\u0000'))
            for row in connection.execute(query).fetchall():
                original = json.loads(row[-1])
                cleaned = _normalize(original)
                if cleaned != original:
                    condition = sa.and_(*(table.c[k] == row[i] for i, k in enumerate(primary)))
                    connection.execute(table.update().where(condition).values({column: cleaned}))


def downgrade():
    # Do not reintroduce invalid binary NUL into text evidence.
    pass

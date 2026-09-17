"""Store binary NUL as visible text so PostgreSQL JSON operators remain usable."""
import json


def normalize_json(value):
    if isinstance(value, str):
        return value.replace(chr(0), r"\x00").encode('utf-8', 'replace').decode('utf-8')
    if isinstance(value, dict):
        return {normalize_json(key): normalize_json(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [normalize_json(item) for item in value]
    return value


def dumps_json(value):
    return json.dumps(normalize_json(value), ensure_ascii=False)

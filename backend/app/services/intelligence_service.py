"""Normalized local IOC library and bounded pulls from configured providers."""
import csv
import io
import ipaddress
import json
import re
from datetime import UTC, datetime
from urllib.parse import urlsplit, urlunsplit

import requests
from sqlalchemy import select

from app.core.config import settings
from app.models import IOC, SystemSetting

MAX_BYTES = 5 * 1024 * 1024
MAX_ROWS = 20000
PROVIDERS = {
    'feodo': {'name': 'Feodo Tracker', 'url': 'https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt', 'format': 'ip-list', 'key_required': False},
    'urlhaus': {'name': 'URLhaus', 'url': 'https://urlhaus-api.abuse.ch/v2/files/exports/{key}/recent.csv', 'format': 'urlhaus', 'key_required': True},
    'custom': {'name': '自建 JSON/CSV 情报源', 'url': '', 'format': 'custom', 'key_required': False},
}


def normalize(kind, value):
    value = str(value).strip()
    if not value or len(value) > 1024:
        raise ValueError('IOC value must contain 1..1024 characters')
    if kind == 'ip':
        return str(ipaddress.ip_address(value))
    if kind == 'domain':
        value = value.rstrip('.').encode('idna').decode().lower()
        if not re.fullmatch(r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}', value):
            raise ValueError('Invalid domain')
        return value
    if kind == 'hash':
        if not re.fullmatch(r'(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})', value):
            raise ValueError('Expected MD5, SHA1 or SHA256')
        return value.lower()
    if kind == 'url':
        url = urlsplit(value)
        if url.scheme not in ('http', 'https') or not url.hostname or url.username or url.password:
            raise ValueError('Expected HTTP(S) URL without credentials')
        return urlunsplit((url.scheme.lower(), url.netloc.lower(), url.path or '/', url.query, ''))
    raise ValueError('Supported IOC types: ip, domain, url, hash')


def parse_indicators(text, format='custom'):
    if len(text.encode('utf-8')) > MAX_BYTES:
        raise ValueError('IOC input exceeds 5 MiB')
    clean = '\n'.join(line for line in text.splitlines() if not line.lstrip().startswith('#'))
    if format == 'ip-list':
        rows = [{'type': 'ip', 'value': line.strip()} for line in clean.splitlines() if line.strip()]
    elif format == 'urlhaus':
        rows = [{'type': 'url', 'value': row[2], 'tags': ['malware']} for row in csv.reader(io.StringIO(clean)) if len(row) >= 3 and row[0].isdigit()]
    elif clean.lstrip().startswith(('[', '{')):
        data = json.loads(clean)
        rows = data if isinstance(data, list) else data.get('items', data.get('iocs', []))
    else:
        rows = list(csv.DictReader(io.StringIO(clean)))
    if len(rows) > MAX_ROWS:
        raise ValueError('IOC batch exceeds 20000 rows')
    normalized, rejected = [], 0
    for row in rows:
        try:
            kind = row.get('type', row.get('ioc_type', ''))
            tags = row.get('tags', [])
            if isinstance(tags, str):
                tags = [v.strip() for v in tags.split(',') if v.strip()]
            normalized.append({'type': kind, 'value': normalize(kind, row['value']), 'tags': [str(v)[:64] for v in tags[:20]]})
        except (ValueError, KeyError, TypeError, AttributeError):
            rejected += 1
    return normalized, rejected


def upsert_iocs(db, rows, source):
    now = datetime.now(UTC).isoformat()
    index = {(r.ioc_type, r.value): r for r in db.scalars(select(IOC).where(IOC.source == source)).all()}
    added, updated = 0, 0
    for item in rows:
        key = item['type'], item['value']
        row = index.get(key)
        if row is None:
            row = IOC(ioc_type=key[0], value=key[1], source=source, first_seen=now, tags=item.get('tags', []), extra={'enabled': True})
            db.add(row)
            index[key] = row
            added += 1
        else:
            updated += 1
        row.last_seen = now
        row.tags = sorted(set((row.tags or []) + item.get('tags', [])))[:30]
    db.flush()
    return {'added': added, 'updated': updated}


def fetch_provider(provider):
    spec = PROVIDERS[provider]
    url = spec['url']
    if provider == 'urlhaus':
        key = settings.urlhaus_auth_key
        if not key or not re.fullmatch(r'[A-Za-z0-9_-]+', key):
            raise ValueError('Set URLHAUS_AUTH_KEY on the server')
        url = url.format(key=key)
    if provider == 'custom':
        url = settings.custom_intel_url
        if not url:
            raise ValueError('Set CUSTOM_INTEL_URL on the server')
    # Custom endpoints are chosen by the server operator, never arbitrary browser input.
    parsed = urlsplit(url)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('Invalid configured feed URL')
    headers = {'Accept': 'application/json,text/csv,text/plain'}
    if provider == 'custom' and settings.custom_intel_token:
        headers['Authorization'] = 'Bearer ' + settings.custom_intel_token
    try:
        with requests.get(url, headers=headers, timeout=(10, 30), stream=True, allow_redirects=False) as response:
            response.raise_for_status()
            if response.status_code != 200:
                raise ValueError('Feed must return HTTP 200 without redirect')
            content = bytearray()
            for part in response.iter_content(65536):
                content.extend(part)
                if len(content) > MAX_BYTES:
                    raise ValueError('Feed exceeds 5 MiB')
    except requests.RequestException:
        # URLhaus embeds a credential in its URL; never return exception URLs.
        raise ValueError('Feed download failed; check connectivity and server credentials') from None
    return parse_indicators(content.decode('utf-8-sig'), spec['format'])


def sync_provider(db, provider):
    key = 'intel_sync_' + provider
    state = db.scalar(select(SystemSetting).where(SystemSetting.key == key))
    if not state:
        state = SystemSetting(key=key, value={})
        db.add(state)
    try:
        rows, rejected = fetch_provider(provider)
        if not rows and rejected:
            raise ValueError('Feed contained no valid IOC records')
        result = {**upsert_iocs(db, rows, provider), 'rejected': rejected, 'status': 'success'}
    except ValueError as exc:
        result = {'status': 'failed', 'error': str(exc)}
    state.value = {**result, 'at': datetime.now(UTC).isoformat()}
    db.commit()
    return state.value

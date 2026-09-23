"""Managed DLP regex rules; upstream Python is parsed as data, never executed."""
import ast
import hashlib
import io
import json
import os
import re
import uuid
import zipfile
from pathlib import Path

import regex
import requests

from app.core.config import settings

from app.services.masking import masked


# Entities that describe infrastructure metadata instead of protected data.
# They stay useful as transfer evidence but can never make a stream sensitive:
# almost every HTTP header carries an IP address and a date.
STRUCTURAL_ENTITIES = {'IP_ADDRESS', 'MAC_ADDRESS', 'DATE_TIME', 'URL', 'NRP', 'LOCATION'}
# Presidio encodes pattern precision in the pattern name and in ``score``.
# Rules stored before ``score`` was persisted fall back to the name marker.
# Marker to confidence, mirroring the Presidio scoring convention (High=.85,
# Medium=.6, Low=.3) for stores written before ``score`` was persisted.
WEAK_MARKERS = (('very weak', .1), ('very low', .1), ('weak', .25), ('low', .3), ('medium', .55), ('high', .85))
# Analyst-authored rules are intentional, so they alert unless told otherwise.
MANUAL_CONFIDENCE = .7
# Upstream imports without a precision annotation are only usable as evidence:
# the worldwide identity pack contains impostor patterns such as foreign
# licence plates that match ordinary payload text.
IMPORTED_CONFIDENCE = .5
DEFAULT_CONFIDENCE = MANUAL_CONFIDENCE
# A hit below this precision is recorded as evidence but never raises an alert.
MIN_ALERT_CONFIDENCE = .6

#: A rule that can only match a run of digits cannot tell an identity number from
#: a counter, a timestamp or an internal request id. Imported packs are full of
#: them - ``\b\d{6}[-]?\d{4}\b`` (a Swedish organisation number) matched the
#: ``: 1784680825:0;`` prefix of a shell-history entry, a JSON mtime and a CGI
#: request id, and produced 331 detections / 3194 hits of pure noise on one host.
#: Such a rule is kept, because it is still useful evidence, but it can never
#: confirm on its own. An analyst-written rule is exempt: those are deliberate,
#: and the console's rule editor is where a human takes that responsibility.
DIGIT_ONLY_CONFIDENCE = .5
#: Regex escapes that still leave a pattern able to match only digits.
_DIGIT_ONLY_ESCAPES = ('\\d', '\\b', '\\s')
#: What may remain once digits and separators are all that is left: quantifiers,
#: groups, anchors, alternation and the separators themselves.
_DIGIT_ONLY_SYNTAX = re.compile(r"[\d\s\-.,:;_+|(){}\[\]?*^$=!<>]*")


def digit_only_pattern(pattern) -> bool:
    """True when a pattern can only ever match digits and their separators."""
    text = str(pattern or '')
    if not text or '[^' in text:
        # A negated class can match anything, which is the opposite of a pattern
        # that is certain to be looking at a number.
        return False
    for escape in _DIGIT_ONLY_ESCAPES:
        text = text.replace(escape, '')
    # Escapes left over are escaped punctuation (``\+``, ``\.``); dropping the
    # backslash keeps them subject to the same "no letters" test below.
    text = text.replace('\\', '')
    # Any letter can introduce a non-digit into the match (a literal, a class,
    # ``\w``, ``\S``), which is exactly the evidence a bare number lacks.
    if re.search(r'[A-Za-z]', text):
        return False
    return bool(_DIGIT_ONLY_SYNTAX.fullmatch(text))


def _plausible_email(value):
    """Reject loose ``user@host`` matches such as ``security@172.18.0.2``.

    The upstream Presidio email pattern accepts any domain, so it also matches
    the host part of a database connection string.
    """
    return bool(re.fullmatch(r'[^@\s]+@[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*\.[A-Za-z]{2,}', value))


# Known-oversensitive upstream patterns that need a value-level sanity check.
MATCH_VALIDATORS = {'EMAIL_ADDRESS': _plausible_email}


def rule_confidence(rule):
    """Precision of one rule in ``0..1``; missing upstream scores stay conservative.

    A non-analyst rule whose pattern can only match digits is capped at
    :data:`DIGIT_ONLY_CONFIDENCE`, below the alert threshold: no score a pack
    reports can make a bare number conclusive, so the cap is applied here rather
    than trusted to the pack. The rule stays in the store and still contributes
    evidence; it just cannot raise a finding by itself.
    """
    value = rule.get('confidence', rule.get('score'))
    if isinstance(value, bool):
        value = None
    try:
        confidence = float(value)
    except (TypeError, ValueError):
        name = str(rule.get('name', '')).casefold()
        fallback = MANUAL_CONFIDENCE if str(rule.get('source') or 'manual') == 'manual' else IMPORTED_CONFIDENCE
        confidence = next((score for marker, score in WEAK_MARKERS if marker in name), fallback)
    confidence = min(1.0, max(0.0, confidence))
    if str(rule.get('source') or 'manual') != 'manual' and digit_only_pattern(rule.get('pattern')):
        confidence = min(confidence, DIGIT_ONLY_CONFIDENCE)
    return round(confidence, 4)


def sensitive_entity(rule):
    """True when the rule describes protected data rather than infrastructure metadata."""
    return str(rule.get('entity') or rule.get('name') or '').upper() not in STRUCTURAL_ENTITIES


# The console's rule store is the only place analyst rules live. The closed set
# of provenance names a rule pack accepts is defined once here, so the platform
# engine and the rule-set working copy cannot disagree about where a rule came
# from.
SOURCE_BY_STORE = {'manual': 'manual', 'presidio': 'presidio_static', 'builtin': 'builtin'}


def rule_source(rule):
    """Provenance of one store rule, mapped onto the names a rule pack accepts."""
    return SOURCE_BY_STORE.get(str(rule.get('source') or 'manual').strip().lower(), 'manual')


def stored_rule(rule):
    """One stored rule in the shared rule (rule pack) format -- the only mapping.

    The platform engine and the rule-set working copy both build their rules
    from here. They used to map the store separately, so an imported rule
    reached a probe without the shape check the platform applied and the same
    rule matched differently on the two sides.

    ``description`` falls back to the recognizer because the rule pack has
    always carried the Presidio recognizer name there; a republish must not
    rewrite rules an operator already published.
    """
    rule_id = str(rule.get('id') or '').strip()
    return {
        'rule_id': rule_id,
        'name': str(rule.get('name') or rule_id),
        'entity': str(rule.get('entity') or rule.get('name') or rule_id),
        'pattern': str(rule.get('pattern') or ''),
        'keywords': [str(item) for item in (rule.get('keywords') or [])],
        'field_hints': [str(item) for item in (rule.get('field_hints') or [])],
        'confidence': rule_confidence(rule),
        'enabled': bool(rule.get('enabled', True)),
        'rule_source': rule_source(rule),
        'recognizer': str(rule.get('recognizer') or ''),
        'description': str(rule.get('description') or rule.get('recognizer') or ''),
    }


def atomic_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    try:
        temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def validate_rule(value):
    if not isinstance(value, dict):
        raise ValueError('规则必须是对象')
    name, pattern = str(value.get('name', '')).strip(), str(value.get('pattern', ''))
    if not name or len(name) > 200 or not pattern or len(pattern) > 10000:
        raise ValueError('规则名称和正则表达式不能为空，长度分别不超过 200 / 10000')
    try:
        compiled = regex.compile(pattern, regex.I | regex.M | regex.S)
        if compiled.search('', timeout=.05):
            raise ValueError('正则不能匹配空字符串')
    except (regex.error, TimeoutError) as exc:
        raise ValueError(f'无效正则: {exc}') from exc
    return {'name': name, 'pattern': pattern, 'entity': str(value.get('entity') or name)[:200],
            'enabled': bool(value.get('enabled', True)), 'source': 'manual', 'mode': 'regex',
            'confidence': rule_confidence({'confidence': value.get('confidence'), 'name': name})}


STORE_DIRECTORY = 'dlp_rules'


def rule_store_directory() -> Path:
    return settings.integration_dir / STORE_DIRECTORY


def rule_store_files() -> list[Path]:
    """Every file the rule store holds, in a stable order.

    The layout is known here and nowhere else: the engine's refresh signature,
    the rule-library listing and an enable/disable write all have to see the
    same set of files, and each of them used to glob the directory itself.
    """
    return sorted(rule_store_directory().glob('*.json'))


def managed_rules():
    result = []
    for path in rule_store_files():
        result.extend(json.loads(path.read_text(encoding='utf-8'))['rules'])
    return result


def save_manual_rule(value):
    rule = validate_rule(value)
    rule['id'] = 'manual-' + uuid.uuid4().hex
    atomic_json(rule_store_directory() / (rule['id'] + '.json'), {'rules': [rule]})
    return rule


def set_rule_enabled(rule_id, enabled):
    """Enable or disable one stored rule in place.

    Returns the updated rule, or ``None`` when the store does not hold it. The
    store writes its own files: the API used to glob, parse and rewrite them,
    and a second reader of the layout is how a second implementation starts.
    """
    for path in rule_store_files():
        document = json.loads(path.read_text(encoding='utf-8'))
        for rule in document.get('rules', []):
            if rule.get('id') != rule_id:
                continue
            rule['enabled'] = bool(enabled)
            atomic_json(path, document)
            return rule
    return None


def import_presidio_wheel(content, version):
    rules, skipped = [], 0
    current = {rule['id']: rule.get('enabled', True) for rule in managed_rules()}
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        for item in archive.infolist():
            if '/predefined_recognizers/' not in item.filename or not item.filename.endswith('.py'):
                continue
            if item.file_size > 1024 * 1024:
                raise ValueError('Presidio 源文件过大')
            tree = ast.parse(archive.read(item).decode('utf-8'))
            for cls in (n for n in tree.body if isinstance(n, ast.ClassDef)):
                entity = cls.name
                for function in cls.body:
                    if isinstance(function, ast.FunctionDef) and function.name == '__init__':
                        for arg, default in zip(function.args.args[-len(function.args.defaults):], function.args.defaults):
                            if arg.arg == 'supported_entity' and isinstance(default, ast.Constant):
                                entity = str(default.value)
                for call in ast.walk(cls):
                    if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Name) or call.func.id != 'Pattern':
                        continue
                    try:
                        values = dict(zip(('name', 'regex', 'score'), [ast.literal_eval(x) for x in call.args]))
                        values.update({x.arg: ast.literal_eval(x.value) for x in call.keywords})
                        rule = validate_rule({'name': cls.name + ': ' + values['name'], 'pattern': values['regex'], 'entity': entity,
                                              'confidence': values.get('score')})
                        rule.update(id='presidio-' + hashlib.sha256((cls.name + values['name']).encode()).hexdigest()[:24],
                                    source='Presidio', version=version, recognizer=cls.name)
                        # Metadata locators and weak patterns are imported for
                        # evidence but stay disabled unless an analyst opts in.
                        rule['enabled'] = current.get(rule['id'], rule['confidence'] >= MIN_ALERT_CONFIDENCE and sensitive_entity(rule))
                        rules.append(rule)
                    except (ValueError, TypeError, KeyError, SyntaxError):
                        skipped += 1
    rules = list({r['id']: r for r in rules}.values())
    if not rules:
        raise ValueError('未找到可导入的 Presidio 正则规则')
    document = {'rules': rules, 'version': version, 'skipped': skipped, 'source': 'https://pypi.org/project/presidio-analyzer/',
                'scope': 'Presidio 静态正则模式；不包含 NLP 模型、上下文评分或 Python 校验器'}
    atomic_json(rule_store_directory() / 'presidio.json', document)
    return {'imported': len(rules), 'skipped': skipped, 'version': version, 'scope': document['scope']}


def update_presidio():
    response = requests.get('https://pypi.org/pypi/presidio-analyzer/json', timeout=(10, 60))
    response.raise_for_status()
    release = response.json()
    wheel = next(x for x in release['urls'] if x['filename'].endswith('.whl'))
    response = requests.get(wheel['url'], timeout=(10, 60))
    response.raise_for_status()
    if len(response.content) > 20 * 1024 * 1024:
        raise ValueError('Presidio 规则包超过 20 MB')
    if hashlib.sha256(response.content).hexdigest() != wheel['digests']['sha256']:
        raise ValueError('Presidio 包 SHA256 校验失败')
    return import_presidio_wheel(response.content, release['info']['version'])


def scan_managed(text, rules, minimum=1, errors=None):
    hits = []
    for rule in rules:
        if not rule.get('enabled', True):
            continue
        validate = MATCH_VALIDATORS.get(str(rule.get('entity', '')).upper())
        try:
            count, samples = 0, []
            for match in regex.finditer(rule['pattern'], text, regex.I | regex.M | regex.S, timeout=.05):
                value = match.group()
                if validate and not validate(value):
                    continue
                count += 1
                if len(samples) < 3:
                    samples.append(masked(value))
            if count >= minimum:
                hits.append({'kind': rule['entity'], 'rule_id': rule.get('id', ''), 'count': count, 'samples': samples,
                             'confidence': rule_confidence(rule), 'sensitive': sensitive_entity(rule)})
        except TimeoutError:
            if errors is not None:
                errors.append(rule['id'])
    return hits

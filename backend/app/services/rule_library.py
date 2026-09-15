"""Managed DLP regex rules; upstream Python is parsed as data, never executed."""
import ast
import hashlib
import io
import json
import os
import uuid
import zipfile
from pathlib import Path

import regex
import requests

from app.core.config import settings


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
            'enabled': bool(value.get('enabled', True)), 'source': 'manual', 'mode': 'regex'}


def managed_rules():
    result = []
    for path in sorted((settings.integration_dir / 'dlp_rules').glob('*.json')):
        result.extend(json.loads(path.read_text(encoding='utf-8'))['rules'])
    return result


def save_manual_rule(value):
    rule = validate_rule(value)
    rule['id'] = 'manual-' + uuid.uuid4().hex
    atomic_json(settings.integration_dir / 'dlp_rules' / (rule['id'] + '.json'), {'rules': [rule]})
    return rule


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
                        rule = validate_rule({'name': cls.name + ': ' + values['name'], 'pattern': values['regex'], 'entity': entity})
                        rule.update(id='presidio-' + hashlib.sha256((cls.name + values['name']).encode()).hexdigest()[:24],
                                    source='Presidio', version=version, recognizer=cls.name, score=float(values.get('score', 0)))
                        rule['enabled'] = current.get(rule['id'], rule['score'] >= .5)
                        rules.append(rule)
                    except (ValueError, TypeError, KeyError, SyntaxError):
                        skipped += 1
    rules = list({r['id']: r for r in rules}.values())
    if not rules:
        raise ValueError('未找到可导入的 Presidio 正则规则')
    document = {'rules': rules, 'version': version, 'skipped': skipped, 'source': 'https://pypi.org/project/presidio-analyzer/',
                'scope': 'Presidio 静态正则模式；不包含 NLP 模型、上下文评分或 Python 校验器'}
    atomic_json(settings.integration_dir / 'dlp_rules' / 'presidio.json', document)
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
    from app.services.dlp_service import masked
    hits = []
    for rule in rules:
        if not rule.get('enabled', True):
            continue
        try:
            matches = regex.finditer(rule['pattern'], text, regex.I | regex.M | regex.S, timeout=.05)
            count, samples = 0, []
            for match in matches:
                count += 1
                if len(samples) < 3:
                    samples.append(masked(match.group()))
            if count >= minimum:
                hits.append({'kind': rule['entity'], 'rule_id': rule['id'], 'count': count, 'samples': samples})
        except TimeoutError:
            if errors is not None:
                errors.append(rule['id'])
    return hits

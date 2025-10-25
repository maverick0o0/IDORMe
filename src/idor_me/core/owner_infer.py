"""Owner inference heuristics for IDORMe."""

import json
import re
import xml.etree.ElementTree as ET

try:
    basestring
except NameError:  # pragma: no cover - CPython 3
    basestring = str
    long = int

OWNER_KEYS = ["id", "userId", "uid", "email", "username", "owner"]
OWNER_PATTERN = re.compile(r"([A-Za-z0-9_.+-]+@[A-Za-z0-9_.-]+|\buser\w*\b|\bid\b|\buid\b)", re.I)


def _flatten_json(value, collector):
    if isinstance(value, dict):
        for key, val in value.items():
            collector.append((key, val))
            _flatten_json(val, collector)
    elif isinstance(value, list):
        for item in value:
            _flatten_json(item, collector)
    else:
        collector.append((None, value))


def extract_tokens_from_json(text):
    try:
        data = json.loads(text)
    except Exception:
        return []
    items = []
    _flatten_json(data, items)
    tokens = []
    for key, val in items:
        if isinstance(val, (int, long)):
            tokens.append(str(val))
        elif isinstance(val, basestring):
            stripped = val.strip()
            if not stripped:
                continue
            if key:
                lowered = key.lower()
                for target in OWNER_KEYS:
                    if target in lowered:
                        tokens.append(stripped)
                        break
            if OWNER_PATTERN.search(stripped):
                tokens.append(stripped)
    return list(set(tokens))


def extract_tokens_from_xml(text):
    try:
        root = ET.fromstring(text)
    except Exception:
        return []
    tokens = []
    for element in root.iter():
        tag = element.tag.lower()
        if element.text:
            content = element.text.strip()
        else:
            content = ""
        for key in OWNER_KEYS:
            if key in tag and content:
                tokens.append(content)
                break
        if content and OWNER_PATTERN.search(content):
            tokens.append(content)
    return list(set(tokens))


def extract_tokens_from_text(text):
    tokens = []
    for match in OWNER_PATTERN.finditer(text):
        value = match.group(1)
        if value not in tokens:
            tokens.append(value)
    return tokens


class OwnerInference(object):
    def __init__(self):
        self._baseline_tokens = []
        self._baseline_status = None

    def learn_baseline(self, response):
        body = response or ""
        tokens = self.extract_tokens(body)
        if tokens:
            self._baseline_tokens = tokens
        return self._baseline_tokens

    def extract_tokens(self, body):
        if not body:
            return []
        if isinstance(body, basestring):
            text = body
        elif isinstance(body, (bytes, bytearray)):
            text = body.decode("utf-8", "ignore")
        elif hasattr(body, "tobytes"):
            try:
                text = body.tobytes().decode("utf-8", "ignore")
            except Exception:
                text = str(body)
        else:
            try:
                text = memoryview(body).tobytes().decode("utf-8", "ignore")
            except Exception:
                text = str(body)
        tokens = []
        tokens.extend(extract_tokens_from_json(text))
        tokens.extend(extract_tokens_from_xml(text))
        tokens.extend(extract_tokens_from_text(text))
        deduped = []
        for token in tokens:
            if token not in deduped:
                deduped.append(token)
        return deduped

    def score(self, baseline_status, baseline_tokens, response_status, response_body, delta_len, hash_changed):
        tokens = self.extract_tokens(response_body)
        new_tokens = [t for t in tokens if t not in baseline_tokens]
        if baseline_status and baseline_status >= 400 and response_status < 400 and new_tokens:
            return {"label": "Definite", "score": 100, "tokens": tokens}
        if response_status < 400 and new_tokens and (abs(delta_len) > 20 or hash_changed):
            return {"label": "Likely", "score": 80, "tokens": tokens}
        if tokens and hash_changed:
            return {"label": "Interesting", "score": 50, "tokens": tokens}
        return {"label": "None", "score": 0, "tokens": tokens}


__all__ = ["OwnerInference"]

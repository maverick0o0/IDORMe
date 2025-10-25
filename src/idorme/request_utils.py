"""HTTP request parsing and building utilities for IDORMe."""
from __future__ import absolute_import

import re
import random

try:
    from urllib import quote_plus
except ImportError:  # pragma: no cover - Py3 fallback for tests
    from urllib.parse import quote_plus

try:  # pragma: no cover - runtime shim
    unicode  # type: ignore[name-defined]
except NameError:  # pragma: no cover - Python 3 compatibility
    unicode = str

REQUEST_LINE_RE = re.compile(r"^(?P<method>[A-Z]+)\s+(?P<target>[^\s]+)\s+(?P<version>HTTP/\d\.\d)\s*$")


class RequestTemplate(object):
    """Container describing the baseline HTTP request."""

    def __init__(self, method, path, query_string, headers, body, http_version="HTTP/1.1"):
        self.method = method.upper()
        self.path = path or "/"
        self.query_string = query_string or ""
        self.headers = list(headers or [])
        self.body = body or b""
        self.http_version = http_version
        self.content_type = self._detect_header_value("Content-Type")

    def _detect_header_value(self, header_name):
        prefix = header_name.lower() + ":"
        for header in self.headers:
            if header.lower().startswith(prefix):
                return header.split(":", 1)[1].strip()
        return None

    def builder(self):
        return RequestBuilder(self)

    def clone(self):
        return RequestTemplate(
            self.method,
            self.path,
            self.query_string,
            list(self.headers),
            self.body,
            self.http_version,
        )

    def path_segments(self):
        if not self.path:
            return []
        segments = [segment for segment in self.path.split("/") if segment]
        return segments

    def has_body(self):
        return bool(self.body)


class RequestBuilder(object):
    """Mutable builder used to derive mutated HTTP requests."""

    def __init__(self, template):
        self.template = template
        self.method = template.method
        self.path = template.path
        self.query_string = template.query_string
        self.headers = list(template.headers)
        self.body = template.body
        self.content_type = template.content_type
        self.notes = []

    # --- header helpers -------------------------------------------------
    def _replace_header(self, name, value):
        lower_name = name.lower()
        prefix = lower_name + ":"
        new_headers = []
        replaced = False
        for header in self.headers:
            header_lower = header.lower()
            if header_lower.startswith(prefix):
                if value is None:
                    # drop header
                    replaced = True
                    continue
                new_headers.append("{}: {}".format(name, value))
                replaced = True
            else:
                new_headers.append(header)
        if not replaced and value is not None:
            new_headers.append("{}: {}".format(name, value))
        self.headers = new_headers

    def set_header(self, name, value):
        self._replace_header(name, value)

    def remove_header(self, name):
        self._replace_header(name, None)

    def add_header_line(self, line):
        self.headers.append(line)

    # --- request modifiers ----------------------------------------------
    def set_method(self, method):
        if method:
            self.method = method.upper()

    def set_path(self, path):
        if path is not None:
            if not path.startswith("/"):
                path = "/" + path
            self.path = path

    def set_query_string(self, query_string):
        self.query_string = query_string or ""

    def set_query_pairs(self, pairs):
        encoded = []
        for key, value in pairs:
            encoded.append("{}={}".format(_quote(key), _quote(value)))
        self.query_string = "&".join(encoded)

    def set_body(self, body, content_type=None):
        if body is None:
            body = b""
        if isinstance(body, unicode):  # noqa: F821 - Py2 specific
            body = body.encode("utf-8")
        elif isinstance(body, str):
            body = body.encode("utf-8")
        self.body = body
        if content_type:
            self.content_type = content_type

    def append_path_suffix(self, suffix):
        if suffix:
            if self.path.endswith("/"):
                self.path = self.path[:-1]
            self.path += suffix

    def mutate_path_segment_case(self, segment_index, variant):
        segments = self.path.split("/")
        if segment_index < 0 or segment_index >= len(segments):
            return
        target = segments[segment_index]
        if not target:
            return
        if variant == "upper":
            new_value = target.upper()
        elif variant == "lower":
            new_value = target.lower()
        else:
            mixed = []
            upper = True
            for char in target:
                if char.isalpha():
                    mixed.append(char.upper() if upper else char.lower())
                    upper = not upper
                else:
                    mixed.append(char)
            new_value = "".join(mixed)
        segments[segment_index] = new_value
        self.path = "/".join(segments)

    def build(self, helpers):
        headers = list(self.headers)
        if self.content_type:
            _replace_header_in_list(headers, "Content-Type", self.content_type)
        _replace_header_in_list(headers, "Content-Length", None)
        path = self.path or "/"
        if self.query_string:
            path = "{}?{}".format(path, self.query_string)
        request_line = "{} {} {}".format(self.method, path, self.template.http_version)
        full_headers = [request_line]
        full_headers.extend(headers)
        body = self.body or b""
        return helpers.buildHttpMessage(full_headers, body)


def _replace_header_in_list(headers, name, value):
    lower_name = name.lower()
    prefix = lower_name + ":"
    new_headers = []
    replaced = False
    for header in headers:
        header_lower = header.lower()
        if header_lower.startswith(prefix):
            if value is None:
                replaced = True
                continue
            new_headers.append("{}: {}".format(name, value))
            replaced = True
        else:
            new_headers.append(header)
    if not replaced and value is not None:
        new_headers.append("{}: {}".format(name, value))
    headers[:] = new_headers


def _quote(value):
    if isinstance(value, unicode):  # noqa: F821 - Py2 specific
        value = value.encode("utf-8")
    if isinstance(value, str):
        value = value
    else:
        value = str(value)
    return quote_plus(value)


def pick_random_identifier(exclude=None):
    """Return a random 4-6 digit identifier avoiding ``exclude``."""
    exclude = {str(value) for value in (exclude or [])}
    candidate = str(random.randint(100, 9999))
    while candidate in exclude:
        candidate = str(random.randint(100, 9999))
    return candidate


def parse_request_template(helpers, message_info):
    """Build a :class:`RequestTemplate` from a Burp message info."""
    request_bytes = message_info.getRequest()
    request_info = helpers.analyzeRequest(message_info)
    headers = list(request_info.getHeaders())
    if not headers:
        raise ValueError("Unable to parse request headers")
    match = REQUEST_LINE_RE.match(headers[0])
    if not match:
        raise ValueError("Unexpected request line: {}".format(headers[0]))
    method = match.group("method")
    target = match.group("target")
    version = match.group("version")

    # ``target`` may contain full URL when captured via proxy; rely on URL object for accuracy
    url = request_info.getUrl()
    path = url.getPath() or "/"
    query = url.getQuery() or ""

    body_offset = request_info.getBodyOffset()
    if body_offset < len(request_bytes):
        body = request_bytes[body_offset:]
    else:
        body = b""

    template = RequestTemplate(method, path, query, headers[1:], body, version)
    return template

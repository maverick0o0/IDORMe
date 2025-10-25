"""HTTP message helpers compatible with Jython 2.7."""

try:
    import urlparse
except ImportError:  # pragma: no cover - CPython 3
    from urllib import parse as urlparse

try:
    basestring
except NameError:  # pragma: no cover - CPython 3
    basestring = str


class HttpRequest(object):
    """Represents a baseline Burp request and offers mutation helpers."""

    def __init__(self, service, method, path, query, headers, body):
        self.service = service
        self.method = method
        self.path = path or "/"
        self.query = query or ""
        self.headers = list(headers)
        self.body = body or ""
        self.content_type = self._detect_content_type()

    @classmethod
    def from_burp(cls, helpers, message_info):
        request = message_info.getRequest()
        analyzed = helpers.analyzeRequest(message_info)
        service = message_info.getHttpService()
        method = analyzed.getMethod()
        url = analyzed.getUrl()
        path = url.getPath() or "/"
        query = url.getQuery()
        headers = []
        for header in analyzed.getHeaders():
            if ":" in header:
                name, value = header.split(":", 1)
                headers.append((name.strip(), value.strip()))
            else:
                headers.append((None, header))
        body = request[analyzed.getBodyOffset():]
        return cls(service, method, path, query, headers, body)

    def clone(self):
        return HttpRequest(self.service, self.method, self.path, self.query, list(self.headers), self.body)

    def url(self):
        if self.query:
            return self.path + "?" + self.query
        return self.path

    def _detect_content_type(self):
        for name, value in self.headers:
            if name and name.lower() == "content-type":
                return value
        return None

    def set_content_type(self, value):
        replaced = False
        new_headers = []
        for name, val in self.headers:
            if name and name.lower() == "content-type":
                new_headers.append((name, value))
                replaced = True
            else:
                new_headers.append((name, val))
        if not replaced:
            new_headers.append(("Content-Type", value))
        self.headers = new_headers
        self.content_type = value

    def apply_delta(self, mutation):
        if mutation.transport_method:
            self.method = mutation.transport_method
        if mutation.path_delta:
            self.path = mutation.path_delta
        if mutation.query_delta is not None:
            self.query = mutation.query_delta
        if mutation.headers_delta:
            for name, value in mutation.headers_delta:
                self._set_header(name, value)
        if mutation.body_bytes is not None:
            self.body = mutation.body_bytes
        if mutation.content_type_hint:
            self.set_content_type(mutation.content_type_hint)

    def _set_header(self, name, value):
        updated = False
        new_headers = []
        for current, val in self.headers:
            if current and current.lower() == name.lower():
                new_headers.append((current, value))
                updated = True
            else:
                new_headers.append((current, val))
        if not updated:
            new_headers.append((name, value))
        self.headers = new_headers

    def build_burp_request(self, helpers):
        headers = []
        for name, value in self.headers:
            if name is None:
                headers.append(value)
            else:
                headers.append("%s: %s" % (name, value))
        body_bytes = self.body
        if body_bytes and isinstance(body_bytes, unicode):
            body_bytes = body_bytes.encode("utf-8")
        if not body_bytes:
            body_bytes = ""
        return helpers.buildHttpMessage(headers, body_bytes)

    def copy_with(self, **kwargs):
        clone = self.clone()
        for key, value in kwargs.items():
            setattr(clone, key, value)
        return clone

    def parsed_query(self):
        if not self.query:
            return {}
        pairs = urlparse.parse_qs(self.query, keep_blank_values=True)
        flat = {}
        for key, values in pairs.items():
            flat[key] = values
        return flat

    def parsed_body(self):
        if not self.body:
            return {}
        ct = self.content_type or ""
        if "application/x-www-form-urlencoded" in ct:
            data = self.body
            if not isinstance(data, basestring):
                data = data.decode("utf-8", "ignore")
            return urlparse.parse_qs(data, keep_blank_values=True)
        return {}


class HttpResponse(object):
    def __init__(self, status_code, headers, body):
        self.status_code = status_code
        self.headers = headers
        self.body = body or ""

    @classmethod
    def from_burp(cls, helpers, message_info):
        response = message_info.getResponse()
        analyzed = helpers.analyzeResponse(response)
        headers = []
        for header in analyzed.getHeaders():
            if ":" in header:
                name, value = header.split(":", 1)
                headers.append((name.strip(), value.strip()))
            else:
                headers.append((None, header))
        body = response[analyzed.getBodyOffset():]
        return cls(analyzed.getStatusCode(), headers, body)

    def body_text(self):
        try:
            return self.body.decode("utf-8")
        except Exception:
            return self.body.decode("latin-1", "ignore")


__all__ = ["HttpRequest", "HttpResponse"]

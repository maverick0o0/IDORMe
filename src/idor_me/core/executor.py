"""Threaded request executor for IDORMe."""

import hashlib
import threading
try:
    import Queue as queue
except ImportError:  # pragma: no cover
    import queue

from .httpmsg import HttpResponse
from .rules_catalog import WRITE_METHODS


class ExecutionOptions(object):
    def __init__(self, safe_mode=True, follow_redirects=False, concurrency=4, timeout=10,
                 apply_global=True, apply_specific=True):
        self.safe_mode = safe_mode
        self.follow_redirects = follow_redirects
        self.concurrency = max(1, int(concurrency))
        self.timeout = max(1, int(timeout))
        self.apply_global = apply_global
        self.apply_specific = apply_specific


class RequestExecutor(object):
    def __init__(self, owner_inference=None):
        self.callbacks = None
        self.helpers = None
        self.owner_inference = owner_inference
        self.result_listener = None
        self._queue = queue.Queue()
        self._threads = []
        self._stop = threading.Event()
        self._options = ExecutionOptions()
        self._sender = None

    def configure(self, callbacks=None, helpers=None, owner_inference=None, result_listener=None):
        self.callbacks = callbacks or self.callbacks
        self.helpers = helpers or self.helpers
        self.owner_inference = owner_inference or self.owner_inference
        self.result_listener = result_listener or self.result_listener

    def set_sender(self, sender):
        self._sender = sender

    def set_options(self, options):
        self._options = options
        self._restart_workers()

    def stop(self):
        self._stop.set()
        while not self._queue.empty():
            try:
                self._queue.get_nowait()
            except Exception:
                break
        for thread in list(self._threads):
            thread.join(timeout=0.5)
        self._threads = []
        self._stop.clear()

    def enqueue(self, baseline_request, baseline_response, mutations):
        if not self._threads:
            self._start_workers()
        baseline_info = self._build_baseline_info(baseline_request, baseline_response)
        counter = 1
        for mutation in mutations:
            self._queue.put((counter, baseline_request, baseline_info, mutation))
            counter += 1

    # ------------------------------------------------------------------
    # Worker lifecycle
    # ------------------------------------------------------------------
    def _start_workers(self):
        for _ in range(self._options.concurrency):
            worker = threading.Thread(target=self._worker, name="IDORMeWorker")
            worker.daemon = True
            worker.start()
            self._threads.append(worker)

    def _restart_workers(self):
        self.stop()
        self._start_workers()

    def _worker(self):
        while not self._stop.is_set():
            try:
                index, baseline_request, baseline_info, mutation = self._queue.get(timeout=0.2)
            except queue.Empty:
                continue
            try:
                result = self._execute_mutation(index, baseline_request, baseline_info, mutation)
                if result and self.result_listener:
                    self.result_listener(result)
            finally:
                self._queue.task_done()

    # ------------------------------------------------------------------
    # Mutation execution
    # ------------------------------------------------------------------
    def _execute_mutation(self, index, baseline_request, baseline_info, mutation):
        request = baseline_request.clone()
        request.apply_delta(mutation)
        method = request.method.upper()
        if self._options.safe_mode and method in WRITE_METHODS:
            return None
        request_bytes = request.build_burp_request(self.helpers)
        response_info = self._send_request(baseline_request.service, request_bytes)
        if not response_info:
            return None
        response = HttpResponse.from_burp(self.helpers, response_info)
        body = response.body or ""
        baseline_len = baseline_info["length"]
        delta_len = len(body) - baseline_len
        hash_digest = hashlib.sha256(body if body else "").hexdigest()
        hash_short = hash_digest[:8]
        hash_changed = hash_digest != baseline_info["hash"]
        owner_score = {"label": "None", "score": 0, "tokens": []}
        if self.owner_inference:
            owner_score = self.owner_inference.score(
                baseline_info["status"],
                baseline_info["owner_tokens"],
                response.status_code,
                body,
                delta_len,
                hash_changed,
            )
        result = {
            "#": index,
            "rule_id": mutation.rule_id,
            "method": request.method,
            "url": request.url(),
            "content_type": request.content_type or "",
            "request_size": len(request_bytes),
            "status": response.status_code,
            "length": len(body),
            "delta_len": delta_len,
            "hash": hash_short,
            "owner": owner_score,
            "note": mutation.note,
            "request": request,
            "response": response,
            "raw_request": request_bytes,
            "raw_response": response_info,
        }
        return result

    def _send_request(self, service, request_bytes):
        sender = self._sender
        if not sender and self.callbacks:
            sender = self.callbacks.makeHttpRequest
        if not sender:
            return None
        try:
            return sender(service, request_bytes)
        except Exception:
            return None

    def _build_baseline_info(self, request, response_info):
        helpers = self.helpers
        baseline = {
            "status": None,
            "length": 0,
            "hash": hashlib.sha256("").hexdigest(),
            "owner_tokens": [],
        }
        if not helpers or not response_info:
            return baseline
        response = HttpResponse.from_burp(helpers, response_info)
        body = response.body or ""
        baseline["status"] = response.status_code
        baseline["length"] = len(body)
        baseline["hash"] = hashlib.sha256(body if body else "").hexdigest()
        if self.owner_inference:
            baseline["owner_tokens"] = self.owner_inference.extract_tokens(body)
        return baseline


__all__ = ["ExecutionOptions", "RequestExecutor"]

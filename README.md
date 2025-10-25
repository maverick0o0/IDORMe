# IDORMe Burp Suite Extension

IDORMe is a Burp Suite extension (Jython 2.7) that stress-tests a single
captured, authenticated request for IDOR weaknesses. It takes the
selected request, generates a catalogue of bypass mutations (path, query,
body and verb tricks), sends them within the same session and scores the
responses using lightweight owner inference heuristics.

## Usage

1. Load the extension in Burp Suite (**Extender → Extensions → Add** →
   *Extension type* `Python`).
2. Capture an authenticated request in Proxy/Repeater, right-click and
   choose **Send to IDORMe**.
3. Review/adjust inputs in the **IDORMe** tab:
   * Optional parameter/value triad.
   * Execution toggles: Safe Mode, follow redirects, concurrency,
     timeouts, apply global rules, apply specific rules.
4. Click **Run All** to execute the generated mutations. Double-click any
   result row to inspect the request/response in Burp editors.
5. Use **Export CSV** for offline analysis.

Safe Mode blocks write verbs by default; disable it only when you
explicitly want to exercise state-changing mutations.

## Development

The codebase is written to run under CPython for testing and under
Jython inside Burp. No third-party libraries are required.

Run unit tests:

```bash
python -m unittest discover -s tests -p "test_*.py"
```

## Notes

* The executor never alters host/authority information or baseline
  cookies/headers.
* If you omit the parameter triad the mutator will infer candidates and
  generate distinct attacker/victim values automatically.
* CSV exports include all table columns for easy diffing.
